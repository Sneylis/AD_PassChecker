#Requires -Version 5.1
<#
.SYNOPSIS
    Главный оркестратор аудита паролей AD. Запускается ЕЖЕМЕСЯЧНО
    на audit-станции по расписанию и координирует Фазы 2 → 5.

.DESCRIPTION
    Архитектура регламента:

        DC:     Phase 1 (New-IFMBackup.ps1) — отдельное ежемесячное
                расписание на контроллере домена, кладёт
                <audit-ifm-YYYYMMDDTHHMM>.7z на SMB-share.

        Station: ЭТОТ скрипт (Start-PasswordAudit.ps1) —
                отдельное ежемесячное расписание на станции,
                стартует чуть позже Phase 1, ждёт готовый архив,
                проводит Фазы 2–5.

    Алгоритм:
        0.  Инициализация Correlation ID + логов.
        1.  Опрос SMB-share: найти самый свежий архив + sidecar .sha256.
            Проверить возраст (MaxArchiveAgeMinutes) и SHA-256.
        2.  Фаза 2: Test-HIBPIntegrity.ps1
                — если не прошла → Фаза 5 (чистка) и выход.
        3.  Фаза 3: Invoke-PasswordAudit.ps1
                — получает путь к (УЖЕ проверенному) архиву,
                  распаковывает локально в WorkDirectory,
                  гонит DSInternals, выдаёт JSON.
        4.  Фаза 4: New-AuditReport.ps1
                — из JSON делает TXT отчёт, архивирует AES-256,
                  кладёт в ReportRetentionDirectory, шлёт пароль
                  по S/MIME-подписанной почте.
        5.  Фаза 5: Invoke-SecureCleanup.ps1
                — ВСЕГДА в finally, даже если выше упало.
        6.  Exit code = первое ненулевое из фаз.

    Разделение ответственности между расписаниями:
        • Phase 1 task (на DC): ежемесячно, 1-е число 02:00 UTC.
        • Start-PasswordAudit task (станция): ежемесячно, 1-е число
          03:00 UTC — даём Phase 1 час на создание архива.
        • Retention task (на станции или файл-сервере): ежедневно в 03:30.

.PARAMETER ConfigPath
    Путь к audit.config.psd1. В Scheduled Task — передаётся
    через AD_AUDIT_CONFIG или явным параметром.

.PARAMETER WaitForArchiveMinutes
    Сколько минут ждать появления свежего архива, если он
    ещё не попал на share. 0 = не ждать. По умолчанию 90.

.PARAMETER MaxArchiveAgeHours
    Архив считается "свежим", если его mtime не старше N часов.
    По умолчанию 24. Отсекает старые архивы, которые уже были
    обработаны в предыдущем прогоне.

.PARAMETER SkipPlatformChecks
    Только для лаборатории: не падать, если BitLocker/pagefile
    не в порядке. В продакшене НЕЛЬЗЯ.

.OUTPUTS
    [PSCustomObject] — сводная картина прогона.
    Exit codes:
        0  — успех
        1  — конфиг / зависимости
        2  — архив не появился / не прошёл проверку целостности
        3  — Фаза 2 (HIBP/platform) упала
        4  — Фаза 3 (audit) упала
        5  — Фаза 4 (report/email) упала
        6  — Фаза 5 (cleanup) нашла residue
        99 — неизвестная ошибка

.EXAMPLE
    # Из Scheduled Task:
    pwsh.exe -NoProfile -ExecutionPolicy Bypass `
             -File C:\ADPasswordAudit\Orchestrator\Start-PasswordAudit.ps1 `
             -ConfigPath C:\ProgramData\ADPasswordAudit\audit.config.psd1
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory)] [string] $ConfigPath,
    [int]    $WaitForArchiveMinutes = 90,
    [int]    $MaxArchiveAgeHours    = 24,
    [switch] $SkipPlatformChecks
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

# Репозиторий: <root>\Orchestrator\this.ps1 → <root>
$repoRoot = Split-Path -Parent (Split-Path -Parent $MyInvocation.MyCommand.Path)
Import-Module (Join-Path $repoRoot 'Common\Logging.psm1')        -Force
Import-Module (Join-Path $repoRoot 'Common\Config.psm1')         -Force
Import-Module (Join-Path $repoRoot 'Common\Crypto.psm1')         -Force
Import-Module (Join-Path $repoRoot 'Common\CleanupHelpers.psm1') -Force

# ------------------------------------------------------------
# Инициализация логгера — ДО чего-либо ещё, чтобы любая
# ошибка ниже попала в журнал.
# ------------------------------------------------------------
$logDirFallback = 'C:\AuditLogs'
try {
    Initialize-AuditLog -LogDirectory $logDirFallback -PhaseName 'Orchestrator'
} catch {
    Write-Error "Не удалось инициализировать лог: $($_.Exception.Message)"
    exit 1
}

$cid = Get-AuditCorrelationId
Write-AuditLog -Level INFO -Message ('=' * 60)
Write-AuditLog -Level INFO -Message ("ОРКЕСТРАТОР АУДИТА ПАРОЛЕЙ — старт (CID={0})" -f $cid)
Write-AuditLog -Level INFO -Message ('=' * 60)
Write-AuditLog -Level INFO -Message ("Host:    {0}" -f $env:COMPUTERNAME)
Write-AuditLog -Level INFO -Message ("User:    {0}\{1}" -f $env:USERDOMAIN, $env:USERNAME)
Write-AuditLog -Level INFO -Message ("Config:  {0}" -f $ConfigPath)
Write-AuditLog -Level INFO -Message ("UTC now: {0:u}" -f (Get-Date).ToUniversalTime())

# ------------------------------------------------------------
# Глобальное состояние прогона (для финального рапорта).
# ------------------------------------------------------------
$run = [pscustomobject]@{
    CorrelationId  = $cid
    StartedUtc     = (Get-Date).ToUniversalTime()
    Phase1Archive  = $null
    Phase2         = $null
    Phase3         = $null
    Phase4         = $null
    Phase5         = $null
    OverallSuccess = $false
    ExitCode       = 99
    Error          = $null
    Duration       = $null
}

$stopwatch = [System.Diagnostics.Stopwatch]::StartNew()

# ------------------------------------------------------------
# Хелпер: найти свежий IFM-архив на SMB.
# ------------------------------------------------------------
function Wait-ForFreshArchive {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [string] $SharePath,
        [int] $MaxAgeHours        = 24,
        [int] $WaitForMinutes     = 90,
        [int] $PollIntervalSeconds = 60
    )

    Set-AuditPhase -PhaseName 'ArchivePoll'
    if (-not (Test-Path -LiteralPath $SharePath)) {
        throw "SMB-share не доступен: $SharePath"
    }

    $threshold = (Get-Date).ToUniversalTime().AddHours(-$MaxAgeHours)
    $deadline  = (Get-Date).AddMinutes($WaitForMinutes)

    do {
        $archives = Get-ChildItem -LiteralPath $SharePath -Filter 'audit-ifm-*.7z' -File -ErrorAction SilentlyContinue
        if ($archives) {
            $fresh = $archives |
                Where-Object { $_.LastWriteTimeUtc -ge $threshold } |
                Sort-Object LastWriteTimeUtc -Descending |
                Select-Object -First 1
            if ($fresh) {
                Write-AuditLog -Level INFO -Message ("Найден свежий архив: {0} ({1:u}, {2:N0} MB)" `
                    -f $fresh.Name, $fresh.LastWriteTimeUtc, ($fresh.Length / 1MB))
                return $fresh
            }
        }
        if ((Get-Date) -ge $deadline -or $WaitForMinutes -le 0) { break }
        Write-AuditLog -Level INFO -Message ("Архива ещё нет. Пауза {0} сек..." -f $PollIntervalSeconds)
        Start-Sleep -Seconds $PollIntervalSeconds
    } while ($true)

    throw "Свежий архив не появился на $SharePath за $WaitForMinutes мин. (порог возраста: $MaxAgeHours ч.)"
}

function Assert-ArchiveSha256 {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [System.IO.FileInfo] $Archive
    )
    $sidecarPath = $Archive.FullName + '.sha256'
    if (-not (Test-Path -LiteralPath $sidecarPath)) {
        throw "Отсутствует sidecar SHA-256: $sidecarPath"
    }
    # Формат sidecar: "<hash>  <filename>"
    $expected = ((Get-Content -LiteralPath $sidecarPath -TotalCount 1) -split '\s+')[0].ToLowerInvariant()
    if ($expected -notmatch '^[0-9a-f]{64}$') {
        throw "В sidecar некорректный SHA-256: $expected"
    }
    Write-AuditLog -Level INFO -Message 'Вычисление SHA-256 архива (может быть долго для больших IFM)...'
    $sw = [System.Diagnostics.Stopwatch]::StartNew()
    $actual = (Get-Sha256Hash -Path $Archive.FullName).ToLowerInvariant()
    $sw.Stop()
    Write-AuditLog -Level INFO -Message ("SHA-256 посчитан за {0:N1} сек" -f $sw.Elapsed.TotalSeconds)
    if ($actual -ne $expected) {
        Write-AuditLog -Level CRITICAL -Message "SHA-256 архива НЕ СОВПАДАЕТ с sidecar. Возможна подмена или повреждение."
        throw "Archive integrity check FAILED: expected $expected, actual $actual"
    }
    Write-AuditLog -Level INFO -Message 'SHA-256 архива совпал с sidecar.'
}

function Invoke-Phase {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [string] $Name,
        [Parameter(Mandatory)] [scriptblock] $Body
    )
    Set-AuditPhase -PhaseName $Name
    Write-AuditLog -Level INFO -Message ("--- Старт {0} ---" -f $Name)
    $swPhase = [System.Diagnostics.Stopwatch]::StartNew()
    try {
        $result = & $Body
        $swPhase.Stop()
        Write-AuditLog -Level INFO -Message ("--- {0} завершено за {1:N1} сек ---" -f $Name, $swPhase.Elapsed.TotalSeconds)
        return $result
    } catch {
        $swPhase.Stop()
        Write-AuditLog -Level CRITICAL -Message ("--- {0} ПАЛО через {1:N1} сек: {2}" -f $Name, $swPhase.Elapsed.TotalSeconds, $_.Exception.Message)
        throw
    }
}

# ============================================================
# Main
# ============================================================
try {
    # 0. Конфиг -----------------------------------------------
    $env:AD_AUDIT_CONFIG = $ConfigPath
    try {
        $cfg = Get-AuditConfig
    } catch {
        Write-AuditLog -Level CRITICAL -Message "Не удалось прочитать конфиг: $($_.Exception.Message)"
        $run.ExitCode = 1
        throw
    }

    # Пути к фазам.
    $phase2Script = Join-Path $repoRoot 'Phase2-HIBP\Test-HIBPIntegrity.ps1'
    $phase3Script = Join-Path $repoRoot 'Phase3-Audit\Invoke-PasswordAudit.ps1'
    $phase4Script = Join-Path $repoRoot 'Phase4-Report\New-AuditReport.ps1'
    $phase5Script = Join-Path $repoRoot 'Phase5-Cleanup\Invoke-SecureCleanup.ps1'

    foreach ($p in @($phase2Script, $phase3Script, $phase4Script, $phase5Script)) {
        if (-not (Test-Path -LiteralPath $p)) {
            Write-AuditLog -Level CRITICAL -Message "Не найден скрипт фазы: $p"
            $run.ExitCode = 1
            throw "Missing phase script: $p"
        }
    }

    # 1. Ждём архив --------------------------------------------
    $archive = $null
    try {
        $archive = Invoke-Phase -Name 'ArchivePoll' -Body {
            Wait-ForFreshArchive `
                -SharePath $cfg.SmbShareUnc `
                -MaxAgeHours $MaxArchiveAgeHours `
                -WaitForMinutes $WaitForArchiveMinutes
        }
        $run.Phase1Archive = $archive.FullName

        Invoke-Phase -Name 'ArchiveIntegrity' -Body {
            Assert-ArchiveSha256 -Archive $archive
        }
    } catch {
        Write-AuditLog -Level CRITICAL -Message "Архив не готов или не прошёл проверку: $($_.Exception.Message)"
        $run.ExitCode = 2
        $run.Error = $_.Exception.Message
        throw
    }

    # 2. Phase 2 — HIBP + платформа -----------------------------
    try {
        $p2Args = @{ ConfigPath = $ConfigPath }
        if ($SkipPlatformChecks) { $p2Args['SkipPlatformChecks'] = $true }
        $run.Phase2 = Invoke-Phase -Name 'Phase2' -Body {
            & $phase2Script @p2Args
        }
    } catch {
        $run.ExitCode = 3
        $run.Error = $_.Exception.Message
        throw
    }

    # 3. Phase 3 — DSInternals audit ----------------------------
    try {
        $run.Phase3 = Invoke-Phase -Name 'Phase3' -Body {
            & $phase3Script -ConfigPath $ConfigPath -ArchivePath $archive.FullName
        }
    } catch {
        $run.ExitCode = 4
        $run.Error = $_.Exception.Message
        throw
    }

    # 4. Phase 4 — отчёт, архив, email -------------------------
    # Phase 4 ожидает путь к JSON-отчёту Фазы 3.
    try {
        $rawReportPath = if ($run.Phase3 -and $run.Phase3.PSObject.Properties.Match('RawReportPath').Count -gt 0) {
            $run.Phase3.RawReportPath
        } else { $null }

        if (-not $rawReportPath) {
            throw "Phase 3 не вернул RawReportPath — нечего отдавать в Phase 4."
        }

        $run.Phase4 = Invoke-Phase -Name 'Phase4' -Body {
            & $phase4Script -ConfigPath $ConfigPath -RawReportPath $rawReportPath
        }
    } catch {
        $run.ExitCode = 5
        $run.Error = $_.Exception.Message
        throw
    }

    # Успех основной части. Phase 5 — в finally.
    $run.OverallSuccess = $true
    $run.ExitCode       = 0

} catch {
    Write-AuditLog -Level CRITICAL -Message "Оркестратор: перехвачено исключение: $($_.Exception.Message)"
    Write-AuditLog -Level CRITICAL -Message $_.ScriptStackTrace
    if ($run.ExitCode -eq 99) {
        $run.ExitCode = 99
    }
    $run.Error = $_.Exception.Message
} finally {
    # 5. Phase 5 — ВСЕГДА, даже если упало всё выше. ------------
    try {
        $p5Args = @{ ConfigPath = $ConfigPath }
        $run.Phase5 = Invoke-Phase -Name 'Phase5' -Body {
            & $phase5Script @p5Args
        }
        if ($run.Phase5 -and $run.Phase5.PSObject.Properties.Match('Success').Count -gt 0 -and -not $run.Phase5.Success) {
            # Residue найден. Если основная часть прошла успешно, всё
            # равно помечаем прогон как "с замечаниями".
            if ($run.ExitCode -eq 0) { $run.ExitCode = 6 }
            $run.OverallSuccess = $false
            Write-AuditLog -Level CRITICAL -Message 'Phase 5: обнаружен residue — прогон помечен как неудачный.'
        }
    } catch {
        Write-AuditLog -Level CRITICAL -Message "Phase 5 упала: $($_.Exception.Message)"
        if ($run.ExitCode -eq 0) { $run.ExitCode = 6 }
        $run.OverallSuccess = $false
    }

    $stopwatch.Stop()
    $run.Duration = $stopwatch.Elapsed

    # Итоговая сводка для SIEM.
    Write-AuditLog -Level INFO -Message ('=' * 60)
    Write-AuditLog -Level INFO -Message ("ИТОГ ПРОГОНА (CID={0})" -f $cid)
    Write-AuditLog -Level INFO -Message ("Успех:          {0}" -f $run.OverallSuccess)
    Write-AuditLog -Level INFO -Message ("Exit code:      {0}" -f $run.ExitCode)
    Write-AuditLog -Level INFO -Message ("Длительность:   {0:hh\:mm\:ss}" -f $run.Duration)
    if ($run.Error) {
        Write-AuditLog -Level INFO -Message ("Последняя ошибка: {0}" -f $run.Error)
    }
    Write-AuditLog -Level INFO -Message ('=' * 60)

    # Возвращаем объект тому, кто запустил интерактивно.
    # Scheduled Task смотрит только на exit code.
    $run
    exit $run.ExitCode
}
