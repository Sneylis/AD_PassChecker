#Requires -Version 5.1
<#
.SYNOPSIS
    Ротация отчётов аудита: безопасное удаление архивов старше
    ReportRetentionDays суток из каталога хранения отчётов.

.DESCRIPTION
    Согласно регламенту аудита (изменение пользователя №1):
    "результат должен храниться в зашифрованном архиве на сервере,
     и удаляться через 5 дней".

    Этот скрипт предполагается запускать ЕЖЕДНЕВНО как Scheduled Task
    от имени gMSA/Backup Operator на audit-станции (или на файл-сервере,
    если хранилище отчётов вынесено туда через UNC).

    Алгоритм:
        1. Прочитать конфиг → получить ReportRetentionDirectory и
           ReportRetentionDays (по умолчанию 5).
        2. Найти в каталоге файлы по маске:
                audit-report-*.7z
                audit-report-*.7z.sha256
                audit-report-*.json
                audit-raw-*.json
           (все артефакты Фаз 3–4 с меткой времени).
        3. Для каждого файла, у которого LastWriteTimeUtc старше порога,
           выполнить SDelete -p 3 (DoD 5220.22-M, 3 прохода) и записать
           запись в журнал аудита.
        4. Если SDelete недоступен, аварийно падать: обычное Remove-Item
           оставляет данные на диске, а в архиве — имена пользователей
           и метаданные пароля; мы НЕ имеем права просто "разлинковать".
        5. В конце — отчёт: сколько файлов удалено, сколько оставлено,
           сколько ошибок.

    Скрипт НИКОГДА не удаляет:
        • Файлы, которые НЕ соответствуют маскам audit-report-* /
          audit-raw-* (случайные файлы в каталоге трогать запрещено).
        • Журналы аудита (*.log) — их ротация делается отдельно,
          они нужны SIEM.
        • Файлы с признаком Read-Only или Hidden (вручную помечены
          оператором как "сохранить для расследования").

    Использует Invoke-WithGuaranteedCleanup из CleanupHelpers для
    финального прохода Test-CleanupResidue: убедиться, что после
    ротации в каталоге не осталось разлинкованных временных файлов.

.PARAMETER ConfigPath
    Путь к audit.config.psd1. Обычно берётся из переменной
    окружения AD_AUDIT_CONFIG, заданной установщиком.

.PARAMETER OverrideRetentionDays
    Принудительный порог в днях (только для лабораторных прогонов).
    В продакшене значение читается из конфига.

.PARAMETER WhatIf
    Стандартный флаг: перечислить, что было бы удалено, но НЕ удалять.
    Полезно для проверки перед первой постановкой на расписание.

.PARAMETER KeepMinimum
    Сколько последних архивов оставить ВСЕГДА, даже если они старше
    порога. Защита от случая "забыли выключить расписание, а аудит
    не бежал 10 дней — удалим единственный отчёт". По умолчанию 1.

.OUTPUTS
    [PSCustomObject] с полями Deleted, Kept, Errors, Duration.
    Exit code:
        0 — ротация выполнена, ошибок нет
        1 — конфиг не прочитан / каталог не найден
        2 — SDelete не найден (критическая ошибка, см. описание)
        3 — часть файлов не удалось удалить

.EXAMPLE
    # Из планировщика, ежедневно в 03:30:
    pwsh.exe -File .\Invoke-ReportRetention.ps1 `
             -ConfigPath 'C:\ProgramData\ADPasswordAudit\audit.config.psd1'

.EXAMPLE
    # Проверка без удаления:
    .\Invoke-ReportRetention.ps1 -ConfigPath ... -WhatIf

.NOTES
    Важно: после удаления архивов в логах аудита остаётся ТОЛЬКО имя
    файла и дата — НИКАКИХ учётных записей или хешей. Имена
    пользователей жили внутри .7z, который уже уничтожен.
#>

[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'Medium')]
param(
    [Parameter(Mandatory)] [string] $ConfigPath,
    [int]    $OverrideRetentionDays = 0,
    [int]    $KeepMinimum           = 1
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$repoRoot = Split-Path -Parent (Split-Path -Parent $MyInvocation.MyCommand.Path)
Import-Module (Join-Path $repoRoot 'Common\Logging.psm1')        -Force
Import-Module (Join-Path $repoRoot 'Common\Config.psm1')         -Force
Import-Module (Join-Path $repoRoot 'Common\CleanupHelpers.psm1') -Force

# Инициализация логгера. Этот скрипт — отдельная задача в
# расписании, у него свой CID и своя фаза "Retention".
if (-not (Get-AuditCorrelationId)) {
    Initialize-AuditLog -LogDirectory 'C:\AuditLogs' -PhaseName 'Retention'
} else {
    Set-AuditPhase -PhaseName 'Retention'
}

Write-AuditLog -Level INFO -Message '=== Ротация отчётов аудита (5-day retention) ==='

# ------------------------------------------------------------
# Маски файлов, подлежащих ротации. Всё, что не попадает под
# эти маски, мы НЕ трогаем — это либо постороннее, либо
# промежуточное состояние, которое должна убрать Phase5.
# ------------------------------------------------------------
$RotatableMasks = @(
    'audit-report-*.7z',
    'audit-report-*.7z.sha256',
    'audit-report-*.json',
    'audit-raw-*.json',
    'audit-report-*.meta'
)

# ------------------------------------------------------------
# Хелпер: получить список подлежащих ротации файлов.
# ------------------------------------------------------------
function Get-ReportFileCandidates {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [string] $Directory
    )

    $all = @()
    foreach ($mask in $RotatableMasks) {
        # -Force чтобы видеть скрытые (их мы потом отфильтруем).
        $found = Get-ChildItem -LiteralPath $Directory -Filter $mask -File -Force -ErrorAction SilentlyContinue
        if ($found) {
            $all += $found
        }
    }
    # Уникализуем по FullName — одна и та же запись может попасть
    # под две маски (например, *.7z и audit-report-*).
    return $all | Sort-Object FullName -Unique
}

# ------------------------------------------------------------
# Хелпер: защитить от удаления — Read-Only / Hidden.
# ------------------------------------------------------------
function Test-ShouldKeepFile {
    [CmdletBinding()]
    param([Parameter(Mandatory)] [System.IO.FileInfo] $File)

    if ($File.IsReadOnly) {
        Write-AuditLog -Level WARN -Message ("Пропускаю {0}: файл помечен Read-Only (оператор явно сохранил)." -f $File.Name)
        return $true
    }
    if ($File.Attributes -band [System.IO.FileAttributes]::Hidden) {
        Write-AuditLog -Level WARN -Message ("Пропускаю {0}: файл скрыт (оператор явно сохранил)." -f $File.Name)
        return $true
    }
    return $false
}

# ------------------------------------------------------------
# Main
# ------------------------------------------------------------

$exitCode = 0
$sw = [System.Diagnostics.Stopwatch]::StartNew()
$deletedCount = 0
$keptCount    = 0
$errorCount   = 0
$deletedFiles = New-Object System.Collections.Generic.List[string]

try {
    # 1. Конфиг ----------------------------------------------------------
    $env:AD_AUDIT_CONFIG = $ConfigPath
    try {
        $cfg = Get-AuditConfig
    } catch {
        Write-AuditLog -Level CRITICAL -Message "Не удалось прочитать конфиг: $($_.Exception.Message)"
        exit 1
    }

    $retentionDir = $cfg.ReportRetentionDirectory
    if (-not $retentionDir) {
        Write-AuditLog -Level CRITICAL -Message 'В конфиге нет ReportRetentionDirectory. Ротация невозможна.'
        exit 1
    }
    if (-not (Test-Path -LiteralPath $retentionDir -PathType Container)) {
        Write-AuditLog -Level CRITICAL -Message "Каталог хранения отчётов не существует: $retentionDir"
        exit 1
    }

    # 2. Порог в днях ----------------------------------------------------
    $retentionDays = 5
    if ($OverrideRetentionDays -gt 0) {
        $retentionDays = $OverrideRetentionDays
        Write-AuditLog -Level WARN -Message "Порог ротации переопределён параметром: $retentionDays дней."
    } elseif ($cfg.PSObject.Properties.Match('ReportRetentionDays').Count -gt 0 -and $cfg.ReportRetentionDays) {
        $retentionDays = [int]$cfg.ReportRetentionDays
    }
    if ($retentionDays -lt 1) {
        Write-AuditLog -Level CRITICAL -Message "Порог ротации $retentionDays дней — недопустим (минимум 1)."
        exit 1
    }

    $threshold = (Get-Date).ToUniversalTime().AddDays(-$retentionDays)
    Write-AuditLog -Level INFO -Message ("Каталог:       {0}" -f $retentionDir)
    Write-AuditLog -Level INFO -Message ("Порог:         старше {0} дней (до {1:u})" -f $retentionDays, $threshold)
    Write-AuditLog -Level INFO -Message ("Минимум держать: {0}"   -f $KeepMinimum)

    # 3. SDelete — обязателен -------------------------------------------
    $sdelete = $null
    foreach ($candidate in @(
        'C:\Tools\SDelete\sdelete64.exe',
        'C:\Tools\sdelete64.exe',
        "$env:ProgramFiles\Sysinternals\sdelete64.exe"
    )) {
        if (Test-Path -LiteralPath $candidate) { $sdelete = $candidate; break }
    }
    if (-not $sdelete) {
        # На этот скрипт уже нельзя опереться — архив содержит
        # PII (имена пользователей), обычный Remove-Item оставит
        # следы на NTFS $MFT.
        Write-AuditLog -Level CRITICAL `
            -Message 'SDelete64 не найден. Ротация архивов отчётов требует безопасного удаления (DoD 3 прохода). Установите SDelete, затем повторите.'
        exit 2
    }
    Write-AuditLog -Level INFO -Message "SDelete: $sdelete"

    # 4. Получаем список кандидатов --------------------------------------
    $candidates = Get-ReportFileCandidates -Directory $retentionDir
    if ($candidates.Count -eq 0) {
        Write-AuditLog -Level INFO -Message 'Файлов, подлежащих ротации, не найдено. Выход.'
        return [pscustomobject]@{
            Deleted  = 0; Kept = 0; Errors = 0
            Duration = $sw.Elapsed
        }
    }
    Write-AuditLog -Level INFO -Message ("Найдено кандидатов: {0}" -f $candidates.Count)

    # 5. Группируем по "базовому имени архива" — чтобы
    #    .7z, .7z.sha256 и *.meta одного отчёта удалялись вместе
    #    (или не удалялись вместе). Основной "якорь" — это .7z.
    $archiveBaseNames = $candidates |
        Where-Object { $_.Name -like 'audit-report-*.7z' } |
        Select-Object -ExpandProperty BaseName
    # BaseName у "audit-report-2026-04-23T03-00-00Z.7z" → "audit-report-2026-04-23T03-00-00Z"

    # 5a. Сортируем архивы по дате записи, чтобы не удалить
    #     последние KeepMinimum штук.
    $archivesSorted = $candidates |
        Where-Object { $_.Name -like 'audit-report-*.7z' } |
        Sort-Object LastWriteTimeUtc -Descending

    $keepByPolicyNames = @()
    if ($archivesSorted.Count -le $KeepMinimum) {
        $keepByPolicyNames = $archivesSorted.BaseName
        Write-AuditLog -Level WARN -Message ("Всего архивов: {0} ≤ KeepMinimum {1}. Ничего не удаляем." -f $archivesSorted.Count, $KeepMinimum)
    } else {
        $keepByPolicyNames = ($archivesSorted | Select-Object -First $KeepMinimum).BaseName
    }

    # 6. Обход -----------------------------------------------------------
    foreach ($file in $candidates) {
        # 6.1 — Read-only / Hidden → хранить.
        if (Test-ShouldKeepFile -File $file) {
            $keptCount++
            continue
        }

        # 6.2 — Якорим на базовое имя архива.
        $anchor = $null
        foreach ($bn in $archiveBaseNames) {
            if ($file.Name -like ($bn + '*')) { $anchor = $bn; break }
        }

        # 6.3 — Если файл-сирота (нет парного .7z), применяем
        #       правило возраста напрямую. Это бывает, если кто-то
        #       вручную удалил .7z и оставил .meta/.json.
        if (-not $anchor) {
            if ($file.LastWriteTimeUtc -ge $threshold) {
                $keptCount++
                continue
            }
            # иначе — удалять
        } else {
            # 6.4 — Якорь есть: KeepMinimum защищает.
            if ($keepByPolicyNames -contains $anchor) {
                Write-AuditLog -Level INFO -Message ("Держим (KeepMinimum): {0}" -f $file.Name)
                $keptCount++
                continue
            }
            if ($file.LastWriteTimeUtc -ge $threshold) {
                $keptCount++
                continue
            }
            # иначе — удалять
        }

        # 6.5 — Удаляем.
        $target = $file.FullName
        $ageDays = [math]::Round(((Get-Date).ToUniversalTime() - $file.LastWriteTimeUtc).TotalDays, 1)

        if ($PSCmdlet.ShouldProcess($target, "SDelete (3 прохода, возраст $ageDays дн.)")) {
            try {
                Write-AuditLog -Level INFO -Message ("SDelete: {0} (возраст {1} дн., {2:N0} KB)" `
                    -f $file.Name, $ageDays, ($file.Length / 1KB))
                Invoke-SecureDelete -Path $target -Passes 3
                $deletedCount++
                $deletedFiles.Add($file.Name) | Out-Null
            } catch {
                $errorCount++
                Write-AuditLog -Level ERROR -Message ("Ошибка удаления {0}: {1}" -f $file.Name, $_.Exception.Message)
            }
        } else {
            # WhatIf путь.
            Write-AuditLog -Level INFO -Message ("(WhatIf) Удалил бы: {0}" -f $file.Name)
            $keptCount++
        }
    }

    # 7. Финальный проход: проверяем, что в каталоге нет
    #    разлинкованных временных файлов от Фаз 3/4.
    try {
        $residue = Test-CleanupResidue -Path $retentionDir `
                                       -Patterns @('*.dit', '*.tmp', 'SYSTEM', 'report-*.txt')
        if ($residue -and $residue.Count -gt 0) {
            foreach ($r in $residue) {
                Write-AuditLog -Level WARN -Message ("Обнаружен промежуточный файл: {0} — будет SDelete." -f $r)
                try {
                    Invoke-SecureDelete -Path $r -Passes 3 -IgnoreMissing
                } catch {
                    Write-AuditLog -Level ERROR -Message ("Не удалось удалить {0}: {1}" -f $r, $_.Exception.Message)
                    $errorCount++
                }
            }
        }
    } catch {
        Write-AuditLog -Level WARN -Message "Test-CleanupResidue завершился с ошибкой: $($_.Exception.Message)"
    }

    # 8. Итоги -----------------------------------------------------------
    $sw.Stop()
    if ($errorCount -gt 0) { $exitCode = 3 }

    Write-AuditLog -Level INFO -Message ('--- Итог ротации ---')
    Write-AuditLog -Level INFO -Message ("Удалено: {0}"  -f $deletedCount)
    Write-AuditLog -Level INFO -Message ("Оставлено: {0}" -f $keptCount)
    Write-AuditLog -Level INFO -Message ("Ошибок: {0}"   -f $errorCount)
    Write-AuditLog -Level INFO -Message ("Длительность: {0:N1} сек" -f $sw.Elapsed.TotalSeconds)
    Write-AuditLog -Level INFO -Message '=== Ротация завершена ==='

    return [pscustomobject]@{
        Deleted      = $deletedCount
        Kept         = $keptCount
        Errors       = $errorCount
        DeletedFiles = $deletedFiles.ToArray()
        Duration     = $sw.Elapsed
        TimestampUtc = (Get-Date).ToUniversalTime().ToString('o')
    }

} catch {
    Write-AuditLog -Level CRITICAL -Message "Фатальная ошибка ротации: $($_.Exception.Message)"
    Write-AuditLog -Level CRITICAL -Message $_.ScriptStackTrace
    exit 3
} finally {
    if ($exitCode -ne 0) { exit $exitCode }
}
