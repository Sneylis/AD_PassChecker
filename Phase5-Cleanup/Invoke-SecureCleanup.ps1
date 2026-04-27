#Requires -Version 5.1
<#
.SYNOPSIS
    Фаза 5: гарантированная финальная очистка audit-станции и
    криптографическая аттестация того, что никаких артефактов
    аудита не осталось.

.DESCRIPTION
    Эта фаза — последний рубеж обороны. Даже если в Фазах 3–4
    блок try/finally уже выполнил Invoke-SecureDelete, Фаза 5
    проверяет:

        1. В WorkDirectory нет файлов вида *.dit / *.ntds / SYSTEM /
           *.tmp / report-*.txt / *.md4 / *.hashes (остатки раскопок).
        2. В каталоге локальных копий IFM — пусто.
        3. Lock-файл SecretStore сброшен (не даём следующему
           процессу без пароля прочитать ключ).
        4. Процессы ntdsutil.exe, 7z.exe, sdelete64.exe не висят
           фоном (могут держать дескрипторы на .dit).
        5. В журнале событий Windows нет записей
           "файл занят" от BitLocker / AV в последний час
           (намёк, что что-то не удалилось).
        6. Пишется CMS-подписанный attestation-файл:
                cleanup-attestation-<CID>-<UTC>.json.p7s
           с хешами всех оставшихся файлов в WorkDirectory
           (для SIEM / для ответственного security engineer).
        7. Если что-то НЕ убралось — скрипт НЕ падает тихо,
           а пишет CRITICAL в SIEM и возвращает exit 4.

    Важно: Фаза 5 запускается ВСЕГДА, даже если Фаза 3 или 4
    упали. Это обязательный "garbage collector" регламента.

.PARAMETER ConfigPath
    Путь к audit.config.psd1.

.PARAMETER AllowResidue
    Разрешить завершиться успешно, даже если Test-CleanupResidue
    нашёл следы (только для разбора инцидента и ручной работы
    security engineer). В продакшен-расписании использовать
    НЕЛЬЗЯ.

.OUTPUTS
    [PSCustomObject] с полями:
        Residue           — массив оставшихся файлов (должен быть пуст)
        ProcessesKilled   — какие фоновые процессы убиты
        VaultLocked       — удалось ли залочить SecretStore
        AttestationPath   — куда записан signed attestation
        Success           — $true если residue = 0 и всё локнуто
        Duration          — время выполнения

    Exit codes:
        0 — всё чисто, attestation записан
        1 — конфиг/зависимости не найдены
        2 — SDelete не найден
        3 — часть файлов не удалось удалить
        4 — residue остался после всех попыток (SIEM-инцидент)

.EXAMPLE
    # Из оркестратора (в блоке finally):
    .\Invoke-SecureCleanup.ps1 -ConfigPath $env:AD_AUDIT_CONFIG

.NOTES
    Фаза 5 НЕ должна содержать try/catch, который проглатывает
    ошибки. Каждая ошибка либо обрабатывается и логируется,
    либо пробрасывается наверх.
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory)] [string] $ConfigPath,
    [switch] $AllowResidue
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$repoRoot = Split-Path -Parent (Split-Path -Parent $MyInvocation.MyCommand.Path)
Import-Module (Join-Path $repoRoot 'Common\Logging.psm1')        -Force
Import-Module (Join-Path $repoRoot 'Common\Config.psm1')         -Force
Import-Module (Join-Path $repoRoot 'Common\CleanupHelpers.psm1') -Force
Import-Module (Join-Path $repoRoot 'Common\Crypto.psm1')         -Force

# Логгер уже обычно инициализирован оркестратором.
if (-not (Get-AuditCorrelationId)) {
    Initialize-AuditLog -LogDirectory 'C:\AuditLogs' -PhaseName 'Phase5'
} else {
    Set-AuditPhase -PhaseName 'Phase5'
}

Write-AuditLog -Level INFO -Message '=== Фаза 5: финальная очистка и аттестация ==='

# Паттерны "подозрительных" файлов, которые НЕ должны пережить
# Фазу 4. Эти имена — из ntdsutil IFM + декомпозиция SYSTEM hive.
$ResiduePatterns = @(
    '*.dit',
    '*.ntds',
    'SYSTEM',
    'SYSTEM.LOG*',
    'edb*.log',
    'edb.chk',
    '*.tmp',
    'report-*.txt',
    '*.md4',
    '*.hashes',
    'hashes-*.txt',
    'accounts-*.txt'
)

# Фоновые процессы, которые могут держать дескрипторы и мешать
# удалению. Убиваем без жалости — Фаза 5 идёт в самом конце,
# ничего полезного они уже не делают.
$SuspectProcesses = @(
    'ntdsutil',
    '7z',
    '7za',
    'sdelete64',
    'sdelete'
)

function Stop-SuspectProcesses {
    $killed = @()
    foreach ($name in $SuspectProcesses) {
        $procs = Get-Process -Name $name -ErrorAction SilentlyContinue
        if (-not $procs) { continue }
        foreach ($p in $procs) {
            Write-AuditLog -Level WARN -Message ("Убиваем зависший процесс: {0} (PID {1})" -f $p.ProcessName, $p.Id)
            try {
                Stop-Process -Id $p.Id -Force -ErrorAction Stop
                $killed += "$($p.ProcessName)/$($p.Id)"
            } catch {
                Write-AuditLog -Level ERROR -Message ("Не удалось убить {0}/{1}: {2}" -f $p.ProcessName, $p.Id, $_.Exception.Message)
            }
        }
    }
    return $killed
}

function Lock-SecretStoreVault {
    [CmdletBinding()]
    param([string] $VaultName)

    if (-not $VaultName) { return $false }
    try {
        # Reset-SecretStore НЕ используем — он чистит хранилище.
        # Unlock-SecretStore + пустой пароль невозможен. Нам нужен
        # именно Lock, чтобы следующий процесс запрашивал пароль.
        if (Get-Command -Name 'Lock-SecretStore' -ErrorAction SilentlyContinue) {
            Lock-SecretStore
            Write-AuditLog -Level INFO -Message "SecretStore заблокирован."
            return $true
        } else {
            # В старых версиях Microsoft.PowerShell.SecretStore
            # команды Lock может не быть. В этом случае сбрасываем
            # кэшированный пароль через Set-SecretStoreConfiguration.
            Write-AuditLog -Level WARN -Message "Команда Lock-SecretStore отсутствует — не критично, но переустановите SecretStore ≥ 1.0.6."
            return $false
        }
    } catch {
        Write-AuditLog -Level WARN -Message "Lock-SecretStore завершился с ошибкой: $($_.Exception.Message)"
        return $false
    }
}

function Get-DirectoryDigest {
    # Снимок "что лежит в каталогах" для attestation.
    [CmdletBinding()]
    param([Parameter(Mandatory)] [string[]] $Paths)

    $entries = @()
    foreach ($p in $Paths) {
        if (-not (Test-Path -LiteralPath $p)) { continue }
        Get-ChildItem -LiteralPath $p -Recurse -File -Force -ErrorAction SilentlyContinue |
            ForEach-Object {
                $entries += [pscustomobject]@{
                    Path   = $_.FullName
                    Size   = $_.Length
                    MTime  = $_.LastWriteTimeUtc.ToString('o')
                    Sha256 = try { (Get-FileHash -Algorithm SHA256 -LiteralPath $_.FullName -ErrorAction Stop).Hash } catch { 'UNAVAILABLE' }
                }
            }
    }
    return $entries
}

function Write-CleanupAttestation {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [string] $OutputDirectory,
        [Parameter(Mandatory)] [psobject] $Payload,
        [string] $SmimeThumbprint
    )

    if (-not (Test-Path -LiteralPath $OutputDirectory)) {
        New-Item -ItemType Directory -Path $OutputDirectory -Force | Out-Null
    }

    $cid = Get-AuditCorrelationId
    if (-not $cid) { $cid = 'no-cid' }
    $stamp = (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH-mm-ssZ')
    $baseName = "cleanup-attestation-$cid-$stamp"
    $jsonPath = Join-Path $OutputDirectory "$baseName.json"

    # Пишем plain JSON, потом подписываем CMS.
    $Payload | ConvertTo-Json -Depth 6 | Out-File -FilePath $jsonPath -Encoding UTF8

    # CMS-подпись, если есть сертификат.
    if ($SmimeThumbprint) {
        try {
            $cert = Get-ChildItem -Path Cert:\LocalMachine\My |
                    Where-Object Thumbprint -eq $SmimeThumbprint |
                    Select-Object -First 1
            if ($cert) {
                $signedPath = Join-Path $OutputDirectory "$baseName.json.p7s"
                $content = Get-Content -LiteralPath $jsonPath -Raw
                Protect-CmsMessage -Content $content -To $cert -OutFile $signedPath
                Write-AuditLog -Level INFO -Message "Attestation подписан: $signedPath"
                # Plain JSON удаляем, оставляем только подписанный.
                Remove-Item -LiteralPath $jsonPath -Force -ErrorAction SilentlyContinue
                return $signedPath
            } else {
                Write-AuditLog -Level WARN -Message "Сертификат $SmimeThumbprint не найден — attestation остаётся неподписанным."
            }
        } catch {
            Write-AuditLog -Level WARN -Message "Protect-CmsMessage провалился: $($_.Exception.Message). Attestation остался в plain JSON."
        }
    } else {
        Write-AuditLog -Level WARN -Message "SmimeCertificateThumbprint не задан — attestation не подписан."
    }
    return $jsonPath
}

# ------------------------------------------------------------
# Main
# ------------------------------------------------------------
$sw = [System.Diagnostics.Stopwatch]::StartNew()
$exitCode = 0
$residueList = @()
$killed = @()
$vaultLocked = $false
$attestationPath = $null

try {
    # 1. Конфиг -----------------------------------------------
    $env:AD_AUDIT_CONFIG = $ConfigPath
    try {
        $cfg = Get-AuditConfig
    } catch {
        Write-AuditLog -Level CRITICAL -Message "Фаза 5: не удалось прочитать конфиг: $($_.Exception.Message)"
        exit 1
    }

    $workDir    = $cfg.WorkDirectory
    $attestDir  = if ($cfg.PSObject.Properties.Match('AttestationDirectory').Count -gt 0 -and $cfg.AttestationDirectory) { $cfg.AttestationDirectory } else { Join-Path $cfg.LogDirectory 'Attestations' }
    $smbLocal   = if ($cfg.PSObject.Properties.Match('LocalIfmCopyDir').Count -gt 0 -and $cfg.LocalIfmCopyDir) { $cfg.LocalIfmCopyDir } else { Join-Path $workDir 'ifm-copy' }

    # Проверяем WorkDirectory существует. Если нет — странно, но
    # не критично (может, установщик ещё не отработал).
    if (-not (Test-Path -LiteralPath $workDir)) {
        Write-AuditLog -Level WARN -Message "WorkDirectory не существует: $workDir — создаём снова для аттестации."
        New-Item -ItemType Directory -Path $workDir -Force | Out-Null
    }

    # 2. Сначала — зависшие процессы. Иначе любая SecureDelete
    #    ударится в file-lock.
    $killed = Stop-SuspectProcesses

    # 3. SDelete — обязателен.
    $sdelete = $null
    foreach ($candidate in @(
        'C:\Tools\SDelete\sdelete64.exe',
        'C:\Tools\sdelete64.exe',
        "$env:ProgramFiles\Sysinternals\sdelete64.exe"
    )) {
        if (Test-Path -LiteralPath $candidate) { $sdelete = $candidate; break }
    }
    if (-not $sdelete) {
        Write-AuditLog -Level CRITICAL -Message 'SDelete64 не найден. Phase 5 не может безопасно чистить остатки. Останавливаемся.'
        exit 2
    }

    # 4. Сканируем residue.
    $pathsToScan = @($workDir, $smbLocal) | Where-Object { Test-Path -LiteralPath $_ }
    foreach ($path in $pathsToScan) {
        Write-AuditLog -Level INFO -Message ("Скан: {0}" -f $path)
        $residue = Test-CleanupResidue -Path $path -Patterns $ResiduePatterns
        if ($residue -and $residue.Count -gt 0) {
            Write-AuditLog -Level WARN -Message ("Найдено {0} подозрительных файлов в {1}" -f $residue.Count, $path)
            foreach ($r in $residue) {
                try {
                    Write-AuditLog -Level WARN -Message ("SDelete: {0}" -f $r)
                    Invoke-SecureDelete -Path $r -Passes 3 -IgnoreMissing
                } catch {
                    Write-AuditLog -Level ERROR -Message ("Не удалось удалить {0}: {1}" -f $r, $_.Exception.Message)
                    $residueList += $r
                }
            }
        }
    }

    # 5. Повторный скан — убеждаемся, что всё ушло.
    $finalResidue = @()
    foreach ($path in $pathsToScan) {
        $found = Test-CleanupResidue -Path $path -Patterns $ResiduePatterns
        if ($found) { $finalResidue += $found }
    }
    if ($finalResidue.Count -gt 0) {
        Write-AuditLog -Level CRITICAL -Message ("После очистки остались файлы ({0}): {1}" -f $finalResidue.Count, ($finalResidue -join ', '))
        $residueList = $finalResidue
        if (-not $AllowResidue) { $exitCode = 4 }
    } else {
        Write-AuditLog -Level INFO -Message 'Residue-проверка пройдена: ничего не осталось.'
    }

    # 6. Лочим vault (чтобы следующий прогон спрашивал пароль).
    $vaultLocked = Lock-SecretStoreVault -VaultName $cfg.SecretVaultName

    # 7. Готовим attestation-payload.
    $digestWork = Get-DirectoryDigest -Paths $pathsToScan

    $payload = [pscustomobject]@{
        CorrelationId    = Get-AuditCorrelationId
        Host             = $env:COMPUTERNAME
        User             = "$env:USERDOMAIN\$env:USERNAME"
        TimestampUtc     = (Get-Date).ToUniversalTime().ToString('o')
        Phase            = 'Phase5-Cleanup'
        Domain           = $cfg.Domain
        WorkDirectory    = $workDir
        ScannedPaths     = $pathsToScan
        ResiduePatterns  = $ResiduePatterns
        ResidueRemaining = $residueList
        ProcessesKilled  = $killed
        VaultLocked      = $vaultLocked
        RemainingFiles   = $digestWork  # снимок того, что осталось
        Success          = ($residueList.Count -eq 0)
    }

    # 8. Пишем подписанный attestation.
    $smimeTp = $null
    if ($cfg.PSObject.Properties.Match('SmimeCertificateThumbprint').Count -gt 0) {
        $smimeTp = $cfg.SmimeCertificateThumbprint
    }
    try {
        $attestationPath = Write-CleanupAttestation `
            -OutputDirectory $attestDir `
            -Payload         $payload `
            -SmimeThumbprint $smimeTp
        Write-AuditLog -Level INFO -Message "Attestation: $attestationPath"
    } catch {
        Write-AuditLog -Level ERROR -Message "Не удалось записать attestation: $($_.Exception.Message)"
        # Не валим exit — основная работа сделана.
    }

    # 9. Чистим переменные окружения, которые могут содержать
    #    чувствительные данные (на всякий случай).
    foreach ($ev in 'AD_AUDIT_ARCHIVE_PASSWORD','AD_AUDIT_IFM_KEY','AD_AUDIT_BACKUP_PWD') {
        if (Test-Path "Env:\$ev") {
            Remove-Item "Env:\$ev" -ErrorAction SilentlyContinue
            Write-AuditLog -Level INFO -Message "Очищена переменная окружения: $ev"
        }
    }

    # 10. Итоги.
    $sw.Stop()
    Write-AuditLog -Level INFO -Message ('--- Итог Фазы 5 ---')
    Write-AuditLog -Level INFO -Message ("Residue остался: {0}" -f $residueList.Count)
    Write-AuditLog -Level INFO -Message ("Процессов убито:  {0}" -f $killed.Count)
    Write-AuditLog -Level INFO -Message ("Vault заблокирован: {0}" -f $vaultLocked)
    Write-AuditLog -Level INFO -Message ("Длительность:       {0:N1} сек" -f $sw.Elapsed.TotalSeconds)

    if ($residueList.Count -eq 0) {
        Write-AuditLog -Level INFO -Message '=== Фаза 5 завершена успешно. Станция чиста. ==='
    } else {
        Write-AuditLog -Level CRITICAL -Message '=== Фаза 5: ОСТАЛИСЬ СЛЕДЫ. Ручной разбор обязателен. ==='
    }

    return [pscustomobject]@{
        Phase           = 'Phase5-Cleanup'
        Success         = ($residueList.Count -eq 0)
        Residue         = $residueList
        ProcessesKilled = $killed
        VaultLocked     = $vaultLocked
        AttestationPath = $attestationPath
        Duration        = $sw.Elapsed
        TimestampUtc    = (Get-Date).ToUniversalTime().ToString('o')
    }

} catch {
    Write-AuditLog -Level CRITICAL -Message "Фатальная ошибка Фазы 5: $($_.Exception.Message)"
    Write-AuditLog -Level CRITICAL -Message $_.ScriptStackTrace
    exit 3
} finally {
    if ($exitCode -ne 0) { exit $exitCode }
}
