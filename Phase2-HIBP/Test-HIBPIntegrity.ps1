#Requires -Version 5.1
<#
.SYNOPSIS
    Фаза 2: проверка целостности словаря HIBP и состояния укрепления
    станции аудита перед началом работы с расшифрованным ntds.dit.

.DESCRIPTION
    Задача — убедиться, что словарь HIBP на станции аудита не был
    модифицирован после установки, и что платформа всё ещё настроена
    безопасно (BitLocker, pagefile, crash dump). Модифицированный
    словарь — серьёзный риск: атакующий, имеющий write-access к
    файлу hibp-ntlm.txt, может удалить из него собственный пароль и
    пройти весь аудит незаметно.

    Если любой из пунктов не проходит — скрипт бросает терминирующую
    ошибку, оркестратор ЛОВИТ её и прерывает весь прогон аудита,
    НЕ расшифровывая IFM-архив.

    Алгоритм (строго по регламенту):
        1. BitLocker FDE активен на всех фиксированных томах.
        2. Pagefile отключён (иначе NTLM-хеши из RAM могут утечь на диск).
        3. Crash dump отключён (дамп памяти = те же хеши на диске).
        4. Файл HIBP существует и доступен для чтения.
        5. SHA-256 файла HIBP совпадает с эталонным из конфига.

.PARAMETER ConfigPath
    Путь к audit.config.psd1.

.PARAMETER SkipPlatformChecks
    Только для лабораторных тестов: пропустить проверки BitLocker/pagefile/crashdump.
    В продакшене использовать НЕЛЬЗЯ.

.OUTPUTS
    Возвращает [PSCustomObject] с деталями проверок, если ВСЁ прошло.
    Иначе — бросает исключение.

.EXAMPLE
    # Из оркестратора:
    $result = .\Test-HIBPIntegrity.ps1 -ConfigPath 'C:\ProgramData\ADPasswordAudit\audit.config.psd1'
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory)] [string] $ConfigPath,
    [switch] $SkipPlatformChecks
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$repoRoot = Split-Path -Parent (Split-Path -Parent $MyInvocation.MyCommand.Path)
Import-Module (Join-Path $repoRoot 'Common\Logging.psm1') -Force
Import-Module (Join-Path $repoRoot 'Common\Crypto.psm1')  -Force
Import-Module (Join-Path $repoRoot 'Common\Config.psm1')  -Force

# Если оркестратор уже инициализировал логгер со своим CID — не
# затираем его, просто переключаем фазу.
if (-not (Get-AuditCorrelationId)) {
    Initialize-AuditLog -LogDirectory 'C:\AuditLogs' -PhaseName 'Phase2'
} else {
    Set-AuditPhase -PhaseName 'Phase2'
}

Write-AuditLog -Level INFO -Message '=== Фаза 2: проверка целостности HIBP и платформы ==='

# ---------- Проверки платформы ----------

function Test-BitLockerEnabled {
    Write-AuditLog -Level DEBUG -Message 'Проверка BitLocker на всех томах...'
    $bad = @()
    try {
        $vols = Get-BitLockerVolume -ErrorAction Stop |
                Where-Object { $_.VolumeType -eq 'Data' -or $_.MountPoint -match '^[A-Z]:$' }
    } catch {
        throw "Не удалось получить список томов BitLocker: $($_.Exception.Message). Модуль BitLocker установлен?"
    }

    foreach ($v in $vols) {
        if ($v.ProtectionStatus -ne 'On' -or $v.VolumeStatus -ne 'FullyEncrypted') {
            $bad += "{0} (Protection={1}, Status={2})" -f `
                $v.MountPoint, $v.ProtectionStatus, $v.VolumeStatus
        }
    }
    if ($bad.Count -gt 0) {
        throw "BitLocker не полностью включён на томах: $($bad -join '; ')"
    }
    Write-AuditLog -Level INFO -Message ("BitLocker: OK ({0} томов зашифровано)" -f $vols.Count)
}

function Test-PagefileDisabled {
    $pf = Get-CimInstance -ClassName Win32_PageFileSetting -ErrorAction SilentlyContinue
    if ($pf) {
        throw "Pagefile включён: $($pf.Name). Отключите его, чтобы NTLM-хеши не могли быть записаны на диск."
    }
    Write-AuditLog -Level INFO -Message 'Pagefile: OK (отключён)'
}

function Test-CrashDumpDisabled {
    $cc = Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\CrashControl' -ErrorAction SilentlyContinue
    if (-not $cc) {
        Write-AuditLog -Level WARN -Message 'Ключ CrashControl в реестре отсутствует — не могу проверить.'
        return
    }
    if ($cc.CrashDumpEnabled -ne 0) {
        throw ("Crash dump включён (CrashDumpEnabled={0}). Дамп памяти способен сохранить на диск содержимое RAM со всеми хешами. Установите CrashDumpEnabled=0." -f $cc.CrashDumpEnabled)
    }
    Write-AuditLog -Level INFO -Message 'Crash dump: OK (отключён)'
}

# ---------- Проверка HIBP ----------

function Test-HibpDictionary {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [string] $HibpPath,
        [Parameter(Mandatory)] [string] $ExpectedSha256
    )

    if ([string]::IsNullOrWhiteSpace($ExpectedSha256) -or $ExpectedSha256 -match '^0{64}$') {
        throw "Эталонный SHA-256 в конфиге не установлен (значение-заглушка). Перезапустите Install-AuditStation.ps1 для импорта словаря."
    }

    if (-not (Test-Path -LiteralPath $HibpPath)) {
        throw "Словарь HIBP не найден: $HibpPath"
    }

    $size = (Get-Item -LiteralPath $HibpPath).Length
    Write-AuditLog -Level INFO -Message ("Словарь: {0}, размер {1:N0} MB" -f $HibpPath, ($size / 1MB))

    # На очень больших HIBP (~30 GB) SHA-256 считается 5-15 минут —
    # вызывающий должен закладывать таймаут.
    Write-AuditLog -Level INFO -Message 'Вычисление SHA-256 словаря (может занять несколько минут)...'
    $sw = [System.Diagnostics.Stopwatch]::StartNew()
    $actual = Get-Sha256Hash -Path $HibpPath
    $sw.Stop()

    Write-AuditLog -Level INFO -Message ("SHA-256 вычислен за {0:N1} сек" -f $sw.Elapsed.TotalSeconds)
    Write-AuditLog -Level INFO -Message "  ожидается: $ExpectedSha256"
    Write-AuditLog -Level INFO -Message "  факт:      $actual"

    if ($actual -ne $ExpectedSha256) {
        # CRITICAL — попадёт в Event Log и в SIEM.
        Write-AuditLog -Level CRITICAL `
            -Message 'SHA-256 словаря HIBP НЕ СОВПАДАЕТ с эталоном. Возможна подмена словаря. Аудит прерван.'
        throw 'HIBP integrity check FAILED. Checksum mismatch.'
    }

    Write-AuditLog -Level INFO -Message 'SHA-256 словаря HIBP совпал с эталоном.'
    return [pscustomobject]@{
        HibpPath   = $HibpPath
        SizeMB     = [math]::Round($size / 1MB, 2)
        Sha256     = $actual
        DurationS  = [math]::Round($sw.Elapsed.TotalSeconds, 1)
    }
}

# ---------- Main ----------

try {
    $env:AD_AUDIT_CONFIG = $ConfigPath
    $cfg = Get-AuditConfig

    # 1-3. Платформа
    if (-not $SkipPlatformChecks) {
        Test-BitLockerEnabled
        Test-PagefileDisabled
        Test-CrashDumpDisabled
    } else {
        Write-AuditLog -Level WARN -Message 'Платформенные проверки пропущены (-SkipPlatformChecks). Только для лабы!'
    }

    # 4-5. Словарь
    $hibpResult = Test-HibpDictionary `
        -HibpPath       $cfg.HibpFilePath `
        -ExpectedSha256 $cfg.HibpExpectedSha256

    Write-AuditLog -Level INFO -Message '=== Фаза 2: все проверки пройдены ==='

    # Возвращаем результат оркестратору.
    return [pscustomobject]@{
        Phase       = 'Phase2-HIBP'
        Success     = $true
        HibpSizeMB  = $hibpResult.SizeMB
        HibpSha256  = $hibpResult.Sha256
        TimestampUtc = (Get-Date).ToUniversalTime().ToString('o')
    }

} catch {
    Write-AuditLog -Level CRITICAL -Message "Фаза 2 провалена: $($_.Exception.Message)"
    # Re-throw, чтобы оркестратор прервал аудит.
    throw
}
