#Requires -Version 5.1
#Requires -Modules DSInternals
<#
.SYNOPSIS
    Фаза 3: аудит качества паролей через DSInternals.Test-PasswordQuality.

.DESCRIPTION
    Сердце системы. На станции аудита в изолированном VLAN:
        1. Получает AES-256 ключ из SecretStore.
        2. Распаковывает IFM-архив во временный каталог (BitLocker-том).
        3. Извлекает BootKey из registry\SYSTEM.
        4. Загружает все учётные записи через Get-ADDBAccount.
        5. Прогоняет Test-PasswordQuality со всеми проверками:
              - WeakPassword (HIBP)
              - DuplicatePasswordGroups
              - EmptyPassword / PasswordNotRequired
              - LMHash
              - DefaultComputerPassword
              - PasswordNeverExpires
              - AESKeysMissing
              - PreAuthNotRequired (AS-REP Roastable)
              - DESEncryptionOnly
              - SmartCardUsersWithPassword
              - Kerberoastable (SPN с паролем)
              - DelegatableAdmins
              - а также самописная проверка SamAccountName == пароль
                (DSInternals её не делает напрямую, но пары plaintext
                нам и не нужны — используем подсказку: если у аккаунта
                NT-хеш равен NT-хешу от его же sAMAccountName).
        6. Сериализует результат в JSON БЕЗ ХЕШЕЙ И ПАРОЛЕЙ — только
           SamAccountName + категория проблемы.
        7. В finally: SDelete временного каталога, обнуление ключа,
           форсированный GC.

    Важно: весь временный каталог должен быть на BitLocker-томе. По
    умолчанию берётся из cfg.WorkDirectory. Перед запуском проверяется,
    что том зашифрован.

.PARAMETER ConfigPath
    Путь к audit.config.psd1.

.PARAMETER ArchivePath
    Путь к IFM-архиву на SMB-шаре. Если не задан — оркестратор передаст.

.PARAMETER ResultJsonPath
    Куда сохранить JSON с результатами. Если не задан — кладётся в
    cfg.WorkDirectory\audit-result-<cid>.json.

.OUTPUTS
    [PSCustomObject] с путём к JSON и сводкой. JSON читается Фазой 4.

.NOTES
    Потребление памяти для 5000 пользователей: 300-500 MB.
    Время: 2-5 минут + время SHA-проверки HIBP (не входит сюда,
    это Фаза 2).
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory)] [string] $ConfigPath,
    [Parameter(Mandatory)] [string] $ArchivePath,
    [string] $ResultJsonPath
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$repoRoot = Split-Path -Parent (Split-Path -Parent $MyInvocation.MyCommand.Path)
Import-Module (Join-Path $repoRoot 'Common\Logging.psm1')        -Force
Import-Module (Join-Path $repoRoot 'Common\Crypto.psm1')         -Force
Import-Module (Join-Path $repoRoot 'Common\CleanupHelpers.psm1') -Force
Import-Module (Join-Path $repoRoot 'Common\Config.psm1')         -Force
Import-Module DSInternals -Force

if (-not (Get-AuditCorrelationId)) {
    Initialize-AuditLog -LogDirectory 'C:\AuditLogs' -PhaseName 'Phase3'
} else {
    Set-AuditPhase -PhaseName 'Phase3'
}
$cid = Get-AuditCorrelationId

Write-AuditLog -Level INFO -Message '=== Фаза 3: аудит паролей DSInternals ==='
Write-AuditLog -Level INFO -Message "Архив: $ArchivePath"

# ---------- Главные шаги ----------

function Assert-WorkDirectoryEncrypted {
    [CmdletBinding()]
    param([Parameter(Mandatory)] [string] $Path)

    $drive = (Split-Path -Qualifier $Path).TrimEnd(':')
    $mount = "${drive}:"
    $vol   = Get-BitLockerVolume -MountPoint $mount -ErrorAction SilentlyContinue
    if (-not $vol) {
        throw "Не удалось получить статус BitLocker для $mount"
    }
    if ($vol.ProtectionStatus -ne 'On' -or $vol.VolumeStatus -ne 'FullyEncrypted') {
        throw "Том $mount не зашифрован BitLocker (Status=$($vol.VolumeStatus), Protection=$($vol.ProtectionStatus)). Расшифровывать ntds.dit на незашифрованном томе запрещено."
    }
    Write-AuditLog -Level DEBUG -Message "Том $mount: BitLocker OK"
}

function Find-DatabaseFiles {
    <#
    .SYNOPSIS
        Находит ntds.dit и registry\SYSTEM в распакованном IFM.
        ntdsutil складывает их в Active Directory\ntds.dit и registry\SYSTEM,
        но регистр и точное название папки зависят от версии Windows —
        ищем рекурсивно.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)] [string] $Root)

    $dit = Get-ChildItem -LiteralPath $Root -Recurse -Filter 'ntds.dit' -ErrorAction SilentlyContinue |
           Select-Object -First 1
    $sys = Get-ChildItem -LiteralPath $Root -Recurse -ErrorAction SilentlyContinue |
           Where-Object { $_.Name -eq 'SYSTEM' -and -not $_.PSIsContainer } |
           Select-Object -First 1

    if (-not $dit) { throw "В распакованном архиве не найден ntds.dit" }
    if (-not $sys) { throw "В распакованном архиве не найден registry\SYSTEM" }

    Write-AuditLog -Level INFO -Message ("ntds.dit: {0} ({1:N1} MB)" -f $dit.FullName, ($dit.Length / 1MB))
    Write-AuditLog -Level INFO -Message ("SYSTEM:   {0} ({1:N0} KB)"  -f $sys.FullName, ($sys.Length / 1KB))

    return [pscustomobject]@{
        NtdsDit = $dit.FullName
        System  = $sys.FullName
    }
}

function Invoke-DSInternalsAudit {
    <#
    .SYNOPSIS
        Ядро фазы: извлекает BootKey, читает ntds.dit, прогоняет
        Test-PasswordQuality, сериализует результат без секретов.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [string] $NtdsDitPath,
        [Parameter(Mandatory)] [string] $SystemHivePath,
        [Parameter(Mandatory)] [string] $HibpFile
    )

    Write-AuditLog -Level INFO -Message 'Получение BootKey из SYSTEM hive...'
    $bootKey = Get-BootKey -SystemHivePath $SystemHivePath
    if (-not $bootKey) { throw 'Get-BootKey вернул пустое значение.' }
    Write-AuditLog -Level INFO -Message 'BootKey получен.'

    try {
        Write-AuditLog -Level INFO -Message 'Загрузка учётных записей из ntds.dit...'
        $sw = [System.Diagnostics.Stopwatch]::StartNew()
        # Get-ADDBAccount -All возвращает коллекцию DSAccount. Для 500-5000
        # пользователей это ~200-500 MB в памяти.
        $accounts = Get-ADDBAccount -All -DBPath $NtdsDitPath -BootKey $bootKey
        $sw.Stop()
        Write-AuditLog -Level INFO -Message ("Загружено {0} аккаунтов за {1:N1} сек" -f `
            $accounts.Count, $sw.Elapsed.TotalSeconds)

        # Test-PasswordQuality — основная проверка.
        # -IncludeDisabledAccounts: проверяем даже отключённые, т.к.
        #   отключённые с паролем — потенциальный вектор для атакующего.
        # -WeakPasswordHashesFile: путь к NTLM-хешам HIBP.
        Write-AuditLog -Level INFO -Message 'Запуск Test-PasswordQuality...'
        $sw.Restart()
        $report = $accounts | Test-PasswordQuality `
            -WeakPasswordHashesFile $HibpFile `
            -IncludeDisabledAccounts
        $sw.Stop()
        Write-AuditLog -Level INFO -Message ("Test-PasswordQuality завершён за {0:N1} сек" -f $sw.Elapsed.TotalSeconds)

        # Самописная проверка: NT-хеш пароля совпадает с NT-хешем от
        # собственного sAMAccountName. DSInternals напрямую этого не
        # проверяет; делаем, потому что регламент требует.
        Write-AuditLog -Level INFO -Message 'Проверка "SamAccountName == пароль"...'
        $samEqualsPwd = @()
        foreach ($acc in $accounts) {
            if (-not $acc.NTHash) { continue }
            $candidate = Get-NtlmHashFromString -Password $acc.SamAccountName
            $actual    = -join ($acc.NTHash | ForEach-Object { $_.ToString('x2') })
            if ($actual.ToUpperInvariant() -eq $candidate.ToUpperInvariant()) {
                $samEqualsPwd += $acc.SamAccountName
            }
        }
        if ($samEqualsPwd.Count -gt 0) {
            Write-AuditLog -Level WARN -Message ("Найдено {0} аккаунтов, где пароль = SamAccountName" -f $samEqualsPwd.Count)
        }

        # Извлекаем из $report только имена, никаких хешей.
        # Свойства DSInternals.PasswordQualityTestResult (v4.7+):
        #   WeakPassword, DuplicatePasswordGroups, EmptyPassword,
        #   LMHash, DefaultComputerPassword, PasswordNotRequired,
        #   PasswordNeverExpires, AESKeysMissing, PreAuthNotRequired,
        #   DESEncryptionOnly, DelegatableAdmins, SmartCardUsersWithPassword,
        #   Kerberoastable, DuplicateNtHashes, ClearTextPassword,
        #   HistoricalPasswords
        $result = [ordered]@{
            CorrelationId     = Get-AuditCorrelationId
            TimestampUtc      = (Get-Date).ToUniversalTime().ToString('o')
            TotalAccounts     = $accounts.Count
            EnabledAccounts   = ($accounts | Where-Object { -not $_.Disabled }).Count
            Categories = [ordered]@{
                WeakPassword               = @($report.WeakPassword)               # HIBP match
                DuplicatePasswordGroups    = @()                                   # заполним ниже
                EmptyPassword              = @($report.EmptyPassword)
                LMHashPresent              = @($report.LMHash)
                DefaultComputerPassword    = @($report.DefaultComputerPassword)
                PasswordNotRequired        = @($report.PasswordNotRequired)
                PasswordNeverExpires       = @($report.PasswordNeverExpires)
                AESKeysMissing             = @($report.AESKeysMissing)
                PreAuthNotRequired         = @($report.PreAuthNotRequired)        # AS-REP Roastable
                DESEncryptionOnly          = @($report.DESEncryptionOnly)
                DelegatableAdmins          = @($report.DelegatableAdmins)
                SmartCardUsersWithPassword = @($report.SmartCardUsersWithPassword)
                Kerberoastable             = @($report.Kerberoastable)
                ClearTextPassword          = @($report.ClearTextPassword)
                DuplicateNtHashes          = @($report.DuplicateNtHashes)
                SamAccountNameAsPassword   = $samEqualsPwd
            }
        }

        # DuplicatePasswordGroups — это Dictionary<byte[], List<string>>.
        # Хеши в ключах НЕ сохраняем — только имена, сгруппированные по
        # анонимизированному индексу группы.
        $groupIdx = 1
        foreach ($kv in $report.DuplicatePasswordGroups.GetEnumerator()) {
            $result.Categories.DuplicatePasswordGroups += [pscustomobject]@{
                GroupId  = "G$groupIdx"
                Accounts = @($kv.Value)
            }
            $groupIdx++
        }

        # Сводка по категориям — пригодится в отчёте.
        $summary = [ordered]@{}
        foreach ($cat in $result.Categories.Keys) {
            $val = $result.Categories[$cat]
            if ($cat -eq 'DuplicatePasswordGroups') {
                $summary[$cat] = ($val | Measure-Object).Count
            } else {
                $summary[$cat] = @($val).Count
            }
        }
        $result.Summary = $summary

        return $result
    } finally {
        # BootKey обнуляем сразу после использования.
        if ($bootKey) {
            try {
                # BootKey — SecureString. Уничтожаем.
                if ($bootKey -is [System.Security.SecureString]) {
                    $bootKey.Dispose()
                }
            } catch { }
            $bootKey = $null
        }
        # Массив аккаунтов — потенциально сотни MB с NT-хешами.
        # Обнуляем перед возвратом управления.
        if ($accounts) {
            [Array]::Clear($accounts, 0, $accounts.Count) 2>$null
            $accounts = $null
        }
        [System.GC]::Collect()
        [System.GC]::WaitForPendingFinalizers()
    }
}

# ---------- Main ----------

$exitCode   = 0
$tempDir    = $null
$aesKey     = $null
$archiveLocal = $null

try {
    $env:AD_AUDIT_CONFIG = $ConfigPath
    $cfg = Get-AuditConfig

    if (-not $ResultJsonPath) {
        $ResultJsonPath = Join-Path $cfg.WorkDirectory "audit-result-$cid.json"
    }

    if (-not (Test-Path -LiteralPath $ArchivePath)) {
        throw "IFM-архив не найден: $ArchivePath"
    }

    Assert-WorkDirectoryEncrypted -Path $cfg.WorkDirectory

    # Делаем локальную копию архива со SMB в WorkDirectory,
    # чтобы случайные разрывы сети не ломали чтение ntds.dit посередине.
    $archiveLocal = Join-Path $cfg.WorkDirectory ("incoming-" + (Split-Path -Leaf $ArchivePath))
    Copy-Item -LiteralPath $ArchivePath -Destination $archiveLocal -Force
    Write-AuditLog -Level INFO -Message "Архив скопирован локально: $archiveLocal"

    Invoke-WithGuaranteedCleanup `
        -Action {
            # 1. Ключ
            $script:aesKey = Get-AesKeyFromSecretStore -Name $cfg.IfmKeyName -VaultName $cfg.SecretVaultName

            # 2. Распаковка
            $script:tempDir = Join-Path $cfg.WorkDirectory "ifm-unpack-$cid"
            if (Test-Path -LiteralPath $script:tempDir) {
                Invoke-SecureDelete -Path $script:tempDir -Passes 3 -Recurse -IgnoreMissing
            }
            New-Item -ItemType Directory -Path $script:tempDir -Force | Out-Null
            Write-AuditLog -Level INFO -Message "Распаковка архива в $($script:tempDir)..."
            Unprotect-Archive -Archive $archiveLocal -Destination $script:tempDir -Password $script:aesKey
            Write-AuditLog -Level INFO -Message 'Архив распакован.'

            # 3-6. Ядро
            $files = Find-DatabaseFiles -Root $script:tempDir
            $result = Invoke-DSInternalsAudit `
                -NtdsDitPath    $files.NtdsDit `
                -SystemHivePath $files.System `
                -HibpFile       $cfg.HibpFilePath

            # 7. Сохранение JSON
            $json = $result | ConvertTo-Json -Depth 6
            Set-Content -LiteralPath $ResultJsonPath -Value $json -Encoding UTF8
            Write-AuditLog -Level INFO -Message "Результат сохранён: $ResultJsonPath"

            # Сводка в лог (без имён, чтобы не разводить PII в логах).
            Write-AuditLog -Level INFO -Message 'Сводка по категориям:'
            foreach ($k in $result.Summary.Keys) {
                $v = $result.Summary[$k]
                if ($v -gt 0) {
                    Write-AuditLog -Level WARN -Message ("  {0,-28} {1,6}" -f $k, $v)
                } else {
                    Write-AuditLog -Level INFO -Message ("  {0,-28} {1,6}" -f $k, $v)
                }
            }
        } `
        -Cleanup {
            # Распакованный ntds.dit + SYSTEM — самый чувствительный
            # артефакт всего пайплайна. Удаляем первым.
            if ($tempDir -and (Test-Path -LiteralPath $tempDir)) {
                Write-AuditLog -Level INFO -Message 'SDelete распакованного IFM...'
                Invoke-SecureDelete -Path $tempDir -Passes 3 -Recurse -IgnoreMissing
            }
            # Локальная копия архива — не критична (он и так зашифрован),
            # но держать лишнюю копию незачем.
            if ($archiveLocal -and (Test-Path -LiteralPath $archiveLocal)) {
                Invoke-SecureDelete -Path $archiveLocal -Passes 3 -IgnoreMissing
            }
            # Ключ
            if ($aesKey) {
                Clear-SensitiveVariable -SecureString $aesKey
                $aesKey = $null
            }
        }

    Write-AuditLog -Level INFO -Message '=== Фаза 3 завершена успешно ==='
    return [pscustomobject]@{
        Phase          = 'Phase3-Audit'
        Success        = $true
        ResultJsonPath = $ResultJsonPath
        CorrelationId  = $cid
    }

} catch {
    Write-AuditLog -Level CRITICAL -Message "Фаза 3 упала: $($_.Exception.Message)"
    Write-AuditLog -Level CRITICAL -Message $_.ScriptStackTrace
    throw
}
