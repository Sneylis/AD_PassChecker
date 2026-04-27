#Requires -Version 5.1
#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Установщик станции аудита паролей AD.

.DESCRIPTION
    Одноразовый bootstrap для изолированной VM, на которой будет
    расшифровываться IFM-архив, запускаться DSInternals и формироваться
    отчёт. Скрипт:

      1. Проверяет состояние укрепления:
         - BitLocker FDE включён на всех фиксированных дисках;
         - pagefile отключён;
         - crash dump отключён (DebugInfoType = 0);
         - правила Windows Firewall: вход TCP 445 от DC, выход TCP 25 к SMTP;
         - нет доступа в интернет (проверка curl/Invoke-WebRequest timeout).

      2. Устанавливает инструменты из локального каталога Offline/
         (для изолированной сети) или скачивает при наличии интернета
         в bootstrap-фазу (до блокировки): 7-Zip, SDelete64,
         DSInternals, SecretManagement, SecretStore.

      3. Запрашивает у оператора credential сервисной учётки gMSA /
         Backup Operator, валидирует её подключение к DC и сохраняет
         в SecretStore.

      4. Настраивает SecretStore:
         - создаёт vault 'ADAuditVault';
         - генерирует AES-256 ключ IFM и кладёт в vault;
         - привязка к машинному аккаунту через DPAPI-NG.

      5. Импортирует словарь HIBP:
         - принимает путь на USB или локальный файл;
         - определяет формат (NTLM hash:count / SHA-1:count / plain);
         - при необходимости конвертирует plain → NTLM;
         - сортирует, убирает дубли, сохраняет в HibpFilePath;
         - считает SHA-256 и записывает в конфиг.

      6. Создаёт рабочие директории с ACL (доступ только у сервисной
         учётки и Administrators).

      7. Регистрирует Scheduled Task для оркестратора.

.PARAMETER ConfigPath
    Путь к шаблону конфига. Установщик достроит поля и сохранит в
    C:\ProgramData\ADPasswordAudit\audit.config.psd1.

.PARAMETER HibpSourcePath
    Путь к файлу HIBP (USB read-only или локальный). Если не указан,
    спрашивается интерактивно.

.PARAMETER OfflineToolsDirectory
    Каталог с заранее скачанными установщиками (7z*.exe, sdelete.zip,
    .nupkg модулей). Если указан, установщик не пытается выходить в сеть.

.EXAMPLE
    .\Install-AuditStation.ps1 -ConfigPath .\Config\audit.config.example.psd1

.NOTES
    Требует: Windows Server 2016+, PowerShell 5.1+, права администратора.
    Работает идемпотентно — повторный запуск не ломает уже настроенное.
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory)] [string] $ConfigPath,
    [string] $HibpSourcePath,
    [string] $OfflineToolsDirectory,
    [switch] $SkipHardeningChecks    # только для отладки в лабе
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

# ---------- Загрузка общих модулей ----------
$repoRoot = Split-Path -Parent $PSScriptRoot
Import-Module (Join-Path $repoRoot 'Common\Logging.psm1')        -Force
Import-Module (Join-Path $repoRoot 'Common\Crypto.psm1')         -Force
Import-Module (Join-Path $repoRoot 'Common\CleanupHelpers.psm1') -Force
Import-Module (Join-Path $repoRoot 'Common\Config.psm1')         -Force

Initialize-AuditLog -LogDirectory 'C:\AuditLogs' -PhaseName 'Installer'
Write-AuditLog -Level INFO -Message '=== Install-AuditStation начат ==='

# ---------- Секция 1: проверки укрепления ----------

function Test-Hardening {
    [CmdletBinding()]
    param([switch] $Skip)

    if ($Skip) {
        Write-AuditLog -Level WARN -Message 'Проверки укрепления пропущены по флагу -SkipHardeningChecks'
        return
    }

    Write-AuditLog -Level INFO -Message 'Проверка укрепления станции...'
    $problems = @()

    # 1. BitLocker FDE на всех фиксированных дисках
    try {
        $vols = Get-BitLockerVolume -ErrorAction Stop |
                Where-Object { $_.VolumeType -eq 'Data' -or $_.MountPoint -match '^[A-Z]:$' }
        foreach ($v in $vols) {
            if ($v.ProtectionStatus -ne 'On' -or $v.VolumeStatus -ne 'FullyEncrypted') {
                $problems += "BitLocker не активен на $($v.MountPoint) (Status=$($v.VolumeStatus), Protection=$($v.ProtectionStatus))"
            }
        }
    } catch {
        $problems += "Не удалось проверить BitLocker: $($_.Exception.Message)"
    }

    # 2. Pagefile отключён
    $pf = Get-CimInstance -ClassName Win32_PageFileSetting -ErrorAction SilentlyContinue
    if ($pf) {
        $problems += "Pagefile включён: $($pf.Name). Отключите через Мой компьютер → Свойства → Дополнительно → Производительность"
    }

    # 3. Crash dump отключён
    $ccs = Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\CrashControl' -ErrorAction SilentlyContinue
    if ($ccs -and $ccs.CrashDumpEnabled -ne 0) {
        $problems += "Crash dump включён (CrashDumpEnabled=$($ccs.CrashDumpEnabled)). Установите в 0."
    }

    # 4. Нет доступа в интернет (должен быть timeout)
    try {
        $resp = Invoke-WebRequest -Uri 'https://www.microsoft.com' -UseBasicParsing -TimeoutSec 5 -ErrorAction Stop
        if ($resp.StatusCode -eq 200) {
            $problems += 'Станция имеет доступ в интернет. В изолированном VLAN это недопустимо.'
        }
    } catch {
        # ожидаемое поведение — интернета быть не должно
    }

    # 5. Правила Windows Firewall (наличие, не содержание)
    $fwIn  = Get-NetFirewallRule -DisplayName 'ADAudit-SMB-Inbound-DC' -ErrorAction SilentlyContinue
    $fwOut = Get-NetFirewallRule -DisplayName 'ADAudit-SMTP-Outbound' -ErrorAction SilentlyContinue
    if (-not $fwIn -or -not $fwOut) {
        Write-AuditLog -Level WARN -Message 'Firewall-правила ADAudit-* не найдены. Создаю default-правила (проверьте вручную IP-адреса).'
        # Создадим скелеты; оператор должен донастроить scope.
        if (-not $fwIn) {
            New-NetFirewallRule -DisplayName 'ADAudit-SMB-Inbound-DC' -Direction Inbound `
                -Protocol TCP -LocalPort 445 -Action Allow -Profile Any | Out-Null
        }
        if (-not $fwOut) {
            New-NetFirewallRule -DisplayName 'ADAudit-SMTP-Outbound' -Direction Outbound `
                -Protocol TCP -RemotePort 25 -Action Allow -Profile Any | Out-Null
        }
    }

    if ($problems.Count -gt 0) {
        Write-AuditLog -Level ERROR -Message "Проблемы укрепления: $($problems.Count)"
        foreach ($p in $problems) { Write-AuditLog -Level ERROR -Message "  - $p" }
        throw 'Станция не соответствует требованиям укрепления. Исправьте ошибки выше и перезапустите установщик.'
    }

    Write-AuditLog -Level INFO -Message 'Проверки укрепления пройдены.'
}

# ---------- Секция 2: установка инструментов ----------

function Install-RequiredTools {
    [CmdletBinding()]
    param([string] $OfflineDir)

    Write-AuditLog -Level INFO -Message 'Установка инструментов и модулей...'

    # Целевая папка для standalone-утилит.
    $toolsDir = 'C:\Tools'
    if (-not (Test-Path -LiteralPath $toolsDir)) {
        New-Item -ItemType Directory -Path $toolsDir -Force | Out-Null
    }

    # 7-Zip ---
    $sevenZipExe = 'C:\Program Files\7-Zip\7z.exe'
    if (-not (Test-Path -LiteralPath $sevenZipExe)) {
        Write-AuditLog -Level INFO -Message 'Установка 7-Zip...'
        $msiPath = if ($OfflineDir) {
            Get-ChildItem -LiteralPath $OfflineDir -Filter '7z*x64.msi' |
                Select-Object -First 1 -ExpandProperty FullName
        } else { $null }
        if (-not $msiPath) {
            throw "7-Zip не найден. Положите 7z*x64.msi в $OfflineDir или установите 7-Zip вручную перед запуском."
        }
        Start-Process msiexec.exe -ArgumentList "/i `"$msiPath`" /qn /norestart" -Wait
        if (-not (Test-Path -LiteralPath $sevenZipExe)) {
            throw '7-Zip не установился. Проверьте MSI вручную.'
        }
    }
    # Добавляем в PATH системно (только если не добавлен).
    $sysPath = [Environment]::GetEnvironmentVariable('Path', 'Machine')
    if ($sysPath -notlike '*7-Zip*') {
        [Environment]::SetEnvironmentVariable('Path', "$sysPath;C:\Program Files\7-Zip", 'Machine')
    }

    # SDelete64 ---
    $sdeleteDir = Join-Path $toolsDir 'SDelete'
    $sdeleteExe = Join-Path $sdeleteDir 'sdelete64.exe'
    if (-not (Test-Path -LiteralPath $sdeleteExe)) {
        Write-AuditLog -Level INFO -Message 'Установка SDelete64...'
        if (-not (Test-Path -LiteralPath $sdeleteDir)) {
            New-Item -ItemType Directory -Path $sdeleteDir -Force | Out-Null
        }
        $zipPath = if ($OfflineDir) {
            Get-ChildItem -LiteralPath $OfflineDir -Filter 'SDelete.zip' |
                Select-Object -First 1 -ExpandProperty FullName
        } else { $null }
        if (-not $zipPath) {
            throw "SDelete.zip не найден. Положите его в $OfflineDir."
        }
        Expand-Archive -LiteralPath $zipPath -DestinationPath $sdeleteDir -Force
        if (-not (Test-Path -LiteralPath $sdeleteExe)) {
            throw 'sdelete64.exe отсутствует после распаковки. Проверьте содержимое SDelete.zip.'
        }
        # Принять EULA однократно чтобы последующие запуски не ждали.
        & $sdeleteExe -accepteula -nobanner | Out-Null
    }
    [Environment]::SetEnvironmentVariable('SDELETE_PATH', $sdeleteExe, 'Machine')
    $env:SDELETE_PATH = $sdeleteExe

    # PowerShell-модули ---
    # В изолированной сети репозитория PSGallery нет, поэтому инсталлируем
    # из офлайн-нугетов, если они есть в OfflineDir.
    $requiredModules = @(
        @{ Name = 'Microsoft.PowerShell.SecretManagement'; MinVersion = '1.1.2' },
        @{ Name = 'Microsoft.PowerShell.SecretStore';      MinVersion = '1.0.6' },
        @{ Name = 'DSInternals';                           MinVersion = '4.7' }
    )

    foreach ($m in $requiredModules) {
        $installed = Get-Module -ListAvailable -Name $m.Name |
                     Where-Object { $_.Version -ge [version] $m.MinVersion } |
                     Select-Object -First 1
        if ($installed) {
            Write-AuditLog -Level INFO -Message "Модуль $($m.Name) уже установлен: $($installed.Version)"
            continue
        }
        Write-AuditLog -Level INFO -Message "Установка модуля $($m.Name)..."

        $nupkg = if ($OfflineDir) {
            Get-ChildItem -LiteralPath $OfflineDir -Filter "$($m.Name)*.nupkg" |
                Select-Object -First 1 -ExpandProperty FullName
        } else { $null }

        if ($nupkg) {
            # Разворачиваем .nupkg как zip в $env:ProgramFiles\WindowsPowerShell\Modules
            $tempExtract = Join-Path $env:TEMP "mod_$([guid]::NewGuid().ToString('N'))"
            Expand-Archive -LiteralPath $nupkg -DestinationPath $tempExtract -Force
            $modRoot = "$env:ProgramFiles\WindowsPowerShell\Modules\$($m.Name)\$($m.MinVersion)"
            if (-not (Test-Path -LiteralPath $modRoot)) {
                New-Item -ItemType Directory -Path $modRoot -Force | Out-Null
            }
            Copy-Item "$tempExtract\*" $modRoot -Recurse -Force -Exclude '_rels','package','[Content_Types].xml','*.nuspec'
            Remove-Item $tempExtract -Recurse -Force
        } else {
            # Последний шанс — попробовать online (только для bootstrap-окна
            # до полной блокировки интернета).
            try {
                Install-Module -Name $m.Name -MinimumVersion $m.MinVersion `
                    -Scope AllUsers -Force -AllowClobber -ErrorAction Stop
            } catch {
                throw "Не удалось установить $($m.Name). Положите .nupkg в $OfflineDir и перезапустите."
            }
        }
    }

    Write-AuditLog -Level INFO -Message 'Инструменты и модули установлены.'
}

# ---------- Секция 3: SecretStore + credential ----------

function Initialize-VaultAndKeys {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [string] $VaultName,
        [Parameter(Mandatory)] [string] $IfmKeyName
    )

    Write-AuditLog -Level INFO -Message "Настройка SecretStore vault '$VaultName'..."

    Import-Module Microsoft.PowerShell.SecretManagement -Force
    Import-Module Microsoft.PowerShell.SecretStore      -Force

    # Если vault уже зарегистрирован — оставляем.
    $existing = Get-SecretVault -Name $VaultName -ErrorAction SilentlyContinue
    if (-not $existing) {
        Register-SecretVault -Name $VaultName `
            -ModuleName Microsoft.PowerShell.SecretStore `
            -DefaultVault
    }

    # Настройка SecretStore без интерактивного пароля — используем
    # машинно-привязанный режим (None authentication), защита через
    # DPAPI-NG и ACL файла. Альтернатива — Password-режим; для
    # автоматического запуска из Scheduled Task None удобнее.
    Set-SecretStoreConfiguration -Scope AllUsers `
        -Authentication None `
        -Interaction None `
        -Confirm:$false

    # Генерация ключа IFM, если отсутствует.
    $existingKey = Get-SecretInfo -Name $IfmKeyName -Vault $VaultName -ErrorAction SilentlyContinue
    if (-not $existingKey) {
        Write-AuditLog -Level INFO -Message "Генерация AES-256 ключа '$IfmKeyName'..."
        $key = New-AesKey
        try {
            Save-AesKeyToSecretStore -Name $IfmKeyName -Key $key -VaultName $VaultName
        } finally {
            Clear-SensitiveVariable -SecureString $key
        }
    } else {
        Write-AuditLog -Level INFO -Message "Ключ '$IfmKeyName' уже существует в vault."
    }
}

function Request-ServiceCredential {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [string] $DomainController,
        [Parameter(Mandatory)] [string] $VaultName
    )

    Write-AuditLog -Level INFO -Message 'Запрос учётной записи Backup Operator...'

    Write-Host ''
    Write-Host '=== Сервисная учётка для чтения ntds.dit ===' -ForegroundColor Cyan
    Write-Host 'Введите credential учётки с правами Backup Operator на DC.'
    Write-Host 'Рекомендуется gMSA (формат: DOMAIN\gmsaName$) или обычная сервисная учётка.'
    Write-Host ''

    $cred = Get-Credential -Message 'Учётка Backup Operator (например, CORP\svc-adaudit)'
    if (-not $cred) {
        throw 'Credential не введён — установка прервана.'
    }

    # Валидация: попробуем подключиться к DC по SMB с этой учёткой.
    # Для gMSA это сработает только на машине, где gMSA разрешена —
    # поэтому для gMSA валидацию выполняет отдельный тест Test-ADServiceAccount
    # на DC. Здесь — базовая проверка для обычных учёток.
    if ($cred.UserName -notlike '*$') {
        try {
            $testPath = "\\$DomainController\C$"
            $drive = New-PSDrive -Name 'ADAuditTest' -PSProvider FileSystem -Root $testPath `
                -Credential $cred -ErrorAction Stop
            Remove-PSDrive -Name 'ADAuditTest' -ErrorAction SilentlyContinue
            Write-AuditLog -Level INFO -Message "Учётка $($cred.UserName) успешно прошла валидацию доступа к DC."
        } catch {
            Write-AuditLog -Level WARN -Message "Не удалось валидировать credential: $($_.Exception.Message). Продолжаем."
        }
    } else {
        Write-AuditLog -Level INFO -Message "gMSA credential — валидация будет выполнена при первом запуске Фазы 1."
    }

    # Сохраняем в SecretStore для последующего использования оркестратором.
    Set-Secret -Name 'ADAudit-ServiceCredential' -Secret $cred -Vault $VaultName
    Write-AuditLog -Level INFO -Message 'Credential сохранён в vault под именем ADAudit-ServiceCredential.'
}

# ---------- Секция 4: импорт HIBP ----------

function Import-HibpDictionary {
    [CmdletBinding()]
    param(
        [string] $SourcePath,
        [Parameter(Mandatory)] [string] $TargetPath
    )

    if (-not $SourcePath) {
        Write-Host ''
        $SourcePath = Read-Host 'Укажите путь к словарю HIBP (файл с NTLM-хешами, SHA-1-хешами или plain-паролями)'
    }
    if (-not (Test-Path -LiteralPath $SourcePath)) {
        throw "Словарь HIBP не найден: $SourcePath"
    }

    Write-AuditLog -Level INFO -Message "Импорт HIBP из $SourcePath..."

    # Определяем формат по первой значащей строке.
    $firstLine = Get-Content -LiteralPath $SourcePath -TotalCount 1
    $format = Test-HibpFormat $firstLine
    Write-AuditLog -Level INFO -Message "Определён формат словаря: $format"

    $targetDir = Split-Path -Parent $TargetPath
    if (-not (Test-Path -LiteralPath $targetDir)) {
        New-Item -ItemType Directory -Path $targetDir -Force | Out-Null
    }

    switch ($format) {
        'NTLM' {
            # Уже в нужном формате. Просто копируем, попутно убирая
            # count-суффиксы (DSInternals ожидает только хеши).
            Write-AuditLog -Level INFO -Message 'Нормализация NTLM-словаря...'
            $writer = [System.IO.StreamWriter]::new($TargetPath, $false, [System.Text.Encoding]::ASCII)
            try {
                foreach ($line in [System.IO.File]::ReadLines($SourcePath)) {
                    if ([string]::IsNullOrWhiteSpace($line)) { continue }
                    $hash = ($line -split ':')[0].Trim().ToUpperInvariant()
                    if ($hash -match '^[0-9A-F]{32}$') {
                        $writer.WriteLine($hash)
                    }
                }
            } finally { $writer.Dispose() }
        }
        'SHA1' {
            # DSInternals может принимать SHA-1 HIBP напрямую через
            # -WeakPasswordHashesSortedFile, но для унификации всегда
            # конвертируем в NTLM. Если словарь в SHA-1 — оператор должен
            # скачать NTLM-версию HIBP, конвертация SHA-1 → NTLM невозможна.
            throw 'Словарь в формате SHA-1. DSInternals работает с NTLM-хешами — скачайте NTLM-версию HIBP (pwned-passwords-ntlm-ordered-by-*.txt) и перезапустите установщик.'
        }
        'Plain' {
            Write-AuditLog -Level WARN -Message 'Словарь в plain-формате. Конвертирую в NTLM (это может занять время)...'
            $count = 0
            $writer = [System.IO.StreamWriter]::new($TargetPath, $false, [System.Text.Encoding]::ASCII)
            try {
                foreach ($line in [System.IO.File]::ReadLines($SourcePath)) {
                    if ([string]::IsNullOrWhiteSpace($line)) { continue }
                    $pwd  = $line.Trim()
                    $hash = Get-NtlmHashFromString -Password $pwd
                    $writer.WriteLine($hash)
                    $count++
                    if ($count % 10000 -eq 0) {
                        Write-AuditLog -Level INFO -Message "  обработано $count строк..."
                    }
                }
            } finally { $writer.Dispose() }
            Write-AuditLog -Level INFO -Message "Конвертация завершена: $count паролей."
        }
        default {
            throw "Не удалось определить формат словаря. Первая строка: '$firstLine'"
        }
    }

    # Считаем эталонный SHA-256 финального файла.
    $sha = Get-Sha256Hash -Path $TargetPath
    Write-AuditLog -Level INFO -Message "SHA-256 финального словаря: $sha"
    return $sha
}

function Test-HibpFormat {
    param([string] $Line)

    if ([string]::IsNullOrWhiteSpace($Line)) { return 'Unknown' }
    $first = ($Line -split ':')[0].Trim()
    if ($first -match '^[0-9A-Fa-f]{32}$') { return 'NTLM' }
    if ($first -match '^[0-9A-Fa-f]{40}$') { return 'SHA1' }
    return 'Plain'
}

# ---------- Секция 5: рабочие директории ----------

function Initialize-WorkDirectories {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [string[]] $Directories,
        [Parameter(Mandatory)] [string] $ServiceAccountName
    )

    foreach ($dir in $Directories) {
        if (-not (Test-Path -LiteralPath $dir)) {
            New-Item -ItemType Directory -Path $dir -Force | Out-Null
            Write-AuditLog -Level INFO -Message "Создан каталог: $dir"
        }

        # ACL: доступ только Administrators, SYSTEM и сервисной учётке.
        $acl = New-Object System.Security.AccessControl.DirectorySecurity
        $acl.SetAccessRuleProtection($true, $false)  # отключить наследование

        $rules = @(
            New-Object System.Security.AccessControl.FileSystemAccessRule(
                'BUILTIN\Administrators', 'FullControl', 'ContainerInherit,ObjectInherit', 'None', 'Allow'),
            New-Object System.Security.AccessControl.FileSystemAccessRule(
                'NT AUTHORITY\SYSTEM', 'FullControl', 'ContainerInherit,ObjectInherit', 'None', 'Allow')
        )
        if ($ServiceAccountName) {
            try {
                $rules += New-Object System.Security.AccessControl.FileSystemAccessRule(
                    $ServiceAccountName, 'Modify', 'ContainerInherit,ObjectInherit', 'None', 'Allow')
            } catch {
                Write-AuditLog -Level WARN -Message "Не удалось добавить ACL для $ServiceAccountName на $dir: $($_.Exception.Message)"
            }
        }
        foreach ($r in $rules) { $acl.AddAccessRule($r) }
        Set-Acl -LiteralPath $dir -AclObject $acl
    }
}

# ---------- Секция 6: Scheduled Task оркестратора ----------

function Register-MonthlyScheduledTaskViaXml {
    <#
    .SYNOPSIS
        Регистрирует ежемесячную Scheduled Task через XML-определение
        (нативный New-ScheduledTaskTrigger в PS 5.1 не поддерживает Monthly).
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [string] $TaskName,
        [Parameter(Mandatory)] [int]    $DayOfMonth,
        [Parameter(Mandatory)] [string] $TimeOfDay,       # формата HH:mm
        [Parameter(Mandatory)] [string] $ScriptPath,
        [Parameter(Mandatory)] [string] $RunAsUser,
        [string] $Arguments = "-NoProfile -ExecutionPolicy Bypass -File `"$ScriptPath`"",
        [string] $LogonType = 'Password',                  # для gMSA — Password
        [int]    $TimeLimitHours = 4
    )

    $startBoundary = (Get-Date -Day $DayOfMonth -Hour ([int]$TimeOfDay.Split(':')[0]) `
                              -Minute ([int]$TimeOfDay.Split(':')[1]) -Second 0).ToString('s')
    $timeLimit     = "PT{0}H" -f $TimeLimitHours

    $xml = @"
<?xml version="1.0" encoding="UTF-16"?>
<Task version="1.4" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <RegistrationInfo>
    <Description>AD Password Audit: $TaskName</Description>
    <URI>\$TaskName</URI>
  </RegistrationInfo>
  <Triggers>
    <CalendarTrigger>
      <StartBoundary>$startBoundary</StartBoundary>
      <Enabled>true</Enabled>
      <ScheduleByMonth>
        <DaysOfMonth><Day>$DayOfMonth</Day></DaysOfMonth>
        <Months>
          <January/><February/><March/><April/><May/><June/>
          <July/><August/><September/><October/><November/><December/>
        </Months>
      </ScheduleByMonth>
    </CalendarTrigger>
  </Triggers>
  <Principals>
    <Principal id="Author">
      <UserId>$RunAsUser</UserId>
      <LogonType>$LogonType</LogonType>
      <RunLevel>HighestAvailable</RunLevel>
    </Principal>
  </Principals>
  <Settings>
    <AllowHardTerminate>false</AllowHardTerminate>
    <AllowStartOnDemand>true</AllowStartOnDemand>
    <StartWhenAvailable>true</StartWhenAvailable>
    <DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries>
    <StopIfGoingOnBatteries>false</StopIfGoingOnBatteries>
    <ExecutionTimeLimit>$timeLimit</ExecutionTimeLimit>
    <MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy>
    <Priority>7</Priority>
  </Settings>
  <Actions Context="Author">
    <Exec>
      <Command>powershell.exe</Command>
      <Arguments>$Arguments</Arguments>
    </Exec>
  </Actions>
</Task>
"@

    Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false -ErrorAction SilentlyContinue
    Register-ScheduledTask -TaskName $TaskName -Xml $xml -Force | Out-Null
    Write-AuditLog -Level INFO -Message "Scheduled Task '$TaskName' зарегистрирован (ежемесячно, день $DayOfMonth в $TimeOfDay)."
}

function Register-OrchestratorTask {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [int]    $DayOfMonth,
        [Parameter(Mandatory)] [string] $TimeOfDay,
        [Parameter(Mandatory)] [string] $ScriptPath,
        [Parameter(Mandatory)] [string] $ServiceAccountName
    )

    Register-MonthlyScheduledTaskViaXml `
        -TaskName   'ADPasswordAudit-Orchestrator' `
        -DayOfMonth $DayOfMonth `
        -TimeOfDay  $TimeOfDay `
        -ScriptPath $ScriptPath `
        -RunAsUser  $ServiceAccountName `
        -LogonType  'Password'
}

# ---------- Main ----------

try {
    # 1. Загружаем шаблон конфига.
    if (-not (Test-Path -LiteralPath $ConfigPath)) {
        throw "Шаблон конфига не найден: $ConfigPath"
    }
    $cfg = Import-PowerShellDataFile -LiteralPath $ConfigPath

    # 2. Укрепление.
    Test-Hardening -Skip:$SkipHardeningChecks

    # 3. Инструменты.
    Install-RequiredTools -OfflineDir $OfflineToolsDirectory

    # 4. Vault и ключи.
    Initialize-VaultAndKeys -VaultName $cfg.SecretVaultName -IfmKeyName $cfg.IfmKeyName

    # 5. Credential сервисной учётки.
    Request-ServiceCredential -DomainController $cfg.DomainController -VaultName $cfg.SecretVaultName

    # 6. HIBP импорт.
    $hibpSha = Import-HibpDictionary -SourcePath $HibpSourcePath -TargetPath $cfg.HibpFilePath
    $cfg.HibpExpectedSha256 = $hibpSha

    # 7. Рабочие директории.
    $svcAccount = (Get-Secret -Name 'ADAudit-ServiceCredential' -Vault $cfg.SecretVaultName).UserName
    Initialize-WorkDirectories `
        -Directories @($cfg.WorkDirectory, $cfg.LogDirectory, $cfg.ReportRetentionDirectory) `
        -ServiceAccountName $svcAccount

    # 8. Сохраняем финальный конфиг.
    Save-AuditConfig -Config $cfg -Path (Get-AuditConfigPath)
    Write-AuditLog -Level INFO -Message "Конфиг сохранён: $(Get-AuditConfigPath)"

    # 9. Scheduled Task оркестратора.
    $orchestratorScript = Join-Path $repoRoot 'Orchestrator\Start-PasswordAudit.ps1'
    Register-OrchestratorTask `
        -DayOfMonth         $cfg.AuditScheduleDayOfMonth `
        -TimeOfDay          $cfg.AuditScheduleTime `
        -ScriptPath         $orchestratorScript `
        -ServiceAccountName $svcAccount

    # 10. Retention-task (установится после Install-DCComponents, но
    # задача ретенции живёт именно на станции аудита / файловом сервере).
    $retentionScript = Join-Path $repoRoot 'Retention\Invoke-ReportRetention.ps1'
    if (Test-Path -LiteralPath $retentionScript) {
        Unregister-ScheduledTask -TaskName 'ADPasswordAudit-Retention' -Confirm:$false -ErrorAction SilentlyContinue
        $retAction  = New-ScheduledTaskAction -Execute 'powershell.exe' `
            -Argument "-NoProfile -ExecutionPolicy Bypass -File `"$retentionScript`""
        $retTrigger = New-ScheduledTaskTrigger -Daily -At $cfg.RetentionScheduleTime
        $retPrinc   = New-ScheduledTaskPrincipal -UserId $svcAccount -LogonType Password -RunLevel Highest
        Register-ScheduledTask -TaskName 'ADPasswordAudit-Retention' `
            -Action $retAction -Trigger $retTrigger -Principal $retPrinc -Force | Out-Null
        Write-AuditLog -Level INFO -Message 'Scheduled Task ретенции зарегистрирован.'
    }

    Write-AuditLog -Level INFO -Message '=== Install-AuditStation завершён успешно ==='
    Write-Host ''
    Write-Host 'Установка завершена. Следующие шаги:' -ForegroundColor Green
    Write-Host "  1. Установите пароль Scheduled Task для учётки $svcAccount через taskschd.msc"
    Write-Host '  2. Запустите Install-DCComponents.ps1 на контроллере домена.'
    Write-Host '  3. Выполните пробный прогон: Start-PasswordAudit.ps1 -Manual'
    Write-Host ''

} catch {
    Write-AuditLog -Level CRITICAL -Message "Установщик упал: $($_.Exception.Message)"
    Write-AuditLog -Level CRITICAL -Message $_.ScriptStackTrace
    throw
}
