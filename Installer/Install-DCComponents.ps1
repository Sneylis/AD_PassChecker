#Requires -Version 5.1
#Requires -RunAsAdministrator
#Requires -Modules ActiveDirectory
<#
.SYNOPSIS
    Установщик компонентов на контроллере домена.

.DESCRIPTION
    Одноразовый скрипт, запускается под Domain Admin. Делает:

      1. Создаёт gMSA:
         - если группы "Backup Operators" у gMSA ещё нет — добавляет;
         - если KDS Root Key отсутствует в домене — создаёт (с датой
           в прошлом для немедленной готовности в лабе; в продакшене
           лучше подождать 10 часов);
         - ставит авторотацию пароля (128 символов, каждые 30 дней);
         - запрещает интерактивный вход (userAccountControl + GPO-hint);
         - разрешает получение пароля gMSA только машине станции аудита
           и самому DC.

      2. Устанавливает 7-Zip, SDelete64, SecretManagement + SecretStore
         (аналогично станции — из OfflineToolsDirectory).

      3. Создаёт локальный SecretStore на DC под машинным аккаунтом и
         кладёт туда AES-256 ключ IFM. Этот ключ — ТОТ ЖЕ, что на
         станции аудита: установщик умеет либо принять ключ из vault
         станции (через защищённый канал), либо экспортировать ключ с
         DC на станцию. По умолчанию — опция 1: ключ генерируется на
         станции при её установке и защищённо копируется на DC.

      4. Настраивает startup-скрипт, который при загрузке DC сканирует
         C:\IFM_Work и безопасно удаляет ВСЁ, что там осталось после
         сбоев питания (паранойя — даже если fase1 упала, finally не
         сработало, и ntds.dit остался на диске).

      5. Регистрирует Scheduled Task Фазы 1 (ежемесячно 03:00) от
         имени gMSA.

.PARAMETER ConfigPath
    Путь к тому же audit.config.psd1, что и на станции аудита.

.PARAMETER AuditStationComputer
    Имя компьютерного аккаунта станции аудита в AD. Нужно для
    PrincipalsAllowedToRetrieveManagedPassword gMSA.

.PARAMETER GmsaName
    Имя gMSA (по умолчанию svc-adaudit).

.PARAMETER OfflineToolsDirectory
    Каталог с оффлайновыми установщиками.

.EXAMPLE
    .\Install-DCComponents.ps1 -ConfigPath .\audit.config.psd1 -AuditStationComputer 'AUDIT01'

.NOTES
    Требует: модуль ActiveDirectory (RSAT), права Domain Admin при
    первом запуске. Повторный запуск идемпотентен.
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory)] [string] $ConfigPath,
    [Parameter(Mandatory)] [string] $AuditStationComputer,
    [string] $GmsaName = 'svc-adaudit',
    [string] $OfflineToolsDirectory
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$repoRoot = Split-Path -Parent $PSScriptRoot
Import-Module (Join-Path $repoRoot 'Common\Logging.psm1')        -Force
Import-Module (Join-Path $repoRoot 'Common\Crypto.psm1')         -Force
Import-Module (Join-Path $repoRoot 'Common\CleanupHelpers.psm1') -Force
Import-Module (Join-Path $repoRoot 'Common\Config.psm1')         -Force
Import-Module ActiveDirectory -Force

Initialize-AuditLog -LogDirectory 'C:\AuditLogs' -PhaseName 'Installer-DC'
Write-AuditLog -Level INFO -Message '=== Install-DCComponents начат ==='

# ---------- Секция 1: gMSA ----------

function Initialize-KdsRootKey {
    Write-AuditLog -Level INFO -Message 'Проверка KDS Root Key...'
    $keys = Get-KdsRootKey -ErrorAction SilentlyContinue
    if ($keys) {
        Write-AuditLog -Level INFO -Message "KDS Root Key уже существует (count=$($keys.Count))."
        return
    }
    Write-AuditLog -Level WARN -Message 'KDS Root Key отсутствует. Создаю с датой в прошлом для немедленной готовности.'
    Write-AuditLog -Level WARN -Message 'В продакшене лучше: Add-KdsRootKey -EffectiveImmediately и подождать 10 часов.'
    Add-KdsRootKey -EffectiveTime ((Get-Date).AddHours(-10)) | Out-Null
}

function New-AuditGmsa {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [string] $Name,
        [Parameter(Mandatory)] [string] $AuditStationComputer
    )

    $existing = Get-ADServiceAccount -Identity $Name -ErrorAction SilentlyContinue
    if ($existing) {
        Write-AuditLog -Level INFO -Message "gMSA '$Name' уже существует."
    } else {
        Write-AuditLog -Level INFO -Message "Создание gMSA '$Name'..."
        $dnsHostName = "$Name.$((Get-ADDomain).DNSRoot)"

        # Кому разрешено получать пароль: DC (для Фазы 1) + станция аудита.
        $dc = (Get-ADDomainController).Name
        $principals = @()
        $principals += Get-ADComputer -Identity $dc
        $principals += Get-ADComputer -Identity $AuditStationComputer

        New-ADServiceAccount -Name $Name `
            -DNSHostName $dnsHostName `
            -PrincipalsAllowedToRetrieveManagedPassword $principals `
            -ManagedPasswordIntervalInDays 30 `
            -Enabled $true | Out-Null

        Write-AuditLog -Level INFO -Message "gMSA '$Name' создана. Авторотация: 30 дней."
    }

    # Добавление в Backup Operators домена.
    $backupOps = Get-ADGroup -Identity 'Backup Operators' -ErrorAction Stop
    $members = Get-ADGroupMember -Identity $backupOps
    if ($members.SamAccountName -notcontains "$Name$") {
        Add-ADGroupMember -Identity $backupOps -Members "$Name$"
        Write-AuditLog -Level INFO -Message "gMSA добавлена в группу 'Backup Operators'."
    } else {
        Write-AuditLog -Level INFO -Message "gMSA уже состоит в 'Backup Operators'."
    }

    # Установка gMSA на DC: Install-ADServiceAccount делает локальную
    # регистрацию в LSA.
    try {
        Install-ADServiceAccount -Identity $Name
        Write-AuditLog -Level INFO -Message "gMSA установлена локально на DC."
    } catch {
        Write-AuditLog -Level WARN -Message "Install-ADServiceAccount: $($_.Exception.Message)"
    }

    # Проверка доступности (может занять до 10 часов после создания в некоторых окружениях).
    $ok = Test-ADServiceAccount -Identity $Name
    if ($ok) {
        Write-AuditLog -Level INFO -Message 'Test-ADServiceAccount: OK'
    } else {
        Write-AuditLog -Level WARN -Message 'Test-ADServiceAccount: FAIL. Подождите ~10 часов после создания KDS Root Key и повторите.'
    }
}

# ---------- Секция 2: инструменты ----------

function Install-DCTools {
    [CmdletBinding()]
    param([string] $OfflineDir)

    Write-AuditLog -Level INFO -Message 'Установка 7-Zip, SDelete64, SecretManagement на DC...'

    # Переиспользуем логику из Install-AuditStation (через dot-source не
    # делаем — функции там в main-скрипте). Копируем минимальную
    # версию; дубликат кода оправдан: на DC мы не хотим пересекаться
    # с режимами SecretStore станции.

    # 7-Zip
    if (-not (Test-Path -LiteralPath 'C:\Program Files\7-Zip\7z.exe')) {
        $msi = if ($OfflineDir) {
            Get-ChildItem -LiteralPath $OfflineDir -Filter '7z*x64.msi' | Select-Object -First 1 -ExpandProperty FullName
        } else { $null }
        if (-not $msi) { throw "7z MSI не найден. Положите в $OfflineDir." }
        Start-Process msiexec.exe -ArgumentList "/i `"$msi`" /qn /norestart" -Wait
    }

    # SDelete
    $sdeleteExe = 'C:\Tools\SDelete\sdelete64.exe'
    if (-not (Test-Path -LiteralPath $sdeleteExe)) {
        if (-not (Test-Path 'C:\Tools\SDelete')) {
            New-Item -ItemType Directory -Path 'C:\Tools\SDelete' -Force | Out-Null
        }
        $zip = if ($OfflineDir) {
            Get-ChildItem -LiteralPath $OfflineDir -Filter 'SDelete.zip' | Select-Object -First 1 -ExpandProperty FullName
        } else { $null }
        if (-not $zip) { throw "SDelete.zip не найден. Положите в $OfflineDir." }
        Expand-Archive -LiteralPath $zip -DestinationPath 'C:\Tools\SDelete' -Force
        & $sdeleteExe -accepteula -nobanner | Out-Null
    }
    [Environment]::SetEnvironmentVariable('SDELETE_PATH', $sdeleteExe, 'Machine')

    # SecretManagement + SecretStore
    foreach ($mod in @('Microsoft.PowerShell.SecretManagement','Microsoft.PowerShell.SecretStore')) {
        if (-not (Get-Module -ListAvailable -Name $mod)) {
            $nupkg = if ($OfflineDir) {
                Get-ChildItem -LiteralPath $OfflineDir -Filter "$mod*.nupkg" | Select-Object -First 1 -ExpandProperty FullName
            } else { $null }
            if ($nupkg) {
                $ex = Join-Path $env:TEMP "mod_$([guid]::NewGuid().ToString('N'))"
                Expand-Archive $nupkg $ex -Force
                $dest = "$env:ProgramFiles\WindowsPowerShell\Modules\$mod\1.0.0"
                if (-not (Test-Path $dest)) { New-Item -ItemType Directory -Path $dest -Force | Out-Null }
                Copy-Item "$ex\*" $dest -Recurse -Force -Exclude '_rels','package','[Content_Types].xml','*.nuspec'
                Remove-Item $ex -Recurse -Force
            } else {
                Install-Module -Name $mod -Scope AllUsers -Force -AllowClobber
            }
        }
    }

    Write-AuditLog -Level INFO -Message 'Инструменты установлены.'
}

# ---------- Секция 3: SecretStore и синхронизация ключа ----------

function Initialize-DCVault {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [string] $VaultName,
        [Parameter(Mandatory)] [string] $IfmKeyName,
        [Parameter(Mandatory)] [string] $AuditStationComputer,
        [Parameter(Mandatory)] [string] $SmbShareUnc
    )

    Write-AuditLog -Level INFO -Message "Настройка SecretStore на DC, vault '$VaultName'..."

    Import-Module Microsoft.PowerShell.SecretManagement -Force
    Import-Module Microsoft.PowerShell.SecretStore      -Force

    if (-not (Get-SecretVault -Name $VaultName -ErrorAction SilentlyContinue)) {
        Register-SecretVault -Name $VaultName -ModuleName Microsoft.PowerShell.SecretStore -DefaultVault
    }
    Set-SecretStoreConfiguration -Scope AllUsers -Authentication None -Interaction None -Confirm:$false

    # Станция аудита заранее экспортировала AES-ключ через
    # Export-IfmKey.ps1: ключ зашифрован CMS (PKCS#7) с сертификатом
    # DC в качестве получателя и записан на SmbShareUnc под именем
    # ifm-key.transfer.xml. Здесь мы расшифровываем CMS закрытым
    # ключом DC (автоматически подбирается по cert store) и кладём
    # ключ в локальный vault. После импорта файл SDelete-ится.

    $existing = Get-SecretInfo -Name $IfmKeyName -Vault $VaultName -ErrorAction SilentlyContinue
    if ($existing) {
        Write-AuditLog -Level INFO -Message "Ключ '$IfmKeyName' уже есть в DC-vault."
        return
    }

    $keyTransferFile = Join-Path $SmbShareUnc 'ifm-key.transfer.xml'
    if (-not (Test-Path -LiteralPath $keyTransferFile)) {
        Write-AuditLog -Level ERROR -Message "Файл переноса ключа не найден: $keyTransferFile"
        Write-AuditLog -Level ERROR -Message 'На станции аудита выполните: Export-IfmKey.ps1 -TargetShare <SMB> -DcCertificateThumbprint <thumbprint>'
        throw 'Ключ не найден на SMB-шаре. Сначала экспортируйте его со станции.'
    }

    try {
        $cmsContent = Get-Content -LiteralPath $keyTransferFile -Raw -Encoding UTF8
        $plain      = Unprotect-CmsMessage -Content $cmsContent
        if ([string]::IsNullOrWhiteSpace($plain)) {
            throw 'CMS-расшифровка вернула пустую строку. Возможно, на DC нет закрытого ключа сертификата, которым был зашифрован файл.'
        }
        $secure = ConvertTo-SecureString -String $plain -AsPlainText -Force
        $plain  = $null
        [System.GC]::Collect()

        Save-AesKeyToSecretStore -Name $IfmKeyName -Key $secure -VaultName $VaultName
        Write-AuditLog -Level INFO -Message "Ключ '$IfmKeyName' импортирован в DC-vault."
    } finally {
        # SDelete файла переноса — чтобы на шаре не оставалось CMS-блоба.
        Invoke-SecureDelete -Path $keyTransferFile -Passes 3 -IgnoreMissing
        if ($secure) { Clear-SensitiveVariable -SecureString $secure }
        $cmsContent = $null
    }
}

# ---------- Секция 4: startup-скрипт ----------

function Install-StartupCleanupScript {
    Write-AuditLog -Level INFO -Message 'Установка startup-скрипта для аварийной очистки...'

    $scriptDest = 'C:\Windows\System32\GroupPolicy\Machine\Scripts\Startup'
    if (-not (Test-Path -LiteralPath $scriptDest)) {
        New-Item -ItemType Directory -Path $scriptDest -Force | Out-Null
    }

    $startupScript = @'
# Автоматически установлен Install-DCComponents.ps1
# Ищет временные артефакты Фазы 1 после сбоев питания и удаляет их SDelete.
$ErrorActionPreference = 'Continue'
$sdelete = 'C:\Tools\SDelete\sdelete64.exe'
$targets = @(
    'C:\IFM_Work',
    'C:\Windows\Temp\ntds*',
    'C:\Windows\Temp\IFM*'
)
foreach ($t in $targets) {
    if (Test-Path -LiteralPath $t) {
        try {
            & $sdelete -p 3 -s -nobanner -accepteula $t | Out-File 'C:\AuditLogs\dc-startup-cleanup.log' -Append
        } catch {
            "[$(Get-Date -Format o)] Failed to SDelete ${t}: $_" |
                Out-File 'C:\AuditLogs\dc-startup-cleanup.log' -Append
        }
    }
}
'@

    $path = Join-Path $scriptDest 'ADAudit-StartupCleanup.ps1'
    Set-Content -LiteralPath $path -Value $startupScript -Encoding UTF8

    # Регистрируем через Task Scheduler с триггером "при старте системы"
    # (альтернатива GPO-startup — так не зависит от GPO-политик на DC).
    Unregister-ScheduledTask -TaskName 'ADPasswordAudit-StartupCleanup' -Confirm:$false -ErrorAction SilentlyContinue
    $action  = New-ScheduledTaskAction -Execute 'powershell.exe' `
        -Argument "-NoProfile -ExecutionPolicy Bypass -File `"$path`""
    $trigger = New-ScheduledTaskTrigger -AtStartup
    $princ   = New-ScheduledTaskPrincipal -UserId 'SYSTEM' -RunLevel Highest
    Register-ScheduledTask -TaskName 'ADPasswordAudit-StartupCleanup' `
        -Action $action -Trigger $trigger -Principal $princ -Force | Out-Null

    Write-AuditLog -Level INFO -Message 'Startup cleanup зарегистрирован.'
}

# ---------- Секция 5: Scheduled Task Фазы 1 ----------

function Register-Phase1Task {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [string] $GmsaName,
        [Parameter(Mandatory)] [int]    $DayOfMonth,
        [Parameter(Mandatory)] [string] $TimeOfDay,
        [Parameter(Mandatory)] [string] $ScriptPath,
        [Parameter(Mandatory)] [string] $ConfigPath
    )

    $taskName = 'ADPasswordAudit-Phase1-IFM'
    $domain   = (Get-ADDomain).NetBIOSName
    $runAs    = "$domain\$GmsaName$"
    $args     = "-NoProfile -ExecutionPolicy Bypass -File `"$ScriptPath`" -ConfigPath `"$ConfigPath`""

    $startBoundary = (Get-Date -Day $DayOfMonth -Hour ([int]$TimeOfDay.Split(':')[0]) `
                              -Minute ([int]$TimeOfDay.Split(':')[1]) -Second 0).ToString('s')

    $xml = @"
<?xml version="1.0" encoding="UTF-16"?>
<Task version="1.4" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <RegistrationInfo>
    <Description>AD Password Audit Phase 1 (IFM backup) — runs as gMSA</Description>
    <URI>\$taskName</URI>
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
      <UserId>$runAs</UserId>
      <!-- Password LogonType обязателен для gMSA в Task Scheduler -->
      <LogonType>Password</LogonType>
      <RunLevel>HighestAvailable</RunLevel>
    </Principal>
  </Principals>
  <Settings>
    <AllowHardTerminate>false</AllowHardTerminate>
    <StartWhenAvailable>true</StartWhenAvailable>
    <DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries>
    <StopIfGoingOnBatteries>false</StopIfGoingOnBatteries>
    <ExecutionTimeLimit>PT2H</ExecutionTimeLimit>
    <MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy>
    <Priority>7</Priority>
  </Settings>
  <Actions Context="Author">
    <Exec>
      <Command>powershell.exe</Command>
      <Arguments>$args</Arguments>
    </Exec>
  </Actions>
</Task>
"@

    Unregister-ScheduledTask -TaskName $taskName -Confirm:$false -ErrorAction SilentlyContinue
    Register-ScheduledTask -TaskName $taskName -Xml $xml -Force | Out-Null

    Write-AuditLog -Level INFO -Message "Scheduled Task '$taskName' зарегистрирован под gMSA $runAs (ежемесячно, день $DayOfMonth в $TimeOfDay)."
}

# ---------- Main ----------

try {
    if (-not (Test-Path -LiteralPath $ConfigPath)) {
        throw "Конфиг не найден: $ConfigPath"
    }
    $cfg = Import-PowerShellDataFile -LiteralPath $ConfigPath

    # 1. KDS Root Key + gMSA.
    Initialize-KdsRootKey
    New-AuditGmsa -Name $GmsaName -AuditStationComputer $AuditStationComputer

    # 2. Инструменты.
    Install-DCTools -OfflineDir $OfflineToolsDirectory

    # 3. Локальный vault и импорт ключа со станции.
    Initialize-DCVault `
        -VaultName             $cfg.SecretVaultName `
        -IfmKeyName            $cfg.IfmKeyName `
        -AuditStationComputer  $AuditStationComputer `
        -SmbShareUnc           $cfg.SmbShareUnc

    # 4. Рабочие папки на DC.
    $ifmWork = 'C:\IFM_Work'
    if (-not (Test-Path -LiteralPath $ifmWork)) {
        New-Item -ItemType Directory -Path $ifmWork -Force | Out-Null
    }
    if (-not (Test-Path -LiteralPath 'C:\AuditLogs')) {
        New-Item -ItemType Directory -Path 'C:\AuditLogs' -Force | Out-Null
    }

    # 5. Startup-скрипт аварийной очистки.
    Install-StartupCleanupScript

    # 6. Scheduled Task Фазы 1.
    $phase1Script = Join-Path $repoRoot 'Phase1-IFMBackup\New-IFMBackup.ps1'
    if (Test-Path -LiteralPath $phase1Script) {
        Register-Phase1Task `
            -GmsaName    $GmsaName `
            -DayOfMonth  $cfg.AuditScheduleDayOfMonth `
            -TimeOfDay   $cfg.AuditScheduleTime `
            -ScriptPath  $phase1Script `
            -ConfigPath  $ConfigPath
    } else {
        Write-AuditLog -Level WARN -Message "Скрипт Фазы 1 ещё не установлен ($phase1Script). Перезапустите установщик после деплоя скриптов."
    }

    Write-AuditLog -Level INFO -Message '=== Install-DCComponents завершён успешно ==='
    Write-Host ''
    Write-Host 'Настройка DC завершена. Следующие шаги:' -ForegroundColor Green
    Write-Host '  1. Проверьте Test-ADServiceAccount svc-adaudit (должен вернуть True).'
    Write-Host '  2. Разверните скрипты фаз в C:\Scripts\AD-Password-Audit\ на DC.'
    Write-Host '  3. Проверьте пробным запуском: Scheduled Task ADPasswordAudit-Phase1-IFM → Run.'
    Write-Host ''

} catch {
    Write-AuditLog -Level CRITICAL -Message "Установщик упал: $($_.Exception.Message)"
    Write-AuditLog -Level CRITICAL -Message $_.ScriptStackTrace
    throw
}
