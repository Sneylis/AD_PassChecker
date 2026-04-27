#Requires -Version 5.1
#Requires -Modules ActiveDirectory
<#
.SYNOPSIS
    Создаёт в лабораторном домене ~20 тестовых учёток с заведомо
    разными "слабостями" паролей — для верификации того, что фазы
    аудита действительно ловят каждую категорию из регламента.

.DESCRIPTION
    Запускать на ЛАБОРАТОРНОМ контроллере домена под Domain Admin.
    НИКОГДА не запускать в продакшене.

    Скрипт создаёт OU=PasswordAuditLab и в нём — учётки, покрывающие
    каждую категорию, которую Phase 3 / DSInternals выводит в отчёт:

        • WeakPassword            — пароль из HIBP.
        • DuplicatePasswordGroups — две учётки с одинаковым паролем.
        • EmptyPassword           — PasswordNotRequired=true, без пароля.
        • LMHashPresent           — старый LM-хеш (если GPO разрешает).
        • DefaultComputerPassword — компьютерная учётка с паролем
                                     = имя компьютера.
        • PasswordNotRequired     — UserAccountControl 32.
        • PasswordNeverExpires    — UAC 65536.
        • SamAccountNameAsPassword — пароль == имя (наша кастом-проверка).
        • PreAuthNotRequired      — UAC 4194304 (DoesNotRequirePreAuth).
        • DESEncryptionOnly       — msDS-SupportedEncryptionTypes=1 или 2.
        • DelegatableAdmins       — AdminCount=1 + TrustedForDelegation.
        • SmartCardUsersWithPassword — UAC SmartCardRequired + пароль.
        • Kerberoastable          — SPN + долгий пароль? нет, наоборот:
                                     SPN + обычный пользовательский
                                     пароль = kerberoastable.
        • ClearTextPassword       — UAC REVERSIBLE_ENCRYPTION (128).
        • AESKeysMissing          — функцio-ональный аналог: учётка
                                     без aes-ключей (обычно старая).

    После прогона аудита (Phase 3) ОЖИДАЕМ, что каждая категория
    в JSON-отчёте содержит соответствующую учётку из lab-OU.

.PARAMETER OUName
    Имя OU (по умолчанию PasswordAuditLab). OU создаётся под корнем
    домена.

.PARAMETER Cleanup
    Удалить lab-OU и ВСЕ учётки в нём. Используется после того, как
    верификация прошла.

.EXAMPLE
    # Первый прогон — создать тестовые учётки:
    .\New-LabTestUsers.ps1

    # После успешной верификации:
    .\New-LabTestUsers.ps1 -Cleanup

.NOTES
    "WeakPassword" использует пароль "Password1" — он ТОЧНО есть в
    любой редакции HIBP. Если у вас политика сложности блокирует
    такой пароль, временно ослабьте её ТОЛЬКО в лабе, либо
    используйте DSInternals Set-ADDBAccountPasswordHash напрямую
    (не делает этот скрипт, чтобы не вводить DSInternals-зависимость
    ещё и в лабораторный генератор).
#>

[CmdletBinding()]
param(
    [string] $OUName = 'PasswordAuditLab',
    [switch] $Cleanup
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
Import-Module ActiveDirectory -ErrorAction Stop

$domain   = (Get-ADDomain).DistinguishedName
$ouDn     = "OU=$OUName,$domain"
$ouExists = [bool] (Get-ADOrganizationalUnit -Filter "Name -eq '$OUName'" -ErrorAction SilentlyContinue)

function Remove-LabOU {
    if (-not $ouExists) { return }
    Write-Host "Удаление OU $ouDn..." -ForegroundColor Yellow
    # Снимаем защиту от случайного удаления.
    Set-ADOrganizationalUnit -Identity $ouDn -ProtectedFromAccidentalDeletion:$false
    Remove-ADOrganizationalUnit -Identity $ouDn -Recursive -Confirm:$false
    Write-Host 'OU удалена.' -ForegroundColor Green
}

if ($Cleanup) {
    Remove-LabOU
    return
}

if (-not $ouExists) {
    New-ADOrganizationalUnit -Name $OUName -Path $domain -ProtectedFromAccidentalDeletion $true
    Write-Host "OU создана: $ouDn" -ForegroundColor Green
}

# Обёртка для создания. Принимает SecureString.
function New-LabUser {
    param(
        [string] $Sam,
        [string] $Display,
        [System.Security.SecureString] $Password,
        [hashtable] $ExtraProps = @{},
        [switch] $PasswordNotRequired,
        [switch] $Enabled = $true
    )

    $upn = "$Sam@$((Get-ADDomain).DNSRoot)"
    $user = New-ADUser -Name $Display -SamAccountName $Sam `
        -UserPrincipalName $upn `
        -Path $ouDn `
        -AccountPassword $Password `
        -Enabled $Enabled `
        -PasswordNotRequired:$PasswordNotRequired `
        -PassThru

    foreach ($k in $ExtraProps.Keys) {
        Set-ADUser -Identity $user -Replace @{ $k = $ExtraProps[$k] }
    }
    Write-Host "  + $Sam ($Display)" -ForegroundColor Gray
    return $user
}

$common = 'Password1!LongEnoughForPolicy#1' # "безопасный" baseline, обойдёт политику
$secureCommon = ConvertTo-SecureString $common -AsPlainText -Force

# Пароли, которые должны попасть под соответствующие категории.
# Все — строки, длинные/сложные, чтобы не ломаться о дефолтную
# policy, но с намеренной уязвимостью для DSInternals.
$pwWeakHIBP = ConvertTo-SecureString 'Password1' -AsPlainText -Force  # в HIBP есть
$pwDupe     = ConvertTo-SecureString 'Zx!qW2e#LongDuplicate$42' -AsPlainText -Force

Write-Host '=== Создание тестовых учётных записей ===' -ForegroundColor Cyan

# 1. WeakPassword (HIBP)
New-LabUser -Sam 'lab-weak-hibp' -Display 'Lab Weak HIBP' -Password $pwWeakHIBP | Out-Null

# 2a-b. DuplicatePasswordGroups — два юзера с одинаковым паролем
New-LabUser -Sam 'lab-dup-a' -Display 'Lab Dup A' -Password $pwDupe | Out-Null
New-LabUser -Sam 'lab-dup-b' -Display 'Lab Dup B' -Password $pwDupe | Out-Null

# 3. EmptyPassword — PasswordNotRequired + любой минимальный пароль
New-LabUser -Sam 'lab-emptypw' -Display 'Lab Empty Pwd' `
    -Password (ConvertTo-SecureString ' ' -AsPlainText -Force) `
    -PasswordNotRequired | Out-Null

# 4. LMHashPresent — только если GPO "Store passwords using reversible /
#    LM hash" разрешает. Обычно нельзя просто флагом на юзере.
#    Оставляем как WARN-напоминание, пользователь выставит сам в GPO.
Write-Host '  ! LMHashPresent требует GPO "NoLMHash=0" — проверьте вручную.' -ForegroundColor Yellow

# 5. DefaultComputerPassword — добавляем компьютерную учётку
try {
    New-ADComputer -Name 'LAB-PC-WEAK' -Path $ouDn `
        -AccountPassword (ConvertTo-SecureString 'LAB-PC-WEAK' -AsPlainText -Force) `
        -Enabled $true | Out-Null
    Write-Host '  + LAB-PC-WEAK (computer)' -ForegroundColor Gray
} catch {
    Write-Host "  ! Не удалось создать LAB-PC-WEAK: $($_.Exception.Message)" -ForegroundColor Yellow
}

# 6. PasswordNotRequired (просто флаг, без пустого пароля)
New-LabUser -Sam 'lab-pwnot-req' -Display 'Lab PasswordNotRequired' `
    -Password $secureCommon -PasswordNotRequired | Out-Null

# 7. PasswordNeverExpires
$u7 = New-LabUser -Sam 'lab-neverexp' -Display 'Lab NeverExpires' -Password $secureCommon
Set-ADUser -Identity $u7 -PasswordNeverExpires $true

# 8. SamAccountNameAsPassword — наша кастом-проверка
New-LabUser -Sam 'lab-samaspwd' -Display 'Lab SAM as Pwd' `
    -Password (ConvertTo-SecureString 'lab-samaspwd' -AsPlainText -Force) | Out-Null

# 9. PreAuthNotRequired — UAC bit 0x400000 (4194304)
$u9 = New-LabUser -Sam 'lab-nopreauth' -Display 'Lab NoPreAuth' -Password $secureCommon
Set-ADAccountControl -Identity $u9 -DoesNotRequirePreAuth $true

# 10. DESEncryptionOnly — msDS-SupportedEncryptionTypes = 3 (DES-CBC-CRC + DES-CBC-MD5)
$u10 = New-LabUser -Sam 'lab-desonly' -Display 'Lab DES Only' -Password $secureCommon
Set-ADUser -Identity $u10 -Replace @{ 'msDS-SupportedEncryptionTypes' = 3 }

# 11. DelegatableAdmins — AdminCount=1 + TrustedForDelegation.
#     Чтобы не засорять реально Domain Admins: делаем юзера
#     членом встроенной группы "Account Operators" (adminCount станет 1)
#     и включаем TrustedForDelegation.
$u11 = New-LabUser -Sam 'lab-delegadmin' -Display 'Lab Delegatable Admin' -Password $secureCommon
Set-ADAccountControl -Identity $u11 -TrustedForDelegation $true
try {
    Add-ADGroupMember -Identity 'Account Operators' -Members $u11
} catch {
    Write-Host "  ! Add to Account Operators failed: $($_.Exception.Message)" -ForegroundColor Yellow
}

# 12. SmartCardUsersWithPassword — UAC SmartCardRequired + обычный пароль
$u12 = New-LabUser -Sam 'lab-smartcard' -Display 'Lab SmartCard' -Password $secureCommon
Set-ADAccountControl -Identity $u12 -SmartcardLogonRequired $true

# 13. Kerberoastable — SPN на пользовательской учётке + короткий/слабый пароль
$u13 = New-LabUser -Sam 'svc-sql-lab' -Display 'Lab SQL Service' -Password $pwWeakHIBP
Set-ADUser -Identity $u13 -ServicePrincipalNames @{ Add = 'MSSQLSvc/lab-sql01.corp.example.com:1433' }

# 14. ClearTextPassword — UAC ENCRYPTED_TEXT_PWD_ALLOWED = 0x80 (128)
$u14 = New-LabUser -Sam 'lab-cleartext' -Display 'Lab ClearText' -Password $secureCommon
Set-ADUser -Identity $u14 -AllowReversiblePasswordEncryption $true

# 15. AESKeysMissing — учётка, у которой в реальности не построены
#     AES-ключи (обычно старые pre-2008). На свежесозданной это
#     почти нереально без понижения функционала; включаем DES+RC4
#     без AES:
$u15 = New-LabUser -Sam 'lab-noaes' -Display 'Lab No AES Keys' -Password $secureCommon
Set-ADUser -Identity $u15 -Replace @{ 'msDS-SupportedEncryptionTypes' = 20 } # RC4_HMAC + DES = нет AES

# 16-20. "Обычные" здоровые учётки — для контроля, что они НЕ попадут
# ни в одну категорию.
foreach ($i in 1..5) {
    New-LabUser -Sam ("lab-ok-{0:00}" -f $i) `
                -Display ("Lab OK User {0:00}" -f $i) `
                -Password (ConvertTo-SecureString ("P@ssw0rdF0rLabOk{0:00}#Strong!" -f $i) -AsPlainText -Force) | Out-Null
}

Write-Host ''
Write-Host '=== Ожидаемая картина в отчёте Phase 3 ===' -ForegroundColor Cyan
Write-Host @'
  WeakPassword                → lab-weak-hibp, svc-sql-lab
  DuplicatePasswordGroups     → lab-dup-a, lab-dup-b
  EmptyPassword               → lab-emptypw (если PasswordNotRequired отработал)
  DefaultComputerPassword     → LAB-PC-WEAK$
  PasswordNotRequired         → lab-emptypw, lab-pwnot-req
  PasswordNeverExpires        → lab-neverexp
  SamAccountNameAsPassword    → lab-samaspwd
  PreAuthNotRequired          → lab-nopreauth
  DESEncryptionOnly           → lab-desonly
  DelegatableAdmins           → lab-delegadmin (AdminCount=1 + Trusted)
  SmartCardUsersWithPassword  → lab-smartcard
  Kerberoastable              → svc-sql-lab
  ClearTextPassword           → lab-cleartext
  AESKeysMissing              → lab-noaes
  LMHashPresent               → зависит от GPO, см. предупреждение выше
'@

Write-Host ''
Write-Host 'Готово. Прогони теперь Start-PasswordAudit.ps1 и сравни с ожидаемой картиной.' -ForegroundColor Green
