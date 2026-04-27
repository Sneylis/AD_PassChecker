#Requires -Version 5.1
<#
.SYNOPSIS
    Экспорт AES-ключа IFM со станции аудита для импорта на DC.

.DESCRIPTION
    Вспомогательный утилитарный скрипт, используемый один раз в момент
    развёртывания. Работает в паре с Install-DCComponents.ps1.

    Процедура передачи ключа:
      1. На станции аудита: Install-AuditStation.ps1 сгенерировал
         AES-256 ключ в локальном SecretStore.
      2. На станции аудита: этот скрипт (Export-IfmKey.ps1)
         экспортирует ключ в SecureString → CliXml-файл, защищённый
         DPAPI-NG с правилом "прочитать может только машинный аккаунт DC".
      3. Файл кладётся на SMB-шару станции.
      4. На DC: Install-DCComponents.ps1 читает файл, импортирует в
         локальный vault, и SDelete-ит файл переноса.

    Защита файла: используем CMS (PKCS#7) с сертификатом DC в качестве
    получателя. Это стандартный PowerShell-механизм Protect-CmsMessage,
    работающий только при наличии сертификата DC в хранилище AD
    (Enterprise CA выписала DC-сертификат с подходящими EKU).

    Если корпоративного CA нет, fallback: ручная передача через
    защищённый канал (USB-флэшка, зашифрованная BitLocker-to-Go).

.PARAMETER TargetShare
    UNC-путь на SMB-шаре, куда записать файл переноса.

.PARAMETER VaultName
    Имя SecretStore vault на станции.

.PARAMETER IfmKeyName
    Имя секрета в vault.

.PARAMETER DcCertificateThumbprint
    Thumbprint DC-сертификата, которым будет зашифрован ключ. Получить:
        Get-ChildItem Cert:\LocalMachine\My | Where Subject -Match 'DC01'

.EXAMPLE
    .\Export-IfmKey.ps1 `
        -TargetShare '\\AUDIT01\IFM_Drop$' `
        -DcCertificateThumbprint 'ABCD1234...'
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory)] [string] $TargetShare,
    [string] $VaultName  = 'ADAuditVault',
    [string] $IfmKeyName = 'ADAudit-IFM-Key',
    [Parameter(Mandatory)] [string] $DcCertificateThumbprint
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$repoRoot = Split-Path -Parent $PSScriptRoot
Import-Module (Join-Path $repoRoot 'Common\Logging.psm1') -Force
Import-Module (Join-Path $repoRoot 'Common\Crypto.psm1')  -Force

Initialize-AuditLog -LogDirectory 'C:\AuditLogs' -PhaseName 'KeyTransfer'
Write-AuditLog -Level INFO -Message 'Экспорт IFM-ключа на DC...'

$cert = Get-Item "Cert:\LocalMachine\My\$DcCertificateThumbprint" -ErrorAction SilentlyContinue
if (-not $cert) {
    $cert = Get-Item "Cert:\LocalMachine\Root\$DcCertificateThumbprint" -ErrorAction SilentlyContinue
}
if (-not $cert) {
    throw "Сертификат DC c thumbprint $DcCertificateThumbprint не найден. Импортируйте сертификат DC (публичная часть достаточна) в Cert:\LocalMachine\My."
}

$key = Get-AesKeyFromSecretStore -Name $IfmKeyName -VaultName $VaultName
try {
    # Преобразуем в plain (короткое время жизни) → CMS-шифрование.
    $bstr = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($key)
    try {
        $plain = [System.Runtime.InteropServices.Marshal]::PtrToStringBSTR($bstr)
        $cms = Protect-CmsMessage -To "*$DcCertificateThumbprint" -Content $plain
    } finally {
        [System.Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstr)
    }

    if (-not (Test-Path -LiteralPath $TargetShare)) {
        throw "Не удаётся получить доступ к $TargetShare. Проверьте сетевую доступность и права."
    }

    $targetFile = Join-Path $TargetShare 'ifm-key.transfer.xml'
    # Кладём CMS-blob, а не SecureString — так DC-сторона сможет
    # расшифровать своим закрытым ключом вне зависимости от DPAPI.
    Set-Content -LiteralPath $targetFile -Value $cms -Encoding UTF8

    # ACL: только машинный аккаунт DC + Administrators.
    $acl = Get-Acl -LiteralPath $targetFile
    $acl.SetAccessRuleProtection($true, $false)
    $acl.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule(
        'BUILTIN\Administrators', 'FullControl', 'Allow')))
    Set-Acl -LiteralPath $targetFile -AclObject $acl

    Write-AuditLog -Level INFO -Message "Ключ зашифрован CMS и записан в $targetFile."
    Write-AuditLog -Level WARN -Message 'Запустите Install-DCComponents.ps1 на DC — он сам удалит файл после импорта.'

} finally {
    Clear-SensitiveVariable -SecureString $key
    $plain = $null
    $cms   = $null
    [System.GC]::Collect()
}
