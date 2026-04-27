#Requires -Version 5.1
#Requires -Modules @{ ModuleName='Pester'; ModuleVersion='5.0' }
<#
.SYNOPSIS
    Тесты модуля Common\Config.psm1 — загрузка, валидация, round-trip.
#>

BeforeAll {
    $repoRoot = Split-Path -Parent (Split-Path -Parent $PSCommandPath)
    Import-Module (Join-Path $repoRoot 'Common\Config.psm1') -Force

    $script:sandbox = Join-Path $env:TEMP ("cfg-test-" + [guid]::NewGuid().ToString('N'))
    New-Item -ItemType Directory -Path $script:sandbox | Out-Null
    $script:cfgPath = Join-Path $script:sandbox 'audit.config.psd1'

    # Базовый валидный набор полей.
    $script:sample = @{
        Domain                     = 'corp.example.com'
        DomainController           = 'dc01.corp.example.com'
        AuditStation               = 'audit01.corp.example.com'
        SmbShareUnc                = '\\files01\IFM-Exchange$'
        WorkDirectory              = 'D:\AuditWork'
        LogDirectory               = 'C:\AuditLogs'
        ReportRetentionDirectory   = 'D:\AuditReports'
        HibpFilePath               = 'D:\HIBP\hibp-ntlm.txt'
        HibpExpectedSha256         = ('a' * 64)
        SecretVaultName            = 'ADAuditVault'
        IfmKeyName                 = 'ADAudit-IFM-Key'
        SmtpServer                 = 'smtp.corp.example.com'
        SmtpFrom                   = 'ad-audit@corp.example.com'
        SmtpRecipients             = @('sec-ops@corp.example.com','ciso@corp.example.com')
        SmimeCertificateThumbprint = '0123456789ABCDEF0123456789ABCDEF01234567'
        ReportRetentionDays        = 5
    }
}

AfterAll {
    $env:AD_AUDIT_CONFIG = $null
    Remove-Item $script:sandbox -Recurse -Force -ErrorAction SilentlyContinue
}

Describe 'Save-AuditConfig / Get-AuditConfig round-trip' {
    It 'сохраняет и корректно читает конфиг' {
        Save-AuditConfig -Config $script:sample -Path $script:cfgPath
        Test-Path -LiteralPath $script:cfgPath | Should -BeTrue

        $env:AD_AUDIT_CONFIG = $script:cfgPath
        $cfg = Get-AuditConfig
        $cfg.Domain              | Should -Be 'corp.example.com'
        $cfg.ReportRetentionDays | Should -Be 5
        $cfg.SmtpRecipients      | Should -HaveCount 2
        $cfg.SmtpRecipients[0]   | Should -Be 'sec-ops@corp.example.com'
    }

    It 'нормализует одиночного получателя в массив' {
        $single = $script:sample.Clone()
        $single.SmtpRecipients = 'only@corp.example.com'
        $single.HibpExpectedSha256 = ('b' * 64)
        $path = Join-Path $script:sandbox 'single.psd1'
        Save-AuditConfig -Config $single -Path $path
        $env:AD_AUDIT_CONFIG = $path
        $cfg = Get-AuditConfig
        ,$cfg.SmtpRecipients | Should -BeOfType [array]
        $cfg.SmtpRecipients.Count | Should -Be 1
    }

    It 'бросает ошибку при отсутствующем обязательном поле' {
        $broken = $script:sample.Clone()
        $broken.Remove('SmimeCertificateThumbprint')
        $path = Join-Path $script:sandbox 'broken.psd1'
        Save-AuditConfig -Config $broken -Path $path
        $env:AD_AUDIT_CONFIG = $path
        { Get-AuditConfig } | Should -Throw '*SmimeCertificateThumbprint*'
    }

    It 'бросает ошибку, если конфига нет по указанному пути' {
        $env:AD_AUDIT_CONFIG = $null
        { Get-AuditConfig -Path 'C:\__nothing__.psd1' } | Should -Throw
    }
}

Describe 'Get-AuditConfigPath' {
    It 'возвращает путь из AD_AUDIT_CONFIG, если он существует' {
        $env:AD_AUDIT_CONFIG = $script:cfgPath
        Get-AuditConfigPath | Should -Be $script:cfgPath
    }

    It 'падает обратно на default, если переменной нет' {
        $env:AD_AUDIT_CONFIG = $null
        # default: C:\ProgramData\ADPasswordAudit\audit.config.psd1 —
        # не обязан существовать на CI, нам важно лишь значение.
        Get-AuditConfigPath | Should -Be 'C:\ProgramData\ADPasswordAudit\audit.config.psd1'
    }
}
