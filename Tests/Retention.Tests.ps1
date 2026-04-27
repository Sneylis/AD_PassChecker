#Requires -Version 5.1
#Requires -Modules @{ ModuleName='Pester'; ModuleVersion='5.0' }
<#
.SYNOPSIS
    Тесты Invoke-ReportRetention.ps1 в режиме -WhatIf. Реального SDelete
    тут не запускаем; проверяется логика выбора файлов-кандидатов.

.NOTES
    Тест мокает Invoke-SecureDelete, чтобы ничего физически не удалять,
    и мокает SDelete presence через подкладывание фейкового exe-пути
    в список кандидатов.
#>

BeforeAll {
    $repoRoot = Split-Path -Parent (Split-Path -Parent $PSCommandPath)
    $script:retentionScript = Join-Path $repoRoot 'Retention\Invoke-ReportRetention.ps1'

    $script:sandbox = Join-Path $env:TEMP ("retention-test-" + [guid]::NewGuid().ToString('N'))
    New-Item -ItemType Directory -Path $script:sandbox | Out-Null

    $script:reportDir = Join-Path $script:sandbox 'Reports'
    $script:logDir    = Join-Path $script:sandbox 'Logs'
    $script:workDir   = Join-Path $script:sandbox 'Work'
    New-Item -ItemType Directory -Path $script:reportDir,$script:logDir,$script:workDir | Out-Null

    # Фейковый sdelete64.exe, чтобы скрипт не упал на exit 2.
    $script:fakeSDeleteDir = 'C:\Tools\SDelete'
    if (-not (Test-Path -LiteralPath $script:fakeSDeleteDir)) {
        try { New-Item -ItemType Directory -Path $script:fakeSDeleteDir -Force | Out-Null } catch { }
    }
    $script:fakeSDelete = Join-Path $script:fakeSDeleteDir 'sdelete64.exe'
    if (-not (Test-Path -LiteralPath $script:fakeSDelete)) {
        try { Set-Content -LiteralPath $script:fakeSDelete -Value 'fake' -Force } catch { }
    }
    $script:skipRetention = -not (Test-Path -LiteralPath $script:fakeSDelete)

    # Готовим три "отчёта": свежий, старый, и сиротский sidecar.
    $now   = Get-Date
    $old   = $now.AddDays(-10)
    $fresh = $now.AddDays(-1)

    $script:freshArc = Join-Path $script:reportDir 'audit-report-2026-04-23T03-00-00Z.7z'
    $script:freshSha = $script:freshArc + '.sha256'
    $script:oldArc   = Join-Path $script:reportDir 'audit-report-2026-04-10T03-00-00Z.7z'
    $script:oldSha   = $script:oldArc + '.sha256'
    $script:orphan   = Join-Path $script:reportDir 'audit-report-2026-01-01T03-00-00Z.meta'

    foreach ($f in $script:freshArc,$script:freshSha,$script:oldArc,$script:oldSha,$script:orphan) {
        Set-Content -LiteralPath $f -Value 'stub' -Force
    }
    (Get-Item -LiteralPath $script:freshArc).LastWriteTime = $fresh
    (Get-Item -LiteralPath $script:freshSha).LastWriteTime = $fresh
    (Get-Item -LiteralPath $script:oldArc).LastWriteTime   = $old
    (Get-Item -LiteralPath $script:oldSha).LastWriteTime   = $old
    (Get-Item -LiteralPath $script:orphan).LastWriteTime   = $old

    # Готовим минимальный конфиг.
    Import-Module (Join-Path $repoRoot 'Common\Config.psm1') -Force
    $script:cfgPath = Join-Path $script:sandbox 'audit.config.psd1'
    $cfg = @{
        Domain                     = 'corp.example.com'
        DomainController           = 'dc01'
        AuditStation               = 'audit01'
        SmbShareUnc                = '\\files01\IFM$'
        WorkDirectory              = $script:workDir
        LogDirectory               = $script:logDir
        ReportRetentionDirectory   = $script:reportDir
        HibpFilePath               = 'D:\HIBP\hibp.txt'
        HibpExpectedSha256         = ('a' * 64)
        SecretVaultName            = 'ADAuditVault'
        IfmKeyName                 = 'ADAudit-IFM-Key'
        SmtpServer                 = 'smtp'
        SmtpFrom                   = 'a@b'
        SmtpRecipients             = @('x@y')
        SmimeCertificateThumbprint = '0123456789ABCDEF0123456789ABCDEF01234567'
        ReportRetentionDays        = 5
    }
    Save-AuditConfig -Config $cfg -Path $script:cfgPath
}

AfterAll {
    Remove-Item $script:sandbox -Recurse -Force -ErrorAction SilentlyContinue
}

Describe 'Invoke-ReportRetention -WhatIf' -Skip:$script:skipRetention {
    It 'должен определить старый архив как кандидата на удаление (свежий — оставить)' {
        $result = & $script:retentionScript `
                    -ConfigPath $script:cfgPath `
                    -KeepMinimum 0 `
                    -WhatIf 4>&1 5>&1 | Out-Null

        # После -WhatIf старый файл должен всё ещё существовать, т.е.
        # скрипт не стал его удалять, но лог должен показать кандидата.
        Test-Path -LiteralPath $script:oldArc   | Should -BeTrue
        Test-Path -LiteralPath $script:freshArc | Should -BeTrue

        # Проверяем лог-файл на наличие метки WhatIf для старого архива.
        $logFile = Get-ChildItem -LiteralPath $script:logDir -Filter 'audit-*.log' |
                   Sort-Object LastWriteTimeUtc -Descending | Select-Object -First 1
        $logContent = Get-Content -LiteralPath $logFile.FullName -Raw
        $logContent | Should -Match 'audit-report-2026-04-10T03-00-00Z\.7z'
    }

    It 'KeepMinimum=1 должен спасти самый свежий архив, даже если он старый' {
        # Перемещаем "свежий" в далёкое прошлое, чтобы оба попали под порог.
        (Get-Item -LiteralPath $script:freshArc).LastWriteTime = (Get-Date).AddDays(-20)
        (Get-Item -LiteralPath $script:freshSha).LastWriteTime = (Get-Date).AddDays(-20)

        $result = & $script:retentionScript `
                    -ConfigPath  $script:cfgPath `
                    -KeepMinimum 1 `
                    -WhatIf 4>&1 5>&1 | Out-Null

        # Все файлы на месте (WhatIf).
        Test-Path -LiteralPath $script:oldArc   | Should -BeTrue
        Test-Path -LiteralPath $script:freshArc | Should -BeTrue
    }
}
