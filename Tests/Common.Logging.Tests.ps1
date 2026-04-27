#Requires -Version 5.1
#Requires -Modules @{ ModuleName='Pester'; ModuleVersion='5.0' }
<#
.SYNOPSIS
    Тесты модуля Common\Logging.psm1.
#>

BeforeAll {
    $repoRoot = Split-Path -Parent (Split-Path -Parent $PSCommandPath)
    Import-Module (Join-Path $repoRoot 'Common\Logging.psm1') -Force

    $script:logDir = Join-Path $env:TEMP ("audit-log-test-" + [guid]::NewGuid().ToString('N'))
    New-Item -ItemType Directory -Path $script:logDir | Out-Null
}

AfterAll {
    Remove-Item $script:logDir -Recurse -Force -ErrorAction SilentlyContinue
}

Describe 'Initialize-AuditLog' {
    It 'создаёт CID и файл лога' {
        Initialize-AuditLog -LogDirectory $script:logDir -PhaseName 'UT-1'
        $cid = Get-AuditCorrelationId
        $cid | Should -MatchExactly '^[0-9a-f]{8}$'
        $files = Get-ChildItem -LiteralPath $script:logDir -Filter 'audit-*.log'
        $files.Count | Should -BeGreaterOrEqual 1
    }

    It 'принимает внешний CorrelationId' {
        Initialize-AuditLog -LogDirectory $script:logDir -PhaseName 'UT-2' -CorrelationId 'deadbeef'
        Get-AuditCorrelationId | Should -Be 'deadbeef'
    }
}

Describe 'Write-AuditLog — форматирование и файл' {
    BeforeAll {
        Initialize-AuditLog -LogDirectory $script:logDir -PhaseName 'UT-W' -CorrelationId 'abcdef01'
    }

    It 'пишет строку в лог-файл с CID и фазой' {
        Write-AuditLog -Level INFO -Message 'hello-from-pester'
        $file = Get-ChildItem -LiteralPath $script:logDir -Filter 'audit-*.log' |
                Sort-Object LastWriteTimeUtc -Descending | Select-Object -First 1
        $content = Get-Content -LiteralPath $file.FullName -Raw
        $content | Should -Match 'hello-from-pester'
        $content | Should -Match 'CID=abcdef01'
        $content | Should -Match '\[UT-W\]'
    }

    It 'Set-AuditPhase переключает фазу' {
        Set-AuditPhase -PhaseName 'UT-W2'
        Write-AuditLog -Level INFO -Message 'phase-switched'
        $file = Get-ChildItem -LiteralPath $script:logDir -Filter 'audit-*.log' |
                Sort-Object LastWriteTimeUtc -Descending | Select-Object -First 1
        (Get-Content -LiteralPath $file.FullName -Raw) | Should -Match '\[UT-W2\].*phase-switched'
    }

    It 'поддерживает уровни DEBUG/INFO/WARN/ERROR/CRITICAL' {
        foreach ($lvl in 'DEBUG','INFO','WARN','ERROR','CRITICAL') {
            { Write-AuditLog -Level $lvl -Message "test-$lvl" } | Should -Not -Throw
        }
    }

    It 'отвергает некорректный уровень' {
        { Write-AuditLog -Level 'TRACE' -Message 'x' } | Should -Throw
    }
}
