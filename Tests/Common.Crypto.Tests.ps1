#Requires -Version 5.1
#Requires -Modules @{ ModuleName='Pester'; ModuleVersion='5.0' }
<#
.SYNOPSIS
    Pester-тесты модуля Common\Crypto.psm1.

.DESCRIPTION
    Покрывают:
      • NTLM (MD4 от UTF-16LE) — по эталонным векторам Microsoft.
      • SHA-256 файла и строки.
      • Генерация AES-ключа / strong password.
      • 7z Protect/Unprotect round-trip (требует 7z.exe в PATH,
        пропускается, если его нет).

    Запускать:
        Invoke-Pester -Path .\Tests\Common.Crypto.Tests.ps1 -Output Detailed
#>

BeforeAll {
    $repoRoot = Split-Path -Parent (Split-Path -Parent $PSCommandPath)
    Import-Module (Join-Path $repoRoot 'Common\Crypto.psm1') -Force
}

Describe 'Get-NtlmHashFromString' {
    It 'возвращает известный NTLM для пустой строки' {
        # Стандартный эталон: NTLM("") = 31D6CFE0D16AE931B73C59D7E0C089C0
        (Get-NtlmHashFromString -Password '') | Should -Be '31D6CFE0D16AE931B73C59D7E0C089C0'
    }

    It 'возвращает известный NTLM для "password"' {
        (Get-NtlmHashFromString -Password 'password') | Should -Be '8846F7EAEE8FB117AD06BDD830B7586C'
    }

    It 'возвращает известный NTLM для "Password123"' {
        (Get-NtlmHashFromString -Password 'Password123') | Should -Be '58A478135A93AC3BF058A5EA0E8FDB71'
    }

    It 'различает заглавные и строчные' {
        (Get-NtlmHashFromString -Password 'Password') |
            Should -Not -Be (Get-NtlmHashFromString -Password 'password')
    }

    It 'корректно считает для unicode (кириллица)' {
        # Длина хеша = 32 символа hex, то есть 16 байт — это основное
        # свойство, которое нам важно; конкретное значение зависит от
        # кодировки (должно быть UTF-16LE).
        $hash = Get-NtlmHashFromString -Password 'ПарольПарль123'
        $hash | Should -Match '^[0-9A-F]{32}$'
    }
}

Describe 'Get-Sha256Hash' {
    It 'считает SHA-256 от файла и возвращает lowercase hex' {
        $tmp = [System.IO.Path]::GetTempFileName()
        try {
            Set-Content -LiteralPath $tmp -Value 'hello' -NoNewline -Encoding Ascii
            $hash = Get-Sha256Hash -Path $tmp
            $hash | Should -Be '2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824'
            $hash | Should -MatchExactly '^[0-9a-f]{64}$'
        } finally {
            Remove-Item -LiteralPath $tmp -Force -ErrorAction SilentlyContinue
        }
    }

    It 'бросает понятную ошибку для отсутствующего файла' {
        { Get-Sha256Hash -Path 'C:\__definitely__not__exist__.tmp' } |
            Should -Throw -ErrorId '*'
    }
}

Describe 'Get-Sha256StringHash' {
    It 'считает SHA-256 от UTF-8 строки' {
        $hash = Get-Sha256StringHash -InputString 'hello'
        $hash | Should -Be '2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824'
    }
}

Describe 'New-AesKey' {
    It 'возвращает SecureString' {
        $key = New-AesKey
        try {
            $key | Should -BeOfType [System.Security.SecureString]
            $key.Length | Should -BeGreaterThan 0
        } finally {
            Clear-SensitiveVariable -SecureString $key
        }
    }

    It 'генерирует разные ключи на каждом вызове' {
        $k1 = New-AesKey
        $k2 = New-AesKey
        try {
            # Разворачиваем только для теста через BSTR.
            $b1 = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($k1)
            $b2 = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($k2)
            try {
                $s1 = [System.Runtime.InteropServices.Marshal]::PtrToStringBSTR($b1)
                $s2 = [System.Runtime.InteropServices.Marshal]::PtrToStringBSTR($b2)
                $s1 | Should -Not -Be $s2
            } finally {
                [System.Runtime.InteropServices.Marshal]::ZeroFreeBSTR($b1)
                [System.Runtime.InteropServices.Marshal]::ZeroFreeBSTR($b2)
            }
        } finally {
            Clear-SensitiveVariable -SecureString $k1
            Clear-SensitiveVariable -SecureString $k2
        }
    }
}

Describe 'New-StrongPassword' {
    It 'имеет ожидаемую длину' {
        $pw = New-StrongPassword -Length 24
        try { $pw.Length | Should -Be 24 } finally { $pw.Dispose() }
    }

    It 'генерирует уникальные значения' {
        $p1 = New-StrongPassword -Length 32
        $p2 = New-StrongPassword -Length 32
        try {
            $b1 = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($p1)
            $b2 = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($p2)
            try {
                $s1 = [System.Runtime.InteropServices.Marshal]::PtrToStringBSTR($b1)
                $s2 = [System.Runtime.InteropServices.Marshal]::PtrToStringBSTR($b2)
                $s1 | Should -Not -Be $s2
                # Разрешённые символы.
                $s1 | Should -MatchExactly '^[A-Za-z0-9!@#%&*_-]+$'
            } finally {
                [System.Runtime.InteropServices.Marshal]::ZeroFreeBSTR($b1)
                [System.Runtime.InteropServices.Marshal]::ZeroFreeBSTR($b2)
            }
        } finally {
            $p1.Dispose(); $p2.Dispose()
        }
    }
}

Describe '7z round-trip (Protect-Archive / Unprotect-Archive)' -Tag 'RequiresSevenZip' {
    BeforeAll {
        $script:has7z = $null -ne (Get-Command 7z.exe -ErrorAction SilentlyContinue)
    }

    It 'успешно шифрует и расшифровывает файл' -Skip:(-not $script:has7z) {
        $srcDir = Join-Path $env:TEMP ("7z-test-" + [guid]::NewGuid().ToString('N'))
        New-Item -ItemType Directory -Path $srcDir | Out-Null
        $srcFile = Join-Path $srcDir 'input.txt'
        'Pester round-trip payload' | Set-Content -LiteralPath $srcFile -Encoding UTF8

        $arc = Join-Path $env:TEMP ("7z-test-{0}.7z" -f [guid]::NewGuid().ToString('N'))
        $dst = Join-Path $env:TEMP ("7z-test-dst-{0}" -f [guid]::NewGuid().ToString('N'))

        $pw = New-StrongPassword -Length 20
        try {
            Protect-Archive   -Source $srcFile -Destination $arc -Password $pw
            Test-Path -LiteralPath $arc | Should -BeTrue
            Unprotect-Archive -Archive $arc -Destination $dst -Password $pw
            $extracted = Get-ChildItem -LiteralPath $dst -Recurse -File
            $extracted.Count | Should -BeGreaterThan 0
            (Get-Content -LiteralPath $extracted[0].FullName -Raw).Trim() |
                Should -Be 'Pester round-trip payload'
        } finally {
            $pw.Dispose()
            Remove-Item $srcDir -Recurse -Force -ErrorAction SilentlyContinue
            Remove-Item $arc           -Force -ErrorAction SilentlyContinue
            Remove-Item $dst -Recurse  -Force -ErrorAction SilentlyContinue
        }
    }
}
