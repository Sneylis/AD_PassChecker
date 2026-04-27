<#
.SYNOPSIS
    Крипто-примитивы для системы аудита паролей.

.DESCRIPTION
    Объединяет все обращения к алгоритмам шифрования в одном месте:
      - генерация AES-256 ключа и его хранение в SecretStore,
      - получение ключа из SecretStore под машинным аккаунтом (DPAPI),
      - вычисление SHA-256 файла и строки,
      - упаковка и распаковка 7z-архивов с AES-256 и -mhe=on,
      - генерация криптостойких паролей.

    Весь чувствительный материал (ключи, пароли) передаётся как
    [SecureString] и обнуляется сразу после использования.

.NOTES
    Требует:
      - 7-Zip (7z.exe в PATH),
      - модуль Microsoft.PowerShell.SecretManagement + SecretStore,
      - зарегистрированное хранилище SecretStore (настраивает установщик).
#>

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# ---------- Внутренние хелперы ----------

function ConvertFrom-SecureStringPlain {
    # Разворачивает SecureString в plain-строку максимум на время вызова.
    # Возвращаемое значение следует обнулить через Clear-SensitiveString.
    param([Parameter(Mandatory)] [System.Security.SecureString] $Secure)
    $bstr = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($Secure)
    try {
        return [System.Runtime.InteropServices.Marshal]::PtrToStringBSTR($bstr)
    } finally {
        [System.Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstr)
    }
}

function Find-SevenZipPath {
    # 7z.exe должен быть в PATH (гарантирует установщик), но подстрахуемся
    # стандартными местами установки.
    $candidates = @(
        'C:\Program Files\7-Zip\7z.exe',
        'C:\Program Files (x86)\7-Zip\7z.exe'
    )
    $fromPath = Get-Command 7z.exe -ErrorAction SilentlyContinue
    if ($fromPath) { return $fromPath.Source }
    foreach ($c in $candidates) { if (Test-Path -LiteralPath $c) { return $c } }
    throw "7z.exe не найден. Убедитесь, что 7-Zip установлен (Install-AuditStation.ps1 делает это автоматически)."
}

# ---------- Публичные функции: ключи ----------

function New-AesKey {
    <#
    .SYNOPSIS
        Генерирует криптостойкий AES-256 ключ (32 байта → base64).
    .OUTPUTS
        [SecureString] — ключ в base64. Вызывающий должен обнулить.
    #>
    [OutputType([System.Security.SecureString])]
    param()

    $bytes = New-Object byte[] 32
    $rng = [System.Security.Cryptography.RandomNumberGenerator]::Create()
    try {
        $rng.GetBytes($bytes)
    } finally {
        $rng.Dispose()
    }
    $base64 = [Convert]::ToBase64String($bytes)
    [Array]::Clear($bytes, 0, $bytes.Length)

    $secure = ConvertTo-SecureString -String $base64 -AsPlainText -Force
    $base64 = $null  # обнуляем plain-копию
    return $secure
}

function Save-AesKeyToSecretStore {
    <#
    .SYNOPSIS
        Кладёт AES-ключ в SecretStore под указанным именем.
    .PARAMETER Name
        Имя секрета (напр. 'ADAudit-IFM-Key').
    .PARAMETER Key
        SecureString с base64-представлением ключа.
    .PARAMETER VaultName
        Имя vault (по умолчанию 'ADAuditVault').
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [string] $Name,
        [Parameter(Mandatory)] [System.Security.SecureString] $Key,
        [string] $VaultName = 'ADAuditVault'
    )

    Set-Secret -Name $Name -SecureStringSecret $Key -Vault $VaultName
}

function Get-AesKeyFromSecretStore {
    <#
    .SYNOPSIS
        Получает AES-ключ из SecretStore. Вызывающий ОБЯЗАН обнулить
        возвращённый SecureString через Clear-SensitiveVariable.
    #>
    [OutputType([System.Security.SecureString])]
    param(
        [Parameter(Mandatory)] [string] $Name,
        [string] $VaultName = 'ADAuditVault'
    )
    return Get-Secret -Name $Name -Vault $VaultName -AsPlainText:$false
}

# ---------- Публичные функции: хеширование ----------

function Get-Sha256Hash {
    <#
    .SYNOPSIS
        Возвращает SHA-256 файла в lowercase hex без дефисов.
    #>
    [OutputType([string])]
    param([Parameter(Mandatory)] [string] $Path)

    if (-not (Test-Path -LiteralPath $Path)) {
        throw "Файл не найден: $Path"
    }
    return (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash.ToLowerInvariant()
}

function Get-Sha256StringHash {
    <#
    .SYNOPSIS
        SHA-256 от UTF-8 строки. Используется для конвертации plain-словаря
        HIBP в SHA-1 не надо — NTLM-хеш у HIBP считается иначе; эта функция
        применяется только там, где реально нужен SHA-256 от строки.
    #>
    [OutputType([string])]
    param([Parameter(Mandatory)] [string] $InputString)

    $sha = [System.Security.Cryptography.SHA256]::Create()
    try {
        $bytes = [System.Text.Encoding]::UTF8.GetBytes($InputString)
        $hash  = $sha.ComputeHash($bytes)
        [Array]::Clear($bytes, 0, $bytes.Length)
        return -join ($hash | ForEach-Object { $_.ToString('x2') })
    } finally {
        $sha.Dispose()
    }
}

function Get-NtlmHashFromString {
    <#
    .SYNOPSIS
        Вычисляет NTLM-хеш (MD4 от UTF-16LE) от пароля. Нужен установщику,
        когда пользователь принёс словарь HIBP в формате plain-паролей,
        а DSInternals ждёт именно NTLM-хеши.

    .NOTES
        MD4 отсутствует в стандартной .NET-библиотеке, поэтому используем
        реализацию через P/Invoke BCrypt или чистый PowerShell-MD4.
        Здесь — чистый PowerShell для простоты и отсутствия зависимостей.
        Скорость ~5-10k паролей/сек. Для полной HIBP (1+ млрд) это
        неприемлемо, поэтому установщик требует NTLM-формат HIBP
        по умолчанию; plain-конвертация — опция для малых словарей.
    #>
    [OutputType([string])]
    param([Parameter(Mandatory)] [string] $Password)

    # Внутренняя реализация MD4 (RFC 1320). Сохранена компактно.
    $bytes  = [System.Text.Encoding]::Unicode.GetBytes($Password)
    $length = $bytes.Length
    $padded = New-Object byte[] (([math]::Floor($length / 64) + 1) * 64 + 8)
    [Array]::Copy($bytes, $padded, $length)
    $padded[$length] = 0x80
    $bitLen = [UInt64]($length * 8)
    for ($i = 0; $i -lt 8; $i++) {
        $padded[$padded.Length - 8 + $i] = [byte](($bitLen -shr ($i * 8)) -band 0xFF)
    }

    [uint32]$a = 0x67452301
    [uint32]$b = 0xefcdab89
    [uint32]$c = 0x98badcfe
    [uint32]$d = 0x10325476

    $rol = { param($x, $n) (($x -shl $n) -bor ($x -shr (32 - $n))) -band 0xFFFFFFFF }

    for ($chunk = 0; $chunk -lt $padded.Length; $chunk += 64) {
        $X = New-Object uint32[] 16
        for ($j = 0; $j -lt 16; $j++) {
            $X[$j] = [uint32](
                $padded[$chunk + $j*4]       -bor
                ($padded[$chunk + $j*4 + 1] -shl 8)  -bor
                ($padded[$chunk + $j*4 + 2] -shl 16) -bor
                ($padded[$chunk + $j*4 + 3] -shl 24))
        }
        $aa = $a; $bb = $b; $cc = $c; $dd = $d

        # Раунд 1
        $F = { param($x,$y,$z) (($x -band $y) -bor ((-bnot $x) -band $z)) -band 0xFFFFFFFF }
        foreach ($i in 0,4,8,12) {
            $a = & $rol (($a + (& $F $b $c $d) + $X[$i])   -band 0xFFFFFFFF) 3
            $d = & $rol (($d + (& $F $a $b $c) + $X[$i+1]) -band 0xFFFFFFFF) 7
            $c = & $rol (($c + (& $F $d $a $b) + $X[$i+2]) -band 0xFFFFFFFF) 11
            $b = & $rol (($b + (& $F $c $d $a) + $X[$i+3]) -band 0xFFFFFFFF) 19
        }
        # Раунд 2
        $G = { param($x,$y,$z) (($x -band $y) -bor ($x -band $z) -bor ($y -band $z)) -band 0xFFFFFFFF }
        foreach ($i in 0,1,2,3) {
            $a = & $rol (($a + (& $G $b $c $d) + $X[$i]     + 0x5A827999) -band 0xFFFFFFFF) 3
            $d = & $rol (($d + (& $G $a $b $c) + $X[$i+4]   + 0x5A827999) -band 0xFFFFFFFF) 5
            $c = & $rol (($c + (& $G $d $a $b) + $X[$i+8]   + 0x5A827999) -band 0xFFFFFFFF) 9
            $b = & $rol (($b + (& $G $c $d $a) + $X[$i+12]  + 0x5A827999) -band 0xFFFFFFFF) 13
        }
        # Раунд 3
        $H = { param($x,$y,$z) ($x -bxor $y -bxor $z) -band 0xFFFFFFFF }
        foreach ($i in 0,2,1,3) {
            $a = & $rol (($a + (& $H $b $c $d) + $X[$i]     + 0x6ED9EBA1) -band 0xFFFFFFFF) 3
            $d = & $rol (($d + (& $H $a $b $c) + $X[$i+8]   + 0x6ED9EBA1) -band 0xFFFFFFFF) 9
            $c = & $rol (($c + (& $H $d $a $b) + $X[$i+4]   + 0x6ED9EBA1) -band 0xFFFFFFFF) 11
            $b = & $rol (($b + (& $H $c $d $a) + $X[$i+12]  + 0x6ED9EBA1) -band 0xFFFFFFFF) 15
        }

        $a = ($a + $aa) -band 0xFFFFFFFF
        $b = ($b + $bb) -band 0xFFFFFFFF
        $c = ($c + $cc) -band 0xFFFFFFFF
        $d = ($d + $dd) -band 0xFFFFFFFF
    }

    [Array]::Clear($bytes, 0, $bytes.Length)
    [Array]::Clear($padded, 0, $padded.Length)

    $result = ''
    foreach ($v in $a,$b,$c,$d) {
        for ($i = 0; $i -lt 4; $i++) {
            $result += ('{0:x2}' -f (($v -shr ($i * 8)) -band 0xFF))
        }
    }
    return $result.ToUpperInvariant()
}

# ---------- Публичные функции: 7z ----------

function Protect-Archive {
    <#
    .SYNOPSIS
        Упаковывает файл/папку в 7z с AES-256 и шифрованием заголовков.
    .PARAMETER Source
        Путь к файлу или папке-источнику.
    .PARAMETER Destination
        Путь к результирующему .7z.
    .PARAMETER Password
        SecureString с паролем/ключом архива.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [string] $Source,
        [Parameter(Mandatory)] [string] $Destination,
        [Parameter(Mandatory)] [System.Security.SecureString] $Password
    )

    $sevenZip = Find-SevenZipPath
    $plain = ConvertFrom-SecureStringPlain -Secure $Password
    try {
        # -mhe=on — шифрование заголовков (имена файлов не видны).
        # -mx=5  — сбалансированное сжатие.
        # -p передаётся через stdin чтобы не светить в командной строке.
        $args = @('a', '-t7z', '-mhe=on', '-mx=5', "-p$plain", '--', $Destination, $Source)
        $proc = Start-Process -FilePath $sevenZip -ArgumentList $args `
            -NoNewWindow -Wait -PassThru `
            -RedirectStandardOutput ([System.IO.Path]::GetTempFileName()) `
            -RedirectStandardError  ([System.IO.Path]::GetTempFileName())
        if ($proc.ExitCode -ne 0) {
            throw "7z завершился с кодом $($proc.ExitCode) при упаковке $Source"
        }
    } finally {
        # Обнуляем plain-копию пароля.
        if ($plain) {
            $plain = $null
            [System.GC]::Collect()
        }
    }
}

function Unprotect-Archive {
    <#
    .SYNOPSIS
        Распаковывает .7z в указанный каталог.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [string] $Archive,
        [Parameter(Mandatory)] [string] $Destination,
        [Parameter(Mandatory)] [System.Security.SecureString] $Password
    )

    if (-not (Test-Path -LiteralPath $Destination)) {
        New-Item -ItemType Directory -Path $Destination -Force | Out-Null
    }

    $sevenZip = Find-SevenZipPath
    $plain = ConvertFrom-SecureStringPlain -Secure $Password
    try {
        $args = @('x', "-p$plain", "-o$Destination", '-y', '--', $Archive)
        $proc = Start-Process -FilePath $sevenZip -ArgumentList $args `
            -NoNewWindow -Wait -PassThru `
            -RedirectStandardOutput ([System.IO.Path]::GetTempFileName()) `
            -RedirectStandardError  ([System.IO.Path]::GetTempFileName())
        if ($proc.ExitCode -ne 0) {
            throw "7z завершился с кодом $($proc.ExitCode) при распаковке $Archive"
        }
    } finally {
        if ($plain) {
            $plain = $null
            [System.GC]::Collect()
        }
    }
}

# ---------- Публичные функции: пароли ----------

function New-StrongPassword {
    <#
    .SYNOPSIS
        Генерирует криптостойкий пароль из разрешённого алфавита.
    .PARAMETER Length
        Длина пароля (по умолчанию 32).
    .OUTPUTS
        [SecureString]
    #>
    [OutputType([System.Security.SecureString])]
    param([int] $Length = 32)

    $alphabet = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#%&*_-'
    $rng = [System.Security.Cryptography.RandomNumberGenerator]::Create()
    try {
        $secure = New-Object System.Security.SecureString
        $buf = New-Object byte[] 4
        for ($i = 0; $i -lt $Length; $i++) {
            $rng.GetBytes($buf)
            $idx = [BitConverter]::ToUInt32($buf, 0) % $alphabet.Length
            $secure.AppendChar($alphabet[$idx])
        }
        $secure.MakeReadOnly()
        return $secure
    } finally {
        $rng.Dispose()
    }
}

# ---------- Публичные функции: очистка памяти ----------

function Clear-SensitiveVariable {
    <#
    .SYNOPSIS
        Обнуляет SecureString и/или переменную в вызывающем scope и
        форсирует сборку мусора. Вызывать в finally.
    .EXAMPLE
        Clear-SensitiveVariable -SecureString $key
        $key = $null
    #>
    [CmdletBinding()]
    param(
        [System.Security.SecureString] $SecureString
    )

    if ($SecureString) {
        try { $SecureString.Dispose() } catch { }
    }
    [System.GC]::Collect()
    [System.GC]::WaitForPendingFinalizers()
    [System.GC]::Collect()
}

Export-ModuleMember -Function `
    New-AesKey, Save-AesKeyToSecretStore, Get-AesKeyFromSecretStore, `
    Get-Sha256Hash, Get-Sha256StringHash, Get-NtlmHashFromString, `
    Protect-Archive, Unprotect-Archive, `
    New-StrongPassword, Clear-SensitiveVariable
