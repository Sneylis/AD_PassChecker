<#
.SYNOPSIS
    Обёртки над SDelete64 и помощники для безопасной очистки.

.DESCRIPTION
    Централизует вызовы Sysinternals SDelete64 — трёхпроходная
    перезапись по стандарту DoD 5220.22-M. Используется во всех фазах
    для удаления расшифрованных ntds.dit, SYSTEM, открытых отчётов и
    прочих временных артефактов.

    Также содержит Invoke-WithGuaranteedCleanup — хелпер вокруг
    try/finally, чтобы код фаз получился короче и читаемее.

.NOTES
    Путь к sdelete64.exe задаётся либо через переменную окружения
    SDELETE_PATH (ставит установщик), либо ищется в PATH.
#>

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

Import-Module (Join-Path $PSScriptRoot 'Logging.psm1') -Force

function Find-SDeletePath {
    if ($env:SDELETE_PATH -and (Test-Path -LiteralPath $env:SDELETE_PATH)) {
        return $env:SDELETE_PATH
    }
    $fromPath = Get-Command sdelete64.exe -ErrorAction SilentlyContinue
    if ($fromPath) { return $fromPath.Source }

    $candidates = @(
        'C:\Tools\SDelete\sdelete64.exe',
        'C:\Program Files\Sysinternals\sdelete64.exe'
    )
    foreach ($c in $candidates) { if (Test-Path -LiteralPath $c) { return $c } }
    throw "sdelete64.exe не найден. Установите Sysinternals SDelete (установщик делает это автоматически)."
}

function Invoke-SecureDelete {
    <#
    .SYNOPSIS
        Безопасно удаляет файл или содержимое каталога через SDelete64.
    .PARAMETER Path
        Путь к файлу или директории.
    .PARAMETER Passes
        Количество проходов перезаписи (по умолчанию 3 — DoD).
    .PARAMETER Recurse
        Рекурсивно для директорий (добавляет -s флаг).
    .PARAMETER IgnoreMissing
        Не считать ошибкой отсутствие файла (актуально для finally-блоков).
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [string] $Path,
        [int] $Passes = 3,
        [switch] $Recurse,
        [switch] $IgnoreMissing
    )

    if (-not (Test-Path -LiteralPath $Path)) {
        if ($IgnoreMissing) {
            Write-AuditLog -Level DEBUG -Message "SDelete: путь $Path не существует, пропускаем"
            return
        }
        throw "Путь для безопасного удаления не существует: $Path"
    }

    $sdelete = Find-SDeletePath
    $args    = @("-p", $Passes, "-nobanner", "-accepteula")
    if ($Recurse) { $args += '-s' }
    $args += $Path

    Write-AuditLog -Level DEBUG -Message "SDelete: $Path (проходов: $Passes)"

    $outFile = [System.IO.Path]::GetTempFileName()
    $errFile = [System.IO.Path]::GetTempFileName()
    try {
        $proc = Start-Process -FilePath $sdelete -ArgumentList $args `
            -NoNewWindow -Wait -PassThru `
            -RedirectStandardOutput $outFile `
            -RedirectStandardError  $errFile

        if ($proc.ExitCode -ne 0) {
            $errText = Get-Content -LiteralPath $errFile -Raw -ErrorAction SilentlyContinue
            throw "SDelete вернул код $($proc.ExitCode) для $Path. stderr: $errText"
        }
    } finally {
        Remove-Item -LiteralPath $outFile, $errFile -ErrorAction SilentlyContinue
    }
}

function Invoke-WithGuaranteedCleanup {
    <#
    .SYNOPSIS
        Запускает -Action и гарантированно вызывает -Cleanup, даже если
        -Action упал. Ошибка cleanup-а логируется как WARN, но НЕ
        затеняет оригинальное исключение из -Action.
    .EXAMPLE
        Invoke-WithGuaranteedCleanup `
            -Action  { Do-Phase1 } `
            -Cleanup { Invoke-SecureDelete $temp -IgnoreMissing }
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [scriptblock] $Action,
        [Parameter(Mandatory)] [scriptblock] $Cleanup
    )

    $originalError = $null
    try {
        & $Action
    } catch {
        $originalError = $_
        throw
    } finally {
        try {
            & $Cleanup
        } catch {
            Write-AuditLog -Level WARN -Message "Ошибка в cleanup-блоке: $($_.Exception.Message)"
            # Не re-throw — не хотим затенять оригинал.
        }
    }
}

function Test-CleanupResidue {
    <#
    .SYNOPSIS
        Финальная верификация Фазы 5: ищет оставшиеся чувствительные
        файлы в указанных директориях и возвращает список. Пустой список
        = всё чисто.
    #>
    [OutputType([string[]])]
    param(
        [Parameter(Mandatory)] [string[]] $Directories,
        [string[]] $Patterns = @('*.dit', '*.tmp', 'SYSTEM', 'report-*.txt', 'ntds*', '*.bak')
    )

    $found = @()
    foreach ($dir in $Directories) {
        if (-not (Test-Path -LiteralPath $dir)) { continue }
        foreach ($pat in $Patterns) {
            $matches = Get-ChildItem -LiteralPath $dir -Recurse -Force -Filter $pat -ErrorAction SilentlyContinue
            if ($matches) { $found += $matches.FullName }
        }
    }
    return $found
}

Export-ModuleMember -Function `
    Invoke-SecureDelete, Invoke-WithGuaranteedCleanup, Test-CleanupResidue
