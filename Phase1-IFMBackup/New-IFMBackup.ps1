#Requires -Version 5.1
<#
.SYNOPSIS
    Фаза 1: создание IFM-бэкапа AD, шифрование и передача на станцию аудита.

.DESCRIPTION
    Запускается на контроллере домена от имени gMSA с Backup Operator.
    Полный алгоритм из регламента (раздел "ФАЗА 1"):

        1. Проверки зависимостей
        2. Получение AES-256 ключа из SecretStore
        3. ntdsutil IFM → ntds.dit + SYSTEM
        4. 7z AES-256 с -mhe=on немедленно
        5. SDelete64 незашифрованных файлов (3 прохода)
        6. SHA-256 архива (локально)
        7. Copy по SMB 3.0 на станцию аудита
        8. Повторное вычисление SHA-256 файла по UNC-пути — сверка.
           Совпадение гарантирует побайтовую целостность передачи.
           (SMB 3.0 даёт TLS-подобную защиту на транспорте, этот шаг —
            application-layer проверка поверх неё.)
        9. SDelete64 локальной копии архива
       10. Обнуление ключа + форсированный GC

    Вся работа в try/finally + Invoke-WithGuaranteedCleanup:
    finally-блок гарантирует SDelete всех временных артефактов
    независимо от того, упал ли скрипт посередине. Startup-скрипт,
    установленный Install-DCComponents.ps1, подстрахует от сбоев
    питания — при старте DC подчистит C:\IFM_Work.

.PARAMETER ConfigPath
    Путь к audit.config.psd1.

.PARAMETER IfmWorkDirectory
    Рабочая папка на DC (по умолчанию C:\IFM_Work).

.PARAMETER Manual
    Сигнализирует, что запуск ручной — меняется только формат логов
    (добавляется пометка MANUAL в Correlation ID).

.EXAMPLE
    .\New-IFMBackup.ps1 -ConfigPath 'C:\ProgramData\ADPasswordAudit\audit.config.psd1'

.NOTES
    Exit codes:
        0 — успех
        1 — проблема зависимостей
        2 — ntdsutil / бэкап не создан
        3 — ошибка шифрования
        4 — ошибка передачи или сверки хеша
        99 — непредвиденная ошибка (см. лог)
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory)] [string] $ConfigPath,
    [string] $IfmWorkDirectory = 'C:\IFM_Work',
    [switch] $Manual
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

# ---------- Загрузка общих модулей ----------
# Скрипт разворачивается в C:\Scripts\AD-Password-Audit\Phase1-IFMBackup
# поэтому путь до Common/ отсчитываем на два уровня вверх.
$repoRoot = Split-Path -Parent (Split-Path -Parent $MyInvocation.MyCommand.Path)
Import-Module (Join-Path $repoRoot 'Common\Logging.psm1')        -Force
Import-Module (Join-Path $repoRoot 'Common\Crypto.psm1')         -Force
Import-Module (Join-Path $repoRoot 'Common\CleanupHelpers.psm1') -Force
Import-Module (Join-Path $repoRoot 'Common\Config.psm1')         -Force

# Уникальный идентификатор прогона. Если ручной запуск — префиксуем.
$cid = if ($Manual) { "MANUAL-$([Guid]::NewGuid().ToString('N').Substring(0,8))" }
       else        { [Guid]::NewGuid().ToString('N').Substring(0,8) }

Initialize-AuditLog -LogDirectory 'C:\AuditLogs' -CorrelationId $cid -PhaseName 'Phase1'
Write-AuditLog -Level INFO -Message '=== Фаза 1: создание IFM-бэкапа начата ==='
Write-AuditLog -Level INFO -Message "Запущено от: $([Security.Principal.WindowsIdentity]::GetCurrent().Name)"

# ---------- Шаг 1: проверки зависимостей ----------

function Test-Phase1Dependencies {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [string] $SmbShareUnc,
        [Parameter(Mandatory)] [string] $WorkDirectory
    )

    Write-AuditLog -Level INFO -Message 'Проверка зависимостей...'
    $problems = @()

    # ntdsutil
    if (-not (Get-Command ntdsutil.exe -ErrorAction SilentlyContinue)) {
        $problems += 'ntdsutil.exe не найден. Установите AD DS Tools (RSAT).'
    }

    # 7z
    try { [void] (Get-Command 7z.exe -ErrorAction Stop) }
    catch {
        $candidates = 'C:\Program Files\7-Zip\7z.exe','C:\Program Files (x86)\7-Zip\7z.exe'
        if (-not ($candidates | Where-Object { Test-Path $_ })) {
            $problems += '7z.exe не найден. Запустите Install-DCComponents.ps1.'
        }
    }

    # SDelete64
    if (-not $env:SDELETE_PATH -or -not (Test-Path -LiteralPath $env:SDELETE_PATH)) {
        $problems += 'SDELETE_PATH не задан или sdelete64.exe отсутствует. Запустите Install-DCComponents.ps1.'
    }

    # SMB доступность
    try {
        $null = Test-Path -LiteralPath $SmbShareUnc -ErrorAction Stop
        if (-not (Test-Path -LiteralPath $SmbShareUnc)) {
            $problems += "SMB-шара недоступна: $SmbShareUnc"
        }
    } catch {
        $problems += "Ошибка доступа к $SmbShareUnc : $($_.Exception.Message)"
    }

    # Рабочая папка
    if (-not (Test-Path -LiteralPath $WorkDirectory)) {
        New-Item -ItemType Directory -Path $WorkDirectory -Force | Out-Null
    }
    # Свободное место — ntdsutil IFM создаёт копию всего ntds.dit плюс
    # registry\SYSTEM. Оцениваем потребность как 3x текущего ntds.dit.
    try {
        $nt = (Get-Item 'C:\Windows\NTDS\ntds.dit' -ErrorAction SilentlyContinue)
        if ($nt) {
            $freeSpace = (Get-PSDrive -Name ((Split-Path -Qualifier $WorkDirectory).TrimEnd(':'))).Free
            $needed = $nt.Length * 3
            if ($freeSpace -lt $needed) {
                $problems += ('Недостаточно места на {0}: есть {1:N0} MB, нужно ~{2:N0} MB' -f `
                    $WorkDirectory, ($freeSpace / 1MB), ($needed / 1MB))
            }
        }
    } catch { }

    # SecretStore
    try {
        Import-Module Microsoft.PowerShell.SecretStore -ErrorAction Stop
    } catch {
        $problems += 'Модуль SecretStore не установлен.'
    }

    if ($problems.Count -gt 0) {
        foreach ($p in $problems) { Write-AuditLog -Level ERROR -Message "  - $p" }
        throw 'Проверка зависимостей провалена. См. ошибки выше.'
    }

    Write-AuditLog -Level INFO -Message 'Все зависимости на месте.'
}

# ---------- Шаг 3: ntdsutil IFM ----------

function Invoke-NtdsutilIfm {
    [CmdletBinding()]
    param([Parameter(Mandatory)] [string] $OutputDirectory)

    Write-AuditLog -Level INFO -Message "Запуск ntdsutil IFM → $OutputDirectory"

    # ntdsutil принимает команды через stdin. Используем activate instance ntds,
    # ifm, create full <path>, q, q.
    # create full создаёт полную структуру: Active Directory\ntds.dit и registry\SYSTEM (+SECURITY).
    $cmdFile = [System.IO.Path]::GetTempFileName()
    try {
        @(
            'activate instance ntds'
            'ifm'
            "create full `"$OutputDirectory`""
            'q'
            'q'
        ) | Set-Content -LiteralPath $cmdFile -Encoding ASCII

        $outFile = [System.IO.Path]::GetTempFileName()
        $errFile = [System.IO.Path]::GetTempFileName()
        try {
            # ntdsutil читает файл если подать < file. Проще через Get-Content | ntdsutil.
            $ps = Start-Process -FilePath 'ntdsutil.exe' `
                -RedirectStandardInput  $cmdFile `
                -RedirectStandardOutput $outFile `
                -RedirectStandardError  $errFile `
                -NoNewWindow -Wait -PassThru

            $stdout = Get-Content -LiteralPath $outFile -Raw -ErrorAction SilentlyContinue
            $stderr = Get-Content -LiteralPath $errFile -Raw -ErrorAction SilentlyContinue

            if ($ps.ExitCode -ne 0) {
                Write-AuditLog -Level ERROR -Message "ntdsutil exit code $($ps.ExitCode)"
                Write-AuditLog -Level ERROR -Message "stdout: $stdout"
                Write-AuditLog -Level ERROR -Message "stderr: $stderr"
                throw 'ntdsutil IFM завершился с ошибкой.'
            }

            # Убеждаемся, что ntds.dit и SYSTEM появились.
            $dit = Get-ChildItem -LiteralPath $OutputDirectory -Recurse -Filter 'ntds.dit' -ErrorAction SilentlyContinue | Select-Object -First 1
            $sys = Get-ChildItem -LiteralPath $OutputDirectory -Recurse -Filter 'SYSTEM' -ErrorAction SilentlyContinue | Select-Object -First 1
            if (-not $dit -or -not $sys) {
                throw 'ntdsutil IFM не создал ожидаемые файлы (ntds.dit + SYSTEM).'
            }
            Write-AuditLog -Level INFO -Message ("IFM создан: ntds.dit={0:N0} MB, SYSTEM={1:N0} KB" -f `
                ($dit.Length / 1MB), ($sys.Length / 1KB))
        } finally {
            Remove-Item -LiteralPath $outFile, $errFile -ErrorAction SilentlyContinue
        }
    } finally {
        Remove-Item -LiteralPath $cmdFile -ErrorAction SilentlyContinue
    }
}

# ---------- Шаг 7-8: передача на станцию + сверка ----------

function Copy-AndVerifyArchive {
    <#
    .SYNOPSIS
        Копирует архив на SMB-шару и сверяет SHA-256 через перечитывание
        файла по UNC-пути. Не совпало — удаляет копию на шаре и бросает.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [string] $LocalArchive,
        [Parameter(Mandatory)] [string] $RemoteUnc,
        [Parameter(Mandatory)] [string] $ExpectedSha256
    )

    $remoteFile = Join-Path $RemoteUnc (Split-Path -Leaf $LocalArchive)

    # Предыдущая копия (если прогон повторный) — зачищаем.
    if (Test-Path -LiteralPath $remoteFile) {
        Write-AuditLog -Level WARN -Message "Предыдущая копия существует, удаляю: $remoteFile"
        Invoke-SecureDelete -Path $remoteFile -Passes 3 -IgnoreMissing
    }

    Write-AuditLog -Level INFO -Message "Копирование $LocalArchive → $remoteFile ..."
    $sw = [System.Diagnostics.Stopwatch]::StartNew()
    Copy-Item -LiteralPath $LocalArchive -Destination $remoteFile -Force
    $sw.Stop()

    $sizeMb = (Get-Item -LiteralPath $remoteFile).Length / 1MB
    Write-AuditLog -Level INFO -Message ("Передано {0:N1} MB за {1:N1} сек ({2:N1} MB/s)" -f `
        $sizeMb, $sw.Elapsed.TotalSeconds, ($sizeMb / [math]::Max($sw.Elapsed.TotalSeconds, 0.001)))

    # Сверка — Get-FileHash по UNC действительно перечитывает файл
    # через SMB, что подтверждает целостность после записи.
    Write-AuditLog -Level INFO -Message 'Сверка SHA-256 через UNC...'
    $remoteSha = Get-Sha256Hash -Path $remoteFile
    if ($remoteSha -ne $ExpectedSha256) {
        Write-AuditLog -Level ERROR -Message "SHA-256 не совпал. Локально: $ExpectedSha256, удалённо: $remoteSha"
        # Удаляем подозрительный файл немедленно.
        Invoke-SecureDelete -Path $remoteFile -Passes 3 -IgnoreMissing
        throw 'Целостность нарушена: SHA-256 отличается. Архив на шаре удалён.'
    }
    Write-AuditLog -Level INFO -Message "SHA-256 совпал: $remoteSha"
}

# ---------- Main ----------

$exitCode = 0
$workSubdir   = $null
$archivePath  = $null
$aesKey       = $null

try {
    # Конфиг
    $env:AD_AUDIT_CONFIG = $ConfigPath
    $cfg = Get-AuditConfig

    # Шаг 1: зависимости
    try {
        Test-Phase1Dependencies -SmbShareUnc $cfg.SmbShareUnc -WorkDirectory $IfmWorkDirectory
    } catch {
        $exitCode = 1; throw
    }

    # Уникальный подкаталог для этого прогона, чтобы одновременные запуски
    # (теоретически) не затерли друг друга.
    $workSubdir = Join-Path $IfmWorkDirectory "run-$cid"
    New-Item -ItemType Directory -Path $workSubdir -Force | Out-Null

    # Итоговый архив кладём рядом в work, потом копируем.
    $archiveName = ('ifm-{0}-{1}.7z' -f (Get-Date -Format 'yyyyMMdd-HHmm'), $cid)
    $archivePath = Join-Path $workSubdir $archiveName

    Invoke-WithGuaranteedCleanup `
        -Action {
            # Шаг 2: ключ
            Write-AuditLog -Level INFO -Message 'Получение AES-256 ключа из SecretStore...'
            $script:aesKey = Get-AesKeyFromSecretStore -Name $cfg.IfmKeyName -VaultName $cfg.SecretVaultName

            # Шаг 3: ntdsutil IFM
            try {
                Invoke-NtdsutilIfm -OutputDirectory $workSubdir
            } catch {
                $script:exitCode = 2; throw
            }

            # Шаг 4: 7z AES-256 с -mhe=on
            Write-AuditLog -Level INFO -Message 'Шифрование IFM в 7z AES-256...'
            try {
                # Источник — весь подкаталог (он содержит "Active Directory\ntds.dit" и "registry\SYSTEM")
                $src = Get-ChildItem -LiteralPath $workSubdir -Directory | Select-Object -First 1
                if (-not $src) { throw 'Пустой каталог после ntdsutil — нечего шифровать.' }
                Protect-Archive -Source $src.FullName -Destination $archivePath -Password $script:aesKey
                Write-AuditLog -Level INFO -Message ("Архив создан: {0:N1} MB" -f ((Get-Item $archivePath).Length / 1MB))
            } catch {
                $script:exitCode = 3; throw
            }

            # Шаг 5: SDelete незашифрованных файлов IFM
            Write-AuditLog -Level INFO -Message 'Безопасное удаление незашифрованного IFM...'
            Invoke-SecureDelete -Path $src.FullName -Passes 3 -Recurse

            # Шаг 6: SHA-256 архива
            $archiveSha = Get-Sha256Hash -Path $archivePath
            Write-AuditLog -Level INFO -Message "SHA-256 архива: $archiveSha"

            # Шаг 7-8: передача + сверка
            try {
                Copy-AndVerifyArchive `
                    -LocalArchive   $archivePath `
                    -RemoteUnc      $cfg.SmbShareUnc `
                    -ExpectedSha256 $archiveSha
            } catch {
                $script:exitCode = 4; throw
            }

            # Сайдкар с именем архива и хешем — чтобы оркестратор знал, какой
            # файл только что пришёл, и не гонялся за "самым новым".
            $sidecar = @{
                ArchiveName    = Split-Path -Leaf $archivePath
                Sha256         = $archiveSha
                CreatedUtc     = (Get-Date).ToUniversalTime().ToString('o')
                CorrelationId  = $cid
                DcHostname     = $env:COMPUTERNAME
            } | ConvertTo-Json
            $sidecarPath = Join-Path $cfg.SmbShareUnc ((Split-Path -Leaf $archivePath) + '.meta.json')
            Set-Content -LiteralPath $sidecarPath -Value $sidecar -Encoding UTF8
            Write-AuditLog -Level INFO -Message "Sidecar-манифест записан: $sidecarPath"
        } `
        -Cleanup {
            # Шаг 9: SDelete локальной копии архива (уже передан и сверен)
            if ($archivePath -and (Test-Path -LiteralPath $archivePath)) {
                Write-AuditLog -Level INFO -Message 'Удаление локальной копии архива...'
                Invoke-SecureDelete -Path $archivePath -Passes 3 -IgnoreMissing
            }

            # На всякий случай — если в workSubdir что-то осталось (напр.,
            # ntdsutil упал посередине), зачищаем.
            if ($workSubdir -and (Test-Path -LiteralPath $workSubdir)) {
                $leftover = Get-ChildItem -LiteralPath $workSubdir -Recurse -Force -ErrorAction SilentlyContinue
                if ($leftover) {
                    Write-AuditLog -Level WARN -Message "В $workSubdir остались файлы, SDelete: $($leftover.Count) шт."
                    Invoke-SecureDelete -Path $workSubdir -Passes 3 -Recurse -IgnoreMissing
                } else {
                    Remove-Item -LiteralPath $workSubdir -Force -Recurse -ErrorAction SilentlyContinue
                }
            }

            # Шаг 10: очистка ключа из памяти
            if ($script:aesKey) {
                Clear-SensitiveVariable -SecureString $script:aesKey
                $script:aesKey = $null
            }

            # Финальная верификация — в рабочей папке не должно остаться
            # *.dit, *.7z, SYSTEM.
            $residue = Test-CleanupResidue -Directories @($IfmWorkDirectory)
            if ($residue) {
                foreach ($r in $residue) { Write-AuditLog -Level WARN -Message "Остаток: $r" }
            } else {
                Write-AuditLog -Level INFO -Message 'Верификация: рабочая папка чиста.'
            }
        }

    Write-AuditLog -Level INFO -Message '=== Фаза 1 завершена успешно ==='

} catch {
    Write-AuditLog -Level CRITICAL -Message "Фаза 1 упала: $($_.Exception.Message)"
    Write-AuditLog -Level CRITICAL -Message $_.ScriptStackTrace
    if ($exitCode -eq 0) { $exitCode = 99 }
} finally {
    exit $exitCode
}
