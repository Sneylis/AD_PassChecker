#Requires -Version 5.1
<#
.SYNOPSIS
    Фаза 4: формирование текстового отчёта, упаковка в зашифрованный
    архив с размещением на файл-сервере и отправка пароля по почте.

.DESCRIPTION
    По регламенту: отчёт содержит ТОЛЬКО имена пользователей и тип
    проблемы — без хешей, без паролей. Архив .7z с AES-256 и
    шифрованием заголовков кладётся на файл-сервер в ReportRetentionDirectory.
    Пароль от архива отправляется получателям по корпоративной почте
    с S/MIME-подписью.

    Двухканальность: в письме — только пароль и путь к архиву.
    Архив на шаре, пароль в почте — перехват одного канала не даёт
    доступа к отчёту.

    Алгоритм:
        1. Разбор JSON из Фазы 3 по категориям.
        2. Формирование текстового отчёта:
             - Заголовок с метаданными (UTC время, длительность, CID,
               общее число аккаунтов, хеш HIBP использованный в прогоне).
             - Сводка: категория → количество.
             - Разделы по категориям с записями [ТИП] DOMAIN\Username.
        3. Генерация одноразового пароля архива (New-StrongPassword, 32 символа).
        4. 7z AES-256 с -mhe=on.
        5. SDelete открытого .txt.
        6. Перемещение архива в ReportRetentionDirectory.
        7. Отправка пароля по корпоративной почте с S/MIME подписью.
        8. Обнуление пароля из памяти.

.PARAMETER ConfigPath
    Путь к audit.config.psd1.

.PARAMETER ResultJsonPath
    JSON с результатами Фазы 3.

.PARAMETER StartTime
    Время старта всего прогона (UTC). Оркестратор передаёт — нужно
    для метаданных "длительность".

.PARAMETER HibpSha256
    SHA-256 словаря из Фазы 2 (логируется в метаданных отчёта).

.OUTPUTS
    [PSCustomObject] с путём к архиву и статусом отправки почты.

.NOTES
    Требует:
      - SmtpServer доступен из VLAN аудита (правило файрволла).
      - Сертификат S/MIME в Cert:\LocalMachine\My с указанным thumbprint.
      - Адрес SmtpFrom совпадает с Subject сертификата.
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory)] [string] $ConfigPath,
    [Parameter(Mandatory)] [string] $ResultJsonPath,
    [datetime] $StartTime   = (Get-Date).ToUniversalTime(),
    [string]   $HibpSha256  = ''
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$repoRoot = Split-Path -Parent (Split-Path -Parent $MyInvocation.MyCommand.Path)
Import-Module (Join-Path $repoRoot 'Common\Logging.psm1')        -Force
Import-Module (Join-Path $repoRoot 'Common\Crypto.psm1')         -Force
Import-Module (Join-Path $repoRoot 'Common\CleanupHelpers.psm1') -Force
Import-Module (Join-Path $repoRoot 'Common\Config.psm1')         -Force

if (-not (Get-AuditCorrelationId)) {
    Initialize-AuditLog -LogDirectory 'C:\AuditLogs' -PhaseName 'Phase4'
} else {
    Set-AuditPhase -PhaseName 'Phase4'
}
$cid = Get-AuditCorrelationId

Write-AuditLog -Level INFO -Message '=== Фаза 4: формирование отчёта и доставка ==='

# ---------- Форматирование отчёта ----------

# Человеко-читаемые имена категорий (для раздела отчёта) и
# метки-префиксы для каждой записи (как требует регламент).
$script:CategoryMeta = [ordered]@{
    WeakPassword               = @{ Title = 'Слабые / скомпрометированные пароли (HIBP)';        Tag = 'WEAK_PWD' }
    DuplicatePasswordGroups    = @{ Title = 'Группы аккаунтов с одинаковым паролем';              Tag = 'DUP_PWD' }
    EmptyPassword              = @{ Title = 'Пустой пароль';                                      Tag = 'EMPTY_PWD' }
    LMHashPresent              = @{ Title = 'Хранится LM-хеш (устаревший алгоритм)';              Tag = 'LM_HASH' }
    DefaultComputerPassword    = @{ Title = 'Дефолтный пароль компьютерного аккаунта';            Tag = 'DEFAULT_CMP_PWD' }
    PasswordNotRequired        = @{ Title = 'Флаг PASSWD_NOTREQD (пароль не обязателен)';         Tag = 'PWD_NOTREQD' }
    PasswordNeverExpires       = @{ Title = 'Флаг "пароль никогда не истекает"';                   Tag = 'PWD_NEVER_EXP' }
    AESKeysMissing             = @{ Title = 'Отсутствуют Kerberos AES-ключи';                     Tag = 'NO_AES_KEYS' }
    PreAuthNotRequired         = @{ Title = 'Pre-auth отключена (AS-REP Roastable)';              Tag = 'AS_REP_ROAST' }
    DESEncryptionOnly          = @{ Title = 'Только DES-шифрование Kerberos (уязвимо)';           Tag = 'DES_ONLY' }
    DelegatableAdmins          = @{ Title = 'Администраторы без флага "не делегировать"';         Tag = 'DELEG_ADMIN' }
    SmartCardUsersWithPassword = @{ Title = 'Пользователи со смарт-картой имеют парольный фолбэк'; Tag = 'SC_PWD_FALLBACK' }
    Kerberoastable             = @{ Title = 'Сервисные SPN с парольной защитой (Kerberoastable)'; Tag = 'KERBEROAST' }
    ClearTextPassword          = @{ Title = 'Пароль хранится в открытом виде (reversible)';       Tag = 'CLEARTEXT_PWD' }
    DuplicateNtHashes          = @{ Title = 'Дубликаты NT-хешей';                                  Tag = 'DUP_NTHASH' }
    SamAccountNameAsPassword   = @{ Title = 'Пароль равен SamAccountName';                        Tag = 'SAM_EQ_PWD' }
}

function Format-AuditReport {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [pscustomobject] $Result,
        [Parameter(Mandatory)] [string] $Domain,
        [Parameter(Mandatory)] [datetime] $StartTime,
        [Parameter(Mandatory)] [datetime] $EndTime,
        [string] $HibpSha256
    )

    $sb = New-Object System.Text.StringBuilder
    $duration = $EndTime - $StartTime
    [void] $sb.AppendLine('=' * 72)
    [void] $sb.AppendLine('AD PASSWORD AUDIT REPORT')
    [void] $sb.AppendLine('=' * 72)
    [void] $sb.AppendLine(("Correlation ID:   {0}" -f $Result.CorrelationId))
    [void] $sb.AppendLine(("Start (UTC):      {0:yyyy-MM-ddTHH:mm:ssZ}" -f $StartTime))
    [void] $sb.AppendLine(("End   (UTC):      {0:yyyy-MM-ddTHH:mm:ssZ}" -f $EndTime))
    [void] $sb.AppendLine(("Duration:         {0:hh\:mm\:ss}" -f $duration))
    [void] $sb.AppendLine(("Domain:           {0}" -f $Domain))
    [void] $sb.AppendLine(("Total accounts:   {0}" -f $Result.TotalAccounts))
    [void] $sb.AppendLine(("Enabled accounts: {0}" -f $Result.EnabledAccounts))
    if ($HibpSha256) {
        [void] $sb.AppendLine(("HIBP SHA-256:     {0}" -f $HibpSha256))
    }
    [void] $sb.AppendLine('')

    # Сводка
    [void] $sb.AppendLine('-' * 72)
    [void] $sb.AppendLine('SUMMARY BY CATEGORY')
    [void] $sb.AppendLine('-' * 72)
    $totalIssues = 0
    foreach ($cat in $script:CategoryMeta.Keys) {
        $count = if ($Result.Summary.PSObject.Properties.Match($cat)) {
            $Result.Summary.$cat
        } else { 0 }
        $title = $script:CategoryMeta[$cat].Title
        [void] $sb.AppendLine(("  {0,-60} {1,6}" -f $title, $count))
        $totalIssues += [int]$count
    }
    [void] $sb.AppendLine(('  ' + ('-' * 68)))
    [void] $sb.AppendLine(("  {0,-60} {1,6}" -f 'TOTAL ISSUES (суммарно, без уникальных)', $totalIssues))
    [void] $sb.AppendLine('')

    # Разделы по категориям
    foreach ($cat in $script:CategoryMeta.Keys) {
        $entries = if ($Result.Categories.PSObject.Properties.Match($cat)) {
            $Result.Categories.$cat
        } else { @() }

        if (-not $entries -or @($entries).Count -eq 0) { continue }

        $meta  = $script:CategoryMeta[$cat]
        [void] $sb.AppendLine('-' * 72)
        [void] $sb.AppendLine(("{0}  ({1} аккаунт/ов)" -f $meta.Title.ToUpper(), @($entries).Count))
        [void] $sb.AppendLine('-' * 72)

        if ($cat -eq 'DuplicatePasswordGroups') {
            # Специальный формат: каждая группа на отдельный блок.
            foreach ($group in $entries) {
                [void] $sb.AppendLine(("[{0}] Группа {1} ({2} аккаунтов):" -f $meta.Tag, $group.GroupId, @($group.Accounts).Count))
                foreach ($sam in $group.Accounts) {
                    [void] $sb.AppendLine(("    [{0}] {1}\{2}" -f $meta.Tag, $Domain, $sam))
                }
                [void] $sb.AppendLine('')
            }
        } else {
            foreach ($sam in $entries) {
                [void] $sb.AppendLine(("[{0}] {1}\{2}" -f $meta.Tag, $Domain, $sam))
            }
            [void] $sb.AppendLine('')
        }
    }

    [void] $sb.AppendLine('=' * 72)
    [void] $sb.AppendLine('END OF REPORT')
    [void] $sb.AppendLine('=' * 72)
    return $sb.ToString()
}

# ---------- Отправка почты с S/MIME ----------

function Send-PasswordEmail {
    <#
    .SYNOPSIS
        Отправляет пароль архива получателям по SMTP с S/MIME-подписью.
        Тело письма — пароль, путь к архиву, сводка проблем. Имён
        пользователей в письме нет.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [string]   $SmtpServer,
        [int]                               $SmtpPort = 25,
        [Parameter(Mandatory)] [string]   $From,
        [Parameter(Mandatory)] [string[]] $To,
        [Parameter(Mandatory)] [string]   $SmimeThumbprint,
        [Parameter(Mandatory)] [System.Security.SecureString] $ArchivePassword,
        [Parameter(Mandatory)] [string]   $ArchivePath,
        [Parameter(Mandatory)] [string]   $CorrelationId,
        [Parameter(Mandatory)] [int]      $TotalIssues,
        [Parameter(Mandatory)] [timespan] $Duration
    )

    # Разворачиваем SecureString только внутри try, чтобы при любой
    # ошибке plain-копия была обнулена.
    $plainPwd = $null
    $bstr     = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($ArchivePassword)
    try {
        $plainPwd = [System.Runtime.InteropServices.Marshal]::PtrToStringBSTR($bstr)

        $body = @"
AD Password Audit — $CorrelationId

Прогон завершён.

  Длительность:    $([math]::Round($Duration.TotalMinutes, 1)) мин
  Всего проблем:   $TotalIssues
  Архив отчёта:    $ArchivePath
  Пароль архива:   $plainPwd

Извлечь отчёт: 7z x -p<пароль> "<путь к архиву>"

Архив хранится 5 дней, затем удаляется автоматически.
Никаких хешей или паролей в отчёте не содержится — только
имена учётных записей и категории проблем.

---
Письмо подписано S/MIME. Если подпись не валидна — не используйте
пароль и сообщите SecOps.
"@

        $subject = "AD Password Audit — $CorrelationId — $TotalIssues issue(s)"

        # Подпись S/MIME через MimeKit через встроенный System.Net.Mail
        # невозможна: нет нативной поддержки CMS-signed email в .NET
        # Framework без доп. библиотек. Используем два подхода:
        #   1) Если в системе есть MimeKit/MailKit (ставится установщиком
        #      опционально) — используем её для CMS-подписи.
        #   2) Fallback: отправка без S/MIME, но с WARN в логе.

        $cert = Get-Item "Cert:\LocalMachine\My\$SmimeThumbprint" -ErrorAction SilentlyContinue
        if (-not $cert) {
            throw "Сертификат S/MIME не найден: $SmimeThumbprint. Проверьте Cert:\LocalMachine\My"
        }
        if (-not $cert.HasPrivateKey) {
            throw "Сертификат $SmimeThumbprint не содержит закрытого ключа — подпись S/MIME невозможна."
        }

        # S/MIME-подпись требует MimeKit + MailKit DLL (NuGet пакеты).
        # Установщик кладёт их в C:\Tools\MimeKit\ (ищем там).
        # Если DLL отсутствуют — fallback на неподписанное письмо с WARN.
        $mimeKitDll = 'C:\Tools\MimeKit\MimeKit.dll'
        $mailKitDll = 'C:\Tools\MimeKit\MailKit.dll'
        $bouncyDll  = 'C:\Tools\MimeKit\BouncyCastle.Crypto.dll'

        $useSmime = (Test-Path -LiteralPath $mimeKitDll) -and `
                    (Test-Path -LiteralPath $mailKitDll) -and `
                    (Test-Path -LiteralPath $bouncyDll)

        if ($useSmime) {
            Write-AuditLog -Level INFO -Message 'Отправка через MimeKit с S/MIME-подписью...'
            Add-Type -Path $bouncyDll
            Add-Type -Path $mimeKitDll
            Add-Type -Path $mailKitDll

            $message = New-Object MimeKit.MimeMessage
            $message.From.Add( [MimeKit.MailboxAddress]::Parse($From) )
            foreach ($addr in $To) {
                $message.To.Add( [MimeKit.MailboxAddress]::Parse($addr) )
            }
            $message.Subject = $subject

            $bodyBuilder = New-Object MimeKit.BodyBuilder
            $bodyBuilder.TextBody = $body
            $unsignedBody = $bodyBuilder.ToMessageBody()

            # Подпись CMS через встроенный WindowsSecureMimeContext.
            # Он забирает сертификат из Cert:\CurrentUser\My или
            # LocalMachine\My по Subject/Thumbprint.
            $ctx = New-Object MimeKit.Cryptography.WindowsSecureMimeContext ([System.Security.Cryptography.X509Certificates.StoreLocation]::LocalMachine)
            try {
                $cmsSigner = New-Object MimeKit.Cryptography.CmsSigner($cert)
                $signedBody = [MimeKit.Cryptography.MultipartSigned]::Create($ctx, $cmsSigner, $unsignedBody)
                $message.Body = $signedBody
            } finally {
                $ctx.Dispose()
            }

            $smtp = New-Object MailKit.Net.Smtp.SmtpClient
            try {
                $smtp.Connect($SmtpServer, $SmtpPort, [MailKit.Security.SecureSocketOptions]::StartTlsWhenAvailable)
                $smtp.Send($message)
                $smtp.Disconnect($true)
            } finally {
                $smtp.Dispose()
            }
        } else {
            # Fallback — неподписанное письмо с явной пометкой. Регламент
            # требует S/MIME, поэтому WARN обязателен.
            Write-AuditLog -Level WARN `
                -Message 'MimeKit/MailKit/BouncyCastle DLL не найдены в C:\Tools\MimeKit\. Отправка без S/MIME-подписи.'
            Send-MailMessage -From $From -To $To `
                -Subject ("[UNSIGNED] " + $subject) -Body $body `
                -SmtpServer $SmtpServer -Port $SmtpPort -Encoding UTF8
        }

        Write-AuditLog -Level INFO -Message "Письмо с паролем отправлено: $($To -join ', ')"

    } finally {
        # Обнуляем plain-копию пароля.
        [System.Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstr)
        if ($plainPwd) {
            # Не просто = $null, а перезаписываем символами.
            $plainPwd = ('X' * $plainPwd.Length)
            $plainPwd = $null
        }
        [System.GC]::Collect()
    }
}

# ---------- Main ----------

$textReportPath = $null
$archiveTempPath = $null
$archiveFinalPath = $null
$archivePassword = $null

try {
    $env:AD_AUDIT_CONFIG = $ConfigPath
    $cfg = Get-AuditConfig

    if (-not (Test-Path -LiteralPath $ResultJsonPath)) {
        throw "JSON-результат Фазы 3 не найден: $ResultJsonPath"
    }

    $endTime = (Get-Date).ToUniversalTime()
    $result  = Get-Content -LiteralPath $ResultJsonPath -Raw | ConvertFrom-Json

    # Убедимся, что директория ретенции существует.
    if (-not (Test-Path -LiteralPath $cfg.ReportRetentionDirectory)) {
        New-Item -ItemType Directory -Path $cfg.ReportRetentionDirectory -Force | Out-Null
    }

    Invoke-WithGuaranteedCleanup `
        -Action {
            # 1. Формируем текстовый отчёт
            $reportText = Format-AuditReport `
                -Result     $result `
                -Domain     $cfg.Domain `
                -StartTime  $StartTime `
                -EndTime    $endTime `
                -HibpSha256 $HibpSha256

            $dateStamp = (Get-Date).ToUniversalTime().ToString('yyyy-MM-dd')
            $script:textReportPath  = Join-Path $cfg.WorkDirectory "report-$dateStamp-$cid.txt"
            $script:archiveTempPath = Join-Path $cfg.WorkDirectory "report-$dateStamp-$cid.7z"
            $script:archiveFinalPath = Join-Path $cfg.ReportRetentionDirectory (Split-Path -Leaf $script:archiveTempPath)

            Set-Content -LiteralPath $script:textReportPath -Value $reportText -Encoding UTF8
            Write-AuditLog -Level INFO -Message "Текстовый отчёт: $($script:textReportPath) ($((Get-Item $script:textReportPath).Length) B)"

            # 2. Генерим пароль и пакуем
            $script:archivePassword = New-StrongPassword -Length 32
            Protect-Archive `
                -Source $script:textReportPath `
                -Destination $script:archiveTempPath `
                -Password $script:archivePassword
            Write-AuditLog -Level INFO -Message "Архив создан: $($script:archiveTempPath)"

            # 3. SDelete открытого .txt
            Invoke-SecureDelete -Path $script:textReportPath -Passes 3 -IgnoreMissing
            $script:textReportPath = $null

            # 4. Перемещение в ретенционную папку
            Move-Item -LiteralPath $script:archiveTempPath -Destination $script:archiveFinalPath -Force
            Write-AuditLog -Level INFO -Message "Архив размещён: $($script:archiveFinalPath)"
            $script:archiveTempPath = $null

            # Подсчёт суммарного числа проблем для письма.
            $totalIssues = 0
            foreach ($cat in $script:CategoryMeta.Keys) {
                if ($result.Summary.PSObject.Properties.Match($cat)) {
                    $totalIssues += [int]$result.Summary.$cat
                }
            }

            # 5. Отправка пароля по почте.
            # PS 5.1-совместимая замена тернарного оператора:
            # если в конфиге задано поле SmtpPort — берём его,
            # иначе используем 25 (стандартный SMTP).
            $smtpPortToUse = 25
            if ($cfg.PSObject.Properties.Match('SmtpPort').Count -gt 0 -and $cfg.SmtpPort) {
                $smtpPortToUse = [int]$cfg.SmtpPort
            }

            Send-PasswordEmail `
                -SmtpServer      $cfg.SmtpServer `
                -SmtpPort        $smtpPortToUse `
                -From            $cfg.SmtpFrom `
                -To              $cfg.SmtpRecipients `
                -SmimeThumbprint $cfg.SmimeCertificateThumbprint `
                -ArchivePassword $script:archivePassword `
                -ArchivePath     $script:archiveFinalPath `
                -CorrelationId   $cid `
                -TotalIssues     $totalIssues `
                -Duration        ($endTime - $StartTime)

        } `
        -Cleanup {
            # Открытый .txt не должен пережить фазу.
            if ($textReportPath -and (Test-Path -LiteralPath $textReportPath)) {
                Write-AuditLog -Level WARN -Message "Открытый .txt остался — SDelete."
                Invoke-SecureDelete -Path $textReportPath -Passes 3 -IgnoreMissing
            }
            # Временный архив в рабочей папке (если не переехал).
            if ($archiveTempPath -and (Test-Path -LiteralPath $archiveTempPath)) {
                Invoke-SecureDelete -Path $archiveTempPath -Passes 3 -IgnoreMissing
            }
            # Пароль архива — обнуляем SecureString.
            if ($archivePassword) {
                Clear-SensitiveVariable -SecureString $archivePassword
                $archivePassword = $null
            }
        }

    Write-AuditLog -Level INFO -Message '=== Фаза 4 завершена успешно ==='
    return [pscustomobject]@{
        Phase            = 'Phase4-Report'
        Success          = $true
        ArchivePath      = $archiveFinalPath
        CorrelationId    = $cid
    }

} catch {
    Write-AuditLog -Level CRITICAL -Message "Фаза 4 упала: $($_.Exception.Message)"
    Write-AuditLog -Level CRITICAL -Message $_.ScriptStackTrace
    throw
}
