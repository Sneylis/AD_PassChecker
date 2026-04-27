<#
.SYNOPSIS
    Загрузка и валидация конфигурации системы аудита.

.DESCRIPTION
    Конфиг живёт в формате PowerShell Data File (.psd1) — нативный для
    PS, без внешних парсеров. Путь по умолчанию —
    C:\ProgramData\ADPasswordAudit\audit.config.psd1, но можно
    переопределить через переменную окружения AD_AUDIT_CONFIG.

    Установщик генерирует конфиг на основе ответов оператора;
    фазы и оркестратор читают его через Get-AuditConfig.

.NOTES
    В конфиге НЕ хранятся секреты. Ключи шифрования — в SecretStore,
    пароль архива генерируется одноразово. Тут только пути,
    расписание, адреса получателей и эталонный хеш HIBP.
#>

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$script:DefaultConfigPath = 'C:\ProgramData\ADPasswordAudit\audit.config.psd1'

function Get-AuditConfigPath {
    if ($env:AD_AUDIT_CONFIG -and (Test-Path -LiteralPath $env:AD_AUDIT_CONFIG)) {
        return $env:AD_AUDIT_CONFIG
    }
    return $script:DefaultConfigPath
}

function Get-AuditConfig {
    <#
    .SYNOPSIS
        Загружает и валидирует конфиг. Бросает понятную ошибку, если
        обязательное поле отсутствует.
    #>
    [CmdletBinding()]
    param([string] $Path = (Get-AuditConfigPath))

    if (-not (Test-Path -LiteralPath $Path)) {
        throw "Конфиг не найден: $Path. Запустите Install-AuditStation.ps1 или укажите путь через AD_AUDIT_CONFIG."
    }

    $cfg = Import-PowerShellDataFile -LiteralPath $Path

    # Обязательные поля. Если добавляете новое поле в конфиг — обнови
    # и этот список, и Config/audit.config.example.psd1.
    $required = @(
        'Domain',
        'DomainController',
        'AuditStation',
        'SmbShareUnc',
        'WorkDirectory',
        'LogDirectory',
        'ReportRetentionDirectory',
        'HibpFilePath',
        'HibpExpectedSha256',
        'SecretVaultName',
        'IfmKeyName',
        'SmtpServer',
        'SmtpFrom',
        'SmtpRecipients',
        'SmimeCertificateThumbprint',
        'ReportRetentionDays'
    )
    foreach ($key in $required) {
        if (-not $cfg.ContainsKey($key)) {
            throw "В конфиге отсутствует обязательное поле: $key"
        }
    }

    # Доводим типы (psd1 хранит всё как строки/массивы).
    $cfg.ReportRetentionDays = [int] $cfg.ReportRetentionDays
    if (-not ($cfg.SmtpRecipients -is [array])) {
        $cfg.SmtpRecipients = @($cfg.SmtpRecipients)
    }

    # Вернём как PSCustomObject, чтобы в вызывающем коде была
    # точечная нотация ($cfg.Domain вместо $cfg['Domain']).
    return [pscustomobject] $cfg
}

function Save-AuditConfig {
    <#
    .SYNOPSIS
        Сохраняет хеш-таблицу конфига обратно в .psd1. Используется
        установщиком.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [hashtable] $Config,
        [string] $Path = (Get-AuditConfigPath)
    )

    $dir = Split-Path -Parent $Path
    if (-not (Test-Path -LiteralPath $dir)) {
        New-Item -ItemType Directory -Path $dir -Force | Out-Null
    }

    $sb = New-Object System.Text.StringBuilder
    [void] $sb.AppendLine('# Автоматически сгенерировано Install-AuditStation.ps1')
    [void] $sb.AppendLine("# Сгенерировано: $((Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ'))")
    [void] $sb.AppendLine('@{')
    foreach ($k in $Config.Keys) {
        $v = $Config[$k]
        if ($v -is [array]) {
            $items = ($v | ForEach-Object { "'$($_ -replace "'", "''")'" }) -join ', '
            [void] $sb.AppendLine("    $k = @($items)")
        } elseif ($v -is [int] -or $v -is [bool]) {
            [void] $sb.AppendLine("    $k = $v")
        } else {
            $escaped = ($v.ToString() -replace "'", "''")
            [void] $sb.AppendLine("    $k = '$escaped'")
        }
    }
    [void] $sb.AppendLine('}')

    Set-Content -LiteralPath $Path -Value $sb.ToString() -Encoding UTF8
}

Export-ModuleMember -Function Get-AuditConfig, Save-AuditConfig, Get-AuditConfigPath
