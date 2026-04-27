<#
.SYNOPSIS
    Централизованный модуль логирования для системы аудита паролей AD.

.DESCRIPTION
    Пишет структурированные записи вида:
        2026-04-23T10:15:32Z [INFO ] [CID=abc12345] [Phase1] Сообщение

    Каждая запись содержит UTC-метку, уровень, Correlation ID (общий для
    одного прогона аудита) и имя фазы. Логи одновременно уходят:
      - в консоль (при интерактивном запуске) с цветом по уровню,
      - в файл на диск (по умолчанию C:\AuditLogs\audit-YYYY-MM-DD.log),
      - в Windows Event Log (источник "ADPasswordAudit") для критичных
        событий (WARN, ERROR, CRITICAL), чтобы SIEM их подхватывал.

    Модуль НЕ записывает в лог чувствительные данные: пароли, ключи,
    хеши. Вызывающий код отвечает за то, чтобы не передавать такие
    значения в параметр -Message.

.NOTES
    Уровни: DEBUG, INFO, WARN, ERROR, CRITICAL
    CRITICAL зарезервирован под события, прерывающие аудит (напр.
    несовпадение SHA-256 словаря HIBP).
#>

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# Модульная переменная — устанавливается один раз при инициализации
# (см. Initialize-AuditLog). Хранится в scope модуля, а не глобально,
# чтобы не конфликтовать с другими скриптами.
$script:LogFilePath     = $null
$script:CorrelationId   = $null
$script:PhaseName       = 'General'
$script:EventLogSource  = 'ADPasswordAudit'
$script:EventLogEnabled = $false

function Initialize-AuditLog {
    <#
    .SYNOPSIS
        Настраивает модуль перед первым использованием.
    .PARAMETER LogDirectory
        Папка, куда будут писаться файлы логов. Должна существовать
        и быть на BitLocker-томе (для станции аудита).
    .PARAMETER CorrelationId
        Уникальный ID текущего прогона. Если не задан — генерируется.
    .PARAMETER PhaseName
        Имя фазы по умолчанию (Installer, Phase1..Phase5, Retention).
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [string] $LogDirectory,
        [string] $CorrelationId = [Guid]::NewGuid().ToString('N').Substring(0, 8),
        [string] $PhaseName     = 'General'
    )

    if (-not (Test-Path -LiteralPath $LogDirectory)) {
        New-Item -ItemType Directory -Path $LogDirectory -Force | Out-Null
    }

    $date = (Get-Date).ToUniversalTime().ToString('yyyy-MM-dd')
    $script:LogFilePath   = Join-Path $LogDirectory "audit-$date.log"
    $script:CorrelationId = $CorrelationId
    $script:PhaseName     = $PhaseName

    # Попытаться зарегистрировать источник Event Log. Требует прав
    # администратора при первом запуске; если не удалось — просто
    # отключаем Event Log, но файловый лог продолжает работать.
    try {
        if (-not [System.Diagnostics.EventLog]::SourceExists($script:EventLogSource)) {
            [System.Diagnostics.EventLog]::CreateEventSource(
                $script:EventLogSource, 'Application')
        }
        $script:EventLogEnabled = $true
    } catch {
        $script:EventLogEnabled = $false
    }

    Write-AuditLog -Level INFO -Message "Logging initialized. CID=$($script:CorrelationId) Phase=$PhaseName File=$($script:LogFilePath)"
}

function Set-AuditPhase {
    <#
    .SYNOPSIS
        Меняет текущее имя фазы. Удобно в оркестраторе, чтобы не
        передавать -Phase в каждый Write-AuditLog.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)] [string] $PhaseName)
    $script:PhaseName = $PhaseName
}

function Write-AuditLog {
    [CmdletBinding()]
    param(
        [ValidateSet('DEBUG','INFO','WARN','ERROR','CRITICAL')]
        [string] $Level = 'INFO',

        [Parameter(Mandatory)]
        [string] $Message,

        [string] $Phase = $script:PhaseName
    )

    $timestamp = (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
    $cid       = if ($script:CorrelationId) { $script:CorrelationId } else { '--------' }
    $line      = "$timestamp [{0,-8}] [CID=$cid] [$Phase] $Message" -f $Level

    # Консоль — с цветом по уровню. Молча игнорируем, если хоста нет
    # (например, запуск из Scheduled Task без консоли).
    try {
        $color = switch ($Level) {
            'DEBUG'    { 'DarkGray' }
            'INFO'     { 'Gray' }
            'WARN'     { 'Yellow' }
            'ERROR'    { 'Red' }
            'CRITICAL' { 'Magenta' }
        }
        Write-Host $line -ForegroundColor $color
    } catch { }

    # Файл — если Initialize-AuditLog был вызван.
    if ($script:LogFilePath) {
        try {
            Add-Content -LiteralPath $script:LogFilePath -Value $line -Encoding UTF8
        } catch {
            # Падение записи в файл не должно валить сам аудит —
            # просто выведем предупреждение в консоль.
            Write-Host "WARN: не удалось записать в лог-файл: $_" -ForegroundColor Yellow
        }
    }

    # Event Log — только для критичных событий, чтобы не засорять.
    if ($script:EventLogEnabled -and $Level -in 'WARN','ERROR','CRITICAL') {
        try {
            $entryType = switch ($Level) {
                'WARN'     { 'Warning' }
                'ERROR'    { 'Error' }
                'CRITICAL' { 'Error' }
            }
            Write-EventLog -LogName Application `
                -Source $script:EventLogSource `
                -EntryType $entryType `
                -EventId 1000 `
                -Message $line
        } catch { }
    }
}

function Get-AuditCorrelationId {
    return $script:CorrelationId
}

Export-ModuleMember -Function Initialize-AuditLog, Set-AuditPhase, Write-AuditLog, Get-AuditCorrelationId
