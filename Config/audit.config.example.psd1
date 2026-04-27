# Пример конфигурационного файла системы аудита паролей AD.
# После правки сохранить как C:\ProgramData\ADPasswordAudit\audit.config.psd1
# (или указать путь через переменную окружения AD_AUDIT_CONFIG).
#
# Секреты (AES-ключ, пароли) здесь НЕ хранятся — они в SecretStore.

@{
    # ---------- Домен и машины ----------
    Domain                   = 'CORP'
    DomainController         = 'DC01.corp.local'
    AuditStation             = 'AUDIT01.corp.local'

    # SMB-шара станции аудита, куда DC кладёт зашифрованный IFM-архив.
    # Доступ — только для gMSA и машинного аккаунта станции.
    SmbShareUnc              = '\\AUDIT01\IFM_Drop$'

    # ---------- Рабочие директории на станции аудита ----------
    WorkDirectory            = 'C:\AuditWork'       # распаковка, временные файлы
    LogDirectory             = 'C:\AuditLogs'       # логи всех фаз
    ReportRetentionDirectory = 'D:\Reports'         # сюда кладём финальный .7z

    # ---------- HIBP ----------
    HibpFilePath             = 'C:\AuditData\hibp-ntlm.txt'
    # Эталонный SHA-256 словаря HIBP. Фиксируется установщиком после
    # первого импорта; фаза 2 сверяется с ним перед каждым прогоном.
    HibpExpectedSha256       = '0000000000000000000000000000000000000000000000000000000000000000'

    # ---------- Секреты ----------
    SecretVaultName          = 'ADAuditVault'
    IfmKeyName               = 'ADAudit-IFM-Key'

    # ---------- Почта ----------
    SmtpServer               = 'mail.corp.local'
    SmtpPort                 = 25
    SmtpFrom                 = 'ad-audit@corp.local'
    # Кому уходит письмо с паролем от архива отчёта.
    SmtpRecipients           = @('secops@corp.local')
    # Thumbprint сертификата для S/MIME-подписи (из хранилища
    # LocalMachine\My сервисной учётки станции аудита).
    SmimeCertificateThumbprint = '0000000000000000000000000000000000000000'

    # ---------- Ретенция ----------
    # Сколько дней хранить архивы отчётов в ReportRetentionDirectory.
    ReportRetentionDays      = 5

    # ---------- Расписание ----------
    # Используется установщиком при регистрации Scheduled Task.
    # Cron-подобный синтаксис Windows Task Scheduler.
    AuditScheduleDayOfMonth  = 1
    AuditScheduleTime        = '03:00'
    RetentionScheduleTime    = '02:00'
}
