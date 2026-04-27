# TROUBLESHOOTING — разбор типовых проблем

> Для любой проблемы: сначала найдите **Correlation ID (CID)**
> последнего прогона в `C:\AuditLogs\audit-<date>.log` — это
> первая строка с `CID=<8hex>`. Затем:
> `Select-String -Path C:\AuditLogs\*.log -Pattern "CID=<cid>"` —
> получите всю хронологию в одном выводе.

## §1 Установщик на DC падает с "KDS root key not found"

**Симптом:** `Install-DCComponents.ps1` → ошибка при `New-ADServiceAccount`.

**Причина:** в домене ещё никогда не использовался gMSA, нет KDS root key.

**Решение:**
```powershell
Add-KdsRootKey -EffectiveTime ((Get-Date).AddHours(-10))
# -10h обход 10-часовой задержки (только для лабы!).
# В продакшене — просто Add-KdsRootKey и подождать 10 часов.
```

## §2 Станция: BitLocker не полностью зашифрован

**Симптом:** `Test-Hardening` → "BitLocker не полностью включён на томах: C: (Protection=On, Status=EncryptionInProgress)".

**Причина:** BitLocker ещё шифрует тома.

**Решение:**
```powershell
Get-BitLockerVolume
# Ждём пока Status=FullyEncrypted на всех томах.
# Обычно 1–4 часа для 300 GB NVMe.
```

## §3 Phase 1 на DC не может записать на SMB

**Симптом:** `ntdsutil` успешен, но `Copy-AndVerifyArchive` падает
с `Access denied`.

**Причины:**
1. gMSA не имеет `Write` на шару.
2. SMB Server требует шифрование, у DC нет SPN.
3. Антивирус на файл-сервере блокирует запись `.7z`.

**Диагностика:**
```powershell
# На DC, под той же учёткой что и scheduled task:
Test-Path \\files01\IFM-Exchange$ -PathType Container
New-Item -Path \\files01\IFM-Exchange$\test-$(Get-Date -Format HHmmss).txt -ItemType File
```

**Решение:** выдать gMSA `Modify` права на шару (ACL уровня Share И
NTFS), включить SMB transport encryption:

```powershell
# На файл-сервере:
Set-SmbShare -Name 'IFM-Exchange$' -EncryptData $true
Grant-SmbShareAccess -Name 'IFM-Exchange$' -AccountName 'CORP\gmsa-adaudit$' -AccessRight Change
```

## §4 Phase 2: несовпадение SHA-256 HIBP

**Симптом:** `SHA-256 словаря HIBP НЕ СОВПАДАЕТ с эталоном. Возможна подмена словаря.`

**Решение:** см. `OPERATIONS.md §4 → "Случай: несовпадение SHA-256 HIBP"`.

**Ни в коем случае** не обновляйте `HibpExpectedSha256` в конфиге,
не проверив происхождение нового файла.

## §5 Phase 4: письмо не приходит / приходит без подписи

### 5a. Send-MailMessage падает с SMTP AUTH

**Симптом:** в логе WARN `Send-MailMessage ... 550 Authentication required`.

**Решение:** MimeKit/MailKit-ветка `Phase4-Report/New-AuditReport.ps1`
поддерживает SMTP AUTH через `SmtpClient.Authenticate()`. Настройте
в конфиге:
```psd1
SmtpServer = 'smtp.corp.example.com'
SmtpPort   = 587
# Креды для SMTP кладутся в SecretStore станции под именем 'SMTP-AuditAuth'.
```
и раскомментируйте соответствующий блок в `Send-PasswordEmail`
(либо используйте внутренний relay без авторизации).

### 5b. Письмо приходит с `[UNSIGNED]` в теме

**Симптом:** MimeKit/MailKit DLL не найдены.

**Решение:**
```powershell
# На станции:
# Скачайте с nuget.org (на machine с интернетом):
#   MimeKit.*.nupkg, MailKit.*.nupkg, BouncyCastle.Crypto.*.nupkg
# Распакуйте (это zip), найдите lib\netstandard2.0\*.dll
# Положите в C:\Tools\MimeKit\:
#   BouncyCastle.Crypto.dll
#   MimeKit.dll
#   MailKit.dll
# Перезапустите Phase 4.
```

### 5c. Подпись невалидна у получателя

**Симптом:** Outlook показывает "The certificate is untrusted".

**Причина:** corporate CA не установлен в Trusted Root у получателя.

**Решение:** распространить CA через GPO на все рабочие станции
получателей.

## §6 Phase 3: DSInternals `Get-ADDBAccount` бросает "DatabaseJetException"

**Симптом:** `Jet database is in use by another process` или
`recovery required`.

**Причины:**
1. Распаковка IFM не завершилась (файл блокирован 7z.exe).
2. `.dit` из "грязного" IFM (Phase 1 упала в середине).
3. Недостаточно RAM для загрузки `.dit` в память.

**Диагностика:**
```powershell
# Station:
esentutl /mh D:\AuditWork\ntds\ntds.dit
# "State: Clean Shutdown" — OK.
# "State: Dirty Shutdown" — нужен esentutl /p (recovery),
#   но это неразрушающий признак — IFM должен быть чистым.
#   Если грязный — перезапустите Phase 1.
```

**Решение при нехватке памяти:** увеличить RAM станции до 32 GB
(см. `INSTALL.md §1`).

## §7 Phase 5: Lock-SecretStore отсутствует

**Симптом:** `WARN: Команда Lock-SecretStore отсутствует`.

**Причина:** установлена старая версия модуля
`Microsoft.PowerShell.SecretStore` (< 1.0.6).

**Решение:**
```powershell
Update-Module Microsoft.PowerShell.SecretStore -Force
```

## §8 Retention: SDelete не удалил файл

**Симптом:** `Invoke-ReportRetention.ps1` exit 3, в логе
`ERROR ... Не удалось удалить ... The file is being used by another process`.

**Причины:**
1. Файл открыт в Explorer / Notepad / антивирусе.
2. Shadow Copy держит дескриптор.

**Диагностика:**
```powershell
handle.exe "D:\AuditReports\audit-report-2026-04-01T03-00-00Z.7z"
```

**Решение:** закрыть держателя, повторить скрипт. Если упрямо
держится — см. `Stop-SuspectProcesses` в Phase 5 и
вручную снять handle через Process Explorer → Find Handle.

## §9 Orchestrator: архив не появляется, ожидание истекает

**Симптом:** `Wait-ForFreshArchive` → `Свежий архив не появился за 90 мин.`

**Причины, по частоте:**
1. Phase 1 на DC не запустилась — см. `Get-ScheduledTaskInfo`.
2. Phase 1 создала архив, но не успела за 60 мин (большой домен).
3. Часы DC и станции разъехались → архив воспринимается как "старый"
   (проверка `MaxArchiveAgeHours`).

**Решения:**
* Увеличить `MaxArchiveAgeHours` до 48 в `Start-PasswordAudit.ps1`
  (параметр уже есть).
* Сдвинуть расписание станции с 03:00 на 04:00 UTC.
* Убедиться, что оба хоста синхронизированы с одним NTP.

## §10 "Я запустил оркестратор вручную, теперь scheduled-запуск не идёт"

Это нормально. Scheduled Task идёт по своему триггеру, ручной запуск
не ломает расписание. Проверка:
```powershell
(Get-ScheduledTask -TaskName 'ADPasswordAudit-Orchestrator' |
    Get-ScheduledTaskInfo).NextRunTime
```

## §11 Утечка пароля архива в историю PowerShell

**Симптом:** пользователь переживает, что пароль архива мог попасть в
`(Get-PSReadlineOption).HistorySavePath`.

**Где регламент это предотвращает:**
* В Phase 4 пароль живёт только в `SecureString` и в теле письма.
* Он НЕ логируется (`Write-AuditLog` фильтр на уровне вызывающего).
* Он НЕ попадает в командную строку 7z (передаётся через `-p<stdin>`).

**Если всё-таки переживаете:**
```powershell
# Почистить PSReadLine history файл:
$histPath = (Get-PSReadlineOption).HistorySavePath
if (Test-Path $histPath) {
    # SDelete обязательно — файл может содержать другие секреты.
    C:\Tools\SDelete\sdelete64.exe -p 3 $histPath
}
```
