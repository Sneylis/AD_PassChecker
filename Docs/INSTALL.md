# INSTALL — первичное развёртывание системы аудита паролей AD

> Этот документ описывает **однократную** установку. Последующие
> прогоны идут автоматически по расписанию, ручных действий
> не требуют (кроме получения письма с паролем архива).

## 0. Контрольный список до начала

Прежде чем запускать установщики, убедитесь:

- [ ] Согласован периметр аудита (частота — ежемесячно, объём — весь домен).
- [ ] Выделена **изолированная VM** под аудит-станцию (см. §1).
- [ ] Выделена **SMB-шара** для передачи IFM-архива между DC и станцией.
- [ ] Есть корпоративный сертификат для **S/MIME** (подпись писем).
- [ ] У оператора есть почтовый ящик и он настроен получать S/MIME.
- [ ] Есть **учётка Backup Operator** (не Domain Admin!) — либо создадите.
- [ ] Есть файл **HIBP NTLM** (рекомендуется `pwned-passwords-ntlm-ordered-by-count`).
- [ ] Согласован и задокументирован **SHA-256 эталон** файла HIBP.

## 1. Характеристики VM аудит-станции (обязательно)

| Компонент | Минимум | Рекомендация 500–1000 юзеров | Рекомендация 1000–5000 юзеров |
|---|---|---|---|
| vCPU | 4 | 4 | 8 |
| RAM | 8 GB | 16 GB | 32 GB |
| Диск (BitLocker) | 200 GB NVMe | 300 GB NVMe | 500 GB NVMe |
| ОС | Windows Server 2019 | 2022 | 2022 |
| Сеть | Изолированный VLAN, outbound только к SMTP + SMB-share | — | — |
| Pagefile | **ВЫКЛЮЧЕН** | — | — |
| Crash dump | **ВЫКЛЮЧЕН** | — | — |
| BitLocker FDE | **ВКЛЮЧЁН на всех томах** | — | — |

PS 5.1 или 7.x; в продакшене регламентирован 5.1 (штатный).

## 2. Сеть и SMB

* На DC → исходящий SMB 3.0 к `\\<fileserver>\IFM-Exchange$` с транспортным
  шифрованием (`Set-SmbServerConfiguration -EncryptData $true`).
* На аудит-станции → только входящий SMB на тот же share (read-only).
* Никаких других сетевых потоков между DC и станцией.

## 3. Установка на DC

Скрипт запускается **однократно** под Domain Admin:

```powershell
# Скопировать репо на DC в C:\ADPasswordAudit
cd C:\ADPasswordAudit\Installer
.\Install-DCComponents.ps1 `
    -ConfigPath C:\ProgramData\ADPasswordAudit\audit.config.psd1
```

Что делает:

1. Создаёт **KDS root key** (если нет).
2. Создаёт **gMSA** с членством в Backup Operators (принцип минимума прав).
3. Ставит **7-Zip**, **SDelete64**, модули **SecretManagement + SecretStore**.
4. Инициализирует локальный vault под машинной учёткой DC
   (`Authentication=None`).
5. Ждёт передачи AES-ключа от аудит-станции (через CMS-файл).
6. Регистрирует **Scheduled Task** `ADPasswordAudit-Phase1`
   (ежемесячно, 1-го числа 02:00 UTC), запуск от gMSA.

## 4. Установка на аудит-станции

Скрипт запускается **однократно** под Local Admin:

```powershell
cd C:\ADPasswordAudit\Installer
.\Install-AuditStation.ps1 -InteractiveConfig
```

Что делает (7 шагов):

1. **Test-Hardening** — BitLocker/pagefile/crashdump/firewall, сетевая
   изоляция. Падает, если что-то не в порядке.
2. **Install-RequiredTools** — 7-Zip, SDelete64, SecretManagement,
   SecretStore, DSInternals (из оффлайн `.nupkg`).
3. **Initialize-VaultAndKeys** — SecretStore без пароля
   (Authentication=None — машина уже защищена BitLocker),
   генерация AES-256 ключа.
4. **Request-ServiceCredential** — Get-Credential, в vault кладёт
   SecureString.
5. **Import-HibpDictionary** — автоопределение формата
   (NTLM/SHA-1/plain), plain → NTLM через MD4.
6. **Initialize-WorkDirectories** — ACL hardening на WorkDir,
   ReportRetentionDirectory, LogDirectory.
7. **Register-MonthlyScheduledTask** — `ADPasswordAudit-Orchestrator`
   (ежемесячно, 1-го числа 03:00 UTC — через час после Phase 1 на DC).

## 5. Передача AES-ключа DC ↔ аудит-станция

Это критический шаг — DC должен уметь **расшифровывать** IFM на своей
стороне тем же ключом, которым аудит-станция будет расшифровывать
на своей.

```powershell
# На АУДИТ-СТАНЦИИ:
cd C:\ADPasswordAudit\Installer
.\Export-IfmKey.ps1 `
    -ConfigPath       C:\ProgramData\ADPasswordAudit\audit.config.psd1 `
    -DCCertThumbprint <thumbprint-сертификата-DC>
```

Скрипт:
1. Получает AES-ключ из SecretStore станции.
2. Шифрует его через **CMS** (`Protect-CmsMessage`) под публичным
   ключом DC.
3. Кладёт в SMB-share как `ifm-key.p7m`.
4. `Install-DCComponents.ps1` (уже запущенный ранее) при следующем
   тике Phase 1 читает, расшифровывает своим **private key** и
   сохраняет в свой vault. После этого `ifm-key.p7m` удаляется
   через SDelete.

## 6. Настройка Scheduled Task'ов

Создаются **автоматически** установщиками, ничего дополнительно
регистрировать не нужно. Проверить:

```powershell
Get-ScheduledTask -TaskName 'ADPasswordAudit-*' |
    Select TaskName, LastRunTime, LastTaskResult, NextRunTime
```

Должны быть:
| Машина | Task Name | Расписание |
|---|---|---|
| DC | ADPasswordAudit-Phase1 | Ежемесячно, 1-го, 02:00 UTC |
| Station | ADPasswordAudit-Orchestrator | Ежемесячно, 1-го, 03:00 UTC |
| Station | ADPasswordAudit-Retention | Ежедневно, 03:30 UTC |

## 7. Smoke test перед первым продакшен-запуском

См. отдельный документ [`Tests/README-LAB.md`](../Tests/README-LAB.md).
Минимум:

```powershell
# На станции, под gMSA или под Local Admin:
cd C:\ADPasswordAudit\Orchestrator
.\Start-PasswordAudit.ps1 `
    -ConfigPath            C:\ProgramData\ADPasswordAudit\audit.config.psd1 `
    -WaitForArchiveMinutes 0           # не ждать, использовать готовый
```

Успех — exit 0 и на почте письмо `AD Password Audit — <date>`
с S/MIME-подписью.

## 8. Аварийный план

Если что-то пошло не так на первом запуске:

1. Не паникуй, **не удаляй** лог-файлы (`C:\AuditLogs\audit-*.log`).
2. Проверь Event Log → Application → source `ADPasswordAudit`
   на записи WARN/ERROR/CRITICAL.
3. Найди CID последнего прогона (первая строка лога) и
   `grep CID=<x> C:\AuditLogs\*.log` — получишь всю хронологию.
4. См. [`TROUBLESHOOTING.md`](TROUBLESHOOTING.md).
5. Обязательно запусти Phase 5 руками:
   ```powershell
   cd C:\ADPasswordAudit\Phase5-Cleanup
   .\Invoke-SecureCleanup.ps1 -ConfigPath C:\ProgramData\ADPasswordAudit\audit.config.psd1
   ```
6. Проверь, что `cleanup-attestation-*.json.p7s` создан
   и `Success=true`.
