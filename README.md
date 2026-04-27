# AD Password Audit

Автоматизированная система аудита качества паролей Active Directory по регламенту `AD-Password-Audit-Workflow-RU.docx`.

## Структура репозитория

```
AD-Password-Audit/
├── Installer/              Скрипты развёртывания (на DC и на станции аудита)
├── Phase1-IFMBackup/       Фаза 1: создание IFM-бэкапа и передача (на DC)
├── Phase2-HIBP/            Фаза 2: проверка целостности словаря HIBP
├── Phase3-Audit/           Фаза 3: DSInternals Test-PasswordQuality
├── Phase4-Report/          Фаза 4: формирование отчёта, архив, email
├── Phase5-Cleanup/         Фаза 5: безопасная очистка и верификация
├── Retention/              Удаление старых отчётов по TTL (5 дней)
├── Orchestrator/           Мастер-скрипт, запускающий фазы 2→5
├── Common/                 Общие модули (Logging, Crypto, CleanupHelpers, Config)
│   ├── Logging.psm1
│   ├── Crypto.psm1
│   ├── CleanupHelpers.psm1
│   └── Config.psm1
├── Config/                 Пример конфига (psd1)
├── Tests/                  Pester-тесты
└── Docs/                   INSTALL, OPERATIONS, TROUBLESHOOTING
```

## Точки развёртывания

1. **Контроллер домена** — запускается `Installer/Install-DCComponents.ps1` однократно с правами Domain Admin. Создаёт gMSA с Backup Operator, ставит 7-Zip/SDelete64, кладёт ключ AES-256 в локальный SecretStore под машинной учёткой, регистрирует Scheduled Task для Фазы 1.

2. **Станция аудита (изолированная VM)** — запускается `Installer/Install-AuditStation.ps1`. Проверяет укрепление (BitLocker, pagefile/crashdump off, firewall), ставит инструменты и модули, запрашивает учётку Backup Operator, настраивает SecretStore, импортирует и верифицирует словарь HIBP, регистрирует Scheduled Task для оркестратора.

## Поток данных

```
DC                        SMB 3.0                 Станция аудита              Файл-сервер
──────────                ─────────               ───────────────              ──────────
ntdsutil IFM  ─→  7z/AES-256  ─→ IFM-архив ─→  расшифровка ─→  DSInternals
                                                     │
                                                     ↓
                                              текстовый отчёт
                                                     │
                                                     ↓
                                              7z/AES-256 (rnd pwd)  ─→  D:\Reports
                                                     │
                                                     ↓  SMTP + S/MIME
                                              корпоративная почта
                                              (только пароль архива)
```

Архив хранится 5 дней, затем Retention-задача удаляет его через SDelete64.

## Безопасность по слоям

- gMSA с Backup Operator (не Domain Admin), авторотация пароля, запрет интерактивного входа.
- AES-256 + шифрование заголовков (`-mhe=on`) для всех архивов.
- BitLocker FDE на станции аудита, pagefile и crash dump отключены.
- VLAN-изоляция: SMB только от DC, SMTP только к почтовому серверу, интернета нет.
- Двухканальная доставка: архив на файл-сервере, пароль — по корпоративной почте с S/MIME-подписью.
- Гарантированная очистка через `try/finally` + SDelete64 (3 прохода) + verification-скан.
- Все операции логируются с UTC-меткой и корреляционным ID.

## Быстрый старт

Подробности — в `Docs/INSTALL.md`. Кратко:

```powershell
# На DC (Domain Admin):
.\Installer\Install-DCComponents.ps1 -ConfigPath .\Config\audit.config.psd1

# На станции аудита (Administrator):
.\Installer\Install-AuditStation.ps1 -InteractiveConfig

# Однократная передача ключа DC ↔ станция:
.\Installer\Export-IfmKey.ps1 -ConfigPath ... -DCCertThumbprint <tp>
```

Дальше всё работает по расписанию (см. `Docs/OPERATIONS.md`).

## Документация

| Документ | Что внутри |
|---|---|
| [`Docs/INSTALL.md`](Docs/INSTALL.md) | Пошаговая установка на DC и станции, передача ключей, smoke test |
| [`Docs/OPERATIONS.md`](Docs/OPERATIONS.md) | Ежемесячная рутина, формат отчёта, инцидент-флоу, ротация ключей |
| [`Docs/TROUBLESHOOTING.md`](Docs/TROUBLESHOOTING.md) | Разбор типовых ошибок по фазам с диагностикой и фиксами |
| [`Docs/ARCHITECTURE.md`](Docs/ARCHITECTURE.md) | Обоснование принятых решений (почему IFM, CMS, gMSA, SDelete 3p и т.д.) |
| [`Tests/README-LAB.md`](Tests/README-LAB.md) | Руководство по ручной верификации всей цепочки в лабораторном домене |

## Статус проекта

Все фазы регламента реализованы:

- Установщики на DC и станции;
- Phase 1 — IFM backup + encrypted delivery;
- Phase 2 — HIBP/platform integrity;
- Phase 3 — DSInternals audit (16 категорий);
- Phase 4 — report, archive, S/MIME email;
- Phase 5 — secure cleanup + signed attestation;
- Retention (5 дней, SDelete 3p);
- Orchestrator;
- Pester-тесты + лаборатория из 20 тестовых учёток;
- Документация.
