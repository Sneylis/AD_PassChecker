# AD Password Audit

Автоматизированная система аудита качества паролей Active Directory по регламенту `AD-Password-Audit-Workflow-RU.docx`.

## Структура репозитория

```
AD-Password-Audit/
├── App/                    WPF-приложение (Wizard + Control Panel + Health Check)
│   ├── ADPasswordAudit.App.ps1
│   ├── Launch-App.cmd      ← двойной клик отсюда
│   └── README.md
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

## Установка через Launch-App.cmd (рекомендуемый путь)

Самый быстрый способ развернуть систему — запустить WPF-приложение
`App\Launch-App.cmd` на аудит-станции. Оно проведёт вас через мастер
из 8 шагов и само вызовет нужные скрипты-фазы.

### Что подготовить заранее

Прежде чем запускать `Launch-App.cmd`, должно быть готово:

1. **Аудит-станция** (отдельная VM):
   - Windows Server 2019 или новее.
   - **BitLocker FDE включён** на всех томах (FullyEncrypted, не EncryptionInProgress).
   - **Pagefile отключён** (`wmic computersystem set AutomaticManagedPagefile=False` + удалить `pagefile.sys`).
   - **Crash dump отключён** (`HKLM:\SYSTEM\CurrentControlSet\Control\CrashControl` → `CrashDumpEnabled=0`).
   - Машина введена в домен.
   - Локальный администратор для запуска приложения.

2. **Контроллер домена** (отдельная VM):
   - Доступен по сети с аудит-станции (LDAP/389, SMB/445).
   - Создан **KDS root key** (если ещё нет): `Add-KdsRootKey -EffectiveTime ((Get-Date).AddHours(-10))`.

3. **Сервисная учётка** одного из двух типов:
   - **gMSA (по регламенту):** `New-ADServiceAccount` + `PrincipalsAllowedToRetrieveManagedPassword` для DC и станции, членство в `Backup Operators`, на каждом хосте — `Install-ADServiceAccount` + `Test-ADServiceAccount`.
   - **Обычная учётка:** AD-пользователь с известным паролем, член `Backup Operators`.

4. **SMB-шара** для передачи IFM-архива DC → станция (например,
   `\\dc01\IFM-Exchange$` или на отдельном файл-сервере). Сервисной
   учётке выданы права `Modify` на share + NTFS.

5. **S/MIME-сертификат** в `Cert:\LocalMachine\My` на станции — для подписи писем с паролем архива.

6. **SMTP-relay**, через который станция сможет отправить письмо получателю(ям).

### Запуск приложения

На аудит-станции:

1. Скопируйте папку `AD-Password-Audit` куда-нибудь, где её сможет
   читать локальный администратор (например, `C:\ADPasswordAudit\`).
2. Откройте `App\Launch-App.cmd` **двойным кликом** или из cmd:
   ```
   C:\ADPasswordAudit\App\Launch-App.cmd
   ```
3. Появится UAC-запрос — подтвердите. Лаунчер сам перезапустится с
   правами администратора и откроет WPF-окно.

Если предпочитаете командную строку:

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass `
    -File C:\ADPasswordAudit\App\ADPasswordAudit.App.ps1
```

### Прохождение мастера

В окне будет три вкладки: `Setup Wizard`, `Control Panel`,
`Health Check`. По умолчанию открывается мастер.

**Шаг 1 — Welcome / Preflight.** Авточек: админ-права, версия Windows,
PowerShell ≥ 5.1, BitLocker на всех томах, pagefile отключён, crash
dump отключён, наличие RSAT-AD-PowerShell. Зелёные галочки —
обязательные пункты пройдены, красные — требуют внимания. Если
что-то не сошлось, исправьте и нажмите **Re-check**.

**Шаг 2 — Контроллер домена и сеть.** Заполните:
- `DC FQDN or IP` — например `dc01.corp.lab.local`.
- `Domain DNS name` — `corp.lab.local`.
- `This audit station hostname` — определяется автоматически.
- `UNC SMB share` — путь к шаре, куда DC положит IFM-архив,
  например `\\dc01\IFM-Exchange$`.

Кнопка **Test DC connection** делает ICMP-пинг + LDAP RootDSE-bind.
**Test SMB share** создаёт пробный файл и удаляет его, проверяя
права на запись. Обе должны вернуть `OK` (зелёный).

**Шаг 3 — Сервисная учётка.** Радио-переключатель:

- **gMSA (рекомендуется по регламенту)** — поле для имени gMSA с
  `$` на конце (`CORP\gmsa-adaudit$`). Кнопка **Test-ADServiceAccount**
  проверит, что текущий хост может получить managed password из AD.
  Пароль вводить НЕ нужно — Windows получает его сам.

- **Regular service account** — поля username и password. Кнопка
  **Verify credential (LDAP bind)** проверит креды через bind на DC.
  Пароль будет сохранён в локальный SecretStore (DPAPI per-machine,
  под BitLocker FDE).

**Шаг 4 — Каталоги.** Четыре пути с кнопками `…` (выбор папки):
- `Work directory` — рабочее пространство фаз (распаковка IFM,
  промежуточные файлы); рекомендуется на NVMe-томе с BitLocker.
- `Log directory` — `C:\AuditLogs` (по умолчанию).
- `Reports retention dir` — куда складываются итоговые
  зашифрованные отчёты (хранятся 5 дней по умолчанию).
- `Attestations dir` — куда Phase 5 пишет подписанные attestation
  после очистки.

**Шаг 5 — HIBP.** Радио:
- **Скачать NTLM-словарь автоматически** — приложение само скачает
  `haveibeenpwned-downloader.exe` с GitHub Releases и выкачает
  ~30 GB словарь в указанную папку. Время — 1–2 часа на 100 Mbps.
- **Использовать существующий файл** — укажите путь и (опционально)
  ожидаемый SHA-256. Если SHA-256 пуст, приложение пересчитает
  его при Install и запишет в конфиг.

**Шаг 6 — Email + S/MIME.** Введите SMTP-сервер, порт (обычно 25
для внутреннего relay), `From`, получателей через запятую и выберите
сертификат S/MIME из выпадающего списка (приложение само подтянет
все непросроченные сертификаты из `Cert:\LocalMachine\My`). Кнопка
**Refresh certificate list** обновит список, если вы только что
импортировали сертификат.

**Шаг 7 — Расписание и retention.** День месяца (1–28), час UTC для
DC (Phase 1) и для станции (Orchestrator), срок хранения отчётов
в днях (по умолчанию 5).

**Шаг 8 — Review and Install.** Текстовая сводка всех введённых
параметров. Внимательно прочтите. Когда всё устраивает — нажмите
большую зелёную кнопку **INSTALL**.

Под кнопкой появится прогресс-бар и лог в реальном времени.
Приложение последовательно выполнит:

1. Установит 7-Zip, SDelete64, RSAT-AD-PowerShell.
2. Установит модули `SecretManagement`, `SecretStore`, `DSInternals`.
3. Зарегистрирует `ADAuditVault` в режиме `Authentication=None`
   (защита через DPAPI per-machine + BitLocker FDE).
4. Сгенерирует AES-256 IFM-ключ и положит в vault.
5. Если выбран обычный аккаунт — сохранит его пароль в vault.
6. Скачает HIBP (если выбрано) или верифицирует SHA-256
   указанного файла.
7. Создаст рабочие каталоги.
8. Запишет `C:\ProgramData\ADPasswordAudit\audit.config.psd1`.
9. Зарегистрирует Scheduled Tasks:
   - `ADPasswordAudit-Orchestrator` — ежемесячно через
     CalendarTrigger XML.
   - `ADPasswordAudit-Retention` — ежедневно в 03:30.
10. Соберёт пакет для DC: `ADPasswordAudit-DC-bootstrap.zip` со
    всем репозиторием, готовым `audit.config.psd1` и
    `DC-INSTALL-README.md`.

По завершении (`progress = 100%`) откроется MessageBox `Install
complete`, окно автоматически переключится на вкладку **Health
Check**, где будут видны зарегистрированные задачи.

### После Install — установка на DC

1. Перенесите `ADPasswordAudit-DC-bootstrap.zip` (он в
   `Reports retention dir` — например `D:\AuditReports\`) на DC
   любым доступным способом.
2. На DC под Domain Admin:
   ```powershell
   Expand-Archive ADPasswordAudit-DC-bootstrap.zip -DestinationPath C:\ADPasswordAudit
   cd C:\ADPasswordAudit
   .\Installer\Install-DCComponents.ps1 -ConfigPath .\audit.config.psd1
   ```
3. Один раз передайте AES-IFM-ключ со станции на DC через CMS:
   ```powershell
   # Обратно на станции:
   .\Installer\Export-IfmKey.ps1 `
        -ConfigPath C:\ProgramData\ADPasswordAudit\audit.config.psd1 `
        -DCCertThumbprint <thumbprint-сертификата-DC>
   ```
   `Install-DCComponents.ps1` при первом тике Phase 1 расшифрует
   `ifm-key.p7m` своим private key и сохранит в свой vault.

### Дальнейшая эксплуатация — три режима приложения

**Setup Wizard** больше не понадобится после первичной установки.
При повторном запуске `Launch-App.cmd` приложение увидит конфиг и
откроется сразу на Health Check.

**Control Panel** — ручное управление:
- **Run audit now** — запуск оркестратора с
  `WaitForArchiveMinutes 0` (использует уже лежащий на SMB архив).
- **Cleanup only (Phase 5)** — точечный запуск Phase 5 для разбора
  инцидентов.
- **Retention sweep** — ручная ротация старых отчётов.
- **Open reports folder** — открывает Explorer на каталоге отчётов.
- **Cancel** — останавливает запущенную фоновую операцию.

**Health Check** — статусная панель:
- Таблица Scheduled Tasks (`Orchestrator`, `Retention`, `Phase1`):
  состояние, последний запуск UTC, exit-code, следующий запуск.
- Tail последних 60 строк из `C:\AuditLogs\audit-<сегодня>.log`.
- Кнопки открытия каталога логов и каталога attestation.

### Если приложение упало с ошибкой

1. Скопируйте текст ошибки целиком (с номером строки).
2. Откройте `C:\AuditLogs\audit-<сегодня>.log` — там вся хронология
   с Correlation ID.
3. См. [`Docs/TROUBLESHOOTING.md`](Docs/TROUBLESHOOTING.md) — там
   разобраны 11 типовых проблем по фазам.
4. Если приложение не запускается вовсе и ругается на синтаксис
   PowerShell — проверьте, что у файла `ADPasswordAudit.App.ps1`
   первые три байта это UTF-8 BOM (`EF BB BF`):
   ```powershell
   Get-Content C:\ADPasswordAudit\App\ADPasswordAudit.App.ps1 -Encoding Byte -TotalCount 3 |
       ForEach-Object { '{0:X2}' -f $_ }
   ```
   Должно вывести `EF`, `BB`, `BF`. Без BOM PS 5.1 на не-английских
   локалях интерпретирует файл как Windows-1252.

## Альтернатива: ручной запуск установщиков

Если по какой-то причине WPF-приложение неприменимо (например, нет
GUI на Server Core), можно использовать ручные скрипты — см.
[`Docs/INSTALL.md`](Docs/INSTALL.md). Кратко:

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
| [`App/README.md`](App/README.md) | Описание WPF-приложения (Wizard / Control Panel / Health Check), горячие клавиши, ограничения |
| [`Docs/INSTALL.md`](Docs/INSTALL.md) | Пошаговая ручная установка на DC и станции (без WPF-приложения), передача ключей, smoke test |
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
