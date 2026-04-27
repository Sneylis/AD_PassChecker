# ADPasswordAudit.App

WPF-приложение «всё-в-одном» для развёртывания и эксплуатации
системы аудита паролей AD на текущей audit-станции.

## Запуск

Двойной клик по `Launch-App.cmd` (попросит UAC), либо:

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\ADPasswordAudit.App.ps1
```

## Три режима

### 1. Setup Wizard
Первичный запуск, конфига ещё нет. 8 шагов:

1. **Welcome / preflight** — авточек: админские права, OS build, BitLocker
   на всех томах, pagefile=off, crash dump=off, RSAT-AD-PowerShell.
2. **Контроллер домена и сеть** — DC FQDN/IP, домен, SMB-share UNC.
   Кнопки `Test DC` (LDAP RootDSE bind) и `Test SMB` (создать пробный
   файл и удалить).
3. **Сервисная учётка (Backup Operator)** — username + password с
   кнопкой `Verify` (LDAP bind с этими кредами). Пароль кладётся в
   локальный SecretStore под именем `BackupOpCredential`.
4. **Каталоги** — Work / Log / Reports / Attestations с FolderBrowser'ами.
5. **HIBP** — radio: «Скачать автоматически» (вытягивает
   `haveibeenpwned-downloader.exe` с GitHub Releases и качает
   NTLM-словарь) или «Использовать существующий файл».
6. **Email + S/MIME** — SMTP server / port / from / recipients;
   ComboBox со всеми не-просроченными сертификатами из
   `Cert:\LocalMachine\My`.
7. **Расписание + Retention** — день месяца, час UTC для DC и для
   станции, срок хранения отчётов в днях.
8. **Review + Install** — текстовая сводка + кнопка `INSTALL`.
   После нажатия в фоновом runspace последовательно:
   * ставит 7-Zip, SDelete64, RSAT-AD-PowerShell;
   * `Install-Module` SecretManagement, SecretStore, DSInternals;
   * регистрирует `ADAuditVault` в режиме `Authentication=None`;
   * генерирует AES-256 IFM-ключ и кладёт в vault;
   * сохраняет пароль сервисной учётки в vault;
   * скачивает HIBP (или верифицирует SHA-256 указанного файла);
   * создаёт каталоги;
   * пишет `C:\ProgramData\ADPasswordAudit\audit.config.psd1`;
   * регистрирует Scheduled Tasks `ADPasswordAudit-Orchestrator`
     (ежемесячно через CalendarTrigger XML) и
     `ADPasswordAudit-Retention` (ежедневно 03:30);
   * собирает `ADPasswordAudit-DC-bootstrap.zip` (полный репо +
     готовый конфиг + DC-INSTALL-README.md) — копируете на DC и
     запускаете там `Install-DCComponents.ps1`.

   Прогресс — ProgressBar + лог в реальном времени.

### 2. Control Panel
Открывается автоматически после первого Install (или сразу при
повторном запуске, если конфиг уже есть).

* **Run audit now** — запускает `Orchestrator\Start-PasswordAudit.ps1`
  с `-WaitForArchiveMinutes 0` (использует уже лежащий на SMB архив).
* **Cleanup only (Phase 5)** — ручной запуск Phase 5 для разбора
  инцидентов.
* **Retention sweep** — ручной запуск ротации старых отчётов.
* **Open reports folder** — открывает Explorer на каталоге отчётов.
* **Cancel** — останавливает фоновую операцию (Stop runspace).

Все действия пишут лог в окно в реальном времени (через
ConcurrentQueue + DispatcherTimer, UI не замораживается).

### 3. Health Check
* `DataGrid` со всеми задачами `ADPasswordAudit-*`: имя, состояние,
  последний запуск UTC, exit-code (`0x...`), следующий запуск.
* Tail последних 60 строк из `C:\AuditLogs\audit-<сегодня>.log` —
  быстрый взгляд на состояние без открытия файла руками.
* Кнопки **Open log folder** и **Open attestations**.

## Что приложение НЕ делает (и почему)

* **Не разворачивает компоненты на DC** — отдельная машина,
  отдельные права; даём вам готовый zip-пакет.
* **Не передаёт ключ DC ↔ station** — это `Export-IfmKey.ps1`
  (см. `DC-INSTALL-README.md` в zip-пакете). Шаг разовый.
* **Не сохраняет пароль архива и не показывает его в UI** —
  пароль одноразовый, генерируется Phase 4 и уходит на e-mail
  через S/MIME.

## Известные ограничения

* `BtnTestDC` пингует ICMP — если ICMP заблокирован GPO,
  тест ругнётся; в этом случае `BtnVerifyCred` всё равно
  попробует bind по LDAP/389 — он и есть авторитетный.
* После Install лучше один раз перелогиниться, чтобы новый PATH
  (7-Zip, SDelete) подхватился.
* Запуск из RDP-сессии без отдельного DPI настроен под 1920×1080;
  на низком разрешении прокручиваем мышью.

## Файлы

| Файл | Назначение |
|---|---|
| `ADPasswordAudit.App.ps1` | Основной скрипт (XAML embedded, ~700 LOC) |
| `Launch-App.cmd`          | Bootstrap-launcher с UAC-elevation |
| `README.md`               | Этот документ |
