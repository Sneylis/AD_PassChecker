# OPERATIONS — регулярная эксплуатация

## 1. Что происходит каждый месяц (без вашего участия)

| UTC | Машина | Задача | Артефакт |
|---|---|---|---|
| 1-е число, 02:00 | DC | `ADPasswordAudit-Phase1` | `\\files01\IFM-Exchange$\audit-ifm-<UTC>.7z` |
| 1-е число, 03:00 | Station | `ADPasswordAudit-Orchestrator` | `\\files01\AuditReports$\audit-report-<UTC>.7z` + email |
| 2-е по 5-е, 03:30 | Station | `ADPasswordAudit-Retention` | (ничего — архивы ещё свежие) |
| 6-е и далее, 03:30 | Station | `ADPasswordAudit-Retention` | самый старый архив уничтожается SDelete |

## 2. Ежедневная рутина security engineer

В 08:00 утром первого дня месяца проверить:

1. **Почта** — пришло ли письмо `AD Password Audit — <YYYY-MM-DD>`
   с S/MIME-подписью?
2. **Подпись валидна?** (Outlook → Details → Show Signature Details).
3. Если письма **нет** — открыть `C:\AuditLogs\audit-<date>.log` на
   станции и искать строку `ИТОГ ПРОГОНА`.
   * `Exit code: 0` → Send-MailMessage упал, см. `TROUBLESHOOTING.md §5`.
   * `Exit code: 2` → DC не поставил архив.
   * `Exit code: 3` → HIBP или BitLocker.
   * `Exit code: 4` → Phase 3 (DSInternals).
   * `Exit code: 5` → Phase 4 (отчёт/почта).
   * `Exit code: 6` → Phase 5 нашла residue — **инцидент**.
4. Если письмо пришло: пароль из письма → распаковать архив →
   прочитать отчёт. **Обновить** тикет / jira / confluence с
   динамикой "сколько слабых паролей стало по сравнению с прошлым
   месяцем".

## 3. Формат отчёта

Внутри `audit-report-<UTC>.7z`:

* `audit-report-<UTC>.txt` — человекочитаемый отчёт. Формат
  каждой строки:
  ```
  [WeakPassword] CORP\j.doe
  [DuplicatePasswordGroups] CORP\a.smith  (group: dup-42)
  [Kerberoastable] CORP\svc-sql
  ```
  Теги (см. `Phase4-Report/New-AuditReport.ps1 → $CategoryMeta`):

  | Тег | Что значит | Как чинить |
  |---|---|---|
  | WeakPassword | В HIBP | Смена пароля + policy reminder |
  | DuplicatePasswordGroups | Несколько учёток с одним паролем | Смена паролей |
  | EmptyPassword | Пароль пустой | Смена + PasswordNotRequired=false |
  | LMHashPresent | Хранится LM-хеш | GPO: NoLMHash=1 |
  | DefaultComputerPassword | Пароль компьютера = имя компьютера | Reset secure channel |
  | PasswordNotRequired | UAC bit 32 | Set-ADUser -PasswordNotRequired $false |
  | PasswordNeverExpires | UAC bit 65536 | Set-ADUser -PasswordNeverExpires $false |
  | AESKeysMissing | Нет AES Kerberos keys | Смена пароля → перегенерирует |
  | PreAuthNotRequired | UAC 4194304 | Снять `DoesNotRequirePreAuth` |
  | DESEncryptionOnly | DES-only в msDS-SupportedEncryptionTypes | Убрать DES |
  | DelegatableAdmins | Admin + TrustedForDelegation | Протектед Users, запрет делегации |
  | SmartCardUsersWithPassword | SmartCardRequired + активный пароль | Smart Card Logon Interactive |
  | Kerberoastable | SPN на юзере + простой пароль | Удлинение пароля до 25+ или gMSA |
  | ClearTextPassword | REVERSIBLE_ENCRYPTION | Снять флаг, сменить пароль |
  | SamAccountNameAsPassword | Пароль == логин | Смена |
  | DuplicateNtHashes | (как Duplicate) | — |

* `audit-report-<UTC>.json` — машинно-читаемое; каждая категория —
  массив `DOMAIN\sam`. **Никаких хешей/паролей** не содержит.

## 4. Инцидент-флоу

### Случай: отчёт не пришёл две периода подряд

1. `Get-ScheduledTask -TaskName ADPasswordAudit-* | Get-ScheduledTaskInfo`.
2. Смотрим `LastTaskResult`:
   * `0x0` — задача стартовала и завершилась нормально →
     значит, проблема в SMTP или S/MIME. Смотри логи станции.
   * `0x1` — общая ошибка, см. логи.
   * `0x41301` — задача ещё выполняется → дай время.
3. Если оркестратор валится на SecretStore (`ошибка доступа к vault`) —
   проверь, что gMSA / сервисная учётка, под которой исполняется
   задача, не была ротирована/заблокирована.

### Случай: Phase 5 записала residue

Это **security-инцидент**. По регламенту — зафиксировать тикет
P1 и не удалять `C:\AuditWork\*` вручную до разбора.

Действия:
1. Прочитать `cleanup-attestation-<CID>-<UTC>.json.p7s`
   (`Unprotect-CmsMessage` → JSON). Поле `ResidueRemaining`
   содержит список файлов, которые не удалось уничтожить.
2. Заснифать, почему не удалось: открытый handle (ProcessExplorer,
   `handle.exe <path>`), права NTFS, или BitLocker в `Locked` state.
3. После устранения — повторить `Invoke-SecureCleanup.ps1`.
4. В vault'е может остаться расшифрованный ключ; если хост
   был скомпрометирован, **считать ключ раскрытым**, перегенерировать
   и повторно `Export-IfmKey.ps1` на DC.

### Случай: несовпадение SHA-256 HIBP

Phase 2 пишет CRITICAL. Возможные причины:
1. Легитимное обновление словаря (HIBP выпускает новые версии) —
   обновите `HibpExpectedSha256` в конфиге **только** после
   ручной верификации подписи релиза HIBP.
2. Подмена злоумышленником, имеющим write-access к файлу.
   Немедленно: SDelete подменённого файла, **заморозить аудит**
   пока не проведёте расследование. Смотрите `4624` / `4663` в
   журнале безопасности по доступам к `hibp-ntlm.txt`.

## 5. Ежеквартальная проверка

Раз в квартал (добавьте в календарь):

1. `.\Tests\Invoke-Pester.ps1 ...` — все unit-тесты зелёные.
2. Прогнать "dry run" на **лабораторном** домене (см. `Tests/README-LAB.md`).
3. Проверить, что vault-пароль gMSA не просрочился
   (`Get-ADServiceAccount -Properties PasswordLastSet`).
4. Ревизия `ReportRetentionDays` — не изменились ли требования
   регулятора/внутренней политики.
5. Ревизия членства Backup Operators — нет ли лишних.

## 6. Ротация ключей (раз в год)

```powershell
# На станции:
.\Installer\Install-AuditStation.ps1 -RotateKey
# → Генерирует новый AES-256, старый помечается как "retired"
# → Export-IfmKey.ps1 — снова на DC.
```

## 7. Резервное копирование конфига

Единственный файл, который критично не потерять:
`C:\ProgramData\ADPasswordAudit\audit.config.psd1`.
Всё остальное восстанавливается прогоном установщиков.
Сам конфиг НЕ содержит секретов и спокойно бэкапится в git.
