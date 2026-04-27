# Ручная верификация в лабораторной среде

Этот документ описывает, как проверить всю цепочку аудита
**от начала до конца** в изолированной лаборатории ДО первого
запуска в продакшене.

## 1. Минимальная лаборатория

* 1 × DC (лаб-домен `corp.lab.local`, Windows Server 2019+, AD DS).
* 1 × Audit Station (Windows Server 2019+ в отдельном VLAN,
  без выхода в интернет после первоначальной настройки).
* 1 × File server / SMB-share (можно совместить с Audit Station).
* Корп-сертификат для S/MIME (можно самоподписанный CA +
  endpoint-сертификат).

Характеристики VM (как в регламенте):

| Роль | vCPU | RAM | Disk |
|---|---|---|---|
| DC (лаб) | 2 | 4 GB | 60 GB |
| Audit Station | 4 | 16 GB | 300 GB (NVMe если есть) |
| File server | 2 | 4 GB | 200 GB |

## 2. Подготовка

1. **На DC**, под Domain Admin:
   ```powershell
   cd C:\ADPasswordAudit\Installer
   .\Install-DCComponents.ps1 -ConfigPath C:\ProgramData\ADPasswordAudit\audit.config.psd1
   ```

2. **На Audit Station**, под Local Admin (без прав в домене):
   ```powershell
   cd C:\ADPasswordAudit\Installer
   .\Install-AuditStation.ps1 -InteractiveConfig
   ```
   Установщик запросит учётку Backup Operator, сгенерирует AES-ключ,
   импортирует HIBP, зарегистрирует ежемесячное расписание.

3. **Экспорт ключа со станции → на DC** (однократно):
   ```powershell
   cd C:\ADPasswordAudit\Installer
   .\Export-IfmKey.ps1 `
       -ConfigPath       C:\ProgramData\ADPasswordAudit\audit.config.psd1 `
       -DCCertThumbprint <thumbprint-DC-LAPS-или-DPAPI-backup-cert>
   ```
   DC при следующем запуске Phase 1 расшифрует ключ и сохранит в свой
   vault (см. `Install-DCComponents.ps1 → Initialize-DCVault`).

## 3. Создание тестовых учётных записей

На DC (лабораторном!), под Domain Admin:

```powershell
cd C:\ADPasswordAudit\Tests
.\New-LabTestUsers.ps1
```

Скрипт создаст ~20 учёток в OU=`PasswordAuditLab`, каждая покрывает
одну из категорий отчёта DSInternals. Список ожидаемых категорий
и связанных имён — в конце вывода скрипта.

## 4. Ручной прогон Phase 1 на DC

```powershell
cd C:\ADPasswordAudit\Phase1-IFMBackup
.\New-IFMBackup.ps1 -ConfigPath C:\ProgramData\ADPasswordAudit\audit.config.psd1
```

Ожидается:
* на SMB-share появится `audit-ifm-<UTC>.7z` + `.sha256` + `.json` sidecar;
* локальный IFM-бэкап уничтожен SDelete;
* exit code = 0; в Event Log (Application / source=ADPasswordAudit)
  нет CRITICAL.

## 5. Ручной прогон оркестратора на Audit Station

```powershell
cd C:\ADPasswordAudit\Orchestrator
.\Start-PasswordAudit.ps1 -ConfigPath C:\ProgramData\ADPasswordAudit\audit.config.psd1
```

Что проверять:

1. **Phase 2** не упала на проверках платформы (BitLocker on,
   pagefile off, crash dump off).
2. **Phase 3** создала RAW-JSON отчёт в `WorkDirectory\reports`.
   Открываем, ищем lab-юзеров:

   ```powershell
   $raw = Get-Content .\audit-raw-<CID>-*.json -Raw | ConvertFrom-Json
   $raw.Categories.WeakPassword                | Where-Object { $_ -match 'lab-weak-hibp' }
   $raw.Categories.DuplicatePasswordGroups     | Where-Object { $_ -match 'lab-dup' }
   $raw.Categories.Kerberoastable              | Where-Object { $_ -match 'svc-sql-lab' }
   $raw.Categories.DelegatableAdmins           | Where-Object { $_ -match 'lab-delegadmin' }
   ```

   Каждая категория должна содержать своего lab-юзера
   (см. ожидаемую картину в выводе `New-LabTestUsers.ps1`).

3. **Phase 4** положила в `ReportRetentionDirectory`:
   * `audit-report-<UTC>.7z`
   * `audit-report-<UTC>.7z.sha256`
   * (опционально) `audit-report-<UTC>.meta`
4. На почте, настроенной в `SmtpRecipients`, пришло письмо с темой
   `AD Password Audit — <date>` и S/MIME-подписью.
   Тело содержит сгенерированный пароль архива.
5. Вручную распаковать архив этим паролем и сверить содержимое.
6. **Phase 5** записала `cleanup-attestation-<CID>-<UTC>.json.p7s`.
   В `WorkDirectory` не осталось `*.dit`, `SYSTEM`, `*.hashes`,
   `report-*.txt`.

## 6. Проверка ротации

Переставляем системное время (или `Set-ItemProperty LastWriteTime`
на файлах отчётов) чтобы имитировать прошествие 6 дней и запускаем:

```powershell
cd C:\ADPasswordAudit\Retention
.\Invoke-ReportRetention.ps1 -ConfigPath C:\ProgramData\ADPasswordAudit\audit.config.psd1
```

Ожидается:
* файлы старше 5 дней — удалены через SDelete (3 прохода);
* хотя бы `KeepMinimum=1` самый свежий архив остался;
* в логе: `Удалено: N`, `Оставлено: M`, `Ошибок: 0`.

## 7. Негативные сценарии

Обязательно прогнать каждый негативный тест и убедиться, что
оркестратор корректно прерывается с правильным exit code:

| Сценарий | Как имитировать | Ожидание |
|---|---|---|
| HIBP изменён | `Add-Content hibp-ntlm.txt "extra"` | Phase 2 → CRITICAL "checksum mismatch", exit 3 |
| Архив старый | Переставить mtime архива на `-25h` | Wait-ForFreshArchive → исключение, exit 2 |
| SHA-256 sidecar не совпадает | Поменять 1 байт в `.7z` | Assert-ArchiveSha256 → exit 2 |
| BitLocker off | `Disable-BitLocker -MountPoint "C:"` | Phase 2 CRITICAL, exit 3 |
| SDelete удалён | `Rename-Item C:\Tools\SDelete\sdelete64.exe ...` | Phase 5 exit 2 |
| Pagefile включён | `wmic computersystem set AutomaticManagedPagefile=True` | Phase 2 exit 3 |

После каждого негативного теста **обязательно** запустить Phase 5
вручную, чтобы убедиться, что residue-проверка отработала и
cleanup-attestation создан.

## 8. Очистка лаборатории

```powershell
.\New-LabTestUsers.ps1 -Cleanup
```

## 9. Unit-тесты (Pester)

Перед продакшен-установкой прогнать:

```powershell
Install-Module Pester -MinimumVersion 5.0 -Scope CurrentUser
cd C:\ADPasswordAudit\Tests
Invoke-Pester -Path . -Output Detailed
```

Все тесты должны пройти. Тесты, помеченные тегом `RequiresSevenZip`,
пропускаются на машинах без 7z в `PATH` — это ожидаемо.
