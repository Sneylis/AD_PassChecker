@echo off
REM =====================================================================
REM  AD Password Audit — launcher
REM
REM  Запускает WPF-приложение под локальным администратором (UAC).
REM  Если уже под админом — стартует напрямую.
REM =====================================================================

setlocal
set "SCRIPT_DIR=%~dp0"
set "APP_PS1=%SCRIPT_DIR%ADPasswordAudit.App.ps1"

if not exist "%APP_PS1%" (
    echo ERROR: %APP_PS1% not found.
    pause
    exit /b 1
)

REM --- Проверка прав администратора через попытку записи в защищённую ветку.
net session >nul 2>&1
if %errorlevel% neq 0 (
    echo Перезапуск под администратором...
    powershell.exe -NoProfile -ExecutionPolicy Bypass -Command ^
        "Start-Process powershell.exe -ArgumentList '-NoProfile','-ExecutionPolicy','Bypass','-File','\"%APP_PS1%\"' -Verb RunAs"
    exit /b 0
)

REM --- Уже под админом → стартуем приложение.
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%APP_PS1%"
endlocal
