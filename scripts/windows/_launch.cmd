@echo off
setlocal
for %%I in ("%~dp0..\..") do set "ROOT=%%~fI"
set "RUN_MODE=%~1"
set "ACTION=%~2"
set "APP_ARGS="

if /I "%ACTION%"=="settings" set "APP_ARGS=--settings"
if /I "%ACTION%"=="install" set "APP_ARGS=--install-autostart"
if /I "%ACTION%"=="remove" set "APP_ARGS=--remove-autostart"

if defined KIRO_IP_GUARD_EXE (
    set "APP=%KIRO_IP_GUARD_EXE%"
    goto run_exe
)
if exist "%ROOT%\dist\KiroIPGuard.exe" (
    set "APP=%ROOT%\dist\KiroIPGuard.exe"
    goto run_exe
)
if exist "%ROOT%\dist\KiroIPGuard\KiroIPGuard.exe" (
    set "APP=%ROOT%\dist\KiroIPGuard\KiroIPGuard.exe"
    goto run_exe
)
goto run_source

:run_exe
if not exist "%APP%" (
    echo [ERROR] Executable not found: %APP%
    exit /b 2
)
if /I "%RUN_MODE%"=="background" (
    start "" "%APP%" %APP_ARGS%
    exit /b 0
)
"%APP%" %APP_ARGS%
exit /b %ERRORLEVEL%

:run_source
if /I "%RUN_MODE%"=="background" (
    set "PYTHON=%ROOT%\.venv\Scripts\pythonw.exe"
) else (
    set "PYTHON=%ROOT%\.venv\Scripts\python.exe"
)
if not exist "%PYTHON%" (
    echo [ERROR] Virtual environment not found. Run: py -m venv .venv
    echo [ERROR] Then run: .venv\Scripts\python -m pip install -r requirements.txt
    exit /b 2
)
cd /d "%ROOT%"
if /I "%RUN_MODE%"=="background" (
    start "" "%PYTHON%" -m ip_guard %APP_ARGS%
    exit /b 0
)
"%PYTHON%" -m ip_guard %APP_ARGS%
exit /b %ERRORLEVEL%
