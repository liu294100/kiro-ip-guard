@echo off
setlocal
for %%I in ("%~dp0.") do set "ROOT=%%~fI"
set "VERSION=%~1"

if not "%~2"=="" goto usage

cd /d "%ROOT%"
echo [1/2] Building Windows onefile package...
call "%ROOT%\scripts\windows\build.cmd"
if errorlevel 1 goto failed

echo [2/2] Creating release ZIP archive...
if defined VERSION (
    powershell -NoProfile -ExecutionPolicy Bypass -File "%ROOT%\scripts\windows\package-release.ps1" -Version "%VERSION%"
) else (
    powershell -NoProfile -ExecutionPolicy Bypass -File "%ROOT%\scripts\windows\package-release.ps1"
)
if errorlevel 1 goto failed

echo.
echo Release packaging completed: %ROOT%\release
exit /b 0

:usage
echo Usage: release.bat [version]
exit /b 2

:failed
set "EXIT_CODE=%ERRORLEVEL%"
echo.
echo Release packaging failed with exit code %EXIT_CODE%.
exit /b %EXIT_CODE%
