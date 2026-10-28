@echo off
setlocal
for %%I in ("%~dp0\..\..") do set "ROOT=%%~fI"

cd /d "%ROOT%"
rem In GitHub Actions, use the exact interpreter installed by actions/setup-python.
set "BUILD_PYTHON=python"
if defined PythonLocation set "BUILD_PYTHON=%PythonLocation%\python.exe"
if not exist ".venv\Scripts\python.exe" "%BUILD_PYTHON%" -m venv .venv
if %ERRORLEVEL% NEQ 0 exit /b %ERRORLEVEL%
.venv\Scripts\python -m pip install --disable-pip-version-check -r requirements-build.txt
if %ERRORLEVEL% NEQ 0 exit /b %ERRORLEVEL%
.venv\Scripts\python -m PyInstaller --noconfirm --clean --onefile --windowed --name KiroIPGuard --icon "assets\kiro-ip-guard.ico" --add-data "assets;assets" --collect-all pystray --collect-data certifi run_guard.py
if %ERRORLEVEL% NEQ 0 exit /b %ERRORLEVEL%
echo Build completed in: %ROOT%\dist
exit /b 0
