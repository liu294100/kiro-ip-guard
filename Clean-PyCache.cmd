@echo off
setlocal
for %%I in ("%~dp0.") do set "ROOT=%%~fI"

powershell -NoProfile -ExecutionPolicy Bypass -Command "$directories = Get-ChildItem -LiteralPath '%ROOT%' -Directory -Recurse -Force | Where-Object { $_.Name -eq '__pycache__' -and $_.FullName -notlike '%ROOT%\.venv\*' }; if ($directories) { $directories | ForEach-Object { Write-Host ('Removing ' + $_.FullName); Remove-Item -LiteralPath $_.FullName -Recurse -Force }; Write-Host ('Removed ' + @($directories).Count + ' __pycache__ director' + $(if (@($directories).Count -eq 1) { 'y.' } else { 'ies.' })) } else { Write-Host 'No __pycache__ directories found.' }"
if errorlevel 1 (
    echo Cleanup failed.
    exit /b 1
)

echo Cleanup completed.
exit /b 0
