@echo off
call "%~dp0_launch.cmd" wait remove
if %ERRORLEVEL% EQU 0 echo Kiro IP Guard autostart is disabled for the current user.
pause
