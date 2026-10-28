@echo off
call "%~dp0_launch.cmd" wait install
if %ERRORLEVEL% EQU 0 echo Kiro IP Guard autostart is enabled for the current user.
pause
