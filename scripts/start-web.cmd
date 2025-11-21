@echo off
setlocal
REM Simple wrapper to start the PowerShell launcher
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0start-web.ps1" %*
endlocal

