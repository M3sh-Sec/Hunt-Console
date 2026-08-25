@echo off
REM Hunt Console -- Windows installer launcher
REM
REM Double-click this file to install. It launches install-windows.ps1
REM with the execution policy bypassed for THIS RUN ONLY -- nothing is
REM changed system-wide or persisted. This exists because Windows blocks
REM .ps1 scripts from running by default (Restricted execution policy on
REM most machines), which is the single most common reason a PowerShell
REM installer silently "does nothing" when double-clicked directly.
REM
REM Requires install-windows.ps1 to be in the same folder as this file.

setlocal
set SCRIPT_DIR=%~dp0
set PS1_PATH=%SCRIPT_DIR%install-windows.ps1

if not exist "%PS1_PATH%" (
    echo ERROR: install-windows.ps1 not found next to this file.
    echo Expected it at: %PS1_PATH%
    echo Keep install-windows.cmd and install-windows.ps1 in the same folder.
    pause
    exit /b 1
)

powershell -NoProfile -ExecutionPolicy Bypass -File "%PS1_PATH%" %*
set EXIT_CODE=%ERRORLEVEL%

echo.
if %EXIT_CODE% NEQ 0 (
    echo Installation did not complete successfully ^(exit code %EXIT_CODE%^).
) else (
    echo Done.
)
pause
exit /b %EXIT_CODE%
