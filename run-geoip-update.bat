@echo off
rem ============================================================================
rem  run-geoip-update.bat  -  计划任务包装器
rem  由 install-task.ps1 注册，也可手动双击执行（需右键以管理员身份运行）
rem ============================================================================
setlocal
set "HERE=%~dp0"
if not exist "%HERE%logs" mkdir "%HERE%logs"

set "PS=%SystemRoot%\System32\WindowsPowerShell\v1.0\powershell.exe"
if not exist "%PS%" set "PS=powershell.exe"

"%PS%" -NoProfile -NonInteractive -ExecutionPolicy Bypass -File "%HERE%geoip-update.ps1" -ConfigPath "%HERE%geoip.config.json" %* >> "%HERE%logs\task.log" 2>&1

set "RC=%ERRORLEVEL%"
if not "%RC%"=="0" (
    echo [%DATE% %TIME%] FAILED with exit code %RC% >> "%HERE%logs\task.log"
)
endlocal & exit /b %RC%
