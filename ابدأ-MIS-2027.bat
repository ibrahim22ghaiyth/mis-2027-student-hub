@echo off
chcp 65001 >nul
cd /d "%~dp0"
title MIS 2027 - Student Platform
set PORT=8127
set HOST=127.0.0.1

echo ======================================
echo   MIS 2027 - Student Platform
echo ======================================
echo.
echo Current local version: Modern Campus
echo Local address: http://127.0.0.1:%PORT%
echo.
start "" cmd /c "timeout /t 2 /nobreak >nul && start http://127.0.0.1:%PORT%/?v=20260923-modern-campus-2"
where py >nul 2>&1
if not errorlevel 1 (
  py -3 server.py
) else (
  python server.py
)
echo.
echo The server has stopped. Check that Python 3.10+ is installed.
pause
