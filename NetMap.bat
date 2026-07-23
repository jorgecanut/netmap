@echo off
rem NetMap launcher - starts netmap.py with no console window.
rem Keep this file in the same folder as netmap.py.
cd /d "%~dp0"

where pythonw >nul 2>nul
if %errorlevel%==0 (
    start "" pythonw netmap.py
    exit /b
)

where pyw >nul 2>nul
if %errorlevel%==0 (
    start "" pyw netmap.py
    exit /b
)

rem Fallback: visible (minimized) console via regular python.
where python >nul 2>nul
if %errorlevel%==0 (
    start "NetMap" /min python netmap.py
    exit /b
)

echo Python was not found. Install it from python.org (check "Add to PATH").
pause
