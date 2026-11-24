@echo off
title NetSentry - Network Intelligence & Live Threat Monitoring System
color 0B

echo =====================================================================
echo                NetSentry - Live Threat Monitoring System
echo                          DEVELOPER: MOHSIN
echo =====================================================================
echo.

cd /d "%~dp0"

echo [1/3] Checking Python installation...
python --version >nul 2>&1
if %errorlevel% neq 0 (
    echo [ERROR] Python 3.11+ is not found in your PATH.
    echo Please install Python 3.11+ from https://www.python.org/
    pause
    exit /b 1
)

echo [2/3] Verifying and installing Python dependencies...
python -m pip install -r requirements.txt --quiet
if %errorlevel% neq 0 (
    echo [WARNING] Pip encountered a notice. Continuing startup...
)

echo [3/3] Starting NetSentry local server at http://127.0.0.1:8088 ...
echo Press Ctrl+C in this console window to stop the server.
echo.

python app.py

if %errorlevel% neq 0 (
    echo.
    echo [ERROR] NetSentry stopped unexpectedly.
    pause
)

