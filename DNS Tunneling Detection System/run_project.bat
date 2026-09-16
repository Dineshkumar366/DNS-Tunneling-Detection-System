@echo off
title DNS Tunneling and Malicious DNS Behaviour Detection System
cd /d "%~dp0"
echo ============================================================
echo DNS Tunneling and Malicious DNS Behaviour Detection System
echo ============================================================
echo.
echo Checking Python...
python --version
if errorlevel 1 (
    echo Python is not available in PATH.
    pause
    exit /b 1
)
echo.
echo Starting live DNS detector...
echo Keep this window open.
echo Open another CMD and run:
echo   scripts\generate_test_traffic.bat
echo.
python scripts\dns_detector.py
echo.
echo Detector stopped.
pause
