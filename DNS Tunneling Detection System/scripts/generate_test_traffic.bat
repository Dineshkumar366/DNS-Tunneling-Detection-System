@echo off
title DNS Security - Synthetic Test Traffic
echo ================================================
echo DNS Security Synthetic Test Traffic
echo ================================================
echo.
echo This uses example.com only for safe lab testing.
echo.
for /L %%i in (1,1,30) do (
    nslookup x9k7m2p8q4s6d1.example.com >nul
)
echo.
echo Test traffic completed.
pause
