@echo off
:: ============================================================
::  PinnacleCyPat - Easy Run Script
::  Author: Maxwell McCormick
::
::  Just double-click this file to run the tool!
::
::  The menu this used to duplicate now lives inside the tool
::  itself (--tui), so this script only checks the two things
::  the tool cannot check for itself - that it is elevated, and
::  that there is a .NET SDK to run it with - and then hands
::  over. Keeping the task list in one place is what stops the
::  script from offering a task the tool no longer has.
:: ============================================================

title PinnacleCyPat
color 0A
cls

echo.
echo  ========================================================
echo   PinnacleCyPat
echo   By Maxwell McCormick
echo  ========================================================
echo.

:: Check if running as admin
net session >nul 2>&1
if %errorLevel% neq 0 (
    echo  [!] This tool requires Administrator privileges!
    echo  [!] Please right-click and select "Run as administrator"
    echo.
    pause
    exit /b 1
)

echo  [+] Running with Administrator privileges

:: A published build needs no SDK. Prefer it when it is there.
if exist "%~dp0publish-win-x64\PinnacleCyPat.exe" (
    echo  [+] Using the published build
    echo.
    "%~dp0publish-win-x64\PinnacleCyPat.exe" --tui
    goto done
)

:: Check if .NET is installed
dotnet --version >nul 2>&1
if %errorLevel% neq 0 (
    echo  [!] No published build found, and the .NET SDK is not installed.
    echo  [!] Install the .NET 10.0 SDK from:
    echo      https://dotnet.microsoft.com/download/dotnet/10.0
    echo.
    pause
    exit /b 1
)

echo  [+] .NET SDK found
echo.

cd /d "%~dp0src"
dotnet run -f net10.0-windows -- --tui

:done
echo.
echo  ========================================================
echo   Task Complete!
echo  ========================================================
echo.
pause
