:: ============================================================
::  PinnacleCyPat - Easy Run Script
::  Author: Maxwell McCormick
::
::  Just double-click this file to run the tool!
::
::  It opens the desktop app, pinnacle-cypat-gui.exe, which walks
::  through the README, a dry run and the real run. The script only
::  checks the two things the app cannot check for itself - that it
::  is elevated, and that there is something to run - then hands over.
:: ============================================================
@echo off
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

:: The shipping artefact. A single self-contained exe with no runtime to
:: install, which is the whole point of shipping it.
if exist "%~dp0publish-win-x64\pinnacle-cypat-gui.exe" (
    echo  [+] Opening the published app
    start "" "%~dp0publish-win-x64\pinnacle-cypat-gui.exe"
    exit /b 0
)

:: A local release build, for anyone running from a clone.
if exist "%~dp0rust\target\release\pinnacle-cypat-gui.exe" (
    echo  [+] Opening the local release build
    start "" "%~dp0rust\target\release\pinnacle-cypat-gui.exe"
    exit /b 0
)

:: Nothing built. Fall back to cargo if the toolchain is here.
cargo --version >nul 2>&1
if %errorLevel% neq 0 (
    echo  [!] No build found, and Rust is not installed.
    echo  [!] Either copy a published pinnacle-cypat-gui.exe into:
    echo         %~dp0publish-win-x64\
    echo  [!] or install Rust from https://rustup.rs and re-run this script.
    echo.
    pause
    exit /b 1
)

echo  [+] Rust toolchain found - building (first run takes a few minutes)
echo.

cd /d "%~dp0rust"
cargo build --release -p pinnacle-cypat-gui
if %errorLevel% neq 0 (
    echo  [!] The build failed; see the output above.
    pause
    exit /b 1
)
start "" "%~dp0rust\target\release\pinnacle-cypat-gui.exe"
