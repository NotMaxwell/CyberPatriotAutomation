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
::  that there is something to run - and then hands over.
::  Keeping the task list in one place is what stops the script
::  from offering a task the tool no longer has.
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

:: The shipping artefact. It is a single self-contained exe with no
:: runtime to install, which is the whole point of shipping it.
if exist "%~dp0publish-win-x64\pinnacle-cypat.exe" (
    echo  [+] Using the published build
    echo.
    "%~dp0publish-win-x64\pinnacle-cypat.exe" --tui
    goto done
)

:: A local release build, for anyone running from a clone.
if exist "%~dp0rust\target\release\pinnacle-cypat.exe" (
    echo  [+] Using the local release build
    echo.
    "%~dp0rust\target\release\pinnacle-cypat.exe" --tui
    goto done
)

:: Nothing built. Fall back to cargo if the toolchain is here.
cargo --version >nul 2>&1
if %errorLevel% neq 0 (
    echo  [!] No build found, and Rust is not installed.
    echo  [!] Either copy a published pinnacle-cypat.exe into:
    echo         %~dp0publish-win-x64\
    echo  [!] or install Rust from https://rustup.rs and re-run this script.
    echo.
    pause
    exit /b 1
)

echo  [+] Rust toolchain found - building (first run takes a minute)
echo.

cd /d "%~dp0rust"
cargo run --release -- --tui

:done
echo.
echo  ========================================================
echo   Task Complete!
echo  ========================================================
echo.
pause
