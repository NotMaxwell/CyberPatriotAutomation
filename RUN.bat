@echo off
:: ============================================================
::  CyberPatriot Automation Tool - Easy Run Script
::  Author: Maxwell McCormick
::
::  Just double-click this file to run the tool!
:: ============================================================

title CyberPatriot Automation Tool
color 0A
cls

echo.
echo  ========================================================
echo   CyberPatriot Automation Tool
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
echo.

:: Check if .NET is installed
dotnet --version >nul 2>&1
if %errorLevel% neq 0 (
    echo  [!] .NET SDK is not installed!
    echo  [!] Please install .NET 9.0 SDK from:
    echo      https://dotnet.microsoft.com/download/dotnet/9.0
    echo.
    pause
    exit /b 1
)

echo  [+] .NET SDK found
echo.

:: Navigate to the src directory
cd /d "%~dp0src"

echo  Choose an option:
echo.
echo   [1] Run ALL security tasks (recommended)
echo   [2] Run with README file (auto-find)
echo   [3] Preview changes only (dry run)
echo   [4] Run specific task
echo   [5] Build and test
echo   [Q] Quit
echo.

set /p choice="Enter your choice: "

if /i "%choice%"=="1" goto run_all
if /i "%choice%"=="2" goto run_readme
if /i "%choice%"=="3" goto dry_run
if /i "%choice%"=="4" goto specific_task
if /i "%choice%"=="5" goto build_test
if /i "%choice%"=="Q" goto quit

echo Invalid choice. Please try again.
pause
goto :eof

:run_all
echo.
echo  [*] Running ALL security tasks...
echo.
dotnet run -- --all --no-interactive
goto done

:run_readme
echo.
echo  [*] Auto-finding README and running all tasks...
echo.
dotnet run -- --auto-readme --all
goto done

:dry_run
echo.
echo  [*] Running in preview mode (no changes will be made)...
echo.
dotnet run -- --all --dry-run
goto done

:specific_task
echo.
echo  Select a task to run:
echo.
echo   [1] Password Policy
echo   [2] Account Permissions
echo   [3] User Management (needs README)
echo   [4] Service Management
echo   [5] Audit Policy
echo   [6] Firewall Configuration
echo   [7] Security Hardening
echo   [8] Media Scanner
echo.
set /p task="Enter task number: "

if "%task%"=="1" dotnet run -- --password-policy
if "%task%"=="2" dotnet run -- --account-permissions
if "%task%"=="3" dotnet run -- --auto-readme --user-management
if "%task%"=="4" dotnet run -- --service-management
if "%task%"=="5" dotnet run -- --audit-policy
if "%task%"=="6" dotnet run -- --firewall
if "%task%"=="7" dotnet run -- --security-hardening
if "%task%"=="8" dotnet run -- --media-scan
goto done

:build_test
echo.
echo  [*] Building and running tests...
echo.
cd /d "%~dp0"
dotnet build
dotnet test
goto done

:quit
echo.
echo  Goodbye!
exit /b 0

:done
echo.
echo  ========================================================
echo   Task Complete!
echo  ========================================================
echo.
pause
