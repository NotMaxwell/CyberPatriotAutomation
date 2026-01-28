@echo off
REM Build and Test Script for CyberPatriot Automation Tool
REM Run this script to build the project and run all unit tests

chcp 65001 > nul
echo.
echo ======================================
echo Building CyberPatriot Automation Tool
echo ======================================

cd /d "%~dp0"

echo.
echo [1/3] Restoring packages...
dotnet restore --verbosity quiet

echo.
echo [2/3] Building solution...
dotnet build --configuration Release --verbosity minimal

echo.
echo [3/3] Running unit tests...
echo.
echo ======================================
echo Unit Test Results
echo ======================================
echo.
dotnet test Tests\CyberPatriotAutomation.Tests.csproj --configuration Release --no-build -v n

echo.
echo ======================================
echo Build and Test Complete
echo ======================================
pause
