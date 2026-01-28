@echo off
:: ============================================================
::  CyberPatriot Automation Tool - Code Formatter
::  Author: Maxwell McCormick
::
::  Formats all C# code using CSharpier (similar to Spotless)
:: ============================================================

echo.
echo  ========================================================
echo   Code Formatter - CyberPatriot Automation Tool
echo  ========================================================
echo.

cd /d "%~dp0"

:: Check if dotnet-csharpier is installed
where dotnet-csharpier >nul 2>&1
if %errorLevel% neq 0 (
    echo  [*] Installing CSharpier formatter...
    dotnet tool install -g csharpier
)

echo  [*] Formatting all C# files...
echo.

dotnet csharpier .

echo.
echo  [+] Formatting complete!
echo.
pause
