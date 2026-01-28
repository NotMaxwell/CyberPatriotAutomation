# CyberPatriot Automation - Test Runner
# This script runs all unit tests with detailed output showing each test name

$ErrorActionPreference = "Continue"

# Set console encoding to UTF-8
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8
$OutputEncoding = [System.Text.Encoding]::UTF8
chcp 65001 > $null

Write-Host ""
Write-Host "======================================" -ForegroundColor Cyan
Write-Host "  CyberPatriot Automation - Tests    " -ForegroundColor Cyan  
Write-Host "======================================" -ForegroundColor Cyan
Write-Host ""

# Change to script directory
Push-Location $PSScriptRoot

try {
    Write-Host "Running unit tests with detailed output..." -ForegroundColor Yellow
    Write-Host ""
    
    # Run tests with normal verbosity which shows all test names
    dotnet test Tests/CyberPatriotAutomation.Tests.csproj -v n
    
    $testExitCode = $LASTEXITCODE
    
    Write-Host ""
    
    if ($testExitCode -eq 0) {
        Write-Host "======================================" -ForegroundColor Green
        Write-Host "  All tests passed!                   " -ForegroundColor Green
        Write-Host "======================================" -ForegroundColor Green
    } else {
        Write-Host "======================================" -ForegroundColor Red
        Write-Host "  Some tests failed!                  " -ForegroundColor Red
        Write-Host "======================================" -ForegroundColor Red
    }
    
    exit $testExitCode
}
finally {
    Pop-Location
}
