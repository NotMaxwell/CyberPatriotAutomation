# ============================================================
#  CyberPatriot Automation Tool - Code Formatter
#  Author: Maxwell McCormick
#
#  Formats all C# code using CSharpier (similar to Spotless)
# ============================================================

param(
    [switch]$Check,      # Only check, don't modify
    [switch]$Install     # Install CSharpier tool
)

$ErrorActionPreference = "Continue"

Write-Host ""
Write-Host "  ========================================================" -ForegroundColor Cyan
Write-Host "   Code Formatter - CyberPatriot Automation Tool" -ForegroundColor Cyan
Write-Host "   By Maxwell McCormick" -ForegroundColor Gray
Write-Host "  ========================================================" -ForegroundColor Cyan
Write-Host ""

# Navigate to project root
$projectRoot = Split-Path -Parent (Split-Path -Parent $MyInvocation.MyCommand.Path)
Set-Location $projectRoot

# Check/Install CSharpier
$csharpierInstalled = $null -ne (Get-Command dotnet-csharpier -ErrorAction SilentlyContinue)

if (-not $csharpierInstalled -or $Install) {
    Write-Host "  [*] Installing CSharpier formatter..." -ForegroundColor Yellow
    dotnet tool install -g csharpier
    Write-Host "  [+] CSharpier installed!" -ForegroundColor Green
    Write-Host ""
}

if ($Check) {
    Write-Host "  [*] Checking code format..." -ForegroundColor Yellow
    Write-Host ""

    dotnet csharpier --check .

    if ($LASTEXITCODE -eq 0) {
        Write-Host ""
        Write-Host "  [+] All files are properly formatted!" -ForegroundColor Green
    } else {
        Write-Host ""
        Write-Host "  [!] Some files need formatting. Run without -Check to fix." -ForegroundColor Red
    }
} else {
    Write-Host "  [*] Formatting all C# files..." -ForegroundColor Yellow
    Write-Host ""

    dotnet csharpier .

    Write-Host ""
    Write-Host "  [+] Formatting complete!" -ForegroundColor Green
}

Write-Host ""
