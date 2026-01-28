# ============================================================
#  CyberPatriot Automation Tool - Easy Run Script (PowerShell)
#  Author: Maxwell McCormick
#
#  Right-click and "Run with PowerShell" to use!
# ============================================================

# Set console encoding
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8
$Host.UI.RawUI.WindowTitle = "CyberPatriot Automation Tool"

# Colors
function Write-Header {
    Write-Host ""
    Write-Host "  ========================================================" -ForegroundColor Cyan
    Write-Host "   CyberPatriot Automation Tool" -ForegroundColor Cyan
    Write-Host "   By Maxwell McCormick" -ForegroundColor Gray
    Write-Host "  ========================================================" -ForegroundColor Cyan
    Write-Host ""
}

function Write-Success($message) {
    Write-Host "  [+] $message" -ForegroundColor Green
}

function Write-Error($message) {
    Write-Host "  [!] $message" -ForegroundColor Red
}

function Write-Info($message) {
    Write-Host "  [*] $message" -ForegroundColor Yellow
}

# Check admin
function Test-Admin {
    $currentUser = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($currentUser)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

# Main
Clear-Host
Write-Header

if (-not (Test-Admin)) {
    Write-Error "This tool requires Administrator privileges!"
    Write-Error "Please right-click and select 'Run as administrator'"
    Write-Host ""
    Read-Host "Press Enter to exit"
    exit 1
}

Write-Success "Running with Administrator privileges"

# Check .NET
try {
    $dotnetVersion = dotnet --version 2>$null
    if ($LASTEXITCODE -ne 0) { throw }
    Write-Success ".NET SDK found: $dotnetVersion"
} catch {
    Write-Error ".NET SDK is not installed!"
    Write-Error "Please install .NET 9.0 SDK from:"
    Write-Host "       https://dotnet.microsoft.com/download/dotnet/9.0" -ForegroundColor White
    Write-Host ""
    Read-Host "Press Enter to exit"
    exit 1
}

Write-Host ""

# Menu
function Show-Menu {
    Write-Host "  Choose an option:" -ForegroundColor White
    Write-Host ""
    Write-Host "   [1] Run ALL security tasks (recommended)" -ForegroundColor Yellow
    Write-Host "   [2] Run with README file (auto-find)" -ForegroundColor Yellow
    Write-Host "   [3] Preview changes only (dry run)" -ForegroundColor Yellow
    Write-Host "   [4] Run specific task" -ForegroundColor Yellow
    Write-Host "   [5] Parse README only" -ForegroundColor Yellow
    Write-Host "   [6] Build and test" -ForegroundColor Yellow
    Write-Host "   [Q] Quit" -ForegroundColor Gray
    Write-Host ""
}

function Show-TaskMenu {
    Write-Host ""
    Write-Host "  Select a task to run:" -ForegroundColor White
    Write-Host ""
    Write-Host "   [1] Password Policy" -ForegroundColor Yellow
    Write-Host "   [2] Account Permissions" -ForegroundColor Yellow
    Write-Host "   [3] User Management (needs README)" -ForegroundColor Yellow
    Write-Host "   [4] Service Management" -ForegroundColor Yellow
    Write-Host "   [5] Audit Policy" -ForegroundColor Yellow
    Write-Host "   [6] Firewall Configuration" -ForegroundColor Yellow
    Write-Host "   [7] Security Hardening" -ForegroundColor Yellow
    Write-Host "   [8] Media Scanner" -ForegroundColor Yellow
    Write-Host "   [B] Back to main menu" -ForegroundColor Gray
    Write-Host ""
}

# Navigate to src
$scriptPath = Split-Path -Parent $MyInvocation.MyCommand.Path
$srcPath = Join-Path $scriptPath "src"

Show-Menu
$choice = Read-Host "  Enter your choice"

switch ($choice.ToUpper()) {
    "1" {
        Write-Info "Running ALL security tasks..."
        Set-Location $srcPath
        dotnet run -- --all --no-interactive
    }
    "2" {
        Write-Info "Auto-finding README and running all tasks..."
        Set-Location $srcPath
        dotnet run -- --auto-readme --all
    }
    "3" {
        Write-Info "Running in preview mode (no changes will be made)..."
        Set-Location $srcPath
        dotnet run -- --all --dry-run
    }
    "4" {
        Show-TaskMenu
        $task = Read-Host "  Enter task number"
        Set-Location $srcPath
        switch ($task) {
            "1" { dotnet run -- --password-policy }
            "2" { dotnet run -- --account-permissions }
            "3" { dotnet run -- --auto-readme --user-management }
            "4" { dotnet run -- --service-management }
            "5" { dotnet run -- --audit-policy }
            "6" { dotnet run -- --firewall }
            "7" { dotnet run -- --security-hardening }
            "8" { dotnet run -- --media-scan }
            "B" { return }
            default { Write-Error "Invalid choice" }
        }
    }
    "5" {
        Write-Info "Parsing README file..."
        Set-Location $srcPath
        dotnet run -- --auto-readme --parse-readme
    }
    "6" {
        Write-Info "Building and running tests..."
        Set-Location $scriptPath
        dotnet build
        dotnet test -v n
    }
    "Q" {
        Write-Host ""
        Write-Host "  Goodbye!" -ForegroundColor Cyan
        exit 0
    }
    default {
        Write-Error "Invalid choice"
    }
}

Write-Host ""
Write-Host "  ========================================================" -ForegroundColor Cyan
Write-Host "   Task Complete!" -ForegroundColor Green
Write-Host "  ========================================================" -ForegroundColor Cyan
Write-Host ""
Read-Host "Press Enter to exit"
