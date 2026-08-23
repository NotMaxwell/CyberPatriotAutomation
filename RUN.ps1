# ============================================================
#  PinnacleCyPat - Easy Run Script (PowerShell)
#  Author: Maxwell McCormick
#
#  Right-click and "Run with PowerShell" to use!
#
#  The menu this used to duplicate now lives inside the tool
#  itself (--tui), so this script only checks the two things the
#  tool cannot check for itself - that it is elevated, and that
#  there is something to run it with - and then hands over.
#  Keeping the task list in one place is what stops the script
#  from offering a task the tool no longer has.
# ============================================================

[Console]::OutputEncoding = [System.Text.Encoding]::UTF8
$Host.UI.RawUI.WindowTitle = "PinnacleCyPat"

function Write-Header {
    Write-Host ""
    Write-Host "  ========================================================" -ForegroundColor Cyan
    Write-Host "   PinnacleCyPat" -ForegroundColor Cyan
    Write-Host "   By Maxwell McCormick" -ForegroundColor Gray
    Write-Host "  ========================================================" -ForegroundColor Cyan
    Write-Host ""
}

function Write-Success($message) { Write-Host "  [+] $message" -ForegroundColor Green }
function Write-Failure($message) { Write-Host "  [!] $message" -ForegroundColor Red }

function Test-Admin {
    $currentUser = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($currentUser)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

Clear-Host
Write-Header

if (-not (Test-Admin)) {
    Write-Failure "This tool requires Administrator privileges!"
    Write-Failure "Please right-click and select 'Run as administrator'"
    Write-Host ""
    Read-Host "Press Enter to exit"
    exit 1
}

Write-Success "Running with Administrator privileges"

$scriptPath = Split-Path -Parent $MyInvocation.MyCommand.Path
$published = Join-Path $scriptPath "publish-win-x64\PinnacleCyPat.exe"

# A published build needs no SDK. Prefer it when it is there.
if (Test-Path $published) {
    Write-Success "Using the published build"
    Write-Host ""
    & $published --tui
}
else {
    try {
        $dotnetVersion = dotnet --version 2>$null
        if ($LASTEXITCODE -ne 0) { throw }
        Write-Success ".NET SDK found: $dotnetVersion"
    }
    catch {
        Write-Failure "No published build found, and the .NET SDK is not installed."
        Write-Failure "Install the .NET 10.0 SDK from:"
        Write-Host "       https://dotnet.microsoft.com/download/dotnet/10.0" -ForegroundColor White
        Write-Host ""
        Read-Host "Press Enter to exit"
        exit 1
    }

    Write-Host ""
    Set-Location (Join-Path $scriptPath "src")
    dotnet run -f net10.0-windows -- --tui
}

Write-Host ""
Write-Host "  ========================================================" -ForegroundColor Cyan
Write-Host "   Task Complete!" -ForegroundColor Green
Write-Host "  ========================================================" -ForegroundColor Cyan
Write-Host ""
Read-Host "Press Enter to exit"
