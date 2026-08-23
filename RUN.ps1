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
$published = Join-Path $scriptPath "publish-win-x64\pinnacle-cypat.exe"
$release   = Join-Path $scriptPath "rust\target\release\pinnacle-cypat.exe"

# The shipping artefact: one self-contained exe, no runtime to install.
if (Test-Path $published) {
    Write-Success "Using the published build"
    Write-Host ""
    & $published --tui
}
elseif (Test-Path $release) {
    Write-Success "Using the local release build"
    Write-Host ""
    & $release --tui
}
else {
    try {
        $cargoVersion = cargo --version 2>$null
        if ($LASTEXITCODE -ne 0) { throw }
        Write-Success "Rust toolchain found: $cargoVersion"
    }
    catch {
        Write-Failure "No build found, and Rust is not installed."
        Write-Failure "Either copy a published pinnacle-cypat.exe into:"
        Write-Host "       $(Join-Path $scriptPath 'publish-win-x64')" -ForegroundColor White
        Write-Failure "or install Rust and re-run this script:"
        Write-Host "       https://rustup.rs" -ForegroundColor White
        Write-Host ""
        Read-Host "Press Enter to exit"
        exit 1
    }

    Write-Host ""
    Write-Host "  Building (the first run takes a minute)..." -ForegroundColor Gray
    Set-Location (Join-Path $scriptPath "rust")
    cargo run --release -- --tui
}

Write-Host ""
Write-Host "  ========================================================" -ForegroundColor Cyan
Write-Host "   Task Complete!" -ForegroundColor Green
Write-Host "  ========================================================" -ForegroundColor Cyan
Write-Host ""
Read-Host "Press Enter to exit"
