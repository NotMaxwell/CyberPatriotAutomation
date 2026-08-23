# =============================================================================
#  PinnacleCyPat - build, lint and test
#
#  Everything CI runs, in the order that fails fastest.
# =============================================================================
$ErrorActionPreference = "Stop"

Set-Location (Join-Path (Split-Path -Parent $MyInvocation.MyCommand.Path) "..\rust")

Write-Host "==> fmt" -ForegroundColor Cyan
cargo fmt --check
if ($LASTEXITCODE -ne 0) { exit 1 }

Write-Host "==> clippy" -ForegroundColor Cyan
cargo clippy --all-targets -- -D warnings
if ($LASTEXITCODE -ne 0) { exit 1 }

Write-Host "==> test" -ForegroundColor Cyan
cargo test
if ($LASTEXITCODE -ne 0) { exit 1 }

Write-Host ""
Write-Host "All checks passed." -ForegroundColor Green
