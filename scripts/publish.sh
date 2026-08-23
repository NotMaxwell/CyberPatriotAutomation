#!/usr/bin/env bash
# =============================================================================
#  PinnacleCyPat - produce the shipping Windows binary
#
#  Cross-compiling from Linux needs the GNU target and the mingw linker; the
#  msvc target needs Microsoft's linker, which is not available here.
# =============================================================================
set -euo pipefail

root="$(cd "$(dirname "$0")/.." && pwd)"
cd "$root/rust"

target=x86_64-pc-windows-gnu
if ! rustup target list --installed | grep -q "$target"; then
    echo "Missing target. Run: rustup target add $target" >&2
    exit 1
fi

cargo build --release --target "$target"

mkdir -p "$root/publish-win-x64"
cp "target/$target/release/pinnacle-cypat.exe" "$root/publish-win-x64/"

echo
echo "-> publish-win-x64/pinnacle-cypat.exe"
ls -lh "$root/publish-win-x64/pinnacle-cypat.exe" | awk '{print "   " $5}'
