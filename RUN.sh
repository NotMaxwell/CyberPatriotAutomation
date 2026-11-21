#!/usr/bin/env bash
# =============================================================================
#  PinnacleCyPat - Linux launcher (the counterpart of RUN.bat)
#  Copyright 2026 Maxwell McCormick
#  SPDX-License-Identifier: Apache-2.0
#
#  Usage:  ./RUN.sh            opens the web interface in your browser
#          ./RUN.sh --all -d   any arguments go straight to the tool
#
#  Like RUN.bat it only checks what the tool cannot check for itself - that it
#  is privileged and that there is a binary to run - and then hands over.
# =============================================================================
set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
args=("$@")
# The web UI, served on 127.0.0.1 only and opened in the invoking user's
# browser; the tool picks that user from SUDO_USER, which sudo sets below.
[ ${#args[@]} -eq 0 ] && args=(--web)

find_binary() {
    local candidate
    for candidate in \
        "$here/publish-linux-x64/pinnacle-cypat" \
        "$here/rust/target/x86_64-unknown-linux-musl/release/pinnacle-cypat" \
        "$here/rust/target/release/pinnacle-cypat"; do
        if [ -f "$candidate" ]; then
            # A binary copied off a zip or a USB stick usually arrives without
            # its executable bit, and the shell's "Permission denied" does not
            # say that is why.
            [ -x "$candidate" ] || chmod +x "$candidate" 2>/dev/null || true
            echo "$candidate"
            return 0
        fi
    done
    return 1
}

echo
echo " ========================================================"
echo "  PinnacleCyPat"
echo "  By Maxwell McCormick"
echo " ========================================================"
echo

binary="$(find_binary || true)"

# Build before escalating: cargo lives in the invoking user's ~/.cargo, which
# root's PATH does not include, and a build as root would leave root-owned files
# in rust/target for the user to trip over later.
if [ -z "$binary" ]; then
    if [ "$(id -u)" -ne 0 ] && command -v cargo >/dev/null 2>&1; then
        echo " [+] No build found; Rust is installed - building (first run takes a minute)"
        cargo build --release --manifest-path "$here/rust/Cargo.toml" -p pinnacle-cypat
        binary="$(find_binary)"
    else
        echo " [!] No build found."
        echo " [!] Copy the published pinnacle-cypat binary into:"
        echo "        $here/publish-linux-x64/"
        echo " [!] or install Rust from https://rustup.rs and re-run this script as your own user."
        exit 1
    fi
fi

if [ "$(id -u)" -ne 0 ]; then
    if ! command -v sudo >/dev/null 2>&1; then
        echo " [!] This tool must run as root, and sudo is not installed. Re-run as root."
        exit 1
    fi
    echo " [+] Root is required - asking sudo"
    # sudo sets SUDO_USER, which README discovery uses to find the competitor's
    # Desktop rather than /root/Desktop.
    exec sudo -- "$binary" "${args[@]}"
fi

echo " [+] Running as root"
echo
exec "$binary" "${args[@]}"
