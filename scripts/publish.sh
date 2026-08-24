#!/usr/bin/env bash
# =============================================================================
#  PinnacleCyPat - produce the shipping binaries
#
#  Windows: cross-compiling from Linux needs the GNU target and the mingw
#  linker; the msvc target needs Microsoft's linker, which is not available
#  here.
#
#  Linux: musl, not glibc, and deliberately. A glibc build links against
#  whatever the *build* machine has, and a binary built on a current distribution
#  requires GLIBC_2.39 while Ubuntu 22.04 - the image a round actually runs on -
#  ships 2.35. It refuses to start, with an error naming a symbol version rather
#  than the problem. glibc cannot be upgraded past what an Ubuntu release ships
#  without breaking the system, so the fix has to be on this side.
#
#  musl links statically: no libc dependency at all, and the same binary runs on
#  any Linux from any era. It costs about 200 KB.
# =============================================================================
set -euo pipefail

root="$(cd "$(dirname "$0")/.." && pwd)"
cd "$root/rust"

build() {
    local target="$1" out_dir="$2" artifact="$3"
    if ! rustup target list --installed | grep -q "^$target"; then
        echo "   skipped: rustup target add $target" >&2
        return
    fi
    cargo build --release -p pinnacle-cypat --target "$target"
    mkdir -p "$root/$out_dir"
    cp "target/$target/release/$artifact" "$root/$out_dir/"
    printf -- '-> %s/%s   %s\n' "$out_dir" "$artifact" \
        "$(ls -lh "$root/$out_dir/$artifact" | awk '{print $5}')"
}

echo "==> Windows"
build x86_64-pc-windows-gnu publish-win-x64 pinnacle-cypat.exe

echo
echo "==> Linux"
build x86_64-unknown-linux-musl publish-linux-x64 pinnacle-cypat

# A glibc build would run only where its own glibc is new enough, and that
# failure appears on the competition image rather than here. Check it.
if [ -f "$root/publish-linux-x64/pinnacle-cypat" ]; then
    if readelf -V "$root/publish-linux-x64/pinnacle-cypat" 2>/dev/null | grep -q GLIBC; then
        echo "   ERROR: the Linux binary links against glibc and will not run on an older image." >&2
        exit 1
    fi
    echo "   statically linked; no libc requirement"
fi
