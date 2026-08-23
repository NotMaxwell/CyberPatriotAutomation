#!/usr/bin/env bash
# =============================================================================
#  PinnacleCyPat - build, lint and test
#
#  Everything CI runs, in the order that fails fastest. The Windows pass is not
#  optional: a Linux host builds pinnacle-core and pinnacle-linux, and checks
#  pinnacle-windows only against its non-Windows fallbacks - so a clean
#  `cargo test` here proves nothing about crates/windows/src/native or the
#  #[cfg(windows)] branches around it.
# =============================================================================
set -euo pipefail

cd "$(dirname "$0")/../rust"

echo "==> fmt"
cargo fmt --check

echo "==> clippy (host: core, linux, cli)"
cargo clippy --workspace --all-targets -- -D warnings

echo "==> test"
cargo test --workspace

echo "==> clippy (windows target, type-checks the #[cfg(windows)] paths)"
if rustup target list --installed | grep -q x86_64-pc-windows-gnu; then
    cargo clippy -p pinnacle-core -p pinnacle-windows -p pinnacle-cypat \
        --all-targets --target x86_64-pc-windows-gnu -- -D warnings
else
    echo "    skipped: rustup target add x86_64-pc-windows-gnu"
fi

echo
echo "All checks passed."
