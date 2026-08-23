#!/usr/bin/env bash
# =============================================================================
#  PinnacleCyPat - build, lint and test
#
#  Everything CI runs, in the order that fails fastest. The Windows type-check
#  is not optional: a Linux build never compiles the #[cfg(windows)] branches,
#  which is the whole of src/native plus several call sites, so a clean
#  `cargo test` here proves nothing about them.
# =============================================================================
set -euo pipefail

cd "$(dirname "$0")/../rust"

echo "==> fmt"
cargo fmt --check

echo "==> clippy (host)"
cargo clippy --all-targets -- -D warnings

echo "==> test"
cargo test

echo "==> clippy (windows target, type-checks the #[cfg(windows)] paths)"
if rustup target list --installed | grep -q x86_64-pc-windows-gnu; then
    cargo clippy --target x86_64-pc-windows-gnu --all-targets -- -D warnings
else
    echo "    skipped: rustup target add x86_64-pc-windows-gnu"
fi

echo
echo "All checks passed."
