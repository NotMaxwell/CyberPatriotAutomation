//! Stamps the build date into the binary as `CPA_BUILD_DATE`.
//!
//! The run log records the version it was produced by, but two builds of the
//! same version are common while iterating between releases. The compile date
//! tells those apart, so a log can always be tied to the binary that wrote it.

use std::time::{SystemTime, UNIX_EPOCH};

fn main() {
    // Re-run whenever the manifest changes so a version bump restamps the date.
    println!("cargo:rerun-if-changed=Cargo.toml");
    println!("cargo:rerun-if-changed=build.rs");

    let secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);

    println!("cargo:rustc-env=CPA_BUILD_DATE={}", format_date(secs));
}

/// Format a Unix timestamp as `YYYY-MM-DD` (UTC).
///
/// Done by hand rather than pulling `chrono` into the build graph: a build
/// script dependency is compiled for the host even when cross-compiling, and
/// this is the only date needed.
fn format_date(secs: u64) -> String {
    let days = (secs / 86_400) as i64;
    let (year, month, day) = civil_from_days(days);
    format!("{year:04}-{month:02}-{day:02}")
}

/// Convert days since 1970-01-01 into a calendar date.
///
/// Howard Hinnant's `civil_from_days` algorithm, which is exact for the whole
/// proleptic Gregorian range and needs no lookup tables.
fn civil_from_days(z: i64) -> (i64, u32, u32) {
    let z = z + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = (z - era * 146_097) as u64; // [0, 146096]
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365; // [0, 399]
    let y = yoe as i64 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100); // [0, 365]
    let mp = (5 * doy + 2) / 153; // [0, 11]
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32; // [1, 31]
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32; // [1, 12]
    (if m <= 2 { y + 1 } else { y }, m, d)
}
