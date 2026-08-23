// =============================================================================
// PinnacleCyPat - Proved systemd operations
// Author: Maxwell McCormick
// Copyright 2026 Maxwell McCormick
// SPDX-License-Identifier: Apache-2.0
// =============================================================================

//! What `service_ops` is on Windows, for systemd.
//!
//! `systemctl` is the whole interface - there is no library binding worth
//! taking, and unlike `net` and `sc` its query subcommands answer in stable,
//! unlocalised tokens (`active`, `enabled`, `masked`) that are documented as
//! machine-readable. So the parsing problem that forced the Win32 path on
//! Windows does not arise here.
//!
//! Disabling is done as stop, disable, *and mask*. Disable alone is not enough:
//! socket activation and a `Wants=` from another unit will both start a
//! disabled service again, and the audit that follows would then find it
//! running with no explanation. Masking points the unit at `/dev/null`, which
//! nothing can override.

use pinnacle_core::command;
use pinnacle_core::remediation;
use std::time::Duration;

/// systemd waits on jobs, and a unit with a slow `ExecStop` can sit there.
const TIMEOUT: Duration = Duration::from_secs(60);

async fn systemctl(args: &str) -> (bool, String) {
    let (ok, out, _err) = command::execute_with_timeout("systemctl", Some(args), TIMEOUT).await;
    (ok, out.trim().to_string())
}

/// Does systemd know this unit at all?
///
/// Asked before acting so that "not installed" is reported as itself rather
/// than as a failed disable. A competition image will not have most of the
/// services on any prohibited list, and reporting fifteen failures for services
/// that were never there buries the one that matters.
pub async fn exists(unit: &str) -> bool {
    let (_ok, out, _err) = command::execute(
        "systemctl",
        Some(&format!("list-unit-files --no-legend --no-pager {unit}")),
    )
    .await;
    !out.trim().is_empty()
}

/// `enabled`, `disabled`, `masked`, `static`, ... or `None` if it could not be
/// asked.
///
/// `systemctl is-enabled` exits non-zero for a disabled unit, which is an
/// answer rather than an error - so the exit code is deliberately ignored and
/// the printed token used instead. Treating the exit code as failure is what
/// made an earlier version report every already-disabled service as unreadable.
pub async fn enablement(unit: &str) -> Option<String> {
    let (_ok, out) = systemctl(&format!("is-enabled {unit}")).await;
    // A unit systemd has never heard of prints nothing at all.
    (!out.is_empty()).then_some(out)
}

/// `active`, `inactive`, `failed`, ... or `None` if it could not be asked.
pub async fn activity(unit: &str) -> Option<String> {
    let (_ok, out) = systemctl(&format!("is-active {unit}")).await;
    (!out.is_empty()).then_some(out)
}

/// Is the unit running right now?
pub async fn is_active(unit: &str) -> bool {
    activity(unit).await.as_deref() == Some("active")
}

/// Stop, disable and mask a unit, and prove it.
///
/// The evidence read back is the enablement state, because that is what decides
/// whether the service comes back on the next boot - which is what a scored
/// check looks at.
pub async fn disable(unit: &str, why: &str) -> Result<(), String> {
    remediation::apply(
        &format!("systemd unit {unit}"),
        &format!("masked so it cannot start ({why})"),
        || async { enablement(unit).await },
        |state| state == "masked",
        "stopped, disabled and masked the unit",
        || async {
            // Order matters: mask first and systemd refuses to stop a unit it
            // has just pointed at /dev/null, leaving it running.
            let _ = systemctl(&format!("stop {unit}")).await;
            let _ = systemctl(&format!("disable {unit}")).await;
            let (ok, out) = systemctl(&format!("mask {unit}")).await;
            if ok {
                Ok(())
            } else {
                Err(if out.is_empty() {
                    format!("systemctl mask {unit} failed")
                } else {
                    out
                })
            }
        },
    )
    .await
}

/// Unmask, enable and start a unit, and prove it.
pub async fn enable(unit: &str, why: &str) -> Result<(), String> {
    remediation::apply(
        &format!("systemd unit {unit}"),
        &format!("enabled and running ({why})"),
        || async {
            let enabled = enablement(unit).await?;
            let active = activity(unit).await.unwrap_or_else(|| "unknown".into());
            Some(format!("{enabled}, {active}"))
        },
        |state| state.starts_with("enabled") && state.ends_with("active"),
        "unmasked, enabled and started the unit",
        || async {
            let _ = systemctl(&format!("unmask {unit}")).await;
            let (enabled_ok, enable_out) = systemctl(&format!("enable {unit}")).await;
            let (start_ok, start_out) = systemctl(&format!("start {unit}")).await;
            if enabled_ok && start_ok {
                Ok(())
            } else if !enabled_ok {
                Err(enable_out)
            } else {
                Err(start_out)
            }
        },
    )
    .await
}

/// Every unit systemd has a unit file for, as `(name, state)`.
pub async fn unit_files(kind: &str) -> Vec<(String, String)> {
    let (_ok, out, _err) = command::execute(
        "systemctl",
        Some(&format!(
            "list-unit-files --type={kind} --no-legend --no-pager --plain"
        )),
    )
    .await;
    parse_unit_files(&out)
}

/// Split `list-unit-files` output into `(unit, state)` pairs.
///
/// Separated from the command so it can be tested without systemd - which is
/// also what lets the parser be exercised on a machine that does not run it.
pub fn parse_unit_files(output: &str) -> Vec<(String, String)> {
    output
        .lines()
        .filter_map(|line| {
            let mut parts = line.split_whitespace();
            let unit = parts.next()?;
            let state = parts.next()?;
            // Newer systemd adds a third "preset" column; older has two. Taking
            // the first two positionally works for both.
            unit.contains('.')
                .then(|| (unit.to_string(), state.to_string()))
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unit_files_are_parsed_from_the_first_two_columns() {
        // Real `systemctl list-unit-files --no-legend --plain` output, from
        // both the two-column and the three-column era.
        let output = "\
ssh.service                    enabled         enabled
telnet.socket                  masked
cups.service                   disabled        enabled
";
        assert_eq!(
            parse_unit_files(output),
            vec![
                ("ssh.service".to_string(), "enabled".to_string()),
                ("telnet.socket".to_string(), "masked".to_string()),
                ("cups.service".to_string(), "disabled".to_string()),
            ]
        );
    }

    /// The legend and the trailing summary line are not units. `--no-legend`
    /// removes them, but an older systemd prints the count anyway.
    #[test]
    fn a_summary_line_is_not_mistaken_for_a_unit() {
        assert!(parse_unit_files("3 unit files listed.\n").is_empty());
        assert!(parse_unit_files("").is_empty());
    }
}
