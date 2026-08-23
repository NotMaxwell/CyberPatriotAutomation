// =============================================================================
// PinnacleCyPat - Package management via apt/dpkg
// Author: Maxwell McCormick
// Copyright 2026 Maxwell McCormick
// SPDX-License-Identifier: Apache-2.0
// =============================================================================

//! What `chocolatey` is on Windows, for Debian and Ubuntu.
//!
//! Three details decide whether this works unattended, and all three have a
//! counterpart in the Chocolatey module:
//!
//! - **`DEBIAN_FRONTEND=noninteractive`.** Without it `apt-get` opens a
//!   full-screen dialog the moment a package ships a modified conffile or a
//!   service needs restarting. With no console to answer it, the run hangs
//!   until the timeout kills it part-way through an install.
//! - **`--force-confold`.** When a package's configuration file has been
//!   changed - which, on a hardened image, is most of them - dpkg asks whose
//!   version to keep. Answering "keep the local one" is what stops an upgrade
//!   silently reverting the hardening this tool just applied.
//! - **A long timeout.** An upgrade can pull hundreds of megabytes. The default
//!   two-minute ceiling would kill it mid-download and leave dpkg needing
//!   `--configure -a`.
//!
//! Queries go to `dpkg-query` rather than `apt list`, whose output format is
//! explicitly documented as unstable and not for scripts.

use pinnacle_core::command;
use pinnacle_core::remediation;
use std::time::Duration;

/// Long enough for a full `dist-upgrade` on a slow competition network.
pub const PACKAGE_TIMEOUT: Duration = Duration::from_secs(1800);

/// The environment every apt invocation needs.
const NONINTERACTIVE: &[(&str, &str)] = &[
    ("DEBIAN_FRONTEND", "noninteractive"),
    // Belt and braces: some maintainer scripts consult this instead.
    ("DEBIAN_PRIORITY", "critical"),
    // A predictable, unlocalised error message when something does fail.
    ("LC_ALL", "C"),
];

/// The switches that make dpkg keep local configuration during an upgrade.
const KEEP_LOCAL_CONFIG: &str =
    "-o Dpkg::Options::=--force-confdef -o Dpkg::Options::=--force-confold";

async fn apt(args: &str) -> (bool, String, Option<String>) {
    let (code, out, err) = command::execute_for_exit_code_with_env(
        "apt-get",
        Some(&format!("-y -q {KEEP_LOCAL_CONFIG} {args}")),
        NONINTERACTIVE,
        PACKAGE_TIMEOUT,
    )
    .await;
    (code == Some(0), out, err)
}

/// Is `apt-get` present? A non-Debian image has none of this.
pub async fn is_available() -> bool {
    let (ok, _o, _e) = command::execute("apt-get", Some("--version")).await;
    ok
}

/// Is this package installed?
///
/// `dpkg-query` exits non-zero for a package it has never heard of, and prints
/// `deinstall ok config-files` for one that was removed but whose
/// configuration remains. Only `install ok installed` means installed - the
/// looser check reports a purged package as present and skips the install.
pub async fn is_installed(package: &str) -> bool {
    installation_state(package).await.as_deref() == Some("installed")
}

/// `installed`, `config-files remain`, or `absent`.
pub async fn installation_state(package: &str) -> Option<String> {
    let (_ok, out, _e) = command::execute(
        "dpkg-query",
        Some(&format!("-W -f=${{db:Status-Status}} {package}")),
    )
    .await;
    Some(match out.trim() {
        "installed" => "installed".to_string(),
        "config-files" => "config-files remain".to_string(),
        // dpkg-query prints nothing and exits 1 for an unknown package.
        _ => "absent".to_string(),
    })
}

/// Every installed package, as `(name, version)`.
pub async fn installed() -> Vec<(String, String)> {
    let (_ok, out, _e) = command::execute(
        "dpkg-query",
        Some("-W -f=${db:Status-Status}\\t${binary:Package}\\t${Version}\\n"),
    )
    .await;
    parse_installed(&out)
}

/// Split `dpkg-query` output into installed packages only.
pub fn parse_installed(output: &str) -> Vec<(String, String)> {
    output
        .lines()
        .filter_map(|line| {
            let mut f = line.split('\t');
            let status = f.next()?;
            let name = f.next()?;
            let version = f.next().unwrap_or("");
            // Removed-but-not-purged packages are listed too, and counting them
            // as installed would report a package that is gone.
            (status.trim() == "installed").then(|| (name.to_string(), version.to_string()))
        })
        .collect()
}

/// Refresh the package lists.
///
/// Failure is not fatal and is deliberately not recorded as a remediation: an
/// image with no network cannot reach the mirrors, and a failed `update` there
/// is the expected outcome rather than a change that did not take.
pub async fn update_lists() -> bool {
    let (ok, _o, _e) = apt("update").await;
    ok
}

/// Install a package, and prove it.
pub async fn install(package: &str, why: &str) -> Result<(), String> {
    remediation::apply(
        &format!("package {package}"),
        &format!("installed ({why})"),
        || async { installation_state(package).await },
        |state| state == "installed",
        &format!("apt-get install {package}"),
        || async {
            let (ok, _o, e) = apt(&format!("install {package}")).await;
            if ok {
                Ok(())
            } else {
                Err(e.unwrap_or_else(|| format!("apt-get install {package} failed")))
            }
        },
    )
    .await
}

/// Remove a package and its configuration, and prove it.
///
/// `purge`, not `remove`: a removed package leaves its configuration and, for a
/// service, its unit file behind, so a later `install` restores the attacker's
/// settings intact. Purging is also what makes the state read back as `absent`
/// rather than `config-files remain`.
pub async fn purge(package: &str, why: &str) -> Result<(), String> {
    remediation::apply(
        &format!("package {package}"),
        &format!("removed ({why})"),
        || async { installation_state(package).await },
        |state| state == "absent",
        &format!("apt-get purge {package}"),
        || async {
            let (ok, _o, e) = apt(&format!("purge {package}")).await;
            if ok {
                Ok(())
            } else {
                Err(e.unwrap_or_else(|| format!("apt-get purge {package} failed")))
            }
        },
    )
    .await
}

/// Packages with a newer version available, as `(name, current, candidate)`.
pub async fn upgradable() -> Vec<(String, String, String)> {
    let (_code, out, _e) = command::execute_for_exit_code_with_env(
        "apt-get",
        Some("--just-print upgrade"),
        NONINTERACTIVE,
        PACKAGE_TIMEOUT,
    )
    .await;
    parse_simulated_upgrade(&out)
}

/// Read `apt-get --just-print upgrade` output.
///
/// Chosen over `apt list --upgradable` because apt prints a warning on every
/// invocation saying its own output has no stable interface. The `--just-print`
/// form is dpkg-level and has been stable for years:
///
/// ```text
/// Inst libc6 [2.35-0ubuntu3.1] (2.35-0ubuntu3.4 Ubuntu:22.04/jammy-updates [amd64])
/// ```
pub fn parse_simulated_upgrade(output: &str) -> Vec<(String, String, String)> {
    output
        .lines()
        .filter(|l| l.starts_with("Inst "))
        .filter_map(|line| {
            let rest = line.strip_prefix("Inst ")?;
            let (name, rest) = rest.split_once(' ')?;
            // The current version is in square brackets; a package being newly
            // installed as a dependency has none, and is not an upgrade.
            let current = rest
                .strip_prefix('[')
                .and_then(|r| r.split_once(']'))
                .map(|(v, _)| v.to_string())?;
            let candidate = rest
                .split_once('(')
                .and_then(|(_, r)| r.split_whitespace().next())
                .unwrap_or("")
                .to_string();
            Some((name.to_string(), current, candidate))
        })
        .collect()
}

/// Upgrade every package that has a newer version.
///
/// Reported as one operation rather than one per package. Splitting it up would
/// give better attribution but costs a full dependency resolution per package,
/// and apt is far better than this tool at ordering the work.
pub async fn upgrade_all() -> Result<(), String> {
    let (ok, _o, e) = apt("upgrade").await;
    if ok {
        Ok(())
    } else {
        Err(e.unwrap_or_else(|| "apt-get upgrade failed".to_string()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The distinction that matters: a package removed but not purged is still
    /// listed by dpkg. Treating it as installed would report a package that is
    /// gone, and skip reinstalling one that is required.
    #[test]
    fn only_fully_installed_packages_are_listed() {
        let output = "\
installed\tfirefox\t115.0
config-files\ttelnetd\t0.17-41
installed\tvim\t2:8.2.3995
not-installed\tnano\t
";
        assert_eq!(
            parse_installed(output),
            vec![
                ("firefox".to_string(), "115.0".to_string()),
                ("vim".to_string(), "2:8.2.3995".to_string()),
            ]
        );
    }

    /// Real `apt-get --just-print upgrade` output, including the two lines that
    /// are not upgrades: a `Conf` line and an `Inst` for a brand-new dependency
    /// with no current version.
    #[test]
    fn a_simulated_upgrade_yields_current_and_candidate_versions() {
        let output = "\
Reading package lists...
Inst libc6 [2.35-0ubuntu3.1] (2.35-0ubuntu3.4 Ubuntu:22.04/jammy-updates [amd64])
Inst libnew (1.0 Ubuntu:22.04/jammy [amd64])
Conf libc6 (2.35-0ubuntu3.4 Ubuntu:22.04/jammy-updates [amd64])
";
        assert_eq!(
            parse_simulated_upgrade(output),
            vec![(
                "libc6".to_string(),
                "2.35-0ubuntu3.1".to_string(),
                "2.35-0ubuntu3.4".to_string()
            )]
        );
    }

    #[test]
    fn no_output_means_nothing_to_upgrade() {
        assert!(parse_simulated_upgrade("Reading package lists...\n").is_empty());
        assert!(parse_installed("").is_empty());
    }

    /// The switches that stop an upgrade reverting the hardening applied
    /// earlier in the same run.
    #[test]
    fn upgrades_keep_locally_modified_configuration() {
        assert!(KEEP_LOCAL_CONFIG.contains("--force-confold"));
        assert!(KEEP_LOCAL_CONFIG.contains("--force-confdef"));
        assert!(NONINTERACTIVE.contains(&("DEBIAN_FRONTEND", "noninteractive")));
    }
}
