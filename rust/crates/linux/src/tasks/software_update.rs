// =============================================================================
// PinnacleCyPat - Software updates (Linux)
// Copyright 2026 Maxwell McCormick
// SPDX-License-Identifier: Apache-2.0
// =============================================================================

//! Brings installed packages up to date, and turns on unattended security
//! updates.
//!
//! Reported as one operation rather than one per package. Splitting it up would
//! give better attribution, but it costs a full dependency resolution per
//! package and apt is far better than this tool at ordering the work - a
//! package-at-a-time upgrade routinely fails on dependencies that a single
//! `apt upgrade` resolves without comment.
//!
//! The upgrade runs with `--force-confold`, so a package that ships a newer
//! configuration file does not overwrite the hardening applied earlier in the
//! same run. Without it, upgrading `openssh-server` silently reverts
//! `sshd_config` - and the run reports both the hardening and the upgrade as
//! successes.

use pinnacle_core::models::{SystemInfo, TaskResult};
use pinnacle_core::task::Task;
use pinnacle_core::{impl_task_meta, models::ReadmeData, remediation, ui};

use crate::apt;
use crate::file_ops::{self, Style};
use crate::systemd_ops;
use async_trait::async_trait;

/// Turning this on is what keeps the machine patched after the round starts.
const UNATTENDED_UPGRADES: &str = "unattended-upgrades";

/// Where apt keeps the periodic-task settings.
///
/// A drop-in named `20auto-upgrades` because that is the file
/// `unattended-upgrades` itself installs and the one the Software & Updates
/// dialog writes; using the same name means the dialog and this tool agree
/// rather than leaving two files that disagree.
const PERIODIC_CONF: &str = "/etc/apt/apt.conf.d/20auto-upgrades";

/// The periodic settings, as `(key, value, why)`.
///
/// `APT::Periodic::Update-Package-Lists "1"` is what the Software & Updates
/// dialog sets when its *Automatically check for updates* dropdown is set to
/// **Daily**, and it is scored: the Ubuntu 22.04 Exhibition Round answer key
/// gives six points for it. The value is a number of days, so `1` is daily and
/// `0` is never - which is the stock setting on a competition image.
pub const PERIODIC_SETTINGS: &[(&str, &str, &str)] = &[
    (
        "APT::Periodic::Update-Package-Lists",
        "1",
        "check for updates every day",
    ),
    (
        "APT::Periodic::Unattended-Upgrade",
        "1",
        "install security updates every day",
    ),
    (
        "APT::Periodic::Download-Upgradeable-Packages",
        "1",
        "download them ahead of installing, so a slow link does not delay the fix",
    ),
    (
        "APT::Periodic::AutocleanInterval",
        "7",
        "clear the downloaded package cache weekly so the disk does not fill",
    ),
];

/// Update Manager's "Apply updates automatically" switch is two things, per
/// `usr/bin/mintupdate-automation` in github.com/linuxmint/mintupdate (what the
/// Preferences > Automation tab runs under pkexec): a flag file that
/// `system_automatic_upgrades.py` checks before doing anything, and the
/// `mintupdate-automation-upgrade.timer` unit being started and enabled. The
/// Preferences dialog shows the switch as on when the flag file exists.
pub const MINT_AUTOMATION_FLAG: &str = "/var/lib/linuxmint/mintupdate-automatic-upgrades-enabled";
pub const MINT_AUTOMATION_TIMER: &str = "mintupdate-automation-upgrade.timer";
/// The helper the dialog calls; it also installs the default blacklist and
/// enables the cleanup service, so running it matches clicking the switch.
const MINT_AUTOMATION_TOOL: &str = "/usr/bin/mintupdate-automation";
const MINT_ON: &str = "flag present, timer enabled";

/// Is this `/etc/os-release` Linux Mint?
pub fn is_linux_mint(os_release: &str) -> bool {
    os_release.lines().any(|line| {
        line.trim().strip_prefix("ID=").is_some_and(|v| {
            v.trim()
                .trim_matches(['"', '\''])
                .eq_ignore_ascii_case("linuxmint")
        })
    })
}

async fn on_linux_mint() -> bool {
    tokio::fs::read_to_string("/etc/os-release")
        .await
        .is_ok_and(|text| is_linux_mint(&text))
}

/// The state of the switch, as text.
fn mint_state(flag_present: bool, timer: Option<&str>) -> String {
    format!(
        "flag {}, timer {}",
        if flag_present { "present" } else { "absent" },
        timer.unwrap_or("unknown")
    )
}

async fn read_mint_state() -> Option<String> {
    let flag = std::path::Path::new(MINT_AUTOMATION_FLAG).exists();
    Some(mint_state(
        flag,
        systemd_ops::enablement(MINT_AUTOMATION_TIMER)
            .await
            .as_deref(),
    ))
}

/// Turn on Update Manager's automatic updates (Linux Mint only), and prove it.
///
/// Report-only when `mintupdate-automation` is not installed: writing the flag
/// without the unit would show the switch on while nothing ever runs.
async fn enable_mint_automatic_updates() -> Result<(), String> {
    if !std::path::Path::new(MINT_AUTOMATION_TOOL).exists() {
        remediation::record_finding(
            "Update Manager automatic updates",
            "Apply updates automatically is on",
            false,
            "mintupdate-automation is not installed; nothing to enable",
        );
        return Ok(());
    }
    remediation::apply(
        MINT_AUTOMATION_FLAG,
        "Update Manager applies updates automatically (flag file and timer)",
        read_mint_state,
        |state| state == MINT_ON,
        "ran mintupdate-automation upgrade enable",
        || async {
            let (ok, out, err) =
                pinnacle_core::command::execute(MINT_AUTOMATION_TOOL, Some("upgrade enable")).await;
            if ok {
                Ok(())
            } else {
                Err(err.filter(|e| !e.is_empty()).unwrap_or(out))
            }
        },
    )
    .await
}

pub struct SoftwareUpdateTask {
    name: String,
    description: String,
    dry_run: bool,
    readme_data: Option<ReadmeData>,
}

impl SoftwareUpdateTask {
    pub fn new() -> Self {
        Self {
            name: "Software Updates".to_string(),
            description: "Upgrade installed packages and enable security updates".to_string(),
            dry_run: false,
            readme_data: None,
        }
    }

    pub fn set_readme_data(&mut self, data: ReadmeData) {
        self.readme_data = Some(data);
    }
}

impl Default for SoftwareUpdateTask {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl Task for SoftwareUpdateTask {
    impl_task_meta!();

    async fn read_system_state(&mut self) -> SystemInfo {
        let pending = apt::upgradable().await;
        SystemInfo {
            raw_output: Some(format!("{} packages have updates available", pending.len())),
            ..Default::default()
        }
    }

    async fn execute(&mut self) -> TaskResult {
        let mut result = TaskResult {
            task_name: self.name.clone(),
            success: true,
            ..Default::default()
        };

        if !apt::is_available().await {
            result.message = "apt is not available; nothing was updated.".to_string();
            return result;
        }

        if !apt::update_lists().await {
            // Expected on an image with no network, and worth saying plainly:
            // "0 packages to upgrade" on an unpatched machine otherwise reads
            // as good news.
            ui::markup_line(
                "[yellow]⚠ Could not refresh the package lists. Anything below reflects \
                 the index as it already was, which on an offline image is stale.[/]",
            );
        }

        let pending = apt::upgradable().await;
        result.items_attempted = pending.len() as i32;

        for (name, current, candidate) in &pending {
            ui::markup_line(&format!(
                "[cyan]{}[/] [dim]{current} → {candidate}[/]",
                ui::escape(name)
            ));
        }

        // Scored on Mint (Update Manager > Automation). Dry-run safe: the write
        // goes through `remediation::apply`.
        if on_linux_mint().await {
            result.items_attempted += 1;
            match enable_mint_automatic_updates().await {
                Ok(()) => result.items_succeeded += 1,
                Err(e) => {
                    result.success = false;
                    ui::markup_line(&format!(
                        "[red]✗ Update Manager automatic updates: {}[/]",
                        ui::escape(&e)
                    ));
                }
            }
        }

        if self.dry_run {
            result.message = format!("DRY RUN: {} packages would be upgraded.", pending.len());
            return result;
        }

        if pending.is_empty() {
            remediation::record_finding(
                "installed packages",
                "every package is at its latest available version",
                true,
                "apt reports nothing to upgrade",
            );
            result.message = "Everything is already up to date.".to_string();
        } else {
            match apt::upgrade_all().await {
                Ok(()) => {
                    let remaining = apt::upgradable().await;
                    result.items_succeeded = (pending.len() - remaining.len()) as i32;
                    remediation::record_finding(
                        "installed packages",
                        "every package is at its latest available version",
                        remaining.is_empty(),
                        &format!(
                            "{} of {} packages upgraded; {} still pending",
                            result.items_succeeded,
                            pending.len(),
                            remaining.len()
                        ),
                    );
                    result.message = format!("Upgraded {} packages.", result.items_succeeded);
                }
                Err(e) => {
                    result.success = false;
                    result.message = "The upgrade did not complete.".to_string();
                    result.error_details = Some(e);
                }
            }
        }

        // Security updates after the round starts matter more than the ones
        // applied during it.
        if !apt::is_installed(UNATTENDED_UPGRADES).await {
            match apt::install(
                UNATTENDED_UPGRADES,
                "security updates are applied automatically from now on",
            )
            .await
            {
                Ok(()) => ui::markup_line("[green]✓ Installed unattended-upgrades[/]"),
                Err(e) => ui::markup_line(&format!(
                    "[yellow]⚠ Could not install unattended-upgrades: {}[/]",
                    ui::escape(&e)
                )),
            }
        }

        // ...and the periodic settings, which are what actually decide whether
        // anything is checked. Installing the package without them leaves the
        // machine exactly as unpatched as before, and reports success.
        for (key, value, why) in PERIODIC_SETTINGS {
            match file_ops::set(PERIODIC_CONF, Style::AptConf, key, value, why).await {
                Ok(()) => result.items_succeeded += 1,
                Err(e) => {
                    result.success = false;
                    ui::markup_line(&format!(
                        "[red]✗ {}: {}[/]",
                        ui::escape(key),
                        ui::escape(&e)
                    ));
                }
            }
        }
        result.items_attempted += PERIODIC_SETTINGS.len() as i32;

        result
    }

    async fn verify(&mut self) -> bool {
        // The periodic settings are checked first because they are the part
        // that has to be exactly right: a scored check reads that file.
        for (key, value, _why) in PERIODIC_SETTINGS {
            if file_ops::read(PERIODIC_CONF, Style::AptConf, key)
                .await
                .as_deref()
                != Some(*value)
            {
                return false;
            }
        }
        if on_linux_mint().await
            && std::path::Path::new(MINT_AUTOMATION_TOOL).exists()
            && read_mint_state().await.as_deref() != Some(MINT_ON)
        {
            return false;
        }
        // "Nothing left to upgrade" is the claim, so that is what is checked.
        // A package held back by a dependency legitimately fails this, which is
        // why verification failure is a warning rather than a task failure.
        apt::upgradable().await.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn a_dry_run_upgrades_nothing() {
        let _dry_run = pinnacle_core::run_log::dry_run_for_test();
        let mut task = SoftwareUpdateTask::new();
        task.set_dry_run(true);
        let result = pinnacle_core::ui::capture(task.execute()).await.0;
        assert!(result.success);
    }

    /// The answer key scores the *daily* check specifically. The value is a
    /// number of days, so 1 is daily and 0 - the stock setting on a competition
    /// image - is never.
    #[test]
    fn the_periodic_settings_ask_for_a_daily_check() {
        let daily = PERIODIC_SETTINGS
            .iter()
            .find(|(key, _, _)| *key == "APT::Periodic::Update-Package-Lists")
            .expect("the daily check must be configured");
        assert_eq!(daily.1, "1");
        for (key, value, why) in PERIODIC_SETTINGS {
            assert!(
                key.starts_with("APT::Periodic::"),
                "{key} is not a periodic key"
            );
            assert!(value.parse::<u32>().is_ok(), "{key} takes a number of days");
            assert!(!why.is_empty(), "{key} has no reason recorded");
        }
    }

    #[test]
    fn linux_mint_is_recognised_from_os_release() {
        let mint = "NAME=\"Linux Mint\"\nVERSION=\"21 (Vanessa)\"\nID=linuxmint\nID_LIKE=\"ubuntu debian\"\n";
        assert!(is_linux_mint(mint));
        assert!(is_linux_mint("ID=\"linuxmint\"\n"));
    }

    /// Mint's ID_LIKE says ubuntu, and Ubuntu's says debian; only `ID=` decides.
    #[test]
    fn ubuntu_is_not_taken_for_mint() {
        assert!(!is_linux_mint(
            "NAME=\"Ubuntu\"\nID=ubuntu\nID_LIKE=debian\n"
        ));
        assert!(!is_linux_mint("ID_LIKE=linuxmint\n"));
        assert!(!is_linux_mint(""));
    }

    /// Both halves of the switch are needed: the flag alone shows the dialog as
    /// on while no timer ever fires.
    #[test]
    fn automatic_updates_need_the_flag_and_the_timer() {
        assert_eq!(mint_state(true, Some("enabled")), MINT_ON);
        assert_ne!(mint_state(true, Some("disabled")), MINT_ON);
        assert_ne!(mint_state(false, Some("enabled")), MINT_ON);
        assert!(MINT_AUTOMATION_FLAG.starts_with("/var/lib/linuxmint/"));
        assert!(MINT_AUTOMATION_TIMER.ends_with(".timer"));
    }

    #[test]
    fn the_readme_is_accepted_even_though_the_task_does_not_need_it() {
        // Registered with `with_readme!` for consistency with the Windows task,
        // which uses it to skip packages the README pins to a version.
        let mut task = SoftwareUpdateTask::new();
        task.set_readme_data(ReadmeData::default());
        assert!(task.readme_data.is_some());
    }
}
