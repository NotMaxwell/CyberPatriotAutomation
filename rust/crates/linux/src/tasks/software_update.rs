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
use async_trait::async_trait;

/// Turning this on is what keeps the machine patched after the round starts.
const UNATTENDED_UPGRADES: &str = "unattended-upgrades";

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
                Ok(()) => ui::markup_line("[green]✓ Enabled automatic security updates[/]"),
                Err(e) => ui::markup_line(&format!(
                    "[yellow]⚠ Could not enable automatic security updates: {}[/]",
                    ui::escape(&e)
                )),
            }
        }

        result
    }

    async fn verify(&mut self) -> bool {
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
        pinnacle_core::run_log::set_dry_run(true);
        let mut task = SoftwareUpdateTask::new();
        task.set_dry_run(true);
        let result = pinnacle_core::ui::capture(task.execute()).await.0;
        pinnacle_core::run_log::set_dry_run(false);
        assert!(result.success);
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
