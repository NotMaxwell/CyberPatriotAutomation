// =============================================================================
// PinnacleCyPat - Service management (Linux)
// Author: Maxwell McCormick
// Copyright 2026 Maxwell McCormick
// SPDX-License-Identifier: Apache-2.0
// =============================================================================

//! Masks the services in
//! [`knowledge::PROHIBITED_SERVICES`](crate::knowledge::PROHIBITED_SERVICES),
//! and starts the ones the README calls critical.
//!
//! **Protection is applied before anything is disabled.** The order is not
//! cosmetic: the prohibited list and the README's critical list overlap by
//! design - a round may well require Apache or Samba on a machine whose default
//! posture is to have neither - and resolving that after the fact means the
//! service is masked and then unmasked, with a window in between where a scored
//! check sees it down.
//!
//! Nothing on [`NEVER_DISABLE`](crate::knowledge::NEVER_DISABLE) is touched
//! whatever the tables say. That list carries the scoring engine and the units
//! the image needs to boot, and masking any of them ends the round.

use pinnacle_core::models::{SystemInfo, TaskResult};
use pinnacle_core::task::Task;
use pinnacle_core::{impl_task_meta, models::ReadmeData, ui};

use crate::knowledge::PROHIBITED_SERVICES;
use crate::{readme_services, systemd_ops};
use async_trait::async_trait;

pub struct ServiceManagementTask {
    name: String,
    description: String,
    dry_run: bool,
    readme_data: Option<ReadmeData>,
}

impl ServiceManagementTask {
    pub fn new() -> Self {
        Self {
            name: "Service Management".to_string(),
            description: "Mask insecure services, protect critical ones".to_string(),
            dry_run: false,
            readme_data: None,
        }
    }

    pub fn set_readme_data(&mut self, data: ReadmeData) {
        self.readme_data = Some(data);
    }

    /// The units the README wants running, resolved to unit names.
    pub fn required_units(&self) -> Vec<String> {
        self.readme_data
            .as_ref()
            .map(|r| {
                r.critical_services
                    .iter()
                    .map(|s| readme_services::resolve(s))
                    .collect()
            })
            .unwrap_or_default()
    }

    /// The units to mask: the prohibited list, minus anything protected.
    pub fn units_to_mask(&self) -> Vec<(&'static str, &'static str)> {
        PROHIBITED_SERVICES
            .iter()
            .copied()
            .filter(|(unit, _)| !readme_services::is_protected(self.readme_data.as_ref(), unit))
            .collect()
    }
}

impl Default for ServiceManagementTask {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl Task for ServiceManagementTask {
    impl_task_meta!();

    async fn read_system_state(&mut self) -> SystemInfo {
        let mut lines = Vec::new();
        for (unit, _why) in PROHIBITED_SERVICES {
            if let Some(state) = systemd_ops::enablement(unit).await {
                lines.push(format!("{unit}: {state}"));
            }
        }
        SystemInfo {
            raw_output: Some(lines.join("\n")),
            ..Default::default()
        }
    }

    async fn execute(&mut self) -> TaskResult {
        let mut result = TaskResult {
            task_name: self.name.clone(),
            success: true,
            ..Default::default()
        };

        let required = self.required_units();
        let to_mask = self.units_to_mask();
        result.items_attempted = (required.len() + to_mask.len()) as i32;

        if self.dry_run {
            for unit in &required {
                ui::markup_line(&format!(
                    "[cyan]Would ensure running: {}[/]",
                    ui::escape(unit)
                ));
            }
            for (unit, why) in &to_mask {
                if systemd_ops::exists(unit).await {
                    ui::markup_line(&format!(
                        "[cyan]Would mask: {} ({})[/]",
                        ui::escape(unit),
                        ui::escape(why)
                    ));
                }
            }
            result.message = format!(
                "DRY RUN: would protect {} services and mask up to {}.",
                required.len(),
                to_mask.len()
            );
            return result;
        }

        // Protection first - see the module comment. A service the README
        // requires must never be masked even momentarily.
        let mut failures: Vec<String> = Vec::new();
        for unit in &required {
            if !systemd_ops::exists(unit).await {
                ui::markup_line(&format!(
                    "[yellow]⚠ The README requires {}, which is not installed.[/]",
                    ui::escape(unit)
                ));
                result.items_skipped += 1;
                continue;
            }
            match systemd_ops::enable(unit, "the README lists it as critical").await {
                Ok(()) => {
                    result.items_succeeded += 1;
                    ui::markup_line(&format!("[green]✓ Protected: {}[/]", ui::escape(unit)));
                }
                Err(e) => failures.push(format!("{unit}: {e}")),
            }
        }

        for (unit, why) in &to_mask {
            // Asking first turns "not installed" into its own outcome. A
            // competition image has none of most of these, and reporting
            // twenty failures for services that were never there buries the
            // one that matters.
            if !systemd_ops::exists(unit).await {
                result.items_skipped += 1;
                continue;
            }
            match systemd_ops::disable(unit, why).await {
                Ok(()) => {
                    result.items_succeeded += 1;
                    ui::markup_line(&format!(
                        "[green]✓ Masked: {} [dim]({})[/][/]",
                        ui::escape(unit),
                        ui::escape(why)
                    ));
                }
                Err(e) => failures.push(format!("{unit}: {e}")),
            }
        }

        result.success = failures.is_empty();
        result.message = format!(
            "{} services changed, {} not installed.",
            result.items_succeeded, result.items_skipped
        );
        if !failures.is_empty() {
            result.error_details = Some(failures.join("; "));
        }
        result
    }

    async fn verify(&mut self) -> bool {
        for (unit, _why) in self.units_to_mask() {
            if !systemd_ops::exists(unit).await {
                continue;
            }
            if systemd_ops::enablement(unit).await.as_deref() != Some("masked") {
                return false;
            }
        }
        for unit in self.required_units() {
            if systemd_ops::exists(&unit).await && !systemd_ops::is_active(&unit).await {
                return false;
            }
        }
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn readme(critical: &[&str]) -> ReadmeData {
        ReadmeData {
            critical_services: critical.iter().map(|s| s.to_string()).collect(),
            ..Default::default()
        }
    }

    /// The overlap the task exists to resolve. A round that requires a web
    /// server must not have it masked by a table that assumes no image needs
    /// one - this is the Windows Remote Desktop bug in its Linux form.
    #[test]
    fn a_service_the_readme_requires_is_not_masked() {
        let mut task = ServiceManagementTask::new();
        assert!(
            task.units_to_mask()
                .iter()
                .any(|(u, _)| *u == "apache2.service"),
            "apache2 should be prohibited by default"
        );

        task.set_readme_data(readme(&["Apache"]));
        assert!(
            !task
                .units_to_mask()
                .iter()
                .any(|(u, _)| *u == "apache2.service"),
            "the README required Apache and it was still going to be masked"
        );
        assert_eq!(task.required_units(), ["apache2.service"]);
    }

    /// The catastrophic case. Nothing on the never-disable list may appear in
    /// the mask set, README or no README.
    #[test]
    fn nothing_protected_by_default_is_ever_masked() {
        let task = ServiceManagementTask::new();
        for (unit, _) in task.units_to_mask() {
            assert!(
                !readme_services::is_protected(None, unit),
                "{unit} is protected and was still queued for masking"
            );
        }
    }

    #[test]
    fn a_readme_display_name_is_resolved_before_it_is_compared() {
        let mut task = ServiceManagementTask::new();
        task.set_readme_data(readme(&["Secure Shell", "FTP"]));
        assert_eq!(task.required_units(), ["ssh.service", "vsftpd.service"]);
        assert!(
            !task
                .units_to_mask()
                .iter()
                .any(|(u, _)| *u == "vsftpd.service"),
            "the README asked for FTP by a name the mask list spells differently"
        );
    }

    #[tokio::test]
    async fn a_dry_run_reports_without_masking_anything() {
        pinnacle_core::run_log::set_dry_run(true);
        let mut task = ServiceManagementTask::new();
        task.set_dry_run(true);
        let result = pinnacle_core::ui::capture(task.execute()).await.0;
        pinnacle_core::run_log::set_dry_run(false);
        assert!(result.success);
        assert!(result.message.starts_with("DRY RUN"), "{}", result.message);
    }
}
