// =============================================================================
// PinnacleCyPat - Firewall (Linux)
// Author: Maxwell McCormick
// Copyright 2026 Maxwell McCormick
// SPDX-License-Identifier: Apache-2.0
// =============================================================================

//! Enables `ufw`, sets it to deny inbound by default, and opens only what the
//! README asks for.
//!
//! **The order here is the whole task.** `ufw enable` with a default-deny
//! policy and no allow rule for SSH drops the connection the run is happening
//! over, on an image that is often administered remotely - and no further
//! command reaches the machine. So the allow rules go in *first*, and only then
//! is the firewall enabled. The Windows firewall task has the same hazard and
//! the same ordering.
//!
//! `ufw` rather than raw `nftables`: it is what a CyberPatriot Ubuntu image
//! ships with and what the scored checks look at, its rules survive a reboot
//! without extra work, and its status output is stable enough to parse.

use pinnacle_core::models::{SystemInfo, TaskResult};
use pinnacle_core::task::Task;
use pinnacle_core::{command, impl_task_meta, models::ReadmeData, remediation, ui};

use crate::readme_services;
use async_trait::async_trait;

/// Services the README may require, and the ufw application profile or port
/// that opens them.
const PORT_FOR_UNIT: &[(&str, &str)] = &[
    ("ssh.service", "22/tcp"),
    ("apache2.service", "80/tcp"),
    ("nginx.service", "80/tcp"),
    ("vsftpd.service", "21/tcp"),
    ("smbd.service", "445/tcp"),
    ("postgresql.service", "5432/tcp"),
    ("mysql.service", "3306/tcp"),
    ("mariadb.service", "3306/tcp"),
    ("xrdp.service", "3389/tcp"),
];

pub struct FirewallTask {
    name: String,
    description: String,
    dry_run: bool,
    readme_data: Option<ReadmeData>,
}

impl FirewallTask {
    pub fn new() -> Self {
        Self {
            name: "Firewall".to_string(),
            description: "Enable ufw, deny inbound, open what the README needs".to_string(),
            dry_run: false,
            readme_data: None,
        }
    }

    pub fn set_readme_data(&mut self, data: ReadmeData) {
        self.readme_data = Some(data);
    }

    /// The ports to open before enabling the firewall.
    ///
    /// SSH is always included, whether or not the README mentions it. Enabling
    /// a default-deny firewall over an SSH session without it ends the round on
    /// a remotely administered image, and an open port 22 on a machine that is
    /// not using it costs nothing that the service being masked does not
    /// already fix.
    pub fn ports_to_open(&self) -> Vec<&'static str> {
        let mut ports = vec!["22/tcp"];
        for (unit, port) in PORT_FOR_UNIT {
            if readme_services::is_critical(self.readme_data.as_ref(), unit)
                && !ports.contains(port)
            {
                ports.push(port);
            }
        }
        ports
    }
}

impl Default for FirewallTask {
    fn default() -> Self {
        Self::new()
    }
}

/// Is ufw active, according to `ufw status`?
///
/// The first line is `Status: active` or `Status: inactive`, which has been
/// stable across every ufw release and is what the scored check reads too.
pub fn is_active(status_output: &str) -> bool {
    status_output
        .lines()
        .find_map(|l| l.trim().strip_prefix("Status:"))
        .is_some_and(|s| s.trim() == "active")
}

async fn ufw_status() -> Option<String> {
    let (_ok, out, _e) = command::execute("ufw", Some("status")).await;
    (!out.trim().is_empty()).then(|| {
        if is_active(&out) {
            "active".to_string()
        } else {
            "inactive".to_string()
        }
    })
}

#[async_trait]
impl Task for FirewallTask {
    impl_task_meta!();

    async fn read_system_state(&mut self) -> SystemInfo {
        let (_ok, out, _e) = command::execute("ufw", Some("status verbose")).await;
        SystemInfo {
            raw_output: Some(out),
            ..Default::default()
        }
    }

    async fn execute(&mut self) -> TaskResult {
        let mut result = TaskResult {
            task_name: self.name.clone(),
            success: true,
            ..Default::default()
        };

        let (available, _o, _e) = command::execute("ufw", Some("--version")).await;
        if !available {
            // Not a failure of this run: an image without ufw is a legitimate
            // configuration, and installing a firewall unasked is a bigger
            // change than this task is entitled to make.
            result.message = "ufw is not installed; the firewall was not changed.".to_string();
            remediation::record_finding(
                "ufw",
                "a host firewall is enabled and denying inbound traffic",
                false,
                "ufw is not installed on this image",
            );
            ui::markup_line(
                "[yellow]⚠ ufw is not installed. Install it with `apt install ufw`, \
                 then re-run this task.[/]",
            );
            return result;
        }

        let ports = self.ports_to_open();
        result.items_attempted = ports.len() as i32 + 3;

        if self.dry_run {
            for port in &ports {
                ui::markup_line(&format!("[cyan]Would allow: {port}[/]"));
            }
            ui::markup_line("[cyan]Would set default deny incoming, allow outgoing[/]");
            ui::markup_line("[cyan]Would enable ufw[/]");
            result.message = format!(
                "DRY RUN: would open {} ports and enable the firewall.",
                ports.len()
            );
            return result;
        }

        let mut failures: Vec<String> = Vec::new();

        // Allow rules FIRST - see the module comment. Getting this backwards
        // drops the administrator's own connection.
        for port in &ports {
            let (ok, _o, e) = command::execute("ufw", Some(&format!("allow {port}"))).await;
            if ok {
                result.items_succeeded += 1;
                ui::markup_line(&format!("[green]✓ Allowed: {port}[/]"));
            } else {
                failures.push(format!(
                    "allow {port}: {}",
                    e.unwrap_or_else(|| "ufw refused the rule".to_string())
                ));
            }
        }

        // If no allow rule landed, enabling would cut the machine off. Stop.
        if result.items_succeeded == 0 {
            result.success = false;
            result.message =
                "No allow rules could be added; the firewall was left as it was.".to_string();
            result.error_details = Some(failures.join("; "));
            ui::markup_line(
                "[red]✗ Refusing to enable the firewall with no allow rules - that would \
                 drop every inbound connection including SSH.[/]",
            );
            return result;
        }

        for (direction, policy) in [("incoming", "deny"), ("outgoing", "allow")] {
            let (ok, _o, e) =
                command::execute("ufw", Some(&format!("default {policy} {direction}"))).await;
            if ok {
                result.items_succeeded += 1;
            } else {
                failures.push(format!(
                    "default {policy} {direction}: {}",
                    e.unwrap_or_default()
                ));
            }
        }

        match remediation::apply(
            "ufw",
            "enabled, denying inbound traffic by default",
            ufw_status,
            |state| state == "active",
            "ufw --force enable",
            || async {
                // `--force` skips the interactive "this may disrupt existing
                // ssh connections" prompt, which with no console to answer it
                // would hang until the timeout.
                let (ok, _o, e) = command::execute("ufw", Some("--force enable")).await;
                if ok {
                    Ok(())
                } else {
                    Err(e.unwrap_or_else(|| "ufw enable failed".to_string()))
                }
            },
        )
        .await
        {
            Ok(()) => {
                result.items_succeeded += 1;
                ui::markup_line("[green]✓ Firewall enabled, inbound denied by default[/]");
            }
            Err(e) => failures.push(format!("enable: {e}")),
        }

        result.success = failures.is_empty();
        result.message = format!("Firewall enabled with {} allow rules.", ports.len());
        if !failures.is_empty() {
            result.error_details = Some(failures.join("; "));
        }
        result
    }

    async fn verify(&mut self) -> bool {
        ufw_status().await.as_deref() == Some("active")
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

    /// The rule that stops the run locking itself out of a remotely
    /// administered image.
    #[test]
    fn ssh_is_always_opened_even_when_the_readme_is_silent() {
        assert_eq!(FirewallTask::new().ports_to_open(), ["22/tcp"]);
    }

    #[test]
    fn a_service_the_readme_requires_gets_its_port() {
        let mut task = FirewallTask::new();
        task.set_readme_data(readme(&["Apache", "PostgreSQL"]));
        let ports = task.ports_to_open();
        assert!(ports.contains(&"80/tcp"), "{ports:?}");
        assert!(ports.contains(&"5432/tcp"), "{ports:?}");
        assert!(ports.contains(&"22/tcp"), "{ports:?}");
    }

    /// Apache and nginx both map to 80. Opening it twice makes ufw print a
    /// "Skipping adding existing rule" that reads as a failure in the log.
    #[test]
    fn a_port_wanted_by_two_services_is_opened_once() {
        let mut task = FirewallTask::new();
        task.set_readme_data(readme(&["Apache", "Nginx"]));
        let ports = task.ports_to_open();
        assert_eq!(ports.iter().filter(|p| **p == "80/tcp").count(), 1);
    }

    /// Real `ufw status` output, both states.
    #[test]
    fn the_status_line_decides_whether_ufw_is_active() {
        assert!(is_active(
            "Status: active\n\nTo    Action  From\n--    ------  ----\n"
        ));
        assert!(!is_active("Status: inactive\n"));
        // No ufw at all, or a permission error, is not "active".
        assert!(!is_active(""));
        assert!(!is_active(
            "ERROR: You need to be root to run this script\n"
        ));
    }
}
