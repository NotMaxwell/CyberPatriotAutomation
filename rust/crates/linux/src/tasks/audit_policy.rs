// =============================================================================
// PinnacleCyPat - Audit policy (Linux)
// Copyright 2026 Maxwell McCormick
// SPDX-License-Identifier: Apache-2.0
// =============================================================================

//! Installs and enables `auditd`, and makes sure the system logger is running -
//! the Linux counterpart of `auditpol` and the Windows event log.
//!
//! Two services, not one, and both are scored. `auditd` records syscall-level
//! events (who changed `/etc/passwd`, who loaded a kernel module); `rsyslog`
//! records what the daemons themselves say. Neither substitutes for the other,
//! and an image with only one of them running fails half the checks.
//!
//! The audit *rules* are deliberately minimal. A full CIS ruleset is several
//! hundred lines and generates enough volume to fill a small disk during a
//! round, at which point `auditd` stops recording and the machine may stop
//! accepting logins. The rules written here watch the files an attacker has to
//! touch, and nothing else.

use pinnacle_core::models::{SystemInfo, TaskResult};
use pinnacle_core::task::Task;
use pinnacle_core::{command, impl_task_meta, remediation, ui};

use crate::file_ops::Style;
use crate::{apt, file_ops, systemd_ops};
use async_trait::async_trait;

const RULES_FILE: &str = "/etc/audit/rules.d/99-pinnacle.rules";

/// What to watch, and why. `-w path -p wa -k key` means "log writes and
/// attribute changes to this path, tagged with this key".
const AUDIT_RULES: &[(&str, &str)] = &[
    (
        "-w /etc/passwd -p wa -k identity",
        "account creation and deletion",
    ),
    ("-w /etc/shadow -p wa -k identity", "password changes"),
    (
        "-w /etc/group -p wa -k identity",
        "group membership changes",
    ),
    (
        "-w /etc/gshadow -p wa -k identity",
        "group password changes",
    ),
    (
        "-w /etc/sudoers -p wa -k privilege",
        "grants of administrative rights",
    ),
    (
        "-w /etc/sudoers.d/ -p wa -k privilege",
        "grants of administrative rights",
    ),
    (
        "-w /etc/ssh/sshd_config -p wa -k remote-access",
        "changes to remote access",
    ),
    (
        "-w /var/log/auth.log -p wa -k logs",
        "tampering with the authentication log",
    ),
    ("-w /etc/hosts -p wa -k network", "static DNS overrides"),
    (
        "-w /etc/crontab -p wa -k persistence",
        "scheduled-task persistence",
    ),
    (
        "-w /etc/cron.d/ -p wa -k persistence",
        "scheduled-task persistence",
    ),
    ("-w /sbin/insmod -p x -k modules", "kernel module loading"),
    ("-w /sbin/modprobe -p x -k modules", "kernel module loading"),
    ("-w /sbin/rmmod -p x -k modules", "kernel module unloading"),
    (
        "-w /etc/pam.d/ -p wa -k pam",
        "changes to how authentication works",
    ),
    (
        "-w /etc/security/ -p wa -k pam",
        "changes to the password and lockout policy",
    ),
    (
        "-w /etc/login.defs -p wa -k logins",
        "changes to the account ageing defaults",
    ),
    (
        "-w /etc/sysctl.conf -p wa -k sysctl",
        "changes to the kernel hardening",
    ),
    (
        "-w /etc/sysctl.d/ -p wa -k sysctl",
        "changes to the kernel hardening",
    ),
    (
        "-w /etc/modprobe.d/ -p wa -k modules",
        "changes to the module blacklist",
    ),
    (
        "-w /var/log/faillog -p wa -k logins",
        "tampering with the failed-login record",
    ),
    (
        "-w /var/log/lastlog -p wa -k logins",
        "tampering with the last-login record",
    ),
    (
        "-w /var/run/utmp -p wa -k session",
        "tampering with the who-is-logged-in record",
    ),
    (
        "-w /var/log/wtmp -p wa -k session",
        "tampering with the login history",
    ),
    (
        "-w /var/log/btmp -p wa -k session",
        "tampering with the failed-login history",
    ),
    (
        "-w /etc/systemd/ -p wa -k persistence",
        "a unit file is persistence",
    ),
    (
        "-w /etc/fstab -p wa -k mounts",
        "an added mount can shadow a system directory",
    ),
    (
        "-w /etc/hosts.allow -p wa -k network",
        "host-based access control",
    ),
    (
        "-w /etc/hosts.deny -p wa -k network",
        "host-based access control",
    ),
    ("-w /usr/bin/sudo -p x -k privilege", "every use of sudo"),
    (
        "-w /var/log/sudo.log -p wa -k privilege",
        "tampering with the sudo log",
    ),
    (
        "-w /etc/ufw/ -p wa -k network",
        "changes to the firewall rules",
    ),
    (
        "-w /etc/apt/sources.list -p wa -k software",
        "a added repository can install anything",
    ),
    (
        "-w /etc/apt/sources.list.d/ -p wa -k software",
        "a added repository can install anything",
    ),
];

/// `auditd`'s own configuration.
///
/// The defaults are the problem: `max_log_file_action = ROTATE` with eight
/// files silently discards the oldest records, and `space_left_action = SYSLOG`
/// means a full disk stops the audit trail without stopping anything else. On a
/// competition image the sensible answer is to keep more history and to make
/// running out of space loud rather than silent - but *not* to halt the machine,
/// which is what the strictest CIS setting does and which would end the round.
const AUDITD_SETTINGS: &[(&str, &str, &str)] = &[
    (
        "max_log_file",
        "32",
        "megabytes per log file before it rotates",
    ),
    (
        "max_log_file_action",
        "keep_logs",
        "keep the history rather than overwriting the oldest",
    ),
    (
        "space_left_action",
        "email",
        "warn while there is still room, rather than only at the end",
    ),
    (
        // CIS asks for `halt` here. That is right for a server with an
        // administrator watching and wrong for a competition image: a disk that
        // fills mid-round would power the machine off and end the round with
        // whatever score it had. `single` drops to single-user mode, which is
        // loud, recoverable, and does not stop the scoring engine reporting.
        "admin_space_left_action",
        "single",
        "loud and recoverable, rather than halting the machine mid-round",
    ),
    ("num_logs", "5", "how many rotated files to keep"),
];

/// Services that must be running for anything to be recorded at all.
const LOGGING_SERVICES: &[(&str, &str, &str)] = &[
    ("auditd.service", "auditd", "syscall-level auditing"),
    (
        "rsyslog.service",
        "rsyslog",
        "system and authentication logging",
    ),
];

pub struct AuditPolicyTask {
    name: String,
    description: String,
    dry_run: bool,
}

impl AuditPolicyTask {
    pub fn new() -> Self {
        Self {
            name: "Audit Policy".to_string(),
            description: "Enable auditd and system logging".to_string(),
            dry_run: false,
        }
    }
}

impl Default for AuditPolicyTask {
    fn default() -> Self {
        Self::new()
    }
}

/// The rules file this task writes, as text.
pub fn rules_text() -> String {
    let mut out = String::from("# Written by PinnacleCyPat.\n");
    out.push_str("# Deliberately minimal: a full CIS ruleset fills the disk during a round.\n\n");
    for (rule, why) in AUDIT_RULES {
        out.push_str(&format!("# {why}\n{rule}\n"));
    }
    out
}

#[async_trait]
impl Task for AuditPolicyTask {
    impl_task_meta!();

    async fn read_system_state(&mut self) -> SystemInfo {
        let mut lines = Vec::new();
        for (unit, _pkg, _why) in LOGGING_SERVICES {
            lines.push(format!(
                "{unit}: {}",
                systemd_ops::activity(unit)
                    .await
                    .unwrap_or_else(|| "not installed".to_string())
            ));
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
            items_attempted: LOGGING_SERVICES.len() as i32 + 1,
            ..Default::default()
        };

        if self.dry_run {
            for (unit, pkg, why) in LOGGING_SERVICES {
                ui::markup_line(&format!(
                    "[cyan]Would ensure {unit} is installed ({pkg}) and running - {why}[/]"
                ));
            }
            ui::markup_line(&format!(
                "[cyan]Would write {} audit rules to {RULES_FILE}[/]",
                AUDIT_RULES.len()
            ));
            result.message = "DRY RUN: no logging configuration was changed.".to_string();
            return result;
        }

        let mut failures: Vec<String> = Vec::new();

        for (unit, package, why) in LOGGING_SERVICES {
            if !systemd_ops::exists(unit).await {
                match apt::install(package, why).await {
                    Ok(()) => ui::markup_line(&format!("[green]✓ Installed {package}[/]")),
                    Err(e) => {
                        failures.push(format!("{package}: {e}"));
                        continue;
                    }
                }
            }
            match systemd_ops::enable(unit, why).await {
                Ok(()) => result.items_succeeded += 1,
                Err(e) => failures.push(format!("{unit}: {e}")),
            }
        }

        // The rules are only useful if auditd is there to read them.
        if systemd_ops::exists("auditd.service").await {
            let wanted = rules_text();
            match remediation::apply(
                RULES_FILE,
                &format!(
                    "{} audit rules watching the files an attacker must touch",
                    AUDIT_RULES.len()
                ),
                || async {
                    Some(match tokio::fs::read_to_string(RULES_FILE).await {
                        Ok(text) => {
                            let live = text.lines().filter(|l| file_ops::is_active(l)).count();
                            format!("{live} rules")
                        }
                        Err(_) => "absent".to_string(),
                    })
                },
                |state| state == format!("{} rules", AUDIT_RULES.len()),
                &format!("wrote {RULES_FILE}"),
                || async {
                    if let Some(parent) = std::path::Path::new(RULES_FILE).parent() {
                        let _ = tokio::fs::create_dir_all(parent).await;
                    }
                    tokio::fs::write(RULES_FILE, &wanted)
                        .await
                        .map_err(|e| format!("could not write {RULES_FILE}: {e}"))
                },
            )
            .await
            {
                Ok(()) => {
                    result.items_succeeded += 1;
                    // Rules on disk do nothing until loaded. Reported rather
                    // than treated as a failure: `augenrules` is absent on some
                    // images, and the rules still apply at the next boot.
                    let (loaded, _o, _e) = command::execute("augenrules", Some("--load")).await;
                    if !loaded {
                        ui::markup_line(
                            "[yellow]⚠ Audit rules are written but not loaded; they take \
                             effect at the next boot.[/]",
                        );
                    }
                }
                Err(e) => failures.push(format!("audit rules: {e}")),
            }
        }

        // auditd's own configuration. Written after the service is installed,
        // since the file does not exist before that.
        if systemd_ops::exists("auditd.service").await {
            for (key, value, why) in AUDITD_SETTINGS {
                match file_ops::set("/etc/audit/auditd.conf", Style::Equals, key, value, why).await
                {
                    Ok(()) => result.items_succeeded += 1,
                    Err(e) => failures.push(format!("auditd.conf {key}: {e}")),
                }
            }
            result.items_attempted += AUDITD_SETTINGS.len() as i32;
        }

        result.success = failures.is_empty();
        result.message = format!(
            "{} logging services running, {} audit rules written.",
            result.items_succeeded.min(LOGGING_SERVICES.len() as i32),
            AUDIT_RULES.len()
        );
        if !failures.is_empty() {
            result.error_details = Some(failures.join("; "));
        }
        result
    }

    async fn verify(&mut self) -> bool {
        for (unit, _pkg, _why) in LOGGING_SERVICES {
            if !systemd_ops::is_active(unit).await {
                return false;
            }
        }
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The rules file has to be syntactically valid or `auditd` refuses to
    /// start at all - which turns a hardening step into an outage.
    #[test]
    fn every_rule_is_a_well_formed_watch_or_exec_rule() {
        for (rule, why) in AUDIT_RULES {
            assert!(rule.starts_with("-w "), "{rule} is not a watch rule");
            assert!(rule.contains(" -p "), "{rule} has no permission filter");
            assert!(
                rule.contains(" -k "),
                "{rule} has no key, so it cannot be searched for"
            );
            assert!(!why.is_empty(), "{rule} has no reason recorded");
        }
    }

    #[test]
    fn the_rules_file_documents_each_rule() {
        let text = rules_text();
        for (rule, why) in AUDIT_RULES {
            assert!(text.contains(rule), "{rule} is missing from the file");
            assert!(text.contains(why), "the reason for {rule} is missing");
        }
        // The count the proof step compares against.
        assert_eq!(
            text.lines().filter(|l| file_ops::is_active(l)).count(),
            AUDIT_RULES.len()
        );
    }

    /// The CIS setting here is `halt`, and it is wrong for this image: a disk
    /// that fills mid-round would power the machine off and end the round with
    /// whatever score it had at the time.
    #[test]
    fn a_full_disk_does_not_halt_the_machine() {
        let action = AUDITD_SETTINGS
            .iter()
            .find(|(key, _, _)| *key == "admin_space_left_action")
            .expect("the full-disk action must be set");
        assert_ne!(action.1, "halt", "halting mid-round ends the round");
        assert_eq!(action.1, "single");
    }

    /// Rotating over the oldest records means the audit trail quietly loses the
    /// beginning of an incident, which is the part worth having.
    #[test]
    fn the_audit_history_is_kept_rather_than_overwritten() {
        let action = AUDITD_SETTINGS
            .iter()
            .find(|(key, _, _)| *key == "max_log_file_action")
            .unwrap();
        assert_eq!(action.1, "keep_logs");
    }

    /// The files an attacker has to touch to persist. Missing any of these
    /// makes the audit log silent about the thing it exists to catch.
    #[test]
    fn the_account_and_privilege_files_are_watched() {
        let text = rules_text();
        for path in [
            "/etc/passwd",
            "/etc/shadow",
            "/etc/sudoers",
            "/etc/ssh/sshd_config",
        ] {
            assert!(text.contains(path), "{path} is not watched");
        }
    }

    #[tokio::test]
    async fn a_dry_run_changes_nothing() {
        pinnacle_core::run_log::set_dry_run(true);
        let mut task = AuditPolicyTask::new();
        task.set_dry_run(true);
        let result = pinnacle_core::ui::capture(task.execute()).await.0;
        pinnacle_core::run_log::set_dry_run(false);
        assert!(result.success);
        assert!(result.message.starts_with("DRY RUN"), "{}", result.message);
    }
}
