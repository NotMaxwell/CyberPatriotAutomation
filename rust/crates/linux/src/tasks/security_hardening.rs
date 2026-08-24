// =============================================================================
// PinnacleCyPat - Security hardening (Linux)
// Author: Maxwell McCormick
// Copyright 2026 Maxwell McCormick
// SPDX-License-Identifier: Apache-2.0
// =============================================================================

//! Applies the kernel, SSH and shadow-suite settings in
//! [`knowledge::HARDENING_SETTINGS`](crate::knowledge::HARDENING_SETTINGS).
//!
//! This is the Linux counterpart of the Windows registry-hardening task, and
//! the settings table plays the same role: the code here is a loop, and every
//! decision about *what* to set lives in one reviewable list.
//!
//! Two things are written to drop-in files rather than to the main
//! configuration, and both matter:
//!
//! - `sshd_config.d/99-pinnacle.conf`, because Ubuntu 22.04 and later put
//!   `Include /etc/ssh/sshd_config.d/*.conf` as the *first* line of
//!   `sshd_config` and sshd obeys the first definition of a keyword it sees.
//!   Editing the main file is then overridden by any drop-in already present -
//!   the run looks applied and changes nothing.
//! - `sysctl.d/99-pinnacle.conf`, because those files are read in lexical order
//!   and later values win, so `99-` makes this the effective setting whatever
//!   else is on the image.
//!
//! The one README-driven exception is remote access. An image whose scenario is
//! "this machine is administered remotely" scores SSH being *available*, and a
//! run that hardens `PermitRootLogin` while masking `ssh` loses that point -
//! the same failure the Windows port had with Remote Desktop.

use pinnacle_core::models::{SystemInfo, TaskResult};
use pinnacle_core::task::Task;
use pinnacle_core::{impl_task_meta, models::ReadmeData, ui};

use crate::knowledge::{
    HARDENING_SETTINGS, MODPROBE_DROPIN, MODULES_TO_BLOCK, SSHD_DROPIN, SYSCTL_DROPIN,
};
use crate::{file_ops, readme_services, systemd_ops};
use async_trait::async_trait;
use pinnacle_core::remediation;

pub struct SecurityHardeningTask {
    name: String,
    description: String,
    dry_run: bool,
    readme_data: Option<ReadmeData>,
}

impl SecurityHardeningTask {
    pub fn new() -> Self {
        Self {
            name: "Security Hardening".to_string(),
            description: "Kernel, SSH and account-ageing hardening".to_string(),
            dry_run: false,
            readme_data: None,
        }
    }

    pub fn set_readme_data(&mut self, data: ReadmeData) {
        self.readme_data = Some(data);
    }

    /// Is SSH something the README wants kept working?
    fn ssh_is_required(&self) -> bool {
        readme_services::is_critical(self.readme_data.as_ref(), "ssh.service")
    }
}

impl Default for SecurityHardeningTask {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl Task for SecurityHardeningTask {
    impl_task_meta!();

    async fn read_system_state(&mut self) -> SystemInfo {
        let mut lines = Vec::new();
        for setting in HARDENING_SETTINGS {
            let state = file_ops::read(setting.path, setting.style, setting.key)
                .await
                .unwrap_or_else(|| "unreadable".to_string());
            lines.push(format!("{}:{} = {}", setting.path, setting.key, state));
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
            items_attempted: HARDENING_SETTINGS.len() as i32,
            ..Default::default()
        };

        if self.dry_run {
            // `file_ops::set` records a Skipped entry per setting during a dry
            // run and writes nothing, so the ledger still shows what would have
            // happened - which is the point of the mode.
            for setting in HARDENING_SETTINGS {
                let _ = file_ops::set(
                    setting.path,
                    setting.style,
                    setting.key,
                    setting.value,
                    setting.why,
                )
                .await;
            }
            result.message = format!(
                "DRY RUN: would apply {} hardening settings.",
                HARDENING_SETTINGS.len()
            );
            return result;
        }

        let mut failures: Vec<String> = Vec::new();
        for setting in HARDENING_SETTINGS {
            match file_ops::set(
                setting.path,
                setting.style,
                setting.key,
                setting.value,
                setting.why,
            )
            .await
            {
                Ok(()) => result.items_succeeded += 1,
                Err(e) => {
                    // Record it. A failure counted for the on-screen tally but
                    // never pushed anywhere never reaches the summary or the log.
                    failures.push(format!("{}:{} ({e})", setting.path, setting.key));
                    ui::markup_line(&format!(
                        "[red]✗ {}: {}[/]",
                        ui::escape(setting.key),
                        ui::escape(&e)
                    ));
                }
            }
        }

        // --- kernel modules ----------------------------------------------
        //
        // Written as a whole file rather than through `file_ops::set`: a
        // modprobe drop-in is a list of directives, not a set of key/value
        // pairs, and two lines per module both name the module rather than
        // being keyed by it.
        match write_module_blacklist().await {
            Ok(()) => result.items_succeeded += 1,
            Err(e) => failures.push(format!("{MODPROBE_DROPIN} ({e})")),
        }
        result.items_attempted += 1;

        // --- login banners --------------------------------------------------
        //
        // Scored, and trivially missed: the stock `/etc/issue` on Ubuntu prints
        // the distribution and kernel version, which tells an attacker exactly
        // which exploits to try before they have authenticated.
        for path in BANNER_FILES {
            match write_banner(path).await {
                Ok(()) => result.items_succeeded += 1,
                Err(e) => failures.push(format!("{path} ({e})")),
            }
        }
        result.items_attempted += BANNER_FILES.len() as i32;

        // A written sysctl file changes nothing until it is loaded. Without
        // this the settings are correct on the next boot and wrong right now,
        // and a scored check that reads the live value sees the old one.
        if result.items_succeeded > 0 {
            let (loaded, _o, _e) =
                pinnacle_core::command::execute("sysctl", Some(&format!("-p {SYSCTL_DROPIN}")))
                    .await;
            if !loaded {
                ui::markup_line(
                    "[yellow]⚠ sysctl settings are written but could not be loaded; \
                     they take effect at the next boot.[/]",
                );
            }
        }

        // Restart sshd so the new configuration is live - but only if it was
        // already running. Starting it on an image where it was deliberately
        // off would open a service the round may well be scoring as closed.
        if systemd_ops::is_active("ssh.service").await {
            let (ok, _o, _e) =
                pinnacle_core::command::execute("systemctl", Some("reload-or-restart ssh.service"))
                    .await;
            if ok {
                ui::markup_line("[green]✓ Reloaded ssh with the new configuration[/]");
            } else {
                // A reload that fails usually means the drop-in has a syntax
                // error, which would leave sshd refusing to start on reboot.
                ui::markup_line(&format!(
                    "[yellow]⚠ ssh did not reload. Check {SSHD_DROPIN} with `sshd -t`.[/]"
                ));
            }
        } else if self.ssh_is_required() {
            ui::markup_line(
                "[yellow]⚠ The README calls SSH critical, but the service is not running. \
                 Service Management will start it.[/]",
            );
        }

        result.success = failures.is_empty();
        result.message = if failures.is_empty() {
            format!("Applied {} hardening settings.", result.items_succeeded)
        } else {
            format!(
                "Applied {} of {} settings; {} failed.",
                result.items_succeeded,
                HARDENING_SETTINGS.len(),
                failures.len()
            )
        };
        if !failures.is_empty() {
            result.error_details = Some(failures.join("; "));
        }
        result
    }

    async fn verify(&mut self) -> bool {
        // Read every setting back out of the file rather than trusting that the
        // writes returned Ok. This is the step that catches a value written to
        // a drop-in that something later in the run overrode.
        for setting in HARDENING_SETTINGS {
            let state = file_ops::read(setting.path, setting.style, setting.key).await;
            if state.as_deref() != Some(setting.value) {
                return false;
            }
        }
        true
    }
}

/// The banner files a login shows, in order of when they are seen.
const BANNER_FILES: &[&str] = &["/etc/issue", "/etc/issue.net", "/etc/motd"];

/// What the banner says.
///
/// Deliberately free of `\\n`, `\\s`, `\\m`, `\\r` and `\\v` - the escapes the
/// stock Ubuntu `/etc/issue` uses, which print the hostname, distribution and
/// kernel version *before* anyone has authenticated. That tells an attacker
/// which exploits to try, and it is what the scored check is looking for the
/// absence of.
const BANNER_TEXT: &str = "\
Authorized users only. All activity may be monitored and reported.
Unauthorized access to this system is prohibited and will be prosecuted.
";

/// Write one banner file, and prove it.
async fn write_banner(path: &str) -> Result<(), String> {
    remediation::apply(
        path,
        "a legal notice with no system information in it",
        || async {
            Some(match tokio::fs::read_to_string(path).await {
                Ok(text) => {
                    // The escapes are what matters, not the wording: a banner
                    // that leaks the kernel version fails the check however
                    // sternly it is worded.
                    if text.contains('\\') {
                        "leaks system information".to_string()
                    } else if text.trim().is_empty() {
                        "empty".to_string()
                    } else {
                        "a plain notice".to_string()
                    }
                }
                Err(_) => "absent".to_string(),
            })
        },
        |state| state == "a plain notice",
        "wrote a legal notice with no escapes in it",
        || async {
            tokio::fs::write(path, BANNER_TEXT)
                .await
                .map_err(|e| format!("could not write {path}: {e}"))
        },
    )
    .await
}

/// The modprobe drop-in, as text.
pub fn module_blacklist_text() -> String {
    let mut out = String::from("# Written by PinnacleCyPat.\n");
    out.push_str(
        "# `install ... /bin/false` is what prevents loading; `blacklist` alone only\n\
         # stops automatic loading and is bypassed by an explicit modprobe.\n\n",
    );
    for (module, why) in MODULES_TO_BLOCK {
        out.push_str(&format!(
            "# {why}\ninstall {module} /bin/false\nblacklist {module}\n\n"
        ));
    }
    out
}

/// Write the modprobe drop-in, and prove it.
async fn write_module_blacklist() -> Result<(), String> {
    let wanted = module_blacklist_text();
    remediation::apply(
        MODPROBE_DROPIN,
        &format!(
            "{} unused kernel modules cannot be loaded",
            MODULES_TO_BLOCK.len()
        ),
        || async {
            Some(match tokio::fs::read_to_string(MODPROBE_DROPIN).await {
                Ok(text) => {
                    let blocked = MODULES_TO_BLOCK
                        .iter()
                        .filter(|(m, _)| text.contains(&format!("install {m} /bin/false")))
                        .count();
                    format!("{blocked} blocked")
                }
                Err(_) => "absent".to_string(),
            })
        },
        |state| state == format!("{} blocked", MODULES_TO_BLOCK.len()),
        &format!("wrote {MODPROBE_DROPIN}"),
        || async {
            if let Some(parent) = std::path::Path::new(MODPROBE_DROPIN).parent() {
                let _ = tokio::fs::create_dir_all(parent).await;
            }
            tokio::fs::write(MODPROBE_DROPIN, &wanted)
                .await
                .map_err(|e| format!("could not write {MODPROBE_DROPIN}: {e}"))
        },
    )
    .await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn a_dry_run_writes_nothing() {
        pinnacle_core::run_log::set_dry_run(true);
        let mut task = SecurityHardeningTask::new();
        task.set_dry_run(true);
        let result = task.execute().await;
        pinnacle_core::run_log::set_dry_run(false);

        assert!(result.success);
        assert!(
            result.message.starts_with("DRY RUN"),
            "message was: {}",
            result.message
        );
        // The drop-ins are what a real run would create. Their absence here is
        // the assertion that matters - a task that ignores dry-run and writes
        // anyway is the worst bug this codebase can have.
        assert!(
            !std::path::Path::new(SSHD_DROPIN).exists(),
            "the dry run created {SSHD_DROPIN}"
        );
        assert!(
            !std::path::Path::new(SYSCTL_DROPIN).exists(),
            "the dry run created {SYSCTL_DROPIN}"
        );
    }

    /// The README override that the Windows port got wrong twice.
    #[test]
    fn the_readme_can_mark_ssh_as_required() {
        let mut task = SecurityHardeningTask::new();
        assert!(!task.ssh_is_required());
        task.set_readme_data(ReadmeData {
            critical_services: vec!["SSH".to_string()],
            ..Default::default()
        });
        assert!(task.ssh_is_required());
    }

    /// Both directives are needed. `blacklist` alone only stops *automatic*
    /// loading, so `modprobe cramfs` still works and the check still fails.
    #[test]
    fn every_blocked_module_gets_both_directives() {
        let text = module_blacklist_text();
        for (module, why) in MODULES_TO_BLOCK {
            assert!(
                text.contains(&format!("install {module} /bin/false")),
                "{module} has no install directive"
            );
            assert!(
                text.contains(&format!("blacklist {module}")),
                "{module} has no blacklist directive"
            );
            assert!(text.contains(why), "{module} has no reason recorded");
        }
    }

    /// Blocking vfat would stop a UEFI machine mounting /boot/efi, and
    /// therefore booting. "Unused filesystem" has to mean unused.
    #[test]
    fn the_filesystem_a_uefi_machine_boots_from_is_not_blocked() {
        assert!(
            !MODULES_TO_BLOCK.iter().any(|(m, _)| *m == "vfat"),
            "blocking vfat can make the image unbootable"
        );
        assert!(!MODULES_TO_BLOCK.iter().any(|(m, _)| *m == "ext4"));
    }

    /// The escapes are the finding, not the wording. Ubuntu's stock /etc/issue
    /// is `Ubuntu 22.04 LTS \\n \\l`, which prints the distribution and the
    /// terminal before anyone has authenticated.
    #[test]
    fn the_banner_carries_no_system_information() {
        assert!(
            !BANNER_TEXT.contains('\\'),
            "an escape in the banner leaks system information: {BANNER_TEXT}"
        );
        assert!(BANNER_TEXT.to_lowercase().contains("authorized"));
        assert!(BANNER_TEXT.ends_with('\n'));
    }

    /// Hardening SSH is pointless if the settings land somewhere sshd does not
    /// read, and this is the mistake that is easy to make.
    #[test]
    fn ssh_settings_go_to_the_drop_in_not_the_main_config() {
        let ssh_settings: Vec<_> = HARDENING_SETTINGS
            .iter()
            .filter(|s| s.key.starts_with("Permit") || s.key == "X11Forwarding")
            .collect();
        assert!(!ssh_settings.is_empty());
        for setting in ssh_settings {
            assert_eq!(
                setting.path, SSHD_DROPIN,
                "{} is in the wrong file",
                setting.key
            );
        }
    }
}
