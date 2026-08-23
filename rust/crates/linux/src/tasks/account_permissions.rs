// =============================================================================
// PinnacleCyPat - Account permissions (Linux)
// Author: Maxwell McCormick
// Copyright 2026 Maxwell McCormick
// SPDX-License-Identifier: Apache-2.0
// =============================================================================

//! The account findings that do not depend on a README: passwordless logins,
//! duplicate uid 0, service accounts with a real shell, and password ageing.
//!
//! Every one of these is scored, and every one is invisible from the desktop.
//! An account with an empty hash field in `/etc/shadow` logs in by pressing
//! enter; an account with uid 0 that is not called `root` is a second
//! superuser that `sudo` never records.
//!
//! Unlike User Management, this task acts without a README - which is why it is
//! careful to change only things that are wrong on any image, and to *report*
//! rather than act where a legitimate configuration exists. A second uid 0
//! account is reported, not deleted: it may be the image's own administrator,
//! and removing the only account someone can log in as would end the round.

use pinnacle_core::models::{SystemInfo, TaskResult};
use pinnacle_core::task::Task;
use pinnacle_core::{impl_task_meta, remediation, ui};

use crate::knowledge::SYSTEM_ACCOUNTS;
use crate::user_ops::{self, Account};
use async_trait::async_trait;

/// The ageing this task applies to every human account, matching
/// `login.defs` as set by Security Hardening. `login.defs` governs accounts
/// created *afterwards*; existing accounts keep whatever they were made with,
/// which on a competition image is `99999` - effectively never.
const MAX_DAYS: u32 = 90;
const MIN_DAYS: u32 = 7;
const WARN_DAYS: u32 = 14;

pub struct AccountPermissionsTask {
    name: String,
    description: String,
    dry_run: bool,
}

impl AccountPermissionsTask {
    pub fn new() -> Self {
        Self {
            name: "Account Permissions".to_string(),
            description: "Passwordless logins, duplicate root, password ageing".to_string(),
            dry_run: false,
        }
    }
}

impl Default for AccountPermissionsTask {
    fn default() -> Self {
        Self::new()
    }
}

/// Accounts sharing uid 0 with root.
///
/// Reported rather than acted on: one of them may be the only account anyone
/// can log in as.
pub fn duplicate_superusers(accounts: &[Account]) -> Vec<String> {
    accounts
        .iter()
        .filter(|a| a.uid == 0 && a.name != "root")
        .map(|a| a.name.clone())
        .collect()
}

/// System accounts that have been given a login shell.
///
/// `www-data` with `/bin/bash` is a backdoor wearing a familiar name, and it is
/// a favourite because it survives a glance at the user list.
pub fn service_accounts_with_shells(accounts: &[Account]) -> Vec<String> {
    accounts
        .iter()
        .filter(|a| !a.is_human() && a.name != "root" && a.can_log_in())
        .filter(|a| {
            SYSTEM_ACCOUNTS
                .iter()
                .any(|s| s.eq_ignore_ascii_case(&a.name))
        })
        .map(|a| a.name.clone())
        .collect()
}

#[async_trait]
impl Task for AccountPermissionsTask {
    impl_task_meta!();

    async fn read_system_state(&mut self) -> SystemInfo {
        let accounts = user_ops::accounts().await;
        SystemInfo {
            raw_output: Some(format!(
                "{} accounts, {} of them human",
                accounts.len(),
                accounts.iter().filter(|a| a.is_human()).count()
            )),
            ..Default::default()
        }
    }

    async fn execute(&mut self) -> TaskResult {
        let mut result = TaskResult {
            task_name: self.name.clone(),
            success: true,
            ..Default::default()
        };

        let accounts = user_ops::accounts().await;
        let humans: Vec<&Account> = accounts.iter().filter(|a| a.is_human()).collect();

        // --- findings, reported rather than acted on ------------------------
        let doubles = duplicate_superusers(&accounts);
        for name in &doubles {
            ui::markup_line(&format!(
                "[red]✗ {} has uid 0 - a second superuser account[/]",
                ui::escape(name)
            ));
        }
        remediation::record_finding(
            "uid 0",
            "only root has uid 0",
            doubles.is_empty(),
            &if doubles.is_empty() {
                "no other account shares uid 0".to_string()
            } else {
                format!(
                    "{} also has uid 0; left in place deliberately, since removing the \
                     only usable login would end the round",
                    doubles.join(", ")
                )
            },
        );

        let shells = service_accounts_with_shells(&accounts);
        for name in &shells {
            ui::markup_line(&format!(
                "[yellow]⚠ {} is a service account with a login shell[/]",
                ui::escape(name)
            ));
        }
        remediation::record_finding(
            "service account shells",
            "system accounts cannot log in",
            shells.is_empty(),
            &if shells.is_empty() {
                "every system account has nologin or false as its shell".to_string()
            } else {
                format!("{} can log in", shells.join(", "))
            },
        );

        // --- passwordless accounts, which are acted on ----------------------
        let mut passwordless: Vec<String> = Vec::new();
        for account in &humans {
            if user_ops::password_state(&account.name).await.as_deref() == Some("no password") {
                passwordless.push(account.name.clone());
            }
        }

        result.items_attempted = (passwordless.len() + humans.len()) as i32;

        if self.dry_run {
            for name in &passwordless {
                ui::markup_line(&format!(
                    "[cyan]Would lock: {} [dim](no password set)[/][/]",
                    ui::escape(name)
                ));
            }
            result.message = format!(
                "DRY RUN: would lock {} passwordless accounts and age {} accounts.",
                passwordless.len(),
                humans.len()
            );
            return result;
        }

        let mut failures: Vec<String> = Vec::new();
        for name in &passwordless {
            // Locked, not given a password. A generated password would let the
            // account keep working with a credential nobody has been told, and
            // the README does not authorise it in the first place - locking is
            // the reversible option.
            match user_ops::lock(name, "the account had no password at all").await {
                Ok(()) => {
                    result.items_succeeded += 1;
                    ui::markup_line(&format!(
                        "[green]✓ Locked: {} [dim](had no password)[/][/]",
                        ui::escape(name)
                    ));
                }
                Err(e) => failures.push(format!("{name}: {e}")),
            }
        }

        for account in &humans {
            match user_ops::set_ageing(&account.name, MAX_DAYS, MIN_DAYS, WARN_DAYS).await {
                Ok(()) => result.items_succeeded += 1,
                Err(e) => failures.push(format!("{}: {e}", account.name)),
            }
        }

        result.success = failures.is_empty();
        result.message = format!(
            "{} passwordless accounts locked, {} accounts aged; {} findings reported.",
            passwordless.len(),
            humans.len(),
            doubles.len() + shells.len()
        );
        if !failures.is_empty() {
            result.error_details = Some(failures.join("; "));
        }
        result
    }

    async fn verify(&mut self) -> bool {
        // Only the things the task actually changed are verified. The findings
        // are reported, not remediated, so failing verification on them would
        // report the task as broken for correctly declining to act.
        for account in user_ops::accounts().await.iter().filter(|a| a.is_human()) {
            if user_ops::password_state(&account.name).await.as_deref() == Some("no password") {
                return false;
            }
        }
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn account(name: &str, uid: u32, shell: &str) -> Account {
        Account {
            name: name.to_string(),
            uid,
            gid: uid,
            comment: String::new(),
            home: format!("/home/{name}"),
            shell: shell.to_string(),
        }
    }

    /// A second uid 0 account is a superuser `sudo` never logs. It is the
    /// highest-value finding this task produces.
    #[test]
    fn a_second_uid_zero_account_is_found() {
        let accounts = vec![
            account("root", 0, "/bin/bash"),
            account("toor", 0, "/bin/bash"),
            account("alice", 1000, "/bin/bash"),
        ];
        assert_eq!(duplicate_superusers(&accounts), ["toor"]);
    }

    #[test]
    fn root_alone_is_not_a_duplicate() {
        let accounts = vec![account("root", 0, "/bin/bash")];
        assert!(duplicate_superusers(&accounts).is_empty());
    }

    /// `www-data` with a real shell is a backdoor wearing a familiar name.
    #[test]
    fn a_service_account_given_a_shell_is_found() {
        let accounts = vec![
            account("www-data", 33, "/bin/bash"),
            account("daemon", 1, "/usr/sbin/nologin"),
            account("alice", 1000, "/bin/bash"),
        ];
        assert_eq!(service_accounts_with_shells(&accounts), ["www-data"]);
    }

    /// Root has a shell by design, and flagging it every run would train the
    /// reader to ignore this finding.
    #[test]
    fn root_having_a_shell_is_not_a_finding() {
        let accounts = vec![account("root", 0, "/bin/bash")];
        assert!(service_accounts_with_shells(&accounts).is_empty());
    }

    #[test]
    fn a_human_account_with_a_shell_is_not_a_finding() {
        let accounts = vec![account("alice", 1000, "/bin/bash")];
        assert!(service_accounts_with_shells(&accounts).is_empty());
    }
}
