//! Audits shared folders to ensure only ADMIN$, C$, IPC$ exist.

use crate::command;
use crate::impl_task_meta;
use crate::models::{SystemInfo, TaskResult};
use crate::tasks::Task;
use crate::ui;
use async_trait::async_trait;

const ALLOWED: &[&str] = &["ADMIN$", "C$", "IPC$"];

pub struct SharedFoldersAuditTask {
    name: String,
    description: String,
    dry_run: bool,
}

impl SharedFoldersAuditTask {
    pub fn new() -> Self {
        Self {
            name: "Shared Folders Audit".to_string(),
            description:
                "Audits shared folders (fsmgmt.msc) to ensure only ADMIN$, C$, IPC$ exist."
                    .to_string(),
            dry_run: false,
        }
    }
}

impl Default for SharedFoldersAuditTask {
    fn default() -> Self {
        Self::new()
    }
}

/// Extract share names from `net share` output.
///
/// Only reached when the Windows API is unavailable. The output is a table
/// wrapped in a header and a trailing status line:
///
/// ```text
/// Share name   Resource                        Remark
/// -------------------------------------------------------------------------------
/// C$           C:\                             Default share
/// IPC$                                         Remote IPC
/// The command completed successfully.
/// ```
///
/// Taking the first token of every line containing a space - as this used to -
/// also picked up "Share" from the header and "The" from the trailing status
/// line, so the task tried to `net share Share /delete` on entries that were
/// never shares. Read only the rows between the separator and the status line.
fn parse_shares(output: &str) -> Vec<String> {
    let mut shares = Vec::new();
    let mut past_separator = false;
    for line in output.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        if trimmed.starts_with("---") {
            past_separator = true;
            continue;
        }
        if !past_separator {
            continue;
        }
        if trimmed.starts_with("The command completed") {
            break;
        }
        if let Some(name) = trimmed.split_whitespace().next() {
            shares.push(name.to_string());
        }
    }
    shares
}

/// The shares on this machine.
///
/// Returns `None` when the list could not be read at all, so "no shares" and
/// "could not look" stay distinguishable.
async fn read_shares() -> Option<Vec<String>> {
    // netapi32 returns the share list as data, so there is nothing to parse and
    // nothing that depends on the console language. `parse_shares` stays as the
    // fallback for the rare case the call itself fails.
    #[cfg(windows)]
    if let Some(shares) = crate::native::shares::enumerate() {
        return Some(shares);
    }

    let (success, output, _error) = command::execute("net", Some("share")).await;
    success.then(|| parse_shares(&output))
}

/// Remove a share, and prove it is gone.
async fn remove_share(share: &str) -> Result<(), String> {
    crate::remediation::apply(
        &format!("Share {share}"),
        "removed - only ADMIN$, C$ and IPC$ belong on a competition image",
        // "absent" has to be a readable state rather than the `None` that means
        // "could not look", so the share list is re-read and searched.
        || async {
            read_shares().await.map(|shares| {
                if shares.iter().any(|s| s.eq_ignore_ascii_case(share)) {
                    "present".to_string()
                } else {
                    "absent".to_string()
                }
            })
        },
        |s| s == "absent",
        "removed the share",
        || remove_share_core(share),
    )
    .await
}

async fn remove_share_core(share: &str) -> Result<(), String> {
    #[cfg(windows)]
    {
        crate::native::shares::delete(share)
    }

    #[cfg(not(windows))]
    {
        // /y answers the "There are open files ... force them closed? (Y/N)"
        // prompt that `net share /delete` asks when the share is in use.
        // Without it the command waits on a keypress it will never get, and
        // aborts having deleted nothing.
        let (success, _out, error) =
            command::execute("net", Some(&format!("share {share} /delete /y"))).await;
        if success {
            Ok(())
        } else {
            Err(error.unwrap_or_else(|| "net share /delete failed".to_string()))
        }
    }
}

fn unauthorized(found: &[String]) -> Vec<String> {
    found
        .iter()
        .filter(|s| !ALLOWED.iter().any(|a| a.eq_ignore_ascii_case(s)))
        .cloned()
        .collect()
}

#[async_trait]
impl Task for SharedFoldersAuditTask {
    impl_task_meta!();

    async fn read_system_state(&mut self) -> SystemInfo {
        let shares = read_shares().await;
        SystemInfo {
            raw_output: Some(shares.clone().unwrap_or_default().join("\n")),
            error_output: shares
                .is_none()
                .then(|| "Could not read the share list".to_string()),
            ..Default::default()
        }
    }

    async fn execute(&mut self) -> TaskResult {
        let Some(found) = read_shares().await else {
            return TaskResult {
                task_name: self.name.clone(),
                success: false,
                message: "Could not read the share list.".to_string(),
                error_details: Some(
                    "Neither the Windows API nor `net share` returned a share list.".to_string(),
                ),
                ..Default::default()
            };
        };
        let unauthorized = unauthorized(&found);

        let mut details: Vec<String> = Vec::new();
        details.push(format!("Shares found: {}", found.join(", ")));
        details.push(format!("Allowed shares: {}", ALLOWED.join(", ")));
        if !unauthorized.is_empty() {
            details.push(format!("Unauthorized shares: {}", unauthorized.join(", ")));
        } else {
            details.push("No unauthorized shares found.".to_string());
        }

        if self.dry_run {
            ui::markup_line(
                "[yellow]DRY RUN: Previewing shared folders audit (no changes will be made)[/]",
            );
            if !unauthorized.is_empty() {
                details.push(format!("Would remove: {}", unauthorized.join(", ")));
            }
            return TaskResult {
                task_name: self.name.clone(),
                success: true,
                message: details.join("\n"),
                ..Default::default()
            };
        }

        let mut removed: Vec<String> = Vec::new();
        let mut failures: Vec<String> = Vec::new();

        for share in &unauthorized {
            match remove_share(share).await {
                Ok(()) => {
                    removed.push(share.clone());
                    ui::markup_line(&format!("[green]✓ Removed share: {}[/]", ui::escape(share)));
                }
                Err(e) => {
                    failures.push(format!("{share}: {e}"));
                    ui::markup_line(&format!(
                        "[red]✗ Failed to remove share: {} ({})[/]",
                        ui::escape(share),
                        ui::escape(&e)
                    ));
                }
            }
        }

        if removed.is_empty() {
            details.push("No shares needed removal.".to_string());
        } else {
            details.push(format!("Removed: {}", removed.join(", ")));
        }
        if !failures.is_empty() {
            details.push(format!("Failed to remove: {}", failures.join("; ")));
        }

        TaskResult {
            task_name: self.name.clone(),
            // Success means the remediation went through. The previous
            // `unauthorized.is_empty()` reported failure precisely when the task
            // had found and removed offending shares.
            success: failures.is_empty(),
            message: details.join("\n"),
            error_details: (!failures.is_empty()).then(|| failures.join("\n")),
            ..Default::default()
        }
    }

    async fn verify(&mut self) -> bool {
        // A read failure is not proof the machine is clean.
        match read_shares().await {
            Some(found) => unauthorized(&found).is_empty(),
            None => false,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const NET_SHARE_OUTPUT: &str = "\
Share name   Resource                        Remark

-------------------------------------------------------------------------------
C$           C:\\                             Default share
IPC$                                         Remote IPC
ADMIN$       C:\\Windows                      Remote Admin
Docs         C:\\Users\\Public\\Docs
The command completed successfully.

";

    #[test]
    fn parse_shares_ignores_header_and_status_lines() {
        let shares = parse_shares(NET_SHARE_OUTPUT);
        assert_eq!(shares, vec!["C$", "IPC$", "ADMIN$", "Docs"]);
        // "Share" (header) and "The" (status line) used to be parsed as shares.
        assert!(!shares.iter().any(|s| s == "Share" || s == "The"));
    }

    #[test]
    fn only_non_default_shares_are_unauthorized() {
        let shares = parse_shares(NET_SHARE_OUTPUT);
        assert_eq!(unauthorized(&shares), vec!["Docs"]);
    }
}
