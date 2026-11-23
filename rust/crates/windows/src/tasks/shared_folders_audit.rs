//! Audits shared folders to ensure only ADMIN$, C$, IPC$ exist (plus NETLOGON
//! and SYSVOL on a domain controller, where removing them breaks logon).

use async_trait::async_trait;
use pinnacle_core::Task;
use pinnacle_core::command;
use pinnacle_core::impl_task_meta;
use pinnacle_core::models::{SystemInfo, TaskResult};
use pinnacle_core::ui;

const ALLOWED: &[&str] = &["ADMIN$", "C$", "IPC$"];

/// The shares a domain controller publishes for logon scripts and group policy.
/// Removing them breaks every domain client, and the scenario penalises it.
const DOMAIN_CONTROLLER_SHARES: &[&str] = &["NETLOGON", "SYSVOL"];

/// The shares that belong on this machine.
fn allowed_shares(is_dc: bool) -> Vec<&'static str> {
    let mut allowed = ALLOWED.to_vec();
    if is_dc {
        allowed.extend_from_slice(DOMAIN_CONTROLLER_SHARES);
    }
    allowed
}

/// Is this a domain controller? `ProductType` is `LanmanNt` only on one.
/// Unreadable counts as "not", which leaves the stricter list in force.
async fn is_domain_controller() -> bool {
    crate::registry_ops::get_string(
        r"HKLM\SYSTEM\CurrentControlSet\Control\ProductOptions",
        "ProductType",
    )
    .await
    .is_some_and(|t| t.trim().eq_ignore_ascii_case("LanmanNt"))
}

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
    pinnacle_core::remediation::apply(
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

fn unauthorized(found: &[String], is_dc: bool) -> Vec<String> {
    let allowed = allowed_shares(is_dc);
    found
        .iter()
        .filter(|s| !allowed.iter().any(|a| a.eq_ignore_ascii_case(s)))
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
        let is_dc = is_domain_controller().await;
        let unauthorized = unauthorized(&found, is_dc);

        let mut details: Vec<String> = Vec::new();
        details.push(format!("Shares found: {}", found.join(", ")));
        details.push(format!(
            "Allowed shares: {}",
            allowed_shares(is_dc).join(", ")
        ));
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
            Some(found) => unauthorized(&found, is_domain_controller().await).is_empty(),
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
        assert_eq!(unauthorized(&shares, false), vec!["Docs"]);
    }

    #[test]
    fn a_member_server_allows_only_the_defaults() {
        assert_eq!(allowed_shares(false), vec!["ADMIN$", "C$", "IPC$"]);
    }

    #[test]
    fn a_domain_controller_also_allows_netlogon_and_sysvol() {
        let allowed = allowed_shares(true);
        assert!(allowed.contains(&"NETLOGON") && allowed.contains(&"SYSVOL"));
        assert!(allowed.contains(&"C$"));
    }

    #[test]
    fn netlogon_and_sysvol_are_unauthorized_off_a_domain_controller() {
        let found: Vec<String> = ["C$", "NETLOGON", "sysvol", "Docs"]
            .map(String::from)
            .to_vec();
        assert_eq!(
            unauthorized(&found, false),
            vec!["NETLOGON", "sysvol", "Docs"]
        );
        assert_eq!(unauthorized(&found, true), vec!["Docs"]);
    }
}
