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
            description: "Audits shared folders (fsmgmt.msc) to ensure only ADMIN$, C$, IPC$ exist."
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

fn parse_shares(output: &str) -> Vec<String> {
    output
        .split('\n')
        .filter(|l| l.contains(' '))
        .map(|l| l.split(' ').next().unwrap_or("").trim().to_string())
        .filter(|s| !s.is_empty())
        .collect()
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
        let (_success, output, error) = command::execute("net", Some("share")).await;
        SystemInfo {
            raw_output: Some(output),
            error_output: error,
            ..Default::default()
        }
    }

    async fn execute(&mut self) -> TaskResult {
        let (_success, output, _error) = command::execute("net", Some("share")).await;
        let found = parse_shares(&output);
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
            ui::markup_line("[yellow]DRY RUN: Previewing shared folders audit (no changes will be made)[/]");
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

        for share in &unauthorized {
            let (del_success, _out, del_err) =
                command::execute("net", Some(&format!("share {share} /delete"))).await;
            if del_success {
                ui::markup_line(&format!("[green]✓ Removed share: {}[/]", ui::escape(share)));
            } else {
                ui::markup_line(&format!(
                    "[red]✗ Failed to remove share: {} ({})[/]",
                    ui::escape(share),
                    ui::escape(&del_err.unwrap_or_default())
                ));
            }
        }
        if !unauthorized.is_empty() {
            details.push(format!("Removed: {}", unauthorized.join(", ")));
        } else {
            details.push("No shares needed removal.".to_string());
        }

        TaskResult {
            task_name: self.name.clone(),
            success: unauthorized.is_empty(),
            message: details.join("\n"),
            ..Default::default()
        }
    }

    async fn verify(&mut self) -> bool {
        let (_success, output, _error) = command::execute("net", Some("share")).await;
        let found = parse_shares(&output);
        unauthorized(&found).is_empty()
    }
}
