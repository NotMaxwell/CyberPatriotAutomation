//! Audits the Windows hosts file for unauthorized entries.

use crate::impl_task_meta;
use crate::models::{SystemInfo, TaskResult};
use crate::tasks::Task;
use crate::ui;
use async_trait::async_trait;

const HOSTS_FILE_PATH: &str = r"C:\Windows\System32\drivers\etc\hosts";
const ALLOWED_ENTRIES: &[&str] = &["127.0.0.1       localhost", "::1             localhost"];

pub struct HostsFileAuditTask {
    name: String,
    description: String,
    dry_run: bool,
}

impl HostsFileAuditTask {
    pub fn new() -> Self {
        Self {
            name: "Hosts File Audit".to_string(),
            description: "Audits the Windows hosts file for unauthorized entries.".to_string(),
            dry_run: false,
        }
    }
}

impl Default for HostsFileAuditTask {
    fn default() -> Self {
        Self::new()
    }
}

fn read_lines() -> Result<Vec<String>, String> {
    std::fs::read_to_string(HOSTS_FILE_PATH)
        .map(|s| s.lines().map(|l| l.to_string()).collect())
        .map_err(|e| e.to_string())
}

fn unauthorized_entries(lines: &[String]) -> Vec<String> {
    lines
        .iter()
        .map(|l| l.trim().to_string())
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
        .filter(|l| !ALLOWED_ENTRIES.iter().any(|a| a.eq_ignore_ascii_case(l)))
        .collect()
}

#[async_trait]
impl Task for HostsFileAuditTask {
    impl_task_meta!();

    async fn read_system_state(&mut self) -> SystemInfo {
        match read_lines() {
            Ok(lines) => SystemInfo {
                raw_output: Some(lines.join("\n")),
                error_output: None,
                ..Default::default()
            },
            Err(e) => SystemInfo {
                raw_output: Some(String::new()),
                error_output: Some(e),
                ..Default::default()
            },
        }
    }

    async fn execute(&mut self) -> TaskResult {
        let lines = match read_lines() {
            Ok(lines) => lines,
            Err(e) => {
                ui::markup_line(&format!("[red]✗ Failed to read hosts file: {}[/]", ui::escape(&e)));
                return TaskResult {
                    task_name: self.name.clone(),
                    success: false,
                    message: e,
                    ..Default::default()
                };
            }
        };

        let unauthorized = unauthorized_entries(&lines);

        let mut details: Vec<String> = Vec::new();
        let entries: Vec<String> = lines
            .iter()
            .map(|l| l.trim().to_string())
            .filter(|l| !l.is_empty())
            .collect();
        details.push(format!("Hosts file entries found: {}", entries.join(", ")));
        details.push(format!("Allowed entries: {}", ALLOWED_ENTRIES.join(", ")));
        if !unauthorized.is_empty() {
            details.push(format!("Unauthorized entries: {}", unauthorized.join(", ")));
        } else {
            details.push("No unauthorized hosts entries found.".to_string());
        }

        if self.dry_run {
            ui::markup_line("[yellow]DRY RUN: Previewing hosts file audit (no changes will be made)[/]");
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

        let new_lines: Vec<String> = lines
            .iter()
            .filter(|l| {
                l.trim().is_empty()
                    || l.trim().starts_with('#')
                    || ALLOWED_ENTRIES.iter().any(|a| a.eq_ignore_ascii_case(l.trim()))
            })
            .cloned()
            .collect();

        match std::fs::write(HOSTS_FILE_PATH, new_lines.join("\n")) {
            Ok(_) => {
                if !unauthorized.is_empty() {
                    details.push(format!("Removed: {}", unauthorized.join(", ")));
                } else {
                    details.push("No entries needed removal.".to_string());
                }
                ui::markup_line(&format!(
                    "[green]✓ Removed unauthorized hosts entries: {}[/]",
                    ui::escape(&unauthorized.join(", "))
                ));
                TaskResult {
                    task_name: self.name.clone(),
                    success: unauthorized.is_empty(),
                    message: details.join("\n"),
                    ..Default::default()
                }
            }
            Err(e) => {
                ui::markup_line(&format!("[red]✗ Failed to update hosts file: {}[/]", ui::escape(&e.to_string())));
                details.push(format!("Failed to update hosts file: {e}"));
                TaskResult {
                    task_name: self.name.clone(),
                    success: false,
                    message: details.join("\n"),
                    ..Default::default()
                }
            }
        }
    }

    async fn verify(&mut self) -> bool {
        match read_lines() {
            Ok(lines) => unauthorized_entries(&lines).is_empty(),
            Err(_) => false,
        }
    }
}
