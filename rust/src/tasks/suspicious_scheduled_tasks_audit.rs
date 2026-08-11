//! Audits and disables suspicious scheduled tasks.

use crate::command;
use crate::impl_task_meta;
use crate::models::{SystemInfo, TaskResult};
use crate::tasks::Task;
use crate::ui;
use async_trait::async_trait;

const SUSPICIOUS_KEYWORDS: &[&str] = &[
    "hack",
    "malware",
    "bitcoin",
    "crypto",
    "miner",
    "backdoor",
    "remote",
    "powershell",
    "cmd.exe",
];

pub struct SuspiciousScheduledTasksAuditTask {
    name: String,
    description: String,
    dry_run: bool,
}

impl SuspiciousScheduledTasksAuditTask {
    pub fn new() -> Self {
        Self {
            name: "Suspicious Scheduled Tasks Audit".to_string(),
            description: "Audits and disables suspicious scheduled tasks.".to_string(),
            dry_run: false,
        }
    }
}

impl Default for SuspiciousScheduledTasksAuditTask {
    fn default() -> Self {
        Self::new()
    }
}

fn contains_ci(haystack: &str, needle: &str) -> bool {
    haystack.to_lowercase().contains(&needle.to_lowercase())
}

#[async_trait]
impl Task for SuspiciousScheduledTasksAuditTask {
    impl_task_meta!();

    async fn read_system_state(&mut self) -> SystemInfo {
        let (_success, output, error) =
            command::execute("schtasks", Some("/query /fo LIST /v")).await;
        SystemInfo {
            raw_output: Some(output),
            error_output: error,
            ..Default::default()
        }
    }

    async fn execute(&mut self) -> TaskResult {
        if self.dry_run {
            ui::markup_line("[yellow]DRY RUN: Previewing scheduled tasks audit (no changes will be made)[/]");
            return TaskResult {
                task_name: self.name.clone(),
                success: true,
                message: "DRY RUN: Scheduled tasks audit previewed.".to_string(),
                ..Default::default()
            };
        }

        let (success, output, error) =
            command::execute("schtasks", Some("/query /fo LIST /v")).await;
        let mut details: Vec<String> = Vec::new();
        if !success {
            details.push(format!("Failed to query scheduled tasks: {}", error.clone().unwrap_or_default()));
            ui::markup_line(&format!(
                "[red]✗ Failed to query scheduled tasks: {}[/]",
                ui::escape(&error.unwrap_or_default())
            ));
            return TaskResult {
                task_name: self.name.clone(),
                success: false,
                message: details.join("\n"),
                ..Default::default()
            };
        }

        let lines: Vec<&str> = output.split(['\n', '\r']).filter(|l| !l.is_empty()).collect();
        let all_task_names: Vec<String> = lines
            .iter()
            .filter(|l| l.to_lowercase().starts_with("taskname:"))
            .map(|l| l["TaskName:".len()..].trim().to_string())
            .collect();
        details.push(format!("Total scheduled tasks found: {}", all_task_names.len()));

        let suspicious_tasks: Vec<&str> = lines
            .iter()
            .copied()
            .filter(|l| SUSPICIOUS_KEYWORDS.iter().any(|k| contains_ci(l, k)))
            .collect();
        details.push(format!("Suspicious keywords checked: {}", SUSPICIOUS_KEYWORDS.join(", ")));

        if suspicious_tasks.is_empty() {
            details.push("No suspicious scheduled tasks found.".to_string());
            ui::markup_line("[green]✓ No suspicious scheduled tasks found[/]");
            return TaskResult {
                task_name: self.name.clone(),
                success: true,
                message: details.join("\n"),
                ..Default::default()
            };
        }
        details.push(format!("Suspicious task lines: {}", suspicious_tasks.len()));

        let mut disabled_tasks: Vec<String> = Vec::new();
        let mut failed_to_disable: Vec<String> = Vec::new();
        for task_line in &suspicious_tasks {
            let name_prefix = "TaskName: ";
            if task_line.to_lowercase().starts_with(&name_prefix.to_lowercase()) {
                let task_name = task_line[name_prefix.len()..].trim().to_string();
                let (disable_success, _out, disable_error) = command::execute(
                    "schtasks",
                    Some(&format!("/Change /TN \"{task_name}\" /Disable")),
                )
                .await;
                if disable_success {
                    ui::markup_line(&format!("[yellow]Disabled suspicious task: {}[/]", ui::escape(&task_name)));
                    disabled_tasks.push(task_name);
                } else {
                    ui::markup_line(&format!(
                        "[red]✗ Failed to disable task: {} ({})[/]",
                        ui::escape(&task_name),
                        ui::escape(&disable_error.clone().unwrap_or_default())
                    ));
                    failed_to_disable.push(format!("{} ({})", task_name, disable_error.unwrap_or_default()));
                }
            }
        }
        details.push(format!(
            "Disabled tasks: {}",
            if !disabled_tasks.is_empty() {
                disabled_tasks.join(", ")
            } else {
                "None".to_string()
            }
        ));
        if !failed_to_disable.is_empty() {
            details.push(format!("Failed to disable: {}", failed_to_disable.join(", ")));
        }

        TaskResult {
            task_name: self.name.clone(),
            success: !disabled_tasks.is_empty() && failed_to_disable.is_empty(),
            message: details.join("\n"),
            ..Default::default()
        }
    }

    async fn verify(&mut self) -> bool {
        let (_success, output, _error) =
            command::execute("schtasks", Some("/query /fo LIST /v")).await;
        let lines: Vec<&str> = output.split(['\n', '\r']).filter(|l| !l.is_empty()).collect();
        !lines
            .iter()
            .any(|l| SUSPICIOUS_KEYWORDS.iter().any(|k| contains_ci(l, k)))
    }
}
