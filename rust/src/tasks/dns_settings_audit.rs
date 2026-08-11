//! Audits DNS settings for security compliance.

use crate::command;
use crate::impl_task_meta;
use crate::models::{SystemInfo, TaskResult};
use crate::tasks::Task;
use crate::ui;
use async_trait::async_trait;

const INSECURE_DNS: &[&str] = &["8.8.8.8", "8.8.4.4", "1.1.1.1", "1.0.0.1"];

pub struct DnsSettingsAuditTask {
    name: String,
    description: String,
    dry_run: bool,
}

impl DnsSettingsAuditTask {
    pub fn new() -> Self {
        Self {
            name: "DNS Settings Audit".to_string(),
            description: "Audits DNS settings for security compliance.".to_string(),
            dry_run: false,
        }
    }
}

impl Default for DnsSettingsAuditTask {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl Task for DnsSettingsAuditTask {
    impl_task_meta!();

    async fn read_system_state(&mut self) -> SystemInfo {
        let (_success, output, error) =
            command::execute("netsh", Some("interface ip show dns")).await;
        SystemInfo {
            raw_output: Some(output),
            error_output: error,
            ..Default::default()
        }
    }

    async fn execute(&mut self) -> TaskResult {
        let (success, output, error) =
            command::execute("netsh", Some("interface ip show dns")).await;
        let mut details: Vec<String> = Vec::new();
        if !success {
            details.push(format!("Failed to read DNS settings: {}", error.clone().unwrap_or_default()));
            ui::markup_line(&format!(
                "[red]✗ Failed to read DNS settings: {}[/]",
                ui::escape(&error.unwrap_or_default())
            ));
            return TaskResult {
                task_name: self.name.clone(),
                success: false,
                message: details.join("\n"),
                ..Default::default()
            };
        }
        details.push("DNS settings output:".to_string());
        for l in output.split(['\n', '\r']).filter(|l| !l.is_empty()) {
            details.push(format!("  {}", l.trim()));
        }
        let found: Vec<&str> = INSECURE_DNS
            .iter()
            .copied()
            .filter(|dns| output.contains(dns))
            .collect();
        if found.is_empty() {
            details.push("No insecure DNS servers found.".to_string());
            ui::markup_line("[green]✓ No insecure DNS servers found[/]");
            return TaskResult {
                task_name: self.name.clone(),
                success: true,
                message: details.join("\n"),
                ..Default::default()
            };
        }
        details.push(format!("Insecure DNS servers found: {}", found.join(", ")));
        ui::markup_line(&format!(
            "[red]✗ Insecure DNS servers found: {}[/]",
            ui::escape(&found.join(", "))
        ));
        TaskResult {
            task_name: self.name.clone(),
            success: false,
            message: details.join("\n"),
            ..Default::default()
        }
    }

    async fn verify(&mut self) -> bool {
        let (_success, output, _error) =
            command::execute("netsh", Some("interface ip show dns")).await;
        !INSECURE_DNS.iter().any(|dns| output.contains(dns))
    }
}
