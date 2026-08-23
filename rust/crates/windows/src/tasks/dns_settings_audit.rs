//! Audits DNS settings for security compliance.

use async_trait::async_trait;
use pinnacle_core::Task;
use pinnacle_core::command;
use pinnacle_core::impl_task_meta;
use pinnacle_core::models::{SystemInfo, TaskResult};
use pinnacle_core::ui;

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

/// The DNS servers configured on every live, non-loopback interface, rendered
/// as "interface: address".
///
/// Returns `None` when they could not be read at all, so "no resolvers" and
/// "could not look" stay distinguishable.
async fn read_dns_servers() -> Option<Vec<String>> {
    #[cfg(windows)]
    if let Some(servers) = crate::native::dns::servers() {
        return Some(
            servers
                .into_iter()
                .map(|(interface, address)| format!("{interface}: {address}"))
                .collect(),
        );
    }

    let (success, output, _error) = command::execute("netsh", Some("interface ip show dns")).await;
    success.then(|| {
        output
            .split(['\n', '\r'])
            .map(|l| l.trim().to_string())
            .filter(|l| !l.is_empty())
            .collect()
    })
}

/// Which insecure resolvers appear in the configured list.
///
/// Compares whole whitespace-delimited tokens. A plain substring search matched
/// an address embedded in a longer one - "1.1.1.1" is a substring of the
/// perfectly ordinary "11.1.1.10" - producing false positives on legitimate
/// configurations.
fn insecure_servers_in(lines: &[String]) -> Vec<&'static str> {
    let tokens: Vec<&str> = lines
        .iter()
        .flat_map(|line| line.split(|c: char| c.is_whitespace() || c == ','))
        .map(|t| t.trim_matches(|c: char| c == ':' || c == '(' || c == ')'))
        .filter(|t| !t.is_empty())
        .collect();
    INSECURE_DNS
        .iter()
        .copied()
        .filter(|dns| tokens.iter().any(|t| t == dns))
        .collect()
}

#[async_trait]
impl Task for DnsSettingsAuditTask {
    impl_task_meta!();

    async fn read_system_state(&mut self) -> SystemInfo {
        let servers = read_dns_servers().await;
        SystemInfo {
            raw_output: Some(servers.clone().unwrap_or_default().join("\n")),
            error_output: servers
                .is_none()
                .then(|| "Could not read the DNS settings".to_string()),
            ..Default::default()
        }
    }

    async fn execute(&mut self) -> TaskResult {
        let mut details: Vec<String> = Vec::new();
        let Some(servers) = read_dns_servers().await else {
            details.push("Failed to read DNS settings".to_string());
            ui::markup_line("[red]✗ Failed to read DNS settings[/]");
            return TaskResult {
                task_name: self.name.clone(),
                success: false,
                message: details.join("\n"),
                ..Default::default()
            };
        };
        details.push("DNS settings output:".to_string());
        for line in &servers {
            details.push(format!("  {line}"));
        }
        let found = insecure_servers_in(&servers);
        pinnacle_core::remediation::record_finding(
            "Configured DNS servers",
            "no public resolver on any live interface",
            found.is_empty(),
            &if servers.is_empty() {
                "no interface reported a DNS server".to_string()
            } else {
                format!("read from the adapter list: {}", servers.join("; "))
            },
        );

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
        // A read failure is not proof the resolvers are clean.
        match read_dns_servers().await {
            Some(servers) => insecure_servers_in(&servers).is_empty(),
            None => false,
        }
    }
}
