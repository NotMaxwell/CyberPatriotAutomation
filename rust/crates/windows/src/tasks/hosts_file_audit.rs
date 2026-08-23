//! Audits the Windows hosts file for unauthorized entries.

use async_trait::async_trait;
use pinnacle_core::Task;
use pinnacle_core::impl_task_meta;
use pinnacle_core::models::{SystemInfo, TaskResult};
use pinnacle_core::ui;

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

/// Collapse runs of whitespace so entries compare on content, not formatting.
///
/// `ALLOWED_ENTRIES` is written with a fixed run of spaces. Comparing raw
/// strings meant a hosts file using a tab or a different number of spaces -
/// which is entirely normal - failed to match, so the legitimate localhost
/// mapping was classified as unauthorized and deleted.
fn normalize_entry(line: &str) -> String {
    line.split_whitespace().collect::<Vec<_>>().join(" ")
}

fn is_allowed_entry(line: &str) -> bool {
    let normalized = normalize_entry(line);
    ALLOWED_ENTRIES
        .iter()
        .any(|a| normalize_entry(a).eq_ignore_ascii_case(&normalized))
}

fn unauthorized_entries(lines: &[String]) -> Vec<String> {
    lines
        .iter()
        .map(|l| l.trim().to_string())
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
        .filter(|l| !is_allowed_entry(l))
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
                ui::markup_line(&format!(
                    "[red]✗ Failed to read hosts file: {}[/]",
                    ui::escape(&e)
                ));
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
            ui::markup_line(
                "[yellow]DRY RUN: Previewing hosts file audit (no changes will be made)[/]",
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

        // Nothing to do - don't rewrite a system file for no reason.
        if unauthorized.is_empty() {
            details.push("No entries needed removal.".to_string());
            ui::markup_line("[green]✓ No unauthorized hosts entries found[/]");
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
                l.trim().is_empty() || l.trim().starts_with('#') || is_allowed_entry(l.trim())
            })
            .cloned()
            .collect();

        // Windows tolerates LF here, but the hosts file is conventionally CRLF
        // and ends with a newline; preserve both.
        let mut contents = new_lines.join("\r\n");
        contents.push_str("\r\n");

        let written = pinnacle_core::remediation::apply(
            HOSTS_FILE_PATH,
            &format!(
                "only loopback entries; {} redirect(s) removed",
                unauthorized.len()
            ),
            || async {
                read_lines()
                    .ok()
                    .map(|l| format!("{} unauthorized entries", unauthorized_entries(&l).len()))
            },
            |s| s == "0 unauthorized entries",
            &format!("rewrote the file without: {}", unauthorized.join(", ")),
            || async {
                std::fs::write(HOSTS_FILE_PATH, contents).map_err(|e: std::io::Error| e.to_string())
            },
        )
        .await;

        match written {
            Ok(_) => {
                details.push(format!("Removed: {}", unauthorized.join(", ")));
                ui::markup_line(&format!(
                    "[green]✓ Removed unauthorized hosts entries: {}[/]",
                    ui::escape(&unauthorized.join(", "))
                ));
                TaskResult {
                    task_name: self.name.clone(),
                    // Success reflects the remediation having been applied. The
                    // previous `unauthorized.is_empty()` inverted this: cleaning
                    // up entries reported the task as failed, and only a file
                    // that needed no work at all counted as a success.
                    success: true,
                    message: details.join("\n"),
                    ..Default::default()
                }
            }
            Err(e) => {
                ui::markup_line(&format!(
                    "[red]✗ Failed to update hosts file: {}[/]",
                    ui::escape(&e)
                ));
                details.push(format!("Failed to update hosts file: {e}"));
                TaskResult {
                    task_name: self.name.clone(),
                    success: false,
                    message: details.join("\n"),
                    error_details: Some(e),
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

#[cfg(test)]
mod tests {
    use super::*;

    fn lines(raw: &str) -> Vec<String> {
        raw.lines().map(|l| l.to_string()).collect()
    }

    #[test]
    fn localhost_entries_are_allowed_regardless_of_spacing() {
        // Tabs and differing space runs are entirely normal in a hosts file.
        // Exact string comparison used to classify these as unauthorized and
        // delete the legitimate localhost mapping.
        let hosts = lines("# comment\n127.0.0.1\tlocalhost\n::1   localhost\n");
        assert!(unauthorized_entries(&hosts).is_empty());
    }

    #[test]
    fn redirected_domains_are_unauthorized() {
        let hosts = lines(
            "127.0.0.1       localhost\n127.0.0.1 www.google.com\n0.0.0.0 update.microsoft.com\n",
        );
        let bad = unauthorized_entries(&hosts);
        assert_eq!(
            bad,
            vec!["127.0.0.1 www.google.com", "0.0.0.0 update.microsoft.com"]
        );
    }

    #[test]
    fn comments_and_blank_lines_are_ignored() {
        let hosts = lines("\n# Copyright (c) 1993-2009 Microsoft Corp.\n#\tsource server\n\n");
        assert!(unauthorized_entries(&hosts).is_empty());
    }
}
