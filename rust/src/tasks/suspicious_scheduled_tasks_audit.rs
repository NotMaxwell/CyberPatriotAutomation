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

/// One scheduled task as reported by `schtasks /query /fo LIST /v`.
struct ScheduledTask {
    name: String,
    command: String,
}

/// Parse `schtasks /query /fo LIST /v` output into task records.
///
/// The verbose LIST format emits one `Field: value` block per task, separated
/// by blank lines. Scanning the output line-by-line (as this used to) conflated
/// fields across tasks: a keyword appearing in any field of any task was enough
/// to mark a *different* task suspicious.
fn parse_scheduled_tasks(output: &str) -> Vec<ScheduledTask> {
    let mut tasks = Vec::new();
    let mut name: Option<String> = None;
    let mut command = String::new();

    let flush = |name: &mut Option<String>, command: &mut String, tasks: &mut Vec<ScheduledTask>| {
        if let Some(n) = name.take() {
            tasks.push(ScheduledTask {
                name: n,
                command: std::mem::take(command),
            });
        } else {
            command.clear();
        }
    };

    for line in output.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        let Some((field, value)) = trimmed.split_once(':') else {
            continue;
        };
        let field = field.trim().to_lowercase();
        let value = value.trim().to_string();

        match field.as_str() {
            // A new TaskName marks the start of the next record.
            "taskname" => {
                flush(&mut name, &mut command, &mut tasks);
                name = Some(value);
            }
            "task to run" => command = value,
            _ => {}
        }
    }
    flush(&mut name, &mut command, &mut tasks);
    tasks
}

/// Is this one of the scheduled tasks Windows ships with?
///
/// Built-in tasks live under `\Microsoft\`. Many of them legitimately run
/// `powershell.exe` or `cmd.exe`, and plenty are named "...Remote...", so the
/// keyword list matches them readily. Disabling them breaks Windows
/// functionality and scores nothing, so they are never touched.
fn is_builtin_task(name: &str) -> bool {
    let normalized = name.trim_start_matches('\\').to_lowercase();
    normalized.starts_with("microsoft\\")
}

/// Tasks worth flagging: non-built-in, with a suspicious name or command.
fn suspicious_tasks(output: &str) -> Vec<ScheduledTask> {
    parse_scheduled_tasks(output)
        .into_iter()
        .filter(|t| !t.name.is_empty() && !is_builtin_task(&t.name))
        .filter(|t| {
            SUSPICIOUS_KEYWORDS
                .iter()
                .any(|k| contains_ci(&t.name, k) || contains_ci(&t.command, k))
        })
        .collect()
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

        let all_tasks = parse_scheduled_tasks(&output);
        details.push(format!("Total scheduled tasks found: {}", all_tasks.len()));

        let suspicious = suspicious_tasks(&output);
        details.push(format!("Suspicious keywords checked: {}", SUSPICIOUS_KEYWORDS.join(", ")));
        details.push("Built-in \\Microsoft\\ tasks are excluded from removal.".to_string());

        if suspicious.is_empty() {
            details.push("No suspicious scheduled tasks found.".to_string());
            ui::markup_line("[green]✓ No suspicious scheduled tasks found[/]");
            return TaskResult {
                task_name: self.name.clone(),
                success: true,
                message: details.join("\n"),
                ..Default::default()
            };
        }
        details.push(format!("Suspicious tasks: {}", suspicious.len()));

        let mut disabled_tasks: Vec<String> = Vec::new();
        let mut failed_to_disable: Vec<String> = Vec::new();
        for task in &suspicious {
            let (disable_success, _out, disable_error) = command::execute(
                "schtasks",
                Some(&format!("/Change /TN \"{}\" /Disable", task.name)),
            )
            .await;
            if disable_success {
                ui::markup_line(&format!(
                    "[yellow]Disabled suspicious task: {}[/]",
                    ui::escape(&task.name)
                ));
                disabled_tasks.push(task.name.clone());
            } else {
                let e = disable_error.unwrap_or_default();
                ui::markup_line(&format!(
                    "[red]✗ Failed to disable task: {} ({})[/]",
                    ui::escape(&task.name),
                    ui::escape(&e)
                ));
                failed_to_disable.push(format!("{} ({})", task.name, e));
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
            // Success means every suspicious task was dealt with. The previous
            // `!disabled_tasks.is_empty() && ...` also reported failure whenever
            // there was simply nothing to disable.
            success: failed_to_disable.is_empty(),
            message: details.join("\n"),
            error_details: (!failed_to_disable.is_empty()).then(|| failed_to_disable.join("\n")),
            ..Default::default()
        }
    }

    async fn verify(&mut self) -> bool {
        let (_success, output, _error) =
            command::execute("schtasks", Some("/query /fo LIST /v")).await;
        // Use the same detection as `execute`. Previously any line mentioning a
        // keyword failed verification, including the many built-in Windows tasks
        // that run powershell.exe - so this could never return true on a real
        // machine, no matter what the task did.
        suspicious_tasks(&output).is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SCHTASKS_OUTPUT: &str = "\
Folder: \\
HostName:      CYBERPC
TaskName:      \\Microsoft\\Windows\\UpdateOrchestrator\\Reboot
Task To Run:   powershell.exe -NoProfile Update
Status:        Ready

HostName:      CYBERPC
TaskName:      \\GoodBackup
Task To Run:   C:\\Tools\\backup.exe
Status:        Ready

HostName:      CYBERPC
TaskName:      \\BitcoinMiner
Task To Run:   C:\\Users\\Public\\miner.exe
Status:        Ready

HostName:      CYBERPC
TaskName:      \\Updater
Task To Run:   cmd.exe /c backdoor.bat
Status:        Ready
";

    #[test]
    fn parse_scheduled_tasks_reads_one_record_per_task() {
        let tasks = parse_scheduled_tasks(SCHTASKS_OUTPUT);
        let names: Vec<&str> = tasks.iter().map(|t| t.name.as_str()).collect();
        assert_eq!(
            names,
            vec![
                "\\Microsoft\\Windows\\UpdateOrchestrator\\Reboot",
                "\\GoodBackup",
                "\\BitcoinMiner",
                "\\Updater",
            ]
        );
        assert_eq!(tasks[1].command, "C:\\Tools\\backup.exe");
    }

    #[test]
    fn builtin_microsoft_tasks_are_never_flagged() {
        let flagged = suspicious_tasks(SCHTASKS_OUTPUT);
        assert!(
            !flagged
                .iter()
                .any(|t| t.name.to_lowercase().contains("microsoft")),
            "built-in Windows tasks must not be disabled, got {:?}",
            flagged.iter().map(|t| &t.name).collect::<Vec<_>>()
        );
    }

    #[test]
    fn suspicious_tasks_flags_bad_names_and_commands() {
        let flagged = suspicious_tasks(SCHTASKS_OUTPUT);
        let names: Vec<&str> = flagged.iter().map(|t| t.name.as_str()).collect();

        // Flagged by name ("bitcoin"/"miner") and by command ("backdoor"/"cmd.exe").
        assert!(names.contains(&"\\BitcoinMiner"), "got {names:?}");
        assert!(names.contains(&"\\Updater"), "got {names:?}");
        // A benign third-party task stays untouched.
        assert!(!names.contains(&"\\GoodBackup"), "got {names:?}");
    }
}
