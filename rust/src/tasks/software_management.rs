//! Removes prohibited software, installs required software as specified in the
//! README, and runs Windows Defender malware scans.

use crate::command;
use crate::impl_task_meta;
use crate::models::{ReadmeData, SoftwareRequirement, SystemInfo, TaskResult};
use crate::tasks::Task;
use crate::ui;
use async_trait::async_trait;

pub struct SoftwareManagementTask {
    name: String,
    description: String,
    dry_run: bool,
    pub prohibited_software: Vec<String>,
    pub required_software: Vec<SoftwareRequirement>,
    pub run_malware_scan: bool,
    pub use_quick_scan: bool,
}

impl SoftwareManagementTask {
    pub fn new() -> Self {
        Self {
            name: "Software Management".to_string(),
            description:
                "Removes prohibited software and installs required software as specified in the README."
                    .to_string(),
            dry_run: false,
            prohibited_software: Vec::new(),
            required_software: Vec::new(),
            run_malware_scan: true,
            use_quick_scan: true,
        }
    }

    pub fn set_readme_data(&mut self, readme: &ReadmeData) {
        self.prohibited_software = readme.prohibited_software.clone();
        self.required_software = readme.required_software.clone();
    }

    fn contains_ci(haystack: &str, needle: &str) -> bool {
        haystack.to_lowercase().contains(&needle.to_lowercase())
    }

    fn parse_installed(output: &str) -> Vec<String> {
        output
            .split(['\n', '\r'])
            .map(|l| l.trim().to_string())
            .filter(|l| !l.is_empty() && l != "Name")
            .collect()
    }

    /// Runs a Windows Defender malware scan and returns (success, threats_found, message).
    async fn run_windows_defender_scan(&self) -> (bool, i32, String) {
        let scan_type = if self.use_quick_scan { "QuickScan" } else { "FullScan" };
        ui::markup_line(&format!("[blue]Running Windows Defender {scan_type}...[/]"));

        let (update_success, _o, update_error) = command::execute(
            "powershell",
            Some("-Command \"Update-MpSignature -ErrorAction SilentlyContinue\""),
        )
        .await;
        if update_success {
            ui::markup_line("[green]✓ Windows Defender signatures updated[/]");
        } else {
            ui::markup_line(&format!(
                "[yellow]⚠ Could not update signatures: {}[/]",
                ui::escape(&update_error.unwrap_or_default())
            ));
        }

        let (scan_success, _scan_output, scan_error) = command::execute(
            "powershell",
            Some(&format!("-Command \"Start-MpScan -ScanType {scan_type}\"")),
        )
        .await;

        if !scan_success {
            ui::markup_line(&format!(
                "[red]✗ Windows Defender scan failed: {}[/]",
                ui::escape(&scan_error.clone().unwrap_or_default())
            ));
            return (false, 0, format!("Windows Defender scan failed: {}", scan_error.unwrap_or_default()));
        }

        ui::markup_line(&format!("[green]✓ Windows Defender {scan_type} completed[/]"));

        let (threat_success, threat_output, _e) = command::execute(
            "powershell",
            Some("-Command \"Get-MpThreatDetection | Select-Object -Property ThreatID, ActionSuccess | ConvertTo-Json\""),
        )
        .await;

        let mut threats_found = 0;
        if threat_success && !threat_output.trim().is_empty() {
            threats_found = threat_output.split("ThreatID").count() as i32 - 1;
            if threats_found > 0 {
                ui::markup_line(&format!("[red]⚠ Windows Defender found {threats_found} threat(s)[/]"));
                let (remove_success, _o, remove_error) = command::execute(
                    "powershell",
                    Some("-Command \"Remove-MpThreat -ErrorAction SilentlyContinue\""),
                )
                .await;
                if remove_success {
                    ui::markup_line("[green]✓ Attempted to remove detected threats[/]");
                } else {
                    ui::markup_line(&format!(
                        "[yellow]⚠ Could not auto-remove threats: {}[/]",
                        ui::escape(&remove_error.unwrap_or_default())
                    ));
                }
            }
        }

        if threats_found == 0 {
            ui::markup_line("[green]✓ No threats detected by Windows Defender[/]");
        }

        let msg = format!(
            "Windows Defender {scan_type}: {}",
            if threats_found > 0 {
                format!("{threats_found} threat(s) found")
            } else {
                "No threats detected".to_string()
            }
        );
        (true, threats_found, msg)
    }
}

impl Default for SoftwareManagementTask {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl Task for SoftwareManagementTask {
    impl_task_meta!();

    async fn read_system_state(&mut self) -> SystemInfo {
        let (_success, output, error) = command::execute("wmic", Some("product get name")).await;
        SystemInfo {
            raw_output: Some(output),
            error_output: error,
            ..Default::default()
        }
    }

    async fn execute(&mut self) -> TaskResult {
        if self.dry_run {
            ui::markup_line("[yellow]DRY RUN: Previewing software management changes (no changes will be made)[/]");
            return TaskResult {
                task_name: self.name.clone(),
                success: true,
                message: "DRY RUN: Software management changes previewed.".to_string(),
                ..Default::default()
            };
        }

        let (success, output, error) = command::execute("wmic", Some("product get name")).await;
        if !success {
            ui::markup_line(&format!(
                "[red]✗ Failed to list installed software: {}[/]",
                ui::escape(&error.clone().unwrap_or_default())
            ));
            return TaskResult {
                task_name: self.name.clone(),
                success: false,
                message: error.unwrap_or_else(|| "Unknown error".to_string()),
                ..Default::default()
            };
        }

        let installed = Self::parse_installed(&output);
        let to_remove: Vec<String> = installed
            .iter()
            .filter(|i| self.prohibited_software.iter().any(|p| Self::contains_ci(i, p)))
            .cloned()
            .collect();
        let to_install: Vec<SoftwareRequirement> = self
            .required_software
            .iter()
            .filter(|r| !installed.iter().any(|i| Self::contains_ci(i, &r.name)))
            .cloned()
            .collect();

        let mut details: Vec<String> = Vec::new();
        details.push(format!("Installed software checked: {}", installed.join(", ")));
        details.push(format!("Prohibited software list: {}", self.prohibited_software.join(", ")));
        details.push(format!(
            "Required software list: {}",
            self.required_software.iter().map(|r| r.name.clone()).collect::<Vec<_>>().join(", ")
        ));

        if !to_remove.is_empty() {
            details.push(format!("To remove: {}", to_remove.join(", ")));
        } else {
            details.push("No prohibited software found to remove.".to_string());
        }

        if !to_install.is_empty() {
            details.push(format!(
                "Missing required software: {}",
                to_install.iter().map(|s| s.name.clone()).collect::<Vec<_>>().join(", ")
            ));
        } else {
            details.push("All required software is installed.".to_string());
        }

        for sw in &to_remove {
            let (rem_success, _o, rem_error) = command::execute(
                "wmic",
                Some(&format!("product where name=\"{sw}\" call uninstall /nointeractive")),
            )
            .await;
            if rem_success {
                ui::markup_line(&format!("[green]✓ Removed: {}[/]", ui::escape(sw)));
            } else {
                ui::markup_line(&format!(
                    "[red]✗ Failed to remove: {} ({})[/]",
                    ui::escape(sw),
                    ui::escape(&rem_error.unwrap_or_default())
                ));
            }
        }
        for sw in &to_install {
            ui::markup_line(&format!(
                "[yellow]Required software not installed: {} (manual install may be needed)[/]",
                ui::escape(&sw.name)
            ));
        }

        let mut malware_scan_success = true;
        let mut threats_found = 0;
        if self.run_malware_scan {
            let (s, t, m) = self.run_windows_defender_scan().await;
            malware_scan_success = s;
            threats_found = t;
            details.push(m);
        }

        TaskResult {
            task_name: self.name.clone(),
            success: to_remove.is_empty() && to_install.is_empty() && malware_scan_success && threats_found == 0,
            message: details.join("\n"),
            ..Default::default()
        }
    }

    async fn verify(&mut self) -> bool {
        let (_success, output, _error) = command::execute("wmic", Some("product get name")).await;
        let installed = Self::parse_installed(&output);
        let still_present = installed
            .iter()
            .any(|i| self.prohibited_software.iter().any(|p| Self::contains_ci(i, p)));
        let still_missing = self
            .required_software
            .iter()
            .any(|r| !installed.iter().any(|i| Self::contains_ci(i, &r.name)));
        !still_present && !still_missing
    }
}
