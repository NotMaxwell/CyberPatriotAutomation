//! Removes prohibited software, installs required software as specified in the
//! README, and runs Windows Defender malware scans.

use crate::command;
use crate::impl_task_meta;
use crate::models::{ReadmeData, SoftwareRequirement, SystemInfo, TaskResult};
use crate::run_log;
use crate::software_matching;
use crate::tasks::Task;
use crate::ui;
use async_trait::async_trait;
use std::time::Duration;

/// An uninstaller can legitimately run for several minutes.
const UNINSTALL_TIMEOUT: Duration = Duration::from_secs(15 * 60);

/// Exit codes that mean the program was removed. 3010 and 1641 both mean
/// "succeeded, reboot pending".
const UNINSTALL_SUCCESS_CODES: [i32; 4] = [0, 1605, 1641, 3010];

/// A full or quick Defender scan runs for many minutes.
const SCAN_TIMEOUT: Duration = Duration::from_secs(60 * 60);

/// `wmic product` is notoriously slow - minutes on a populated machine.
const INVENTORY_TIMEOUT: Duration = Duration::from_secs(10 * 60);

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
        let mut task = Self {
            name: "Software Management".to_string(),
            description:
                "Removes prohibited software and installs required software as specified in the README."
                    .to_string(),
            dry_run: false,
            prohibited_software: Vec::new(),
            required_software: Vec::new(),
            run_malware_scan: true,
            use_quick_scan: true,
        };
        // With no README the default prohibitions are the whole list, so they
        // are seeded here rather than waiting for a set_readme_data that may
        // never come.
        task.apply_default_prohibitions();
        task
    }

    /// Software treated as prohibited even when the README does not name it.
    ///
    /// Scoring images routinely include software that is not a hacking tool but
    /// is not authorised either - a media player, a scripting runtime, a
    /// registry cleaner. The CP19 exhibition answer key scored removing Jellyfin
    /// Media Player and Python 3 as separate items and the README named neither,
    /// so they are prohibited by default and only spared when the README
    /// explicitly requires them.
    pub const ALWAYS_PROHIBITED: [&str; 3] = ["Python", "CCleaner", "Jellyfin"];

    pub fn set_readme_data(&mut self, readme: &ReadmeData) {
        self.required_software = readme.required_software.clone();
        self.prohibited_software = readme.prohibited_software.clone();
        self.apply_default_prohibitions();
    }

    /// Add [`Self::ALWAYS_PROHIBITED`] unless the README requires that software.
    ///
    /// Called from `new` as well as from `set_readme_data`. It used to live only
    /// in the latter, which the caller invokes only when a README parsed - so a
    /// run without one left the prohibited list **empty** and removed nothing at
    /// all. Python, CCleaner and Jellyfin are prohibited by default precisely
    /// because no README names them, so the defaults have to survive the README
    /// being absent.
    fn apply_default_prohibitions(&mut self) {
        for candidate in Self::ALWAYS_PROHIBITED {
            // A README that requires something wins over the default list: an
            // image that legitimately needs Python must not have it removed.
            let required = self
                .required_software
                .iter()
                .any(|r| software_matching::matches(&r.name, candidate));
            let already_listed = self
                .prohibited_software
                .iter()
                .any(|p| p.eq_ignore_ascii_case(candidate));
            if !required && !already_listed {
                self.prohibited_software.push(candidate.to_string());
            }
        }
    }

    /// The installed-software inventory, with uninstall commands where Windows
    /// records them.
    ///
    /// `wmic product get name` is the fallback only: it is deprecated, absent on
    /// current Windows 11 images, sees only MSI installs, and reconfigures every
    /// installed product just to list them. It also yields no uninstall command,
    /// so removal has nothing to work with.
    async fn read_installed() -> Option<Vec<software_matching::InstalledSoftware>> {
        #[cfg(windows)]
        {
            if let Some(programs) = crate::native::installed_software::enumerate() {
                return Some(
                    programs
                        .into_iter()
                        .map(|p| software_matching::InstalledSoftware {
                            name: p.name,
                            version: p.version,
                            uninstall_string: p.uninstall_string,
                            uninstall_is_quiet: p.uninstall_is_quiet,
                        })
                        .collect(),
                );
            }
            run_log::diagnostic(
                "software",
                "the uninstall registry could not be read; falling back to wmic",
            );
        }

        let (success, output, error) =
            command::execute_with_timeout("wmic", Some("product get name"), INVENTORY_TIMEOUT)
                .await;
        if !success {
            run_log::diagnostic(
                "software",
                &format!(
                    "wmic inventory failed: {}",
                    error.unwrap_or_else(|| "no reason reported".to_string())
                ),
            );
            return None;
        }

        Some(
            Self::parse_installed(&output)
                .into_iter()
                .map(software_matching::InstalledSoftware::named)
                .collect(),
        )
    }

    /// Uninstall one program. Returns `None` on success, or the reason.
    ///
    /// `wmic product call uninstall` is gone: it reads Win32_Product, which
    /// knows only MSI installs, and exits 0 when its where-clause matches
    /// nothing - so it reported success for every non-MSI program while removing
    /// none of them. The registered uninstall command, made unattended, is what
    /// actually removes CCleaner, Notepad++ and Jellyfin.
    async fn uninstall(software: &software_matching::InstalledSoftware) -> Option<String> {
        let Some(command) = software_matching::build_uninstall_command(
            software.uninstall_string.as_deref(),
            software.uninstall_is_quiet,
        ) else {
            run_log::diagnostic(
                "software",
                &format!("{}: no usable uninstall command registered", software.name),
            );
            return Some("no uninstall command is registered for this program".to_string());
        };

        run_log::diagnostic(
            "software",
            &format!("{}: running {} {}", software.name, command.program, command.arguments),
        );

        let (exit_code, output, error) = command::execute_for_exit_code(
            &command.program,
            Some(&command.arguments),
            UNINSTALL_TIMEOUT,
        )
        .await;

        match exit_code {
            // 3010 and 1641 mean "done, reboot pending" - the software is gone.
            Some(code) if UNINSTALL_SUCCESS_CODES.contains(&code) => None,
            Some(code) => Some(
                error
                    .filter(|e| !e.trim().is_empty())
                    .or_else(|| {
                        output
                            .lines()
                            .map(str::trim)
                            .rfind(|l| !l.is_empty())
                            .map(str::to_string)
                    })
                    .unwrap_or_else(|| format!("the uninstaller exited with code {code}")),
            ),
            None => Some("the uninstaller did not finish within the time limit".to_string()),
        }
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

        let (update_success, _o, update_error) = command::powershell("Update-MpSignature").await;
        if update_success {
            ui::markup_line("[green]✓ Windows Defender signatures updated[/]");
        } else {
            ui::markup_line(&format!(
                "[yellow]⚠ Could not update signatures: {}[/]",
                ui::escape(&update_error.unwrap_or_default())
            ));
        }

        // A Defender scan runs for many minutes; under the default two-minute
        // ceiling it was killed part-way and reported as a failure.
        let (scan_success, _scan_output, scan_error) = command::powershell_with_timeout(
            &format!("Start-MpScan -ScanType {scan_type}"),
            SCAN_TIMEOUT,
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

        let (threat_success, threat_output, _e) = command::powershell_query(
            "Get-MpThreatDetection | Select-Object -Property ThreatID, ActionSuccess | ConvertTo-Json",
        )
        .await;

        let mut threats_found = 0;
        if threat_success && !threat_output.trim().is_empty() {
            threats_found = threat_output.split("ThreatID").count() as i32 - 1;
            if threats_found > 0 {
                ui::markup_line(&format!("[red]⚠ Windows Defender found {threats_found} threat(s)[/]"));
                let (remove_success, _o, remove_error) = command::powershell("Remove-MpThreat").await;
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
        let installed = Self::read_installed().await;
        SystemInfo {
            raw_output: Some(
                installed
                    .as_ref()
                    .map(|list| {
                        list.iter()
                            .map(|p| match &p.version {
                                Some(v) => format!("{} [{v}]", p.name),
                                None => p.name.clone(),
                            })
                            .collect::<Vec<_>>()
                            .join("\n")
                    })
                    .unwrap_or_default(),
            ),
            error_output: installed
                .is_none()
                .then(|| "Could not read installed software".to_string()),
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

        let Some(installed) = Self::read_installed().await else {
            ui::markup_line("[red]✗ Failed to list installed software[/]");
            return TaskResult {
                task_name: self.name.clone(),
                success: false,
                message: "Could not read the installed software inventory".to_string(),
                ..Default::default()
            };
        };

        let to_remove: Vec<software_matching::InstalledSoftware> = installed
            .iter()
            .filter(|i| {
                self.prohibited_software
                    .iter()
                    .any(|p| software_matching::matches(&i.name, p))
            })
            .cloned()
            .collect();
        let to_install: Vec<SoftwareRequirement> = self
            .required_software
            .iter()
            .filter(|r| {
                !installed
                    .iter()
                    .any(|i| software_matching::matches(&i.name, &r.name))
            })
            .cloned()
            .collect();

        // What matched what, and why. Reconstructing this after a run used to be
        // impossible: the console said "Failed to remove: X" and nothing said
        // whether X was matched at all, or what the uninstaller returned.
        run_log::diagnostic("software", &format!("inventory: {} programs", installed.len()));
        run_log::diagnostic(
            "software",
            &format!("prohibited terms: {}", self.prohibited_software.join(", ")),
        );
        for item in &to_remove {
            run_log::diagnostic(
                "software",
                &format!(
                    "matched for removal: {} (uninstall string: {})",
                    item.name,
                    item.uninstall_string.as_deref().unwrap_or("none registered")
                ),
            );
        }

        let mut details: Vec<String> = Vec::new();
        details.push(format!(
            "Installed software checked: {}",
            installed.iter().map(|i| i.name.clone()).collect::<Vec<_>>().join(", ")
        ));
        details.push(format!("Prohibited software list: {}", self.prohibited_software.join(", ")));
        details.push(format!(
            "Required software list: {}",
            self.required_software.iter().map(|r| r.name.clone()).collect::<Vec<_>>().join(", ")
        ));

        if !to_remove.is_empty() {
            details.push(format!(
                "To remove: {}",
                to_remove.iter().map(|i| i.name.clone()).collect::<Vec<_>>().join(", ")
            ));
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

        let mut removal_failures: Vec<String> = Vec::new();
        for sw in &to_remove {
            match Self::uninstall(sw).await {
                None => ui::markup_line(&format!("[green]✓ Removed: {}[/]", ui::escape(&sw.name))),
                Some(reason) => {
                    removal_failures.push(format!("{}: {reason}", sw.name));
                    ui::markup_line(&format!(
                        "[red]✗ Failed to remove: {} ({})[/]",
                        ui::escape(&sw.name),
                        ui::escape(&reason)
                    ));
                }
            }
        }

        // Confirm removals against a fresh inventory rather than trusting exit
        // codes. An uninstaller that exits 0 having shown a dialog nobody
        // answered, or that needs a reboot to finish, both report success.
        if !to_remove.is_empty() {
            if let Some(after) = Self::read_installed().await {
                let survivors: Vec<String> = after
                    .iter()
                    .filter(|i| {
                        self.prohibited_software
                            .iter()
                            .any(|p| software_matching::matches(&i.name, p))
                    })
                    .map(|i| i.name.clone())
                    .collect();
                for name in &survivors {
                    run_log::diagnostic("software", &format!("still present after removal: {name}"));
                    if !removal_failures.iter().any(|f| f.starts_with(name)) {
                        removal_failures
                            .push(format!("{name}: reported removed but still installed"));
                        ui::markup_line(&format!(
                            "[red]✗ {} is still installed after removal[/]",
                            ui::escape(name)
                        ));
                    }
                }
                if !survivors.is_empty() {
                    details.push(format!(
                        "Still installed after removal: {}",
                        survivors.join(", ")
                    ));
                }
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
            // Success reflects whether remediation succeeded, not whether there
            // was nothing to do. The previous condition included
            // `to_remove.is_empty()`, so successfully uninstalling prohibited
            // software reported the task as failed. Missing required software is
            // still a genuine outstanding problem (it needs a manual install),
            // so that remains part of the condition.
            success: removal_failures.is_empty()
                && to_install.is_empty()
                && malware_scan_success
                && threats_found == 0,
            message: details.join("\n"),
            error_details: (!removal_failures.is_empty()).then(|| removal_failures.join("\n")),
            ..Default::default()
        }
    }

    async fn verify(&mut self) -> bool {
        let (_success, output, _error) = command::execute_with_timeout("wmic", Some("product get name"), INVENTORY_TIMEOUT).await;
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
