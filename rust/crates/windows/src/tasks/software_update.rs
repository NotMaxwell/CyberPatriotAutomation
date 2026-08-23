//! Inventories installed applications, compares each against the latest
//! available version, and applies the outstanding updates.
//!
//! Out-of-date third-party software is a standard CyberPatriot scoring item.
//! Two separate questions have to be answered, and they need different sources:
//!
//! - *What is installed, and at what version?* Read from the Windows uninstall
//!   registry keys. This always works, offline, and covers everything that
//!   registers itself - far more than `wmic product`, which only knows about MSI
//!   packages and is slow enough to be disruptive.
//! - *What is the latest version?* Requires a package catalogue. Chocolatey is
//!   used here: `choco outdated` reports the installed and available versions
//!   side by side, which is exactly the comparison needed, and it is installable
//!   on any image rather than shipping only with certain Windows SKUs.
//!
//! Chocolatey is preferred over winget for two practical reasons. It installs
//! from a script on any supported Windows, including the LTSC images
//! CyberPatriot uses, where winget's "App Installer" package is absent and
//! awkward to add. And `--limit-output` emits pipe-delimited records, so the
//! results need no fixed-width table parsing - which is what the winget path
//! required and where it was most fragile.
//!
//! Operating-system patches are deliberately out of scope here: Windows Update
//! is configured by the audit-policy task, which owns those settings.

use async_trait::async_trait;
use pinnacle_core::Task;
use pinnacle_core::command;
use pinnacle_core::impl_task_meta;
use pinnacle_core::models::{ReadmeData, SystemInfo, TaskResult};
use pinnacle_core::ui;
use std::time::Duration;

/// Installing an update can involve a large download, so it needs far longer
/// than the default two-minute command ceiling.
const UPDATE_TIMEOUT: Duration = Duration::from_secs(15 * 60);

/// Listing the catalogue can be slow on a cold source index.
const CHOCO_QUERY_TIMEOUT: Duration = Duration::from_secs(5 * 60);

/// Bootstrapping Chocolatey downloads and runs its installer.
const CHOCO_BOOTSTRAP_TIMEOUT: Duration = Duration::from_secs(15 * 60);

/// Exit codes Chocolatey uses for "succeeded, but a reboot is pending".
const CHOCO_SUCCESS_CODES: [i32; 5] = [0, 1605, 1614, 1641, 3010];

/// Enumerate installed software from all three uninstall locations: 64-bit,
/// 32-bit-on-64-bit, and per-user. Entries without a `DisplayName` are stubs
/// (patches, components) rather than applications, and `SystemComponent`
/// entries are hidden from Programs and Features for the same reason.
const INSTALLED_SOFTWARE_QUERY: &str = "\
$paths = @('HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\*', \
'HKLM:\\SOFTWARE\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\*', \
'HKCU:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\*'); \
Get-ItemProperty -Path $paths | \
Where-Object { $_.DisplayName -and -not $_.SystemComponent -and -not $_.ReleaseType } | \
Select-Object DisplayName, DisplayVersion, Publisher | \
Sort-Object DisplayName -Unique | ConvertTo-Csv -NoTypeInformation";

/// An application present on the machine.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InstalledApp {
    pub name: String,
    pub version: String,
    pub publisher: String,
}

/// An application with a newer version available.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AvailableUpdate {
    pub name: String,
    /// Chocolatey package id, used to target the upgrade precisely.
    pub id: String,
    pub current_version: String,
    pub available_version: String,
}

pub struct SoftwareUpdateTask {
    name: String,
    description: String,
    dry_run: bool,
    readme_data: Option<ReadmeData>,
    installed: Vec<InstalledApp>,
    updates: Vec<AvailableUpdate>,
    choco_available: bool,
}

impl SoftwareUpdateTask {
    pub fn new() -> Self {
        Self {
            name: "Software Updates".to_string(),
            description:
                "Check installed applications against the latest available versions and update them"
                    .to_string(),
            dry_run: false,
            readme_data: None,
            installed: Vec::new(),
            updates: Vec::new(),
            choco_available: false,
        }
    }

    pub fn set_readme_data(&mut self, data: ReadmeData) {
        self.readme_data = Some(data);
    }

    /// The Chocolatey executable, or `None` when it is not installed.
    ///
    /// The bootstrap adds Chocolatey to the machine PATH, but a process that is
    /// already running keeps the environment it started with, so `choco` stays
    /// unresolvable in this process until it restarts. Falling back to the
    /// standard install path is what makes an install usable in the same run.
    async fn choco_path() -> Option<String> {
        let (success, output, _e) = command::execute("choco", Some("--version")).await;
        if success && !output.trim().is_empty() {
            return Some("choco".to_string());
        }

        let program_data =
            std::env::var("ProgramData").unwrap_or_else(|_| "C:\\ProgramData".to_string());
        let absolute = std::path::Path::new(&program_data)
            .join("chocolatey")
            .join("bin")
            .join("choco.exe");
        if !absolute.exists() {
            return None;
        }

        let absolute = absolute.to_string_lossy().into_owned();
        let (success, output, _e) = command::execute(&absolute, Some("--version")).await;
        (success && !output.trim().is_empty()).then_some(absolute)
    }

    /// Is Chocolatey present and runnable?
    async fn detect_choco() -> bool {
        Self::choco_path().await.is_some()
    }

    /// Ensure Chocolatey is usable, installing it if it is missing.
    ///
    /// This is the documented bootstrap. TLS 1.2 is forced because Windows
    /// PowerShell 5.1 still offers older protocols that the Chocolatey community
    /// repository refuses, which otherwise fails the download with an error that
    /// says nothing about TLS.
    async fn ensure_choco() -> bool {
        if Self::detect_choco().await {
            return true;
        }

        ui::markup_line("[yellow]Chocolatey not available - installing...[/]");

        let script = "Set-ExecutionPolicy Bypass -Scope Process -Force; \
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12; \
Invoke-Expression ((New-Object System.Net.WebClient).DownloadString('https://community.chocolatey.org/install.ps1'))";

        let (_ok, _o, error) =
            command::powershell_with_timeout(script, CHOCO_BOOTSTRAP_TIMEOUT).await;

        // Re-detect regardless of the reported status: the installer can exit
        // non-zero having produced a working install, and the new binary is only
        // reachable by absolute path in this process.
        if Self::detect_choco().await {
            ui::markup_line("[green]✓ Chocolatey installed[/]");
            true
        } else {
            ui::markup_line(&format!(
                "[yellow]⚠ Chocolatey could not be installed: {}[/]",
                ui::escape(&error.unwrap_or_else(|| "no reason reported".to_string()))
            ));
            false
        }
    }

    async fn read_installed_software() -> Vec<InstalledApp> {
        // Read the uninstall keys directly. The PowerShell query below asks for
        // the same data, but pays a process launch and a CSV round-trip for it.
        #[cfg(windows)]
        if let Some(programs) = crate::native::installed_software::enumerate() {
            return programs
                .into_iter()
                .map(|p| InstalledApp {
                    name: p.name,
                    version: p.version.unwrap_or_default(),
                    publisher: p.publisher.unwrap_or_default(),
                })
                .collect();
        }

        let (success, output, _e) = command::powershell_query(INSTALLED_SOFTWARE_QUERY).await;
        if !success {
            return Vec::new();
        }
        parse_installed_software(&output)
    }

    async fn read_available_updates() -> Vec<AvailableUpdate> {
        let Some(choco) = Self::choco_path().await else {
            return Vec::new();
        };

        // `--limit-output` drops the banner and summary and prints one
        // pipe-delimited record per package, so nothing here parses a table or
        // depends on the console language.
        let (code, output, _e) = command::execute_for_exit_code(
            &choco,
            Some("outdated --limit-output --ignore-pinned"),
            CHOCO_QUERY_TIMEOUT,
        )
        .await;

        // `choco outdated` exits 2 when it found outdated packages, which is the
        // case this function exists to handle - so success alone is not the test.
        match code {
            Some(c) if CHOCO_SUCCESS_CODES.contains(&c) || c == 2 => parse_choco_outdated(&output),
            _ => Vec::new(),
        }
    }

    /// Names the README explicitly requires to be at the latest version.
    fn readme_priority_names(&self) -> Vec<String> {
        self.readme_data
            .as_ref()
            .map(|r| {
                r.required_software
                    .iter()
                    .filter(|s| s.should_be_latest)
                    .map(|s| s.name.to_lowercase())
                    .collect()
            })
            .unwrap_or_default()
    }

    /// Does this update correspond to software the README calls out?
    fn is_priority(&self, update: &AvailableUpdate, priority: &[String]) -> bool {
        let name = update.name.to_lowercase();
        let id = update.id.to_lowercase();
        priority
            .iter()
            .any(|p| name.contains(p.as_str()) || id.contains(p.as_str()))
    }

    fn display_installed(&self) {
        if self.installed.is_empty() {
            ui::markup_line("[yellow]No installed applications could be enumerated[/]");
            return;
        }
        ui::markup_line(&format!(
            "[cyan]{} installed application(s) detected[/]",
            self.installed.len()
        ));

        let mut table = ui::TableBuilder::new()
            .title("[bold]Installed Software (first 20)[/]")
            .columns(&[
                "[bold]Application[/]",
                "[bold]Version[/]",
                "[bold]Publisher[/]",
            ]);
        for app in self.installed.iter().take(20) {
            table.add_row([
                ui::escape(&app.name),
                if app.version.is_empty() {
                    "[dim]unknown[/]".to_string()
                } else {
                    ui::escape(&app.version)
                },
                ui::escape(&app.publisher),
            ]);
        }
        table.print();
        if self.installed.len() > 20 {
            ui::markup_line(&format!(
                "[dim]...and {} more[/]",
                self.installed.len() - 20
            ));
        }
    }

    fn display_updates(&self) {
        if self.updates.is_empty() {
            ui::markup_line("[green]✓ All applications are up to date[/]");
            return;
        }

        let priority = self.readme_priority_names();
        let mut table = ui::TableBuilder::new()
            .title("[bold yellow]Updates Available[/]")
            .columns(&[
                "[bold]Application[/]",
                "[bold]Installed[/]",
                "[bold]Latest[/]",
                "[bold]Source ID[/]",
            ]);
        for update in &self.updates {
            let name = if self.is_priority(update, &priority) {
                // Called out by the README, so it carries points directly.
                format!("[bold yellow]{} (README)[/]", ui::escape(&update.name))
            } else {
                ui::escape(&update.name)
            };
            table.add_row([
                name,
                format!("[red]{}[/]", ui::escape(&update.current_version)),
                format!("[green]{}[/]", ui::escape(&update.available_version)),
                format!("[dim]{}[/]", ui::escape(&update.id)),
            ]);
        }
        table.print();
    }

    /// Apply one update, returning the outcome message on failure.
    async fn apply_update(update: &AvailableUpdate) -> Result<(), String> {
        let Some(choco) = Self::choco_path().await else {
            return Err("Chocolatey is not installed".to_string());
        };

        // `-y` answers the confirmation prompt, and `--no-progress` keeps the
        // download percentage out of the captured output.
        let args = format!("upgrade {} -y --no-progress --limit-output", update.id);
        let (code, output, error) =
            command::execute_for_exit_code(&choco, Some(&args), UPDATE_TIMEOUT).await;

        match code {
            Some(c) if CHOCO_SUCCESS_CODES.contains(&c) => Ok(()),
            _ => {
                // Chocolatey puts the useful detail on stdout, not stderr.
                let detail = error
                    .filter(|e| !e.trim().is_empty())
                    .or_else(|| {
                        let trimmed = output.trim();
                        (!trimmed.is_empty())
                            .then(|| trimmed.lines().last().unwrap_or("").to_string())
                    })
                    .unwrap_or_else(|| match code {
                        Some(c) => format!("Chocolatey exited with code {c}"),
                        None => "Chocolatey did not complete".to_string(),
                    });
                Err(detail)
            }
        }
    }
}

impl Default for SoftwareUpdateTask {
    fn default() -> Self {
        Self::new()
    }
}

/// Parse the `ConvertTo-Csv` inventory into applications.
pub fn parse_installed_software(csv: &str) -> Vec<InstalledApp> {
    let mut apps = Vec::new();
    for line in csv
        .split(['\r', '\n'])
        .filter(|l| !l.trim().is_empty())
        .skip(1)
    {
        let fields = crate::tasks::parse_csv_line(line);
        if fields.is_empty() {
            continue;
        }
        let unquote = |s: &str| s.trim().trim_matches('"').trim().to_string();
        let name = unquote(&fields[0]);
        if name.is_empty() {
            continue;
        }
        apps.push(InstalledApp {
            name,
            version: fields.get(1).map(|v| unquote(v)).unwrap_or_default(),
            publisher: fields.get(2).map(|v| unquote(v)).unwrap_or_default(),
        });
    }
    apps
}

/// Parse the records `choco outdated --limit-output` prints.
///
/// Each line is `name|current|available|pinned`. This replaced a fixed-width
/// table parser written against `winget upgrade`, which had to locate columns by
/// header offset and measure text by terminal display width so that a CJK
/// package name - two columns wide per character but one `char` - did not shift
/// every following field. None of that applies to a delimited format.
pub fn parse_choco_outdated(output: &str) -> Vec<AvailableUpdate> {
    output
        .lines()
        .filter_map(|line| {
            let line = line.trim();
            if line.is_empty() {
                return None;
            }

            let fields: Vec<&str> = line.split('|').collect();
            if fields.len() < 3 {
                return None;
            }

            let name = fields[0].trim();
            let current = fields[1].trim();
            let available = fields[2].trim();
            if name.is_empty() || available.is_empty() {
                return None;
            }

            // A package already at the newest version is not an update. Chocolatey
            // does not normally list these, but `--ignore-pinned` changes what is
            // included, so the check is cheap insurance.
            if current == available {
                return None;
            }

            Some(AvailableUpdate {
                // Chocolatey has one id, used both to identify and to display.
                name: name.to_string(),
                id: name.to_string(),
                current_version: current.to_string(),
                available_version: available.to_string(),
            })
        })
        .collect()
}

#[async_trait]
impl Task for SoftwareUpdateTask {
    impl_task_meta!();

    async fn read_system_state(&mut self) -> SystemInfo {
        let mut system_info = SystemInfo::new();

        ui::markup_line("[cyan]Reading installed software inventory...[/]");
        self.installed = Self::read_installed_software().await;
        self.display_installed();
        ui::write_line();

        for app in &self.installed {
            system_info
                .installed_applications
                .push(format!("{} {}", app.name, app.version));
        }

        // Detect only. Reading system state must observe, not change the
        // machine - installing a package here would also mean `--dry-run`
        // installed software before reaching the dry-run check.
        self.choco_available = Self::detect_choco().await;
        if !self.choco_available {
            ui::markup_line(
                "[yellow]⚠ Chocolatey is not available - cannot determine latest versions[/]",
            );
            return system_info;
        }

        ui::markup_line("[cyan]Checking for available updates...[/]");
        self.updates = Self::read_available_updates().await;
        self.display_updates();

        system_info
    }

    async fn execute(&mut self) -> TaskResult {
        let mut result = TaskResult {
            task_name: self.name.clone(),
            success: true,
            message: "Software update check completed".to_string(),
            ..Default::default()
        };

        if self.installed.is_empty() && self.updates.is_empty() {
            self.installed = Self::read_installed_software().await;
            self.choco_available = Self::detect_choco().await;
        }

        // Installing the package manager is itself a change to the machine, so
        // it belongs here rather than in the read phase, and never under
        // `--dry-run`.
        if !self.choco_available && !self.dry_run {
            self.choco_available = Self::ensure_choco().await;
        }
        if self.choco_available && self.updates.is_empty() {
            self.updates = Self::read_available_updates().await;
        }

        // Without a catalogue there is no "latest version" to compare against,
        // so the task cannot do its job. Say so plainly rather than reporting a
        // vacuous success.
        if !self.choco_available {
            result.success = false;
            result.message = format!(
                "Inventoried {} application(s) but could not check for updates: Chocolatey is not installed.",
                self.installed.len()
            );
            result.error_details = Some(
                "Chocolatey is required to determine the latest available \
                 versions. Automatic installation of the App Installer package was attempted and \
                 did not succeed - most often because the image has no network access. Install \
                 'App Installer' from the Microsoft Store, or update the listed applications \
                 manually."
                    .to_string(),
            );
            result.items_attempted = self.installed.len() as i32;
            return result;
        }

        let priority = self.readme_priority_names();
        result.items_attempted = self.updates.len() as i32;

        if self.updates.is_empty() {
            result.message = format!(
                "All {} installed application(s) are up to date.",
                self.installed.len()
            );
            return result;
        }

        if self.dry_run {
            ui::markup_line(
                "[yellow]DRY RUN: Previewing software updates (no changes will be made)[/]",
            );
            for update in &self.updates {
                ui::markup_line(&format!(
                    "[cyan]Would update {} from {} to {}[/]",
                    ui::escape(&update.name),
                    ui::escape(&update.current_version),
                    ui::escape(&update.available_version)
                ));
            }
            result.items_skipped = self.updates.len() as i32;
            result.message = format!(
                "DRY RUN: {} update(s) would be applied.",
                self.updates.len()
            );
            return result;
        }

        ui::write_line();
        ui::rule("[bold yellow]Applying Software Updates[/]");
        ui::write_line();

        // Update README-mandated software first: if the run is cut short, the
        // scored items are the ones already done.
        let mut ordered: Vec<AvailableUpdate> = self.updates.clone();
        ordered.sort_by_key(|u| !self.is_priority(u, &priority));

        let mut updated: Vec<String> = Vec::new();
        let mut failed: Vec<String> = Vec::new();

        let total = ordered.len();
        for (index, update) in ordered.iter().enumerate() {
            ui::markup_line(&format!(
                "[yellow]({}/{}) Updating {} {} → {}...[/]",
                index + 1,
                total,
                ui::escape(&update.name),
                ui::escape(&update.current_version),
                ui::escape(&update.available_version)
            ));

            match Self::apply_update(update).await {
                Ok(()) => {
                    updated.push(format!(
                        "{} {} → {}",
                        update.name, update.current_version, update.available_version
                    ));
                    ui::markup_line(&format!(
                        "[green]✓ Updated {} to {}[/]",
                        ui::escape(&update.name),
                        ui::escape(&update.available_version)
                    ));
                }
                Err(reason) => {
                    failed.push(format!("{} ({}): {}", update.name, update.id, reason));
                    ui::markup_line(&format!(
                        "[red]✗ Failed to update {}: {}[/]",
                        ui::escape(&update.name),
                        ui::escape(&reason)
                    ));
                }
            }
        }

        result.items_succeeded = updated.len() as i32;
        result.success = failed.is_empty();
        result.message = if failed.is_empty() {
            format!(
                "Updated {} application(s) to the latest version.",
                updated.len()
            )
        } else {
            format!(
                "Updated {} of {} application(s); {} could not be updated.",
                updated.len(),
                total,
                failed.len()
            )
        };
        if !failed.is_empty() {
            result.error_details = Some(failed.join("\n"));
        }

        result
    }

    async fn verify(&mut self) -> bool {
        if !self.choco_available {
            ui::markup_line("[yellow]⚠ Cannot verify update status without Chocolatey[/]");
            return false;
        }

        let remaining = Self::read_available_updates().await;
        if remaining.is_empty() {
            ui::markup_line("[green]✓ All applications are at the latest available version[/]");
            return true;
        }

        for update in &remaining {
            ui::markup_line(&format!(
                "[red]✗ {} is still at {} (latest {})[/]",
                ui::escape(&update.name),
                ui::escape(&update.current_version),
                ui::escape(&update.available_version)
            ));
        }
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const CHOCO_OUTDATED_OUTPUT: &str = "\
Microsoft Edge|120.0.2210|121.0.2277|false
7zip|22.01|23.01|false
firefox|115.0|122.0.1|false
";

    #[test]
    fn choco_records_are_split_on_the_delimiter() {
        let updates = parse_choco_outdated(CHOCO_OUTDATED_OUTPUT);
        assert_eq!(updates.len(), 3, "got {updates:#?}");

        // A name containing spaces stays intact: only `|` separates fields.
        assert_eq!(updates[0].name, "Microsoft Edge");
        assert_eq!(updates[0].current_version, "120.0.2210");
        assert_eq!(updates[0].available_version, "121.0.2277");

        assert_eq!(updates[1].name, "7zip");
        assert_eq!(updates[1].id, "7zip");
        assert_eq!(updates[2].available_version, "122.0.1");
    }

    #[test]
    fn no_upgrades_yields_no_results() {
        assert!(parse_choco_outdated("").is_empty());
        assert!(parse_choco_outdated("\n  \n").is_empty());
    }

    #[test]
    fn malformed_records_are_skipped_rather_than_panicking() {
        // Too few fields, and an empty available version.
        let output = "brokenline\nonly|two\ngood|1.0|2.0|false\nempty|1.0||false\n";
        let updates = parse_choco_outdated(output);
        assert_eq!(updates.len(), 1, "got {updates:#?}");
        assert_eq!(updates[0].name, "good");
    }

    #[test]
    fn packages_already_current_are_not_reported_as_updates() {
        let updates = parse_choco_outdated("uptodate|2.0|2.0|false\nstale|1.0|2.0|false\n");
        assert_eq!(updates.len(), 1, "got {updates:#?}");
        assert_eq!(updates[0].name, "stale");
    }

    #[test]
    fn non_ascii_package_names_survive_intact() {
        // The old fixed-width parser had to measure display width to avoid
        // slicing mid-character here; a delimiter has no such problem.
        let updates = parse_choco_outdated("メモ帳|1.0|2.0|false\n");
        assert_eq!(updates.len(), 1, "got {updates:#?}");
        assert_eq!(updates[0].name, "メモ帳");
        assert_eq!(updates[0].available_version, "2.0");
    }

    #[test]
    fn installed_software_csv_is_parsed() {
        let csv = "\"DisplayName\",\"DisplayVersion\",\"Publisher\"\r\n\
\"7-Zip 22.01 (x64)\",\"22.01\",\"Igor Pavlov\"\r\n\
\"Mozilla Firefox, Inc.\",\"115.0\",\"Mozilla\"\r\n";
        let apps = parse_installed_software(csv);
        assert_eq!(apps.len(), 2);
        assert_eq!(apps[0].name, "7-Zip 22.01 (x64)");
        assert_eq!(apps[0].version, "22.01");
        assert_eq!(apps[0].publisher, "Igor Pavlov");
        // A comma inside quotes must not split the field.
        assert_eq!(apps[1].name, "Mozilla Firefox, Inc.");
    }

    #[test]
    fn installed_software_skips_entries_without_a_name() {
        let csv = "\"DisplayName\",\"DisplayVersion\",\"Publisher\"\r\n\
\"\",\"1.0\",\"Nobody\"\r\n\
\"Real App\",\"2.0\",\"Somebody\"\r\n";
        let apps = parse_installed_software(csv);
        assert_eq!(apps.len(), 1);
        assert_eq!(apps[0].name, "Real App");
    }

    #[test]
    fn readme_required_software_is_prioritised() {
        use pinnacle_core::models::SoftwareRequirement;

        let mut task = SoftwareUpdateTask::new();
        let mut readme = ReadmeData::default();
        readme.required_software.push(SoftwareRequirement {
            name: "Firefox".to_string(),
            should_be_latest: true,
            ..Default::default()
        });
        readme.required_software.push(SoftwareRequirement {
            name: "Edge".to_string(),
            should_be_latest: false,
            ..Default::default()
        });
        task.set_readme_data(readme);

        let priority = task.readme_priority_names();
        assert_eq!(priority, vec!["firefox"]);

        let firefox = AvailableUpdate {
            name: "Mozilla Firefox (x64 en-US)".to_string(),
            id: "Mozilla.Firefox".to_string(),
            current_version: "115.0".to_string(),
            available_version: "122.0.1".to_string(),
        };
        let edge = AvailableUpdate {
            name: "Microsoft Edge".to_string(),
            id: "Microsoft.Edge".to_string(),
            current_version: "120.0".to_string(),
            available_version: "121.0".to_string(),
        };
        assert!(task.is_priority(&firefox, &priority));
        // Present in the README but not flagged "latest", so not prioritised.
        assert!(!task.is_priority(&edge, &priority));
    }
}
