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
//! - *What is the latest version?* Requires a package catalogue. `winget` is the
//!   one shipped by Microsoft, and `winget upgrade` reports the installed and
//!   available versions side by side, which is exactly the comparison needed.
//!
//! Operating-system patches are deliberately out of scope here: Windows Update
//! is configured by the audit-policy task, which owns those settings.

use crate::command;
use crate::impl_task_meta;
use crate::models::{ReadmeData, SystemInfo, TaskResult};
use crate::tasks::Task;
use crate::ui;
use async_trait::async_trait;
use std::time::Duration;
use unicode_width::{UnicodeWidthChar, UnicodeWidthStr};

/// Installing an update can involve a large download, so it needs far longer
/// than the default two-minute command ceiling.
const UPDATE_TIMEOUT: Duration = Duration::from_secs(15 * 60);

/// Listing the catalogue can be slow on a cold source index.
const WINGET_QUERY_TIMEOUT: Duration = Duration::from_secs(5 * 60);

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
    /// winget package identifier, used to target the upgrade precisely.
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
    winget_available: bool,
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
            winget_available: false,
        }
    }

    pub fn set_readme_data(&mut self, data: ReadmeData) {
        self.readme_data = Some(data);
    }

    /// Is `winget` present and runnable?
    ///
    /// It ships with Windows 11 and recent Windows 10 builds, but *not* with
    /// LTSC images - which CyberPatriot uses - so its absence has to be handled
    /// as a normal outcome rather than an error.
    async fn detect_winget() -> bool {
        let (success, output, _e) = command::execute("winget", Some("--version")).await;
        success && !output.trim().is_empty()
    }

    /// Ensure `winget` is usable, installing it if it is missing.
    ///
    /// winget ships as the "App Installer" MSIX package. It is absent from LTSC
    /// images and from some server SKUs, and is occasionally present but
    /// unregistered for the current user - which is why re-registration is tried
    /// first, being far cheaper than a download.
    ///
    /// The `aka.ms` links are Microsoft's own permanent redirects to the current
    /// release, so no version is pinned here and the newest package is always
    /// fetched.
    async fn ensure_winget() -> bool {
        if Self::detect_winget().await {
            return true;
        }

        ui::markup_line("[yellow]winget not available - attempting to install App Installer...[/]");

        // Cheap path: the package is present but not registered for this user.
        let (_ok, _o, _e) = command::powershell(
            "Add-AppxPackage -RegisterByFamilyName -MainPackage Microsoft.DesktopAppInstaller_8wekyb3d8bbwe",
        )
        .await;
        if Self::detect_winget().await {
            ui::markup_line("[green]✓ winget re-registered for the current user[/]");
            return true;
        }

        // Otherwise download the package and its runtime dependency. VCLibs must
        // be installed first or the bundle is rejected for a missing dependency.
        let temp = std::env::temp_dir();
        let downloads = [
            (
                "https://aka.ms/Microsoft.VCLibs.x64.14.00.Desktop.appx",
                temp.join("cpa_vclibs.appx"),
                true, // a dependency; failure here is not necessarily fatal
            ),
            (
                "https://aka.ms/getwinget",
                temp.join("cpa_winget.msixbundle"),
                false,
            ),
        ];

        for (url, dest, optional) in &downloads {
            ui::markup_line(&format!("[cyan]Downloading {}[/]", ui::escape(url)));
            if let Err(reason) = command::download_file(url, dest).await {
                ui::markup_line(&format!(
                    "[yellow]⚠ Could not download {}: {}[/]",
                    ui::escape(url),
                    ui::escape(&reason)
                ));
                if !optional {
                    ui::markup_line("[red]✗ Cannot install winget without the package[/]");
                    return false;
                }
                continue;
            }

            let (ok, _o, error) = command::powershell(&format!(
                "Add-AppxPackage -Path {}",
                command::ps_quote(&dest.to_string_lossy())
            ))
            .await;
            if ok {
                ui::markup_line(&format!("[green]✓ Installed {}[/]", ui::escape(&dest.to_string_lossy())));
            } else if !optional {
                ui::markup_line(&format!(
                    "[red]✗ Failed to install App Installer: {}[/]",
                    ui::escape(&error.unwrap_or_default())
                ));
            }
            let _ = std::fs::remove_file(dest);
        }

        if Self::detect_winget().await {
            ui::markup_line("[green]✓ winget installed[/]");
            true
        } else {
            ui::markup_line(
                "[yellow]⚠ winget is still unavailable. Install 'App Installer' from the Microsoft Store to enable update checking.[/]",
            );
            false
        }
    }

    async fn read_installed_software() -> Vec<InstalledApp> {
        let (success, output, _e) =
            command::powershell_query(INSTALLED_SOFTWARE_QUERY).await;
        if !success {
            return Vec::new();
        }
        parse_installed_software(&output)
    }

    async fn read_available_updates() -> Vec<AvailableUpdate> {
        // `--include-unknown` also lists packages whose installed version winget
        // cannot determine; without it those are silently skipped and quietly
        // stay out of date.
        let (success, output, _e) = command::execute_with_timeout(
            "winget",
            Some("upgrade --include-unknown --accept-source-agreements"),
            WINGET_QUERY_TIMEOUT,
        )
        .await;
        if !success {
            return Vec::new();
        }
        parse_winget_upgrades(&output)
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
            .columns(&["[bold]Application[/]", "[bold]Version[/]", "[bold]Publisher[/]"]);
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
        // `--exact` on the id avoids matching a different package with a
        // similar name; the agreement flags and `--disable-interactivity` keep
        // winget from blocking on a prompt no one is there to answer.
        let args = format!(
            "upgrade --id {} --exact --silent --accept-package-agreements --accept-source-agreements --disable-interactivity",
            update.id
        );
        let (success, output, error) =
            command::execute_with_timeout("winget", Some(&args), UPDATE_TIMEOUT).await;

        if success {
            return Ok(());
        }
        let detail = error
            .filter(|e| !e.trim().is_empty())
            .or_else(|| {
                let trimmed = output.trim();
                (!trimmed.is_empty()).then(|| trimmed.lines().last().unwrap_or("").to_string())
            })
            .unwrap_or_else(|| "winget reported a failure".to_string());
        Err(detail)
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
    for line in csv.split(['\r', '\n']).filter(|l| !l.trim().is_empty()).skip(1) {
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

/// Parse the table `winget upgrade` prints.
///
/// winget emits a fixed-width table rather than anything machine-readable, and
/// application names contain spaces, so columns cannot be recovered by
/// splitting on whitespace. The header row locates where each column begins and
/// every row is cut at those positions.
///
/// Positions are measured in **terminal display width**, not characters or
/// bytes. winget pads its columns so they line up visually, and a CJK package
/// name occupies two columns per character - so counting characters drifts off
/// the column boundary exactly when the name is non-Latin, and counting bytes
/// would additionally panic mid-character.
pub fn parse_winget_upgrades(output: &str) -> Vec<AvailableUpdate> {
    let lines = normalize_winget_lines(output);

    let Some(header_idx) = lines.iter().position(|l| is_upgrade_header(l)) else {
        return Vec::new();
    };
    let header = &lines[header_idx];

    let Some(id_at) = column_start(header, "Id") else {
        return Vec::new();
    };
    let Some(version_at) = column_start(header, "Version") else {
        return Vec::new();
    };
    let Some(available_at) = column_start(header, "Available") else {
        return Vec::new();
    };
    // "Source" is optional - it is absent when every entry came from one source.
    let source_at = column_start(header, "Source").unwrap_or(usize::MAX);

    let mut updates = Vec::new();
    for line in lines.iter().skip(header_idx + 1) {
        let trimmed = line.trim();
        // The dashed rule under the header, and the blank line before the
        // trailing "N upgrades available." summary, bound the data rows.
        if trimmed.is_empty() {
            if updates.is_empty() {
                continue;
            }
            break;
        }
        if trimmed.chars().all(|c| c == '-') {
            continue;
        }

        let name = slice_by_width(line, 0, id_at);
        let id = slice_by_width(line, id_at, version_at);
        let current_version = slice_by_width(line, version_at, available_at);
        let available_version = slice_by_width(line, available_at, source_at);

        // The summary line ("2 upgrades available.") has no id column content.
        if name.is_empty() || id.is_empty() || available_version.is_empty() {
            continue;
        }

        updates.push(AvailableUpdate {
            name,
            id,
            current_version,
            available_version,
        });
    }
    updates
}

/// Strip progress-spinner artefacts and split into display lines.
///
/// winget animates progress by rewriting the current line with `\r`, so a naive
/// split leaves spinner fragments interleaved with the table. Keeping only the
/// text after the final `\r` on each line discards them.
fn normalize_winget_lines(output: &str) -> Vec<String> {
    output
        .split('\n')
        .map(|line| line.rsplit('\r').next().unwrap_or(line).trim_end().to_string())
        .filter(|line| !line.chars().all(|c| matches!(c, '-' | '\\' | '|' | '/' | ' ')) || line.is_empty())
        .collect()
}

fn is_upgrade_header(line: &str) -> bool {
    line.contains("Name") && line.contains("Id") && line.contains("Version") && line.contains("Available")
}

/// Display-width position at which a header column begins.
fn column_start(header: &str, label: &str) -> Option<usize> {
    let byte_idx = header.find(label)?;
    Some(header[..byte_idx].width())
}

/// Take the part of `line` lying between two display-width positions.
///
/// Characters are consumed until `from` is reached and collected until `to`.
/// A wide character straddling a boundary is assigned to the column it starts
/// in, which matches how the padding was generated.
fn slice_by_width(line: &str, from: usize, to: usize) -> String {
    let mut column = 0usize;
    let mut out = String::new();
    for ch in line.chars() {
        let w = ch.width().unwrap_or(0);
        if column >= to {
            break;
        }
        if column >= from {
            out.push(ch);
        }
        column += w;
    }
    out.trim().to_string()
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

        self.winget_available = Self::ensure_winget().await;
        if !self.winget_available {
            ui::markup_line(
                "[yellow]⚠ winget is not available - cannot determine latest versions[/]",
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
            self.winget_available = Self::ensure_winget().await;
            if self.winget_available {
                self.updates = Self::read_available_updates().await;
            }
        }

        // Without a catalogue there is no "latest version" to compare against,
        // so the task cannot do its job. Say so plainly rather than reporting a
        // vacuous success.
        if !self.winget_available {
            result.success = false;
            result.message = format!(
                "Inventoried {} application(s) but could not check for updates: winget is not installed.",
                self.installed.len()
            );
            result.error_details = Some(
                "winget (Windows Package Manager) is required to determine the latest available \
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
            result.message = format!("DRY RUN: {} update(s) would be applied.", self.updates.len());
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
            format!("Updated {} application(s) to the latest version.", updated.len())
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
        if !self.winget_available {
            ui::markup_line("[yellow]? Cannot verify update status without winget[/]");
            return false;
        }

        let remaining = Self::read_available_updates().await;
        if remaining.is_empty() {
            ui::markup_line("[green]? All applications are at the latest available version[/]");
            return true;
        }

        for update in &remaining {
            ui::markup_line(&format!(
                "[red]? {} is still at {} (latest {})[/]",
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

    const WINGET_UPGRADE_OUTPUT: &str = "\
Name                             Id                            Version      Available    Source
-------------------------------------------------------------------------------------------------
Microsoft Edge                   Microsoft.Edge                120.0.2210   121.0.2277   winget
7-Zip 22.01 (x64)                7zip.7zip                     22.01        23.01        winget
Mozilla Firefox (x64 en-US)      Mozilla.Firefox               115.0        122.0.1      winget

3 upgrades available.
";

    #[test]
    fn winget_table_is_split_on_header_column_offsets() {
        let updates = parse_winget_upgrades(WINGET_UPGRADE_OUTPUT);
        assert_eq!(updates.len(), 3, "got {updates:#?}");

        // Names contain spaces and parentheses, so whitespace splitting would
        // mangle them; column offsets keep them intact.
        assert_eq!(updates[1].name, "7-Zip 22.01 (x64)");
        assert_eq!(updates[1].id, "7zip.7zip");
        assert_eq!(updates[1].current_version, "22.01");
        assert_eq!(updates[1].available_version, "23.01");

        assert_eq!(updates[2].name, "Mozilla Firefox (x64 en-US)");
        assert_eq!(updates[2].available_version, "122.0.1");
    }

    #[test]
    fn winget_summary_line_is_not_parsed_as_a_package() {
        let updates = parse_winget_upgrades(WINGET_UPGRADE_OUTPUT);
        assert!(
            !updates.iter().any(|u| u.name.contains("upgrades available")),
            "summary line leaked into results: {updates:#?}"
        );
    }

    #[test]
    fn winget_progress_spinner_artifacts_are_discarded() {
        // winget rewrites the line with \r while it works; the table follows.
        let noisy = format!("  -\r  \\\r  |\r  /\r{WINGET_UPGRADE_OUTPUT}");
        let updates = parse_winget_upgrades(&noisy);
        assert_eq!(updates.len(), 3, "got {updates:#?}");
        assert_eq!(updates[0].name, "Microsoft Edge");
    }

    #[test]
    fn no_upgrades_yields_no_results() {
        assert!(parse_winget_upgrades("No installed package found matching input criteria.").is_empty());
        assert!(parse_winget_upgrades("").is_empty());
    }

    #[test]
    fn non_ascii_package_names_do_not_panic_and_keep_their_columns() {
        // Byte-offset slicing would panic mid-character here.
        let output = "\
Name                    Id                  Version   Available  Source
------------------------------------------------------------------------
メモ帳                  Example.Notepad     1.0       2.0        winget
";
        let updates = parse_winget_upgrades(output);
        assert_eq!(updates.len(), 1, "got {updates:#?}");
        assert_eq!(updates[0].id, "Example.Notepad");
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
        use crate::models::SoftwareRequirement;

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
