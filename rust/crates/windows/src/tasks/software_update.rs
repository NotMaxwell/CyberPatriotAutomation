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

use crate::chocolatey;
use crate::knowledge::{ALWAYS_PROHIBITED, PACKAGE_IDS};
use async_trait::async_trait;
use pinnacle_core::Task;
use pinnacle_core::command;
use pinnacle_core::impl_task_meta;
use pinnacle_core::models::{ReadmeData, SystemInfo, TaskResult};
use pinnacle_core::remediation;
use pinnacle_core::software_matching;
use pinnacle_core::ui;
use std::cmp::Ordering;
use std::time::Duration;

/// Each uninstall entry's display name and `InstallLocation`.
///
/// Read through PowerShell because the native inventory does not carry the
/// location; only used to compare before and after an upgrade.
const INSTALL_LOCATION_QUERY: &str = "\
$paths = @('HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\*', \
'HKLM:\\SOFTWARE\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\*', \
'HKCU:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\*'); \
Get-ItemProperty -Path $paths | Where-Object { $_.DisplayName } | \
Select-Object DisplayName, InstallLocation | ConvertTo-Csv -NoTypeInformation";

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

    /// `InstallLocation` of every uninstall entry that has one.
    async fn read_install_locations() -> Vec<(String, String)> {
        if !cfg!(windows) {
            return Vec::new();
        }
        let (success, output, _e) = command::powershell_query(INSTALL_LOCATION_QUERY).await;
        if success {
            parse_install_locations(&output)
        } else {
            Vec::new()
        }
    }

    /// Updates for installed programs Chocolatey did not install.
    ///
    /// `choco outdated` only sees packages it manages, which is not the software
    /// that came with the image. For each inventory entry that maps to a package,
    /// ask the catalogue for the latest version and keep it when ours is older.
    async fn read_unmanaged_updates(&self) -> Vec<AvailableUpdate> {
        let Some(choco) = Self::choco_path().await else {
            return Vec::new();
        };
        let managed = chocolatey::list_installed().await.unwrap_or_default();
        let prohibited = prohibited_terms(self.readme_data.as_ref());

        let mut updates = Vec::new();
        for candidate in unmanaged_candidates(&self.installed, &managed, &prohibited) {
            let args = format!("search {} --exact --limit-output", candidate.id);
            let (code, output, _e) =
                command::execute_for_exit_code(&choco, Some(&args), CHOCO_QUERY_TIMEOUT).await;
            if !code.is_some_and(|c| CHOCO_SUCCESS_CODES.contains(&c)) {
                continue;
            }
            let Some(latest) = parse_choco_search(&output, &candidate.id) else {
                continue;
            };
            if is_older(&candidate.version, &latest) {
                updates.push(AvailableUpdate {
                    name: candidate.name,
                    id: candidate.id,
                    current_version: candidate.version,
                    available_version: latest,
                });
            }
        }
        updates
    }

    /// Everything out of date: choco-managed packages and the rest.
    async fn read_all_updates(&self) -> Vec<AvailableUpdate> {
        let mut updates = Self::read_available_updates().await;
        for extra in self.read_unmanaged_updates().await {
            if !updates.iter().any(|u| same_package(&u.id, &extra.id)) {
                updates.push(extra);
            }
        }
        updates
    }

    /// Does this update correspond to software the README requires at all?
    fn is_required(&self, update: &AvailableUpdate) -> bool {
        self.readme_data.as_ref().is_some_and(|r| {
            r.required_software.iter().any(|req| {
                software_matching::matches(&update.name, &req.name)
                    || software_matching::resolve_package_id(&req.name, PACKAGE_IDS)
                        .is_some_and(|id| same_package(&id, &update.id))
            })
        })
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

/// Compare two dotted version strings numerically.
///
/// Segments are split on `.` and `-`, and only their leading digits count, so
/// `24.08` equals `24.8.0` and a pre-release suffix is ignored. Plain string
/// comparison puts `9.0` after `10.0`, which would report an old install as newer.
pub fn compare_versions(a: &str, b: &str) -> Ordering {
    fn parts(v: &str) -> Vec<u64> {
        v.trim()
            .trim_start_matches(['v', 'V'])
            .split(['.', '-', '+'])
            .map(|seg| {
                seg.chars()
                    .take_while(char::is_ascii_digit)
                    .collect::<String>()
                    .parse()
                    .unwrap_or(0)
            })
            .collect()
    }
    let (a, b) = (parts(a), parts(b));
    for i in 0..a.len().max(b.len()) {
        let ordering = a.get(i).unwrap_or(&0).cmp(b.get(i).unwrap_or(&0));
        if ordering != Ordering::Equal {
            return ordering;
        }
    }
    Ordering::Equal
}

/// Is the installed version strictly older than the latest?
///
/// An empty or unparseable-as-nothing installed version is not "older": with no
/// evidence the software is out of date, it is left alone.
pub fn is_older(installed: &str, latest: &str) -> bool {
    let has_digit = |v: &str| v.chars().any(|c| c.is_ascii_digit());
    has_digit(installed)
        && has_digit(latest)
        && compare_versions(installed, latest) == Ordering::Less
}

/// The version `choco search <id> --exact --limit-output` printed for `id`.
pub fn parse_choco_search(output: &str, id: &str) -> Option<String> {
    output.lines().find_map(|line| {
        let (name, version) = line.trim().split_once('|')?;
        let version = version.split('|').next()?.trim();
        (name.trim().eq_ignore_ascii_case(id) && !version.is_empty()).then(|| version.to_string())
    })
}

/// Two package ids that name the same software: `7zip` and `7zip.install` do.
fn same_package(a: &str, b: &str) -> bool {
    let core = |id: &str| {
        let lower = id.to_lowercase();
        lower.strip_suffix(".install").unwrap_or(&lower).to_string()
    };
    core(a) == core(b)
}

/// An installed program Chocolatey does not manage, that maps to a package.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnmanagedCandidate {
    pub name: String,
    pub id: String,
    pub version: String,
}

/// The programs worth asking Chocolatey about: installed with a known version,
/// mapped to a package id, not already choco-managed (`choco outdated` covers
/// those) and not prohibited (`choco upgrade` of a missing package would install
/// it). One entry per package, since "Python" and "Python Launcher" are one id.
pub fn unmanaged_candidates(
    installed: &[InstalledApp],
    managed: &[String],
    prohibited: &[String],
) -> Vec<UnmanagedCandidate> {
    let mut out: Vec<UnmanagedCandidate> = Vec::new();
    for app in installed {
        if app.version.trim().is_empty()
            || prohibited
                .iter()
                .any(|p| software_matching::matches(&app.name, p))
        {
            continue;
        }
        let Some(id) = software_matching::resolve_package_id(&app.name, PACKAGE_IDS) else {
            continue;
        };
        if managed.iter().any(|m| same_package(m, &id))
            || out.iter().any(|c| same_package(&c.id, &id))
        {
            continue;
        }
        out.push(UnmanagedCandidate {
            name: app.name.clone(),
            id,
            version: app.version.clone(),
        });
    }
    out
}

/// The prohibited terms in force: the README's list plus the defaults it does
/// not require, the same rule Software Management applies.
pub fn prohibited_terms(readme: Option<&ReadmeData>) -> Vec<String> {
    let mut terms: Vec<String> = readme
        .map(|r| r.prohibited_software.clone())
        .unwrap_or_default();
    for default in ALWAYS_PROHIBITED {
        let required = readme.is_some_and(|r| {
            r.required_software
                .iter()
                .any(|req| software_matching::matches(&req.name, default))
        });
        if !required && !terms.iter().any(|t| t.eq_ignore_ascii_case(default)) {
            terms.push((*default).to_string());
        }
    }
    terms
}

/// Parse the `DisplayName, InstallLocation` CSV into (name, location) pairs,
/// dropping entries with no location.
pub fn parse_install_locations(csv: &str) -> Vec<(String, String)> {
    csv.split(['\r', '\n'])
        .filter(|l| !l.trim().is_empty())
        .skip(1)
        .filter_map(|line| {
            let fields = crate::tasks::parse_csv_line(line);
            let unquote = |s: &str| s.trim().trim_matches('"').trim().to_string();
            let name = unquote(fields.first()?);
            let location = unquote(fields.get(1)?);
            (!name.is_empty() && !location.is_empty()).then_some((name, location))
        })
        .collect()
}

fn normalize_location(path: &str) -> String {
    path.trim()
        .trim_matches('"')
        .trim_end_matches(['\\', '/'])
        .to_lowercase()
}

/// Did upgrading `id` move the program? Returns (before, after) when every
/// location recorded for it beforehand is absent afterwards.
///
/// Entries are matched through the package table because the display name changes
/// with the version ("7-Zip 24.08 (x64)" becomes "7-Zip 25.01 (x64)"). A program
/// with no location on either side has nothing to compare, and is not flagged.
pub fn location_shift(
    before: &[(String, String)],
    after: &[(String, String)],
    id: &str,
) -> Option<(String, String)> {
    let locations = |entries: &[(String, String)]| -> Vec<String> {
        entries
            .iter()
            .filter(|(name, _)| {
                software_matching::resolve_package_id(name, PACKAGE_IDS)
                    .is_some_and(|resolved| same_package(&resolved, id))
            })
            .map(|(_, location)| location.clone())
            .collect()
    };
    let (was, now) = (locations(before), locations(after));
    let (first_was, first_now) = (was.first()?, now.first()?);
    let unchanged = now.iter().any(|n| {
        was.iter()
            .any(|w| normalize_location(w) == normalize_location(n))
    });
    (!unchanged).then(|| (first_was.clone(), first_now.clone()))
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
        self.updates = self.read_all_updates().await;
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
            self.updates = self.read_all_updates().await;
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
        ordered.sort_by_key(|u| !(self.is_priority(u, &priority) || self.is_required(u)));

        let mut updated: Vec<String> = Vec::new();
        let mut failed: Vec<String> = Vec::new();
        let mut moved: Vec<String> = Vec::new();

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

            let locations_before = Self::read_install_locations().await;
            match Self::apply_update(update).await {
                Ok(()) => {
                    updated.push(format!(
                        "{} {} → {}",
                        update.name, update.current_version, update.available_version
                    ));
                    // A vendor installer that moved the program leaves it "not
                    // installed at the default location", which the CP18 keys
                    // penalise for Chrome, Notepad++, 7-Zip, Wireshark and Firefox.
                    let locations_after = Self::read_install_locations().await;
                    if let Some((was, now)) =
                        location_shift(&locations_before, &locations_after, &update.id)
                    {
                        let evidence = format!(
                            "{} moved from {was} to {now} while updating; probable penalty, \
                             not installed at the default location",
                            update.name
                        );
                        remediation::record_finding(
                            &format!("InstallLocation of {}", update.name),
                            "stays at the default install location",
                            false,
                            &evidence,
                        );
                        ui::markup_line(&format!("[red]✗ {}[/]", ui::escape(&evidence)));
                        moved.push(evidence);
                    }
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
        if !moved.is_empty() {
            result.message = format!("{}\n{}", result.message, moved.join("\n"));
        }

        result
    }

    async fn verify(&mut self) -> bool {
        if !self.choco_available {
            ui::markup_line("[yellow]⚠ Cannot verify update status without Chocolatey[/]");
            return false;
        }

        let remaining = self.read_all_updates().await;
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

    fn app(name: &str, version: &str) -> InstalledApp {
        InstalledApp {
            name: name.to_string(),
            version: version.to_string(),
            publisher: String::new(),
        }
    }

    fn strings(items: &[&str]) -> Vec<String> {
        items.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn versions_compare_numerically_not_as_text() {
        assert_eq!(compare_versions("9.0", "10.0"), Ordering::Less);
        assert_eq!(compare_versions("24.08", "24.8.0"), Ordering::Equal);
        assert_eq!(
            compare_versions("120.0.6099.109", "119.9"),
            Ordering::Greater
        );
        assert_eq!(compare_versions("2.0.0-beta1", "2.0"), Ordering::Equal);
    }

    #[test]
    fn only_a_strictly_older_install_needs_updating() {
        assert!(is_older("115.0", "122.0.1"));
        assert!(!is_older("122.0.1", "122.0.1"));
        assert!(!is_older("123.0", "122.0.1"));
        // No installed version is no evidence of staleness.
        assert!(!is_older("", "122.0.1"));
    }

    #[test]
    fn the_latest_version_is_read_from_the_exact_match() {
        let output = "googlechrome|126.0.6478.127\nother|1.0\n";
        assert_eq!(
            parse_choco_search(output, "googlechrome").as_deref(),
            Some("126.0.6478.127")
        );
        assert_eq!(parse_choco_search(output, "firefox"), None);
        assert_eq!(parse_choco_search("", "firefox"), None);
    }

    #[test]
    fn unmanaged_candidates_skip_managed_prohibited_and_versionless() {
        let installed = vec![
            app("Google Chrome", "120.0"),
            app("Notepad++ (64-bit x64)", "8.5"),
            app("7-Zip 22.01 (x64)", "22.01"),
            app("Wireshark 4.0", "4.0"),
            app("Mozilla Firefox (x64 en-US)", ""),
            app("Unrelated Tool", "1.0"),
        ];
        let managed = strings(&["notepadplusplus.install"]);
        let prohibited = prohibited_terms(None);
        let found = unmanaged_candidates(&installed, &managed, &prohibited);
        let ids: Vec<&str> = found.iter().map(|c| c.id.as_str()).collect();
        // Wireshark is prohibited by default; Notepad++ is choco-managed.
        assert_eq!(ids, vec!["googlechrome", "7zip.install"]);
    }

    #[test]
    fn a_required_wireshark_is_offered_for_update() {
        use pinnacle_core::models::SoftwareRequirement;
        let mut readme = ReadmeData::default();
        readme.required_software.push(SoftwareRequirement {
            name: "Wireshark".to_string(),
            ..Default::default()
        });
        let prohibited = prohibited_terms(Some(&readme));
        let found = unmanaged_candidates(&[app("Wireshark 4.0", "4.0")], &[], &prohibited);
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].id, "wireshark");
    }

    #[test]
    fn install_locations_are_parsed_and_blanks_dropped() {
        let csv = "\"DisplayName\",\"InstallLocation\"\r\n\
\"Google Chrome\",\"C:\\Program Files\\Google\\Chrome\\Application\"\r\n\
\"No Location\",\"\"\r\n";
        let locations = parse_install_locations(csv);
        assert_eq!(locations.len(), 1);
        assert_eq!(locations[0].0, "Google Chrome");
    }

    #[test]
    fn a_moved_install_is_detected_and_a_same_place_one_is_not() {
        let before = vec![(
            "7-Zip 22.01 (x64)".to_string(),
            r"C:\Program Files\7-Zip\".to_string(),
        )];
        let same = vec![(
            "7-Zip 23.01 (x64)".to_string(),
            r"c:\program files\7-zip".to_string(),
        )];
        let moved = vec![(
            "7-Zip 23.01 (x64)".to_string(),
            r"C:\ProgramData\chocolatey\lib\7zip".to_string(),
        )];
        assert_eq!(location_shift(&before, &same, "7zip.install"), None);
        assert_eq!(
            location_shift(&before, &moved, "7zip.install"),
            Some((
                r"C:\Program Files\7-Zip\".to_string(),
                r"C:\ProgramData\chocolatey\lib\7zip".to_string()
            ))
        );
        // Nothing recorded beforehand: nothing to compare.
        assert_eq!(location_shift(&[], &moved, "7zip.install"), None);
    }

    #[test]
    fn readme_required_software_is_updated_before_the_rest() {
        use pinnacle_core::models::SoftwareRequirement;
        let mut task = SoftwareUpdateTask::new();
        let mut readme = ReadmeData::default();
        readme.required_software.push(SoftwareRequirement {
            name: "Google Chrome".to_string(),
            ..Default::default()
        });
        task.set_readme_data(readme);
        let chrome = AvailableUpdate {
            name: "Google Chrome".to_string(),
            id: "googlechrome".to_string(),
            current_version: "1".to_string(),
            available_version: "2".to_string(),
        };
        let putty = AvailableUpdate {
            name: "PuTTY".to_string(),
            id: "putty".to_string(),
            current_version: "1".to_string(),
            available_version: "2".to_string(),
        };
        assert!(task.is_required(&chrome));
        assert!(!task.is_required(&putty));
    }
}
