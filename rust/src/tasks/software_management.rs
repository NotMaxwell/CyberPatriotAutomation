//! Removes prohibited software, installs required software as specified in the
//! README, and runs Windows Defender malware scans.

use crate::chocolatey;
use crate::command;
use crate::impl_task_meta;
use crate::knowledge::{ALWAYS_PROHIBITED, PACKAGE_IDS};
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

/// Windows display names mapped to the Chocolatey package that installs them.
///
/// The `.install` packages run the vendor installer, which puts the program
/// under Program Files. The bare ids are portable packages that unpack under
/// ProgramData instead - and the CP19 answer key deducts points when 7-Zip,
/// Notepad++, Chrome or Wireshark are "not installed at the default location".
/// The Chocolatey package id to install for a requirement.
pub fn package_id_for(requirement: &SoftwareRequirement) -> String {
    if let Some((_, id)) = PACKAGE_IDS
        .iter()
        .find(|(key, _)| key.eq_ignore_ascii_case(&requirement.name))
    {
        return (*id).to_string();
    }

    // Chocolatey ids are lower-case and unspaced; this is a best effort for
    // anything the table does not name explicitly.
    requirement
        .name
        .to_lowercase()
        .chars()
        .filter(|c| c.is_ascii_alphanumeric() || *c == '-' || *c == '.')
        .collect()
}

pub struct SoftwareManagementTask {
    name: String,
    description: String,
    dry_run: bool,
    pub prohibited_software: Vec<String>,
    pub required_software: Vec<SoftwareRequirement>,
    pub run_malware_scan: bool,
    pub use_quick_scan: bool,
    /// Bring already-installed software up to date through Chocolatey.
    pub update_installed_software: bool,
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
            update_installed_software: true,
        };
        // With no README the default prohibitions are the whole list, so they
        // are seeded here rather than waiting for a set_readme_data that may
        // never come.
        task.apply_default_prohibitions();
        task
    }

    pub fn set_readme_data(&mut self, readme: &ReadmeData) {
        self.required_software = readme.required_software.clone();
        self.prohibited_software = readme.prohibited_software.clone();
        self.apply_default_prohibitions();
    }

    /// Add [`ALWAYS_PROHIBITED`] unless the README requires that software.
    ///
    /// Called from `new` as well as from `set_readme_data`. It used to live only
    /// in the latter, which the caller invokes only when a README parsed - so a
    /// run without one left the prohibited list **empty** and removed nothing at
    /// all. Python, CCleaner and Jellyfin are prohibited by default precisely
    /// because no README names them, so the defaults have to survive the README
    /// being absent.
    fn apply_default_prohibitions(&mut self) {
        for candidate in ALWAYS_PROHIBITED {
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
    /// Returns `None` when it could not be read - which is different from an
    /// empty machine, and every caller has to keep treating it that way.
    ///
    /// There is no `wmic product` fallback any more. It was wrong on every axis
    /// that matters here: deprecated and absent on current Windows 11 images;
    /// blind to everything not installed by MSI, which is most of what a
    /// competition asks you to remove; minutes slow, because enumerating
    /// `Win32_Product` makes the installer service *reconfigure every installed
    /// product*; and it yields no uninstall string, so a program it did find
    /// could not then be removed. Worse than useless: a partial MSI-only list
    /// looks like a successful read, so verification would pass judgement on an
    /// inventory missing most of the machine.
    async fn read_installed() -> Option<Vec<software_matching::InstalledSoftware>> {
        #[cfg(windows)]
        {
            let programs = crate::native::installed_software::enumerate().or_else(|| {
                run_log::diagnostic("software", "the uninstall registry could not be read");
                None
            })?;
            Some(
                programs
                    .into_iter()
                    .map(|p| software_matching::InstalledSoftware {
                        name: p.name,
                        version: p.version,
                        uninstall_string: p.uninstall_string,
                        uninstall_is_quiet: p.uninstall_is_quiet,
                    })
                    .collect(),
            )
        }

        // The uninstall keys are a Windows concept; off Windows there is no
        // inventory to read, and saying so is better than reporting an empty
        // machine.
        #[cfg(not(windows))]
        {
            run_log::diagnostic(
                "software",
                "not running on Windows; there is no installed-software inventory to read",
            );
            None
        }
    }

    /// Uninstall one program. Returns `None` on success, or the reason.
    ///
    /// `wmic product call uninstall` is gone: it reads Win32_Product, which
    /// knows only MSI installs, and exits 0 when its where-clause matches
    /// nothing - so it reported success for every non-MSI program while removing
    /// none of them. The registered uninstall command, made unattended, is what
    /// actually removes CCleaner, Notepad++ and Jellyfin.
    async fn uninstall(
        software: &software_matching::InstalledSoftware,
        choco_packages: Option<&[String]>,
    ) -> Option<String> {
        // 1. Chocolatey, if it owns the package. It uninstalls silently and
        //    reports a real reason when it cannot.
        if let Some(packages) = choco_packages
            && let Some(id) = software_matching::resolve_package_id(&software.name, PACKAGE_IDS)
            && packages.iter().any(|p| p.eq_ignore_ascii_case(&id))
        {
            run_log::diagnostic(
                "software",
                &format!("{}: uninstalling through Chocolatey as {id}", software.name),
            );
            match chocolatey::uninstall(&id).await {
                None => return None,
                Some(reason) => run_log::diagnostic(
                    "software",
                    &format!(
                        "{}: choco uninstall {id} failed ({reason}); \
                                 falling back to the registered uninstall command",
                        software.name
                    ),
                ),
            }
        }

        // 2. The registered uninstall command, made unattended. This is what
        //    removes NSIS and Inno software - CCleaner, Notepad++, Jellyfin
        //    Media Player - none of which `wmic product` could touch.
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
            &format!(
                "{}: running {} {}",
                software.name, command.program, command.arguments
            ),
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

    /// Runs a Windows Defender malware scan and returns (success, threats_found, message).
    async fn run_windows_defender_scan(&self) -> (bool, i32, String) {
        let scan_type = if self.use_quick_scan {
            "QuickScan"
        } else {
            "FullScan"
        };
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
            return (
                false,
                0,
                format!(
                    "Windows Defender scan failed: {}",
                    scan_error.unwrap_or_default()
                ),
            );
        }

        ui::markup_line(&format!(
            "[green]✓ Windows Defender {scan_type} completed[/]"
        ));

        let (threat_success, threat_output, _e) = command::powershell_query(
            "Get-MpThreatDetection | Select-Object -Property ThreatID, ActionSuccess | ConvertTo-Json",
        )
        .await;

        let mut threats_found = 0;
        if threat_success && !threat_output.trim().is_empty() {
            threats_found = threat_output.split("ThreatID").count() as i32 - 1;
            if threats_found > 0 {
                ui::markup_line(&format!(
                    "[red]⚠ Windows Defender found {threats_found} threat(s)[/]"
                ));
                let (remove_success, _o, remove_error) =
                    command::powershell("Remove-MpThreat").await;
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
            ui::markup_line(
                "[yellow]DRY RUN: Previewing software management changes (no changes will be made)[/]",
            );
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
                error_details: Some(
                    "The Windows uninstall registry could not be read.".to_string(),
                ),
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
        run_log::diagnostic(
            "software",
            &format!("inventory: {} programs", installed.len()),
        );
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
                    item.uninstall_string
                        .as_deref()
                        .unwrap_or("none registered")
                ),
            );
        }

        let mut details: Vec<String> = Vec::new();
        details.push(format!(
            "Installed software checked: {}",
            installed
                .iter()
                .map(|i| i.name.clone())
                .collect::<Vec<_>>()
                .join(", ")
        ));
        details.push(format!(
            "Prohibited software list: {}",
            self.prohibited_software.join(", ")
        ));
        details.push(format!(
            "Required software list: {}",
            self.required_software
                .iter()
                .map(|r| r.name.clone())
                .collect::<Vec<_>>()
                .join(", ")
        ));

        if !to_remove.is_empty() {
            details.push(format!(
                "To remove: {}",
                to_remove
                    .iter()
                    .map(|i| i.name.clone())
                    .collect::<Vec<_>>()
                    .join(", ")
            ));
        } else {
            details.push("No prohibited software found to remove.".to_string());
        }

        if !to_install.is_empty() {
            details.push(format!(
                "Missing required software: {}",
                to_install
                    .iter()
                    .map(|s| s.name.clone())
                    .collect::<Vec<_>>()
                    .join(", ")
            ));
        } else {
            details.push("All required software is installed.".to_string());
        }

        // Read once: `choco list` is slow, and the answer does not change
        // between removals.
        let choco_packages = if to_remove.is_empty() {
            None
        } else {
            chocolatey::list_installed().await
        };

        let mut removal_failures: Vec<String> = Vec::new();
        for sw in &to_remove {
            match Self::uninstall(sw, choco_packages.as_deref()).await {
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
        let mut survivors: Vec<String> = Vec::new();
        if !to_remove.is_empty()
            && let Some(after) = Self::read_installed().await
        {
            survivors = after
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
                    removal_failures.push(format!("{name}: reported removed but still installed"));
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
        // Install required software through Chocolatey, bootstrapping it if
        // absent. The port used to print "manual install may be needed" and
        // stop there, so a README's required software was never installed.
        let mut install_failures: Vec<String> = Vec::new();
        let mut installed_now: Vec<String> = Vec::new();
        if !to_install.is_empty() {
            match chocolatey::ensure_available().await {
                Some(choco_error) => {
                    for sw in &to_install {
                        install_failures.push(format!("{}: {choco_error}", sw.name));
                        ui::markup_line(&format!(
                            "[red]✗ Cannot install {}: {}[/]",
                            ui::escape(&sw.name),
                            ui::escape(&choco_error)
                        ));
                    }
                    details.push(format!("Chocolatey unavailable: {choco_error}"));
                }
                None => {
                    for sw in &to_install {
                        let package = package_id_for(sw);
                        ui::markup_line(&format!(
                            "[cyan]Installing {} (choco: {})...[/]",
                            ui::escape(&sw.name),
                            ui::escape(&package)
                        ));
                        match chocolatey::install(&package).await {
                            None => {
                                installed_now.push(sw.name.clone());
                                ui::markup_line(&format!(
                                    "[green]✓ Installed: {}[/]",
                                    ui::escape(&sw.name)
                                ));
                            }
                            Some(failure) => {
                                install_failures.push(format!("{}: {failure}", sw.name));
                                ui::markup_line(&format!(
                                    "[red]✗ Failed to install {}: {}[/]",
                                    ui::escape(&sw.name),
                                    ui::escape(&failure)
                                ));
                            }
                        }
                    }
                }
            }
        }

        if !installed_now.is_empty() {
            details.push(format!(
                "Installed via Chocolatey: {}",
                installed_now.join(", ")
            ));
        }
        if !install_failures.is_empty() {
            details.push(format!(
                "Failed to install: {}",
                install_failures.join("; ")
            ));
        }

        // Bring already-installed software up to date.
        //
        // `choco upgrade all` only touches packages Chocolatey itself
        // installed, so software that came with the image - which is exactly
        // what a competition asks you to update - is never considered.
        // Upgrading each package by name reaches it regardless of how it was
        // installed, because `choco upgrade` runs the newer vendor installer
        // over the top. The CP19 answer key scored "Notepad++ has been updated"
        // and "Google Chrome has been updated" as separate items, and both were
        // pre-installed.
        let mut update_failures: Vec<String> = Vec::new();
        let mut updated_now: Vec<String> = Vec::new();
        // Chocolatey is *ensured*, not merely detected. Detecting it while the
        // bootstrap lived inside the install branch above meant that on the
        // common image - required software present but out of date - nothing
        // was missing, so Chocolatey was never installed and the whole update
        // step was skipped in silence.
        let update_blocker = if self.update_installed_software {
            chocolatey::ensure_available().await
        } else {
            None
        };

        if let Some(blocker) = update_blocker {
            details.push(format!("Could not update installed software: {blocker}"));
            run_log::diagnostic("software", &format!("updates skipped: {blocker}"));
            ui::markup_line(&format!(
                "[red]✗ Cannot update installed software: {}[/]",
                ui::escape(&blocker)
            ));
        } else if self.update_installed_software {
            // Never offer prohibited software to the updater.
            //
            // `choco upgrade <pkg>` *installs* a package that is not present,
            // so feeding it software this run just uninstalled reinstalls it -
            // and the candidate list is built from the inventory read *before*
            // removal, so every removed program is still in it. A real run
            // removed Python 3.13.0 and then put Python 3.14.7 back four
            // minutes later, which is worse than never having removed it.
            let prohibited_ids: Vec<String> = to_remove
                .iter()
                .filter_map(|i| software_matching::resolve_package_id(&i.name, PACKAGE_IDS))
                .collect();

            for id in &prohibited_ids {
                run_log::diagnostic(
                    "software",
                    &format!("excluded from updates (prohibited): {id}"),
                );
            }

            // Anything installed whose display name resolves to a package id we
            // recognise: an image can ship outdated software the README never
            // mentions. Resolution is fuzzy because display names carry
            // version, bitness and locale suffixes - "Notepad++ (64-bit x64)",
            // "Mozilla Firefox (x64 en-US)".
            let mut to_update: Vec<String> = Vec::new();
            /// Add a package id once, unless it would upgrade prohibited software.
            fn push(id: String, prohibited: &[String], to_update: &mut Vec<String>) {
                if !id.is_empty()
                    && !prohibited.iter().any(|p| p.eq_ignore_ascii_case(&id))
                    && !to_update.iter().any(|u| u.eq_ignore_ascii_case(&id))
                {
                    to_update.push(id);
                }
            }

            for requirement in &self.required_software {
                push(package_id_for(requirement), &prohibited_ids, &mut to_update);
            }
            for item in &installed {
                if to_remove.iter().any(|r| r.name == item.name) {
                    continue;
                }
                if let Some(id) = software_matching::resolve_package_id(&item.name, PACKAGE_IDS) {
                    run_log::diagnostic(
                        "software",
                        &format!("update candidate: {} -> {id}", item.name),
                    );
                    push(id, &prohibited_ids, &mut to_update);
                }
            }

            for package in &to_update {
                ui::markup_line(&format!("[cyan]Updating {}...[/]", ui::escape(package)));
                match chocolatey::upgrade(package).await {
                    None => {
                        updated_now.push(package.clone());
                        ui::markup_line(&format!(
                            "[green]✓ Up to date: {}[/]",
                            ui::escape(package)
                        ));
                    }
                    Some(failure) => {
                        update_failures.push(format!("{package}: {failure}"));
                        ui::markup_line(&format!(
                            "[yellow]! Could not update {}: {}[/]",
                            ui::escape(package),
                            ui::escape(&failure)
                        ));
                    }
                }
            }

            // Then anything else Chocolatey manages, which the loop above
            // misses. Skipped when prohibited software is still installed:
            // `upgrade all` would happily bring the survivor to its latest
            // version, which is the opposite of what this task is for.
            //
            // The question is "did anything prohibited survive", so it is asked
            // of the post-removal inventory rather than of `prohibited_ids`.
            // Keying it on the ids meant the guard depended on the package
            // table being complete: CCleaner and Jellyfin had no entry, so on
            // an image where either survived removal the list came back empty
            // and `upgrade all` ran anyway - exactly the case the guard exists
            // to prevent.
            if survivors.is_empty() {
                if let Some(upgrade_error) = chocolatey::upgrade_all().await {
                    details.push(format!("choco upgrade all reported: {upgrade_error}"));
                }
            } else {
                run_log::diagnostic(
                    "software",
                    &format!(
                        "skipped `choco upgrade all`: {} is still installed and it would upgrade it",
                        survivors.join(", ")
                    ),
                );
            }
        }

        if !updated_now.is_empty() {
            details.push(format!("Updated: {}", updated_now.join(", ")));
        }
        if !update_failures.is_empty() {
            details.push(format!("Could not update: {}", update_failures.join("; ")));
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
            // software reported the task as failed. Software that is still
            // missing after the install step is a genuine outstanding problem,
            // so those failures remain part of the condition.
            success: removal_failures.is_empty()
                && install_failures.is_empty()
                && malware_scan_success
                && threats_found == 0,
            message: details.join("\n"),
            error_details: (!removal_failures.is_empty() || !install_failures.is_empty()).then(
                || {
                    removal_failures
                        .iter()
                        .chain(install_failures.iter())
                        .cloned()
                        .collect::<Vec<_>>()
                        .join("\n")
                },
            ),
            ..Default::default()
        }
    }

    async fn verify(&mut self) -> bool {
        // The same inventory the task itself works from, rather than a second
        // `wmic product` call: wmic sees only MSI installs, so it could not see
        // the NSIS and Inno programs this task removes and reported them gone
        // whether they were or not.
        //
        // A read failure is not proof the machine is in the wanted state, so it
        // fails verification rather than passing on an empty list.
        let Some(installed) = Self::read_installed().await else {
            run_log::diagnostic("software", "verify: the inventory could not be read");
            return false;
        };

        let still_present: Vec<&str> = installed
            .iter()
            .filter(|i| {
                self.prohibited_software
                    .iter()
                    .any(|p| software_matching::matches(&i.name, p))
            })
            .map(|i| i.name.as_str())
            .collect();
        let still_missing: Vec<&str> = self
            .required_software
            .iter()
            .filter(|r| {
                !installed
                    .iter()
                    .any(|i| software_matching::matches(&i.name, &r.name))
            })
            .map(|r| r.name.as_str())
            .collect();

        // Say which, rather than just failing. A bare false sends the reader
        // back to the console scrollback to work out what verification objected
        // to.
        for name in &still_present {
            run_log::diagnostic(
                "software",
                &format!("verify: prohibited software still installed: {name}"),
            );
        }
        for name in &still_missing {
            run_log::diagnostic(
                "software",
                &format!("verify: required software still missing: {name}"),
            );
        }

        still_present.is_empty() && still_missing.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn requirement(name: &str) -> SoftwareRequirement {
        SoftwareRequirement {
            name: name.to_string(),
            ..Default::default()
        }
    }

    #[test]
    fn a_named_requirement_uses_its_table_entry() {
        assert_eq!(
            package_id_for(&requirement("Notepad++")),
            "notepadplusplus.install"
        );
        assert_eq!(
            package_id_for(&requirement("Google Chrome")),
            "googlechrome"
        );
        // The table is matched without regard to case.
        assert_eq!(package_id_for(&requirement("mozilla firefox")), "firefox");
    }

    /// Chocolatey ids are lower-case and unspaced, so an unlisted name is
    /// slugified rather than passed through with its spaces intact.
    #[test]
    fn an_unlisted_requirement_falls_back_to_a_slug() {
        assert_eq!(
            package_id_for(&requirement("Some Bespoke Tool")),
            "somebespoketool"
        );
        assert_eq!(package_id_for(&requirement("Node.js")), "node.js");
    }

    /// The display names from a real run resolve to the ids that run logged.
    #[test]
    fn real_installed_names_resolve_to_their_package() {
        for (installed, expected) in [
            ("7-Zip 24.08 (x64)", "7zip.install"),
            ("Notepad++ (32-bit x86)", "notepadplusplus.install"),
            ("Wireshark 4.4.1 x64", "wireshark"),
            ("Google Chrome", "googlechrome"),
            // Both Python entries must resolve, because that id is what the
            // prohibited-software exclusion is keyed on.
            ("Python 3.13.0 (64-bit)", "python"),
            ("Python Launcher", "python"),
        ] {
            assert_eq!(
                software_matching::resolve_package_id(installed, PACKAGE_IDS).as_deref(),
                Some(expected),
                "installed: {installed}"
            );
        }
    }

    /// The defaults have to survive the README being absent - that was the
    /// reason a run without one removed nothing at all.
    #[test]
    fn default_prohibitions_apply_without_a_readme() {
        let task = SoftwareManagementTask::new();
        for name in ALWAYS_PROHIBITED {
            assert!(
                task.prohibited_software.iter().any(|p| p == name),
                "{name} missing from {:?}",
                task.prohibited_software
            );
        }
    }

    /// A README that requires the software still wins over the default.
    #[test]
    fn required_software_is_not_prohibited_by_default() {
        let mut task = SoftwareManagementTask::new();
        task.required_software.clear();
        task.prohibited_software.clear();
        task.required_software.push(requirement("Python 3"));
        task.apply_default_prohibitions();

        assert!(!task.prohibited_software.iter().any(|p| p == "Python"));
        assert!(task.prohibited_software.iter().any(|p| p == "CCleaner"));
        assert!(task.prohibited_software.iter().any(|p| p == "Jellyfin"));
    }
}
