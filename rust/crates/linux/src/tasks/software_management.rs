// =============================================================================
// PinnacleCyPat - Software management (Linux)
// Author: Maxwell McCormick
// Copyright 2026 Maxwell McCormick
// SPDX-License-Identifier: Apache-2.0
// =============================================================================

//! Purges prohibited packages and installs the ones the README requires.
//!
//! The matching - turning "Firefox (latest)" in a README into the package
//! `firefox` - is done by `pinnacle_core::software_matching`, the same code the
//! Windows task uses against Chocolatey ids. Only the table differs.
//!
//! **`purge`, not `remove`.** A removed package leaves its configuration and,
//! for a service, its unit file behind, so the settings an attacker put there
//! survive and a later reinstall picks them straight back up. Purging is also
//! what makes the state read back as `absent` rather than
//! `config-files remain`, which is what the proof step checks.
//!
//! The always-prohibited list is applied whether or not the README mentions
//! those packages, and that is the point: a README lists what is *required*,
//! and the planted tools are precisely the ones it will not name. A README that
//! explicitly requires one of them wins, because the requirement is checked
//! first.

use pinnacle_core::models::{ReadmeData, SystemInfo, TaskResult};
use pinnacle_core::software_matching::resolve_package_id;
use pinnacle_core::task::Task;
use pinnacle_core::{impl_task_meta, ui};

use crate::apt;
use crate::knowledge::{ALWAYS_PROHIBITED, PACKAGE_IDS};
use async_trait::async_trait;

pub struct SoftwareManagementTask {
    name: String,
    description: String,
    dry_run: bool,
    readme_data: Option<ReadmeData>,
}

impl SoftwareManagementTask {
    pub fn new() -> Self {
        Self {
            name: "Software Management".to_string(),
            description: "Purge prohibited packages, install required ones".to_string(),
            dry_run: false,
            readme_data: None,
        }
    }

    pub fn set_readme_data(&mut self, readme: &ReadmeData) {
        self.readme_data = Some(readme.clone());
    }
}

impl Default for SoftwareManagementTask {
    fn default() -> Self {
        Self::new()
    }
}

/// The packages the README requires, resolved to apt names.
///
/// A name that resolves to nothing is returned as a warning rather than
/// silently dropped: "no package matched Adobe Reader" is a fact the competitor
/// needs, and a required install that vanished without trace is the failure
/// mode this reporting exists to prevent.
pub fn required_packages(readme: &ReadmeData) -> (Vec<String>, Vec<String>) {
    let mut resolved = Vec::new();
    let mut unresolved = Vec::new();
    for requirement in &readme.required_software {
        match resolve_package_id(&requirement.name, PACKAGE_IDS) {
            Some(id) if !resolved.contains(&id) => resolved.push(id),
            Some(_) => {}
            None => unresolved.push(requirement.name.clone()),
        }
    }
    (resolved, unresolved)
}

/// The packages to purge: the always-prohibited list plus whatever the README
/// names, minus anything the README also requires.
pub fn prohibited_packages(readme: Option<&ReadmeData>) -> Vec<(String, String)> {
    let required: Vec<String> = readme.map(|r| required_packages(r).0).unwrap_or_default();

    let mut out: Vec<(String, String)> = Vec::new();
    let push = |name: String, why: String, out: &mut Vec<(String, String)>| {
        // A README requirement beats the default prohibition. Installing and
        // purging the same package in one run would otherwise come down to
        // which loop ran last.
        if required.contains(&name) || out.iter().any(|(n, _)| *n == name) {
            return;
        }
        out.push((name, why));
    };

    for (name, why) in ALWAYS_PROHIBITED {
        push(name.to_string(), (*why).to_string(), &mut out);
    }

    if let Some(readme) = readme {
        for entry in &readme.prohibited_software {
            // A README naming something the table does not know is used
            // verbatim: apt will simply report no such package, which is a
            // better outcome than not trying.
            let name =
                resolve_package_id(entry, PACKAGE_IDS).unwrap_or_else(|| entry.to_lowercase());
            push(name, "the README prohibits it".to_string(), &mut out);
        }
    }
    out
}

#[async_trait]
impl Task for SoftwareManagementTask {
    impl_task_meta!();

    async fn read_system_state(&mut self) -> SystemInfo {
        let installed = apt::installed().await;
        SystemInfo {
            raw_output: Some(format!("{} packages installed", installed.len())),
            ..Default::default()
        }
    }

    async fn execute(&mut self) -> TaskResult {
        let mut result = TaskResult {
            task_name: self.name.clone(),
            success: true,
            ..Default::default()
        };

        if !apt::is_available().await {
            result.message = "apt is not available; no packages were changed.".to_string();
            ui::markup_line("[yellow]⚠ This image does not use apt. Nothing was changed.[/]");
            return result;
        }

        let readme = self.readme_data.clone();
        let (required, unresolved) = readme
            .as_ref()
            .map(required_packages)
            .unwrap_or_else(|| (Vec::new(), Vec::new()));
        let prohibited = prohibited_packages(readme.as_ref());

        for name in &unresolved {
            ui::markup_line(&format!(
                "[yellow]⚠ No package matches \"{}\" - install it by hand.[/]",
                ui::escape(name)
            ));
        }

        // Only act on what is actually there. Purging twenty packages the image
        // never had produces twenty failures that bury the one that mattered.
        let mut present: Vec<(String, String)> = Vec::new();
        for (name, why) in &prohibited {
            if apt::is_installed(name).await {
                present.push((name.clone(), why.clone()));
            }
        }
        let mut missing: Vec<String> = Vec::new();
        for name in &required {
            if !apt::is_installed(name).await {
                missing.push(name.clone());
            }
        }

        result.items_attempted = (present.len() + missing.len()) as i32;

        if self.dry_run {
            for (name, why) in &present {
                ui::markup_line(&format!(
                    "[cyan]Would purge: {} [dim]({})[/][/]",
                    ui::escape(name),
                    ui::escape(why)
                ));
            }
            for name in &missing {
                ui::markup_line(&format!("[cyan]Would install: {}[/]", ui::escape(name)));
            }
            result.message = format!(
                "DRY RUN: would purge {} and install {} packages.",
                present.len(),
                missing.len()
            );
            return result;
        }

        let mut failures: Vec<String> = Vec::new();

        for (name, why) in &present {
            match apt::purge(name, why).await {
                Ok(()) => {
                    result.items_succeeded += 1;
                    ui::markup_line(&format!(
                        "[green]✓ Purged: {} [dim]({})[/][/]",
                        ui::escape(name),
                        ui::escape(why)
                    ));
                }
                Err(e) => failures.push(format!("{name}: {e}")),
            }
        }

        if !missing.is_empty() {
            // Refresh the lists once, not per package: an install against a
            // stale index fails with "unable to locate package" for something
            // that is perfectly available.
            apt::update_lists().await;
        }
        for name in &missing {
            match apt::install(name, "the README lists it as required").await {
                Ok(()) => {
                    result.items_succeeded += 1;
                    ui::markup_line(&format!("[green]✓ Installed: {}[/]", ui::escape(name)));
                }
                Err(e) => failures.push(format!("{name}: {e}")),
            }
        }

        result.success = failures.is_empty();
        result.message = format!("Purged {}, installed {}.", present.len(), missing.len());
        if !failures.is_empty() {
            result.error_details = Some(failures.join("; "));
        }
        result
    }

    async fn verify(&mut self) -> bool {
        for (name, _why) in prohibited_packages(self.readme_data.as_ref()) {
            if apt::is_installed(&name).await {
                return false;
            }
        }
        if let Some(readme) = &self.readme_data {
            for name in required_packages(readme).0 {
                if !apt::is_installed(&name).await {
                    return false;
                }
            }
        }
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use pinnacle_core::models::SoftwareRequirement;

    fn requirement(name: &str) -> SoftwareRequirement {
        SoftwareRequirement {
            name: name.to_string(),
            version: None,
            should_be_latest: true,
            is_required: true,
            notes: None,
        }
    }

    #[test]
    fn readme_names_resolve_to_apt_packages() {
        let readme = ReadmeData {
            required_software: vec![requirement("Firefox"), requirement("LibreOffice")],
            ..Default::default()
        };
        let (resolved, unresolved) = required_packages(&readme);
        assert_eq!(resolved, ["firefox", "libreoffice"]);
        assert!(unresolved.is_empty());
    }

    /// A requirement that matches nothing must be reported, not dropped. A
    /// silently skipped install is indistinguishable from one that worked.
    #[test]
    fn an_unmatched_requirement_is_reported() {
        let readme = ReadmeData {
            required_software: vec![requirement("Some Bespoke Internal Tool")],
            ..Default::default()
        };
        let (resolved, unresolved) = required_packages(&readme);
        assert!(resolved.is_empty());
        assert_eq!(unresolved, ["Some Bespoke Internal Tool"]);
    }

    /// The always-prohibited list applies with no README at all - which is the
    /// point, since a README never names the planted tools.
    #[test]
    fn hacking_tools_are_purged_without_the_readme_saying_so() {
        let prohibited = prohibited_packages(None);
        for expected in ["john", "hydra", "nmap"] {
            assert!(
                prohibited.iter().any(|(n, _)| n == expected),
                "{expected} is not on the purge list"
            );
        }
    }

    /// The conflict that would otherwise depend on loop order: a round whose
    /// scenario is "this is the security team's workstation" legitimately
    /// requires Wireshark.
    #[test]
    fn a_readme_requirement_beats_the_default_prohibition() {
        let readme = ReadmeData {
            required_software: vec![requirement("Wireshark")],
            ..Default::default()
        };
        let prohibited = prohibited_packages(Some(&readme));
        assert!(
            !prohibited.iter().any(|(n, _)| n == "wireshark"),
            "the README required Wireshark and it was still queued for purging"
        );
        // ...and the rest of the list is unaffected.
        assert!(prohibited.iter().any(|(n, _)| n == "john"));
    }

    #[test]
    fn a_readme_can_prohibit_something_the_table_does_not_know() {
        let readme = ReadmeData {
            prohibited_software: vec!["Some Game".to_string()],
            ..Default::default()
        };
        let prohibited = prohibited_packages(Some(&readme));
        assert!(prohibited.iter().any(|(n, _)| n == "some game"));
    }

    #[test]
    fn nothing_is_listed_for_purging_twice() {
        let readme = ReadmeData {
            prohibited_software: vec!["john".to_string(), "John the Ripper".to_string()],
            ..Default::default()
        };
        let prohibited = prohibited_packages(Some(&readme));
        let johns = prohibited.iter().filter(|(n, _)| n == "john").count();
        assert!(johns <= 1, "john appears {johns} times");
    }

    #[tokio::test]
    async fn a_dry_run_changes_nothing() {
        pinnacle_core::run_log::set_dry_run(true);
        let mut task = SoftwareManagementTask::new();
        task.set_dry_run(true);
        let result = pinnacle_core::ui::capture(task.execute()).await.0;
        pinnacle_core::run_log::set_dry_run(false);
        assert!(result.success);
    }
}
