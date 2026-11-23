// =============================================================================
// PinnacleCyPat - Security hardening (Linux)
// Author: Maxwell McCormick
// Copyright 2026 Maxwell McCormick
// SPDX-License-Identifier: Apache-2.0
// =============================================================================

//! Applies the kernel, SSH and shadow-suite settings in
//! [`knowledge::HARDENING_SETTINGS`](crate::knowledge::HARDENING_SETTINGS).
//!
//! This is the Linux counterpart of the Windows registry-hardening task, and
//! the settings table plays the same role: the code here is a loop, and every
//! decision about *what* to set lives in one reviewable list.
//!
//! Two things are written to drop-in files rather than to the main
//! configuration, and both matter:
//!
//! - `sshd_config.d/00-pinnacle.conf`, because Ubuntu 22.04 and later put
//!   `Include /etc/ssh/sshd_config.d/*.conf` as the *first* line of
//!   `sshd_config` and sshd obeys the first definition of a keyword it sees,
//!   reading drop-ins in lexical order. `00-` sorts first, so this file wins
//!   over every other drop-in (`99-` lost to a stock `50-cloud-init.conf`).
//! - `sysctl.d/99-pinnacle.conf`, because those files are read in lexical order
//!   and later values win, so `99-` makes this the effective setting among the
//!   drop-ins.
//!
//! Neither drop-in is the whole story, and a scored check does not care which
//! file is "effective": it greps. `/etc/sysctl.conf` is read *after* every
//! `sysctl.d` file (so a contrary line there beats the drop-in), and a checker
//! reading `sshd_config` sees whatever that file says. So a contrary *active*
//! line for a managed key is also rewritten in the main file and in the other
//! drop-ins - never a key added to a file that lacked it.
//!
//! The one README-driven exception is remote access. An image whose scenario is
//! "this machine is administered remotely" scores SSH being *available*, and a
//! run that hardens `PermitRootLogin` while masking `ssh` loses that point -
//! the same failure the Windows port had with Remote Desktop.

use pinnacle_core::models::{SystemInfo, TaskResult};
use pinnacle_core::task::Task;
use pinnacle_core::{impl_task_meta, models::ReadmeData, ui};

use crate::file_ops::{self, Style};
use crate::knowledge::{
    HARDENING_SETTINGS, MODPROBE_DROPIN, MODULES_TO_BLOCK, SSHD_DROPIN, SSHD_LEGACY_DROPIN,
    SYSCTL_DROPIN,
};
use crate::{readme_services, systemd_ops};
use async_trait::async_trait;
use pinnacle_core::remediation;

pub struct SecurityHardeningTask {
    name: String,
    description: String,
    dry_run: bool,
    readme_data: Option<ReadmeData>,
}

impl SecurityHardeningTask {
    pub fn new() -> Self {
        Self {
            name: "Security Hardening".to_string(),
            description: "Kernel, SSH and account-ageing hardening".to_string(),
            dry_run: false,
            readme_data: None,
        }
    }

    pub fn set_readme_data(&mut self, data: ReadmeData) {
        self.readme_data = Some(data);
    }

    /// Is SSH something the README wants kept working?
    fn ssh_is_required(&self) -> bool {
        readme_services::is_critical(self.readme_data.as_ref(), "ssh.service")
    }
}

impl Default for SecurityHardeningTask {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl Task for SecurityHardeningTask {
    impl_task_meta!();

    async fn read_system_state(&mut self) -> SystemInfo {
        let mut lines = Vec::new();
        for setting in HARDENING_SETTINGS {
            let state = file_ops::read(setting.path, setting.style, setting.key)
                .await
                .unwrap_or_else(|| "unreadable".to_string());
            lines.push(format!("{}:{} = {}", setting.path, setting.key, state));
        }
        SystemInfo {
            raw_output: Some(lines.join("\n")),
            ..Default::default()
        }
    }

    async fn execute(&mut self) -> TaskResult {
        let mut result = TaskResult {
            task_name: self.name.clone(),
            success: true,
            items_attempted: HARDENING_SETTINGS.len() as i32,
            ..Default::default()
        };

        if self.dry_run {
            // `file_ops::set` records a Skipped entry per setting during a dry
            // run and writes nothing, so the ledger still shows what would have
            // happened - which is the point of the mode.
            for setting in HARDENING_SETTINGS {
                let _ = file_ops::set(
                    setting.path,
                    setting.style,
                    setting.key,
                    setting.value,
                    setting.why,
                )
                .await;
            }
            // Same code path as the real run: every write in it goes through
            // `remediation::apply`, which records and skips during a dry run.
            let _ = fix_sysctl_precedence().await;
            let _ = fix_sshd_precedence(true).await;
            let _ = remove_legacy_sshd_dropin().await;
            let _ = harden_apache().await;
            result.message = format!(
                "DRY RUN: would apply {} hardening settings.",
                HARDENING_SETTINGS.len()
            );
            return result;
        }

        let mut failures: Vec<String> = Vec::new();
        // What the drop-in held before this run, so a configuration sshd
        // rejects can be rolled back to it.
        let dropin_before = tokio::fs::read_to_string(SSHD_DROPIN).await.ok();
        for setting in HARDENING_SETTINGS {
            match file_ops::set(
                setting.path,
                setting.style,
                setting.key,
                setting.value,
                setting.why,
            )
            .await
            {
                Ok(()) => result.items_succeeded += 1,
                Err(e) => {
                    // Record it. A failure counted for the on-screen tally but
                    // never pushed anywhere never reaches the summary or the log.
                    failures.push(format!("{}:{} ({e})", setting.path, setting.key));
                    ui::markup_line(&format!(
                        "[red]✗ {}: {}[/]",
                        ui::escape(setting.key),
                        ui::escape(&e)
                    ));
                }
            }
        }

        // --- kernel modules ----------------------------------------------
        //
        // Written as a whole file rather than through `file_ops::set`: a
        // modprobe drop-in is a list of directives, not a set of key/value
        // pairs, and two lines per module both name the module rather than
        // being keyed by it.
        match write_module_blacklist().await {
            Ok(()) => result.items_succeeded += 1,
            Err(e) => failures.push(format!("{MODPROBE_DROPIN} ({e})")),
        }
        result.items_attempted += 1;

        // --- login banners --------------------------------------------------
        //
        // Scored, and trivially missed: the stock `/etc/issue` on Ubuntu prints
        // the distribution and kernel version, which tells an attacker exactly
        // which exploits to try before they have authenticated.
        for path in BANNER_FILES {
            match write_banner(path).await {
                Ok(()) => result.items_succeeded += 1,
                Err(e) => failures.push(format!("{path} ({e})")),
            }
        }
        result.items_attempted += BANNER_FILES.len() as i32;

        // --- precedence ---------------------------------------------------------
        //
        // The drop-ins are written; now take away the contrary lines that a
        // checker (or sysctl, for `/etc/sysctl.conf`) would still see.
        result.items_attempted += 1;
        match fix_sysctl_precedence().await {
            Ok(n) => {
                result.items_succeeded += 1;
                if n > 0 {
                    ui::markup_line(&format!(
                        "[green]✓ Rewrote {n} contrary sysctl line(s) in other files[/]"
                    ));
                }
            }
            Err(e) => failures.push(format!("sysctl precedence ({e})")),
        }

        result.items_attempted += 1;
        let mut ssh_rolled_back = false;
        match fix_sshd_precedence(false).await {
            Ok(mut snapshots) => {
                snapshots.push((SSHD_DROPIN.to_string(), dropin_before));
                if sshd_config_is_valid().await {
                    result.items_succeeded += 1;
                    if let Err(e) = remove_legacy_sshd_dropin().await {
                        failures.push(format!("{SSHD_LEGACY_DROPIN} ({e})"));
                    }
                } else {
                    // sshd that cannot parse its configuration refuses to start,
                    // and the next reboot (or reload) locks the machine out.
                    ssh_rolled_back = true;
                    restore_files(&snapshots).await;
                    failures.push("sshd -t rejected the new configuration; rolled back".into());
                    ui::markup_line(
                        "[red]✗ sshd -t rejected the new configuration. The SSH changes \
                         were rolled back.[/]",
                    );
                }
            }
            Err(e) => failures.push(format!("sshd precedence ({e})")),
        }

        // --- apache -------------------------------------------------------------
        result.items_attempted += 1;
        match harden_apache().await {
            Ok(()) => result.items_succeeded += 1,
            Err(e) => failures.push(format!("apache ({e})")),
        }

        // A written sysctl file changes nothing until it is loaded. Without
        // this the settings are correct on the next boot and wrong right now,
        // and a scored check that reads the live value sees the old one.
        // `--system` rather than `-p <dropin>`: it reads every file in the
        // order the boot does, so the live value is what a reboot would give.
        if result.items_succeeded > 0 {
            let (loaded, _o, _e) =
                pinnacle_core::command::execute("sysctl", Some("--system")).await;
            if !loaded {
                ui::markup_line(
                    "[yellow]⚠ sysctl settings are written but could not be loaded; \
                     they take effect at the next boot.[/]",
                );
            }
        }

        // Restart sshd so the new configuration is live - but only if it was
        // already running. Starting it on an image where it was deliberately
        // off would open a service the round may well be scoring as closed.
        if ssh_rolled_back {
            // Nothing new to load; the running daemon still has what it had.
        } else if systemd_ops::is_active("ssh.service").await {
            let (ok, _o, _e) =
                pinnacle_core::command::execute("systemctl", Some("reload-or-restart ssh.service"))
                    .await;
            if ok {
                ui::markup_line("[green]✓ Reloaded ssh with the new configuration[/]");
            } else {
                // A reload that fails usually means the drop-in has a syntax
                // error, which would leave sshd refusing to start on reboot.
                ui::markup_line(&format!(
                    "[yellow]⚠ ssh did not reload. Check {SSHD_DROPIN} with `sshd -t`.[/]"
                ));
            }
        } else if self.ssh_is_required() {
            ui::markup_line(
                "[yellow]⚠ The README calls SSH critical, but the service is not running. \
                 Service Management will start it.[/]",
            );
        }

        result.success = failures.is_empty();
        result.message = if failures.is_empty() {
            format!("Applied {} hardening settings.", result.items_succeeded)
        } else {
            format!(
                "Applied {} of {} settings; {} failed.",
                result.items_succeeded,
                HARDENING_SETTINGS.len(),
                failures.len()
            )
        };
        if !failures.is_empty() {
            result.error_details = Some(failures.join("; "));
        }
        result
    }

    async fn verify(&mut self) -> bool {
        // Read every setting back out of the file rather than trusting that the
        // writes returned Ok. This is the step that catches a value written to
        // a drop-in that something later in the run overrode.
        for setting in HARDENING_SETTINGS {
            let state = file_ops::read(setting.path, setting.style, setting.key).await;
            if state.as_deref() != Some(setting.value) {
                return false;
            }
        }
        // ...and the files that could still contradict them.
        sysctl_conflicts_on_disk().await.is_empty() && sshd_conflicts_on_disk().await.is_empty()
    }
}

// =============================================================================
// Precedence: contrary lines in the files a drop-in does not replace
// =============================================================================

/// The sysctl settings, as `(key, value)`.
fn sysctl_wanted() -> Vec<(&'static str, &'static str)> {
    HARDENING_SETTINGS
        .iter()
        .filter(|s| s.path == SYSCTL_DROPIN)
        .map(|s| (s.key, s.value))
        .collect()
}

/// The sshd settings, as `(key, value)`.
fn sshd_wanted() -> Vec<(&'static str, &'static str)> {
    HARDENING_SETTINGS
        .iter()
        .filter(|s| s.path == SSHD_DROPIN)
        .map(|s| (s.key, s.value))
        .collect()
}

/// Collapse runs of whitespace, so `1  ` and `1` compare as written rather than
/// as spaced.
fn squash(value: &str) -> String {
    value.split_whitespace().collect::<Vec<_>>().join(" ")
}

/// Which `(path, key)` pairs carry an active value other than the wanted one.
///
/// Only keys already present are reported: a file that does not mention a key is
/// not contradicting it, and adding the key there would just be noise.
pub fn sysctl_conflicts(
    files: &[(String, String)],
    wanted: &[(&str, &str)],
) -> Vec<(String, String)> {
    let mut out = Vec::new();
    for (path, text) in files {
        for (key, value) in wanted {
            let contrary = file_ops::active_values(text, Style::Equals, key)
                .iter()
                .any(|v| squash(v) != squash(value));
            if contrary {
                out.push((path.clone(), (*key).to_string()));
            }
        }
    }
    out
}

/// The part of an sshd config that applies to everyone: everything before the
/// first `Match` line. After it, keywords apply only to the matching
/// connections, which is a different decision from the server-wide one.
pub fn sshd_global_section(text: &str) -> &str {
    let mut offset = 0;
    for line in text.split_inclusive('\n') {
        if is_match_line(line) {
            return &text[..offset];
        }
        offset += line.len();
    }
    text
}

fn is_match_line(line: &str) -> bool {
    if !file_ops::is_active(line) {
        return false;
    }
    line.split_whitespace()
        .next()
        .is_some_and(|k| k.eq_ignore_ascii_case("Match"))
}

fn sshd_contrary(text: &str, wanted: &[(&str, &str)]) -> Vec<String> {
    wanted
        .iter()
        .filter(|(key, value)| {
            file_ops::active_values(text, Style::Space, key)
                .iter()
                .any(|v| !squash(v).eq_ignore_ascii_case(&squash(value)))
        })
        .map(|(key, _)| (*key).to_string())
        .collect()
}

/// `(path, key)` pairs whose *global* active value is contrary to the wanted one.
pub fn sshd_conflicts(
    files: &[(String, String)],
    wanted: &[(&str, &str)],
) -> Vec<(String, String)> {
    let mut out = Vec::new();
    for (path, text) in files {
        for key in sshd_contrary(sshd_global_section(text), wanted) {
            out.push((path.clone(), key));
        }
    }
    out
}

/// `(path, key)` pairs overridden inside a `Match` block. Not rewritten - a
/// `Match` override is usually deliberate and scoped - but worth saying.
pub fn sshd_match_overrides(
    files: &[(String, String)],
    wanted: &[(&str, &str)],
) -> Vec<(String, String)> {
    let mut out = Vec::new();
    for (path, text) in files {
        let scoped = &text[sshd_global_section(text).len()..];
        for key in sshd_contrary(scoped, wanted) {
            out.push((path.clone(), key));
        }
    }
    out
}

/// Rewrite every contrary *global* line for a wanted key, leaving `Match`
/// blocks, comments and other keys alone. The original line stays as a comment.
pub fn rewrite_sshd_conflicts(text: &str, wanted: &[(&str, &str)]) -> String {
    let mut out = String::with_capacity(text.len() + 64);
    let mut in_match = false;
    for raw in text.split_inclusive('\n') {
        let line = raw.trim_end_matches(['\n', '\r']);
        if is_match_line(line) {
            in_match = true;
        }
        let replacement = if in_match || !file_ops::is_active(line) {
            None
        } else {
            let mut parts = line.trim().splitn(2, char::is_whitespace);
            let key = parts.next().unwrap_or("");
            let current = squash(parts.next().unwrap_or(""));
            wanted
                .iter()
                .find(|(k, v)| {
                    k.eq_ignore_ascii_case(key) && !current.eq_ignore_ascii_case(&squash(v))
                })
                .copied()
        };
        match replacement {
            Some((key, value)) => {
                let indent: String = line.chars().take_while(|c| c.is_whitespace()).collect();
                out.push_str(&format!("# {line}    # superseded by PinnacleCyPat\n"));
                out.push_str(&format!("{indent}{key} {value}\n"));
            }
            None => out.push_str(raw),
        }
    }
    out
}

/// Every `*.conf` in a directory, sorted, as canonical paths. Canonical so that
/// `sysctl.d/99-sysctl.conf -> ../sysctl.conf` is edited at its target: writing
/// "through" the link by rename would replace the link with a regular file.
async fn conf_files(dir: &str) -> Vec<String> {
    let mut found = Vec::new();
    if let Ok(mut entries) = tokio::fs::read_dir(dir).await {
        while let Ok(Some(entry)) = entries.next_entry().await {
            let path = entry.path();
            if path.extension().is_some_and(|e| e == "conf") {
                found.push(path);
            }
        }
    }
    found.sort();
    let mut canon: Vec<String> = Vec::new();
    for p in found {
        if let Ok(c) = tokio::fs::canonicalize(&p).await {
            let c = c.to_string_lossy().into_owned();
            if !canon.contains(&c) {
                canon.push(c);
            }
        }
    }
    canon
}

async fn read_all(paths: Vec<String>) -> Vec<(String, String)> {
    let mut out = Vec::new();
    for path in paths {
        if let Ok(text) = tokio::fs::read_to_string(&path).await {
            out.push((path, text));
        }
    }
    out
}

async fn canonical_or(path: &str) -> String {
    tokio::fs::canonicalize(path)
        .await
        .map(|p| p.to_string_lossy().into_owned())
        .unwrap_or_else(|_| path.to_string())
}

/// The sysctl files other than our own drop-in.
async fn other_sysctl_files() -> Vec<(String, String)> {
    let mut paths = conf_files("/etc/sysctl.d").await;
    let main = canonical_or("/etc/sysctl.conf").await;
    if !paths.contains(&main) {
        paths.push(main);
    }
    let own = canonical_or(SYSCTL_DROPIN).await;
    paths.retain(|p| *p != own);
    read_all(paths).await
}

/// The sshd files other than our own drop-in and the legacy one.
async fn other_sshd_files() -> Vec<(String, String)> {
    let mut paths = conf_files("/etc/ssh/sshd_config.d").await;
    let main = canonical_or("/etc/ssh/sshd_config").await;
    if !paths.contains(&main) {
        paths.insert(0, main);
    }
    paths.retain(|p| p != SSHD_DROPIN && p != SSHD_LEGACY_DROPIN);
    read_all(paths).await
}

async fn sysctl_conflicts_on_disk() -> Vec<(String, String)> {
    sysctl_conflicts(&other_sysctl_files().await, &sysctl_wanted())
}

async fn sshd_conflicts_on_disk() -> Vec<(String, String)> {
    sshd_conflicts(&other_sshd_files().await, &sshd_wanted())
}

/// Rewrite contrary sysctl lines elsewhere. Returns how many keys were rewritten.
async fn fix_sysctl_precedence() -> Result<usize, String> {
    let wanted = sysctl_wanted();
    let conflicts = sysctl_conflicts(&other_sysctl_files().await, &wanted);
    let mut first_error = None;
    for (path, key) in &conflicts {
        let value = wanted
            .iter()
            .find(|(k, _)| k == key)
            .map(|(_, v)| *v)
            .unwrap_or_default();
        let why = "another file must not contradict the hardened value";
        if let Err(e) = file_ops::set(path, Style::Equals, key, value, why).await {
            ui::markup_line(&format!(
                "[red]✗ {}:{}: {}[/]",
                ui::escape(path),
                ui::escape(key),
                ui::escape(&e)
            ));
            first_error.get_or_insert(e);
        }
    }
    match first_error {
        Some(e) => Err(e),
        None => Ok(conflicts.len()),
    }
}

/// Rewrite contrary global sshd lines elsewhere. Returns the prior contents of
/// every file it changed, for rollback.
async fn fix_sshd_precedence(dry_run: bool) -> Result<Vec<(String, Option<String>)>, String> {
    let wanted = sshd_wanted();
    let files = other_sshd_files().await;

    for (path, key) in sshd_match_overrides(&files, &wanted) {
        ui::markup_line(&format!(
            "[yellow]⚠ {} sets {} inside a Match block; left alone, since it applies only to \
             matching connections.[/]",
            ui::escape(&path),
            ui::escape(&key)
        ));
    }

    let mut snapshots = Vec::new();
    let mut first_error = None;
    let paths: std::collections::BTreeSet<String> = sshd_conflicts(&files, &wanted)
        .into_iter()
        .map(|(p, _)| p)
        .collect();
    for path in paths {
        let original = files
            .iter()
            .find(|(p, _)| *p == path)
            .map(|(_, t)| t.clone())
            .unwrap_or_default();
        let wanted_ref = &wanted;
        let result = remediation::apply(
            &path,
            "no contrary SSH keyword before the hardened one is read",
            || async {
                let text = tokio::fs::read_to_string(&path).await.ok()?;
                let n = sshd_conflicts(&[(path.clone(), text)], wanted_ref).len();
                Some(format!("{n} contrary keyword(s)"))
            },
            |state| state == "0 contrary keyword(s)",
            "rewrote contrary global keywords, keeping the originals as comments",
            || async {
                let updated = rewrite_sshd_conflicts(&original, wanted_ref);
                file_ops::back_up(&path, &original).await?;
                file_ops::write_atomically(&path, &updated).await
            },
        )
        .await;
        match result {
            Ok(()) if !dry_run => snapshots.push((path.clone(), Some(original))),
            Ok(()) => {}
            Err(e) => {
                first_error.get_or_insert(e);
            }
        }
    }
    match first_error {
        Some(e) => {
            // Partial edits are worse than none: put back what was changed.
            restore_files(&snapshots).await;
            Err(e)
        }
        None => Ok(snapshots),
    }
}

/// Does sshd accept its configuration? A host without sshd has nothing to break.
async fn sshd_config_is_valid() -> bool {
    let sshd = ["/usr/sbin/sshd", "/usr/bin/sshd", "/sbin/sshd"]
        .into_iter()
        .find(|p| std::path::Path::new(p).exists());
    let Some(sshd) = sshd else {
        return true;
    };
    pinnacle_core::command::execute(sshd, Some("-t")).await.0
}

/// Put files back as they were: contents restored, or the file removed if it did
/// not exist before.
async fn restore_files(snapshots: &[(String, Option<String>)]) {
    for (path, original) in snapshots {
        match original {
            Some(text) => {
                let _ = file_ops::write_atomically(path, text).await;
            }
            None => {
                let _ = tokio::fs::remove_file(path).await;
            }
        }
    }
}

/// Remove the `99-pinnacle.conf` an earlier version wrote.
async fn remove_legacy_sshd_dropin() -> Result<(), String> {
    remediation::apply(
        SSHD_LEGACY_DROPIN,
        "no stale second copy of the SSH settings",
        || async {
            Some(
                if std::path::Path::new(SSHD_LEGACY_DROPIN).exists() {
                    "present"
                } else {
                    "absent"
                }
                .to_string(),
            )
        },
        |state| state == "absent",
        "removed the legacy drop-in; 00-pinnacle.conf replaces it",
        || async {
            tokio::fs::remove_file(SSHD_LEGACY_DROPIN)
                .await
                .map_err(|e| format!("could not remove {SSHD_LEGACY_DROPIN}: {e}"))
        },
    )
    .await
}

// =============================================================================
// Apache
// =============================================================================

const APACHE_DIR: &str = "/etc/apache2";
const APACHE_SECURITY_CONF: &str = "/etc/apache2/conf-available/security.conf";
const APACHE_SECURITY_ENABLED: &str = "/etc/apache2/conf-enabled/security.conf";

/// What stops Apache announcing its version and modules in headers and error
/// pages, as `(key, value, why)`.
pub const APACHE_SETTINGS: &[(&str, &str, &str)] = &[
    (
        "ServerSignature",
        "Off",
        "error pages do not print the server version",
    ),
    (
        "ServerTokens",
        "Prod",
        "the Server header says only 'Apache', not the version and modules",
    ),
];

/// Harden Apache if it is installed. Does nothing otherwise.
async fn harden_apache() -> Result<(), String> {
    if !std::path::Path::new(APACHE_DIR).is_dir() {
        return Ok(());
    }
    let mut first_error = None;
    for (key, value, why) in APACHE_SETTINGS {
        if let Err(e) = file_ops::set(APACHE_SECURITY_CONF, Style::Space, key, value, why).await {
            first_error.get_or_insert(e);
        }
    }

    // Settings in a conf-available file do nothing until it is enabled.
    let enabled = remediation::apply(
        APACHE_SECURITY_ENABLED,
        "the security configuration is enabled, so its settings are read",
        || async {
            Some(
                if std::path::Path::new(APACHE_SECURITY_ENABLED).exists() {
                    "enabled"
                } else {
                    "not enabled"
                }
                .to_string(),
            )
        },
        |state| state == "enabled",
        "ran a2enconf security",
        || async {
            let (ok, _o, e) = pinnacle_core::command::execute("a2enconf", Some("security")).await;
            if ok {
                Ok(())
            } else {
                Err(e.unwrap_or_else(|| "a2enconf failed".to_string()))
            }
        },
    )
    .await;
    if let Err(e) = enabled {
        first_error.get_or_insert(e);
    }

    if first_error.is_none()
        && !pinnacle_core::run_log::dry_run()
        && systemd_ops::is_active("apache2.service").await
    {
        let (ok, _o, _e) =
            pinnacle_core::command::execute("systemctl", Some("reload apache2.service")).await;
        if ok {
            ui::markup_line("[green]✓ Reloaded apache2 with ServerTokens Prod[/]");
        } else {
            ui::markup_line("[yellow]⚠ apache2 did not reload; check `apache2ctl configtest`.[/]");
        }
    }
    match first_error {
        Some(e) => Err(e),
        None => Ok(()),
    }
}

/// The banner files a login shows, in order of when they are seen.
const BANNER_FILES: &[&str] = &["/etc/issue", "/etc/issue.net", "/etc/motd"];

/// What the banner says.
///
/// Deliberately free of `\\n`, `\\s`, `\\m`, `\\r` and `\\v` - the escapes the
/// stock Ubuntu `/etc/issue` uses, which print the hostname, distribution and
/// kernel version *before* anyone has authenticated. That tells an attacker
/// which exploits to try, and it is what the scored check is looking for the
/// absence of.
const BANNER_TEXT: &str = "\
Authorized users only. All activity may be monitored and reported.
Unauthorized access to this system is prohibited and will be prosecuted.
";

/// Write one banner file, and prove it.
async fn write_banner(path: &str) -> Result<(), String> {
    remediation::apply(
        path,
        "a legal notice with no system information in it",
        || async {
            Some(match tokio::fs::read_to_string(path).await {
                Ok(text) => {
                    // The escapes are what matters, not the wording: a banner
                    // that leaks the kernel version fails the check however
                    // sternly it is worded.
                    if text.contains('\\') {
                        "leaks system information".to_string()
                    } else if text.trim().is_empty() {
                        "empty".to_string()
                    } else {
                        "a plain notice".to_string()
                    }
                }
                Err(_) => "absent".to_string(),
            })
        },
        |state| state == "a plain notice",
        "wrote a legal notice with no escapes in it",
        || async {
            tokio::fs::write(path, BANNER_TEXT)
                .await
                .map_err(|e| format!("could not write {path}: {e}"))
        },
    )
    .await
}

/// The modprobe drop-in, as text.
pub fn module_blacklist_text() -> String {
    let mut out = String::from("# Written by PinnacleCyPat.\n");
    out.push_str(
        "# `install ... /bin/false` is what prevents loading; `blacklist` alone only\n\
         # stops automatic loading and is bypassed by an explicit modprobe.\n\n",
    );
    for (module, why) in MODULES_TO_BLOCK {
        out.push_str(&format!(
            "# {why}\ninstall {module} /bin/false\nblacklist {module}\n\n"
        ));
    }
    out
}

/// Write the modprobe drop-in, and prove it.
async fn write_module_blacklist() -> Result<(), String> {
    let wanted = module_blacklist_text();
    remediation::apply(
        MODPROBE_DROPIN,
        &format!(
            "{} unused kernel modules cannot be loaded",
            MODULES_TO_BLOCK.len()
        ),
        || async {
            Some(match tokio::fs::read_to_string(MODPROBE_DROPIN).await {
                Ok(text) => {
                    let blocked = MODULES_TO_BLOCK
                        .iter()
                        .filter(|(m, _)| text.contains(&format!("install {m} /bin/false")))
                        .count();
                    format!("{blocked} blocked")
                }
                Err(_) => "absent".to_string(),
            })
        },
        |state| state == format!("{} blocked", MODULES_TO_BLOCK.len()),
        &format!("wrote {MODPROBE_DROPIN}"),
        || async {
            if let Some(parent) = std::path::Path::new(MODPROBE_DROPIN).parent() {
                let _ = tokio::fs::create_dir_all(parent).await;
            }
            tokio::fs::write(MODPROBE_DROPIN, &wanted)
                .await
                .map_err(|e| format!("could not write {MODPROBE_DROPIN}: {e}"))
        },
    )
    .await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn a_dry_run_writes_nothing() {
        let _dry_run = pinnacle_core::run_log::dry_run_for_test();
        let mut task = SecurityHardeningTask::new();
        task.set_dry_run(true);
        let result = task.execute().await;

        assert!(result.success);
        assert!(
            result.message.starts_with("DRY RUN"),
            "message was: {}",
            result.message
        );
        // The drop-ins are what a real run would create. Their absence here is
        // the assertion that matters - a task that ignores dry-run and writes
        // anyway is the worst bug this codebase can have.
        assert!(
            !std::path::Path::new(SSHD_DROPIN).exists(),
            "the dry run created {SSHD_DROPIN}"
        );
        assert!(
            !std::path::Path::new(SYSCTL_DROPIN).exists(),
            "the dry run created {SYSCTL_DROPIN}"
        );
    }

    fn files(items: &[(&str, &str)]) -> Vec<(String, String)> {
        items
            .iter()
            .map(|(p, t)| (p.to_string(), t.to_string()))
            .collect()
    }

    /// `/etc/sysctl.conf` is read after the drop-in, so a contrary line there
    /// wins (Ubuntu 22 T2: `net.ipv4.ip_forward=1` planted in sysctl.conf).
    #[test]
    fn a_contrary_sysctl_line_in_the_main_file_is_found() {
        let found = sysctl_conflicts(
            &files(&[
                ("/etc/sysctl.conf", "net.ipv4.ip_forward=1\n"),
                ("/etc/sysctl.d/10-x.conf", "net.ipv4.ip_forward = 0\n"),
                ("/etc/sysctl.d/20-y.conf", "vm.swappiness = 10\n"),
            ]),
            &sysctl_wanted(),
        );
        assert_eq!(
            found,
            vec![(
                "/etc/sysctl.conf".to_string(),
                "net.ipv4.ip_forward".to_string()
            )]
        );
    }

    /// Files that do not mention a key are not contradicting it, and a
    /// commented line is not a setting.
    #[test]
    fn sysctl_files_without_the_key_or_with_it_commented_are_left_alone() {
        let found = sysctl_conflicts(
            &files(&[
                ("/etc/sysctl.conf", "#net.ipv4.ip_forward=1\n"),
                ("/etc/sysctl.d/a.conf", "\n"),
            ]),
            &sysctl_wanted(),
        );
        assert!(found.is_empty(), "{found:?}");
    }

    #[test]
    fn a_contrary_global_sshd_line_is_found_and_rewritten() {
        let text = "Include /etc/ssh/sshd_config.d/*.conf\nPermitRootLogin yes\nPort 22\n";
        let wanted = sshd_wanted();
        let found = sshd_conflicts(&files(&[("/etc/ssh/sshd_config", text)]), &wanted);
        assert_eq!(
            found,
            vec![(
                "/etc/ssh/sshd_config".to_string(),
                "PermitRootLogin".to_string()
            )]
        );
        let out = rewrite_sshd_conflicts(text, &wanted);
        assert_eq!(
            file_ops::active_values(&out, Style::Space, "PermitRootLogin"),
            ["no"]
        );
        assert!(out.contains("# PermitRootLogin yes"), "{out}");
        assert!(out.contains("Port 22\n") && out.starts_with("Include"));
        assert!(sshd_conflicts(&files(&[("x", &out)]), &wanted).is_empty());
    }

    /// A `Match` block scopes a keyword to some connections; rewriting it
    /// would change a decision nobody asked this tool to make.
    #[test]
    fn sshd_lines_inside_a_match_block_are_not_rewritten() {
        let text = "PermitRootLogin no\nMatch User backup\n    PermitRootLogin yes\n";
        let wanted = sshd_wanted();
        let f = files(&[("/etc/ssh/sshd_config", text)]);
        assert!(sshd_conflicts(&f, &wanted).is_empty());
        assert_eq!(sshd_match_overrides(&f, &wanted).len(), 1);
        assert_eq!(rewrite_sshd_conflicts(text, &wanted), text);
    }

    #[test]
    fn sshd_values_compare_without_regard_to_case_or_spacing() {
        let f = files(&[("a", "PermitRootLogin   No\nLogLevel verbose\n")]);
        assert!(sshd_conflicts(&f, &sshd_wanted()).is_empty());
    }

    /// The renamed drop-in sorts before every other `*.conf`, and the legacy
    /// one sorts after them, which is why it lost.
    #[test]
    fn the_sshd_drop_in_sorts_first_and_the_legacy_one_last() {
        assert!(SSHD_DROPIN.ends_with("/00-pinnacle.conf"));
        assert!(SSHD_LEGACY_DROPIN.ends_with("/99-pinnacle.conf"));
        assert!(SSHD_DROPIN < "/etc/ssh/sshd_config.d/50-cloud-init.conf");
    }

    #[test]
    fn apache_is_told_to_hide_its_version() {
        assert!(APACHE_SETTINGS.contains(&(
            "ServerSignature",
            "Off",
            "error pages do not print the server version"
        )));
        assert!(
            APACHE_SETTINGS
                .iter()
                .any(|(k, v, _)| *k == "ServerTokens" && *v == "Prod")
        );
    }

    /// The README override that the Windows port got wrong twice.
    #[test]
    fn the_readme_can_mark_ssh_as_required() {
        let mut task = SecurityHardeningTask::new();
        assert!(!task.ssh_is_required());
        task.set_readme_data(ReadmeData {
            critical_services: vec!["SSH".to_string()],
            ..Default::default()
        });
        assert!(task.ssh_is_required());
    }

    /// Both directives are needed. `blacklist` alone only stops *automatic*
    /// loading, so `modprobe cramfs` still works and the check still fails.
    #[test]
    fn every_blocked_module_gets_both_directives() {
        let text = module_blacklist_text();
        for (module, why) in MODULES_TO_BLOCK {
            assert!(
                text.contains(&format!("install {module} /bin/false")),
                "{module} has no install directive"
            );
            assert!(
                text.contains(&format!("blacklist {module}")),
                "{module} has no blacklist directive"
            );
            assert!(text.contains(why), "{module} has no reason recorded");
        }
    }

    /// Blocking vfat would stop a UEFI machine mounting /boot/efi, and
    /// therefore booting. "Unused filesystem" has to mean unused.
    #[test]
    fn the_filesystem_a_uefi_machine_boots_from_is_not_blocked() {
        assert!(
            !MODULES_TO_BLOCK.iter().any(|(m, _)| *m == "vfat"),
            "blocking vfat can make the image unbootable"
        );
        assert!(!MODULES_TO_BLOCK.iter().any(|(m, _)| *m == "ext4"));
    }

    /// The escapes are the finding, not the wording. Ubuntu's stock /etc/issue
    /// is `Ubuntu 22.04 LTS \\n \\l`, which prints the distribution and the
    /// terminal before anyone has authenticated.
    #[test]
    fn the_banner_carries_no_system_information() {
        assert!(
            !BANNER_TEXT.contains('\\'),
            "an escape in the banner leaks system information: {BANNER_TEXT}"
        );
        assert!(BANNER_TEXT.to_lowercase().contains("authorized"));
        assert!(BANNER_TEXT.ends_with('\n'));
    }

    /// Hardening SSH is pointless if the settings land somewhere sshd does not
    /// read, and this is the mistake that is easy to make.
    #[test]
    fn ssh_settings_go_to_the_drop_in_not_the_main_config() {
        let ssh_settings: Vec<_> = HARDENING_SETTINGS
            .iter()
            .filter(|s| s.key.starts_with("Permit") || s.key == "X11Forwarding")
            .collect();
        assert!(!ssh_settings.is_empty());
        for setting in ssh_settings {
            assert_eq!(
                setting.path, SSHD_DROPIN,
                "{} is in the wrong file",
                setting.key
            );
        }
    }
}
