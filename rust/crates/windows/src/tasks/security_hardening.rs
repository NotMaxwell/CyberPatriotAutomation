//! Apply additional security hardening settings via registry and system config.

use crate::knowledge::{FEATURES_TO_DISABLE, REGISTRY_SETTINGS, REMOTE_DESKTOP_VALUES};
use crate::readme_services;
use crate::registry_ops;
use crate::service_ops;
use async_trait::async_trait;
use indicatif::{ProgressBar, ProgressStyle};
use pinnacle_core::Task;
use pinnacle_core::command;
use pinnacle_core::impl_task_meta;
use pinnacle_core::models::{SystemInfo, TaskResult};
use pinnacle_core::run_log;
use pinnacle_core::ui;

/// The values that turn Remote Desktop off.
///
/// Named rather than filtered by path: the Terminal Server key also carries
/// `fAllowToGetHelp`, which disables Remote *Assistance* - a different feature,
/// never required by a README, and still worth turning off.
/// The two keys the state read and the verify step check by hand, named so the
/// paths are not repeated character by character between them.
const POLICIES_SYSTEM_KEY: &str = r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System";
const TERMINAL_SERVER_KEY: &str = r"HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server";

/// Directives that stop Apache announcing its version on every response and
/// error page. The scenario scores both.
const APACHE_DIRECTIVES: &[(&str, &str)] = &[("ServerSignature", "Off"), ("ServerTokens", "Prod")];

/// Where Apache keeps `httpd.conf` on the usual Windows layouts; wildcard
/// parents are expanded by [`apache_conf_candidates`].
const APACHE_CONF_DIRS: &[&str] = &[r"C:\Apache24\conf", r"C:\xampp\apache\conf"];
const APACHE_PARENT_DIRS: &[&str] = &[r"C:\Program Files", r"C:\Program Files (x86)"];

/// The suffix `.pinnacle.bak` keeps the original beside the file we change.
const BACKUP_SUFFIX: &str = ".pinnacle.bak";

/// Rewrite `ServerSignature` and `ServerTokens` to the hardened values.
///
/// Active (uncommented) lines are replaced in place, case-insensitively, so the
/// directive keeps its position in the file; a directive that is absent is
/// appended. Commented lines are left alone - they are documentation, and
/// uncommenting one could re-enable something the admin disabled on purpose.
/// The file's own line ending is kept so a CRLF config does not end up mixed.
fn harden_httpd_conf(text: &str) -> String {
    let eol = if text.contains("\r\n") { "\r\n" } else { "\n" };
    let mut seen = [false; APACHE_DIRECTIVES.len()];
    let mut out = String::with_capacity(text.len() + 64);

    for line in text.split_inclusive('\n') {
        let body = line.trim_end_matches(['\r', '\n']);
        let ending = &line[body.len()..];
        let first = body.split_whitespace().next().unwrap_or("");
        let hit = (!first.starts_with('#'))
            .then(|| {
                APACHE_DIRECTIVES
                    .iter()
                    .position(|(name, _)| name.eq_ignore_ascii_case(first))
            })
            .flatten();
        match hit {
            Some(i) => {
                seen[i] = true;
                let (name, value) = APACHE_DIRECTIVES[i];
                let wanted = format!("{name} {value}");
                // Leave an already-correct line byte-for-byte as it was.
                let already = body.split_whitespace().eq(wanted.split_whitespace());
                out.push_str(if already { body } else { &wanted });
                out.push_str(ending);
            }
            None => out.push_str(line),
        }
    }

    for (i, (name, value)) in APACHE_DIRECTIVES.iter().enumerate() {
        if !seen[i] {
            if !out.is_empty() && !out.ends_with('\n') {
                out.push_str(eol);
            }
            out.push_str(&format!("{name} {value}{eol}"));
        }
    }
    out
}

/// Where the config lives, given a service's `ImagePath`
/// (`"C:\Apache24\bin\httpd.exe" -k runservice` -> `C:\Apache24\conf\httpd.conf`).
fn conf_from_image_path(image_path: &str) -> Option<String> {
    let trimmed = image_path.trim();
    let exe = match trimmed.strip_prefix('"') {
        Some(rest) => rest.split('"').next()?,
        None => {
            let end = trimmed.to_ascii_lowercase().find(".exe")? + ".exe".len();
            &trimmed[..end]
        }
    };
    let sep = |c: char| c == '\\' || c == '/';
    let bin_dir = &exe[..exe.rfind(sep)?];
    let (root, last) = bin_dir.rsplit_once(sep)?;
    last.eq_ignore_ascii_case("bin")
        .then(|| format!("{root}\\conf\\httpd.conf"))
}

/// Every `httpd.conf` that exists on this machine, without duplicates.
async fn apache_conf_candidates() -> Vec<std::path::PathBuf> {
    let mut found: Vec<std::path::PathBuf> = Vec::new();
    let mut consider = |path: std::path::PathBuf| {
        if path.is_file()
            && !found.iter().any(|p| {
                p.to_string_lossy()
                    .eq_ignore_ascii_case(&path.to_string_lossy())
            })
        {
            found.push(path);
        }
    };

    for dir in APACHE_CONF_DIRS {
        consider(std::path::Path::new(dir).join("httpd.conf"));
    }
    for parent in APACHE_PARENT_DIRS {
        let Ok(entries) = std::fs::read_dir(parent) else {
            continue;
        };
        for entry in entries.flatten() {
            if entry
                .file_name()
                .to_string_lossy()
                .to_ascii_lowercase()
                .starts_with("apache")
            {
                consider(entry.path().join("conf").join("httpd.conf"));
            }
        }
    }
    for name in apache_service_names().await {
        let key = format!(r"HKLM\SYSTEM\CurrentControlSet\Services\{name}");
        if let Some(conf) = registry_ops::get_string(&key, "ImagePath")
            .await
            .and_then(|image| conf_from_image_path(&image))
        {
            consider(std::path::PathBuf::from(conf));
        }
    }
    found
}

/// Services whose name starts with `Apache` (`Apache2.4`, `ApacheHTTPServer`).
async fn apache_service_names() -> Vec<String> {
    service_ops::enumerate_states()
        .await
        .unwrap_or_default()
        .into_iter()
        .map(|(name, _)| name)
        .filter(|name| name.to_ascii_lowercase().starts_with("apache"))
        .collect()
}

/// Summarise a config for the ledger: hardened or not.
fn httpd_state(text: &str) -> String {
    if harden_httpd_conf(text) == text {
        "ServerSignature Off, ServerTokens Prod".to_string()
    } else {
        "version banner not hidden".to_string()
    }
}

/// Harden one `httpd.conf`: back it up, write it, prove it by reading it back.
async fn harden_one_httpd_conf(path: &std::path::Path) -> Result<bool, String> {
    let display = path.display().to_string();
    let original = std::fs::read_to_string(path).map_err(|e| format!("{display}: {e}"))?;
    if harden_httpd_conf(&original) == original {
        return Ok(false);
    }

    pinnacle_core::remediation::apply(
        &format!("Apache config {display}"),
        "ServerSignature Off and ServerTokens Prod, so responses do not reveal the version",
        || async { std::fs::read_to_string(path).ok().map(|t| httpd_state(&t)) },
        |state| state.starts_with("ServerSignature Off"),
        "rewrote ServerSignature and ServerTokens",
        || async {
            let backup = format!("{display}{BACKUP_SUFFIX}");
            // Only the first backup: a second run must not overwrite the
            // original with our own output.
            if !std::path::Path::new(&backup).exists() {
                std::fs::copy(path, &backup).map_err(|e| format!("backup to {backup}: {e}"))?;
            }
            std::fs::write(path, harden_httpd_conf(&original))
                .map_err(|e| format!("{display}: {e}"))
        },
    )
    .await?;
    Ok(!pinnacle_core::run_log::dry_run())
}

/// Hide the Apache version in every `httpd.conf` found, restarting the service
/// only if it was running, since a stopped server should stay stopped.
async fn harden_apache(fixes: &mut Vec<String>, issues: &mut Vec<String>) {
    let confs = apache_conf_candidates().await;
    if confs.is_empty() {
        return;
    }
    ui::markup_line("[cyan]Hardening Apache (ServerSignature / ServerTokens)...[/]");

    let mut changed = false;
    for conf in &confs {
        match harden_one_httpd_conf(conf).await {
            Ok(true) => {
                changed = true;
                fixes.push(format!("Hid the Apache version in {}", conf.display()));
            }
            Ok(false) => {}
            Err(e) => issues.push(format!("Could not harden {}: {e}", conf.display())),
        }
    }
    if !changed {
        return;
    }

    for service in apache_service_names().await {
        if service_ops::state(&service).await != service_ops::ServiceState::Running {
            continue;
        }
        match service_ops::stop(&service).await {
            Ok(()) => match service_ops::start(&service).await {
                Ok(()) => fixes.push(format!("Restarted {service} to load the new config")),
                Err(e) => issues.push(format!("{service} stopped but did not restart: {e}")),
            },
            Err(e) => issues.push(format!("Could not restart {service}: {e}")),
        }
    }
}

/// Registry settings to apply: (path, name, type, value, description).
pub struct SecurityHardeningTask {
    name: String,
    description: String,
    dry_run: bool,
    readme_data: Option<pinnacle_core::models::ReadmeData>,
}

impl SecurityHardeningTask {
    pub fn new() -> Self {
        Self {
            name: "Security Hardening".to_string(),
            description:
                "Apply additional security hardening settings via registry and system configuration"
                    .to_string(),
            dry_run: false,
            readme_data: None,
        }
    }

    pub fn set_readme_data(&mut self, data: pinnacle_core::models::ReadmeData) {
        self.readme_data = Some(data);
    }

    async fn apply_registry_settings(&self, fixes: &mut Vec<String>, issues: &mut Vec<String>) {
        ui::markup_line(&format!(
            "[cyan]Applying {} registry settings...[/]",
            REGISTRY_SETTINGS.len()
        ));

        // An image whose scenario is "this machine is administered remotely"
        // scores RDP being *available*. Denying it loses that point while every
        // other hardening step still applies, so honour the README here rather
        // than fighting the service management task, which already protects
        // TermService in the same situation.
        let skip_remote_desktop =
            readme_services::is_remote_desktop_required(self.readme_data.as_ref());
        if skip_remote_desktop {
            ui::markup_line(
                "[yellow]! Leaving Remote Desktop enabled: the README lists it as a critical service[/]",
            );
        }

        let mut success_count = 0;
        let mut fail_count = 0;
        let mut skipped_count = 0;

        let bar = ProgressBar::new(REGISTRY_SETTINGS.len() as u64);
        bar.set_style(
            ProgressStyle::with_template("{msg} [{bar:40.cyan/blue}] {pos}/{len}")
                .unwrap()
                .progress_chars("=> "),
        );
        bar.set_message("Applying registry settings...");

        for (path, name, ty, value, description) in REGISTRY_SETTINGS {
            // Leave Remote Desktop alone when the README calls it critical.
            // Service management already protects TermService in that case;
            // denying connections here as well would leave the service running
            // with every connection refused.
            if skip_remote_desktop && REMOTE_DESKTOP_VALUES.contains(name) {
                run_log::diagnostic(
                    "hardening",
                    &format!(
                        "skipped {name}: the README lists Remote Desktop as a critical service"
                    ),
                );
                skipped_count += 1;
                bar.inc(1);
                continue;
            }

            // The table is all REG_DWORD today; a REG_SZ added later must not be
            // silently written as a number, so it is failed loudly instead.
            let Some(parsed) = (*ty == "REG_DWORD")
                .then(|| value.parse::<u32>().ok())
                .flatten()
            else {
                issues.push(format!(
                    "Cannot set {description} ({path}\\{name}): \
                     unsupported type {ty} with value {value}"
                ));
                fail_count += 1;
                bar.inc(1);
                continue;
            };

            // Through registry_ops so the write uses the API where available and
            // the run log gets the read-back that proves it landed.
            match registry_ops::set_dword_because(path, name, parsed, Some(description)).await {
                Ok(()) => {
                    fixes.push(format!("Set {description}"));
                    success_count += 1;
                }
                Err(e) => {
                    // Failures were counted for the on-screen tally but never
                    // recorded, so they never reached the run summary or the
                    // task's error details.
                    issues.push(format!("Failed to set {description} ({path}\\{name}): {e}"));
                    fail_count += 1;
                }
            }
            bar.inc(1);
        }
        bar.finish_and_clear();

        ui::markup_line(&format!("[green]✓ Applied {success_count} settings[/]"));
        if skipped_count > 0 {
            ui::markup_line(&format!(
                "[dim]{skipped_count} Remote Desktop settings skipped at the README's request[/]"
            ));
        }
        if fail_count > 0 {
            ui::markup_line(&format!(
                "[yellow]⚠ {fail_count} settings could not be applied[/]"
            ));
        }
    }

    async fn disable_insecure_features(fixes: &mut Vec<String>, _issues: &mut [String]) {
        ui::markup_line("[cyan]Disabling insecure Windows features...[/]");
        for feature in FEATURES_TO_DISABLE {
            let (success, _o, _e) = command::powershell(&format!(
                "Disable-WindowsOptionalFeature -Online -FeatureName {} -NoRestart",
                command::ps_quote(feature)
            ))
            .await;
            if success {
                fixes.push(format!("Disabled feature: {feature}"));
                ui::markup_line(&format!("[green]✓ Disabled: {feature}[/]"));
            } else {
                ui::markup_line(&format!(
                    "[dim]Feature {feature} may not exist or already disabled[/]"
                ));
            }
        }
        // Result was previously discarded while the fix was recorded regardless.
        let (smb1_success, _o, _e) =
            command::powershell("Set-SmbServerConfiguration -EnableSMB1Protocol $false -Force")
                .await;
        if smb1_success {
            fixes.push("Disabled SMB1 protocol".to_string());
            ui::markup_line("[green]✓ Disabled SMB1 protocol[/]");
        } else {
            ui::markup_line("[yellow]⚠ Could not disable SMB1 protocol[/]");
        }
    }

    async fn configure_system_settings(fixes: &mut Vec<String>, issues: &mut Vec<String>) {
        ui::markup_line("[cyan]Configuring additional system settings...[/]");

        // Each of these used to discard its result and record the fix
        // unconditionally, so the summary credited work that never happened.
        // `record` keeps that reporting honest.
        fn record(
            label: &str,
            outcome: pinnacle_core::command::CommandOutput,
            fixes: &mut Vec<String>,
            issues: &mut Vec<String>,
        ) {
            let (success, _o, error) = outcome;
            if success {
                fixes.push(label.to_string());
                ui::markup_line(&format!("[green]✓ {label}[/]"));
            } else {
                let e = error.unwrap_or_default();
                issues.push(format!("{label} failed: {e}"));
                ui::markup_line(&format!(
                    "[yellow]⚠ {} failed: {}[/]",
                    label,
                    ui::escape(&e)
                ));
            }
        }

        record(
            "Flushed DNS cache",
            command::execute("ipconfig", Some("/flushdns")).await,
            fixes,
            issues,
        );
        record(
            "Enabled Windows Defender real-time monitoring",
            command::powershell("Set-MpPreference -DisableRealtimeMonitoring $false").await,
            fixes,
            issues,
        );

        ui::markup_line("[cyan]Updating Windows Defender definitions...[/]");
        record(
            "Updated Windows Defender definitions",
            command::powershell("Update-MpSignature").await,
            fixes,
            issues,
        );

        // `net start` reports failure only through an exit code, and would ask
        // about dependents with nothing there to answer.
        match service_ops::start("wuauserv").await {
            Ok(()) => fixes.push("Started Windows Update service".to_string()),
            Err(_) => issues.push("Could not start the Windows Update service".to_string()),
        }
    }

    async fn disable_suspicious_startup(fixes: &mut Vec<String>, _issues: &mut [String]) {
        ui::markup_line("[cyan]Checking startup programs...[/]");

        let (success, output, _e) = command::powershell_query(
            "Get-CimInstance Win32_StartupCommand | Select-Object Name, Command, Location | ConvertTo-Json",
        )
        .await;
        if success && !output.is_empty() {
            ui::markup_line("[dim]Startup programs have been logged for manual review[/]");
            fixes.push("Reviewed startup programs".to_string());
        }

        let suspicious_run_keys = [
            r"HKCU\Software\Microsoft\Windows\CurrentVersion\Run",
            r"HKLM\Software\Microsoft\Windows\CurrentVersion\Run",
            r"HKCU\Software\Microsoft\Windows\CurrentVersion\RunOnce",
            r"HKLM\Software\Microsoft\Windows\CurrentVersion\RunOnce",
        ];
        for key in suspicious_run_keys {
            if registry_ops::key_exists(key).await == Some(true) {
                ui::markup_line(&format!("[dim]Checked: {key}[/]"));
            }
        }
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
        let system_info = SystemInfo::new();
        ui::markup_line("[cyan]Reading current security configuration...[/]");

        let mut table = ui::TableBuilder::new().columns(&["[bold]Setting[/]", "[bold]Status[/]"]);

        // Through registry_ops so the value is compared exactly, and read via the
        // API where there is one. The substring test this replaces matched "0x1"
        // inside "0x10" and "0x1a" alike, so a setting could read as correct
        // whatever it actually held.
        let uac_enabled = registry_ops::dword_equals(POLICIES_SYSTEM_KEY, "EnableLUA", 1).await;
        table.add_row([
            "UAC Enabled".to_string(),
            if uac_enabled {
                "[green]Yes[/]"
            } else {
                "[red]No[/]"
            }
            .to_string(),
        ]);

        let cad_required = registry_ops::dword_equals(POLICIES_SYSTEM_KEY, "DisableCAD", 0).await;
        table.add_row([
            "Ctrl+Alt+Del Required".to_string(),
            if cad_required {
                "[green]Yes[/]"
            } else {
                "[red]No[/]"
            }
            .to_string(),
        ]);

        let rdp_disabled =
            registry_ops::dword_equals(TERMINAL_SERVER_KEY, "fDenyTSConnections", 1).await;
        table.add_row([
            "Remote Desktop Disabled".to_string(),
            if rdp_disabled {
                "[green]Yes[/]"
            } else {
                "[red]No[/]"
            }
            .to_string(),
        ]);

        table.print();
        system_info
    }

    async fn execute(&mut self) -> TaskResult {
        let mut result = TaskResult {
            task_name: self.name.clone(),
            success: true,
            message: "Security hardening completed".to_string(),
            ..Default::default()
        };

        let mut fixes: Vec<String> = Vec::new();
        let mut issues: Vec<String> = Vec::new();

        if self.dry_run {
            ui::markup_line(
                "[yellow]DRY RUN: Previewing security hardening changes (no changes will be made)[/]",
            );
            result.message = "DRY RUN: Security hardening changes previewed.".to_string();
            return result;
        }

        ui::write_line();
        ui::rule("[bold yellow]Step 1: Apply Registry Settings[/]");
        self.apply_registry_settings(&mut fixes, &mut issues).await;

        ui::write_line();
        ui::rule("[bold yellow]Step 2: Disable Insecure Features[/]");
        Self::disable_insecure_features(&mut fixes, &mut issues).await;

        ui::write_line();
        ui::rule("[bold yellow]Step 3: Configure System Settings[/]");
        Self::configure_system_settings(&mut fixes, &mut issues).await;

        ui::write_line();
        ui::rule("[bold yellow]Step 4: Disable Startup Programs[/]");
        Self::disable_suspicious_startup(&mut fixes, &mut issues).await;

        ui::write_line();
        ui::rule("[bold yellow]Step 5: Harden Apache[/]");
        harden_apache(&mut fixes, &mut issues).await;

        if !issues.is_empty() {
            result.message = format!(
                "Applied {} security settings. {} issues encountered.",
                fixes.len(),
                issues.len()
            );
            result.error_details = Some(
                issues
                    .iter()
                    .take(10)
                    .cloned()
                    .collect::<Vec<_>>()
                    .join("\n"),
            );
        } else {
            result.message = format!(
                "Successfully applied {} security hardening settings.",
                fixes.len()
            );
        }

        result
    }

    async fn verify(&mut self) -> bool {
        let mut all_good = true;

        if registry_ops::dword_equals(POLICIES_SYSTEM_KEY, "EnableLUA", 1).await {
            ui::markup_line("[green]✓ UAC is enabled[/]");
        } else {
            ui::markup_line("[red]✗ UAC is not enabled[/]");
            all_good = false;
        }

        if readme_services::is_remote_desktop_required(self.readme_data.as_ref()) {
            // Deliberately left enabled; verifying it as "must be denied" would
            // report a failure for having done the right thing.
            ui::markup_line("[dim]· Remote Desktop left enabled at the README's request[/]");
        } else if registry_ops::dword_equals(TERMINAL_SERVER_KEY, "fDenyTSConnections", 1).await {
            ui::markup_line("[green]✓ Remote Desktop is disabled[/]");
        } else {
            ui::markup_line("[red]✗ Remote Desktop is not disabled[/]");
            all_good = false;
        }

        all_good
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn missing_directives_are_appended() {
        let out = harden_httpd_conf("Listen 80\n");
        assert_eq!(out, "Listen 80\nServerSignature Off\nServerTokens Prod\n");
    }

    #[test]
    fn active_directives_are_replaced_in_place_ignoring_case() {
        let out = harden_httpd_conf("serversignature On\nListen 80\nSERVERTOKENS Full\n");
        assert_eq!(out, "ServerSignature Off\nListen 80\nServerTokens Prod\n");
    }

    #[test]
    fn commented_directives_are_left_alone_and_real_ones_appended() {
        let text = "#ServerSignature On\n  # ServerTokens Full\n";
        let out = harden_httpd_conf(text);
        assert!(out.starts_with(text));
        assert!(out.ends_with("ServerSignature Off\nServerTokens Prod\n"));
    }

    #[test]
    fn hardening_is_idempotent_and_keeps_a_correct_file_byte_for_byte() {
        let once = harden_httpd_conf("Listen 80\nServerTokens Full\n");
        assert_eq!(harden_httpd_conf(&once), once);
        let tidy = "ServerSignature   Off\r\nServerTokens Prod\r\n";
        assert_eq!(harden_httpd_conf(tidy), tidy);
    }

    #[test]
    fn crlf_files_stay_crlf() {
        let out = harden_httpd_conf("Listen 80\r\nServerSignature On\r\n");
        assert_eq!(
            out,
            "Listen 80\r\nServerSignature Off\r\nServerTokens Prod\r\n"
        );
        assert!(!out.replace("\r\n", "").contains('\n'));
    }

    #[test]
    fn a_missing_final_newline_does_not_glue_directives_on() {
        let out = harden_httpd_conf("Listen 80");
        assert_eq!(out, "Listen 80\nServerSignature Off\nServerTokens Prod\n");
    }

    #[test]
    fn an_empty_file_gets_both_directives() {
        assert_eq!(
            harden_httpd_conf(""),
            "ServerSignature Off\nServerTokens Prod\n"
        );
    }

    #[test]
    fn the_config_is_found_from_a_quoted_service_image_path() {
        assert_eq!(
            conf_from_image_path(r#""C:\Apache24\bin\httpd.exe" -k runservice"#).as_deref(),
            Some(r"C:\Apache24\conf\httpd.conf")
        );
    }

    #[test]
    fn the_config_is_found_from_an_unquoted_service_image_path() {
        assert_eq!(
            conf_from_image_path(r"C:\xampp\apache\bin\httpd.exe -k runservice").as_deref(),
            Some(r"C:\xampp\apache\conf\httpd.conf")
        );
    }

    #[test]
    fn a_non_apache_layout_yields_no_config_path() {
        assert_eq!(conf_from_image_path(r"C:\Tools\svc.exe"), None);
        assert_eq!(conf_from_image_path(""), None);
    }
}
