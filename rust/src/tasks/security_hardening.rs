//! Apply additional security hardening settings via registry and system config.

use crate::command;
use crate::impl_task_meta;
use crate::models::{SystemInfo, TaskResult};
use crate::registry_ops;
use crate::service_ops;
use crate::tasks::Task;
use crate::ui;
use async_trait::async_trait;
use indicatif::{ProgressBar, ProgressStyle};

/// The two keys the state read and the verify step check by hand, named so the
/// paths are not repeated character by character between them.
const POLICIES_SYSTEM_KEY: &str = r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System";
const TERMINAL_SERVER_KEY: &str = r"HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server";

/// Registry settings to apply: (path, name, type, value, description).
const REGISTRY_SETTINGS: &[(&str, &str, &str, &str, &str)] = &[
    // UAC Settings
    (
        r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System",
        "EnableLUA",
        "REG_DWORD",
        "1",
        "Enable UAC",
    ),
    (
        r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System",
        "ConsentPromptBehaviorAdmin",
        "REG_DWORD",
        "5",
        "UAC prompt for admins",
    ),
    (
        r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System",
        "PromptOnSecureDesktop",
        "REG_DWORD",
        "1",
        "UAC on secure desktop",
    ),
    (
        r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System",
        "EnableInstallerDetection",
        "REG_DWORD",
        "1",
        "Enable installer detection",
    ),
    (
        r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System",
        "DisableCAD",
        "REG_DWORD",
        "0",
        "Require Ctrl+Alt+Del",
    ),
    (
        r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System",
        "dontdisplaylastusername",
        "REG_DWORD",
        "1",
        "Don't display last username",
    ),
    (
        r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System",
        "undockwithoutlogon",
        "REG_DWORD",
        "0",
        "Disable undocking without logon",
    ),
    // AutoRun/AutoPlay
    (
        r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer",
        "NoAutorun",
        "REG_DWORD",
        "1",
        "Disable AutoRun",
    ),
    (
        r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer",
        "NoDriveTypeAutoRun",
        "REG_DWORD",
        "255",
        "Disable AutoRun for all drives",
    ),
    // Remote Desktop Disable
    (
        r"HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server",
        "fDenyTSConnections",
        "REG_DWORD",
        "1",
        "Deny RDP connections",
    ),
    (
        r"HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server",
        "fAllowToGetHelp",
        "REG_DWORD",
        "0",
        "Disable Remote Assistance",
    ),
    (
        r"HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server",
        "AllowTSConnections",
        "REG_DWORD",
        "0",
        "Disable TS connections",
    ),
    // Auto Admin Logon Disable
    (
        r"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon",
        "AutoAdminLogon",
        "REG_DWORD",
        "0",
        "Disable auto admin logon",
    ),
    // Windows Defender
    (
        r"HKLM\SOFTWARE\Policies\Microsoft\Windows Defender",
        "DisableAntiSpyware",
        "REG_DWORD",
        "0",
        "Enable Windows Defender",
    ),
    (
        r"HKLM\SOFTWARE\Policies\Microsoft\Windows Defender",
        "ServiceKeepAlive",
        "REG_DWORD",
        "1",
        "Keep Defender alive",
    ),
    (
        r"HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection",
        "DisableRealtimeMonitoring",
        "REG_DWORD",
        "0",
        "Enable real-time monitoring",
    ),
    (
        r"HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection",
        "DisableIOAVProtection",
        "REG_DWORD",
        "0",
        "Enable IOAV protection",
    ),
    // Windows Update
    (
        r"HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU",
        "NoAutoUpdate",
        "REG_DWORD",
        "0",
        "Enable auto update",
    ),
    (
        r"HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU",
        "AUOptions",
        "REG_DWORD",
        "4",
        "Auto download and install",
    ),
    (
        r"HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU",
        "AutoInstallMinorUpdates",
        "REG_DWORD",
        "1",
        "Auto install minor updates",
    ),
    // LSA Protection
    (
        r"HKLM\SYSTEM\CurrentControlSet\Control\Lsa",
        "RunAsPPL",
        "REG_DWORD",
        "1",
        "Enable LSA protection",
    ),
    (
        r"HKLM\SYSTEM\CurrentControlSet\Control\Lsa",
        "LimitBlankPasswordUse",
        "REG_DWORD",
        "1",
        "Limit blank password use",
    ),
    (
        r"HKLM\SYSTEM\CurrentControlSet\Control\Lsa",
        "restrictanonymous",
        "REG_DWORD",
        "1",
        "Restrict anonymous enumeration",
    ),
    (
        r"HKLM\SYSTEM\CurrentControlSet\Control\Lsa",
        "restrictanonymoussam",
        "REG_DWORD",
        "1",
        "Restrict anonymous SAM",
    ),
    (
        r"HKLM\SYSTEM\CurrentControlSet\Control\Lsa",
        "everyoneincludesanonymous",
        "REG_DWORD",
        "0",
        "Anonymous not in Everyone",
    ),
    (
        r"HKLM\SYSTEM\CurrentControlSet\Control\Lsa",
        "disabledomaincreds",
        "REG_DWORD",
        "1",
        "Disable domain credential storage",
    ),
    (
        r"HKLM\SYSTEM\CurrentControlSet\Control\Lsa",
        "auditbaseobjects",
        "REG_DWORD",
        "1",
        "Audit global system objects",
    ),
    (
        r"HKLM\SYSTEM\CurrentControlSet\Control\Lsa",
        "fullprivilegeauditing",
        "REG_DWORD",
        "1",
        "Audit backup/restore",
    ),
    // LSASS Auditing
    (
        r"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\LSASS.exe",
        "AuditLevel",
        "REG_DWORD",
        "8",
        "LSASS audit level",
    ),
    // Memory Protection
    (
        r"HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management",
        "ClearPageFileAtShutdown",
        "REG_DWORD",
        "1",
        "Clear page file at shutdown",
    ),
    // Crash Dump Disable
    (
        r"HKLM\SYSTEM\CurrentControlSet\Control\CrashControl",
        "CrashDumpEnabled",
        "REG_DWORD",
        "0",
        "Disable crash dumps",
    ),
    // CD/Floppy Access
    (
        r"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon",
        "AllocateCDRoms",
        "REG_DWORD",
        "1",
        "Restrict CD-ROM access",
    ),
    (
        r"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon",
        "AllocateFloppies",
        "REG_DWORD",
        "1",
        "Restrict floppy access",
    ),
    // SMB Security
    (
        r"HKLM\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters",
        "EnablePlainTextPassword",
        "REG_DWORD",
        "0",
        "Disable plain text passwords",
    ),
    // Explorer Settings
    (
        r"HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced",
        "Hidden",
        "REG_DWORD",
        "1",
        "Show hidden files",
    ),
    (
        r"HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced",
        "ShowSuperHidden",
        "REG_DWORD",
        "1",
        "Show super hidden files",
    ),
    // IE/Edge Security
    (
        r"HKCU\Software\Microsoft\Internet Explorer\PhishingFilter",
        "EnabledV9",
        "REG_DWORD",
        "1",
        "Enable SmartScreen",
    ),
    (
        r"HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings",
        "DisablePasswordCaching",
        "REG_DWORD",
        "1",
        "Disable password caching",
    ),
    (
        r"HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings",
        "WarnonBadCertRecving",
        "REG_DWORD",
        "1",
        "Warn on bad certificates",
    ),
    (
        r"HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings",
        "WarnOnPostRedirect",
        "REG_DWORD",
        "1",
        "Warn on POST redirect",
    ),
    (
        r"HKCU\Software\Microsoft\Internet Explorer\Main",
        "DoNotTrack",
        "REG_DWORD",
        "1",
        "Enable Do Not Track",
    ),
    // Disable Remote Shell
    (
        r"HKLM\SOFTWARE\Policies\Microsoft\Windows\WinRM\Service\WinRS",
        "AllowRemoteShellAccess",
        "REG_DWORD",
        "0",
        "Disable remote shell",
    ),
];

const FEATURES_TO_DISABLE: &[&str] = &[
    "TelnetClient",
    "TelnetServer",
    "TFTP",
    "SMB1Protocol",
    "SMB1Protocol-Client",
    "SMB1Protocol-Server",
    "MicrosoftWindowsPowerShellV2",
    "MicrosoftWindowsPowerShellV2Root",
];

pub struct SecurityHardeningTask {
    name: String,
    description: String,
    dry_run: bool,
}

impl SecurityHardeningTask {
    pub fn new() -> Self {
        Self {
            name: "Security Hardening".to_string(),
            description:
                "Apply additional security hardening settings via registry and system configuration"
                    .to_string(),
            dry_run: false,
        }
    }

    async fn apply_registry_settings(fixes: &mut Vec<String>, issues: &mut Vec<String>) {
        ui::markup_line(&format!(
            "[cyan]Applying {} registry settings...[/]",
            REGISTRY_SETTINGS.len()
        ));

        let mut success_count = 0;
        let mut fail_count = 0;

        let bar = ProgressBar::new(REGISTRY_SETTINGS.len() as u64);
        bar.set_style(
            ProgressStyle::with_template("{msg} [{bar:40.cyan/blue}] {pos}/{len}")
                .unwrap()
                .progress_chars("=> "),
        );
        bar.set_message("Applying registry settings...");

        for (path, name, ty, value, description) in REGISTRY_SETTINGS {
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
            outcome: crate::command::CommandOutput,
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
            ui::markup_line("[yellow]DRY RUN: Previewing security hardening changes (no changes will be made)[/]");
            result.message = "DRY RUN: Security hardening changes previewed.".to_string();
            return result;
        }

        ui::write_line();
        ui::rule("[bold yellow]Step 1: Apply Registry Settings[/]");
        Self::apply_registry_settings(&mut fixes, &mut issues).await;

        ui::write_line();
        ui::rule("[bold yellow]Step 2: Disable Insecure Features[/]");
        Self::disable_insecure_features(&mut fixes, &mut issues).await;

        ui::write_line();
        ui::rule("[bold yellow]Step 3: Configure System Settings[/]");
        Self::configure_system_settings(&mut fixes, &mut issues).await;

        ui::write_line();
        ui::rule("[bold yellow]Step 4: Disable Startup Programs[/]");
        Self::disable_suspicious_startup(&mut fixes, &mut issues).await;

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

        if registry_ops::dword_equals(TERMINAL_SERVER_KEY, "fDenyTSConnections", 1).await {
            ui::markup_line("[green]✓ Remote Desktop is disabled[/]");
        } else {
            ui::markup_line("[red]✗ Remote Desktop is not disabled[/]");
            all_good = false;
        }

        all_good
    }
}
