//! Configure Windows audit policies for security logging (CIS Benchmarks).

use crate::command;
use crate::impl_task_meta;
use crate::models::{SystemInfo, TaskResult};
use crate::registry_ops;
use crate::tasks::Task;
use crate::ui;
use async_trait::async_trait;

/// Audit categories with their subcategories.
const AUDIT_CATEGORIES: &[(&str, &[&str])] = &[
    (
        "Account Logon",
        &[
            "Credential Validation",
            "Kerberos Authentication Service",
            "Kerberos Service Ticket Operations",
            "Other Account Logon Events",
        ],
    ),
    (
        "Account Management",
        &[
            "Application Group Management",
            "Computer Account Management",
            "Distribution Group Management",
            "Other Account Management Events",
            "Security Group Management",
            "User Account Management",
        ],
    ),
    (
        "Detailed Tracking",
        &[
            "DPAPI Activity",
            "PNP Activity",
            "Process Creation",
            "Process Termination",
            "RPC Events",
            "Token Right Adjusted Events",
        ],
    ),
    (
        "DS Access",
        &[
            "Detailed Directory Service Replication",
            "Directory Service Access",
            "Directory Service Changes",
            "Directory Service Replication",
        ],
    ),
    (
        "Logon/Logoff",
        &[
            "Account Lockout",
            "User / Device Claims",
            "Group Membership",
            "IPsec Extended Mode",
            "IPsec Main Mode",
            "IPsec Quick Mode",
            "Logoff",
            "Logon",
            "Network Policy Server",
            "Other Logon/Logoff Events",
            "Special Logon",
        ],
    ),
    (
        "Object Access",
        &[
            "Application Generated",
            "Certification Services",
            "Detailed File Share",
            "File Share",
            "File System",
            "Filtering Platform Connection",
            "Filtering Platform Packet Drop",
            "Handle Manipulation",
            "Kernel Object",
            "Other Object Access Events",
            "Registry",
            "Removable Storage",
            "SAM",
            "Central Policy Staging",
        ],
    ),
    (
        "Policy Change",
        &[
            "Audit Policy Change",
            "Authentication Policy Change",
            "Authorization Policy Change",
            "Filtering Platform Policy Change",
            "MPSSVC Rule-Level Policy Change",
            "Other Policy Change Events",
        ],
    ),
    (
        "Privilege Use",
        &[
            "Non Sensitive Privilege Use",
            "Other Privilege Use Events",
            "Sensitive Privilege Use",
        ],
    ),
    (
        "System",
        &[
            "IPsec Driver",
            "Other System Events",
            "Security State Change",
            "Security System Extension",
            "System Integrity",
        ],
    ),
];

/// Registry settings for security options: (key, (path, name, value, description)).
#[allow(clippy::type_complexity)]
const SECURITY_SETTINGS: &[(&str, (&str, &str, i32, &str))] = &[
    (
        "AuditBaseObjects",
        (
            r"HKLM\SYSTEM\CurrentControlSet\Control\Lsa",
            "auditbaseobjects",
            1,
            "Audit access of Global System Objects",
        ),
    ),
    (
        "FullPrivilegeAuditing",
        (
            r"HKLM\SYSTEM\CurrentControlSet\Control\Lsa",
            "fullprivilegeauditing",
            1,
            "Audit Backup and Restore privilege",
        ),
    ),
    (
        "CrashOnAuditFail",
        (
            r"HKLM\SYSTEM\CurrentControlSet\Control\Lsa",
            "crashonauditfail",
            0,
            "Crash on audit fail (disabled)",
        ),
    ),
    (
        "RunAsPPL",
        (
            r"HKLM\SYSTEM\CurrentControlSet\Control\Lsa",
            "RunAsPPL",
            1,
            "Enable LSA protection",
        ),
    ),
    (
        "LsassAuditLevel",
        (
            r"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\LSASS.exe",
            "AuditLevel",
            8,
            "LSASS audit level",
        ),
    ),
    (
        "DontDisplayLastUsername",
        (
            r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System",
            "dontdisplaylastusername",
            1,
            "Don't display last username",
        ),
    ),
    (
        "DisableCAD",
        (
            r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System",
            "DisableCAD",
            0,
            "Require Ctrl+Alt+Del",
        ),
    ),
    (
        "RestrictAnonymous",
        (
            r"HKLM\SYSTEM\CurrentControlSet\Control\Lsa",
            "restrictanonymous",
            1,
            "Restrict anonymous enumeration of shares",
        ),
    ),
    (
        "RestrictAnonymousSAM",
        (
            r"HKLM\SYSTEM\CurrentControlSet\Control\Lsa",
            "restrictanonymoussam",
            1,
            "Restrict anonymous enumeration of SAM",
        ),
    ),
    (
        "EveryoneIncludesAnonymous",
        (
            r"HKLM\SYSTEM\CurrentControlSet\Control\Lsa",
            "everyoneincludesanonymous",
            0,
            "Anonymous not in Everyone group",
        ),
    ),
    (
        "LimitBlankPasswordUse",
        (
            r"HKLM\SYSTEM\CurrentControlSet\Control\Lsa",
            "LimitBlankPasswordUse",
            1,
            "Limit blank password use",
        ),
    ),
    (
        "DisableDomainCreds",
        (
            r"HKLM\SYSTEM\CurrentControlSet\Control\Lsa",
            "disabledomaincreds",
            1,
            "Don't store domain credentials",
        ),
    ),
    (
        "RequireSecuritySignature",
        (
            r"HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters",
            "requiresecuritysignature",
            1,
            "Require SMB signing",
        ),
    ),
    (
        "EnableSecuritySignature",
        (
            r"HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters",
            "enablesecuritysignature",
            1,
            "Enable SMB signing",
        ),
    ),
    (
        "NullSessionPipes",
        (
            r"HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters",
            "NullSessionPipes",
            0,
            "Clear null session pipes",
        ),
    ),
    (
        "NullSessionShares",
        (
            r"HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters",
            "NullSessionShares",
            0,
            "Clear null session shares",
        ),
    ),
    (
        "AutoDisconnect",
        (
            r"HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters",
            "autodisconnect",
            15,
            "Auto disconnect idle sessions (15 min)",
        ),
    ),
    (
        "EnablePlainTextPassword",
        (
            r"HKLM\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters",
            "EnablePlainTextPassword",
            0,
            "Disable plain text passwords",
        ),
    ),
    (
        "ClearPageFileAtShutdown",
        (
            r"HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management",
            "ClearPageFileAtShutdown",
            1,
            "Clear page file at shutdown",
        ),
    ),
    (
        "CrashDumpEnabled",
        (
            r"HKLM\SYSTEM\CurrentControlSet\Control\CrashControl",
            "CrashDumpEnabled",
            0,
            "Disable crash dump",
        ),
    ),
];

pub struct AuditPolicyTask {
    name: String,
    description: String,
    dry_run: bool,
}

impl AuditPolicyTask {
    pub fn new() -> Self {
        Self {
            name: "Audit Policy Configuration".to_string(),
            description:
                "Configure Windows audit policies to log security events (success and failure)"
                    .to_string(),
            dry_run: false,
        }
    }

    fn display_current_audit_policy(output: &str) {
        let mut table = ui::TableBuilder::new()
            .title("[bold]Current Audit Policy[/]")
            .columns(&["[bold]Category/Subcategory[/]", "[bold]Setting[/]"]);

        let mut count = 0;
        for line in output.split(['\r', '\n']).filter(|l| !l.is_empty()) {
            if line.contains("Success") || line.contains("Failure") || line.contains("No Auditing")
            {
                let parts: Vec<&str> = line.split("  ").filter(|p| !p.is_empty()).collect();
                if parts.len() >= 2 {
                    let category = parts[0].trim();
                    let setting = parts[parts.len() - 1].trim();
                    let color = match setting {
                        "Success and Failure" => "green",
                        "Success" | "Failure" => "yellow",
                        "No Auditing" => "red",
                        _ => "white",
                    };
                    table.add_row([category.to_string(), format!("[{color}]{setting}[/]")]);
                    count += 1;
                    if count >= 15 {
                        break;
                    }
                }
            }
        }

        if count > 0 {
            table.footnote(&format!("[dim](Showing {count} of many audit settings)[/]"));
            table.print();
        }
    }

    async fn configure_audit_categories(fixes: &mut Vec<String>, issues: &mut Vec<String>) {
        let mut table = ui::TableBuilder::new().columns(&["[bold]Category[/]", "[bold]Status[/]"]);

        for (category, _subs) in AUDIT_CATEGORIES {
            ui::markup_line(&format!("[cyan]Configuring {category}...[/]"));

            // advapi32 addresses the category by GUID and sets every subcategory
            // under it in one call, so this works whatever the display language.
            #[cfg(windows)]
            if let Some(guid) = crate::native::audit_policy::category_guid(category) {
                match crate::native::audit_policy::enable_success_and_failure(&guid) {
                    Ok(count) => {
                        table.add_row([
                            category.to_string(),
                            format!("[green]✓ Success & Failure ({count} subcategories)[/]"),
                        ]);
                        fixes.push(format!(
                            "Configured audit: {category} (Success & Failure, {count} subcategories)"
                        ));
                    }
                    Err(reason) => {
                        table.add_row([category.to_string(), "[red]✗ Failed[/]".to_string()]);
                        issues.push(format!("Failed to configure {category}: {reason}"));
                    }
                }
                continue;
            }

            // Fallback: auditpol.exe, whose /category: argument only matches on
            // an English-language image.
            let (success_enable, _o, success_error) = command::execute(
                "auditpol",
                Some(&format!("/set /category:\"{category}\" /success:enable")),
            )
            .await;
            let (failure_enable, _o, failure_error) = command::execute(
                "auditpol",
                Some(&format!("/set /category:\"{category}\" /failure:enable")),
            )
            .await;

            if success_enable && failure_enable {
                table.add_row([
                    category.to_string(),
                    "[green]✓ Success & Failure[/]".to_string(),
                ]);
                fixes.push(format!("Configured audit: {category} (Success & Failure)"));
            } else {
                table.add_row([category.to_string(), "[red]✗ Failed[/]".to_string()]);
                issues.push(format!(
                    "Failed to configure {}: {}",
                    category,
                    success_error.or(failure_error).unwrap_or_default()
                ));
            }
        }
        table.print();
    }

    async fn configure_advanced_audit_policies(fixes: &mut Vec<String>, issues: &mut Vec<String>) {
        ui::markup_line("[cyan]Configuring advanced audit subcategories...[/]");
        let mut configured_count = 0;
        let mut failed: Vec<String> = Vec::new();

        for (_category, subcategories) in AUDIT_CATEGORIES {
            for subcategory in *subcategories {
                let (success_enable, _o, _e) = command::execute(
                    "auditpol",
                    Some(&format!(
                        "/set /subcategory:\"{subcategory}\" /success:enable"
                    )),
                )
                .await;
                let (failure_enable, _o, _e) = command::execute(
                    "auditpol",
                    Some(&format!(
                        "/set /subcategory:\"{subcategory}\" /failure:enable"
                    )),
                )
                .await;
                if success_enable && failure_enable {
                    configured_count += 1;
                } else {
                    failed.push((*subcategory).to_string());
                }
            }
        }

        // The fix used to be recorded unconditionally, so a run that configured
        // nothing still reported "Configured 0 audit subcategories" as a success.
        if configured_count > 0 {
            fixes.push(format!("Configured {configured_count} audit subcategories"));
            ui::markup_line(&format!(
                "[green]✓ Configured {configured_count} audit subcategories[/]"
            ));
        }
        if !failed.is_empty() {
            issues.push(format!(
                "Could not configure {} audit subcategories: {}",
                failed.len(),
                failed.join(", ")
            ));
            ui::markup_line(&format!(
                "[yellow]⚠ Could not configure {} audit subcategories[/]",
                failed.len()
            ));
        }

        let additional = [
            "Logon",
            "Process Creation",
            "Special Logon",
            "Security State Change",
        ];
        for subcategory in additional {
            let _ = command::execute(
                "auditpol",
                Some(&format!(
                    "/set /subcategory:\"{subcategory}\" /success:enable /failure:enable"
                )),
            )
            .await;
        }
    }

    async fn configure_security_registry(fixes: &mut Vec<String>, issues: &mut Vec<String>) {
        let mut table = ui::TableBuilder::new().columns(&[
            "[bold]Setting[/]",
            "[bold]Description[/]",
            "[bold]Status[/]",
        ]);

        for (key, (path, name, value, description)) in SECURITY_SETTINGS {
            match registry_ops::set_dword(path, name, *value as u32).await {
                Ok(()) => {
                    table.add_row([
                        key.to_string(),
                        description.to_string(),
                        "[green]✓ Set[/]".to_string(),
                    ]);
                    fixes.push(format!("Set registry: {name}"));
                }
                Err(error) => {
                    table.add_row([
                        key.to_string(),
                        description.to_string(),
                        "[red]✗ Failed[/]".to_string(),
                    ]);
                    issues.push(format!("Failed to set {name}: {error}"));
                }
            }
        }
        table.print();
    }

    async fn configure_event_log_settings(fixes: &mut Vec<String>, issues: &mut Vec<String>) {
        ui::markup_line("[cyan]Configuring event log settings...[/]");

        let log_settings = [
            ("Security", 196608),
            ("Application", 32768),
            ("System", 32768),
        ];
        for (log_name, max_size) in log_settings {
            let (success, _o, _e) = command::powershell(&format!(
                "Limit-EventLog -LogName {} -MaximumSize {max_size}KB -OverflowAction OverwriteAsNeeded",
                command::ps_quote(log_name)
            ))
            .await;
            if success {
                fixes.push(format!(
                    "Configured {log_name} log: {}MB max size",
                    max_size / 1024
                ));
                ui::markup_line(&format!(
                    "[green]✓ Configured {log_name} log: {}MB max size[/]",
                    max_size / 1024
                ));
            } else {
                ui::markup_line(&format!("[yellow]⚠ Could not configure {log_name} log[/]"));
            }
        }

        ui::markup_line("[cyan]Enabling PowerShell logging...[/]");
        let ps_logging_keys = [
            (
                r"HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging",
                "EnableScriptBlockLogging",
                1,
            ),
            (
                r"HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging",
                "EnableModuleLogging",
                1,
            ),
            (
                r"HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription",
                "EnableTranscripting",
                1,
            ),
        ];
        for (path, name, value) in ps_logging_keys {
            // The key has to exist before the value can be written; `set_dword`
            // creates it, so the separate create is only here for the policy
            // keys that are meant to exist even with no values under them.
            let _ = registry_ops::create_key(path).await;
            if registry_ops::set_dword(path, name, value).await.is_ok() {
                fixes.push(format!("Enabled PowerShell {name}"));
            }
        }
        ui::markup_line("[green]✓ Configured PowerShell logging[/]");

        // Previously the result was discarded and the fix recorded regardless.
        let cmdline_result = registry_ops::set_dword(
            r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit",
            "ProcessCreationIncludeCmdLine_Enabled",
            1,
        )
        .await;

        if let Err(cmdline_error) = cmdline_result {
            issues.push(format!(
                "Failed to enable command line in process creation audit: {cmdline_error}"
            ));
            ui::markup_line("[red]✗ Failed to enable command line in process creation audit[/]");
        } else {
            fixes.push("Enabled command line in process creation audit".to_string());
            ui::markup_line("[green]✓ Enabled command line in process creation audit[/]");
        }
    }
}

impl Default for AuditPolicyTask {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl Task for AuditPolicyTask {
    impl_task_meta!();

    async fn read_system_state(&mut self) -> SystemInfo {
        let system_info = SystemInfo::new();
        ui::markup_line("[cyan]Reading current audit policy settings...[/]");
        let (success, output, _e) = command::execute("auditpol", Some("/get /category:*")).await;
        if success && !output.is_empty() {
            Self::display_current_audit_policy(&output);
        }
        system_info
    }

    async fn execute(&mut self) -> TaskResult {
        let mut result = TaskResult {
            task_name: self.name.clone(),
            success: true,
            message: "Audit policy configuration completed".to_string(),
            ..Default::default()
        };

        let mut fixes: Vec<String> = Vec::new();
        let mut issues: Vec<String> = Vec::new();

        if self.dry_run {
            ui::markup_line(
                "[yellow]DRY RUN: Previewing audit policy changes (no changes will be made)[/]",
            );
            ui::markup_line(&format!(
                "[cyan]Would configure {} audit categories[/]",
                AUDIT_CATEGORIES.len()
            ));
            let total_subcategories: usize = AUDIT_CATEGORIES.iter().map(|(_, s)| s.len()).sum();
            ui::markup_line(&format!(
                "[cyan]Would configure {total_subcategories} advanced subcategories[/]"
            ));
            ui::markup_line(&format!(
                "[cyan]Would configure {} security registry settings[/]",
                SECURITY_SETTINGS.len()
            ));
            result.message = "DRY RUN: Audit policy changes previewed.".to_string();
            return result;
        }

        ui::write_line();
        ui::rule("[bold yellow]Step 1: Configure Audit Categories[/]");
        Self::configure_audit_categories(&mut fixes, &mut issues).await;

        ui::write_line();
        ui::rule("[bold yellow]Step 2: Configure Advanced Audit Policies[/]");
        Self::configure_advanced_audit_policies(&mut fixes, &mut issues).await;

        ui::write_line();
        ui::rule("[bold yellow]Step 3: Configure Security Registry Settings[/]");
        Self::configure_security_registry(&mut fixes, &mut issues).await;

        ui::write_line();
        ui::rule("[bold yellow]Step 4: Configure Event Log Settings[/]");
        Self::configure_event_log_settings(&mut fixes, &mut issues).await;

        if !issues.is_empty() {
            result.message = format!(
                "Applied {} audit settings. {} issues encountered.",
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
                "Successfully configured {} audit policy settings.",
                fixes.len()
            );
        }

        result
    }

    async fn verify(&mut self) -> bool {
        let mut all_good = true;
        let categories = [
            "Account Logon",
            "Account Management",
            "Logon/Logoff",
            "System",
        ];
        for category in categories {
            #[cfg(windows)]
            if let Some(guid) = crate::native::audit_policy::category_guid(category) {
                if let Some(states) = crate::native::audit_policy::query(&guid) {
                    let unaudited = states.iter().filter(|s| s.is_unaudited()).count();
                    if unaudited == 0 {
                        ui::markup_line(&format!(
                            "[green]✓ {category}: Success and Failure auditing enabled[/]"
                        ));
                    } else {
                        ui::markup_line(&format!(
                            "[red]✗ {category}: {unaudited} subcategory(ies) still set to No Auditing[/]"
                        ));
                        all_good = false;
                    }
                    continue;
                }
            }

            let (success, output, _e) =
                command::execute("auditpol", Some(&format!("/get /category:\"{category}\""))).await;
            if success && !output.is_empty() {
                // `auditpol /get /category:"X"` prints one line per subcategory.
                // Testing the whole blob for "Success" AND "Failure" passed as
                // soon as one subcategory audited Success and a *different* one
                // audited Failure - even with others set to "No Auditing".
                // Require that no subcategory is left unaudited instead.
                let unaudited: Vec<&str> = output
                    .lines()
                    .map(|l| l.trim())
                    .filter(|l| l.contains("No Auditing"))
                    .collect();
                if unaudited.is_empty() {
                    ui::markup_line(&format!(
                        "[green]✓ {category}: Success and Failure auditing enabled[/]"
                    ));
                } else {
                    ui::markup_line(&format!(
                        "[red]✗ {category}: {} subcategory(ies) still set to No Auditing[/]",
                        unaudited.len()
                    ));
                    all_good = false;
                }
            }
        }
        all_good
    }
}
