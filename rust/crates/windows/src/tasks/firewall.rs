//! Configure Windows Firewall and block insecure ports.

use async_trait::async_trait;
use pinnacle_core::Task;
use pinnacle_core::command;
use pinnacle_core::impl_task_meta;
use pinnacle_core::models::{SystemInfo, TaskResult};
use pinnacle_core::ui;

/// Ports that should be blocked for security: (port, protocol, description).
const PORTS_TO_BLOCK: &[(u16, &str, &str)] = &[
    (21, "TCP", "FTP Control"),
    (20, "TCP", "FTP Data"),
    (22, "TCP", "SSH"),
    (23, "TCP", "Telnet"),
    (25, "TCP", "SMTP"),
    (69, "UDP", "TFTP"),
    (110, "TCP", "POP3"),
    (135, "TCP", "RPC"),
    (137, "UDP", "NetBIOS Name"),
    (138, "UDP", "NetBIOS Datagram"),
    (139, "TCP", "NetBIOS Session"),
    (143, "TCP", "IMAP"),
    (161, "UDP", "SNMP"),
    (162, "UDP", "SNMP Trap"),
    (389, "TCP", "LDAP"),
    (445, "TCP", "SMB"),
    (512, "TCP", "rexec"),
    (513, "TCP", "rlogin"),
    (514, "TCP", "rsh/syslog"),
    (1433, "TCP", "MS SQL"),
    (1434, "UDP", "MS SQL Browser"),
    (3306, "TCP", "MySQL"),
    (3389, "TCP", "RDP"),
    (5900, "TCP", "VNC"),
    (5901, "TCP", "VNC"),
    (5902, "TCP", "VNC"),
];

const RULES_TO_DISABLE: &[&str] = &[
    "Remote Assistance (DCOM-In)",
    "Remote Assistance (PNRP-In)",
    "Remote Assistance (RA Server TCP-In)",
    "Remote Assistance (SSDP TCP-In)",
    "Remote Assistance (SSDP UDP-In)",
    "Remote Assistance (TCP-In)",
    "Telnet Server",
    "netcat",
];

const RULE_GROUPS_TO_DISABLE: &[&str] = &[
    "Network Discovery",
    "File and Printer Sharing",
    "Remote Desktop",
    "Remote Assistance",
    "Remote Event Log Management",
    "Remote Service Management",
    "Remote Volume Management",
    "Windows Remote Management",
];

pub struct FirewallConfigurationTask {
    name: String,
    description: String,
    dry_run: bool,
}

impl FirewallConfigurationTask {
    pub fn new() -> Self {
        Self {
            name: "Firewall Configuration".to_string(),
            description: "Enable Windows Firewall and block insecure ports".to_string(),
            dry_run: false,
        }
    }

    async fn enable_firewall_profiles(fixes: &mut Vec<String>, issues: &mut Vec<String>) {
        ui::markup_line("[cyan]Enabling firewall for all profiles...[/]");

        // INetFwPolicy2 addresses the profiles by enum, so this works whatever
        // the display language, reports a real HRESULT on failure, and avoids
        // the PowerShell launch that dominated this task's runtime.
        #[cfg(windows)]
        match crate::native::firewall::enable_all_profiles() {
            Ok(profiles) => {
                fixes.push(format!(
                    "Enabled firewall for {} profiles",
                    profiles.join(", ")
                ));
                ui::markup_line("[green]✓ Firewall enabled for all profiles[/]");
                return;
            }
            Err(reason) => {
                ui::markup_line(&format!(
                    "[yellow]! Firewall COM path unavailable ({}); falling back[/]",
                    ui::escape(&reason)
                ));
            }
        }

        let (success, _o, error) = command::powershell(
            "Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled True",
        )
        .await;
        if success {
            fixes.push("Enabled firewall for Domain, Public, and Private profiles".to_string());
            ui::markup_line("[green]✓ Firewall enabled for all profiles[/]");
        } else {
            issues.push(format!(
                "Failed to enable firewall profiles: {}",
                error.unwrap_or_default()
            ));
            ui::markup_line("[red]✗ Failed to enable firewall profiles[/]");
        }
    }

    async fn configure_default_actions(fixes: &mut Vec<String>, issues: &mut Vec<String>) {
        ui::markup_line("[cyan]Configuring default firewall actions...[/]");
        let (success, _o, error) = command::powershell(
            "Set-NetFirewallProfile -Profile Domain,Public,Private -DefaultInboundAction Block -DefaultOutboundAction Allow -NotifyOnListen True -AllowUnicastResponseToMulticast True",
        )
        .await;
        if success {
            fixes.push(
                "Configured default firewall actions (Block inbound, Allow outbound)".to_string(),
            );
            ui::markup_line("[green]✓ Default actions configured[/]");
        } else {
            issues.push(format!(
                "Failed to configure default actions: {}",
                error.unwrap_or_default()
            ));
        }

        // Best-effort: there may be no active connection profile to change, so a
        // failure here is reported but not treated as an issue.
        let (profile_success, _o, _e) =
            command::powershell("Set-NetConnectionProfile -NetworkCategory Public").await;
        if profile_success {
            fixes.push("Set network profile to Public".to_string());
            ui::markup_line("[green]✓ Network profile set to Public[/]");
        } else {
            ui::markup_line("[dim]No network connection profile to set to Public[/]");
        }
    }

    async fn block_insecure_ports(fixes: &mut Vec<String>, issues: &mut Vec<String>) {
        let mut table = ui::TableBuilder::new()
            .title("[bold]Blocking Insecure Ports[/]")
            .columns(&[
                "[bold]Port[/]",
                "[bold]Protocol[/]",
                "[bold]Description[/]",
                "[bold]Status[/]",
            ]);

        for (port, protocol, description) in PORTS_TO_BLOCK {
            let rule_name = format!(
                "PinnacleCyPat_Block_{}_{}_{}",
                description.replace(' ', ""),
                protocol,
                port
            );
            let quoted = command::ps_quote(&rule_name);
            let (success, _o, _e) = command::powershell(&format!(
                "New-NetFirewallRule -DisplayName {quoted} -Direction Inbound -LocalPort {port} -Protocol {protocol} -Action Block"
            ))
            .await;

            if success {
                table.add_row([
                    port.to_string(),
                    protocol.to_string(),
                    description.to_string(),
                    "[green]Blocked[/]".to_string(),
                ]);
                fixes.push(format!("Blocked port {port}/{protocol} ({description})"));
                continue;
            }

            // Creation fails when the rule already exists, so fall back to
            // enabling it. The fallback ran before too, but its result was
            // discarded: a rule that could not be enabled was still reported as
            // "Exists", implying the port was covered when it was not.
            let (enabled, _o, enable_error) = command::powershell(&format!(
                "Set-NetFirewallRule -DisplayName {quoted} -Enabled True"
            ))
            .await;
            if enabled {
                table.add_row([
                    port.to_string(),
                    protocol.to_string(),
                    description.to_string(),
                    "[yellow]Exists[/]".to_string(),
                ]);
                fixes.push(format!(
                    "Enabled existing block rule for {port}/{protocol} ({description})"
                ));
            } else {
                table.add_row([
                    port.to_string(),
                    protocol.to_string(),
                    description.to_string(),
                    "[red]Failed[/]".to_string(),
                ]);
                issues.push(format!(
                    "Could not block port {port}/{protocol} ({description}): {}",
                    enable_error.unwrap_or_default()
                ));
            }
        }
        table.print();
    }

    async fn disable_risky_rules(fixes: &mut Vec<String>, issues: &mut Vec<String>) {
        ui::markup_line("[cyan]Disabling risky firewall rules...[/]");

        for rule in RULES_TO_DISABLE {
            let (success, _o, _e) = command::execute(
                "netsh",
                Some(&format!(
                    "advfirewall firewall set rule name=\"{rule}\" new enable=no"
                )),
            )
            .await;
            if success {
                fixes.push(format!("Disabled rule: {rule}"));
                ui::markup_line(&format!("[green]✓ Disabled: {}[/]", ui::escape(rule)));
            }
        }

        for group in RULE_GROUPS_TO_DISABLE {
            let (success, _o, _e) = command::execute(
                "netsh",
                Some(&format!(
                    "advfirewall firewall set rule group=\"{group}\" new enable=No"
                )),
            )
            .await;
            if success {
                fixes.push(format!("Disabled rule group: {group}"));
                ui::markup_line(&format!(
                    "[green]✓ Disabled group: {}[/]",
                    ui::escape(group)
                ));
            }
        }

        // Both results used to be discarded while the fix was recorded
        // unconditionally, so a failure to block Remote Registry still reported
        // as applied. Record what actually happened.
        let (in_success, _o, in_error) = command::execute(
            "netsh",
            Some("advfirewall firewall add rule name=\"Block_RemoteRegistry_In\" dir=in service=\"RemoteRegistry\" action=block enable=yes"),
        )
        .await;
        let (out_success, _o, out_error) = command::execute(
            "netsh",
            Some("advfirewall firewall add rule name=\"Block_RemoteRegistry_Out\" dir=out service=\"RemoteRegistry\" action=block enable=yes"),
        )
        .await;

        if in_success && out_success {
            fixes.push("Blocked Remote Registry service in firewall".to_string());
            ui::markup_line("[green]✓ Blocked Remote Registry service[/]");
        } else {
            let e = in_error.or(out_error).unwrap_or_default();
            issues.push(format!(
                "Failed to block Remote Registry service in firewall: {e}"
            ));
            ui::markup_line("[red]✗ Failed to block Remote Registry service[/]");
        }
    }

    async fn configure_firewall_logging(fixes: &mut Vec<String>, issues: &mut Vec<String>) {
        ui::markup_line("[cyan]Configuring firewall logging...[/]");
        let log_path = r"%SystemRoot%\System32\LogFiles\Firewall\pfirewall.log";

        let (success, _o, _e) = command::powershell(&format!(
            "Set-NetFirewallProfile -Profile Domain,Public,Private -LogFileName {} -LogBlocked True -LogAllowed False -LogMaxSizeKilobytes 32767",
            command::ps_quote(log_path)
        ))
        .await;

        if success {
            fixes.push("Configured firewall logging".to_string());
            ui::markup_line("[green]✓ Firewall logging configured[/]");
            return;
        }

        // The netsh fallback previously discarded all three results and recorded
        // the fix unconditionally, reporting success even when every command
        // failed.
        let (name_ok, _o, name_err) = command::execute(
            "netsh",
            Some(&format!(
                "advfirewall set allprofiles logging filename {log_path}"
            )),
        )
        .await;
        let (dropped_ok, _o, dropped_err) = command::execute(
            "netsh",
            Some("advfirewall set allprofiles logging droppedconnections enable"),
        )
        .await;
        let (size_ok, _o, size_err) = command::execute(
            "netsh",
            Some("advfirewall set allprofiles logging maxfilesize 32767"),
        )
        .await;

        if name_ok && dropped_ok && size_ok {
            fixes.push("Configured firewall logging (via netsh)".to_string());
            ui::markup_line("[green]✓ Firewall logging configured via netsh[/]");
        } else {
            let e = name_err.or(dropped_err).or(size_err).unwrap_or_default();
            issues.push(format!("Failed to configure firewall logging: {e}"));
            ui::markup_line("[red]✗ Failed to configure firewall logging[/]");
        }
    }
}

impl Default for FirewallConfigurationTask {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl Task for FirewallConfigurationTask {
    impl_task_meta!();

    async fn read_system_state(&mut self) -> SystemInfo {
        let system_info = SystemInfo::new();
        ui::markup_line("[cyan]Reading firewall configuration...[/]");

        for profile in ["Domain", "Private", "Public"] {
            let (success, output, _e) = command::powershell_query(&format!(
                "(Get-NetFirewallProfile -Name {}).Enabled",
                command::ps_quote(profile)
            ))
            .await;
            let enabled = success && output.trim().eq_ignore_ascii_case("True");
            ui::markup_line(&format!(
                "  {} Profile: {}",
                profile,
                if enabled {
                    "[green]Enabled[/]"
                } else {
                    "[red]Disabled[/]"
                }
            ));
        }

        system_info
    }

    async fn execute(&mut self) -> TaskResult {
        let mut result = TaskResult {
            task_name: self.name.clone(),
            success: true,
            message: "Firewall configuration completed".to_string(),
            ..Default::default()
        };

        let mut fixes: Vec<String> = Vec::new();
        let mut issues: Vec<String> = Vec::new();

        if self.dry_run {
            ui::markup_line(
                "[yellow]DRY RUN: Previewing firewall changes (no changes will be made)[/]",
            );
            result.message = "DRY RUN: Firewall configuration changes previewed.".to_string();
            return result;
        }

        ui::write_line();
        ui::rule("[bold yellow]Step 1: Enable Firewall Profiles[/]");
        Self::enable_firewall_profiles(&mut fixes, &mut issues).await;

        ui::write_line();
        ui::rule("[bold yellow]Step 2: Configure Default Actions[/]");
        Self::configure_default_actions(&mut fixes, &mut issues).await;

        ui::write_line();
        ui::rule("[bold yellow]Step 3: Block Insecure Ports[/]");
        Self::block_insecure_ports(&mut fixes, &mut issues).await;

        ui::write_line();
        ui::rule("[bold yellow]Step 4: Disable Risky Firewall Rules[/]");
        Self::disable_risky_rules(&mut fixes, &mut issues).await;

        ui::write_line();
        ui::rule("[bold yellow]Step 5: Configure Firewall Logging[/]");
        Self::configure_firewall_logging(&mut fixes, &mut issues).await;

        if !issues.is_empty() {
            result.message = format!(
                "Applied {} firewall changes. {} issues encountered.",
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
                "Successfully applied {} firewall configuration changes.",
                fixes.len()
            );
        }

        result
    }

    async fn verify(&mut self) -> bool {
        let mut all_good = true;
        for profile in ["Domain", "Private", "Public"] {
            let (success, output, _e) = command::powershell_query(&format!(
                "(Get-NetFirewallProfile -Name {}).Enabled",
                command::ps_quote(profile)
            ))
            .await;
            let enabled = success && output.trim().eq_ignore_ascii_case("True");
            if enabled {
                ui::markup_line(&format!(
                    "[green]✓ {profile} firewall profile is enabled[/]"
                ));
            } else {
                ui::markup_line(&format!("[red]✗ {profile} firewall profile is disabled[/]"));
                all_good = false;
            }
        }
        all_good
    }
}
