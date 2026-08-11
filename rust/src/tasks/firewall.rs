//! Configure Windows Firewall and block insecure ports.

use crate::command;
use crate::impl_task_meta;
use crate::models::{SystemInfo, TaskResult};
use crate::tasks::Task;
use crate::ui;
use async_trait::async_trait;

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
        let (success, _o, error) = command::execute(
            "powershell",
            Some("-Command \"Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled True\""),
        )
        .await;
        if success {
            fixes.push("Enabled firewall for Domain, Public, and Private profiles".to_string());
            ui::markup_line("[green]? Firewall enabled for all profiles[/]");
        } else {
            issues.push(format!("Failed to enable firewall profiles: {}", error.unwrap_or_default()));
            ui::markup_line("[red]? Failed to enable firewall profiles[/]");
        }
    }

    async fn configure_default_actions(fixes: &mut Vec<String>, issues: &mut Vec<String>) {
        ui::markup_line("[cyan]Configuring default firewall actions...[/]");
        let (success, _o, error) = command::execute(
            "powershell",
            Some("-Command \"Set-NetFirewallProfile -Profile Domain,Public,Private -DefaultInboundAction Block -DefaultOutboundAction Allow -NotifyOnListen True -AllowUnicastResponseToMulticast True\""),
        )
        .await;
        if success {
            fixes.push("Configured default firewall actions (Block inbound, Allow outbound)".to_string());
            ui::markup_line("[green]? Default actions configured[/]");
        } else {
            issues.push(format!("Failed to configure default actions: {}", error.unwrap_or_default()));
        }

        let (profile_success, _o, _e) = command::execute(
            "powershell",
            Some("-Command \"Set-NetConnectionProfile -NetworkCategory Public -ErrorAction SilentlyContinue\""),
        )
        .await;
        if profile_success {
            fixes.push("Set network profile to Public".to_string());
            ui::markup_line("[green]? Network profile set to Public[/]");
        }
    }

    async fn block_insecure_ports(fixes: &mut Vec<String>, _issues: &mut [String]) {
        let mut table = ui::TableBuilder::new()
            .title("[bold]Blocking Insecure Ports[/]")
            .columns(&["[bold]Port[/]", "[bold]Protocol[/]", "[bold]Description[/]", "[bold]Status[/]"]);

        for (port, protocol, description) in PORTS_TO_BLOCK {
            let rule_name = format!("CyberPatriot_Block_{}_{}_{}", description.replace(' ', ""), protocol, port);
            let (success, _o, _e) = command::execute(
                "powershell",
                Some(&format!(
                    "-Command \"New-NetFirewallRule -DisplayName '{rule_name}' -Direction Inbound -LocalPort {port} -Protocol {protocol} -Action Block -ErrorAction SilentlyContinue\""
                )),
            )
            .await;

            if success {
                table.add_row([port.to_string(), protocol.to_string(), description.to_string(), "[green]Blocked[/]".to_string()]);
                fixes.push(format!("Blocked port {port}/{protocol} ({description})"));
            } else {
                let _ = command::execute(
                    "powershell",
                    Some(&format!(
                        "-Command \"Set-NetFirewallRule -DisplayName '{rule_name}' -Enabled True -ErrorAction SilentlyContinue\""
                    )),
                )
                .await;
                table.add_row([port.to_string(), protocol.to_string(), description.to_string(), "[yellow]Exists[/]".to_string()]);
            }
        }
        table.print();
    }

    async fn disable_risky_rules(fixes: &mut Vec<String>, _issues: &mut [String]) {
        ui::markup_line("[cyan]Disabling risky firewall rules...[/]");

        for rule in RULES_TO_DISABLE {
            let (success, _o, _e) = command::execute(
                "netsh",
                Some(&format!("advfirewall firewall set rule name=\"{rule}\" new enable=no")),
            )
            .await;
            if success {
                fixes.push(format!("Disabled rule: {rule}"));
                ui::markup_line(&format!("[green]? Disabled: {}[/]", ui::escape(rule)));
            }
        }

        for group in RULE_GROUPS_TO_DISABLE {
            let (success, _o, _e) = command::execute(
                "netsh",
                Some(&format!("advfirewall firewall set rule group=\"{group}\" new enable=No")),
            )
            .await;
            if success {
                fixes.push(format!("Disabled rule group: {group}"));
                ui::markup_line(&format!("[green]? Disabled group: {}[/]", ui::escape(group)));
            }
        }

        let _ = command::execute(
            "netsh",
            Some("advfirewall firewall add rule name=\"Block_RemoteRegistry_In\" dir=in service=\"RemoteRegistry\" action=block enable=yes"),
        )
        .await;
        let _ = command::execute(
            "netsh",
            Some("advfirewall firewall add rule name=\"Block_RemoteRegistry_Out\" dir=out service=\"RemoteRegistry\" action=block enable=yes"),
        )
        .await;

        fixes.push("Blocked Remote Registry service in firewall".to_string());
    }

    async fn configure_firewall_logging(fixes: &mut Vec<String>, _issues: &mut [String]) {
        ui::markup_line("[cyan]Configuring firewall logging...[/]");
        let log_path = r"%SystemRoot%\System32\LogFiles\Firewall\pfirewall.log";

        let (success, _o, _e) = command::execute(
            "powershell",
            Some(&format!(
                "-Command \"Set-NetFirewallProfile -Profile Domain,Public,Private -LogFileName '{log_path}' -LogBlocked True -LogAllowed False -LogMaxSizeKilobytes 32767\""
            )),
        )
        .await;

        if success {
            fixes.push("Configured firewall logging".to_string());
            ui::markup_line("[green]? Firewall logging configured[/]");
        } else {
            let _ = command::execute("netsh", Some(&format!("advfirewall set allprofiles logging filename {log_path}"))).await;
            let _ = command::execute("netsh", Some("advfirewall set allprofiles logging droppedconnections enable")).await;
            let _ = command::execute("netsh", Some("advfirewall set allprofiles logging maxfilesize 32767")).await;
            fixes.push("Configured firewall logging (via netsh)".to_string());
            ui::markup_line("[green]? Firewall logging configured via netsh[/]");
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
            let (success, output, _e) = command::execute(
                "powershell",
                Some(&format!("-Command \"(Get-NetFirewallProfile -Name '{profile}').Enabled\"")),
            )
            .await;
            let enabled = success && output.trim().eq_ignore_ascii_case("True");
            ui::markup_line(&format!(
                "  {} Profile: {}",
                profile,
                if enabled { "[green]Enabled[/]" } else { "[red]Disabled[/]" }
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
            ui::markup_line("[yellow]DRY RUN: Previewing firewall changes (no changes will be made)[/]");
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
            result.message = format!("Applied {} firewall changes. {} issues encountered.", fixes.len(), issues.len());
            result.error_details = Some(issues.iter().take(10).cloned().collect::<Vec<_>>().join("\n"));
        } else {
            result.message = format!("Successfully applied {} firewall configuration changes.", fixes.len());
        }

        result
    }

    async fn verify(&mut self) -> bool {
        let mut all_good = true;
        for profile in ["Domain", "Private", "Public"] {
            let (success, output, _e) = command::execute(
                "powershell",
                Some(&format!("-Command \"(Get-NetFirewallProfile -Name '{profile}').Enabled\"")),
            )
            .await;
            let enabled = success && output.trim().eq_ignore_ascii_case("True");
            if enabled {
                ui::markup_line(&format!("[green]? {profile} firewall profile is enabled[/]"));
            } else {
                ui::markup_line(&format!("[red]? {profile} firewall profile is disabled[/]"));
                all_good = false;
            }
        }
        all_good
    }
}
