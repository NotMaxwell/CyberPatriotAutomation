//! Manage Windows services based on README requirements and security best practices.

use crate::command;
use crate::impl_task_meta;
use crate::models::{ReadmeData, SystemInfo, TaskResult};
use crate::tasks::Task;
use crate::ui;
use async_trait::async_trait;
use std::collections::HashSet;

/// Services that should generally be DISABLED for security: (service, description).
const SERVICES_TO_DISABLE: &[(&str, &str)] = &[
    ("TermService", "Remote Desktop Services"),
    ("SessionEnv", "Remote Desktop Configuration"),
    ("UmRdpService", "Remote Desktop Services UserMode Port Redirector"),
    ("RemoteRegistry", "Remote Registry"),
    ("RemoteAccess", "Routing and Remote Access"),
    ("RasMan", "Remote Access Connection Manager"),
    ("RasAuto", "Remote Access Auto Connection Manager"),
    ("TlntSvr", "Telnet"),
    ("ftpsvc", "FTP Publishing Service"),
    ("Msftpsvc", "Microsoft FTP Service (Legacy)"),
    ("SNMP", "SNMP Service"),
    ("SNMPTRAP", "SNMP Trap"),
    ("SSDPSRV", "SSDP Discovery"),
    ("upnphost", "UPnP Device Host"),
    ("SharedAccess", "Internet Connection Sharing (ICS)"),
    ("HomeGroupProvider", "HomeGroup Provider"),
    ("HomeGroupListener", "HomeGroup Listener"),
    ("LanmanServer", "Server (File/Print Sharing)"),
    ("W3SVC", "World Wide Web Publishing Service"),
    ("IISADMIN", "IIS Admin Service"),
    ("WAS", "Windows Process Activation Service"),
    ("TapiSrv", "Telephony"),
    ("Messenger", "Messenger (Legacy)"),
    ("XblAuthManager", "Xbox Live Auth Manager"),
    ("XblGameSave", "Xbox Live Game Save"),
    ("XboxGipSvc", "Xbox Accessory Management Service"),
    ("XboxNetApiSvc", "Xbox Live Networking Service"),
    ("mnmsrvc", "NetMeeting Remote Desktop Sharing"),
    ("NetTcpPortSharing", "Net.Tcp Port Sharing Service"),
    ("simptcp", "Simple TCP/IP Services"),
    ("p2pimsvc", "Peer Networking Identity Manager"),
    ("p2psvc", "Peer Networking Grouping"),
    ("PNRPsvc", "Peer Name Resolution Protocol"),
    ("Fax", "Fax"),
    ("Smtpsvc", "Simple Mail Transfer Protocol (SMTP)"),
    ("IPRIP", "RIP Listener"),
    ("Dfs", "Distributed File System"),
    ("MSDTC", "Distributed Transaction Coordinator"),
    ("ERSvc", "Error Reporting Service"),
    ("WerSvc", "Windows Error Reporting Service"),
    ("helpsvc", "Help and Support"),
    ("seclogon", "Secondary Logon"),
    ("SENS", "System Event Notification Service"),
    ("SCardSvr", "Smart Card"),
    ("SCPolicySvc", "Smart Card Removal Policy"),
    ("TabletInputService", "Tablet PC Input Service"),
    ("WMPNetworkSvc", "Windows Media Player Network Sharing Service"),
    ("icssvc", "Windows Mobile Hotspot Service"),
    ("lfsvc", "Geolocation Service"),
    ("MapsBroker", "Downloaded Maps Manager"),
    ("PhoneSvc", "Phone Service"),
    ("WalletService", "Wallet Service"),
    ("RetailDemo", "Retail Demo Service"),
    ("DiagTrack", "Connected User Experiences and Telemetry"),
    ("dmwappushservice", "WAP Push Message Routing Service"),
];

/// Services that should generally REMAIN ENABLED for system functionality.
const CRITICAL_SERVICES: &[(&str, &str)] = &[
    ("wuauserv", "Windows Update"),
    ("WinDefend", "Windows Defender Antivirus Service"),
    ("SecurityHealthService", "Windows Security Service"),
    ("wscsvc", "Security Center"),
    ("MpsSvc", "Windows Defender Firewall"),
    ("EventLog", "Windows Event Log"),
    ("Schedule", "Task Scheduler"),
    ("Winmgmt", "Windows Management Instrumentation"),
    ("CryptSvc", "Cryptographic Services"),
    ("DcomLaunch", "DCOM Server Process Launcher"),
    ("RpcSs", "Remote Procedure Call (RPC)"),
    ("RpcEptMapper", "RPC Endpoint Mapper"),
    ("Dhcp", "DHCP Client"),
    ("Dnscache", "DNS Client"),
    ("NlaSvc", "Network Location Awareness"),
    ("nsi", "Network Store Interface Service"),
    ("BFE", "Base Filtering Engine"),
    ("BITS", "Background Intelligent Transfer Service"),
    ("TrustedInstaller", "Windows Modules Installer"),
    ("Spooler", "Print Spooler"),
];

const SERVICE_NAME_MAPPINGS: &[(&str, &str)] = &[
    ("CCS Client", "CCSClient"),
    ("Remote Desktop", "TermService"),
    ("Remote Desktop Services", "TermService"),
    ("RDP", "TermService"),
    ("FTP", "ftpsvc"),
    ("Telnet", "TlntSvr"),
    ("SSH", "sshd"),
    ("OpenSSH", "sshd"),
    ("OpenSSH SSH Server", "sshd"),
    ("Remote Registry", "RemoteRegistry"),
    ("Windows Update", "wuauserv"),
    ("Windows Defender", "WinDefend"),
    ("Windows Firewall", "MpsSvc"),
    ("Print Spooler", "Spooler"),
    ("ICS", "SharedAccess"),
    ("Internet Connection Sharing", "SharedAccess"),
];

const FEATURES_TO_DISABLE: &[&str] = &[
    "TelnetClient",
    "TelnetServer",
    "TFTP",
    "SMB1Protocol",
    "SMB1Protocol-Client",
    "SMB1Protocol-Server",
];

/// A case-insensitive ordered set of service names.
#[derive(Default)]
struct ServiceSet {
    items: Vec<String>,
    lower: HashSet<String>,
}

impl ServiceSet {
    fn add(&mut self, name: &str) {
        if self.lower.insert(name.to_lowercase()) {
            self.items.push(name.to_string());
        }
    }
    fn contains(&self, name: &str) -> bool {
        self.lower.contains(&name.to_lowercase())
    }
    fn len(&self) -> usize {
        self.items.len()
    }
    fn iter(&self) -> impl Iterator<Item = &String> {
        self.items.iter()
    }
}

pub struct ServiceManagementTask {
    name: String,
    description: String,
    dry_run: bool,
    readme_data: Option<ReadmeData>,
}

impl ServiceManagementTask {
    pub fn new() -> Self {
        Self {
            name: "Service Management".to_string(),
            description:
                "Enable/disable Windows services based on README and security best practices"
                    .to_string(),
            dry_run: false,
            readme_data: None,
        }
    }

    pub fn set_readme_data(&mut self, data: ReadmeData) {
        self.readme_data = Some(data);
    }

    fn map_service_name(display_name: &str) -> String {
        SERVICE_NAME_MAPPINGS
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case(display_name))
            .map(|(_, v)| v.to_string())
            .unwrap_or_else(|| display_name.to_string())
    }

    fn service_description(service: &str) -> Option<&'static str> {
        SERVICES_TO_DISABLE
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case(service))
            .map(|(_, v)| *v)
    }

    fn display_readme_service_requirements(&self) {
        let Some(readme) = &self.readme_data else {
            return;
        };
        if !readme.critical_services.is_empty() {
            ui::markup_line("[bold green]README Critical Services (Do NOT disable):[/]");
            for service in &readme.critical_services {
                ui::markup_line(&format!("  [green]? {}[/]", ui::escape(service)));
            }
            ui::write_line();
        }
        if !readme.prohibited_services.is_empty() {
            ui::markup_line("[bold red]README Services to Disable:[/]");
            for service in &readme.prohibited_services {
                ui::markup_line(&format!("  [red]? {}[/]", ui::escape(service)));
            }
            ui::write_line();
        }
    }

    fn build_service_lists(&self) -> (ServiceSet, ServiceSet, ServiceSet) {
        let mut to_disable = ServiceSet::default();
        let mut to_enable = ServiceSet::default();
        let mut do_not_touch = ServiceSet::default();

        for (service, _) in CRITICAL_SERVICES {
            do_not_touch.add(service);
        }

        if let Some(readme) = &self.readme_data {
            for service in &readme.critical_services {
                let name = Self::map_service_name(service);
                do_not_touch.add(&name);
                to_enable.add(&name);
            }
        }

        for (service, _) in SERVICES_TO_DISABLE {
            if !do_not_touch.contains(service) {
                to_disable.add(service);
            }
        }

        if let Some(readme) = &self.readme_data {
            for service in &readme.prohibited_services {
                let name = Self::map_service_name(service);
                if !do_not_touch.contains(&name) {
                    to_disable.add(&name);
                }
            }
        }

        (to_disable, to_enable, do_not_touch)
    }

    async fn protect_critical_services(fixes: &mut Vec<String>, _issues: &mut [String]) {
        ui::markup_line(&format!("[cyan]Protecting {} critical services...[/]", CRITICAL_SERVICES.len()));

        for (service, _) in CRITICAL_SERVICES.iter().take(10) {
            let (success, output, _e) = command::execute(
                "powershell",
                Some(&format!("-Command \"(Get-Service -Name '{service}' -ErrorAction SilentlyContinue).Status\"")),
            )
            .await;
            if success && !output.trim().is_empty() {
                if !output.trim().eq_ignore_ascii_case("Running") {
                    ui::markup_line(&format!("[yellow]Starting critical service: {service}...[/]"));
                    let (start_success, _o, start_error) =
                        command::execute("net", Some(&format!("start \"{service}\""))).await;
                    if start_success {
                        fixes.push(format!("Started critical service: {service}"));
                        ui::markup_line(&format!("[green]? Started {service}[/]"));
                    } else {
                        ui::markup_line(&format!(
                            "[dim]Could not start {}: {}[/]",
                            service,
                            ui::escape(&start_error.unwrap_or_default())
                        ));
                    }
                } else {
                    ui::markup_line(&format!("[dim]? {service} is already running[/]"));
                }
            }
        }
    }

    async fn enable_services(to_enable: &ServiceSet, fixes: &mut Vec<String>, issues: &mut Vec<String>) {
        if to_enable.len() == 0 {
            ui::markup_line("[green]? No additional services need to be enabled[/]");
            return;
        }
        for service in to_enable.iter() {
            ui::markup_line(&format!("[yellow]Enabling service: {service}...[/]"));
            let (config_success, _o, config_error) =
                command::execute("sc", Some(&format!("config \"{service}\" start= auto"))).await;
            let _ = command::execute("net", Some(&format!("start \"{service}\""))).await;
            if config_success {
                fixes.push(format!("Enabled service: {service}"));
                ui::markup_line(&format!("[green]? Enabled {service}[/]"));
            } else {
                issues.push(format!("Could not enable {}: {}", service, config_error.unwrap_or_default()));
            }
        }
    }

    async fn disable_services(
        to_disable: &ServiceSet,
        do_not_touch: &ServiceSet,
        fixes: &mut Vec<String>,
        issues: &mut Vec<String>,
    ) {
        let mut table = ui::TableBuilder::new()
            .title("[bold red]Services to Disable[/]")
            .columns(&["[bold]Service[/]", "[bold]Description[/]", "[bold]Status[/]"]);

        let mut disabled_count = 0;
        let mut skipped_count = 0;

        for service in to_disable.iter() {
            if do_not_touch.contains(service) {
                skipped_count += 1;
                continue;
            }

            let (check_success, check_output, _e) = command::execute(
                "powershell",
                Some(&format!("-Command \"Get-Service -Name '{service}' -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Status\"")),
            )
            .await;

            if !check_success || check_output.trim().is_empty() {
                continue;
            }

            let current_status = check_output.trim().to_string();
            let description = Self::service_description(service).unwrap_or("Unknown");

            if current_status.eq_ignore_ascii_case("Running") {
                let _ = command::execute("net", Some(&format!("stop \"{service}\""))).await;
            }

            let (disable_success, _o, disable_error) =
                command::execute("sc", Some(&format!("config \"{service}\" start= disabled"))).await;

            if disable_success {
                table.add_row([format!("[red]{service}[/]"), description.to_string(), "[green]Disabled[/]".to_string()]);
                fixes.push(format!("Disabled service: {service}"));
                disabled_count += 1;
            } else {
                table.add_row([format!("[yellow]{service}[/]"), description.to_string(), "[red]Failed[/]".to_string()]);
                issues.push(format!("Failed to disable {}: {}", service, disable_error.unwrap_or_default()));
            }
        }

        if disabled_count > 0 {
            table.print();
        }
        ui::markup_line(&format!(
            "[cyan]Disabled {disabled_count} services, skipped {skipped_count} protected services[/]"
        ));
    }

    async fn disable_insecure_features(fixes: &mut Vec<String>, _issues: &mut [String]) {
        ui::markup_line("[cyan]Disabling insecure Windows features...[/]");
        for feature in FEATURES_TO_DISABLE {
            let (success, _o, _e) = command::execute(
                "powershell",
                Some(&format!("-Command \"Disable-WindowsOptionalFeature -Online -FeatureName '{feature}' -NoRestart -ErrorAction SilentlyContinue\"")),
            )
            .await;
            if success {
                fixes.push(format!("Disabled feature: {feature}"));
                ui::markup_line(&format!("[green]? Disabled feature: {feature}[/]"));
            } else {
                ui::markup_line(&format!("[dim]Feature {feature} may not exist or already disabled[/]"));
            }
        }
        ui::markup_line("[cyan]Ensuring SMB1 is disabled...[/]");
        let _ = command::execute(
            "powershell",
            Some("-Command \"Set-SmbServerConfiguration -EnableSMB1Protocol $false -Force -ErrorAction SilentlyContinue\""),
        )
        .await;
    }
}

impl Default for ServiceManagementTask {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl Task for ServiceManagementTask {
    impl_task_meta!();

    async fn read_system_state(&mut self) -> SystemInfo {
        let mut system_info = SystemInfo::new();
        ui::markup_line("[cyan]Reading current service states...[/]");

        let (success, output, _e) = command::execute(
            "powershell",
            Some("-Command \"Get-Service | Select-Object Name, DisplayName, Status, StartType | ConvertTo-Csv -NoTypeInformation\""),
        )
        .await;

        if success && !output.is_empty() {
            for line in output.split(['\r', '\n']).filter(|l| !l.is_empty()).skip(1).take(20) {
                system_info.running_services.push(line.to_string());
            }
        }

        self.display_readme_service_requirements();
        system_info
    }

    async fn execute(&mut self) -> TaskResult {
        let mut result = TaskResult {
            task_name: self.name.clone(),
            success: true,
            message: "Service management completed".to_string(),
            ..Default::default()
        };

        let mut fixes: Vec<String> = Vec::new();
        let mut issues: Vec<String> = Vec::new();

        let (to_disable, to_enable, do_not_touch) = self.build_service_lists();

        if self.dry_run {
            ui::markup_line("[yellow]DRY RUN: Previewing service changes (no changes will be made)[/]");
            ui::markup_line(&format!("[cyan]Services to disable: {}[/]", to_disable.len()));
            ui::markup_line(&format!("[cyan]Services to enable: {}[/]", to_enable.len()));
            ui::markup_line(&format!("[cyan]Services protected: {}[/]", do_not_touch.len()));
            result.message = format!("DRY RUN: Would apply changes to {} services.", to_disable.len() + to_enable.len());
            return result;
        }

        ui::write_line();
        ui::rule("[bold yellow]Step 1: Protect Critical Services[/]");
        Self::protect_critical_services(&mut fixes, &mut issues).await;

        ui::write_line();
        ui::rule("[bold yellow]Step 2: Enable Required Services[/]");
        Self::enable_services(&to_enable, &mut fixes, &mut issues).await;

        ui::write_line();
        ui::rule("[bold yellow]Step 3: Disable Insecure Services[/]");
        Self::disable_services(&to_disable, &do_not_touch, &mut fixes, &mut issues).await;

        ui::write_line();
        ui::rule("[bold yellow]Step 4: Disable Windows Features[/]");
        Self::disable_insecure_features(&mut fixes, &mut issues).await;

        if !issues.is_empty() {
            result.message = format!("Applied {} service changes. {} issues encountered.", fixes.len(), issues.len());
            result.error_details = Some(issues.iter().take(10).cloned().collect::<Vec<_>>().join("\n"));
        } else {
            result.message = format!("Successfully applied {} service management changes.", fixes.len());
        }

        result
    }

    async fn verify(&mut self) -> bool {
        let mut all_good = true;
        let (to_disable, _to_enable, do_not_touch) = self.build_service_lists();

        for service in do_not_touch.iter() {
            let (success, output, _e) = command::execute(
                "powershell",
                Some(&format!("-Command \"(Get-Service -Name '{service}' -ErrorAction SilentlyContinue).Status\"")),
            )
            .await;
            if success && output.trim().eq_ignore_ascii_case("Running") {
                ui::markup_line(&format!("[green]? Critical service {service} is running[/]"));
            } else if success && !output.trim().is_empty() {
                ui::markup_line(&format!("[yellow]? Critical service {} is {}[/]", service, ui::escape(output.trim())));
            }
        }

        for service in to_disable.iter().take(5) {
            let (success, output, _e) = command::execute(
                "powershell",
                Some(&format!("-Command \"(Get-Service -Name '{service}' -ErrorAction SilentlyContinue).Status\"")),
            )
            .await;
            if success && output.trim().eq_ignore_ascii_case("Stopped") {
                ui::markup_line(&format!("[green]? Insecure service {service} is stopped[/]"));
            } else if success && !output.trim().is_empty() {
                ui::markup_line(&format!("[red]? Insecure service {} is still {}[/]", service, ui::escape(output.trim())));
                all_good = false;
            }
        }

        all_good
    }
}
