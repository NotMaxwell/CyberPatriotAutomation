//! Manage Windows services based on README requirements and security best practices.

use crate::knowledge::{FEATURES_TO_DISABLE, SERVICE_NAME_MAP};
use crate::service_ops::{self, ServiceState};
use async_trait::async_trait;
use pinnacle_core::Task;
use pinnacle_core::command;
use pinnacle_core::impl_task_meta;
use pinnacle_core::models::{ReadmeData, SystemInfo, TaskResult};
use pinnacle_core::ui;
use std::collections::HashSet;

/// Services that should generally be DISABLED for security: (service, description).
const SERVICES_TO_DISABLE: &[(&str, &str)] = &[
    ("TermService", "Remote Desktop Services"),
    ("SessionEnv", "Remote Desktop Configuration"),
    (
        "UmRdpService",
        "Remote Desktop Services UserMode Port Redirector",
    ),
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
    (
        "WMPNetworkSvc",
        "Windows Media Player Network Sharing Service",
    ),
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
        SERVICE_NAME_MAP
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
                ui::markup_line(&format!("  [green]✓ {}[/]", ui::escape(service)));
            }
            ui::write_line();
        }
        if !readme.prohibited_services.is_empty() {
            ui::markup_line("[bold red]README Services to Disable:[/]");
            for service in &readme.prohibited_services {
                ui::markup_line(&format!("  [red]✗ {}[/]", ui::escape(service)));
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

    /// Query every service's status in one call, keyed by lowercased name.
    ///
    /// The C# original spawned a separate PowerShell process per service, which
    /// is why it only ever sampled the first handful. One bulk query makes
    /// checking *all* of them cheap enough to be correct.
    async fn service_status_map() -> std::collections::HashMap<String, ServiceState> {
        service_ops::enumerate_states()
            .await
            .unwrap_or_default()
            .into_iter()
            .map(|(name, state)| (name.to_lowercase(), state))
            .collect()
    }

    /// Ensure every protected service is running.
    ///
    /// The C# original iterated only the first 10 of its hard-coded critical
    /// list, which meant services the README itself marked critical (CCS Client
    /// above all) were never started - the exact opposite of the intent. Protect
    /// the full `do_not_touch` set, which includes the README's own entries.
    async fn protect_critical_services(
        do_not_touch: &ServiceSet,
        fixes: &mut Vec<String>,
        issues: &mut Vec<String>,
    ) {
        ui::markup_line(&format!(
            "[cyan]Protecting {} critical services...[/]",
            do_not_touch.len()
        ));

        let statuses = Self::service_status_map().await;

        for service in do_not_touch.iter() {
            let Some(status) = statuses.get(&service.to_lowercase()) else {
                // Not installed on this image - nothing to protect.
                continue;
            };
            if *status == ServiceState::Running {
                ui::markup_line(&format!("[dim]? {service} is already running[/]"));
                continue;
            }

            ui::markup_line(&format!(
                "[yellow]Starting critical service: {service}...[/]"
            ));
            // A disabled service cannot be started until its start type is reset.
            let _ = service_ops::set_automatic(service).await;
            let start_error = service_ops::start(service).await.err();
            if start_error.is_none() {
                fixes.push(format!("Started critical service: {service}"));
                ui::markup_line(&format!("[green]✓ Started {service}[/]"));
            } else {
                let e = start_error.unwrap_or_default();
                issues.push(format!("Could not start critical service {service}: {e}"));
                ui::markup_line(&format!(
                    "[red]✗ Could not start {}: {}[/]",
                    service,
                    ui::escape(&e)
                ));
            }
        }
    }

    async fn enable_services(
        to_enable: &ServiceSet,
        fixes: &mut Vec<String>,
        issues: &mut Vec<String>,
    ) {
        if to_enable.len() == 0 {
            ui::markup_line("[green]✓ No additional services need to be enabled[/]");
            return;
        }
        for service in to_enable.iter() {
            ui::markup_line(&format!("[yellow]Enabling service: {service}...[/]"));
            let config_error = service_ops::set_automatic(service).await.err();
            if let Some(config_error) = config_error {
                issues.push(format!("Could not enable {service}: {config_error}"));
                ui::markup_line(&format!("[red]✗ Could not enable {service}[/]"));
                continue;
            }

            // The C# original discarded this result and reported success purely
            // on `sc config`, so a service set to auto-start but failing to
            // start was still counted as enabled.
            // service_ops::start treats "already running" as success, so the
            // string match the shell path needed is gone.
            let start_error = service_ops::start(service).await.err();

            if start_error.is_none() {
                fixes.push(format!("Enabled service: {service}"));
                ui::markup_line(&format!("[green]✓ Enabled {service}[/]"));
            } else {
                let e = start_error.unwrap_or_default();
                issues.push(format!(
                    "Set {service} to auto-start but could not start it: {e}"
                ));
                ui::markup_line(&format!(
                    "[yellow]⚠ {} set to auto-start but did not start: {}[/]",
                    service,
                    ui::escape(&e)
                ));
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
            .columns(&[
                "[bold]Service[/]",
                "[bold]Description[/]",
                "[bold]Status[/]",
            ]);

        let mut disabled_count = 0;
        let mut skipped_count = 0;

        for service in to_disable.iter() {
            if do_not_touch.contains(service) {
                skipped_count += 1;
                continue;
            }

            let state = service_ops::state(service).await;
            if state == service_ops::ServiceState::Absent {
                // Nothing installed to disable.
                continue;
            }

            let description = Self::service_description(service).unwrap_or("Unknown");

            if state == service_ops::ServiceState::Running {
                // Not `net stop`: when a service has dependents it asks "Do you
                // want to continue this operation? (Y/N)". Stdin is /dev/null
                // here so the prompt reaches EOF and `net` aborts rather than
                // hanging - but it aborts having stopped nothing, and the
                // failure is silent. `Stop-Service -Force` stops the dependents
                // too and never asks.
                if let Err(stop_error) = service_ops::stop(service).await {
                    // Not fatal: a service that will not stop can still be set to
                    // disabled so it does not come back after a reboot.
                    issues.push(format!("Could not stop {service}: {stop_error}"));
                }
            }

            let disable_error = service_ops::disable(service).await.err();

            if disable_error.is_none() {
                table.add_row([
                    format!("[red]{service}[/]"),
                    description.to_string(),
                    "[green]Disabled[/]".to_string(),
                ]);
                fixes.push(format!("Disabled service: {service}"));
                disabled_count += 1;
            } else {
                table.add_row([
                    format!("[yellow]{service}[/]"),
                    description.to_string(),
                    "[red]Failed[/]".to_string(),
                ]);
                issues.push(format!(
                    "Failed to disable {}: {}",
                    service,
                    disable_error.unwrap_or_default()
                ));
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
            let (success, _o, _e) = command::powershell(&format!(
                "Disable-WindowsOptionalFeature -Online -FeatureName {} -NoRestart",
                command::ps_quote(feature)
            ))
            .await;
            if success {
                fixes.push(format!("Disabled feature: {feature}"));
                ui::markup_line(&format!("[green]✓ Disabled feature: {feature}[/]"));
            } else {
                ui::markup_line(&format!(
                    "[dim]Feature {feature} may not exist or already disabled[/]"
                ));
            }
        }
        ui::markup_line("[cyan]Ensuring SMB1 is disabled...[/]");
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

        if let Some(services) = service_ops::enumerate_states().await {
            for (name, state) in services.into_iter().take(20) {
                system_info
                    .running_services
                    .push(format!("{name},{state:?}"));
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
            ui::markup_line(
                "[yellow]DRY RUN: Previewing service changes (no changes will be made)[/]",
            );
            ui::markup_line(&format!(
                "[cyan]Services to disable: {}[/]",
                to_disable.len()
            ));
            ui::markup_line(&format!("[cyan]Services to enable: {}[/]", to_enable.len()));
            ui::markup_line(&format!(
                "[cyan]Services protected: {}[/]",
                do_not_touch.len()
            ));
            result.message = format!(
                "DRY RUN: Would apply changes to {} services.",
                to_disable.len() + to_enable.len()
            );
            return result;
        }

        ui::write_line();
        ui::rule("[bold yellow]Step 1: Protect Critical Services[/]");
        Self::protect_critical_services(&do_not_touch, &mut fixes, &mut issues).await;

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
            result.message = format!(
                "Applied {} service changes. {} issues encountered.",
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
                "Successfully applied {} service management changes.",
                fixes.len()
            );
        }

        result
    }

    async fn verify(&mut self) -> bool {
        let mut all_good = true;
        let (to_disable, _to_enable, do_not_touch) = self.build_service_lists();

        // One bulk query instead of a process per service, so every service can
        // be checked. The C# original sampled only the first five of `toDisable`
        // and then reported that partial result as full verification.
        let statuses = Self::service_status_map().await;

        for service in do_not_touch.iter() {
            let Some(status) = statuses.get(&service.to_lowercase()) else {
                continue;
            };
            if *status == ServiceState::Running {
                ui::markup_line(&format!(
                    "[green]✓ Critical service {service} is running[/]"
                ));
            } else {
                // A critical service that is not running is a verification
                // failure: these are the services that must stay up.
                ui::markup_line(&format!(
                    "[red]✗ Critical service {service} is {status:?}[/]"
                ));
                all_good = false;
            }
        }

        for service in to_disable.iter() {
            let Some(status) = statuses.get(&service.to_lowercase()) else {
                continue;
            };
            if *status == ServiceState::Stopped {
                ui::markup_line(&format!(
                    "[green]✓ Insecure service {service} is stopped[/]"
                ));
            } else {
                ui::markup_line(&format!(
                    "[red]✗ Insecure service {service} is still {status:?}[/]"
                ));
                all_good = false;
            }
        }

        all_good
    }
}
