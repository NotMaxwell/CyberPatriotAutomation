using CyberPatriotAutomation.Core.Models;
using CyberPatriotAutomation.Core.Utilities;
using Spectre.Console;

namespace CyberPatriotAutomation.Core.Tasks;

/// <summary>
/// Task to manage Windows services based on README requirements and security best practices
/// Prioritizes README instructions, then applies general hardening rules
/// </summary>
public class ServiceManagementTask : BaseTask
{
    private ReadmeData? _readmeData;

    /// <summary>
    /// Services that should generally be DISABLED for security
    /// Based on CyberPatriot best practices and CIS benchmarks
    /// </summary>
    private static readonly Dictionary<string, string> ServicesToDisable =
        new(StringComparer.OrdinalIgnoreCase)
        {
            // Remote Access Services (High Risk)
            { "TermService", "Remote Desktop Services" },
            { "SessionEnv", "Remote Desktop Configuration" },
            { "UmRdpService", "Remote Desktop Services UserMode Port Redirector" },
            { "RemoteRegistry", "Remote Registry" },
            { "RemoteAccess", "Routing and Remote Access" },
            { "RasMan", "Remote Access Connection Manager" },
            { "RasAuto", "Remote Access Auto Connection Manager" },
            // Telnet/FTP Services (Insecure Protocols)
            { "TlntSvr", "Telnet" },
            { "ftpsvc", "FTP Publishing Service" },
            { "Msftpsvc", "Microsoft FTP Service (Legacy)" },
            // SNMP Services
            { "SNMP", "SNMP Service" },
            { "SNMPTRAP", "SNMP Trap" },
            // Network Discovery Services
            { "SSDPSRV", "SSDP Discovery" },
            { "upnphost", "UPnP Device Host" },
            // Sharing Services
            { "SharedAccess", "Internet Connection Sharing (ICS)" },
            { "HomeGroupProvider", "HomeGroup Provider" },
            { "HomeGroupListener", "HomeGroup Listener" },
            { "LanmanServer", "Server (File/Print Sharing)" },
            // Web Services (unless required)
            { "W3SVC", "World Wide Web Publishing Service" },
            { "IISADMIN", "IIS Admin Service" },
            { "WAS", "Windows Process Activation Service" },
            // Telephony Services
            { "TapiSrv", "Telephony" },
            // Messaging Services
            { "Messenger", "Messenger (Legacy)" },
            // Xbox Services (not needed in enterprise)
            { "XblAuthManager", "Xbox Live Auth Manager" },
            { "XblGameSave", "Xbox Live Game Save" },
            { "XboxGipSvc", "Xbox Accessory Management Service" },
            { "XboxNetApiSvc", "Xbox Live Networking Service" },
            // Other potentially risky services
            { "mnmsrvc", "NetMeeting Remote Desktop Sharing" },
            { "NetTcpPortSharing", "Net.Tcp Port Sharing Service" },
            { "simptcp", "Simple TCP/IP Services" },
            { "p2pimsvc", "Peer Networking Identity Manager" },
            { "p2psvc", "Peer Networking Grouping" },
            { "PNRPsvc", "Peer Name Resolution Protocol" },
            { "Fax", "Fax" },
            { "Smtpsvc", "Simple Mail Transfer Protocol (SMTP)" },
            { "IPRIP", "RIP Listener" },
            { "Dfs", "Distributed File System" },
            { "MSDTC", "Distributed Transaction Coordinator" },
            { "ERSvc", "Error Reporting Service" },
            { "WerSvc", "Windows Error Reporting Service" },
            { "helpsvc", "Help and Support" },
            { "seclogon", "Secondary Logon" },
            { "SENS", "System Event Notification Service" },
            { "SCardSvr", "Smart Card" },
            { "SCPolicySvc", "Smart Card Removal Policy" },
            { "TabletInputService", "Tablet PC Input Service" },
            { "WMPNetworkSvc", "Windows Media Player Network Sharing Service" },
            { "icssvc", "Windows Mobile Hotspot Service" },
            { "lfsvc", "Geolocation Service" },
            { "MapsBroker", "Downloaded Maps Manager" },
            { "PhoneSvc", "Phone Service" },
            { "WalletService", "Wallet Service" },
            { "RetailDemo", "Retail Demo Service" },
            { "DiagTrack", "Connected User Experiences and Telemetry" },
            { "dmwappushservice", "WAP Push Message Routing Service" },
        };

    /// <summary>
    /// Services that should generally REMAIN ENABLED for system functionality
    /// </summary>
    private static readonly Dictionary<string, string> CriticalServices =
        new(StringComparer.OrdinalIgnoreCase)
        {
            { "wuauserv", "Windows Update" },
            { "WinDefend", "Windows Defender Antivirus Service" },
            { "SecurityHealthService", "Windows Security Service" },
            { "wscsvc", "Security Center" },
            { "MpsSvc", "Windows Defender Firewall" },
            { "EventLog", "Windows Event Log" },
            { "Schedule", "Task Scheduler" },
            { "Winmgmt", "Windows Management Instrumentation" },
            { "CryptSvc", "Cryptographic Services" },
            { "DcomLaunch", "DCOM Server Process Launcher" },
            { "RpcSs", "Remote Procedure Call (RPC)" },
            { "RpcEptMapper", "RPC Endpoint Mapper" },
            { "Dhcp", "DHCP Client" },
            { "Dnscache", "DNS Client" },
            { "NlaSvc", "Network Location Awareness" },
            { "nsi", "Network Store Interface Service" },
            { "BFE", "Base Filtering Engine" },
            { "BITS", "Background Intelligent Transfer Service" },
            { "TrustedInstaller", "Windows Modules Installer" },
            { "Spooler", "Print Spooler" }, // May be needed - check README
        };

    public ServiceManagementTask()
    {
        Name = "Service Management";
        Description = "Enable/disable Windows services based on README and security best practices";
    }

    /// <summary>
    /// Set the README data for this task
    /// </summary>
    public void SetReadmeData(ReadmeData data)
    {
        _readmeData = data;
    }

    public override async Task<SystemInfo> ReadSystemStateAsync()
    {
        var systemInfo = new SystemInfo();

        AnsiConsole.MarkupLine("[cyan]Reading current service states...[/]");

        // Get all services
        var (success, output, _) = await CommandExecutor.ExecuteAsync(
            "powershell",
            "-Command \"Get-Service | Select-Object Name, DisplayName, Status, StartType | ConvertTo-Csv -NoTypeInformation\""
        );

        if (success && !string.IsNullOrEmpty(output))
        {
            var lines = output.Split(new[] { '\r', '\n' }, StringSplitOptions.RemoveEmptyEntries);
            foreach (var line in lines.Skip(1).Take(20)) // Show first 20 services
            {
                systemInfo.RunningServices.Add(line);
            }
        }

        // Display README service requirements
        DisplayReadmeServiceRequirements();

        return systemInfo;
    }

    public override async Task<TaskResult> ExecuteAsync()
    {
        var result = new TaskResult
        {
            TaskName = Name,
            Success = true,
            Message = "Service management completed",
        };

        var fixes = new List<string>();
        var issues = new List<string>();

        try
        {
            // Build service management lists based on README + defaults
            var (toDisable, toEnable, doNotTouch) = BuildServiceLists();

            if (DryRun)
            {
                AnsiConsole.MarkupLine(
                    "[yellow]DRY RUN: Previewing service changes (no changes will be made)[/]"
                );
                AnsiConsole.MarkupLine($"[cyan]Services to disable: {toDisable.Count}[/]");
                AnsiConsole.MarkupLine($"[cyan]Services to enable: {toEnable.Count}[/]");
                AnsiConsole.MarkupLine($"[cyan]Services protected: {doNotTouch.Count}[/]");
                result.Message =
                    $"DRY RUN: Would apply changes to {toDisable.Count + toEnable.Count} services.";
                return result;
            }

            AnsiConsole.WriteLine();
            AnsiConsole.Write(
                new Rule("[bold yellow]Step 1: Protect Critical Services[/]").RuleStyle("yellow")
            );
            await ProtectCriticalServicesAsync(doNotTouch, fixes, issues);

            AnsiConsole.WriteLine();
            AnsiConsole.Write(
                new Rule("[bold yellow]Step 2: Enable Required Services[/]").RuleStyle("yellow")
            );
            await EnableServicesAsync(toEnable, fixes, issues);

            AnsiConsole.WriteLine();
            AnsiConsole.Write(
                new Rule("[bold yellow]Step 3: Disable Insecure Services[/]").RuleStyle("yellow")
            );
            await DisableServicesAsync(toDisable, doNotTouch, fixes, issues);

            AnsiConsole.WriteLine();
            AnsiConsole.Write(
                new Rule("[bold yellow]Step 4: Disable Windows Features[/]").RuleStyle("yellow")
            );
            await DisableInsecureFeaturesAsync(fixes, issues);

            // Summary
            if (issues.Count > 0)
            {
                result.Message =
                    $"Applied {fixes.Count} service changes. {issues.Count} issues encountered.";
                result.ErrorDetails = string.Join("\n", issues.Take(10));
            }
            else
            {
                result.Message = $"Successfully applied {fixes.Count} service management changes.";
            }
        }
        catch (Exception ex)
        {
            result.Success = false;
            result.Message = "Failed to complete service management";
            result.ErrorDetails = ex.Message;
            AnsiConsole.WriteException(ex);
        }

        return result;
    }

    public override async Task<bool> VerifyAsync()
    {
        bool allGood = true;
        var (toDisable, _, doNotTouch) = BuildServiceLists();

        // Verify critical services are running
        foreach (var service in doNotTouch)
        {
            var (success, output, _) = await CommandExecutor.ExecuteAsync(
                "powershell",
                $"-Command \"(Get-Service -Name '{service}' -ErrorAction SilentlyContinue).Status\""
            );

            if (success && output.Trim().Equals("Running", StringComparison.OrdinalIgnoreCase))
            {
                AnsiConsole.MarkupLine($"[green]? Critical service {service} is running[/]");
            }
            else if (success && !string.IsNullOrEmpty(output.Trim()))
            {
                AnsiConsole.MarkupLine(
                    $"[yellow]? Critical service {service} is {output.Trim()}[/]"
                );
            }
        }

        // Verify insecure services are disabled (sample check)
        var checkServices = toDisable.Take(5).ToList();
        foreach (var service in checkServices)
        {
            var (success, output, _) = await CommandExecutor.ExecuteAsync(
                "powershell",
                $"-Command \"(Get-Service -Name '{service}' -ErrorAction SilentlyContinue).Status\""
            );

            if (success && output.Trim().Equals("Stopped", StringComparison.OrdinalIgnoreCase))
            {
                AnsiConsole.MarkupLine($"[green]? Insecure service {service} is stopped[/]");
            }
            else if (success && !string.IsNullOrEmpty(output.Trim()))
            {
                AnsiConsole.MarkupLine(
                    $"[red]? Insecure service {service} is still {output.Trim()}[/]"
                );
                allGood = false;
            }
        }

        return allGood;
    }

    #region Helper Methods

    private void DisplayReadmeServiceRequirements()
    {
        if (_readmeData == null)
            return;

        if (_readmeData.CriticalServices.Count > 0)
        {
            AnsiConsole.MarkupLine("[bold green]README Critical Services (Do NOT disable):[/]");
            foreach (var service in _readmeData.CriticalServices)
            {
                AnsiConsole.MarkupLine($"  [green]? {service}[/]");
            }
            AnsiConsole.WriteLine();
        }

        if (_readmeData.ProhibitedServices.Count > 0)
        {
            AnsiConsole.MarkupLine("[bold red]README Services to Disable:[/]");
            foreach (var service in _readmeData.ProhibitedServices)
            {
                AnsiConsole.MarkupLine($"  [red]? {service}[/]");
            }
            AnsiConsole.WriteLine();
        }
    }

    private (
        HashSet<string> ToDisable,
        HashSet<string> ToEnable,
        HashSet<string> DoNotTouch
    ) BuildServiceLists()
    {
        var toDisable = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var toEnable = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var doNotTouch = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

        // Start with default critical services that should not be touched
        foreach (var service in CriticalServices.Keys)
        {
            doNotTouch.Add(service);
        }

        // Add README critical services to do-not-touch list
        if (_readmeData != null)
        {
            foreach (var service in _readmeData.CriticalServices)
            {
                // Try to map display name to service name
                var serviceName = MapServiceName(service);
                doNotTouch.Add(serviceName);
                toEnable.Add(serviceName); // Ensure they're enabled
            }
        }

        // Build disable list from defaults
        foreach (var service in ServicesToDisable.Keys)
        {
            if (!doNotTouch.Contains(service))
            {
                toDisable.Add(service);
            }
        }

        // Add README prohibited services to disable list
        if (_readmeData != null)
        {
            foreach (var service in _readmeData.ProhibitedServices)
            {
                var serviceName = MapServiceName(service);
                if (!doNotTouch.Contains(serviceName))
                {
                    toDisable.Add(serviceName);
                }
            }
        }

        return (toDisable, toEnable, doNotTouch);
    }

    /// <summary>
    /// Map common service display names to actual service names
    /// </summary>
    private string MapServiceName(string displayName)
    {
        var mappings = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
        {
            { "CCS Client", "CCSClient" },
            { "Remote Desktop", "TermService" },
            { "Remote Desktop Services", "TermService" },
            { "RDP", "TermService" },
            { "FTP", "ftpsvc" },
            { "Telnet", "TlntSvr" },
            { "SSH", "sshd" },
            { "OpenSSH", "sshd" },
            { "OpenSSH SSH Server", "sshd" },
            { "Remote Registry", "RemoteRegistry" },
            { "Windows Update", "wuauserv" },
            { "Windows Defender", "WinDefend" },
            { "Windows Firewall", "MpsSvc" },
            { "Print Spooler", "Spooler" },
            { "ICS", "SharedAccess" },
            { "Internet Connection Sharing", "SharedAccess" },
        };

        return mappings.TryGetValue(displayName, out var serviceName) ? serviceName : displayName;
    }

    private async Task ProtectCriticalServicesAsync(
        HashSet<string> doNotTouch,
        List<string> fixes,
        List<string> issues
    )
    {
        AnsiConsole.MarkupLine($"[cyan]Protecting {doNotTouch.Count} critical services...[/]");

        foreach (var service in CriticalServices.Keys.Take(10)) // Check top 10 critical services
        {
            var (success, output, _) = await CommandExecutor.ExecuteAsync(
                "powershell",
                $"-Command \"(Get-Service -Name '{service}' -ErrorAction SilentlyContinue).Status\""
            );

            if (success && !string.IsNullOrEmpty(output.Trim()))
            {
                if (!output.Trim().Equals("Running", StringComparison.OrdinalIgnoreCase))
                {
                    // Try to start the service
                    AnsiConsole.MarkupLine($"[yellow]Starting critical service: {service}...[/]");
                    var (startSuccess, _, startError) = await CommandExecutor.ExecuteAsync(
                        "net",
                        $"start \"{service}\""
                    );

                    if (startSuccess)
                    {
                        fixes.Add($"Started critical service: {service}");
                        AnsiConsole.MarkupLine($"[green]? Started {service}[/]");
                    }
                    else
                    {
                        AnsiConsole.MarkupLine($"[dim]Could not start {service}: {startError}[/]");
                    }
                }
                else
                {
                    AnsiConsole.MarkupLine($"[dim]? {service} is already running[/]");
                }
            }
        }
    }

    private async Task EnableServicesAsync(
        HashSet<string> toEnable,
        List<string> fixes,
        List<string> issues
    )
    {
        if (toEnable.Count == 0)
        {
            AnsiConsole.MarkupLine("[green]? No additional services need to be enabled[/]");
            return;
        }

        foreach (var service in toEnable)
        {
            AnsiConsole.MarkupLine($"[yellow]Enabling service: {service}...[/]");

            // Set to automatic start
            var (configSuccess, _, configError) = await CommandExecutor.ExecuteAsync(
                "sc",
                $"config \"{service}\" start= auto"
            );

            // Start the service
            var (startSuccess, _, _) = await CommandExecutor.ExecuteAsync(
                "net",
                $"start \"{service}\""
            );

            if (configSuccess)
            {
                fixes.Add($"Enabled service: {service}");
                AnsiConsole.MarkupLine($"[green]? Enabled {service}[/]");
            }
            else
            {
                issues.Add($"Could not enable {service}: {configError}");
            }
        }
    }

    private async Task DisableServicesAsync(
        HashSet<string> toDisable,
        HashSet<string> doNotTouch,
        List<string> fixes,
        List<string> issues
    )
    {
        var disableTable = new Table()
            .Border(TableBorder.Rounded)
            .BorderColor(Color.Red)
            .Title("[bold red]Services to Disable[/]")
            .AddColumn("[bold]Service[/]")
            .AddColumn("[bold]Description[/]")
            .AddColumn("[bold]Status[/]");

        int disabledCount = 0;
        int skippedCount = 0;

        foreach (var service in toDisable)
        {
            // Double-check it's not a protected service
            if (doNotTouch.Contains(service))
            {
                skippedCount++;
                continue;
            }

            // Check if service exists
            var (checkSuccess, checkOutput, _) = await CommandExecutor.ExecuteAsync(
                "powershell",
                $"-Command \"Get-Service -Name '{service}' -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Status\""
            );

            if (!checkSuccess || string.IsNullOrEmpty(checkOutput.Trim()))
            {
                // Service doesn't exist, skip
                continue;
            }

            var currentStatus = checkOutput.Trim();
            var description = ServicesToDisable.TryGetValue(service, out var desc)
                ? desc
                : "Unknown";

            // Stop the service
            if (currentStatus.Equals("Running", StringComparison.OrdinalIgnoreCase))
            {
                var (stopSuccess, _, _) = await CommandExecutor.ExecuteAsync(
                    "net",
                    $"stop \"{service}\""
                );
            }

            // Disable the service
            var (disableSuccess, _, disableError) = await CommandExecutor.ExecuteAsync(
                "sc",
                $"config \"{service}\" start= disabled"
            );

            if (disableSuccess)
            {
                disableTable.AddRow($"[red]{service}[/]", description, "[green]Disabled[/]");
                fixes.Add($"Disabled service: {service}");
                disabledCount++;
            }
            else
            {
                disableTable.AddRow($"[yellow]{service}[/]", description, $"[red]Failed[/]");
                issues.Add($"Failed to disable {service}: {disableError}");
            }
        }

        if (disabledCount > 0)
        {
            AnsiConsole.Write(disableTable);
        }

        AnsiConsole.MarkupLine(
            $"[cyan]Disabled {disabledCount} services, skipped {skippedCount} protected services[/]"
        );
    }

    private async Task DisableInsecureFeaturesAsync(List<string> fixes, List<string> issues)
    {
        AnsiConsole.MarkupLine("[cyan]Disabling insecure Windows features...[/]");

        var featuresToDisable = new[]
        {
            "TelnetClient",
            "TelnetServer",
            "TFTP",
            "SMB1Protocol",
            "SMB1Protocol-Client",
            "SMB1Protocol-Server",
        };

        foreach (var feature in featuresToDisable)
        {
            var (success, _, error) = await CommandExecutor.ExecuteAsync(
                "powershell",
                $"-Command \"Disable-WindowsOptionalFeature -Online -FeatureName '{feature}' -NoRestart -ErrorAction SilentlyContinue\""
            );

            if (success)
            {
                fixes.Add($"Disabled feature: {feature}");
                AnsiConsole.MarkupLine($"[green]? Disabled feature: {feature}[/]");
            }
            else
            {
                AnsiConsole.MarkupLine(
                    $"[dim]Feature {feature} may not exist or already disabled[/]"
                );
            }
        }

        // Disable SMB1 via PowerShell
        AnsiConsole.MarkupLine("[cyan]Ensuring SMB1 is disabled...[/]");
        await CommandExecutor.ExecuteAsync(
            "powershell",
            "-Command \"Set-SmbServerConfiguration -EnableSMB1Protocol $false -Force -ErrorAction SilentlyContinue\""
        );
    }

    #endregion
}
