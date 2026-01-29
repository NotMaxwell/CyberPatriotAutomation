using CyberPatriotAutomation.Core.Models;
using CyberPatriotAutomation.Core.Utilities;
using Spectre.Console;

namespace CyberPatriotAutomation.Core.Tasks;

/// <summary>
/// Task to configure Windows Firewall and block insecure ports
/// Based on CyberPatriot best practices
/// </summary>
public class FirewallConfigurationTask : BaseTask
{
    /// <summary>
    /// Ports that should be blocked for security
    /// </summary>
    private static readonly (int Port, string Protocol, string Description)[] PortsToBlock = new[]
    {
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
    };

    /// <summary>
    /// Firewall rules to disable
    /// </summary>
    private static readonly string[] RulesToDisable = new[]
    {
        "Remote Assistance (DCOM-In)",
        "Remote Assistance (PNRP-In)",
        "Remote Assistance (RA Server TCP-In)",
        "Remote Assistance (SSDP TCP-In)",
        "Remote Assistance (SSDP UDP-In)",
        "Remote Assistance (TCP-In)",
        "Telnet Server",
        "netcat",
    };

    /// <summary>
    /// Firewall rule groups to disable
    /// </summary>
    private static readonly string[] RuleGroupsToDisable = new[]
    {
        "Network Discovery",
        "File and Printer Sharing",
        "Remote Desktop",
        "Remote Assistance",
        "Remote Event Log Management",
        "Remote Service Management",
        "Remote Volume Management",
        "Windows Remote Management",
    };

    public FirewallConfigurationTask()
    {
        Name = "Firewall Configuration";
        Description = "Enable Windows Firewall and block insecure ports";
    }

    public override async Task<SystemInfo> ReadSystemStateAsync()
    {
        var systemInfo = new SystemInfo();

        AnsiConsole.MarkupLine("[cyan]Reading firewall configuration...[/]");

        // Check firewall status for each profile
        var profiles = new[] { "Domain", "Private", "Public" };
        foreach (var profile in profiles)
        {
            var (success, output, _) = await CommandExecutor.ExecuteAsync(
                "powershell",
                $"-Command \"(Get-NetFirewallProfile -Name '{profile}').Enabled\""
            );

            var enabled =
                success && output.Trim().Equals("True", StringComparison.OrdinalIgnoreCase);
            AnsiConsole.MarkupLine(
                $"  {profile} Profile: {(enabled ? "[green]Enabled[/]" : "[red]Disabled[/]")}"
            );
        }

        return systemInfo;
    }

    public override async Task<TaskResult> ExecuteAsync()
    {
        var result = new TaskResult
        {
            TaskName = Name,
            Success = true,
            Message = "Firewall configuration completed",
        };

        var fixes = new List<string>();
        var issues = new List<string>();

        try
        {
            if (DryRun)
            {
                AnsiConsole.MarkupLine(
                    "[yellow]DRY RUN: Previewing firewall changes (no changes will be made)[/]"
                );
                result.Message = "DRY RUN: Firewall configuration changes previewed.";
                return result;
            }

            AnsiConsole.WriteLine();
            AnsiConsole.Write(
                new Rule("[bold yellow]Step 1: Enable Firewall Profiles[/]").RuleStyle("yellow")
            );
            await EnableFirewallProfilesAsync(fixes, issues);

            AnsiConsole.WriteLine();
            AnsiConsole.Write(
                new Rule("[bold yellow]Step 2: Configure Default Actions[/]").RuleStyle("yellow")
            );
            await ConfigureDefaultActionsAsync(fixes, issues);

            AnsiConsole.WriteLine();
            AnsiConsole.Write(
                new Rule("[bold yellow]Step 3: Block Insecure Ports[/]").RuleStyle("yellow")
            );
            await BlockInsecurePortsAsync(fixes, issues);

            AnsiConsole.WriteLine();
            AnsiConsole.Write(
                new Rule("[bold yellow]Step 4: Disable Risky Firewall Rules[/]").RuleStyle("yellow")
            );
            await DisableRiskyRulesAsync(fixes, issues);

            AnsiConsole.WriteLine();
            AnsiConsole.Write(
                new Rule("[bold yellow]Step 5: Configure Firewall Logging[/]").RuleStyle("yellow")
            );
            await ConfigureFirewallLoggingAsync(fixes, issues);

            // Summary
            if (issues.Count > 0)
            {
                result.Message =
                    $"Applied {fixes.Count} firewall changes. {issues.Count} issues encountered.";
                result.ErrorDetails = string.Join("\n", issues.Take(10));
            }
            else
            {
                result.Message =
                    $"Successfully applied {fixes.Count} firewall configuration changes.";
            }
        }
        catch (Exception ex)
        {
            result.Success = false;
            result.Message = "Failed to configure firewall";
            result.ErrorDetails = ex.Message;
            AnsiConsole.WriteException(ex);
        }

        return result;
    }

    public override async Task<bool> VerifyAsync()
    {
        bool allGood = true;

        // Check firewall is enabled on all profiles
        var profiles = new[] { "Domain", "Private", "Public" };
        foreach (var profile in profiles)
        {
            var (success, output, _) = await CommandExecutor.ExecuteAsync(
                "powershell",
                $"-Command \"(Get-NetFirewallProfile -Name '{profile}').Enabled\""
            );

            var enabled =
                success && output.Trim().Equals("True", StringComparison.OrdinalIgnoreCase);
            if (enabled)
            {
                AnsiConsole.MarkupLine($"[green]? {profile} firewall profile is enabled[/]");
            }
            else
            {
                AnsiConsole.MarkupLine($"[red]? {profile} firewall profile is disabled[/]");
                allGood = false;
            }
        }

        return allGood;
    }

    #region Helper Methods

    private async Task EnableFirewallProfilesAsync(List<string> fixes, List<string> issues)
    {
        AnsiConsole.MarkupLine("[cyan]Enabling firewall for all profiles...[/]");

        var (success, _, error) = await CommandExecutor.ExecuteAsync(
            "powershell",
            "-Command \"Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled True\""
        );

        if (success)
        {
            fixes.Add("Enabled firewall for Domain, Public, and Private profiles");
            AnsiConsole.MarkupLine("[green]? Firewall enabled for all profiles[/]");
        }
        else
        {
            issues.Add($"Failed to enable firewall profiles: {error}");
            AnsiConsole.MarkupLine("[red]? Failed to enable firewall profiles[/]");
        }
    }

    private async Task ConfigureDefaultActionsAsync(List<string> fixes, List<string> issues)
    {
        AnsiConsole.MarkupLine("[cyan]Configuring default firewall actions...[/]");

        // Block inbound by default, allow outbound
        var (success, _, error) = await CommandExecutor.ExecuteAsync(
            "powershell",
            "-Command \"Set-NetFirewallProfile -Profile Domain,Public,Private -DefaultInboundAction Block -DefaultOutboundAction Allow -NotifyOnListen True -AllowUnicastResponseToMulticast True\""
        );

        if (success)
        {
            fixes.Add("Configured default firewall actions (Block inbound, Allow outbound)");
            AnsiConsole.MarkupLine("[green]? Default actions configured[/]");
        }
        else
        {
            issues.Add($"Failed to configure default actions: {error}");
        }

        // Set network to Public profile for maximum security
        var (profileSuccess, _, profileError) = await CommandExecutor.ExecuteAsync(
            "powershell",
            "-Command \"Set-NetConnectionProfile -NetworkCategory Public -ErrorAction SilentlyContinue\""
        );

        if (profileSuccess)
        {
            fixes.Add("Set network profile to Public");
            AnsiConsole.MarkupLine("[green]? Network profile set to Public[/]");
        }
    }

    private async Task BlockInsecurePortsAsync(List<string> fixes, List<string> issues)
    {
        var table = new Table()
            .Border(TableBorder.Rounded)
            .BorderColor(Color.Red)
            .Title("[bold]Blocking Insecure Ports[/]")
            .AddColumn("[bold]Port[/]")
            .AddColumn("[bold]Protocol[/]")
            .AddColumn("[bold]Description[/]")
            .AddColumn("[bold]Status[/]");

        foreach (var (port, protocol, description) in PortsToBlock)
        {
            var ruleName = $"CyberPatriot_Block_{description.Replace(" ", "")}_{protocol}_{port}";

            // Create inbound rule
            var (success, _, _) = await CommandExecutor.ExecuteAsync(
                "powershell",
                $"-Command \"New-NetFirewallRule -DisplayName '{ruleName}' -Direction Inbound -LocalPort {port} -Protocol {protocol} -Action Block -ErrorAction SilentlyContinue\""
            );

            if (success)
            {
                table.AddRow(port.ToString(), protocol, description, "[green]Blocked[/]");
                fixes.Add($"Blocked port {port}/{protocol} ({description})");
            }
            else
            {
                // Rule might already exist, try enabling it
                await CommandExecutor.ExecuteAsync(
                    "powershell",
                    $"-Command \"Set-NetFirewallRule -DisplayName '{ruleName}' -Enabled True -ErrorAction SilentlyContinue\""
                );
                table.AddRow(port.ToString(), protocol, description, "[yellow]Exists[/]");
            }
        }

        AnsiConsole.Write(table);
    }

    private async Task DisableRiskyRulesAsync(List<string> fixes, List<string> issues)
    {
        AnsiConsole.MarkupLine("[cyan]Disabling risky firewall rules...[/]");

        // Disable specific rules
        foreach (var rule in RulesToDisable)
        {
            var (success, _, _) = await CommandExecutor.ExecuteAsync(
                "netsh",
                $"advfirewall firewall set rule name=\"{rule}\" new enable=no"
            );

            if (success)
            {
                fixes.Add($"Disabled rule: {rule}");
                AnsiConsole.MarkupLine($"[green]? Disabled: {rule}[/]");
            }
        }

        // Disable rule groups
        foreach (var group in RuleGroupsToDisable)
        {
            var (success, _, _) = await CommandExecutor.ExecuteAsync(
                "netsh",
                $"advfirewall firewall set rule group=\"{group}\" new enable=No"
            );

            if (success)
            {
                fixes.Add($"Disabled rule group: {group}");
                AnsiConsole.MarkupLine($"[green]? Disabled group: {group}[/]");
            }
        }

        // Block Remote Registry service via firewall
        await CommandExecutor.ExecuteAsync(
            "netsh",
            "advfirewall firewall add rule name=\"Block_RemoteRegistry_In\" dir=in service=\"RemoteRegistry\" action=block enable=yes"
        );
        await CommandExecutor.ExecuteAsync(
            "netsh",
            "advfirewall firewall add rule name=\"Block_RemoteRegistry_Out\" dir=out service=\"RemoteRegistry\" action=block enable=yes"
        );

        fixes.Add("Blocked Remote Registry service in firewall");
    }

    private async Task ConfigureFirewallLoggingAsync(List<string> fixes, List<string> issues)
    {
        AnsiConsole.MarkupLine("[cyan]Configuring firewall logging...[/]");

        var logPath = @"%SystemRoot%\System32\LogFiles\Firewall\pfirewall.log";

        var (success, _, error) = await CommandExecutor.ExecuteAsync(
            "powershell",
            $"-Command \"Set-NetFirewallProfile -Profile Domain,Public,Private -LogFileName '{logPath}' -LogBlocked True -LogAllowed False -LogMaxSizeKilobytes 32767\""
        );

        if (success)
        {
            fixes.Add("Configured firewall logging");
            AnsiConsole.MarkupLine("[green]? Firewall logging configured[/]");
        }
        else
        {
            // Try alternative method
            await CommandExecutor.ExecuteAsync(
                "netsh",
                $"advfirewall set allprofiles logging filename {logPath}"
            );
            await CommandExecutor.ExecuteAsync(
                "netsh",
                "advfirewall set allprofiles logging droppedconnections enable"
            );
            await CommandExecutor.ExecuteAsync(
                "netsh",
                "advfirewall set allprofiles logging maxfilesize 32767"
            );

            fixes.Add("Configured firewall logging (via netsh)");
            AnsiConsole.MarkupLine("[green]? Firewall logging configured via netsh[/]");
        }
    }

    #endregion
}
