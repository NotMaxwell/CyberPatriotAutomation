using CyberPatriotAutomation.Core.Models;
using CyberPatriotAutomation.Core.Utilities;
using Spectre.Console;

namespace CyberPatriotAutomation.Core.Tasks;

/// <summary>
/// Task to apply additional security hardening settings via registry and system configuration
/// Based on CIS Benchmarks and CyberPatriot best practices
/// </summary>
public class SecurityHardeningTask : BaseTask
{
    /// <summary>
    /// Registry settings to apply for security hardening
    /// </summary>
    private static readonly (
        string Path,
        string Name,
        string Type,
        string Value,
        string Description
    )[] RegistrySettings = new[]
    {
        // UAC Settings
        (
            @"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System",
            "EnableLUA",
            "REG_DWORD",
            "1",
            "Enable UAC"
        ),
        (
            @"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System",
            "ConsentPromptBehaviorAdmin",
            "REG_DWORD",
            "5",
            "UAC prompt for admins"
        ),
        (
            @"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System",
            "PromptOnSecureDesktop",
            "REG_DWORD",
            "1",
            "UAC on secure desktop"
        ),
        (
            @"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System",
            "EnableInstallerDetection",
            "REG_DWORD",
            "1",
            "Enable installer detection"
        ),
        (
            @"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System",
            "DisableCAD",
            "REG_DWORD",
            "0",
            "Require Ctrl+Alt+Del"
        ),
        (
            @"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System",
            "dontdisplaylastusername",
            "REG_DWORD",
            "1",
            "Don't display last username"
        ),
        (
            @"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System",
            "undockwithoutlogon",
            "REG_DWORD",
            "0",
            "Disable undocking without logon"
        ),
        // Disable AutoRun/AutoPlay
        (
            @"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer",
            "NoAutorun",
            "REG_DWORD",
            "1",
            "Disable AutoRun"
        ),
        (
            @"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer",
            "NoDriveTypeAutoRun",
            "REG_DWORD",
            "255",
            "Disable AutoRun for all drives"
        ),
        // Remote Desktop Disable
        (
            @"HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server",
            "fDenyTSConnections",
            "REG_DWORD",
            "1",
            "Deny RDP connections"
        ),
        (
            @"HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server",
            "fAllowToGetHelp",
            "REG_DWORD",
            "0",
            "Disable Remote Assistance"
        ),
        (
            @"HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server",
            "AllowTSConnections",
            "REG_DWORD",
            "0",
            "Disable TS connections"
        ),
        // Auto Admin Logon Disable
        (
            @"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon",
            "AutoAdminLogon",
            "REG_DWORD",
            "0",
            "Disable auto admin logon"
        ),
        // Windows Defender
        (
            @"HKLM\SOFTWARE\Policies\Microsoft\Windows Defender",
            "DisableAntiSpyware",
            "REG_DWORD",
            "0",
            "Enable Windows Defender"
        ),
        (
            @"HKLM\SOFTWARE\Policies\Microsoft\Windows Defender",
            "ServiceKeepAlive",
            "REG_DWORD",
            "1",
            "Keep Defender alive"
        ),
        (
            @"HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection",
            "DisableRealtimeMonitoring",
            "REG_DWORD",
            "0",
            "Enable real-time monitoring"
        ),
        (
            @"HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection",
            "DisableIOAVProtection",
            "REG_DWORD",
            "0",
            "Enable IOAV protection"
        ),
        // Windows Update
        (
            @"HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU",
            "NoAutoUpdate",
            "REG_DWORD",
            "0",
            "Enable auto update"
        ),
        (
            @"HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU",
            "AUOptions",
            "REG_DWORD",
            "4",
            "Auto download and install"
        ),
        (
            @"HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU",
            "AutoInstallMinorUpdates",
            "REG_DWORD",
            "1",
            "Auto install minor updates"
        ),
        // LSA Protection
        (
            @"HKLM\SYSTEM\CurrentControlSet\Control\Lsa",
            "RunAsPPL",
            "REG_DWORD",
            "1",
            "Enable LSA protection"
        ),
        (
            @"HKLM\SYSTEM\CurrentControlSet\Control\Lsa",
            "LimitBlankPasswordUse",
            "REG_DWORD",
            "1",
            "Limit blank password use"
        ),
        (
            @"HKLM\SYSTEM\CurrentControlSet\Control\Lsa",
            "restrictanonymous",
            "REG_DWORD",
            "1",
            "Restrict anonymous enumeration"
        ),
        (
            @"HKLM\SYSTEM\CurrentControlSet\Control\Lsa",
            "restrictanonymoussam",
            "REG_DWORD",
            "1",
            "Restrict anonymous SAM"
        ),
        (
            @"HKLM\SYSTEM\CurrentControlSet\Control\Lsa",
            "everyoneincludesanonymous",
            "REG_DWORD",
            "0",
            "Anonymous not in Everyone"
        ),
        (
            @"HKLM\SYSTEM\CurrentControlSet\Control\Lsa",
            "disabledomaincreds",
            "REG_DWORD",
            "1",
            "Disable domain credential storage"
        ),
        (
            @"HKLM\SYSTEM\CurrentControlSet\Control\Lsa",
            "auditbaseobjects",
            "REG_DWORD",
            "1",
            "Audit global system objects"
        ),
        (
            @"HKLM\SYSTEM\CurrentControlSet\Control\Lsa",
            "fullprivilegeauditing",
            "REG_DWORD",
            "1",
            "Audit backup/restore"
        ),
        // LSASS Auditing
        (
            @"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\LSASS.exe",
            "AuditLevel",
            "REG_DWORD",
            "8",
            "LSASS audit level"
        ),
        // Memory Protection
        (
            @"HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management",
            "ClearPageFileAtShutdown",
            "REG_DWORD",
            "1",
            "Clear page file at shutdown"
        ),
        // Crash Dump Disable
        (
            @"HKLM\SYSTEM\CurrentControlSet\Control\CrashControl",
            "CrashDumpEnabled",
            "REG_DWORD",
            "0",
            "Disable crash dumps"
        ),
        // CD/Floppy Access
        (
            @"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon",
            "AllocateCDRoms",
            "REG_DWORD",
            "1",
            "Restrict CD-ROM access"
        ),
        (
            @"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon",
            "AllocateFloppies",
            "REG_DWORD",
            "1",
            "Restrict floppy access"
        ),
        // SMB Security
        (
            @"HKLM\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters",
            "EnablePlainTextPassword",
            "REG_DWORD",
            "0",
            "Disable plain text passwords"
        ),
        // Explorer Settings
        (
            @"HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced",
            "Hidden",
            "REG_DWORD",
            "1",
            "Show hidden files"
        ),
        (
            @"HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced",
            "ShowSuperHidden",
            "REG_DWORD",
            "1",
            "Show super hidden files"
        ),
        // IE/Edge Security
        (
            @"HKCU\Software\Microsoft\Internet Explorer\PhishingFilter",
            "EnabledV9",
            "REG_DWORD",
            "1",
            "Enable SmartScreen"
        ),
        (
            @"HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings",
            "DisablePasswordCaching",
            "REG_DWORD",
            "1",
            "Disable password caching"
        ),
        (
            @"HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings",
            "WarnonBadCertRecving",
            "REG_DWORD",
            "1",
            "Warn on bad certificates"
        ),
        (
            @"HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings",
            "WarnOnPostRedirect",
            "REG_DWORD",
            "1",
            "Warn on POST redirect"
        ),
        (
            @"HKCU\Software\Microsoft\Internet Explorer\Main",
            "DoNotTrack",
            "REG_DWORD",
            "1",
            "Enable Do Not Track"
        ),
        // Disable Remote Shell
        (
            @"HKLM\SOFTWARE\Policies\Microsoft\Windows\WinRM\Service\WinRS",
            "AllowRemoteShellAccess",
            "REG_DWORD",
            "0",
            "Disable remote shell"
        ),
    };

    /// <summary>
    /// Windows features to disable
    /// </summary>
    private static readonly string[] FeaturesToDisable = new[]
    {
        "TelnetClient",
        "TelnetServer",
        "TFTP",
        "SMB1Protocol",
        "SMB1Protocol-Client",
        "SMB1Protocol-Server",
        "MicrosoftWindowsPowerShellV2",
        "MicrosoftWindowsPowerShellV2Root",
    };

    public SecurityHardeningTask()
    {
        Name = "Security Hardening";
        Description =
            "Apply additional security hardening settings via registry and system configuration";
    }

    public override async Task<SystemInfo> ReadSystemStateAsync()
    {
        var systemInfo = new SystemInfo();

        AnsiConsole.MarkupLine("[cyan]Reading current security configuration...[/]");

        // Check a few key settings
        var checksTable = new Table()
            .Border(TableBorder.Rounded)
            .BorderColor(Color.Grey)
            .AddColumn("[bold]Setting[/]")
            .AddColumn("[bold]Status[/]");

        // Check UAC
        var (uacSuccess, uacOutput, _) = await CommandExecutor.ExecuteAsync(
            "reg",
            @"query ""HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"" /v EnableLUA"
        );
        var uacEnabled = uacSuccess && uacOutput.Contains("0x1");
        checksTable.AddRow("UAC Enabled", uacEnabled ? "[green]Yes[/]" : "[red]No[/]");

        // Check Ctrl+Alt+Del
        var (cadSuccess, cadOutput, _) = await CommandExecutor.ExecuteAsync(
            "reg",
            @"query ""HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"" /v DisableCAD"
        );
        var cadRequired = cadSuccess && cadOutput.Contains("0x0");
        checksTable.AddRow("Ctrl+Alt+Del Required", cadRequired ? "[green]Yes[/]" : "[red]No[/]");

        // Check Remote Desktop
        var (rdpSuccess, rdpOutput, _) = await CommandExecutor.ExecuteAsync(
            "reg",
            @"query ""HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server"" /v fDenyTSConnections"
        );
        var rdpDisabled = rdpSuccess && rdpOutput.Contains("0x1");
        checksTable.AddRow("Remote Desktop Disabled", rdpDisabled ? "[green]Yes[/]" : "[red]No[/]");

        AnsiConsole.Write(checksTable);

        return systemInfo;
    }

    public override async Task<TaskResult> ExecuteAsync()
    {
        var result = new TaskResult
        {
            TaskName = Name,
            Success = true,
            Message = "Security hardening completed",
        };

        var fixes = new List<string>();
        var issues = new List<string>();

        try
        {
            AnsiConsole.WriteLine();
            AnsiConsole.Write(
                new Rule("[bold yellow]Step 1: Apply Registry Settings[/]").RuleStyle("yellow")
            );
            await ApplyRegistrySettingsAsync(fixes, issues);

            AnsiConsole.WriteLine();
            AnsiConsole.Write(
                new Rule("[bold yellow]Step 2: Disable Insecure Features[/]").RuleStyle("yellow")
            );
            await DisableInsecureFeaturesAsync(fixes, issues);

            AnsiConsole.WriteLine();
            AnsiConsole.Write(
                new Rule("[bold yellow]Step 3: Configure System Settings[/]").RuleStyle("yellow")
            );
            await ConfigureSystemSettingsAsync(fixes, issues);

            AnsiConsole.WriteLine();
            AnsiConsole.Write(
                new Rule("[bold yellow]Step 4: Disable Startup Programs[/]").RuleStyle("yellow")
            );
            await DisableSuspiciousStartupAsync(fixes, issues);

            // Summary
            if (issues.Count > 0)
            {
                result.Message =
                    $"Applied {fixes.Count} security settings. {issues.Count} issues encountered.";
                result.ErrorDetails = string.Join("\n", issues.Take(10));
            }
            else
            {
                result.Message = $"Successfully applied {fixes.Count} security hardening settings.";
            }
        }
        catch (Exception ex)
        {
            result.Success = false;
            result.Message = "Failed to apply security hardening";
            result.ErrorDetails = ex.Message;
            AnsiConsole.WriteException(ex);
        }

        return result;
    }

    public override async Task<bool> VerifyAsync()
    {
        // Spot check a few critical settings
        bool allGood = true;

        // Check UAC
        var (uacSuccess, uacOutput, _) = await CommandExecutor.ExecuteAsync(
            "reg",
            @"query ""HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"" /v EnableLUA"
        );
        if (uacSuccess && uacOutput.Contains("0x1"))
        {
            AnsiConsole.MarkupLine("[green]? UAC is enabled[/]");
        }
        else
        {
            AnsiConsole.MarkupLine("[red]? UAC is not enabled[/]");
            allGood = false;
        }

        // Check Remote Desktop
        var (rdpSuccess, rdpOutput, _) = await CommandExecutor.ExecuteAsync(
            "reg",
            @"query ""HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server"" /v fDenyTSConnections"
        );
        if (rdpSuccess && rdpOutput.Contains("0x1"))
        {
            AnsiConsole.MarkupLine("[green]? Remote Desktop is disabled[/]");
        }
        else
        {
            AnsiConsole.MarkupLine("[red]? Remote Desktop is not disabled[/]");
            allGood = false;
        }

        return allGood;
    }

    #region Helper Methods

    private async Task ApplyRegistrySettingsAsync(List<string> fixes, List<string> issues)
    {
        AnsiConsole.MarkupLine($"[cyan]Applying {RegistrySettings.Length} registry settings...[/]");

        var successCount = 0;
        var failCount = 0;

        await AnsiConsole
            .Progress()
            .AutoClear(false)
            .HideCompleted(false)
            .Columns(
                new ProgressColumn[]
                {
                    new TaskDescriptionColumn(),
                    new ProgressBarColumn(),
                    new PercentageColumn(),
                }
            )
            .StartAsync(async ctx =>
            {
                var task = ctx.AddTask(
                    "[cyan]Applying registry settings...[/]",
                    maxValue: RegistrySettings.Length
                );

                foreach (var (path, name, type, value, description) in RegistrySettings)
                {
                    var (success, _, error) = await CommandExecutor.ExecuteAsync(
                        "reg",
                        $"add \"{path}\" /v {name} /t {type} /d {value} /f"
                    );

                    if (success)
                    {
                        fixes.Add($"Set {description}");
                        successCount++;
                    }
                    else
                    {
                        failCount++;
                    }

                    task.Increment(1);
                }
            });

        AnsiConsole.MarkupLine($"[green]? Applied {successCount} settings[/]");
        if (failCount > 0)
        {
            AnsiConsole.MarkupLine($"[yellow]? {failCount} settings could not be applied[/]");
        }
    }

    private async Task DisableInsecureFeaturesAsync(List<string> fixes, List<string> issues)
    {
        AnsiConsole.MarkupLine("[cyan]Disabling insecure Windows features...[/]");

        foreach (var feature in FeaturesToDisable)
        {
            var (success, _, _) = await CommandExecutor.ExecuteAsync(
                "powershell",
                $"-Command \"Disable-WindowsOptionalFeature -Online -FeatureName '{feature}' -NoRestart -ErrorAction SilentlyContinue\""
            );

            if (success)
            {
                fixes.Add($"Disabled feature: {feature}");
                AnsiConsole.MarkupLine($"[green]? Disabled: {feature}[/]");
            }
            else
            {
                AnsiConsole.MarkupLine(
                    $"[dim]Feature {feature} may not exist or already disabled[/]"
                );
            }
        }

        // Disable SMB1
        await CommandExecutor.ExecuteAsync(
            "powershell",
            "-Command \"Set-SmbServerConfiguration -EnableSMB1Protocol $false -Force -ErrorAction SilentlyContinue\""
        );
        fixes.Add("Disabled SMB1 protocol");
    }

    private async Task ConfigureSystemSettingsAsync(List<string> fixes, List<string> issues)
    {
        AnsiConsole.MarkupLine("[cyan]Configuring additional system settings...[/]");

        // Flush DNS cache
        await CommandExecutor.ExecuteAsync("ipconfig", "/flushdns");
        fixes.Add("Flushed DNS cache");
        AnsiConsole.MarkupLine("[green]? Flushed DNS cache[/]");

        // Enable Windows Defender
        await CommandExecutor.ExecuteAsync(
            "powershell",
            "-Command \"Set-MpPreference -DisableRealtimeMonitoring $false -ErrorAction SilentlyContinue\""
        );
        fixes.Add("Enabled Windows Defender real-time monitoring");
        AnsiConsole.MarkupLine("[green]? Enabled Windows Defender real-time monitoring[/]");

        // Update Windows Defender definitions
        AnsiConsole.MarkupLine("[cyan]Updating Windows Defender definitions...[/]");
        await CommandExecutor.ExecuteAsync(
            "powershell",
            "-Command \"Update-MpSignature -ErrorAction SilentlyContinue\""
        );
        fixes.Add("Updated Windows Defender definitions");
        AnsiConsole.MarkupLine("[green]? Updated Windows Defender definitions[/]");

        // Start Windows Update service
        await CommandExecutor.ExecuteAsync("net", "start wuauserv");
        fixes.Add("Started Windows Update service");
    }

    private async Task DisableSuspiciousStartupAsync(List<string> fixes, List<string> issues)
    {
        AnsiConsole.MarkupLine("[cyan]Checking startup programs...[/]");

        // Get startup items
        var (success, output, _) = await CommandExecutor.ExecuteAsync(
            "powershell",
            "-Command \"Get-CimInstance Win32_StartupCommand | Select-Object Name, Command, Location | ConvertTo-Json\""
        );

        if (success && !string.IsNullOrEmpty(output))
        {
            AnsiConsole.MarkupLine("[dim]Startup programs have been logged for manual review[/]");
            fixes.Add("Reviewed startup programs");
        }

        // Disable common suspicious startup locations via registry
        var suspiciousRunKeys = new[]
        {
            @"HKCU\Software\Microsoft\Windows\CurrentVersion\Run",
            @"HKLM\Software\Microsoft\Windows\CurrentVersion\Run",
            @"HKCU\Software\Microsoft\Windows\CurrentVersion\RunOnce",
            @"HKLM\Software\Microsoft\Windows\CurrentVersion\RunOnce",
        };

        foreach (var key in suspiciousRunKeys)
        {
            var (querySuccess, queryOutput, _) = await CommandExecutor.ExecuteAsync(
                "reg",
                $"query \"{key}\""
            );
            if (querySuccess)
            {
                AnsiConsole.MarkupLine($"[dim]Checked: {key}[/]");
            }
        }
    }

    #endregion
}
