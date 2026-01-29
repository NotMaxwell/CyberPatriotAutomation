using CyberPatriotAutomation.Core.Models;
using CyberPatriotAutomation.Core.Utilities;
using Spectre.Console;

namespace CyberPatriotAutomation.Core.Tasks;

/// <summary>
/// Task to configure Windows audit policies for security logging
/// Based on CIS Benchmarks and CyberPatriot best practices
/// </summary>
public class AuditPolicyTask : BaseTask
{
    /// <summary>
    /// Audit categories with their subcategories
    /// All should be set to log both success and failure
    /// </summary>
    private static readonly Dictionary<string, string[]> AuditCategories =
        new()
        {
            {
                "Account Logon",
                new[]
                {
                    "Credential Validation",
                    "Kerberos Authentication Service",
                    "Kerberos Service Ticket Operations",
                    "Other Account Logon Events",
                }
            },
            {
                "Account Management",
                new[]
                {
                    "Application Group Management",
                    "Computer Account Management",
                    "Distribution Group Management",
                    "Other Account Management Events",
                    "Security Group Management",
                    "User Account Management",
                }
            },
            {
                "Detailed Tracking",
                new[]
                {
                    "DPAPI Activity",
                    "PNP Activity",
                    "Process Creation",
                    "Process Termination",
                    "RPC Events",
                    "Token Right Adjusted Events",
                }
            },
            {
                "DS Access",
                new[]
                {
                    "Detailed Directory Service Replication",
                    "Directory Service Access",
                    "Directory Service Changes",
                    "Directory Service Replication",
                }
            },
            {
                "Logon/Logoff",
                new[]
                {
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
                }
            },
            {
                "Object Access",
                new[]
                {
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
                }
            },
            {
                "Policy Change",
                new[]
                {
                    "Audit Policy Change",
                    "Authentication Policy Change",
                    "Authorization Policy Change",
                    "Filtering Platform Policy Change",
                    "MPSSVC Rule-Level Policy Change",
                    "Other Policy Change Events",
                }
            },
            {
                "Privilege Use",
                new[]
                {
                    "Non Sensitive Privilege Use",
                    "Other Privilege Use Events",
                    "Sensitive Privilege Use",
                }
            },
            {
                "System",
                new[]
                {
                    "IPsec Driver",
                    "Other System Events",
                    "Security State Change",
                    "Security System Extension",
                    "System Integrity",
                }
            },
        };

    /// <summary>
    /// Registry settings for security options
    /// </summary>
    private static readonly Dictionary<
        string,
        (string Path, string Name, int Value, string Description)
    > SecuritySettings =
        new()
        {
            // Auditing settings
            {
                "AuditBaseObjects",
                (
                    @"HKLM\SYSTEM\CurrentControlSet\Control\Lsa",
                    "auditbaseobjects",
                    1,
                    "Audit access of Global System Objects"
                )
            },
            {
                "FullPrivilegeAuditing",
                (
                    @"HKLM\SYSTEM\CurrentControlSet\Control\Lsa",
                    "fullprivilegeauditing",
                    1,
                    "Audit Backup and Restore privilege"
                )
            },
            {
                "CrashOnAuditFail",
                (
                    @"HKLM\SYSTEM\CurrentControlSet\Control\Lsa",
                    "crashonauditfail",
                    0,
                    "Crash on audit fail (disabled)"
                )
            },
            // LSA Protection
            {
                "RunAsPPL",
                (
                    @"HKLM\SYSTEM\CurrentControlSet\Control\Lsa",
                    "RunAsPPL",
                    1,
                    "Enable LSA protection"
                )
            },
            {
                "LsassAuditLevel",
                (
                    @"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\LSASS.exe",
                    "AuditLevel",
                    8,
                    "LSASS audit level"
                )
            },
            // Logon settings
            {
                "DontDisplayLastUsername",
                (
                    @"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System",
                    "dontdisplaylastusername",
                    1,
                    "Don't display last username"
                )
            },
            {
                "DisableCAD",
                (
                    @"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System",
                    "DisableCAD",
                    0,
                    "Require Ctrl+Alt+Del"
                )
            },
            // Anonymous restrictions
            {
                "RestrictAnonymous",
                (
                    @"HKLM\SYSTEM\CurrentControlSet\Control\Lsa",
                    "restrictanonymous",
                    1,
                    "Restrict anonymous enumeration of shares"
                )
            },
            {
                "RestrictAnonymousSAM",
                (
                    @"HKLM\SYSTEM\CurrentControlSet\Control\Lsa",
                    "restrictanonymoussam",
                    1,
                    "Restrict anonymous enumeration of SAM"
                )
            },
            {
                "EveryoneIncludesAnonymous",
                (
                    @"HKLM\SYSTEM\CurrentControlSet\Control\Lsa",
                    "everyoneincludesanonymous",
                    0,
                    "Anonymous not in Everyone group"
                )
            },
            // Password/credential settings
            {
                "LimitBlankPasswordUse",
                (
                    @"HKLM\SYSTEM\CurrentControlSet\Control\Lsa",
                    "LimitBlankPasswordUse",
                    1,
                    "Limit blank password use"
                )
            },
            {
                "DisableDomainCreds",
                (
                    @"HKLM\SYSTEM\CurrentControlSet\Control\Lsa",
                    "disabledomaincreds",
                    1,
                    "Don't store domain credentials"
                )
            },
            // Network security
            {
                "RequireSecuritySignature",
                (
                    @"HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters",
                    "requiresecuritysignature",
                    1,
                    "Require SMB signing"
                )
            },
            {
                "EnableSecuritySignature",
                (
                    @"HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters",
                    "enablesecuritysignature",
                    1,
                    "Enable SMB signing"
                )
            },
            {
                "NullSessionPipes",
                (
                    @"HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters",
                    "NullSessionPipes",
                    0,
                    "Clear null session pipes"
                )
            },
            {
                "NullSessionShares",
                (
                    @"HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters",
                    "NullSessionShares",
                    0,
                    "Clear null session shares"
                )
            },
            // Session settings
            {
                "AutoDisconnect",
                (
                    @"HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters",
                    "autodisconnect",
                    15,
                    "Auto disconnect idle sessions (15 min)"
                )
            },
            {
                "EnablePlainTextPassword",
                (
                    @"HKLM\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters",
                    "EnablePlainTextPassword",
                    0,
                    "Disable plain text passwords"
                )
            },
            // Crash/dump settings
            {
                "ClearPageFileAtShutdown",
                (
                    @"HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management",
                    "ClearPageFileAtShutdown",
                    1,
                    "Clear page file at shutdown"
                )
            },
            {
                "CrashDumpEnabled",
                (
                    @"HKLM\SYSTEM\CurrentControlSet\Control\CrashControl",
                    "CrashDumpEnabled",
                    0,
                    "Disable crash dump"
                )
            },
        };

    public AuditPolicyTask()
    {
        Name = "Audit Policy Configuration";
        Description =
            "Configure Windows audit policies to log security events (success and failure)";
    }

    public override async Task<SystemInfo> ReadSystemStateAsync()
    {
        var systemInfo = new SystemInfo();

        AnsiConsole.MarkupLine("[cyan]Reading current audit policy settings...[/]");

        // Get current audit policy
        var (success, output, _) = await CommandExecutor.ExecuteAsync(
            "auditpol",
            "/get /category:*"
        );

        if (success && !string.IsNullOrEmpty(output))
        {
            // Parse and display current settings
            DisplayCurrentAuditPolicy(output);
        }

        return systemInfo;
    }

    public override async Task<TaskResult> ExecuteAsync()
    {
        var result = new TaskResult
        {
            TaskName = Name,
            Success = true,
            Message = "Audit policy configuration completed",
        };

        var fixes = new List<string>();
        var issues = new List<string>();

        try
        {
            if (DryRun)
            {
                AnsiConsole.MarkupLine(
                    "[yellow]DRY RUN: Previewing audit policy changes (no changes will be made)[/]"
                );
                AnsiConsole.MarkupLine(
                    $"[cyan]Would configure {AuditCategories.Count} audit categories[/]"
                );
                var totalSubcategories = AuditCategories.Values.Sum(s => s.Length);
                AnsiConsole.MarkupLine(
                    $"[cyan]Would configure {totalSubcategories} advanced subcategories[/]"
                );
                AnsiConsole.MarkupLine(
                    $"[cyan]Would configure {SecuritySettings.Count} security registry settings[/]"
                );
                result.Message = "DRY RUN: Audit policy changes previewed.";
                return result;
            }

            AnsiConsole.WriteLine();
            AnsiConsole.Write(
                new Rule("[bold yellow]Step 1: Configure Audit Categories[/]").RuleStyle("yellow")
            );
            await ConfigureAuditCategoriesAsync(fixes, issues);

            AnsiConsole.WriteLine();
            AnsiConsole.Write(
                new Rule("[bold yellow]Step 2: Configure Advanced Audit Policies[/]").RuleStyle(
                    "yellow"
                )
            );
            await ConfigureAdvancedAuditPoliciesAsync(fixes, issues);

            AnsiConsole.WriteLine();
            AnsiConsole.Write(
                new Rule("[bold yellow]Step 3: Configure Security Registry Settings[/]").RuleStyle(
                    "yellow"
                )
            );
            await ConfigureSecurityRegistryAsync(fixes, issues);

            AnsiConsole.WriteLine();
            AnsiConsole.Write(
                new Rule("[bold yellow]Step 4: Configure Event Log Settings[/]").RuleStyle("yellow")
            );
            await ConfigureEventLogSettingsAsync(fixes, issues);

            // Summary
            if (issues.Count > 0)
            {
                result.Message =
                    $"Applied {fixes.Count} audit settings. {issues.Count} issues encountered.";
                result.ErrorDetails = string.Join("\n", issues.Take(10));
            }
            else
            {
                result.Message = $"Successfully configured {fixes.Count} audit policy settings.";
            }
        }
        catch (Exception ex)
        {
            result.Success = false;
            result.Message = "Failed to configure audit policies";
            result.ErrorDetails = ex.Message;
            AnsiConsole.WriteException(ex);
        }

        return result;
    }

    public override async Task<bool> VerifyAsync()
    {
        bool allGood = true;

        // Verify a sample of audit categories
        var categoriesToCheck = new[]
        {
            "Account Logon",
            "Account Management",
            "Logon/Logoff",
            "System",
        };

        foreach (var category in categoriesToCheck)
        {
            var (success, output, _) = await CommandExecutor.ExecuteAsync(
                "auditpol",
                $"/get /category:\"{category}\""
            );

            if (success && !string.IsNullOrEmpty(output))
            {
                if (
                    output.Contains("Success and Failure")
                    || (output.Contains("Success") && output.Contains("Failure"))
                )
                {
                    AnsiConsole.MarkupLine(
                        $"[green]? {category}: Success and Failure auditing enabled[/]"
                    );
                }
                else
                {
                    AnsiConsole.MarkupLine($"[red]? {category}: Auditing not fully configured[/]");
                    allGood = false;
                }
            }
        }

        return allGood;
    }

    #region Helper Methods

    private void DisplayCurrentAuditPolicy(string output)
    {
        var table = new Table()
            .Border(TableBorder.Rounded)
            .BorderColor(Color.Grey)
            .Title("[bold]Current Audit Policy[/]")
            .AddColumn("[bold]Category/Subcategory[/]")
            .AddColumn("[bold]Setting[/]");

        var lines = output.Split(new[] { '\r', '\n' }, StringSplitOptions.RemoveEmptyEntries);
        int count = 0;

        foreach (var line in lines)
        {
            if (
                line.Contains("Success")
                || line.Contains("Failure")
                || line.Contains("No Auditing")
            )
            {
                var parts = line.Split(new[] { "  " }, StringSplitOptions.RemoveEmptyEntries);
                if (parts.Length >= 2)
                {
                    var category = parts[0].Trim();
                    var setting = parts[^1].Trim();

                    var settingColor = setting switch
                    {
                        "Success and Failure" => "green",
                        "Success" => "yellow",
                        "Failure" => "yellow",
                        "No Auditing" => "red",
                        _ => "white",
                    };

                    table.AddRow(category, $"[{settingColor}]{setting}[/]");
                    count++;

                    if (count >= 15)
                        break; // Limit display
                }
            }
        }

        if (count > 0)
        {
            AnsiConsole.Write(table);
            AnsiConsole.MarkupLine($"[dim](Showing {count} of many audit settings)[/]");
        }
    }

    private async Task ConfigureAuditCategoriesAsync(List<string> fixes, List<string> issues)
    {
        var progressTable = new Table()
            .Border(TableBorder.Rounded)
            .BorderColor(Color.Blue)
            .AddColumn("[bold]Category[/]")
            .AddColumn("[bold]Status[/]");

        foreach (var category in AuditCategories.Keys)
        {
            AnsiConsole.MarkupLine($"[cyan]Configuring {category}...[/]");

            // Enable success auditing
            var (successEnable, _, successError) = await CommandExecutor.ExecuteAsync(
                "auditpol",
                $"/set /category:\"{category}\" /success:enable"
            );

            // Enable failure auditing
            var (failureEnable, _, failureError) = await CommandExecutor.ExecuteAsync(
                "auditpol",
                $"/set /category:\"{category}\" /failure:enable"
            );

            if (successEnable && failureEnable)
            {
                progressTable.AddRow(category, "[green]? Success & Failure[/]");
                fixes.Add($"Configured audit: {category} (Success & Failure)");
            }
            else
            {
                progressTable.AddRow(category, "[red]? Failed[/]");
                issues.Add($"Failed to configure {category}: {successError ?? failureError}");
            }
        }

        AnsiConsole.Write(progressTable);
    }

    private async Task ConfigureAdvancedAuditPoliciesAsync(List<string> fixes, List<string> issues)
    {
        AnsiConsole.MarkupLine("[cyan]Configuring advanced audit subcategories...[/]");

        int configuredCount = 0;

        foreach (var (category, subcategories) in AuditCategories)
        {
            foreach (var subcategory in subcategories)
            {
                // Enable success
                var (successEnable, _, _) = await CommandExecutor.ExecuteAsync(
                    "auditpol",
                    $"/set /subcategory:\"{subcategory}\" /success:enable"
                );

                // Enable failure
                var (failureEnable, _, _) = await CommandExecutor.ExecuteAsync(
                    "auditpol",
                    $"/set /subcategory:\"{subcategory}\" /failure:enable"
                );

                if (successEnable && failureEnable)
                {
                    configuredCount++;
                }
            }
        }

        fixes.Add($"Configured {configuredCount} audit subcategories");
        AnsiConsole.MarkupLine($"[green]? Configured {configuredCount} audit subcategories[/]");

        // Additional specific auditing commands
        var additionalAudits = new[]
        {
            ("Logon", "Audit Logon events"),
            ("Process Creation", "Audit Process Creation"),
            ("Special Logon", "Audit Special Logon"),
            ("Security State Change", "Audit Security State Change"),
        };

        foreach (var (subcategory, description) in additionalAudits)
        {
            await CommandExecutor.ExecuteAsync(
                "auditpol",
                $"/set /subcategory:\"{subcategory}\" /success:enable /failure:enable"
            );
        }
    }

    private async Task ConfigureSecurityRegistryAsync(List<string> fixes, List<string> issues)
    {
        var settingsTable = new Table()
            .Border(TableBorder.Rounded)
            .BorderColor(Color.Magenta1)
            .AddColumn("[bold]Setting[/]")
            .AddColumn("[bold]Description[/]")
            .AddColumn("[bold]Status[/]");

        foreach (var (key, setting) in SecuritySettings)
        {
            var (path, name, value, description) = setting;

            // Determine the registry type based on value
            var regType = "REG_DWORD";
            var valueStr = value.ToString();

            var (success, _, error) = await CommandExecutor.ExecuteAsync(
                "reg",
                $"add \"{path}\" /v {name} /t {regType} /d {valueStr} /f"
            );

            if (success)
            {
                settingsTable.AddRow(key, description, "[green]? Set[/]");
                fixes.Add($"Set registry: {name}");
            }
            else
            {
                settingsTable.AddRow(key, description, "[red]? Failed[/]");
                issues.Add($"Failed to set {name}: {error}");
            }
        }

        AnsiConsole.Write(settingsTable);
    }

    private async Task ConfigureEventLogSettingsAsync(List<string> fixes, List<string> issues)
    {
        AnsiConsole.MarkupLine("[cyan]Configuring event log settings...[/]");

        // Configure Security log size (at least 196608 KB = 192 MB)
        var logSettings = new[] { ("Security", 196608), ("Application", 32768), ("System", 32768) };

        foreach (var (logName, maxSize) in logSettings)
        {
            var (success, _, error) = await CommandExecutor.ExecuteAsync(
                "powershell",
                $"-Command \"Limit-EventLog -LogName '{logName}' -MaximumSize {maxSize}KB -OverflowAction OverwriteAsNeeded\""
            );

            if (success)
            {
                fixes.Add($"Configured {logName} log: {maxSize / 1024}MB max size");
                AnsiConsole.MarkupLine(
                    $"[green]? Configured {logName} log: {maxSize / 1024}MB max size[/]"
                );
            }
            else
            {
                AnsiConsole.MarkupLine($"[yellow]? Could not configure {logName} log[/]");
            }
        }

        // Enable Windows PowerShell logging
        AnsiConsole.MarkupLine("[cyan]Enabling PowerShell logging...[/]");

        var psLoggingKeys = new[]
        {
            (
                @"HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging",
                "EnableScriptBlockLogging",
                1
            ),
            (
                @"HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging",
                "EnableModuleLogging",
                1
            ),
            (
                @"HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription",
                "EnableTranscripting",
                1
            ),
        };

        foreach (var (path, name, value) in psLoggingKeys)
        {
            // Ensure the key exists
            await CommandExecutor.ExecuteAsync("reg", $"add \"{path}\" /f");

            var (success, _, _) = await CommandExecutor.ExecuteAsync(
                "reg",
                $"add \"{path}\" /v {name} /t REG_DWORD /d {value} /f"
            );

            if (success)
            {
                fixes.Add($"Enabled PowerShell {name}");
            }
        }

        AnsiConsole.MarkupLine("[green]? Configured PowerShell logging[/]");

        // Enable command line auditing in process creation events
        await CommandExecutor.ExecuteAsync(
            "reg",
            @"add ""HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit"" /v ProcessCreationIncludeCmdLine_Enabled /t REG_DWORD /d 1 /f"
        );

        fixes.Add("Enabled command line in process creation audit");
        AnsiConsole.MarkupLine("[green]? Enabled command line in process creation audit[/]");
    }

    #endregion
}
