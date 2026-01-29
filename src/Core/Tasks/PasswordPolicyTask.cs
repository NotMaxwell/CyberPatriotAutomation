using CyberPatriotAutomation.Core.Models;
using CyberPatriotAutomation.Core.Utilities;
using Spectre.Console;

namespace CyberPatriotAutomation.Core.Tasks;

/// <summary>
/// Task to check and enforce secure password policies
/// Based on NIST SP 800-63B, CIS Benchmarks, and industry best practices
/// </summary>
public class PasswordPolicyTask : BaseTask
{
    private PasswordPolicyInfo? _currentPolicy;

    public PasswordPolicyTask()
    {
        Name = "Password Policy Enforcement";
        Description =
            "Check and enforce secure password policies according to professional security standards";
    }

    public override async Task<SystemInfo> ReadSystemStateAsync()
    {
        var systemInfo = new SystemInfo();
        _currentPolicy = await GetCurrentPasswordPolicyAsync();

        // Store policy info in registry settings for reference
        systemInfo.RegistrySettings["MinPasswordLength"] =
            _currentPolicy.MinPasswordLength.ToString();
        systemInfo.RegistrySettings["MaxPasswordAge"] = _currentPolicy.MaxPasswordAge.ToString();
        systemInfo.RegistrySettings["MinPasswordAge"] = _currentPolicy.MinPasswordAge.ToString();
        systemInfo.RegistrySettings["PasswordHistoryCount"] =
            _currentPolicy.PasswordHistoryCount.ToString();
        systemInfo.RegistrySettings["ComplexityEnabled"] =
            _currentPolicy.ComplexityEnabled.ToString();
        systemInfo.RegistrySettings["LockoutThreshold"] =
            _currentPolicy.LockoutThreshold.ToString();
        systemInfo.RegistrySettings["LockoutDuration"] = _currentPolicy.LockoutDuration.ToString();

        return systemInfo;
    }

    public override async Task<TaskResult> ExecuteAsync()
    {
        var result = new TaskResult
        {
            TaskName = Name,
            Success = true,
            Message = "Password policy enforcement completed",
        };

        var issues = new List<string>();
        var fixes = new List<string>();

        try
        {
            AnsiConsole.MarkupLine("[bold]Checking Password Policy Settings...[/]");

            if (_currentPolicy == null)
            {
                _currentPolicy = await GetCurrentPasswordPolicyAsync();
            }

            // Display current vs recommended settings
            DisplayPolicyComparison(_currentPolicy);

            // Apply password policy fixes
            var policyFixes = await ApplyPasswordPolicyAsync(_currentPolicy);
            fixes.AddRange(policyFixes.Fixes);
            issues.AddRange(policyFixes.Issues);

            // Apply account lockout policy fixes
            var lockoutFixes = await ApplyLockoutPolicyAsync(_currentPolicy);
            fixes.AddRange(lockoutFixes.Fixes);
            issues.AddRange(lockoutFixes.Issues);

            if (issues.Count > 0)
            {
                result.Message = $"Applied {fixes.Count} fixes. {issues.Count} issues remain.";
                result.ErrorDetails = string.Join("\n", issues);
            }
            else
            {
                result.Message = $"Successfully applied {fixes.Count} password policy settings.";
            }
        }
        catch (Exception ex)
        {
            result.Success = false;
            result.Message = "Failed to enforce password policy";
            result.ErrorDetails = ex.Message;
            AnsiConsole.WriteException(ex);
        }

        return result;
    }

    public override async Task<bool> VerifyAsync()
    {
        var verifiedPolicy = await GetCurrentPasswordPolicyAsync();

        bool allGood = true;

        if (verifiedPolicy.MinPasswordLength < PasswordPolicyStandards.MinPasswordLength)
        {
            AnsiConsole.MarkupLine("[red]? Minimum password length not set correctly[/]");
            allGood = false;
        }

        if (
            verifiedPolicy.MaxPasswordAge > PasswordPolicyStandards.MaxPasswordAge
            || verifiedPolicy.MaxPasswordAge == 0
        )
        {
            AnsiConsole.MarkupLine("[red]? Maximum password age not set correctly[/]");
            allGood = false;
        }

        if (!verifiedPolicy.ComplexityEnabled)
        {
            AnsiConsole.MarkupLine("[red]? Password complexity not enabled[/]");
            allGood = false;
        }

        if (
            verifiedPolicy.LockoutThreshold == 0
            || verifiedPolicy.LockoutThreshold > PasswordPolicyStandards.LockoutThreshold
        )
        {
            AnsiConsole.MarkupLine("[red]? Account lockout threshold not set correctly[/]");
            allGood = false;
        }

        if (allGood)
        {
            AnsiConsole.MarkupLine("[green]? All password policy settings verified[/]");
        }

        return allGood;
    }

    private async Task<PasswordPolicyInfo> GetCurrentPasswordPolicyAsync()
    {
        var policy = new PasswordPolicyInfo();

        // Use net accounts to get current policy on Windows
        var (success, output, _) = await CommandExecutor.ExecuteAsync("net", "accounts");

        if (success && !string.IsNullOrEmpty(output))
        {
            var lines = output.Split(new[] { '\r', '\n' }, StringSplitOptions.RemoveEmptyEntries);

            foreach (var line in lines)
            {
                if (line.Contains("Minimum password length"))
                {
                    var value = ExtractNumericValue(line);
                    policy.MinPasswordLength = value;
                }
                else if (line.Contains("Maximum password age"))
                {
                    var value = ExtractNumericValue(line);
                    policy.MaxPasswordAge = value == -1 ? 0 : value; // -1 means unlimited/never
                }
                else if (line.Contains("Minimum password age"))
                {
                    policy.MinPasswordAge = ExtractNumericValue(line);
                }
                else if (line.Contains("Length of password history"))
                {
                    policy.PasswordHistoryCount = ExtractNumericValue(line);
                }
                else if (line.Contains("Lockout threshold"))
                {
                    var value = ExtractNumericValue(line);
                    policy.LockoutThreshold = value == -1 ? 0 : value;
                }
                else if (line.Contains("Lockout duration"))
                {
                    policy.LockoutDuration = ExtractNumericValue(line);
                }
                else if (line.Contains("Lockout observation window"))
                {
                    policy.LockoutObservationWindow = ExtractNumericValue(line);
                }
            }
        }

        // Check password complexity via secedit (requires admin)
        var (secSuccess, _, _) = await CommandExecutor.ExecuteAsync(
            "secedit",
            "/export /cfg %TEMP%\\secpol.cfg /quiet"
        );
        if (secSuccess)
        {
            var (readSuccess, cfgOutput, _) = await CommandExecutor.ExecuteAsync(
                "cmd",
                "/c type %TEMP%\\secpol.cfg"
            );
            if (readSuccess && cfgOutput.Contains("PasswordComplexity"))
            {
                policy.ComplexityEnabled = cfgOutput.Contains("PasswordComplexity = 1");
            }
        }

        return policy;
    }

    private void DisplayPolicyComparison(PasswordPolicyInfo current)
    {
        var table = new Table()
            .Border(TableBorder.Rounded)
            .AddColumn("Setting")
            .AddColumn("Current")
            .AddColumn("Recommended")
            .AddColumn("Status");

        AddComparisonRow(
            table,
            "Min Password Length",
            current.MinPasswordLength,
            PasswordPolicyStandards.MinPasswordLength,
            current.MinPasswordLength >= PasswordPolicyStandards.MinPasswordLength
        );

        AddComparisonRow(
            table,
            "Max Password Age (days)",
            current.MaxPasswordAge == 0 ? "Never" : current.MaxPasswordAge.ToString(),
            PasswordPolicyStandards.MaxPasswordAge.ToString(),
            current.MaxPasswordAge > 0
                && current.MaxPasswordAge <= PasswordPolicyStandards.MaxPasswordAge
        );

        AddComparisonRow(
            table,
            "Min Password Age (days)",
            current.MinPasswordAge,
            PasswordPolicyStandards.MinPasswordAge,
            current.MinPasswordAge >= PasswordPolicyStandards.MinPasswordAge
        );

        AddComparisonRow(
            table,
            "Password History",
            current.PasswordHistoryCount,
            PasswordPolicyStandards.PasswordHistoryCount,
            current.PasswordHistoryCount >= PasswordPolicyStandards.PasswordHistoryCount
        );

        AddComparisonRow(
            table,
            "Complexity Enabled",
            current.ComplexityEnabled ? "Yes" : "No",
            "Yes",
            current.ComplexityEnabled
        );

        AddComparisonRow(
            table,
            "Lockout Threshold",
            current.LockoutThreshold == 0 ? "Disabled" : current.LockoutThreshold.ToString(),
            PasswordPolicyStandards.LockoutThreshold.ToString(),
            current.LockoutThreshold > 0
                && current.LockoutThreshold <= PasswordPolicyStandards.LockoutThreshold
        );

        AddComparisonRow(
            table,
            "Lockout Duration (min)",
            current.LockoutDuration,
            PasswordPolicyStandards.LockoutDuration,
            current.LockoutDuration >= PasswordPolicyStandards.LockoutDuration
        );

        AnsiConsole.Write(table);
    }

    private void AddComparisonRow(
        Table table,
        string setting,
        object current,
        object recommended,
        bool isCompliant
    )
    {
        var status = isCompliant ? "[green]? OK[/]" : "[red]? Fix[/]";
        var currentFormatted = isCompliant ? $"[green]{current}[/]" : $"[yellow]{current}[/]";
        table.AddRow(setting, currentFormatted, recommended.ToString()!, status);
    }

    private async Task<(List<string> Fixes, List<string> Issues)> ApplyPasswordPolicyAsync(
        PasswordPolicyInfo current
    )
    {
        var fixes = new List<string>();
        var issues = new List<string>();

        if (DryRun)
        {
            AnsiConsole.MarkupLine("[yellow]DRY RUN: Skipping password policy changes[/]");
            if (current.MinPasswordLength < PasswordPolicyStandards.MinPasswordLength)
                issues.Add(
                    $"Would set minimum password length to {PasswordPolicyStandards.MinPasswordLength}"
                );
            if (current.PasswordHistoryCount < PasswordPolicyStandards.PasswordHistoryCount)
                issues.Add(
                    $"Would set password history to {PasswordPolicyStandards.PasswordHistoryCount}"
                );
            if (!current.ComplexityEnabled)
                issues.Add("Would enable password complexity");
            return (fixes, issues);
        }

        // Set minimum password length
        if (current.MinPasswordLength < PasswordPolicyStandards.MinPasswordLength)
        {
            AnsiConsole.MarkupLine(
                $"[yellow]Setting minimum password length to {PasswordPolicyStandards.MinPasswordLength}...[/]"
            );
            var (success, _, error) = await CommandExecutor.ExecuteAsync(
                "net",
                $"accounts /minpwlen:{PasswordPolicyStandards.MinPasswordLength}"
            );

            if (success)
                fixes.Add(
                    $"Set minimum password length to {PasswordPolicyStandards.MinPasswordLength}"
                );
            else
                issues.Add($"Failed to set minimum password length: {error}");
        }

        // Set maximum password age
        if (
            current.MaxPasswordAge == 0
            || current.MaxPasswordAge > PasswordPolicyStandards.MaxPasswordAge
        )
        {
            AnsiConsole.MarkupLine(
                $"[yellow]Setting maximum password age to {PasswordPolicyStandards.MaxPasswordAge} days...[/]"
            );
            var (success, _, error) = await CommandExecutor.ExecuteAsync(
                "net",
                $"accounts /maxpwage:{PasswordPolicyStandards.MaxPasswordAge}"
            );

            if (success)
                fixes.Add(
                    $"Set maximum password age to {PasswordPolicyStandards.MaxPasswordAge} days"
                );
            else
                issues.Add($"Failed to set maximum password age: {error}");
        }

        // Set minimum password age
        if (current.MinPasswordAge < PasswordPolicyStandards.MinPasswordAge)
        {
            AnsiConsole.MarkupLine(
                $"[yellow]Setting minimum password age to {PasswordPolicyStandards.MinPasswordAge} day(s)...[/]"
            );
            var (success, _, error) = await CommandExecutor.ExecuteAsync(
                "net",
                $"accounts /minpwage:{PasswordPolicyStandards.MinPasswordAge}"
            );

            if (success)
                fixes.Add(
                    $"Set minimum password age to {PasswordPolicyStandards.MinPasswordAge} day(s)"
                );
            else
                issues.Add($"Failed to set minimum password age: {error}");
        }

        // Set password history
        if (current.PasswordHistoryCount < PasswordPolicyStandards.PasswordHistoryCount)
        {
            AnsiConsole.MarkupLine(
                $"[yellow]Setting password history to {PasswordPolicyStandards.PasswordHistoryCount}...[/]"
            );
            var (success, _, error) = await CommandExecutor.ExecuteAsync(
                "net",
                $"accounts /uniquepw:{PasswordPolicyStandards.PasswordHistoryCount}"
            );

            if (success)
                fixes.Add(
                    $"Set password history to {PasswordPolicyStandards.PasswordHistoryCount}"
                );
            else
                issues.Add($"Failed to set password history: {error}");
        }

        // Enable password complexity via secpol (requires more complex approach)
        if (!current.ComplexityEnabled)
        {
            AnsiConsole.MarkupLine("[yellow]Enabling password complexity...[/]");
            var complexityResult = await EnablePasswordComplexityAsync();
            if (complexityResult.Success)
                fixes.Add("Enabled password complexity requirement");
            else
                issues.Add($"Failed to enable password complexity: {complexityResult.Error}");
        }

        return (fixes, issues);
    }

    private async Task<(List<string> Fixes, List<string> Issues)> ApplyLockoutPolicyAsync(
        PasswordPolicyInfo current
    )
    {
        var fixes = new List<string>();
        var issues = new List<string>();

        if (DryRun)
        {
            AnsiConsole.MarkupLine("[yellow]DRY RUN: Skipping lockout policy changes[/]");
            return (fixes, issues);
        }

        // Set lockout threshold
        if (
            current.LockoutThreshold == 0
            || current.LockoutThreshold > PasswordPolicyStandards.LockoutThreshold
        )
        {
            AnsiConsole.MarkupLine(
                $"[yellow]Setting account lockout threshold to {PasswordPolicyStandards.LockoutThreshold}...[/]"
            );
            var (success, _, error) = await CommandExecutor.ExecuteAsync(
                "net",
                $"accounts /lockoutthreshold:{PasswordPolicyStandards.LockoutThreshold}"
            );

            if (success)
                fixes.Add(
                    $"Set account lockout threshold to {PasswordPolicyStandards.LockoutThreshold}"
                );
            else
                issues.Add($"Failed to set lockout threshold: {error}");
        }

        // Set lockout duration
        if (current.LockoutDuration < PasswordPolicyStandards.LockoutDuration)
        {
            AnsiConsole.MarkupLine(
                $"[yellow]Setting lockout duration to {PasswordPolicyStandards.LockoutDuration} minutes...[/]"
            );
            var (success, _, error) = await CommandExecutor.ExecuteAsync(
                "net",
                $"accounts /lockoutduration:{PasswordPolicyStandards.LockoutDuration}"
            );

            if (success)
                fixes.Add(
                    $"Set lockout duration to {PasswordPolicyStandards.LockoutDuration} minutes"
                );
            else
                issues.Add($"Failed to set lockout duration: {error}");
        }

        // Set lockout observation window
        if (current.LockoutObservationWindow < PasswordPolicyStandards.LockoutObservationWindow)
        {
            AnsiConsole.MarkupLine(
                $"[yellow]Setting lockout observation window to {PasswordPolicyStandards.LockoutObservationWindow} minutes...[/]"
            );
            var (success, _, error) = await CommandExecutor.ExecuteAsync(
                "net",
                $"accounts /lockoutwindow:{PasswordPolicyStandards.LockoutObservationWindow}"
            );

            if (success)
                fixes.Add(
                    $"Set lockout observation window to {PasswordPolicyStandards.LockoutObservationWindow} minutes"
                );
            else
                issues.Add($"Failed to set lockout observation window: {error}");
        }

        return (fixes, issues);
    }

    private async Task<(bool Success, string? Error)> EnablePasswordComplexityAsync()
    {
        // Export current security policy
        var tempFile = Path.Combine(Path.GetTempPath(), "secpol_temp.inf");
        var dbFile = Path.Combine(Path.GetTempPath(), "secpol_temp.sdb");

        try
        {
            // Export current policy
            var (exportSuccess, _, exportError) = await CommandExecutor.ExecuteAsync(
                "secedit",
                $"/export /cfg \"{tempFile}\""
            );

            if (!exportSuccess)
                return (false, exportError);

            // Read and modify the policy file
            var content = await File.ReadAllTextAsync(tempFile);

            // Modify password complexity setting
            if (content.Contains("PasswordComplexity = 0"))
            {
                content = content.Replace("PasswordComplexity = 0", "PasswordComplexity = 1");
            }
            else if (!content.Contains("PasswordComplexity"))
            {
                // Add the setting if it doesn't exist
                content = content.Replace(
                    "[System Access]",
                    "[System Access]\nPasswordComplexity = 1"
                );
            }

            // Also ensure reversible encryption is disabled
            if (content.Contains("ClearTextPassword = 1"))
            {
                content = content.Replace("ClearTextPassword = 1", "ClearTextPassword = 0");
            }

            await File.WriteAllTextAsync(tempFile, content);

            // Import the modified policy
            var (importSuccess, _, importError) = await CommandExecutor.ExecuteAsync(
                "secedit",
                $"/configure /db \"{dbFile}\" /cfg \"{tempFile}\" /areas SECURITYPOLICY"
            );

            // Cleanup temp files
            if (File.Exists(tempFile))
                File.Delete(tempFile);
            if (File.Exists(dbFile))
                File.Delete(dbFile);

            return (importSuccess, importError);
        }
        catch (Exception ex)
        {
            return (false, ex.Message);
        }
    }

    private int ExtractNumericValue(string line)
    {
        var parts = line.Split(':');
        if (parts.Length > 1)
        {
            var value = parts[1].Trim();

            // Handle "Never" or "Unlimited" cases
            if (
                value.Contains("Never", StringComparison.OrdinalIgnoreCase)
                || value.Contains("Unlimited", StringComparison.OrdinalIgnoreCase)
            )
            {
                return -1;
            }

            // Handle "None" case for lockout
            if (value.Contains("None", StringComparison.OrdinalIgnoreCase))
            {
                return 0;
            }

            // Extract just the numeric part
            var numericPart = new string(
                value.TakeWhile(c => char.IsDigit(c) || c == '-').ToArray()
            );
            if (int.TryParse(numericPart, out int result))
            {
                return result;
            }
        }
        return 0;
    }
}
