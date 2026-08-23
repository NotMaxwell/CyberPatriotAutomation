using PinnacleCyPat.Core.Models;
using PinnacleCyPat.Core.Utilities;
using Spectre.Console;

namespace PinnacleCyPat.Core.Tasks;

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
            AnsiConsole.MarkupLine("[red]✗ Minimum password length not set correctly[/]");
            allGood = false;
        }

        if (
            verifiedPolicy.MaxPasswordAge > PasswordPolicyStandards.MaxPasswordAge
            || verifiedPolicy.MaxPasswordAge == 0
        )
        {
            AnsiConsole.MarkupLine("[red]✗ Maximum password age not set correctly[/]");
            allGood = false;
        }

        if (!verifiedPolicy.ComplexityEnabled)
        {
            AnsiConsole.MarkupLine("[red]✗ Password complexity not enabled[/]");
            allGood = false;
        }

        if (
            verifiedPolicy.LockoutThreshold == 0
            || verifiedPolicy.LockoutThreshold > PasswordPolicyStandards.LockoutThreshold
        )
        {
            AnsiConsole.MarkupLine("[red]✗ Account lockout threshold not set correctly[/]");
            allGood = false;
        }

        if (allGood)
        {
            AnsiConsole.MarkupLine("[green]✓ All password policy settings verified[/]");
        }

        return allGood;
    }

    private async Task<PasswordPolicyInfo> GetCurrentPasswordPolicyAsync()
    {
        var policy = new PasswordPolicyInfo();

#if WINDOWS
        // Read the policy as data first. `net accounts` prints a localised table,
        // and on a non-English image every line test below fails to match, which
        // leaves the policy at its zero defaults and reads as "already compliant".
        var nativePolicy = Native.NativeAccounts.GetPasswordPolicy();
        if (nativePolicy is { } n)
        {
            policy.MinPasswordLength = n.MinPasswordLength;
            policy.MaxPasswordAge = n.MaxPasswordAgeDays;
            policy.MinPasswordAge = n.MinPasswordAgeDays;
            policy.PasswordHistoryCount = n.PasswordHistoryLength;
            policy.LockoutThreshold = n.LockoutThreshold;
            policy.LockoutDuration = n.LockoutDurationMinutes;
            policy.LockoutObservationWindow = n.LockoutObservationMinutes;
        }
        else
#endif
        {
            // Fallback: parse the table `net accounts` prints. Matches an
            // English-language console only, which is why it is the fallback.
            // The parser lives on the model so PolicyOps reads its evidence the
            // same way rather than through a second one that could disagree.
            var (success, output, _) = await CommandExecutor.ExecuteAsync("net", "accounts");
            if (success && !string.IsNullOrEmpty(output))
                policy = PasswordPolicyInfo.ParseNetAccounts(output);
        }

        // Check password complexity via secedit (requires admin).
        //
        // The path is expanded here rather than written as %TEMP%. Process
        // arguments are passed to the child verbatim - ProcessStartInfo does no
        // environment expansion when UseShellExecute is false - so `secedit`
        // received the literal string "%TEMP%\secpol.cfg", could not create it,
        // and exited 2 on every run. Complexity therefore always read as
        // disabled, and the comparison table always reported "No" no matter how
        // the machine was configured.
        var exportPath = Path.Combine(Path.GetTempPath(), "secpol_read.cfg");
        var (secSuccess, _, _) = await CommandExecutor.ExecuteAsync(
            "secedit",
            $"/export /cfg \"{exportPath}\" /quiet"
        );
        if (secSuccess)
        {
            try
            {
                // Read it directly instead of shelling out to `cmd /c type`,
                // which had the same unexpanded-variable problem.
                var cfgOutput = await File.ReadAllTextAsync(exportPath);
                if (cfgOutput.Contains("PasswordComplexity"))
                    policy.ComplexityEnabled = cfgOutput.Contains("PasswordComplexity = 1");
            }
            catch (Exception ex)
            {
                RunLog.Diagnostic("password", $"could not read the exported policy: {ex.Message}");
            }
            finally
            {
                try
                {
                    if (File.Exists(exportPath))
                        File.Delete(exportPath);
                }
                catch
                {
                    // A leftover temp file is not worth failing the task over.
                }
            }
        }
        else
        {
            RunLog.Diagnostic(
                "password",
                "secedit export failed; password complexity could not be read"
            );
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
        var status = isCompliant ? "[green]✓ OK[/]" : "[red]✗ Fix[/]";
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
            var error = await PolicyOps.SetMinPasswordLengthAsync(
                PasswordPolicyStandards.MinPasswordLength
            );

            if (error is null)
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
            var error = await PolicyOps.SetMaxPasswordAgeDaysAsync(
                PasswordPolicyStandards.MaxPasswordAge
            );

            if (error is null)
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
            var error = await PolicyOps.SetMinPasswordAgeDaysAsync(
                PasswordPolicyStandards.MinPasswordAge
            );

            if (error is null)
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
            var error = await PolicyOps.SetPasswordHistoryLengthAsync(
                PasswordPolicyStandards.PasswordHistoryCount
            );

            if (error is null)
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
            var error = await PolicyOps.SetLockoutThresholdAsync(
                PasswordPolicyStandards.LockoutThreshold
            );

            if (error is null)
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
            var error = await PolicyOps.SetLockoutDurationMinutesAsync(
                PasswordPolicyStandards.LockoutDuration
            );

            if (error is null)
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
            var error = await PolicyOps.SetLockoutObservationMinutesAsync(
                PasswordPolicyStandards.LockoutObservationWindow
            );

            if (error is null)
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
}
