// =============================================================================
// CyberPatriot Automation Tool - Group Policy Task
// Author: Maxwell McCormick
// Copyright (c) 2026 Maxwell McCormick. All Rights Reserved.
// =============================================================================
using System;
using System.Collections.Generic;
using System.Threading.Tasks;
using CyberPatriotAutomation.Core.Models;
using CyberPatriotAutomation.Core.Utilities;
using Spectre.Console;

namespace CyberPatriotAutomation.Core.Tasks;

/// <summary>
/// Configures key Group Policy (gpedit) settings for security hardening.
/// </summary>
public class GroupPolicyTask : BaseTask
{
    public GroupPolicyTask()
    {
        Name = "Group Policy";
        Description =
            "Configures Group Policy settings: Hide last user, require Ctrl+Alt+Del, disable ICS, and more.";
    }

    public override async Task<SystemInfo> ReadSystemStateAsync()
    {
        var (success, output, error) = await CommandExecutor.ExecuteAsync(
            "reg",
            "query HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System"
        );
        return new SystemInfo { RawOutput = output, ErrorOutput = error };
    }

    public override async Task<TaskResult> ExecuteAsync()
    {
        if (DryRun)
        {
            AnsiConsole.MarkupLine(
                "[yellow]DRY RUN: Previewing Group Policy changes (no changes will be made)[/]"
            );
            return new TaskResult
            {
                TaskName = Name,
                Success = true,
                Message =
                    "DRY RUN: Would apply:\n✓ Don't display last user name set\n✓ Require Ctrl+Alt+Del set\n✓ ICS (Internet Connection Sharing) disabled\n✓ Restrict anonymous access set",
            };
        }

        var details = new List<string>();
        bool allSuccess = true;

        // 1. Don't display last user name
        var (hideUserSuccess, _, hideUserError) = await CommandExecutor.ExecuteAsync(
            "reg",
            "add HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System /v dontdisplaylastusername /t REG_DWORD /d 1 /f"
        );
        details.Add(
            hideUserSuccess ? "✓ Don't display last user name set" : $"✗ Failed: {hideUserError}"
        );
        allSuccess &= hideUserSuccess;

        // 2. Require Ctrl+Alt+Del
        var (ctrlAltDelSuccess, _, ctrlAltDelError) = await CommandExecutor.ExecuteAsync(
            "reg",
            "add HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System /v DisableCAD /t REG_DWORD /d 0 /f"
        );
        details.Add(
            ctrlAltDelSuccess ? "✓ Require Ctrl+Alt+Del set" : $"✗ Failed: {ctrlAltDelError}"
        );
        allSuccess &= ctrlAltDelSuccess;

        // 3. Disable ICS (Internet Connection Sharing)
        var (icsSuccess, _, icsError) = await CommandExecutor.ExecuteAsync(
            "sc",
            "config SharedAccess start= disabled"
        );
        details.Add(
            icsSuccess ? "✓ ICS (Internet Connection Sharing) disabled" : $"✗ Failed: {icsError}"
        );
        allSuccess &= icsSuccess;

        // 4. Additional local security policies (example: restrict anonymous access)
        var (anonSuccess, _, anonError) = await CommandExecutor.ExecuteAsync(
            "reg",
            "add HKLM\\SYSTEM\\CurrentControlSet\\Control\\Lsa /v restrictanonymous /t REG_DWORD /d 1 /f"
        );
        details.Add(anonSuccess ? "✓ Restrict anonymous access set" : $"✗ Failed: {anonError}");
        allSuccess &= anonSuccess;

        return new TaskResult
        {
            TaskName = Name,
            Success = allSuccess,
            Message = string.Join("\n", details),
        };
    }

    /// <summary>
    /// Read a REG_DWORD value out of <c>reg query</c> output.
    /// </summary>
    /// <remarks>
    /// The value appears on its own indented line, e.g.
    /// <c>    dontdisplaylastusername    REG_DWORD    0x1</c>.
    /// </remarks>
    public static uint? ParseRegDword(string output, string name)
    {
        foreach (
            var line in output.Split(new[] { '\r', '\n' }, StringSplitOptions.RemoveEmptyEntries)
        )
        {
            var fields = line.Split((char[]?)null, StringSplitOptions.RemoveEmptyEntries);
            if (
                fields.Length >= 3
                && fields[0].Equals(name, StringComparison.OrdinalIgnoreCase)
                && fields[1].Equals("REG_DWORD", StringComparison.OrdinalIgnoreCase)
            )
            {
                var raw = fields[2];
                if (
                    raw.StartsWith("0x", StringComparison.OrdinalIgnoreCase)
                    && uint.TryParse(
                        raw[2..],
                        System.Globalization.NumberStyles.HexNumber,
                        System.Globalization.CultureInfo.InvariantCulture,
                        out var hex
                    )
                )
                    return hex;
                if (uint.TryParse(raw, out var dec))
                    return dec;
            }
        }
        return null;
    }

    /// <summary>Confirm a registry value is present *and* set to the expected value.</summary>
    private static async Task<bool> RegDwordEqualsAsync(string key, string name, uint expected)
    {
        var (success, output, _) = await CommandExecutor.ExecuteAsync(
            "reg",
            $"query {key} /v {name}"
        );
        return success && ParseRegDword(output, name) == expected;
    }

    public override async Task<bool> VerifyAsync()
    {
        // These checks previously only asserted that `reg query` / `sc qc` exited
        // successfully, which is true whenever the value merely *exists*. A
        // setting left at the wrong value therefore verified as correct.
        const string policies =
            "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System";
        const string lsa = "HKLM\\SYSTEM\\CurrentControlSet\\Control\\Lsa";

        var hideUserOk = await RegDwordEqualsAsync(policies, "dontdisplaylastusername", 1);
        // DisableCAD = 0 means Ctrl+Alt+Del *is* required.
        var ctrlAltDelOk = await RegDwordEqualsAsync(policies, "DisableCAD", 0);
        var anonOk = await RegDwordEqualsAsync(lsa, "restrictanonymous", 1);

        var (scSuccess, scOutput, _) = await CommandExecutor.ExecuteAsync("sc", "qc SharedAccess");
        // `sc qc` prints e.g. "START_TYPE : 4   DISABLED".
        var icsOk =
            scSuccess
            && scOutput
                .Split(new[] { '\r', '\n' }, StringSplitOptions.RemoveEmptyEntries)
                .Any(l =>
                    l.Contains("START_TYPE", StringComparison.OrdinalIgnoreCase)
                    && l.Contains("DISABLED", StringComparison.OrdinalIgnoreCase)
                );

        if (!hideUserOk)
            AnsiConsole.MarkupLine("[red]? 'Don't display last user name' is not set[/]");
        if (!ctrlAltDelOk)
            AnsiConsole.MarkupLine("[red]? Ctrl+Alt+Del is not required at logon[/]");
        if (!anonOk)
            AnsiConsole.MarkupLine("[red]? Anonymous access is not restricted[/]");
        if (!icsOk)
            AnsiConsole.MarkupLine("[red]? Internet Connection Sharing is not disabled[/]");

        return hideUserOk && ctrlAltDelOk && anonOk && icsOk;
    }
}
