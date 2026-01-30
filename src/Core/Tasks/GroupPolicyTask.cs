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
        Description = "Configures Group Policy settings: Hide last user, require Ctrl+Alt+Del, disable ICS, and more.";
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
        var details = new List<string>();
        bool allSuccess = true;

        // 1. Don't display last user name
        var (hideUserSuccess, _, hideUserError) = await CommandExecutor.ExecuteAsync(
            "reg",
            "add HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System /v dontdisplaylastusername /t REG_DWORD /d 1 /f"
        );
        details.Add(hideUserSuccess ? "✓ Don't display last user name set" : $"✗ Failed: {hideUserError}");
        allSuccess &= hideUserSuccess;

        // 2. Require Ctrl+Alt+Del
        var (ctrlAltDelSuccess, _, ctrlAltDelError) = await CommandExecutor.ExecuteAsync(
            "reg",
            "add HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System /v DisableCAD /t REG_DWORD /d 0 /f"
        );
        details.Add(ctrlAltDelSuccess ? "✓ Require Ctrl+Alt+Del set" : $"✗ Failed: {ctrlAltDelError}");
        allSuccess &= ctrlAltDelSuccess;

        // 3. Disable ICS (Internet Connection Sharing)
        var (icsSuccess, _, icsError) = await CommandExecutor.ExecuteAsync(
            "sc",
            "config SharedAccess start= disabled"
        );
        details.Add(icsSuccess ? "✓ ICS (Internet Connection Sharing) disabled" : $"✗ Failed: {icsError}");
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

    public override async Task<bool> VerifyAsync()
    {
        // Check all registry/service settings
        var (hideUserSuccess, _, _) = await CommandExecutor.ExecuteAsync(
            "reg",
            "query HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System /v dontdisplaylastusername"
        );
        var (ctrlAltDelSuccess, _, _) = await CommandExecutor.ExecuteAsync(
            "reg",
            "query HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System /v DisableCAD"
        );
        var (icsSuccess, _, _) = await CommandExecutor.ExecuteAsync(
            "sc",
            "qc SharedAccess"
        );
        var (anonSuccess, _, _) = await CommandExecutor.ExecuteAsync(
            "reg",
            "query HKLM\\SYSTEM\\CurrentControlSet\\Control\\Lsa /v restrictanonymous"
        );
        return hideUserSuccess && ctrlAltDelSuccess && icsSuccess && anonSuccess;
    }
}
