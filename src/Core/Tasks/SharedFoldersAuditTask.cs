// =============================================================================
// CyberPatriot Automation Tool - Shared Folders Audit Task
// Author: Maxwell McCormick
// Copyright (c) 2026 Maxwell McCormick. All Rights Reserved.
// =============================================================================
using System.Threading.Tasks;
using CyberPatriotAutomation.Core.Models;
using CyberPatriotAutomation.Core.Utilities;
using Spectre.Console;

namespace CyberPatriotAutomation.Core.Tasks;

/// <summary>
/// Audits shared folders to ensure only ADMIN$, C$, IPC$ exist
/// </summary>
public class SharedFoldersAuditTask : BaseTask
{
    public SharedFoldersAuditTask()
    {
        Name = "Shared Folders Audit";
        Description = "Audits shared folders (fsmgmt.msc) to ensure only ADMIN$, C$, IPC$ exist.";
    }

    public override async Task<SystemInfo> ReadSystemStateAsync()
    {
        var (success, output, error) = await CommandExecutor.ExecuteAsync("net", "share");
        return new SystemInfo { RawOutput = output, ErrorOutput = error };
    }

    public override async Task<TaskResult> ExecuteAsync()
    {
        var (success, output, error) = await CommandExecutor.ExecuteAsync("net", "share");
        var lines = output?.Split('\n') ?? Array.Empty<string>();
        var allowed = new[] { "ADMIN$", "C$", "IPC$" };
        var found = lines
            .Where(l => l.Contains(" "))
            .Select(l => l.Split(' ')[0].Trim())
            .Where(s => !string.IsNullOrWhiteSpace(s))
            .ToList();
        var unauthorized = found.Except(allowed, StringComparer.OrdinalIgnoreCase).ToList();

        var details = new List<string>();
        details.Add($"Shares found: {string.Join(", ", found)}");
        details.Add($"Allowed shares: {string.Join(", ", allowed)}");
        if (unauthorized.Count > 0)
            details.Add($"Unauthorized shares: {string.Join(", ", unauthorized)}");
        else
            details.Add("No unauthorized shares found.");

        if (DryRun)
        {
            AnsiConsole.MarkupLine(
                "[yellow]DRY RUN: Previewing shared folders audit (no changes will be made)[/]"
            );
            if (unauthorized.Count > 0)
                details.Add($"Would remove: {string.Join(", ", unauthorized)}");
            return new TaskResult
            {
                TaskName = Name,
                Success = true,
                Message = string.Join("\n", details),
            };
        }

        foreach (var share in unauthorized)
        {
            var (delSuccess, delOut, delErr) = await CommandExecutor.ExecuteAsync(
                "net",
                $"share {share} /delete"
            );
            if (delSuccess)
                AnsiConsole.MarkupLine($"[green]✓ Removed share: {share}[/]");
            else
                AnsiConsole.MarkupLine($"[red]✗ Failed to remove share: {share} ({delErr})[/]");
        }
        if (unauthorized.Count > 0)
            details.Add($"Removed: {string.Join(", ", unauthorized)}");
        else
            details.Add("No shares needed removal.");

        return new TaskResult
        {
            TaskName = Name,
            Success = unauthorized.Count == 0,
            Message = string.Join("\n", details),
        };
    }

    public override async Task<bool> VerifyAsync()
    {
        var (success, output, error) = await CommandExecutor.ExecuteAsync("net", "share");
        var lines = output?.Split('\n') ?? Array.Empty<string>();
        var allowed = new[] { "ADMIN$", "C$", "IPC$" };
        var found = lines
            .Where(l => l.Contains(" "))
            .Select(l => l.Split(' ')[0].Trim())
            .Where(s => !string.IsNullOrWhiteSpace(s))
            .ToList();
        var unauthorized = found.Except(allowed, StringComparer.OrdinalIgnoreCase).ToList();
        return unauthorized.Count == 0;
    }
}
