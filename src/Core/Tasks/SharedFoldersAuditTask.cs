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
        if (unauthorized.Count == 0)
        {
            AnsiConsole.MarkupLine("[green]✓ No unauthorized shares found[/]");
            return new TaskResult
            {
                TaskName = Name,
                Success = true,
                Message = "No unauthorized shares found.",
            };
        }
        // No dryRun support in base signature; always perform action
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
        return new TaskResult
        {
            TaskName = Name,
            Success = unauthorized.Count == 0,
            Message =
                unauthorized.Count == 0
                    ? "All shares valid."
                    : $"Removed: {string.Join(", ", unauthorized)}",
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
