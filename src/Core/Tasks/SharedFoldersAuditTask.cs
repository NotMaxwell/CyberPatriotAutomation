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
        var allowed = new[] { "ADMIN$", "C$", "IPC$" };
        var found = ParseShares(output ?? string.Empty);
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

        var removed = new List<string>();
        var failures = new List<string>();

        foreach (var share in unauthorized)
        {
            var (delSuccess, _, delErr) = await CommandExecutor.ExecuteAsync(
                "net",
                $"share {share} /delete"
            );
            if (delSuccess)
            {
                removed.Add(share);
                AnsiConsole.MarkupLine($"[green]✓ Removed share: {Markup.Escape(share)}[/]");
            }
            else
            {
                failures.Add($"{share}: {delErr}");
                AnsiConsole.MarkupLine(
                    $"[red]✗ Failed to remove share: {Markup.Escape(share)} ({Markup.Escape(delErr ?? "")})[/]"
                );
            }
        }

        details.Add(
            removed.Count > 0
                ? $"Removed: {string.Join(", ", removed)}"
                : "No shares needed removal."
        );
        if (failures.Count > 0)
            details.Add($"Failed to remove: {string.Join("; ", failures)}");

        return new TaskResult
        {
            TaskName = Name,
            // Success means the remediation went through. The previous
            // `unauthorized.Count == 0` reported failure precisely when the task
            // had found and removed offending shares.
            Success = failures.Count == 0,
            Message = string.Join("\n", details),
            ErrorDetails = failures.Count > 0 ? string.Join("\n", failures) : null,
        };
    }

    /// <summary>
    /// Extract share names from <c>net share</c> output.
    /// </summary>
    /// <remarks>
    /// The output is a table wrapped in a header and a trailing status line.
    /// Taking the first token of every line containing a space also picked up
    /// "Share" from the header and "The" from "The command completed
    /// successfully.", so the task tried to <c>net share Share /delete</c> on
    /// entries that were never shares. Read only the rows between the separator
    /// and the status line.
    /// </remarks>
    public static List<string> ParseShares(string output)
    {
        var shares = new List<string>();
        var pastSeparator = false;

        foreach (var raw in output.Split('\n'))
        {
            var line = raw.Trim();
            if (line.Length == 0)
                continue;

            if (line.StartsWith("---", StringComparison.Ordinal))
            {
                pastSeparator = true;
                continue;
            }

            if (!pastSeparator)
                continue;

            if (line.StartsWith("The command completed", StringComparison.OrdinalIgnoreCase))
                break;

            var name = line.Split(
                (char[]?)null,
                StringSplitOptions.RemoveEmptyEntries
            ).FirstOrDefault();
            if (!string.IsNullOrWhiteSpace(name))
                shares.Add(name);
        }

        return shares;
    }

    public override async Task<bool> VerifyAsync()
    {
        var (success, output, error) = await CommandExecutor.ExecuteAsync("net", "share");
        var lines = output?.Split('\n') ?? Array.Empty<string>();
        var allowed = new[] { "ADMIN$", "C$", "IPC$" };
        var found = ParseShares(output ?? string.Empty);
        var unauthorized = found.Except(allowed, StringComparer.OrdinalIgnoreCase).ToList();
        return unauthorized.Count == 0;
    }
}
