// =============================================================================
// PinnacleCyPat - Hosts File Audit Task
// Author: Maxwell McCormick
// Copyright (c) 2026 Maxwell McCormick. All Rights Reserved.
// =============================================================================
using System;
using System.IO;
using System.Linq;
using System.Threading.Tasks;
using PinnacleCyPat.Core.Models;
using PinnacleCyPat.Core.Utilities;
using Spectre.Console;

namespace PinnacleCyPat.Core.Tasks;

/// <summary>
/// Audits the Windows hosts file for unauthorized entries
/// </summary>
public class HostsFileAuditTask : BaseTask
{
    private const string HostsFilePath = @"C:\Windows\System32\drivers\etc\hosts";

    /// <summary>
    /// Collapse runs of whitespace so entries compare on content, not formatting.
    /// </summary>
    /// <remarks>
    /// <see cref="AllowedEntries"/> is written with a fixed run of spaces.
    /// Comparing raw strings meant a hosts file using a tab or a different number
    /// of spaces - entirely normal - failed to match, so the legitimate localhost
    /// mapping was classified as unauthorized and deleted.
    /// </remarks>
    private static string NormalizeEntry(string line) =>
        string.Join(' ', line.Split((char[]?)null, StringSplitOptions.RemoveEmptyEntries));

    public static bool IsAllowedEntry(string line)
    {
        var normalized = NormalizeEntry(line);
        return AllowedEntries.Any(a =>
            NormalizeEntry(a).Equals(normalized, StringComparison.OrdinalIgnoreCase)
        );
    }

    private static readonly string[] AllowedEntries = new[]
    {
        "127.0.0.1       localhost",
        "::1             localhost",
    };

    public HostsFileAuditTask()
    {
        Name = "Hosts File Audit";
        Description = "Audits the Windows hosts file for unauthorized entries.";
    }

    public override async Task<SystemInfo> ReadSystemStateAsync()
    {
        string[] lines = Array.Empty<string>();
        string? error = null;
        try
        {
            lines = await File.ReadAllLinesAsync(HostsFilePath);
        }
        catch (Exception ex)
        {
            error = ex.Message;
        }
        return new SystemInfo { RawOutput = string.Join("\n", lines), ErrorOutput = error };
    }

    public override async Task<TaskResult> ExecuteAsync()
    {
        string[] lines;
        try
        {
            lines = await File.ReadAllLinesAsync(HostsFilePath);
        }
        catch (Exception ex)
        {
            AnsiConsole.MarkupLine($"[red]✗ Failed to read hosts file: {ex.Message}[/]");
            return new TaskResult
            {
                TaskName = Name,
                Success = false,
                Message = ex.Message,
            };
        }
        var unauthorized = lines
            .Select(l => l.Trim())
            .Where(l => !string.IsNullOrWhiteSpace(l) && !l.StartsWith("#"))
            .Where(l => !IsAllowedEntry(l))
            .ToList();

        var details = new List<string>();
        details.Add(
            $"Hosts file entries found: {string.Join(", ", lines.Select(l => l.Trim()).Where(l => !string.IsNullOrWhiteSpace(l)))}"
        );
        details.Add($"Allowed entries: {string.Join(", ", AllowedEntries)}");
        if (unauthorized.Count > 0)
            details.Add($"Unauthorized entries: {string.Join(", ", unauthorized)}");
        else
            details.Add("No unauthorized hosts entries found.");

        if (DryRun)
        {
            AnsiConsole.MarkupLine(
                "[yellow]DRY RUN: Previewing hosts file audit (no changes will be made)[/]"
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

        // Nothing to do - don't rewrite a system file for no reason.
        if (unauthorized.Count == 0)
        {
            details.Add("No entries needed removal.");
            AnsiConsole.MarkupLine("[green]✓ No unauthorized hosts entries found[/]");
            return new TaskResult
            {
                TaskName = Name,
                Success = true,
                Message = string.Join("\n", details),
            };
        }

        // Remove unauthorized entries
        var newLines = lines
            .Where(l =>
                string.IsNullOrWhiteSpace(l) || l.Trim().StartsWith("#") || IsAllowedEntry(l.Trim())
            )
            .ToArray();
        try
        {
            await File.WriteAllLinesAsync(HostsFilePath, newLines);
            details.Add($"Removed: {string.Join(", ", unauthorized)}");
            AnsiConsole.MarkupLine(
                $"[green]✓ Removed unauthorized hosts entries: {string.Join(", ", unauthorized)}[/]"
            );
            return new TaskResult
            {
                TaskName = Name,
                // Success reflects the remediation having been applied. The
                // previous `unauthorized.Count == 0` inverted this: cleaning up
                // entries reported the task as failed, and only a file needing no
                // work at all counted as a success.
                Success = true,
                Message = string.Join("\n", details),
            };
        }
        catch (Exception ex)
        {
            AnsiConsole.MarkupLine($"[red]✗ Failed to update hosts file: {ex.Message}[/]");
            details.Add($"Failed to update hosts file: {ex.Message}");
            return new TaskResult
            {
                TaskName = Name,
                Success = false,
                Message = string.Join("\n", details),
            };
        }
    }

    public override async Task<bool> VerifyAsync()
    {
        string[] lines;
        try
        {
            lines = await File.ReadAllLinesAsync(HostsFilePath);
        }
        catch
        {
            return false;
        }
        var unauthorized = lines
            .Select(l => l.Trim())
            .Where(l => !string.IsNullOrWhiteSpace(l) && !l.StartsWith("#"))
            .Where(l => !IsAllowedEntry(l))
            .ToList();
        return unauthorized.Count == 0;
    }
}
