// =============================================================================
// CyberPatriot Automation Tool - Hosts File Audit Task
// Author: Maxwell McCormick
// Copyright (c) 2026 Maxwell McCormick. All Rights Reserved.
// =============================================================================
using System;
using System.IO;
using System.Linq;
using System.Threading.Tasks;
using CyberPatriotAutomation.Core.Models;
using CyberPatriotAutomation.Core.Utilities;
using Spectre.Console;

namespace CyberPatriotAutomation.Core.Tasks;

/// <summary>
/// Audits the Windows hosts file for unauthorized entries
/// </summary>
public class HostsFileAuditTask : BaseTask
{
    private const string HostsFilePath = @"C:\Windows\System32\drivers\etc\hosts";
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
            .Except(AllowedEntries, StringComparer.OrdinalIgnoreCase)
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

        // Remove unauthorized entries
        var newLines = lines
            .Where(l =>
                string.IsNullOrWhiteSpace(l)
                || l.Trim().StartsWith("#")
                || AllowedEntries.Contains(l.Trim(), StringComparer.OrdinalIgnoreCase)
            )
            .ToArray();
        try
        {
            await File.WriteAllLinesAsync(HostsFilePath, newLines);
            if (unauthorized.Count > 0)
                details.Add($"Removed: {string.Join(", ", unauthorized)}");
            else
                details.Add("No entries needed removal.");
            AnsiConsole.MarkupLine(
                $"[green]✓ Removed unauthorized hosts entries: {string.Join(", ", unauthorized)}[/]"
            );
            return new TaskResult
            {
                TaskName = Name,
                Success = unauthorized.Count == 0,
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
            .Except(AllowedEntries, StringComparer.OrdinalIgnoreCase)
            .ToList();
        return unauthorized.Count == 0;
    }
}
