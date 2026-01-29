// =============================================================================
// CyberPatriot Automation Tool - Software Management Task
// Author: Maxwell McCormick
// Copyright (c) 2026 Maxwell McCormick. All Rights Reserved.
// =============================================================================
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Threading.Tasks;
using CyberPatriotAutomation.Core.Models;
using CyberPatriotAutomation.Core.Utilities;
using Spectre.Console;

namespace CyberPatriotAutomation.Core.Tasks;

/// <summary>
/// Removes prohibited software and installs required software as specified in the README
/// </summary>
public class SoftwareManagementTask : BaseTask
{
    public List<string> ProhibitedSoftware { get; set; } = new();
    public List<SoftwareRequirement> RequiredSoftware { get; set; } = new();

    // Helper for name-only matching
    private List<string> RequiredSoftwareNames => RequiredSoftware.Select(r => r.Name).ToList();

    public SoftwareManagementTask()
    {
        Name = "Software Management";
        Description =
            "Removes prohibited software and installs required software as specified in the README.";
    }

    public void SetReadmeData(ReadmeData? readme)
    {
        if (readme == null)
            return;
        ProhibitedSoftware = readme.ProhibitedSoftware?.ToList() ?? new List<string>();
        RequiredSoftware = readme.RequiredSoftware?.ToList() ?? new List<SoftwareRequirement>();
    }

    public override async Task<SystemInfo> ReadSystemStateAsync()
    {
        var (success, output, error) = await CommandExecutor.ExecuteAsync(
            "wmic",
            "product get name"
        );
        return new SystemInfo { RawOutput = output, ErrorOutput = error };
    }

    public override async Task<TaskResult> ExecuteAsync()
    {
        if (DryRun)
        {
            AnsiConsole.MarkupLine(
                "[yellow]DRY RUN: Previewing software management changes (no changes will be made)[/]"
            );
            return new TaskResult
            {
                TaskName = Name,
                Success = true,
                Message = "DRY RUN: Software management changes previewed.",
            };
        }

        var (success, output, error) = await CommandExecutor.ExecuteAsync(
            "wmic",
            "product get name"
        );
        if (!success)
        {
            AnsiConsole.MarkupLine($"[red]✗ Failed to list installed software: {error}[/]");
            return new TaskResult
            {
                TaskName = Name,
                Success = false,
                Message = error ?? "Unknown error",
            };
        }
        var installed = output
            .Split(new[] { '\n', '\r' }, StringSplitOptions.RemoveEmptyEntries)
            .Select(l => l.Trim())
            .Where(l => !string.IsNullOrWhiteSpace(l) && l != "Name")
            .ToList();
        var toRemove = installed
            .Where(i =>
                ProhibitedSoftware.Any(p => i.Contains(p, StringComparison.OrdinalIgnoreCase))
            )
            .ToList();
        var toInstall = RequiredSoftware
            .Where(r => !installed.Any(i => i.Contains(r.Name, StringComparison.OrdinalIgnoreCase)))
            .ToList();

        var details = new List<string>();
        // List all installed software checked
        details.Add($"Installed software checked: {string.Join(", ", installed)}");
        // List all prohibited software checked
        details.Add($"Prohibited software list: {string.Join(", ", ProhibitedSoftware)}");
        // List all required software checked
        details.Add(
            $"Required software list: {string.Join(", ", RequiredSoftware.Select(r => r.Name))}"
        );

        if (toRemove.Count > 0)
            details.Add($"To remove: {string.Join(", ", toRemove)}");
        else
            details.Add("No prohibited software found to remove.");

        if (toInstall.Count > 0)
            details.Add(
                $"Missing required software: {string.Join(", ", toInstall.Select(s => s.Name))}"
            );
        else
            details.Add("All required software is installed.");

        // Remove prohibited software
        foreach (var sw in toRemove)
        {
            var (remSuccess, _, remError) = await CommandExecutor.ExecuteAsync(
                "wmic",
                $"product where name=\"{sw}\" call uninstall /nointeractive"
            );
            if (remSuccess)
                AnsiConsole.MarkupLine($"[green]✓ Removed: {sw}[/]");
            else
                AnsiConsole.MarkupLine($"[red]✗ Failed to remove: {sw} ({remError})[/]");
        }
        // Install required software (assumes installer is available in a known location)
        foreach (var sw in toInstall)
        {
            // This is a placeholder; actual install logic may require more info
            AnsiConsole.MarkupLine(
                $"[yellow]Required software not installed: {sw.Name} (manual install may be needed)[/]"
            );
        }
        return new TaskResult
        {
            TaskName = Name,
            Success = toRemove.Count == 0 && toInstall.Count == 0,
            Message = string.Join("\n", details),
        };
    }

    public override async Task<bool> VerifyAsync()
    {
        var (success, output, error) = await CommandExecutor.ExecuteAsync(
            "wmic",
            "product get name"
        );
        var installed = output
            .Split(new[] { '\n', '\r' }, StringSplitOptions.RemoveEmptyEntries)
            .Select(l => l.Trim())
            .Where(l => !string.IsNullOrWhiteSpace(l) && l != "Name")
            .ToList();
        var stillPresent = installed.Any(i =>
            ProhibitedSoftware.Any(p => i.Contains(p, StringComparison.OrdinalIgnoreCase))
        );
        var stillMissing = RequiredSoftware.Any(r =>
            !installed.Any(i => i.Contains(r.Name, StringComparison.OrdinalIgnoreCase))
        );
        return !stillPresent && !stillMissing;
    }
}
