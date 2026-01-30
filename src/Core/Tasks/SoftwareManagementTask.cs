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
/// Removes prohibited software, installs required software as specified in the README,
/// and runs Windows Defender malware scans
/// </summary>
public class SoftwareManagementTask : BaseTask
{
    public List<string> ProhibitedSoftware { get; set; } = new();
    public List<SoftwareRequirement> RequiredSoftware { get; set; } = new();
    public bool RunMalwareScan { get; set; } = true;
    public bool UseQuickScan { get; set; } = true; // Quick scan by default, set false for full scan

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

        // Run Windows Defender malware scan
        var malwareScanSuccess = true;
        var threatsFound = 0;
        if (RunMalwareScan)
        {
            var scanResult = await RunWindowsDefenderScanAsync();
            malwareScanSuccess = scanResult.Success;
            threatsFound = scanResult.ThreatsFound;
            details.Add(scanResult.Message);
        }

        return new TaskResult
        {
            TaskName = Name,
            Success = toRemove.Count == 0 && toInstall.Count == 0 && malwareScanSuccess && threatsFound == 0,
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

    /// <summary>
    /// Runs a Windows Defender malware scan and returns the results
    /// </summary>
    private async Task<(bool Success, int ThreatsFound, string Message)> RunWindowsDefenderScanAsync()
    {
        var scanType = UseQuickScan ? "QuickScan" : "FullScan";
        AnsiConsole.MarkupLine($"[blue]Running Windows Defender {scanType}...[/]");

        // Update Windows Defender signatures first
        var (updateSuccess, _, updateError) = await CommandExecutor.ExecuteAsync(
            "powershell",
            "-Command \"Update-MpSignature -ErrorAction SilentlyContinue\""
        );
        if (updateSuccess)
            AnsiConsole.MarkupLine("[green]✓ Windows Defender signatures updated[/]");
        else
            AnsiConsole.MarkupLine($"[yellow]⚠ Could not update signatures: {updateError}[/]");

        // Run the scan
        var (scanSuccess, scanOutput, scanError) = await CommandExecutor.ExecuteAsync(
            "powershell",
            $"-Command \"Start-MpScan -ScanType {scanType}\""
        );

        if (!scanSuccess)
        {
            AnsiConsole.MarkupLine($"[red]✗ Windows Defender scan failed: {scanError}[/]");
            return (false, 0, $"Windows Defender scan failed: {scanError}");
        }

        AnsiConsole.MarkupLine($"[green]✓ Windows Defender {scanType} completed[/]");

        // Check for detected threats
        var (threatSuccess, threatOutput, _) = await CommandExecutor.ExecuteAsync(
            "powershell",
            "-Command \"Get-MpThreatDetection | Select-Object -Property ThreatID, ActionSuccess | ConvertTo-Json\""
        );

        var threatsFound = 0;
        if (threatSuccess && !string.IsNullOrWhiteSpace(threatOutput) && threatOutput.Trim() != "")
        {
            // Count threats - if output is not empty/null, there are threats
            // Simple count by looking for ThreatID occurrences
            threatsFound = threatOutput.Split("ThreatID").Length - 1;
            if (threatsFound > 0)
            {
                AnsiConsole.MarkupLine($"[red]⚠ Windows Defender found {threatsFound} threat(s)[/]");

                // Attempt to remove detected threats
                var (removeSuccess, _, removeError) = await CommandExecutor.ExecuteAsync(
                    "powershell",
                    "-Command \"Remove-MpThreat -ErrorAction SilentlyContinue\""
                );
                if (removeSuccess)
                    AnsiConsole.MarkupLine("[green]✓ Attempted to remove detected threats[/]");
                else
                    AnsiConsole.MarkupLine($"[yellow]⚠ Could not auto-remove threats: {removeError}[/]");
            }
        }

        if (threatsFound == 0)
            AnsiConsole.MarkupLine("[green]✓ No threats detected by Windows Defender[/]");

        return (true, threatsFound, $"Windows Defender {scanType}: {(threatsFound > 0 ? $"{threatsFound} threat(s) found" : "No threats detected")}");
    }
}
