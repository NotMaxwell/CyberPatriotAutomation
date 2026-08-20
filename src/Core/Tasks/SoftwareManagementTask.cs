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
    /// <summary>A full or quick Defender scan runs for many minutes.</summary>
    private static readonly TimeSpan ScanTimeout = TimeSpan.FromHours(1);

    /// <summary>
    /// `wmic product` is notoriously slow - minutes on a populated machine.
    /// </summary>
    private static readonly TimeSpan InventoryTimeout = TimeSpan.FromMinutes(10);

    public List<string> ProhibitedSoftware { get; set; } = new();
    public List<SoftwareRequirement> RequiredSoftware { get; set; } = new();

    /// <summary>
    /// Upgrade already-installed Chocolatey packages as part of the run.
    /// </summary>
    /// <remarks>
    /// Out-of-date software is scored separately from missing software, so this
    /// defaults on. It only runs when Chocolatey is already present.
    /// </remarks>
    public bool UpdateInstalledSoftware { get; set; } = true;

    /// <summary>
    /// Chocolatey package ids for the software READMEs ask for by display name.
    /// </summary>
    /// <remarks>
    /// A README says "Mozilla Firefox"; the package is "firefox". Without the
    /// mapping every install would look up a package that does not exist. Names
    /// not listed fall through to a normalised form of the display name, which is
    /// right often enough to be worth trying before reporting a failure.
    /// </remarks>
    private static readonly Dictionary<string, string> PackageIds = new(
        StringComparer.OrdinalIgnoreCase
    )
    {
        ["Mozilla Firefox"] = "firefox",
        ["Firefox"] = "firefox",
        ["Google Chrome"] = "googlechrome",
        ["Chrome"] = "googlechrome",
        ["7-Zip"] = "7zip",
        ["7Zip"] = "7zip",
        ["Notepad++"] = "notepadplusplus",
        ["VLC"] = "vlc",
        ["VLC media player"] = "vlc",
        ["Wireshark"] = "wireshark",
        ["PuTTY"] = "putty",
        ["Python"] = "python",
        ["Adobe Acrobat Reader DC"] = "adobereader",
        ["Adobe Reader"] = "adobereader",
        ["Microsoft Edge"] = "microsoft-edge",
        ["Thunderbird"] = "thunderbird",
        ["Mozilla Thunderbird"] = "thunderbird",
        ["LibreOffice"] = "libreoffice-fresh",
        ["Git"] = "git",
        ["Malwarebytes"] = "malwarebytes",
    };

    /// <summary>The Chocolatey package id to install for a requirement.</summary>
    private static string PackageIdFor(SoftwareRequirement requirement)
    {
        if (PackageIds.TryGetValue(requirement.Name, out var mapped))
            return mapped;

        // Chocolatey ids are lower-case and unspaced; this is a best effort for
        // anything the table does not name explicitly.
        return new string(
            requirement
                .Name.ToLowerInvariant()
                .Where(c => char.IsLetterOrDigit(c) || c == '-' || c == '.')
                .ToArray()
        );
    }

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

    /// <summary>
    /// The installed-software list, from the uninstall registry where possible.
    /// Returns null when the inventory could not be read at all.
    /// </summary>
    private static async Task<List<string>?> ReadInstalledSoftwareAsync()
    {
#if WINDOWS
        var fromRegistry = Native.NativeInstalledSoftware.EnumerateNames();
        if (fromRegistry is not null)
            return fromRegistry;
#endif

        // Fallback only. `wmic product` is deprecated, misses non-MSI installs,
        // and reconfigures every installed product just to list them.
        var (success, output, _) = await CommandExecutor.ExecuteAsync(
            "wmic",
            "product get name",
            InventoryTimeout
        );
        if (!success)
            return null;

        return output
            .Split(new[] { '\n', '\r' }, StringSplitOptions.RemoveEmptyEntries)
            .Select(l => l.Trim())
            .Where(l => !string.IsNullOrWhiteSpace(l) && l != "Name")
            .ToList();
    }

    public override async Task<SystemInfo> ReadSystemStateAsync()
    {
        var installed = await ReadInstalledSoftwareAsync();
        return new SystemInfo
        {
            RawOutput = installed is null
                ? string.Empty
                : string.Join(Environment.NewLine, installed),
            ErrorOutput = installed is null ? "Could not read installed software" : string.Empty,
        };
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

        var installed = await ReadInstalledSoftwareAsync();
        if (installed is null)
        {
            AnsiConsole.MarkupLine("[red]✗ Failed to list installed software[/]");
            return new TaskResult
            {
                TaskName = Name,
                Success = false,
                Message = "Could not read the installed software inventory",
            };
        }
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
        var removalFailures = new List<string>();
        var chocoPackages = await Chocolatey.ListInstalledAsync();
        foreach (var sw in toRemove)
        {
            // Prefer Chocolatey when it owns the package: it uninstalls silently
            // and reports a real reason. `wmic product call uninstall` stays as
            // the fallback for software Chocolatey did not install.
            string? remError = null;
            var remSuccess = false;

            if (
                chocoPackages is not null
                && chocoPackages.Any(p => p.Contains(sw, StringComparison.OrdinalIgnoreCase))
            )
            {
                var package = chocoPackages.First(p =>
                    p.Contains(sw, StringComparison.OrdinalIgnoreCase)
                );
                remError = await Chocolatey.UninstallAsync(package);
                remSuccess = remError is null;
            }

            if (!remSuccess)
            {
                (remSuccess, _, remError) = await CommandExecutor.ExecuteAsync(
                    "wmic",
                    $"product where name=\"{sw}\" call uninstall /nointeractive"
                );
            }

            if (remSuccess)
            {
                AnsiConsole.MarkupLine($"[green]✓ Removed: {Markup.Escape(sw)}[/]");
            }
            else
            {
                removalFailures.Add($"{sw}: {remError}");
                AnsiConsole.MarkupLine(
                    $"[red]✗ Failed to remove: {Markup.Escape(sw)} ({Markup.Escape(remError ?? "")})[/]"
                );
            }
        }
        // Install required software through Chocolatey, bootstrapping it if absent.
        var installFailures = new List<string>();
        var installedNow = new List<string>();
        if (toInstall.Count > 0)
        {
            var chocoError = await Chocolatey.EnsureAvailableAsync();
            if (chocoError is not null)
            {
                foreach (var sw in toInstall)
                {
                    installFailures.Add($"{sw.Name}: {chocoError}");
                    AnsiConsole.MarkupLine(
                        $"[red]✗ Cannot install {Markup.Escape(sw.Name)}: {Markup.Escape(chocoError)}[/]"
                    );
                }
                details.Add($"Chocolatey unavailable: {chocoError}");
            }
            else
            {
                foreach (var sw in toInstall)
                {
                    var package = PackageIdFor(sw);
                    AnsiConsole.MarkupLine(
                        $"[cyan]Installing {Markup.Escape(sw.Name)} (choco: {Markup.Escape(package)})...[/]"
                    );

                    var failure = await Chocolatey.InstallAsync(package);
                    if (failure is null)
                    {
                        installedNow.Add(sw.Name);
                        AnsiConsole.MarkupLine($"[green]✓ Installed: {Markup.Escape(sw.Name)}[/]");
                    }
                    else
                    {
                        installFailures.Add($"{sw.Name}: {failure}");
                        AnsiConsole.MarkupLine(
                            $"[red]✗ Failed to install {Markup.Escape(sw.Name)}: {Markup.Escape(failure)}[/]"
                        );
                    }
                }
            }
        }

        if (installedNow.Count > 0)
            details.Add($"Installed via Chocolatey: {string.Join(", ", installedNow)}");
        if (installFailures.Count > 0)
            details.Add($"Failed to install: {string.Join("; ", installFailures)}");

        // Bring already-present packages up to date. Out-of-date software is a
        // scored finding in its own right, so this runs even when nothing was
        // missing - but only when Chocolatey is already usable, since installing
        // it purely to run an upgrade is not worth the download.
        if (UpdateInstalledSoftware && await Chocolatey.IsAvailableAsync())
        {
            AnsiConsole.MarkupLine("[cyan]Updating installed packages...[/]");
            var upgradeError = await Chocolatey.UpgradeAllAsync();
            if (upgradeError is null)
            {
                details.Add("Updated installed packages via Chocolatey");
                AnsiConsole.MarkupLine("[green]✓ Packages updated[/]");
            }
            else
            {
                details.Add($"Package update reported: {upgradeError}");
                AnsiConsole.MarkupLine(
                    $"[yellow]! Package update reported: {Markup.Escape(upgradeError)}[/]"
                );
            }
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
            // Success reflects whether remediation succeeded, not whether there
            // was nothing to do. Including `toRemove.Count == 0` meant
            // successfully uninstalling prohibited software reported the task as
            // failed. Missing required software is still a genuine outstanding
            // problem needing a manual install, so it remains in the condition.
            Success =
                removalFailures.Count == 0
                && installFailures.Count == 0
                && malwareScanSuccess
                && threatsFound == 0,
            Message = string.Join("\n", details),
            ErrorDetails =
                removalFailures.Count + installFailures.Count > 0
                    ? string.Join("\n", removalFailures.Concat(installFailures))
                    : null,
        };
    }

    public override async Task<bool> VerifyAsync()
    {
        var installed = await ReadInstalledSoftwareAsync() ?? new List<string>();
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
    private async Task<(
        bool Success,
        int ThreatsFound,
        string Message
    )> RunWindowsDefenderScanAsync()
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

        // Run the scan. A Defender scan runs for many minutes; under the default
        // two-minute ceiling it was killed part-way and reported as a failure.
        var (scanSuccess, scanOutput, scanError) = await CommandExecutor.PowerShellAsync(
            $"Start-MpScan -ScanType {scanType}",
            ScanTimeout
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
                AnsiConsole.MarkupLine(
                    $"[red]⚠ Windows Defender found {threatsFound} threat(s)[/]"
                );

                // Attempt to remove detected threats
                var (removeSuccess, _, removeError) = await CommandExecutor.ExecuteAsync(
                    "powershell",
                    "-Command \"Remove-MpThreat -ErrorAction SilentlyContinue\""
                );
                if (removeSuccess)
                    AnsiConsole.MarkupLine("[green]✓ Attempted to remove detected threats[/]");
                else
                    AnsiConsole.MarkupLine(
                        $"[yellow]⚠ Could not auto-remove threats: {removeError}[/]"
                    );
            }
        }

        if (threatsFound == 0)
            AnsiConsole.MarkupLine("[green]✓ No threats detected by Windows Defender[/]");

        return (
            true,
            threatsFound,
            $"Windows Defender {scanType}: {(threatsFound > 0 ? $"{threatsFound} threat(s) found" : "No threats detected")}"
        );
    }
}
