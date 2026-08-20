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
        // The `.install` packages run the vendor installer, which puts the
        // program under Program Files. The bare ids are portable packages that
        // unpack under ProgramData instead - and the CP19 answer key deducts
        // points when 7-Zip, Notepad++, Chrome or Wireshark are "not installed
        // at the default location".
        ["7-Zip"] = "7zip.install",
        ["7Zip"] = "7zip.install",
        ["Notepad++"] = "notepadplusplus.install",
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

    /// <summary>
    /// Software treated as prohibited even when the README does not name it.
    /// </summary>
    /// <remarks>
    /// Scoring images routinely include software that is not a hacking tool but
    /// is not authorised either - a media player, a scripting runtime, a
    /// registry cleaner. The answer key for the CP19 exhibition round scored
    /// removing Jellyfin Media Player and Python 3 as separate items, and the
    /// README named neither: they are prohibited by default, and only permitted
    /// when the README explicitly lists them as required.
    /// </remarks>
    public static readonly string[] AlwaysProhibited = ["Python", "CCleaner", "Jellyfin"];

    public void SetReadmeData(ReadmeData? readme)
    {
        if (readme == null)
            return;
        RequiredSoftware = readme.RequiredSoftware?.ToList() ?? new List<SoftwareRequirement>();

        var prohibited = readme.ProhibitedSoftware?.ToList() ?? new List<string>();

        // A README that requires something wins over the default list: an image
        // that legitimately needs Python must not have it uninstalled.
        foreach (var candidate in AlwaysProhibited)
        {
            var required = RequiredSoftware.Any(r =>
                r.Name.Contains(candidate, StringComparison.OrdinalIgnoreCase)
            );
            var alreadyListed = prohibited.Any(p =>
                p.Equals(candidate, StringComparison.OrdinalIgnoreCase)
            );
            if (!required && !alreadyListed)
                prohibited.Add(candidate);
        }

        ProhibitedSoftware = prohibited;
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

        // Bring already-installed software up to date.
        //
        // `choco upgrade all` only touches packages Chocolatey itself installed,
        // so software that came with the image - which is exactly what a
        // competition asks you to update - is never considered. Upgrading each
        // required package by name reaches it regardless of how it was
        // installed, because `choco upgrade` runs the newer vendor installer
        // over the top. The CP19 answer key scored "Notepad++ has been updated"
        // and "Google Chrome has been updated" as separate items, and both were
        // pre-installed.
        var updateFailures = new List<string>();
        var updatedNow = new List<string>();
        if (UpdateInstalledSoftware && await Chocolatey.IsAvailableAsync())
        {
            // Anything the README requires, plus whatever is installed and has a
            // package id we recognise: an image can ship outdated software the
            // README never mentions.
            var toUpdate = RequiredSoftware
                .Select(PackageIdFor)
                .Concat(
                    installed
                        .Where(name => PackageIds.ContainsKey(name.Trim()))
                        .Select(name => PackageIds[name.Trim()])
                )
                .Where(id => id.Length > 0)
                .Distinct(StringComparer.OrdinalIgnoreCase)
                .ToList();

            foreach (var package in toUpdate)
            {
                AnsiConsole.MarkupLine($"[cyan]Updating {Markup.Escape(package)}...[/]");
                var failure = await Chocolatey.UpgradeAsync(package);
                if (failure is null)
                {
                    updatedNow.Add(package);
                    AnsiConsole.MarkupLine($"[green]✓ Up to date: {Markup.Escape(package)}[/]");
                }
                else
                {
                    updateFailures.Add($"{package}: {failure}");
                    AnsiConsole.MarkupLine(
                        $"[yellow]! Could not update {Markup.Escape(package)}: {Markup.Escape(failure)}[/]"
                    );
                }
            }

            // Then anything else Chocolatey manages, which the loop above misses.
            var upgradeError = await Chocolatey.UpgradeAllAsync();
            if (upgradeError is not null)
                details.Add($"choco upgrade all reported: {upgradeError}");
        }

        if (updatedNow.Count > 0)
            details.Add($"Updated: {string.Join(", ", updatedNow)}");
        if (updateFailures.Count > 0)
            details.Add($"Could not update: {string.Join("; ", updateFailures)}");

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
