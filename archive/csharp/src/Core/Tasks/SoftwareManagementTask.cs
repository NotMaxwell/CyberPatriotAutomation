// =============================================================================
// PinnacleCyPat - Software Management Task
// Author: Maxwell McCormick
// Copyright 2026 Maxwell McCormick. Licensed under Apache-2.0.
// =============================================================================
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Threading.Tasks;
using PinnacleCyPat.Core.Models;
using PinnacleCyPat.Core.Utilities;
using Spectre.Console;

namespace PinnacleCyPat.Core.Tasks;

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
    public static readonly Dictionary<string, string> PackageIds = new(
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

        // With no README the default prohibitions are the whole list, so they
        // are seeded here rather than waiting for SetReadmeData that may never
        // be called.
        ApplyDefaultProhibitions();
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
        RequiredSoftware = readme?.RequiredSoftware?.ToList() ?? new List<SoftwareRequirement>();
        ProhibitedSoftware = readme?.ProhibitedSoftware?.ToList() ?? new List<string>();
        ApplyDefaultProhibitions();
    }

    /// <summary>
    /// Add <see cref="AlwaysProhibited"/> to the prohibited list, unless the
    /// README requires that software.
    /// </summary>
    /// <remarks>
    /// Called from the constructor as well as from <see cref="SetReadmeData"/>.
    /// It used to live only inside SetReadmeData, behind an early return on a
    /// null README - so a run without one, or with one that failed to parse,
    /// left the prohibited list <b>empty</b> and removed nothing at all. Python,
    /// CCleaner and Jellyfin are prohibited by default precisely because no
    /// README names them, so the default list has to survive the README being
    /// absent.
    /// </remarks>
    private void ApplyDefaultProhibitions()
    {
        foreach (var candidate in AlwaysProhibited)
        {
            // A README that requires something wins over the default list: an
            // image that legitimately needs Python must not have it uninstalled.
            var required = RequiredSoftware.Any(r => PackageMatching.Matches(r.Name, candidate));
            var alreadyListed = ProhibitedSoftware.Any(p =>
                p.Equals(candidate, StringComparison.OrdinalIgnoreCase)
            );
            if (!required && !alreadyListed)
                ProhibitedSoftware.Add(candidate);
        }
    }

    /// <summary>
    /// The installed-software list, from the uninstall registry where possible.
    /// Returns null when the inventory could not be read at all.
    /// </summary>
    private static async Task<List<InstalledSoftware>?> ReadInstalledSoftwareAsync()
    {
#if WINDOWS
        // The uninstall keys carry the uninstall command as well as the name,
        // and that command is what actually removes the software. The previous
        // reader called EnumerateNames() and discarded it, leaving nothing to
        // uninstall with but `wmic`.
        var fromRegistry = Native.NativeInstalledSoftware.Enumerate();
        if (fromRegistry is not null)
        {
            return fromRegistry
                .Select(p => new InstalledSoftware(
                    p.Name,
                    p.Version,
                    p.UninstallCommand,
                    p.UninstallIsQuiet
                ))
                .ToList();
        }
#endif

        // Fallback only, and a poor one: `wmic product` is deprecated, absent on
        // current Windows 11 images, misses every non-MSI install, and
        // reconfigures every installed product just to list them. It yields
        // names with no uninstall command, so removal falls back to msiexec by
        // product name.
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
            .Select(name => new InstalledSoftware(name))
            .ToList();
    }

    public override async Task<SystemInfo> ReadSystemStateAsync()
    {
        var installed = await ReadInstalledSoftwareAsync();
        return new SystemInfo
        {
            RawOutput = installed is null
                ? string.Empty
                : string.Join(
                    Environment.NewLine,
                    installed.Select(p => p.Version is null ? p.Name : $"{p.Name} [{p.Version}]")
                ),
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
            .Where(i => ProhibitedSoftware.Any(p => PackageMatching.Matches(i.Name, p)))
            .ToList();
        var toInstall = RequiredSoftware
            .Where(r => !installed.Any(i => PackageMatching.Matches(i.Name, r.Name)))
            .ToList();

        // What matched what, and why. Reconstructing this after a run used to be
        // impossible: the console said "Failed to remove: X" and nothing said
        // whether X was even matched, which mechanism was tried, or what it
        // returned.
        RunLog.Diagnostic("software", $"inventory: {installed.Count} programs");
        RunLog.Diagnostic("software", $"prohibited terms: {string.Join(", ", ProhibitedSoftware)}");
        foreach (var item in toRemove)
        {
            RunLog.Diagnostic(
                "software",
                $"matched for removal: {item.Name} "
                    + $"(uninstall string: {item.UninstallString ?? "none registered"})"
            );
        }

        var details = new List<string>();
        // List all installed software checked
        details.Add(
            $"Installed software checked: {string.Join(", ", installed.Select(i => i.Name))}"
        );
        // List all prohibited software checked
        details.Add($"Prohibited software list: {string.Join(", ", ProhibitedSoftware)}");
        // List all required software checked
        details.Add(
            $"Required software list: {string.Join(", ", RequiredSoftware.Select(r => r.Name))}"
        );

        if (toRemove.Count > 0)
            details.Add($"To remove: {string.Join(", ", toRemove.Select(i => i.Name))}");
        else
            details.Add("No prohibited software found to remove.");

        if (toInstall.Count > 0)
            details.Add(
                $"Missing required software: {string.Join(", ", toInstall.Select(s => s.Name))}"
            );
        else
            details.Add("All required software is installed.");

        // Remove prohibited software.
        var removalFailures = new List<string>();
        var chocoPackages = await Chocolatey.ListInstalledAsync();
        foreach (var sw in toRemove)
        {
            var failure = await UninstallAsync(sw, chocoPackages);
            if (failure is null)
            {
                AnsiConsole.MarkupLine($"[green]✓ Removed: {Markup.Escape(sw.Name)}[/]");
            }
            else
            {
                removalFailures.Add($"{sw.Name}: {failure}");
                AnsiConsole.MarkupLine(
                    $"[red]✗ Failed to remove: {Markup.Escape(sw.Name)} "
                        + $"({Markup.Escape(failure)})[/]"
                );
            }
        }

        // Confirm removals against a fresh inventory rather than trusting exit
        // codes. An uninstaller that exits 0 having shown a dialog nobody
        // answered, or that needs a reboot to finish, both report success.
        if (toRemove.Count > 0)
        {
            var after = await ReadInstalledSoftwareAsync();
            if (after is not null)
            {
                var survivors = after
                    .Where(i => ProhibitedSoftware.Any(p => PackageMatching.Matches(i.Name, p)))
                    .Select(i => i.Name)
                    .ToList();
                foreach (var name in survivors)
                {
                    RunLog.Diagnostic("software", $"still present after removal: {name}");
                    if (!removalFailures.Any(f => f.StartsWith(name, StringComparison.Ordinal)))
                    {
                        removalFailures.Add($"{name}: reported removed but still installed");
                        AnsiConsole.MarkupLine(
                            $"[red]✗ {Markup.Escape(name)} is still installed after removal[/]"
                        );
                    }
                }
                if (survivors.Count > 0)
                    details.Add($"Still installed after removal: {string.Join(", ", survivors)}");
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
        // Chocolatey is *ensured*, not merely detected.
        //
        // This used to call IsAvailableAsync, while the bootstrap lived inside
        // the install branch above - which only runs when something is missing.
        // On the common image, where the required software is already present
        // and merely out of date, nothing was missing, so Chocolatey was never
        // installed and the entire update step was skipped in silence. That is
        // the reported symptom: Chrome and Notepad++ never being updated.
        var updateBlocker = UpdateInstalledSoftware
            ? await Chocolatey.EnsureAvailableAsync()
            : null;
        if (UpdateInstalledSoftware && updateBlocker is not null)
        {
            details.Add($"Could not update installed software: {updateBlocker}");
            RunLog.Diagnostic("software", $"updates skipped: {updateBlocker}");
            AnsiConsole.MarkupLine(
                $"[red]✗ Cannot update installed software: {Markup.Escape(updateBlocker)}[/]"
            );
        }
        else if (UpdateInstalledSoftware)
        {
            // Anything the README requires, plus whatever is installed and has a
            // package id we recognise: an image can ship outdated software the
            // README never mentions.
            //
            // Resolution is fuzzy because display names carry version, bitness
            // and locale suffixes - "Notepad++ (64-bit x64)", "Mozilla Firefox
            // (x64 en-US)". The previous exact dictionary lookup matched only
            // names with no suffix at all, which is why Notepad++ was never
            // updated.
            // Never offer prohibited software to the updater.
            //
            // `choco upgrade <pkg>` *installs* a package that is not present, so
            // feeding it software this run just uninstalled reinstalls it - and
            // the candidate list is built from the inventory read *before*
            // removal, so every removed program was still in it. A real run
            // removed Python 3.13.0 and then put Python 3.14.7 back four minutes
            // later, which is worse than never having removed it.
            var recognised = installed
                .Where(i => !ProhibitedSoftware.Any(p => PackageMatching.Matches(i.Name, p)))
                .Select(i => (i.Name, Id: PackageMatching.ResolvePackageId(i.Name, PackageIds)))
                .Where(x => x.Id is not null)
                .ToList();

            // The README's own required list gets the same treatment: a package
            // id that would reinstall prohibited software must not survive
            // because two different display names mapped onto it.
            var prohibitedIds = installed
                .Where(i => ProhibitedSoftware.Any(p => PackageMatching.Matches(i.Name, p)))
                .Select(i => PackageMatching.ResolvePackageId(i.Name, PackageIds))
                .Where(id => id is not null)
                .Select(id => id!)
                .ToHashSet(StringComparer.OrdinalIgnoreCase);

            foreach (var id in prohibitedIds)
                RunLog.Diagnostic("software", $"excluded from updates (prohibited): {id}");

            foreach (var (name, id) in recognised)
                RunLog.Diagnostic("software", $"update candidate: {name} -> {id}");

            var toUpdate = RequiredSoftware
                .Select(PackageIdFor)
                .Concat(recognised.Select(x => x.Id!))
                .Where(id => id.Length > 0 && !prohibitedIds.Contains(id))
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
            //
            // Skipped when prohibited software is still installed: `upgrade all`
            // would happily bring the survivor to its latest version, which is
            // the opposite of what this task is for.
            if (prohibitedIds.Count == 0)
            {
                var upgradeError = await Chocolatey.UpgradeAllAsync();
                if (upgradeError is not null)
                    details.Add($"choco upgrade all reported: {upgradeError}");
            }
            else
            {
                RunLog.Diagnostic(
                    "software",
                    "skipped `choco upgrade all`: prohibited software is still installed and it would upgrade it"
                );
            }
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
        var installed = await ReadInstalledSoftwareAsync() ?? new List<InstalledSoftware>();

        var stillPresent = installed
            .Where(i => ProhibitedSoftware.Any(p => PackageMatching.Matches(i.Name, p)))
            .Select(i => i.Name)
            .ToList();
        var stillMissing = RequiredSoftware
            .Where(r => !installed.Any(i => PackageMatching.Matches(i.Name, r.Name)))
            .Select(r => r.Name)
            .ToList();

        // Say which, rather than just failing. A bare false sends the reader
        // back to the console scrollback to work out what verification objected
        // to.
        foreach (var name in stillPresent)
            RunLog.Diagnostic("software", $"verify: prohibited software still installed: {name}");
        foreach (var name in stillMissing)
            RunLog.Diagnostic("software", $"verify: required software still missing: {name}");

        return stillPresent.Count == 0 && stillMissing.Count == 0;
    }

    /// <summary>
    /// Uninstall one program. Returns null on success, or the reason.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Three mechanisms, tried in order of reliability:
    /// </para>
    /// <list type="number">
    /// <item><b>Chocolatey</b>, when it owns the package. It uninstalls silently
    /// and reports a real reason.</item>
    /// <item><b>The registered uninstall command</b>, made unattended by
    /// <see cref="UninstallCommandBuilder"/>. This is what removes NSIS and Inno
    /// software - CCleaner, Notepad++, Jellyfin Media Player - none of which the
    /// previous <c>wmic</c> path could touch.</item>
    /// <item><b>msiexec by product name</b>, only for an inventory that came
    /// from the <c>wmic</c> fallback and so carries no uninstall string.</item>
    /// </list>
    /// <para>
    /// <c>wmic product call uninstall</c> is gone. It reads Win32_Product, which
    /// knows only MSI installs, and it exits 0 when its where-clause matches
    /// nothing - so it reported success for every non-MSI program while removing
    /// none of them.
    /// </para>
    /// </remarks>
    private static async Task<string?> UninstallAsync(
        InstalledSoftware software,
        List<string>? chocoPackages
    )
    {
        // 1. Chocolatey, if it owns it.
        //
        // The test used to be `package.Contains(displayName)` - backwards, since
        // the package id is the short name and the display name the long one, so
        // it never matched and this path never ran.
        var owned = chocoPackages?.FirstOrDefault(p =>
            PackageMatching.Matches(software.Name, p)
            || PackageMatching.ResolvePackageId(software.Name, PackageIds) is { } id
                && id.Equals(p, StringComparison.OrdinalIgnoreCase)
        );

        if (owned is not null)
        {
            RunLog.Diagnostic(
                "software",
                $"{software.Name}: uninstalling via Chocolatey ({owned})"
            );
            var chocoFailure = await Chocolatey.UninstallAsync(owned);
            if (chocoFailure is null)
                return null;
            RunLog.Diagnostic(
                "software",
                $"{software.Name}: Chocolatey uninstall failed ({chocoFailure}); trying the registered uninstaller"
            );
        }

        // 2. The registered uninstall command.
        var command = UninstallCommandBuilder.Build(
            software.UninstallString,
            software.UninstallIsQuiet
        );

        if (command is { } cmd)
        {
            RunLog.Diagnostic("software", $"{software.Name}: running {cmd}");
            var (exitCode, output, error) = await CommandExecutor.ExecuteForExitCodeAsync(
                cmd.Program,
                cmd.Arguments,
                UninstallTimeout
            );

            if (exitCode is null)
                return "the uninstaller did not finish within the time limit";

            // 3010 and 1641 are "done, reboot pending" - the software is gone.
            if (UninstallSuccessExitCodes.Contains(exitCode.Value))
                return null;

            var reason = !string.IsNullOrWhiteSpace(error)
                ? error.Trim()
                : LastMeaningfulLine(output) ?? $"the uninstaller exited with code {exitCode}";
            return reason;
        }

        // 3. No uninstall string: the inventory came from the wmic fallback.
        if (software.UninstallString is null)
        {
            RunLog.Diagnostic(
                "software",
                $"{software.Name}: no uninstall command registered; trying msiexec by name"
            );
            var (ok, _, msiError) = await CommandExecutor.ExecuteAsync(
                "msiexec.exe",
                $"/x \"{software.Name}\" /qn /norestart",
                UninstallTimeout
            );
            return ok ? null : msiError ?? "no uninstall command is registered for this program";
        }

        return $"the registered uninstall command could not be used: {software.UninstallString}";
    }

    /// <summary>An uninstaller can legitimately run for several minutes.</summary>
    private static readonly TimeSpan UninstallTimeout = TimeSpan.FromMinutes(15);

    /// <summary>Exit codes that mean the program was removed.</summary>
    /// <remarks>3010 and 1641 both mean "succeeded, reboot pending".</remarks>
    private static readonly int[] UninstallSuccessExitCodes = [0, 1605, 1641, 3010];

    /// <summary>The last non-empty line of output, used when stderr is silent.</summary>
    private static string? LastMeaningfulLine(string output) =>
        output
            .Split('\n', StringSplitOptions.RemoveEmptyEntries)
            .Select(l => l.Trim())
            .LastOrDefault(l => l.Length > 0);

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
