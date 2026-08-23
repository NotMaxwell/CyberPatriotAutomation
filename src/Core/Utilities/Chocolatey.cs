// =============================================================================
// PinnacleCyPat - Chocolatey package manager
// Author: Maxwell McCormick
// Copyright (c) 2026 Maxwell McCormick. All Rights Reserved.
// =============================================================================
using Spectre.Console;

namespace PinnacleCyPat.Core.Utilities;

/// <summary>
/// Package installs and upgrades through Chocolatey.
/// </summary>
/// <remarks>
/// <para>
/// Chocolatey is the default package source for this tool: it is scriptable
/// without a console prompt, it is present on or installable onto every
/// supported image, and its package names are stable across Windows editions.
/// If it is missing it is bootstrapped from the official install script rather
/// than leaving required software uninstalled.
/// </para>
/// <para>
/// The one sharp edge is PATH. The bootstrap adds Chocolatey to the machine PATH,
/// but an already-running process keeps the environment block it started with, so
/// <c>choco</c> stays unresolvable in this process until it restarts. Every call
/// therefore resolves the executable by absolute path as well as by name.
/// </para>
/// </remarks>
public static class Chocolatey
{
    /// <summary>Installs and upgrades routinely outrun the default ceiling.</summary>
    private static readonly TimeSpan PackageTimeout = TimeSpan.FromMinutes(20);

    /// <summary>Upgrading everything on a stale image can take far longer.</summary>
    private static readonly TimeSpan UpgradeAllTimeout = TimeSpan.FromMinutes(60);

    private static readonly TimeSpan BootstrapTimeout = TimeSpan.FromMinutes(15);

    /// <summary>
    /// Exit codes Chocolatey uses for "succeeded, but a reboot is pending".
    /// Treating these as failure would report completed installs as failed.
    /// </summary>
    private static readonly int[] SuccessExitCodes = [0, 1605, 1614, 1641, 3010];

    /// <summary>Cached resolved path, so detection runs once per run.</summary>
    private static string? _resolved;

    /// <summary>The standard install location, used when PATH is stale.</summary>
    private static string DefaultPath =>
        Path.Combine(
            Environment.GetEnvironmentVariable("ProgramData") ?? @"C:\ProgramData",
            "chocolatey",
            "bin",
            "choco.exe"
        );

    /// <summary>
    /// Locate a usable <c>choco</c>, or null when it is not installed.
    /// </summary>
    public static async Task<string?> ResolveAsync()
    {
        if (_resolved is not null)
            return _resolved;

        // PATH first, so a non-standard install location still works.
        var (onPath, _, _) = await CommandExecutor.ExecuteAsync(
            "choco",
            "--version",
            TimeSpan.FromMinutes(1)
        );
        if (onPath)
            return _resolved = "choco";

        var absolute = DefaultPath;
        if (File.Exists(absolute))
        {
            var (works, _, _) = await CommandExecutor.ExecuteAsync(
                absolute,
                "--version",
                TimeSpan.FromMinutes(1)
            );
            if (works)
                return _resolved = absolute;
        }

        return null;
    }

    /// <summary>Is Chocolatey already usable?</summary>
    public static async Task<bool> IsAvailableAsync() => await ResolveAsync() is not null;

    /// <summary>
    /// Ensure Chocolatey is usable, installing it if absent. Returns null on
    /// success or the reason it could not be made available.
    /// </summary>
    public static async Task<string?> EnsureAvailableAsync()
    {
        if (await IsAvailableAsync())
            return null;

        AnsiConsole.MarkupLine("[yellow]Chocolatey not found - installing...[/]");

        // The documented bootstrap. TLS 1.2 is forced because Windows PowerShell
        // 5.1 still offers older protocols that community.chocolatey.org refuses.
        var script =
            "Set-ExecutionPolicy Bypass -Scope Process -Force; "
            + "[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12; "
            + "Invoke-Expression ((New-Object System.Net.WebClient).DownloadString("
            + "'https://community.chocolatey.org/install.ps1'))";

        var (ok, _, error) = await CommandExecutor.PowerShellAsync(script, BootstrapTimeout);

        // Re-resolve either way: the bootstrap can report a non-zero exit while
        // still having produced a working install, and the fresh binary is only
        // reachable by absolute path in this process.
        _resolved = null;
        if (await IsAvailableAsync())
        {
            AnsiConsole.MarkupLine("[green]✓ Chocolatey installed[/]");
            return null;
        }

        return ok
            ? "the Chocolatey installer completed but choco.exe is still not usable"
            : $"could not install Chocolatey: {error ?? "no reason reported"}";
    }

    /// <summary>Install one package. Returns null on success, else the reason.</summary>
    public static async Task<string?> InstallAsync(string package) =>
        await RunAsync($"install {Quote(package)} -y --no-progress --limit-output", PackageTimeout);

    /// <summary>Upgrade one package. Returns null on success, else the reason.</summary>
    public static async Task<string?> UpgradeAsync(string package) =>
        await RunAsync($"upgrade {Quote(package)} -y --no-progress --limit-output", PackageTimeout);

    /// <summary>Upgrade every managed package. Returns null on success.</summary>
    public static async Task<string?> UpgradeAllAsync() =>
        await RunAsync("upgrade all -y --no-progress --limit-output", UpgradeAllTimeout);

    /// <summary>Uninstall one package. Returns null on success, else the reason.</summary>
    public static async Task<string?> UninstallAsync(string package) =>
        await RunAsync(
            $"uninstall {Quote(package)} -y --remove-dependencies --limit-output",
            PackageTimeout
        );

    /// <summary>
    /// The packages Chocolatey currently manages, or null when it cannot be read.
    /// </summary>
    public static async Task<List<string>?> ListInstalledAsync()
    {
        var choco = await ResolveAsync();
        if (choco is null)
            return null;

        var (exitCode, output, _) = await CommandExecutor.ExecuteForExitCodeAsync(
            choco,
            "list --local-only --limit-output",
            PackageTimeout
        );
        if (exitCode is null || !SuccessExitCodes.Contains(exitCode.Value))
            return null;

        // --limit-output prints "name|version" per line and nothing else, so there
        // is no banner or summary to skip and no localised text to match.
        return output
            .Split('\n', StringSplitOptions.RemoveEmptyEntries)
            .Select(line => line.Split('|')[0].Trim())
            .Where(name => name.Length > 0)
            .ToList();
    }

    private static async Task<string?> RunAsync(string arguments, TimeSpan timeout)
    {
        var choco = await ResolveAsync();
        if (choco is null)
            return "Chocolatey is not installed";

        var (exitCode, output, error) = await CommandExecutor.ExecuteForExitCodeAsync(
            choco,
            arguments,
            timeout
        );

        if (exitCode is null)
            return error ?? "the Chocolatey command did not complete";

        if (SuccessExitCodes.Contains(exitCode.Value))
            return null;

        // Chocolatey reports the useful detail on stdout, not stderr.
        var reason = !string.IsNullOrWhiteSpace(error)
            ? error.Trim()
            : LastMeaningfulLine(output) ?? $"exit code {exitCode}";
        return reason;
    }

    private static string? LastMeaningfulLine(string output) =>
        output
            .Split('\n', StringSplitOptions.RemoveEmptyEntries)
            .Select(l => l.Trim())
            .LastOrDefault(l => l.Length > 0);

    /// <summary>Quote a package id so a name with a space stays one argument.</summary>
    private static string Quote(string value) => $"\"{value.Replace("\"", "\\\"")}\"";
}
