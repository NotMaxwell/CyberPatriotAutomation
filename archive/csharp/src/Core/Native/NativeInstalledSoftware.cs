using System.Runtime.Versioning;
using Microsoft.Win32;

namespace PinnacleCyPat.Core.Native;

/// <summary>One entry from the Windows uninstall registry.</summary>
public readonly record struct InstalledProgram(
    string Name,
    string? Version,
    string? UninstallCommand,
    bool UninstallIsQuiet
);

/// <summary>
/// Installed-software inventory read from the uninstall registry keys.
/// </summary>
/// <remarks>
/// <para>
/// This replaces <c>wmic product get name</c>, which was wrong on three counts.
/// It is deprecated and already disabled by default on current Windows 11 images,
/// so it is on a countdown. It only ever saw MSI-installed products, missing
/// everything installed by an EXE bundle. And, worst for a timed run, enumerating
/// Win32_Product makes the installer service reconfigure every installed
/// product - which takes minutes and has been known to re-trigger repairs.
/// </para>
/// <para>
/// The uninstall keys are what Add/Remove Programs itself lists, so this sees
/// strictly more software and returns immediately.
/// </para>
/// </remarks>
[SupportedOSPlatform("windows")]
public static class NativeInstalledSoftware
{
    private const string UninstallPath = @"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall";

    private const string UninstallPathWow =
        @"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall";

    /// <summary>
    /// Every visible installed program. Returns null only if nothing could be
    /// read at all, so an empty machine stays distinguishable from a failure.
    /// </summary>
    public static List<InstalledProgram>? Enumerate()
    {
        var found = new Dictionary<string, InstalledProgram>(StringComparer.OrdinalIgnoreCase);
        var readAny = false;

        foreach (var (root, path) in Roots())
        {
            try
            {
                using var key = root.OpenSubKey(path);
                if (key is null)
                    continue;

                readAny = true;
                foreach (var subkeyName in key.GetSubKeyNames())
                {
                    try
                    {
                        using var entry = key.OpenSubKey(subkeyName);
                        var program = ReadEntry(entry);
                        if (program is { } value)
                            found[value.Name] = value;
                    }
                    catch (System.Security.SecurityException)
                    {
                        // A single unreadable entry should not lose the inventory.
                    }
                }
            }
            catch (System.Security.SecurityException)
            {
                // Same for a whole hive we lack rights to.
            }
        }

        return readAny ? found.Values.OrderBy(p => p.Name).ToList() : null;
    }

    /// <summary>Just the display names, for callers that only match on name.</summary>
    public static List<string>? EnumerateNames() => Enumerate()?.Select(p => p.Name).ToList();

    private static IEnumerable<(RegistryKey Root, string Path)> Roots()
    {
        // 64-bit and 32-bit views plus the per-user hive. Software installed for
        // a single user never appears under HKLM at all.
        yield return (Registry.LocalMachine, UninstallPath);
        yield return (Registry.LocalMachine, UninstallPathWow);
        yield return (Registry.CurrentUser, UninstallPath);
        yield return (Registry.CurrentUser, UninstallPathWow);
    }

    private static InstalledProgram? ReadEntry(RegistryKey? entry)
    {
        if (entry is null)
            return null;

        var name = entry.GetValue("DisplayName") as string;
        if (string.IsNullOrWhiteSpace(name))
            return null;

        // Updates and driver payloads set SystemComponent=1 to stay out of
        // Add/Remove Programs; listing them would bury the real software.
        if (entry.GetValue("SystemComponent") is int component && component == 1)
            return null;

        // Patches point at their parent product rather than being installs.
        if (entry.GetValue("ParentKeyName") is string parent && parent.Length > 0)
            return null;

        // QuietUninstallString is the publisher's own unattended form; when it
        // exists it needs no silent switch added, and adding one can break it.
        // UninstallString is the interactive uninstaller, which has to be made
        // silent before it can be run without a human at the screen.
        var quiet = entry.GetValue("QuietUninstallString") as string;
        var interactive = entry.GetValue("UninstallString") as string;

        return new InstalledProgram(
            name.Trim(),
            entry.GetValue("DisplayVersion") as string,
            string.IsNullOrWhiteSpace(quiet) ? interactive : quiet,
            !string.IsNullOrWhiteSpace(quiet)
        );
    }
}
