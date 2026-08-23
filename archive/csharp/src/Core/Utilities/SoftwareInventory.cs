// =============================================================================
// PinnacleCyPat - Installed software inventory and package matching
// Author: Maxwell McCormick
// Copyright 2026 Maxwell McCormick. Licensed under Apache-2.0.
// =============================================================================
namespace PinnacleCyPat.Core.Utilities;

/// <summary>One installed program, as Add/Remove Programs sees it.</summary>
/// <remarks>
/// Portable on purpose. The native reader's own record lives under
/// <c>Core/Native</c>, which is compiled only for the Windows target framework,
/// so a task that referenced it directly would not build on the plain
/// <c>net10.0</c> flavour the tests run on.
/// </remarks>
public sealed record InstalledSoftware(
    string Name,
    string? Version = null,
    string? UninstallString = null,
    bool UninstallIsQuiet = false
);

/// <summary>
/// Matching between the display names Windows records and the package ids
/// Chocolatey uses.
/// </summary>
/// <remarks>
/// <para>
/// The two never agree. Windows records <c>Notepad++ (64-bit x64)</c>,
/// <c>Mozilla Firefox (x64 en-US)</c>, <c>7-Zip 23.01 (x64)</c>; Chocolatey
/// wants <c>notepadplusplus.install</c>, <c>firefox</c>, <c>7zip.install</c>.
/// </para>
/// <para>
/// The update step used to bridge them with an exact dictionary lookup on the
/// full display name. That matches <c>Google Chrome</c>, whose registered name
/// happens to carry no suffix, and essentially nothing else - which is exactly
/// the reported symptom, Notepad++ never being updated while Chrome sometimes
/// was. Matching has to tolerate the version, architecture and locale suffixes
/// that real display names carry.
/// </para>
/// </remarks>
public static class PackageMatching
{
    /// <summary>
    /// Reduce a display name to a comparable core: lower-cased, with version,
    /// architecture and locale decoration removed.
    /// </summary>
    /// <remarks>
    /// Punctuation is kept. <c>Notepad++</c> and <c>7-Zip</c> would otherwise
    /// normalise to <c>notepad</c> and <c>7zip</c>, and <c>notepad</c> is a
    /// prefix of nothing useful while being a suspiciously generic word to match
    /// on.
    /// </remarks>
    public static string Normalize(string displayName)
    {
        if (string.IsNullOrWhiteSpace(displayName))
            return string.Empty;

        var text = displayName.Trim();

        // Drop every parenthesised group: "(64-bit)", "(x64 en-US)", "(64-bit x64)".
        text = System.Text.RegularExpressions.Regex.Replace(text, @"\s*\([^)]*\)", " ");

        // Drop a trailing version number, with or without a leading "v".
        text = System.Text.RegularExpressions.Regex.Replace(
            text,
            @"\s+v?\d+(\.\d+)*\s*$",
            " ",
            System.Text.RegularExpressions.RegexOptions.None
        );

        // Drop bare architecture and bitness words wherever they appear.
        text = System.Text.RegularExpressions.Regex.Replace(
            text,
            @"\b(x64|x86|amd64|32-bit|64-bit|win64|win32)\b",
            " ",
            System.Text.RegularExpressions.RegexOptions.IgnoreCase
        );

        // Collapse whitespace last, once everything above has left gaps.
        text = System.Text.RegularExpressions.Regex.Replace(text, @"\s+", " ");

        return text.Trim().ToLowerInvariant();
    }

    /// <summary>
    /// Does <paramref name="displayName"/> name the software <paramref name="term"/> refers to?
    /// </summary>
    /// <remarks>
    /// Used for the prohibited list, where the term is a bare product name
    /// ("CCleaner") and the display name is whatever the publisher registered
    /// ("CCleaner", "Python 3.12.1 (64-bit)", "Jellyfin Media Player").
    /// Substring matching on the normalised forms covers all three shapes.
    /// </remarks>
    public static bool Matches(string displayName, string term)
    {
        if (string.IsNullOrWhiteSpace(term))
            return false;

        var name = Normalize(displayName);
        var needle = Normalize(term);
        if (name.Length == 0 || needle.Length == 0)
            return false;

        return name.Contains(needle, StringComparison.Ordinal);
    }

    /// <summary>
    /// The Chocolatey package id for an installed program, or null when none of
    /// the known names apply.
    /// </summary>
    /// <remarks>
    /// The longest matching key wins, so "Mozilla Firefox" is preferred over
    /// "Firefox" and a short key cannot shadow a more specific one that also
    /// matches.
    /// </remarks>
    public static string? ResolvePackageId(
        string displayName,
        IReadOnlyDictionary<string, string> packageIds
    )
    {
        var name = Normalize(displayName);
        if (name.Length == 0)
            return null;

        string? best = null;
        var bestLength = 0;

        foreach (var (key, id) in packageIds)
        {
            var needle = Normalize(key);
            if (needle.Length == 0 || !name.Contains(needle, StringComparison.Ordinal))
                continue;

            if (needle.Length > bestLength)
            {
                best = id;
                bestLength = needle.Length;
            }
        }

        return best;
    }
}
