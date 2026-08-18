// =============================================================================
// CyberPatriot Automation Tool
// Author: Maxwell McCormick
// Copyright (c) 2026 Maxwell McCormick. All Rights Reserved.
// =============================================================================

using CyberPatriotAutomation.Core.Utilities;

namespace CyberPatriotAutomation.Core;

/// <summary>
/// Application configuration and default paths
/// </summary>
public static class AppConfig
{
    /// <summary>
    /// Default CyberPatriot competition README path on Windows images
    /// The README is typically located on the desktop of the primary user
    /// </summary>
    /// <remarks>
    /// A standard image ships <c>C:\CyberPatriot\README.url</c> - an *Internet
    /// Shortcut*, not the document. It is listed first because it is the
    /// canonical location; <see cref="ResolveReadmeCandidateAsync"/> follows it
    /// to the document it names, which on a real image is a remote https:// URL.
    /// The literal .html paths remain for images that place the file directly.
    /// </remarks>
    public static readonly string[] DefaultReadmePaths = new[]
    {
        @"C:\CyberPatriot\README.url",
        @"C:\CyberPatriot\README.html",
        @"C:\Users\Public\Desktop\README.url",
        @"C:\Users\Public\Desktop\README.html",
        @"C:\Users\Public\Documents\README.html",
        Environment.GetFolderPath(Environment.SpecialFolder.CommonDesktopDirectory)
            + @"\README.url",
        Environment.GetFolderPath(Environment.SpecialFolder.CommonDesktopDirectory)
            + @"\README.html",
        Environment.GetFolderPath(Environment.SpecialFolder.Desktop) + @"\README.url",
        Environment.GetFolderPath(Environment.SpecialFolder.Desktop) + @"\README.html",
        // Fallback: any user's desktop.
        @"C:\Users\*\Desktop\README.url",
        @"C:\Users\*\Desktop\README.html",
    };

    /// <summary>
    /// CCS Client service name - must never be disabled
    /// </summary>
    public const string CCSClientServiceName = "CCSClient";

    /// <summary>
    /// CyberPatriot scoring report desktop shortcut name
    /// </summary>
    public const string ScoringReportShortcut = "CyberPatriot Scoring Report";

    /// <summary>
    /// Application version
    /// </summary>
    public const string Version = "1.0.0";

    /// <summary>
    /// Try to find the README file automatically
    /// </summary>
    public static async Task<string?> FindReadmeFileAsync() =>
        await FindReadmeFileAsync(new List<string>());

    /// <summary>
    /// As <see cref="FindReadmeFileAsync()"/>, but records every location examined.
    /// </summary>
    /// <remarks>
    /// When discovery fails there is otherwise nothing to go on: the run reports
    /// no README and gives no indication of where it looked or which candidate
    /// existed but could not be followed.
    /// </remarks>
    public static async Task<string?> FindReadmeFileAsync(List<string> attempts)
    {
        // Desktop shortcuts first - that is what a competitor actually clicks.
        foreach (
            var dir in new[]
            {
                Environment.GetFolderPath(Environment.SpecialFolder.Desktop),
                Environment.GetFolderPath(Environment.SpecialFolder.CommonDesktopDirectory),
            }
        )
        {
            var found = await FindReadmeShortcutAsync(dir);
            if (found != null)
            {
                attempts.Add($"{dir} -> {found}");
                return found;
            }
            attempts.Add($"{dir} (no README shortcut resolved)");
        }

        foreach (var path in DefaultReadmePaths)
        {
            var candidates = path.Contains('*') ? ExpandWildcardPath(path) : new[] { path };
            if (candidates.Length == 0)
            {
                attempts.Add($"{path} (no match)");
                continue;
            }

            foreach (var candidate in candidates)
            {
                var found = await ResolveReadmeCandidateAsync(candidate);
                if (found != null)
                {
                    attempts.Add($"{candidate} -> {found}");
                    return found;
                }

                // Distinguish "not there" from "there but unusable", and in the
                // latter case say what the shortcut actually points at.
                attempts.Add(
                    File.Exists(candidate)
                        ? $"{candidate} ({DescribeUnresolvable(candidate)})"
                        : $"{candidate} (not found)"
                );
            }
        }

        return null;
    }

    /// <summary>
    /// Resolve one candidate path to a readable README document.
    /// </summary>
    /// <remarks>
    /// Shortcuts are followed <b>repeatedly</b>, because on a real image they
    /// chain: the desktop .lnk targets <c>C:\CyberPatriot\README.url</c>, which
    /// in turn names the document. Stopping after one hop returns the .url
    /// itself, and parsing that INI file as HTML yields a README with no title
    /// and no detectable operating system - the "Unknown / Unknown" symptom.
    /// A remote target is downloaded, since a standard image hosts the README on
    /// the web rather than shipping it.
    /// </remarks>
    public static async Task<string?> ResolveReadmeCandidateAsync(string path)
    {
        // Accept a URL given directly, so --readme <https url> works.
        if (IsRemoteTarget(path))
            return await DownloadReadmeAsync(path.Trim());

        // Enough for lnk -> url -> html with room to spare; also bounds a
        // shortcut that points at itself.
        const int maxHops = 5;
        var current = path;

        for (var hop = 0; hop < maxHops; hop++)
        {
            var extension = Path.GetExtension(current).ToLowerInvariant();
            string? next;

            switch (extension)
            {
                case ".url":
                    var contents = ReadTextLenient(current);
                    if (contents == null)
                        return null;
                    var target = ParseInternetShortcut(contents);
                    if (target == null)
                        return null;
                    if (IsRemoteTarget(target))
                        return await DownloadReadmeAsync(target);
                    next = ToLocalPath(target);
                    break;

                case ".lnk":
                    next = await ResolveShortcutTargetAsync(current);
                    break;

                default:
                    // Not a shortcut: this is the document itself.
                    return File.Exists(current) ? current : null;
            }

            if (next == null)
                return null;
            current = next;
        }

        return null;
    }

    /// <summary>
    /// Look in <paramref name="directory"/> for a README shortcut and resolve it.
    /// </summary>
    /// <remarks>
    /// Competition images use .url Internet Shortcuts; a hand-made desktop link
    /// is usually a .lnk. .url is preferred because it is the form the image
    /// ships, and entries are sorted so a directory containing both resolves the
    /// same way on every run.
    /// </remarks>
    private static async Task<string?> FindReadmeShortcutAsync(string directory)
    {
        if (string.IsNullOrWhiteSpace(directory) || !Directory.Exists(directory))
            return null;

        string[] entries;
        try
        {
            entries = Directory.GetFiles(directory);
        }
        catch
        {
            return null;
        }

        var candidates = entries
            .Where(IsShortcut)
            .Where(ShortcutNameLooksLikeReadme)
            .OrderBy(p => Path.GetExtension(p).ToLowerInvariant() != ".url")
            .ThenBy(p => p, StringComparer.OrdinalIgnoreCase);

        foreach (var candidate in candidates)
        {
            var target = await ResolveReadmeCandidateAsync(candidate);
            if (target != null)
                return target;
        }

        return null;
    }

    private static bool IsShortcut(string path)
    {
        var extension = Path.GetExtension(path);
        return extension.Equals(".url", StringComparison.OrdinalIgnoreCase)
            || extension.Equals(".lnk", StringComparison.OrdinalIgnoreCase);
    }

    private static bool ShortcutNameLooksLikeReadme(string path) =>
        Path.GetFileNameWithoutExtension(path)
            .Replace(" ", "")
            .Contains("readme", StringComparison.OrdinalIgnoreCase);

    /// <summary>
    /// Resolve a Windows .lnk shortcut via the WScript.Shell COM object.
    /// </summary>
    private static async Task<string?> ResolveShortcutTargetAsync(string lnkPath)
    {
        var script =
            $"(New-Object -ComObject WScript.Shell).CreateShortcut({CommandExecutor.PsQuote(lnkPath)}).TargetPath";
        var (success, output, _) = await CommandExecutor.PowerShellQueryAsync(script);
        if (!success)
            return null;
        var target = output.Trim();
        return string.IsNullOrEmpty(target) ? null : target;
    }

    /// <summary>
    /// Is this shortcut target a remote address rather than a path?
    /// </summary>
    /// <remarks>
    /// Only the scheme is inspected. The README URL is unique per image and
    /// changes every competition, so it is always read from the shortcut at run
    /// time and nothing about it is baked in.
    /// </remarks>
    public static bool IsRemoteTarget(string target)
    {
        var lower = target.Trim().ToLowerInvariant();
        return lower.StartsWith("http://", StringComparison.Ordinal)
            || lower.StartsWith("https://", StringComparison.Ordinal);
    }

    /// <summary>
    /// Extract the <c>URL=</c> value from an Internet Shortcut.
    /// </summary>
    public static string? ParseInternetShortcut(string contents)
    {
        foreach (var line in contents.Split('\n'))
        {
            var index = line.IndexOf('=');
            if (index <= 0)
                continue;
            if (line[..index].Trim().Equals("URL", StringComparison.OrdinalIgnoreCase))
                return line[(index + 1)..].Trim();
        }
        return null;
    }

    /// <summary>
    /// Convert a shortcut target into a local path, if it names one.
    /// </summary>
    public static string? ToLocalPath(string target)
    {
        target = target.Trim();
        if (target.Length == 0)
            return null;

        if (IsRemoteTarget(target))
            return null;

        if (target.StartsWith("file:", StringComparison.OrdinalIgnoreCase))
        {
            var rest = target["file:".Length..];
            if (rest.StartsWith("//", StringComparison.Ordinal))
                rest = rest[2..];
            if (rest.StartsWith("localhost", StringComparison.OrdinalIgnoreCase))
                rest = rest["localhost".Length..];

            var decoded = Uri.UnescapeDataString(rest);

            // Only a drive-letter target is a Windows path. Stripping every
            // leading slash and swapping separators would turn the absolute
            // POSIX path /tmp/README.html into the relative tmp\README.html.
            var withoutRoot = decoded.TrimStart('/');
            if (IsWindowsDrivePath(withoutRoot))
                return withoutRoot.Replace('/', '\\');
            return decoded.StartsWith('/') ? decoded : "/" + decoded;
        }

        return IsWindowsDrivePath(target) ? target.Replace('/', '\\') : target;
    }

    private static bool IsWindowsDrivePath(string path) =>
        path.Length >= 2 && char.IsAsciiLetter(path[0]) && path[1] == ':';

    /// <summary>
    /// Read a text file without assuming it is valid UTF-8.
    /// </summary>
    /// <remarks>
    /// Windows tools routinely write UTF-16 with a BOM. Decoding by BOM and
    /// falling back to a lossy read means a shortcut written that way is still
    /// followed rather than silently discarded.
    /// </remarks>
    private static string? ReadTextLenient(string path)
    {
        try
        {
            var bytes = File.ReadAllBytes(path);
            if (bytes.Length >= 2 && bytes[0] == 0xFF && bytes[1] == 0xFE)
                return System.Text.Encoding.Unicode.GetString(bytes, 2, bytes.Length - 2);
            if (bytes.Length >= 2 && bytes[0] == 0xFE && bytes[1] == 0xFF)
                return System.Text.Encoding.BigEndianUnicode.GetString(bytes, 2, bytes.Length - 2);
            if (bytes.Length >= 3 && bytes[0] == 0xEF && bytes[1] == 0xBB && bytes[2] == 0xBF)
                return System.Text.Encoding.UTF8.GetString(bytes, 3, bytes.Length - 3);
            return System.Text.Encoding.UTF8.GetString(bytes);
        }
        catch
        {
            return null;
        }
    }

    /// <summary>
    /// Where a downloaded README is cached.
    /// </summary>
    public static string DownloadedReadmePath =>
        Path.Combine(Path.GetTempPath(), "cyberpatriot_readme.html");

    /// <summary>
    /// Fetch a remotely hosted README and return the local path it was saved to.
    /// </summary>
    /// <remarks>
    /// A standard competition image does not ship the README as a file:
    /// <c>C:\CyberPatriot\README.url</c> points at an https:// document, which is
    /// what the competitor's browser opens. Reading it requires an HTTP request.
    /// </remarks>
    private static async Task<string?> DownloadReadmeAsync(string url)
    {
        var destination = DownloadedReadmePath;
        Spectre.Console.AnsiConsole.MarkupLine(
            $"[cyan]Downloading README from {Spectre.Console.Markup.Escape(url)}[/]"
        );

        var error = await CommandExecutor.DownloadFileAsync(url, destination);
        if (error == null)
            return destination;

        Spectre.Console.AnsiConsole.MarkupLine(
            $"[red]Could not download the README: {Spectre.Console.Markup.Escape(error)}[/]"
        );
        return null;
    }

    /// <summary>
    /// Explain why an existing candidate could not be turned into a README path.
    /// </summary>
    private static string DescribeUnresolvable(string path)
    {
        if (!Path.GetExtension(path).Equals(".url", StringComparison.OrdinalIgnoreCase))
            return "exists but could not be resolved to a readable file";

        var contents = ReadTextLenient(path);
        if (contents == null)
            return "shortcut could not be read";

        var target = ParseInternetShortcut(contents);
        if (target == null)
            return "shortcut has no URL= entry";

        if (IsRemoteTarget(target))
            return $"shortcut points to '{target}', which could not be downloaded";

        var local = ToLocalPath(target);
        return local == null
            ? $"shortcut target '{target}' is not a usable location"
            : $"shortcut points to '{local}', which does not exist";
    }

    /// <summary>
    /// Resolve a single-<c>*</c> pattern such as
    /// <c>C:\Users\*\Desktop\README.html</c> by enumerating the starred position.
    /// </summary>
    /// <remarks>
    /// Stripping the <c>*</c> and searching recursively - as this used to - turned
    /// the pattern into a parent of <c>C:\Users\Desktop</c>, which does not exist,
    /// so the fallback silently never matched. Had it existed, recursing all of
    /// <c>C:\Users</c> would have been worse: it would return the first
    /// README.html found anywhere in any profile, documents and downloads
    /// included, rather than a competition README.
    /// </remarks>
    public static string[] ExpandWildcardPath(string pattern)
    {
        var star = pattern.IndexOf('*');
        if (star < 0)
            return Array.Empty<string>();

        var prefix = pattern[..star].TrimEnd('\\', '/');
        var suffix = pattern[(star + 1)..].TrimStart('\\', '/');

        try
        {
            if (!Directory.Exists(prefix))
                return Array.Empty<string>();

            // Directory order is arbitrary; sort so repeated runs pick the same file.
            return Directory
                .GetDirectories(prefix)
                .Select(dir => Path.Combine(dir, suffix))
                .Where(File.Exists)
                .OrderBy(p => p, StringComparer.OrdinalIgnoreCase)
                .ToArray();
        }
        catch
        {
            return Array.Empty<string>();
        }
    }

    /// <summary>
    /// Secure passwords for user account management
    /// These meet complexity requirements: 14+ chars, upper, lower, digit, special
    /// </summary>
    public static readonly string[] SecurePasswords = new[]
    {
        "CyberP@tr10t2026!",
        "Secur3P@ssw0rd#1",
        "Str0ng!P@ssKey99",
        "C0mpl3x#Pass2026",
        "H@rdT0Gu3ss!123",
        "S@fetyF1rst#2026",
        "Pr0t3ct3d!Acc0unt",
        "N0H@ck1ng#All0wed",
        "D3f3nd3r$#Strong1",
        "W1nd0ws!S3cur3#99",
    };
}
