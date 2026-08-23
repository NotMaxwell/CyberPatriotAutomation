// =============================================================================
// PinnacleCyPat - Uninstall command derivation
// Author: Maxwell McCormick
// Copyright (c) 2026 Maxwell McCormick. All Rights Reserved.
// =============================================================================
namespace PinnacleCyPat.Core.Utilities;

/// <summary>An uninstaller to run: the program, and the arguments to pass it.</summary>
public readonly record struct UninstallCommand(string Program, string Arguments)
{
    public override string ToString() => Arguments.Length == 0 ? Program : $"{Program} {Arguments}";
}

/// <summary>
/// Turns the <c>UninstallString</c> a program registers into something that can
/// actually be run unattended.
/// </summary>
/// <remarks>
/// <para>
/// This exists because <c>wmic product call uninstall</c> does not work. It reads
/// <c>Win32_Product</c>, which lists <b>only MSI-installed</b> software - and
/// CCleaner, Notepad++ and Jellyfin Media Player all ship NSIS installers, so
/// they are not in it at all. Worse, <c>wmic</c> exits <b>0</b> when its
/// <c>where</c> clause matches nothing, printing "No Instance(s) Available." to
/// stdout, so the caller saw success and reported the software as removed while
/// it sat untouched on disk. That is the reported symptom: the run says
/// "Removed: CCleaner" and CCleaner is still installed.
/// </para>
/// <para>
/// The uninstall registry keys already hold the real answer, and the inventory
/// reader was already reading it and throwing it away. What it holds is the
/// <i>interactive</i> uninstaller though, so running it as-is puts a dialog on
/// screen and blocks forever with stdin closed. Each installer family has its own
/// silent switch, and picking the right one is all this class does.
/// </para>
/// </remarks>
public static class UninstallCommandBuilder
{
    /// <summary>
    /// Silent switches by installer family. Order matters: the first match wins.
    /// </summary>
    /// <remarks>
    /// <list type="bullet">
    /// <item>MSI is detected by the <c>msiexec</c> program name.</item>
    /// <item>Inno Setup names its uninstaller <c>unins000.exe</c>.</item>
    /// <item>A bundle invoked with <c>/uninstall</c> - which is how Python's
    /// installer registers - takes <c>/quiet</c>.</item>
    /// <item>Everything else is assumed NSIS, whose switch is <c>/S</c>. That is
    /// the right default: NSIS is what CCleaner, Notepad++ and Jellyfin use, and
    /// an unrecognised switch is ignored by most installers rather than being
    /// fatal.</item>
    /// </list>
    /// </remarks>
    private static readonly string[] InnoSilentSwitches =
    [
        "/VERYSILENT",
        "/SUPPRESSMSGBOXES",
        "/NORESTART",
    ];

    /// <summary>
    /// Build a runnable, unattended uninstall command.
    /// </summary>
    /// <param name="uninstallString">The registry <c>UninstallString</c>.</param>
    /// <param name="alreadySilent">
    /// True when the value came from <c>QuietUninstallString</c>, which the
    /// publisher has already made unattended - nothing should be added to it.
    /// </param>
    /// <returns>The command, or null when the string cannot be parsed.</returns>
    public static UninstallCommand? Build(string? uninstallString, bool alreadySilent = false)
    {
        if (string.IsNullOrWhiteSpace(uninstallString))
            return null;

        var (program, arguments) = Split(uninstallString.Trim());
        if (program.Length == 0)
            return null;

        if (alreadySilent)
            return new UninstallCommand(program, arguments);

        var fileName = FileNameOf(program);

        // MSI: rewrite rather than append. The registered string is usually
        // "MsiExec.exe /I{GUID}" - /I is *install*, and passing it to an
        // installed product opens the repair/modify dialog instead of removing
        // anything. The product code is what matters; /x and /qn do the rest.
        if (fileName.Contains("msiexec", StringComparison.OrdinalIgnoreCase))
        {
            var productCode = ExtractProductCode(arguments);
            return productCode is null
                ? null
                : new UninstallCommand("msiexec.exe", $"/x {productCode} /qn /norestart");
        }

        var switches = new List<string>();

        // Inno names its uninstaller unins000.exe, numbered. A plain "unins"
        // prefix is too loose: CCleaner's NSIS uninstaller is uninst.exe, which
        // also starts with those five letters, and handing NSIS Inno's switches
        // means it gets no silent switch at all and blocks on a dialog.
        if (
            System.Text.RegularExpressions.Regex.IsMatch(
                fileName,
                @"^unins\d+\.exe$",
                System.Text.RegularExpressions.RegexOptions.IgnoreCase
            )
        )
        {
            switches.AddRange(InnoSilentSwitches);
        }
        else if (arguments.Contains("/uninstall", StringComparison.OrdinalIgnoreCase))
        {
            // A bundle re-invoked to uninstall itself, which is how Python
            // registers. Its own switch is already in `arguments`; this adds the
            // quiet half.
            switches.Add("/quiet");
            switches.Add("/norestart");
        }
        else
        {
            // NSIS. /S is case-sensitive - a lowercase /s is a different switch
            // or none at all.
            switches.Add("/S");
        }

        // Don't add a switch the string already carries: NSIS treats a repeated
        // /S harmlessly, but Inno's /VERYSILENT twice has been seen to trip its
        // own argument validation.
        var final = switches
            .Where(s => !arguments.Contains(s, StringComparison.OrdinalIgnoreCase))
            .ToList();

        var combined = string.Join(' ', new[] { arguments }.Concat(final).Where(p => p.Length > 0));
        return new UninstallCommand(program, combined);
    }

    /// <summary>
    /// The last path segment, splitting on both Windows and POSIX separators.
    /// </summary>
    /// <remarks>
    /// Not <see cref="Path.GetFileName(string)"/>: it uses the *host's*
    /// separator, so on a non-Windows host it does not treat a backslash as one
    /// and returns the entire path. These paths are always Windows paths
    /// whatever the host, and the tests run on Linux - where that difference
    /// silently turned every Inno uninstaller into an NSIS one.
    /// </remarks>
    private static string FileNameOf(string path)
    {
        var cut = path.LastIndexOfAny(['\\', '/']);
        return cut < 0 ? path : path[(cut + 1)..];
    }

    /// <summary>Executable extensions an uninstall string can name.</summary>
    private static readonly string[] ProgramExtensions = [".exe", ".com", ".bat", ".cmd", ".msi"];

    /// <summary>
    /// Split a command line into its program and the rest.
    /// </summary>
    /// <remarks>
    /// <para>
    /// A quoted program path is taken verbatim up to the closing quote.
    /// </para>
    /// <para>
    /// An unquoted one cannot simply end at the first space. Plenty of programs
    /// register an unquoted <c>UninstallString</c>, and the path routinely
    /// contains one - <c>C:\Program Files\CCleaner\uninst.exe</c> splits into
    /// the program <c>C:\Program</c> and nonsense arguments, and starting that
    /// fails outright. <c>CreateProcess</c> recovers by trying successive
    /// interpretations; <see cref="System.Diagnostics.ProcessStartInfo"/> with a
    /// separate FileName and Arguments does not. So the split is made at the
    /// executable extension instead, which is unambiguous.
    /// </para>
    /// </remarks>
    public static (string Program, string Arguments) Split(string commandLine)
    {
        commandLine = commandLine.Trim();
        if (commandLine.Length == 0)
            return (string.Empty, string.Empty);

        if (commandLine[0] == '"')
        {
            var end = commandLine.IndexOf('"', 1);
            if (end < 0)
                return (commandLine.Trim('"'), string.Empty);
            return (commandLine[1..end], commandLine[(end + 1)..].Trim());
        }

        // Split at the end of the first executable extension. The earliest match
        // wins so that arguments naming another executable cannot capture the
        // split.
        var best = -1;
        foreach (var extension in ProgramExtensions)
        {
            var at = commandLine.IndexOf(extension, StringComparison.OrdinalIgnoreCase);
            if (at >= 0 && (best < 0 || at < best))
                best = at + extension.Length;
        }

        if (best > 0)
            return (commandLine[..best], commandLine[best..].Trim());

        // No recognisable extension: fall back to the first space.
        var space = commandLine.IndexOf(' ');
        return space < 0
            ? (commandLine, string.Empty)
            : (commandLine[..space], commandLine[(space + 1)..].Trim());
    }

    /// <summary>
    /// Pull the <c>{GUID}</c> product code out of an msiexec argument list.
    /// </summary>
    public static string? ExtractProductCode(string arguments)
    {
        var open = arguments.IndexOf('{');
        if (open < 0)
            return null;
        var close = arguments.IndexOf('}', open);
        if (close < 0)
            return null;

        var code = arguments[open..(close + 1)];
        // A product code is {8-4-4-4-12}; anything else is not one, and passing
        // a malformed code to msiexec pops an error dialog.
        return code.Length == 38 ? code : null;
    }
}
