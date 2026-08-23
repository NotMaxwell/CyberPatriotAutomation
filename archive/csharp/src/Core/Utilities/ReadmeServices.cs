// =============================================================================
// PinnacleCyPat - README service-name resolution
// Author: Maxwell McCormick
// Copyright 2026 Maxwell McCormick. Licensed under Apache-2.0.
// =============================================================================
using PinnacleCyPat.Core.Models;

namespace PinnacleCyPat.Core.Utilities;

/// <summary>
/// Resolving the service names a README uses to the names Windows uses, and
/// answering "does the README say this service is critical?".
/// </summary>
/// <remarks>
/// <para>
/// This lives in one place because more than one task needs the answer and they
/// must not disagree. Service management protected <c>TermService</c> when the
/// README called Remote Desktop critical, while security hardening set
/// <c>fDenyTSConnections=1</c> regardless and never looked at the README at all
/// - so the service kept running and every connection to it was refused. That is
/// the worst of both outcomes, and it silently loses a scored item.
/// </para>
/// <para>
/// A README writes display names ("Remote Desktop"), not service names
/// ("TermService"), and is inconsistent about which - the same document may say
/// "Remote Desktop Services" in one line and "RDP" in another.
/// </para>
/// </remarks>
public static class ReadmeServices
{
    /// <summary>
    /// Display names a README might use, mapped to the Windows service name.
    /// </summary>
    public static readonly Dictionary<string, string> ServiceNameMap = new(
        StringComparer.OrdinalIgnoreCase
    )
    {
        { "CCS Client", "CCSClient" },
        { "Remote Desktop", "TermService" },
        { "Remote Desktop Services", "TermService" },
        { "Remote Desktop Service", "TermService" },
        { "RDP", "TermService" },
        { "Terminal Services", "TermService" },
        { "FTP", "ftpsvc" },
        { "Telnet", "TlntSvr" },
        { "SSH", "sshd" },
        { "OpenSSH", "sshd" },
        { "OpenSSH SSH Server", "sshd" },
        { "Remote Registry", "RemoteRegistry" },
        { "Windows Update", "wuauserv" },
        { "Windows Defender", "WinDefend" },
        { "Windows Firewall", "MpsSvc" },
        { "Print Spooler", "Spooler" },
        { "ICS", "SharedAccess" },
        { "Internet Connection Sharing", "SharedAccess" },
    };

    /// <summary>
    /// The Windows service name for a README's display name, or the name
    /// unchanged when it is not one this table knows.
    /// </summary>
    public static string Resolve(string displayName) =>
        ServiceNameMap.TryGetValue(displayName.Trim(), out var name) ? name : displayName.Trim();

    /// <summary>
    /// Does the README mark <paramref name="serviceName"/> as critical?
    /// </summary>
    /// <remarks>
    /// Every critical entry is resolved before comparing, so "Remote Desktop",
    /// "RDP" and "TermService" all answer the same question. A null README means
    /// no - nothing has been said either way, and the hardening default applies.
    /// </remarks>
    public static bool IsCritical(ReadmeData? readme, string serviceName)
    {
        if (readme is null)
            return false;

        var wanted = Resolve(serviceName);
        return readme.CriticalServices.Any(entry =>
            Resolve(entry).Equals(wanted, StringComparison.OrdinalIgnoreCase)
        );
    }

    /// <summary>
    /// Does the README require Remote Desktop to keep working?
    /// </summary>
    /// <remarks>
    /// Separate from <see cref="IsCritical"/> because RDP is asked about by two
    /// tasks and is the one hardening default a README routinely overrides: an
    /// image whose scenario is "this machine is administered remotely" scores
    /// RDP being *available*, and denying it loses that point while every other
    /// hardening step still applies.
    /// </remarks>
    public static bool IsRemoteDesktopRequired(ReadmeData? readme) =>
        IsCritical(readme, "TermService");
}
