using System.Runtime.Versioning;
using Windows.Win32;
// The Win32 metadata files the share APIs under Storage rather than with the
// rest of netapi32, so SHARE_INFO_502 is generated into this namespace even
// though NetShareEnum links against netapi32.dll like everything else here.
using Windows.Win32.Storage.FileSystem;

namespace PinnacleCyPat.Core.Native;

/// <summary>
/// Shared-folder enumeration and removal through netapi32, replacing
/// <c>net share</c> and <c>net share NAME /delete</c>.
/// </summary>
/// <remarks>
/// <para>
/// <c>net share</c> prints a localised table wrapped in a header, a dashed rule
/// and a trailing status sentence. The parser over that output reads the rows
/// between the rule and the sentence, which works on an English image and
/// returns nothing on any other - and "no shares" reads to the caller as "this
/// machine is already clean" rather than as a failure to look.
/// </para>
/// <para>
/// The delete path had a second problem: <c>net share NAME /delete</c> asks
/// "There are open files ... force them closed? (Y/N)" when the share is in use,
/// and with stdout redirected that question is captured rather than shown, so
/// the tool appears to hang. <see cref="Delete"/> takes no interest in open
/// handles and returns a status instead.
/// </para>
/// </remarks>
[SupportedOSPlatform("windows5.1.2600")]
public static class NativeShares
{
    private const uint NERR_Success = 0;

    /// <summary>netapi32's "that share does not exist" status.</summary>
    private const uint NERR_NetNameNotFound = 2310;

    /// <summary>netapi32 sizes the buffer itself when given this length.</summary>
    private const uint MAX_PREFERRED_LENGTH = uint.MaxValue;

    /// <summary>
    /// The names of every share on this machine, including the administrative
    /// ones. Returns null when the enumeration fails, so callers can tell "no
    /// shares" apart from "could not read the share list".
    /// </summary>
    public static unsafe List<string>? Enumerate()
    {
        byte* buffer = null;
        try
        {
            // Level 502 is the full view and needs administrator rights, which
            // the tool already requires for every remediation it performs. A
            // non-elevated run fails here and falls back to `net share`.
            var status = PInvoke.NetShareEnum(
                null!,
                502,
                out buffer,
                MAX_PREFERRED_LENGTH,
                out var read,
                out _,
                null
            );

            if (status != NERR_Success || buffer == null)
                return null;

            var shares = new List<string>((int)read);
            var entries = (SHARE_INFO_502*)buffer;
            for (uint i = 0; i < read; i++)
            {
                var name = entries[i].shi502_netname.ToString();
                if (!string.IsNullOrWhiteSpace(name))
                    shares.Add(name);
            }
            return shares;
        }
        finally
        {
            if (buffer != null)
                PInvoke.NetApiBufferFree(buffer);
        }
    }

    /// <summary>
    /// Remove a share. Returns null on success, or the reason. A share that is
    /// already gone is the desired end state, not a failure.
    /// </summary>
    public static string? Delete(string share)
    {
        var status = PInvoke.NetShareDel(null!, share, 0);
        return status == NERR_Success || status == NERR_NetNameNotFound
            ? null
            : $"could not remove share {share} ({Describe(status)})";
    }

    private static string Describe(uint status) =>
        new System.ComponentModel.Win32Exception((int)status).Message;
}
