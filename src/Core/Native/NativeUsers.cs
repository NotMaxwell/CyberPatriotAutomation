using System.Runtime.Versioning;
using Windows.Win32;
using Windows.Win32.Foundation;
using Windows.Win32.NetworkManagement.NetManagement;

namespace CyberPatriotAutomation.Core.Native;

/// <summary>
/// Local account changes through netapi32, replacing <c>net user</c> and the
/// <c>*-LocalUser</c> cmdlets.
/// </summary>
/// <remarks>
/// <para>
/// Both shell paths failed in their own way. <c>net user</c> asks "Do you want
/// to continue this operation? (Y/N)" for any password longer than 14
/// characters, and these commands run with no console to answer it, so the
/// prompt reaches EOF and <c>net</c> aborts - every generated password is longer
/// than that, so every password change failed. The <c>*-LocalUser</c> cmdlets
/// have no prompt but cost a PowerShell start-up per account, and report
/// failure as a formatted English error record rather than a status code.
/// </para>
/// <para>
/// These calls change the account database directly and hand back a Win32
/// status, so "no such user" and "access denied" stop looking alike.
/// </para>
/// </remarks>
[SupportedOSPlatform("windows5.1.2600")]
public static class NativeUsers
{
    private const uint NERR_Success = 0;

    /// <summary>netapi32's "that account does not exist" status.</summary>
    private const uint NERR_UserNotFound = 2221;

    /// <summary>The account is disabled and cannot be logged into.</summary>
    public const uint UF_ACCOUNTDISABLE = 0x0002;

    /// <summary>No password is required to log into the account.</summary>
    public const uint UF_PASSWD_NOTREQD = 0x0020;

    /// <summary>The account's password is exempt from the maximum-age policy.</summary>
    public const uint UF_DONT_EXPIRE_PASSWD = 0x10000;

    /// <summary>netapi32 sizes the buffer itself when given this length.</summary>
    private const uint MAX_PREFERRED_LENGTH = uint.MaxValue;

    /// <summary>Leave out the machine and trust accounts.</summary>
    private const uint FILTER_NORMAL_ACCOUNT = 0x0002;

    /// <summary>
    /// Every ordinary local account on this machine. Returns null when the
    /// enumeration fails, so callers can tell "no accounts" apart from "could
    /// not read the account list".
    /// </summary>
    /// <remarks>
    /// Replaces <c>Get-LocalUser | ConvertTo-Csv</c> and the CSV parser over its
    /// output, which cost a PowerShell start-up and reported <c>Enabled</c> as
    /// an English word.
    /// </remarks>
    public static unsafe List<LocalUser>? Enumerate()
    {
        byte* buffer = null;
        try
        {
            // Level 3 carries the flags and the last-logon stamp alongside the
            // names, so one call answers everything the account tasks ask.
            var status = PInvoke.NetUserEnum(
                null!,
                3,
                (NET_USER_ENUM_FILTER_FLAGS)FILTER_NORMAL_ACCOUNT,
                out buffer,
                MAX_PREFERRED_LENGTH,
                out var read,
                out _,
                null
            );

            if (status != NERR_Success || buffer == null)
                return null;

            var users = new List<LocalUser>((int)read);
            var entries = (USER_INFO_3*)buffer;
            for (uint i = 0; i < read; i++)
            {
                var name = entries[i].usri3_name.ToString();
                if (string.IsNullOrEmpty(name))
                    continue;

                users.Add(
                    new LocalUser(
                        Name: name,
                        FullName: entries[i].usri3_full_name.ToString() ?? string.Empty,
                        Comment: entries[i].usri3_comment.ToString() ?? string.Empty,
                        Flags: (uint)entries[i].usri3_flags,
                        LastLogon: entries[i].usri3_last_logon
                    )
                );
            }
            return users;
        }
        finally
        {
            if (buffer != null)
                PInvoke.NetApiBufferFree(buffer);
        }
    }

    /// <summary>
    /// An account's <c>UF_*</c> flags, or null when the account does not exist
    /// or could not be read.
    /// </summary>
    public static unsafe uint? GetFlags(string username)
    {
        byte* buffer = null;
        try
        {
            // Level 1 is the general account view; its flags field carries every
            // UF_* bit the tasks care about.
            var status = PInvoke.NetUserGetInfo(null!, username, 1, out buffer);
            if (status != NERR_Success || buffer == null)
                return null;

            // The cast covers both spellings of the field: the generated type is
            // a uint-backed enum, and a plain uint would widen to the same value.
            return (uint)((USER_INFO_1*)buffer)->usri1_flags;
        }
        finally
        {
            if (buffer != null)
                PInvoke.NetApiBufferFree(buffer);
        }
    }

    /// <summary>Does a local account by this name exist?</summary>
    public static bool Exists(string username) => GetFlags(username) is not null;

    /// <summary>
    /// Replace an account's <c>UF_*</c> flags wholesale. Returns null on
    /// success, or the reason.
    /// </summary>
    private static unsafe string? SetFlags(string username, uint flags)
    {
        // Level 1008 takes USER_INFO_1008, whose only field is the flags word,
        // so the address of a local uint is the whole structure. Setting only
        // this level leaves the rest of the account untouched - level 1 would
        // rewrite the home directory, comment and script path as well.
        var status = PInvoke.NetUserSetInfo(null!, username, 1008, (byte*)&flags, null);
        return status == NERR_Success
            ? null
            : $"could not update {username} ({Describe(status)})";
    }

    /// <summary>
    /// Turn one <c>UF_*</c> bit on or off, leaving the rest as they were.
    /// Returns null on success, or the reason.
    /// </summary>
    private static string? SetFlag(string username, uint flag, bool on)
    {
        if (GetFlags(username) is not uint current)
            return $"could not read the account flags of {username}";

        var updated = on ? current | flag : current & ~flag;

        // Already in the wanted state: nothing to write, and writing anyway
        // would fail on accounts the caller has no permission to change.
        return updated == current ? null : SetFlags(username, updated);
    }

    /// <summary>
    /// Subject an account's password to the maximum-age policy, or exempt it.
    /// Returns null on success, or the reason.
    /// </summary>
    public static string? SetPasswordNeverExpires(string username, bool neverExpires) =>
        SetFlag(username, UF_DONT_EXPIRE_PASSWD, neverExpires);

    /// <summary>
    /// Enable or disable an account. Returns null on success, or the reason.
    /// </summary>
    public static string? SetEnabled(string username, bool enabled) =>
        // The flag is stored the other way round: it marks the account disabled.
        SetFlag(username, UF_ACCOUNTDISABLE, !enabled);

    /// <summary>
    /// Require a password on an account that was set up without one. Returns
    /// null on success, or the reason.
    /// </summary>
    public static string? RequirePassword(string username) =>
        SetFlag(username, UF_PASSWD_NOTREQD, false);

    /// <summary>
    /// Set an account's password. Returns null on success, or the reason.
    /// </summary>
    /// <remarks>
    /// This is the call that <c>net user USER PASSWORD</c> could not make,
    /// because it refuses to accept a password over 14 characters without an
    /// answer to an interactive prompt.
    /// </remarks>
    public static unsafe string? SetPassword(string username, string password)
    {
        fixed (char* raw = password)
        {
            // Level 1003 takes USER_INFO_1003, whose only field is the password
            // pointer, so the address of a local PWSTR is the whole structure.
            var value = new PWSTR(raw);
            var status = PInvoke.NetUserSetInfo(null!, username, 1003, (byte*)&value, null);
            return status == NERR_Success
                ? null
                : $"could not set the password for {username} ({Describe(status)})";
        }
    }

    /// <summary>
    /// Delete a local account. Returns null on success, or the reason. An
    /// account that is already gone is the desired end state, not a failure.
    /// </summary>
    public static string? Delete(string username)
    {
        var status = PInvoke.NetUserDel(null!, username);
        return status == NERR_Success || status == NERR_UserNotFound
            ? null
            : $"could not delete {username} ({Describe(status)})";
    }

    private static string Describe(uint status) =>
        new System.ComponentModel.Win32Exception((int)status).Message;
}

/// <summary>One local account, as the account database holds it.</summary>
/// <param name="Flags">The <c>UF_*</c> bits; see <see cref="NativeUsers"/>.</param>
/// <param name="LastLogon">
/// Seconds since the Unix epoch, or 0 for "never logged on".
/// </param>
public readonly record struct LocalUser(
    string Name,
    string FullName,
    string Comment,
    uint Flags,
    uint LastLogon
)
{
    public bool IsEnabled => (Flags & NativeUsers.UF_ACCOUNTDISABLE) == 0;

    public bool PasswordRequired => (Flags & NativeUsers.UF_PASSWD_NOTREQD) == 0;

    public bool PasswordNeverExpires => (Flags & NativeUsers.UF_DONT_EXPIRE_PASSWD) != 0;
}
