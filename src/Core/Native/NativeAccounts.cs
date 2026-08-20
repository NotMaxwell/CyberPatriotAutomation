using System.Runtime.Versioning;
using Windows.Win32;
using Windows.Win32.NetworkManagement.NetManagement;

namespace CyberPatriotAutomation.Core.Native;

/// <summary>
/// Local account and policy reads that go straight to netapi32 instead of
/// parsing the console output of <c>net</c>.
/// </summary>
/// <remarks>
/// <c>net localgroup</c> and <c>net accounts</c> print localised, human-formatted
/// tables: a header, a dashed rule, rows, then a status sentence. Any parser over
/// that output is guessing, and on a non-English Windows image the guess returns
/// nothing at all - which reads to the caller as "the group is empty" or "the
/// policy is already compliant" rather than as a failure. These calls return
/// structured data plus a Win32 status, so neither confusion is possible.
/// </remarks>
[SupportedOSPlatform("windows5.1.2600")]
public static class NativeAccounts
{
    private const uint NERR_Success = 0;

    /// <summary>netapi32 sizes the buffer itself when given this length.</summary>
    private const uint MAX_PREFERRED_LENGTH = uint.MaxValue;

    /// <summary>netapi32 reports "never expires" as this age.</summary>
    private const uint TIMEQ_FOREVER = uint.MaxValue;

    /// <summary>
    /// Members of a local group, by name. Returns null when the lookup fails, so
    /// callers can tell "no members" apart from "could not read the group".
    /// </summary>
    public static unsafe List<string>? GetGroupMembers(string group)
    {
        byte* buffer = null;
        try
        {
            // Level 3 yields LOCALGROUP_MEMBERS_INFO_3, whose one field is the
            // account already rendered as DOMAIN\user - no SID translation here.
            var status = PInvoke.NetLocalGroupGetMembers(
                null!,
                group,
                3,
                out buffer,
                MAX_PREFERRED_LENGTH,
                out var read,
                out _,
                null
            );

            if (status != NERR_Success || buffer == null)
                return null;

            var members = new List<string>((int)read);
            var entries = (LOCALGROUP_MEMBERS_INFO_3*)buffer;
            for (uint i = 0; i < read; i++)
            {
                var name = entries[i].lgrmi3_domainandname.ToString();
                if (!string.IsNullOrWhiteSpace(name))
                    members.Add(name);
            }
            return members;
        }
        finally
        {
            if (buffer != null)
                PInvoke.NetApiBufferFree(buffer);
        }
    }

    /// <summary>
    /// The machine's password policy. Returns null when the lookup fails.
    /// </summary>
    /// <remarks>
    /// netapi32 reports both ages in seconds; they are normalised to days here,
    /// with "never expires" surfaced as 0 to match what <c>net accounts</c> printed.
    /// </remarks>
    public static unsafe PasswordPolicyValues? GetPasswordPolicy()
    {
        byte* buffer = null;
        try
        {
            // Level 0 is the password-policy view of the user modals.
            var status = PInvoke.NetUserModalsGet(null!, 0, out buffer);
            if (status != NERR_Success || buffer == null)
                return null;

            var info = (USER_MODALS_INFO_0*)buffer;
            var policy = new PasswordPolicyValues(
                MinPasswordLength: (int)info->usrmod0_min_passwd_len,
                MaxPasswordAgeDays: ToDays(info->usrmod0_max_passwd_age),
                MinPasswordAgeDays: ToDays(info->usrmod0_min_passwd_age),
                PasswordHistoryLength: (int)info->usrmod0_password_hist_len,
                LockoutThreshold: 0,
                LockoutDurationMinutes: 0,
                LockoutObservationMinutes: 0
            );

            // Lockout lives in a different modals level, so it takes a second
            // call. A failure there leaves the password half of the policy
            // usable rather than discarding everything.
            var lockout = GetLockoutPolicy();
            return lockout is null
                ? policy
                : policy with
                {
                    LockoutThreshold = lockout.Value.Threshold,
                    LockoutDurationMinutes = lockout.Value.DurationMinutes,
                    LockoutObservationMinutes = lockout.Value.ObservationMinutes,
                };
        }
        finally
        {
            if (buffer != null)
                PInvoke.NetApiBufferFree(buffer);
        }
    }

    private static unsafe (
        int Threshold,
        int DurationMinutes,
        int ObservationMinutes
    )? GetLockoutPolicy()
    {
        byte* buffer = null;
        try
        {
            // Level 3 is the lockout view of the user modals.
            var status = PInvoke.NetUserModalsGet(null!, 3, out buffer);
            if (status != NERR_Success || buffer == null)
                return null;

            var info = (USER_MODALS_INFO_3*)buffer;
            return (
                (int)info->usrmod3_lockout_threshold,
                ToMinutes(info->usrmod3_lockout_duration),
                ToMinutes(info->usrmod3_lockout_observation_window)
            );
        }
        finally
        {
            if (buffer != null)
                PInvoke.NetApiBufferFree(buffer);
        }
    }

    private static int ToDays(uint seconds) =>
        seconds == TIMEQ_FOREVER ? 0 : (int)(seconds / 86400);

    // `net accounts` reported both lockout spans in minutes, so callers that
    // compare against a README figure still see the units they expect.
    private static int ToMinutes(uint seconds) =>
        seconds == TIMEQ_FOREVER ? 0 : (int)(seconds / 60);
}

/// <summary>Password policy as netapi32 reports it, normalised to days.</summary>
public readonly record struct PasswordPolicyValues(
    int MinPasswordLength,
    int MaxPasswordAgeDays,
    int MinPasswordAgeDays,
    int PasswordHistoryLength,
    int LockoutThreshold,
    int LockoutDurationMinutes,
    int LockoutObservationMinutes
);
