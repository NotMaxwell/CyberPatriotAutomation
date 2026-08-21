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

    // Local groups are aliases at the LSA level, so a membership change reports
    // "already there" and "not there" with the alias spellings rather than the
    // NERR ones. Both are accepted: either way the wanted state already holds.
    private const uint ERROR_MEMBER_NOT_IN_ALIAS = 1377;
    private const uint ERROR_MEMBER_IN_ALIAS = 1378;
    private const uint NERR_UserInGroup = 2236;
    private const uint NERR_UserNotInGroup = 2237;

    // Same duality for the group itself: the NERR spellings come back from the
    // netapi32 layer, the alias ones from LSA underneath it.
    private const uint NERR_GroupNotFound = 2220;
    private const uint NERR_GroupExists = 2223;
    private const uint ERROR_ALIAS_EXISTS = 1379;
    private const uint ERROR_NO_SUCH_ALIAS = 1376;

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
    /// The local groups an account belongs to, by name. Returns null when the
    /// lookup fails.
    /// </summary>
    /// <remarks>
    /// Replaces one <c>(Get-LocalUser X | Get-LocalGroup).Name</c> per account -
    /// a PowerShell start-up each - with a single call.
    /// </remarks>
    public static unsafe List<string>? GroupsOf(string username)
    {
        byte* buffer = null;
        try
        {
            // Level 0 is just the group name. The flags argument would add the
            // groups reached through other groups; the tasks ask about direct
            // membership, which is what the cmdlet reported too.
            var status = PInvoke.NetUserGetLocalGroups(
                null!,
                username,
                0,
                0,
                out buffer,
                MAX_PREFERRED_LENGTH,
                out var read,
                out _
            );

            if (status != NERR_Success || buffer == null)
                return null;

            var groups = new List<string>((int)read);
            var entries = (LOCALGROUP_USERS_INFO_0*)buffer;
            for (uint i = 0; i < read; i++)
            {
                var name = entries[i].lgrui0_name.ToString();
                if (!string.IsNullOrWhiteSpace(name))
                    groups.Add(name);
            }
            return groups;
        }
        finally
        {
            if (buffer != null)
                PInvoke.NetApiBufferFree(buffer);
        }
    }

    /// <summary>
    /// Does a local group by this name exist? Returns null when the question
    /// could not be answered, which is not the same as "no".
    /// </summary>
    /// <remarks>
    /// The caller used to look for "does not exist" in <c>net localgroup</c>
    /// output. That string is localised, so on a non-English image the check
    /// read every group as already present and the tool created none of them.
    /// </remarks>
    public static unsafe bool? GroupExists(string group)
    {
        byte* buffer = null;
        try
        {
            // Level 0 is just the name; the status is the whole answer.
            var status = PInvoke.NetLocalGroupGetInfo(null!, group, 0, out buffer);
            return status switch
            {
                NERR_Success => true,
                NERR_GroupNotFound or ERROR_NO_SUCH_ALIAS => false,
                _ => null,
            };
        }
        finally
        {
            if (buffer != null)
                PInvoke.NetApiBufferFree(buffer);
        }
    }

    /// <summary>
    /// Create a local group. Returns null on success, or the reason. A group
    /// that already exists is the desired end state, not a failure.
    /// </summary>
    public static unsafe string? CreateGroup(string group)
    {
        fixed (char* name = group)
        {
            var info = new LOCALGROUP_INFO_0
            {
                lgrpi0_name = new Windows.Win32.Foundation.PWSTR(name),
            };
            var status = PInvoke.NetLocalGroupAdd(null!, 0, (byte*)&info, null);
            return status is NERR_Success or NERR_GroupExists or ERROR_ALIAS_EXISTS
                ? null
                : $"could not create group {group} ({Describe(status)})";
        }
    }

    /// <summary>
    /// Add an account to a local group. Returns null on success, or the reason.
    /// An account that is already a member is the desired end state, not a
    /// failure.
    /// </summary>
    public static unsafe string? AddToGroup(string username, string group)
    {
        // Level 3 takes the account as DOMAIN\user or a bare local name, so the
        // caller never has to look a SID up.
        fixed (char* name = username)
        {
            var member = new LOCALGROUP_MEMBERS_INFO_3
            {
                lgrmi3_domainandname = new Windows.Win32.Foundation.PWSTR(name),
            };
            var status = PInvoke.NetLocalGroupAddMembers(null!, group, 3, (byte*)&member, 1);
            return status is NERR_Success or ERROR_MEMBER_IN_ALIAS or NERR_UserInGroup
                ? null
                : $"could not add {username} to {group} ({Describe(status)})";
        }
    }

    /// <summary>
    /// Remove an account from a local group. Returns null on success, or the
    /// reason. An account that is not a member is the desired end state.
    /// </summary>
    public static unsafe string? RemoveFromGroup(string username, string group)
    {
        fixed (char* name = username)
        {
            var member = new LOCALGROUP_MEMBERS_INFO_3
            {
                lgrmi3_domainandname = new Windows.Win32.Foundation.PWSTR(name),
            };
            var status = PInvoke.NetLocalGroupDelMembers(null!, group, 3, (byte*)&member, 1);
            return status is NERR_Success or ERROR_MEMBER_NOT_IN_ALIAS or NERR_UserNotInGroup
                ? null
                : $"could not remove {username} from {group} ({Describe(status)})";
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

    /// <summary>
    /// Write a single-field user-modals level. Returns null on success, or the
    /// reason.
    /// </summary>
    /// <remarks>
    /// Levels 1001 to 1005 each take a struct whose only field is a
    /// <c>DWORD</c>, so the address of a local uint is the whole structure.
    /// Setting one of those leaves the rest of the policy untouched, which
    /// writing level 0 would not.
    /// </remarks>
    private static unsafe string? SetModals(uint level, uint value)
    {
        var status = PInvoke.NetUserModalsSet(null!, level, (byte*)&value, null);
        return status == NERR_Success
            ? null
            : $"could not write the password policy ({Describe(status)})";
    }

    /// <summary>Set the minimum password length, in characters.</summary>
    public static string? SetMinPasswordLength(int characters) =>
        SetModals(1001, Clamp(characters));

    /// <summary>Set the maximum password age. Zero means "never expires".</summary>
    public static string? SetMaxPasswordAgeDays(int days) =>
        SetModals(1002, days <= 0 ? TIMEQ_FOREVER : (uint)days * 86400);

    /// <summary>Set the minimum password age, in days.</summary>
    public static string? SetMinPasswordAgeDays(int days) =>
        SetModals(1003, Clamp(days) * 86400);

    /// <summary>Set how many previous passwords are remembered.</summary>
    public static string? SetPasswordHistoryLength(int count) => SetModals(1005, Clamp(count));

    /// <summary>
    /// The lockout policy as it currently stands, or null when it could not be
    /// read.
    /// </summary>
    /// <remarks>
    /// Lockout has no single-field modals level: it is written as a whole at
    /// level 3, so a change to one of its three values has to read the other two
    /// back first.
    /// </remarks>
    private static unsafe USER_MODALS_INFO_3? GetLockoutModals()
    {
        byte* buffer = null;
        try
        {
            var status = PInvoke.NetUserModalsGet(null!, 3, out buffer);
            if (status != NERR_Success || buffer == null)
                return null;
            return *(USER_MODALS_INFO_3*)buffer;
        }
        finally
        {
            if (buffer != null)
                PInvoke.NetApiBufferFree(buffer);
        }
    }

    private static unsafe string? SetLockoutModals(USER_MODALS_INFO_3 info)
    {
        var status = PInvoke.NetUserModalsSet(null!, 3, (byte*)&info, null);
        return status == NERR_Success
            ? null
            : $"could not write the lockout policy ({Describe(status)})";
    }

    /// <summary>Set how many bad passwords lock an account out. Zero disables lockout.</summary>
    public static string? SetLockoutThreshold(int attempts)
    {
        if (GetLockoutModals() is not USER_MODALS_INFO_3 info)
            return "could not read the lockout policy";

        info.usrmod3_lockout_threshold = Clamp(attempts);
        return SetLockoutModals(info);
    }

    /// <summary>Set how long an account stays locked out, in minutes.</summary>
    public static string? SetLockoutDurationMinutes(int minutes)
    {
        if (GetLockoutModals() is not USER_MODALS_INFO_3 info)
            return "could not read the lockout policy";

        info.usrmod3_lockout_duration = Clamp(minutes) * 60;
        // Windows rejects an observation window longer than the duration, and
        // `net accounts` silently narrowed one to match the other. Do the same
        // rather than fail.
        if (info.usrmod3_lockout_observation_window > info.usrmod3_lockout_duration)
            info.usrmod3_lockout_observation_window = info.usrmod3_lockout_duration;
        return SetLockoutModals(info);
    }

    /// <summary>Set how long bad attempts are counted for, in minutes.</summary>
    public static string? SetLockoutObservationMinutes(int minutes)
    {
        if (GetLockoutModals() is not USER_MODALS_INFO_3 info)
            return "could not read the lockout policy";

        info.usrmod3_lockout_observation_window = Clamp(minutes) * 60;
        if (info.usrmod3_lockout_duration < info.usrmod3_lockout_observation_window)
            info.usrmod3_lockout_duration = info.usrmod3_lockout_observation_window;
        return SetLockoutModals(info);
    }

    /// <summary>
    /// The policy standards are signed so a task can compare them against a
    /// parsed value; the API takes unsigned counts, and a negative one is
    /// meaningless.
    /// </summary>
    private static uint Clamp(int value) => value < 0 ? 0 : (uint)value;

    private static int ToDays(uint seconds) =>
        seconds == TIMEQ_FOREVER ? 0 : (int)(seconds / 86400);

    // `net accounts` reported both lockout spans in minutes, so callers that
    // compare against a README figure still see the units they expect.
    private static int ToMinutes(uint seconds) =>
        seconds == TIMEQ_FOREVER ? 0 : (int)(seconds / 60);

    private static string Describe(uint status) =>
        new System.ComponentModel.Win32Exception((int)status).Message;
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
