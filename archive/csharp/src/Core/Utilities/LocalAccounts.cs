using PinnacleCyPat.Core.Models;

namespace PinnacleCyPat.Core.Utilities;

/// <summary>
/// Local account and group operations shared by the account-related tasks.
/// </summary>
/// <remarks>
/// These go through PowerShell rather than <c>net</c>. <c>net user</c>
/// interactively confirms any password longer than 14 characters ("Do you want
/// to continue this operation? (Y/N)"), and these commands run without a console
/// to answer it, so the prompt reaches EOF and <c>net</c> aborts. Every generated
/// password is longer than that, so every password change and every account
/// creation failed. The <c>*-LocalUser</c> cmdlets have no prompt and report a
/// real reason on failure.
/// </remarks>
public static class LocalAccounts
{
    /// <summary>
    /// Read the members of a local group via <c>net localgroup</c>.
    /// </summary>
    /// <remarks>
    /// The output wraps the member list in a header, a dashed separator and a
    /// trailing status line. Only the rows between them are members. Callers
    /// previously substring-searched the whole blob, which matched the
    /// surrounding prose - an account named "admin" matched the word
    /// "Administrators" in the header and was treated as an administrator.
    /// </remarks>
    public static async Task<List<string>> GetGroupMembersAsync(string group)
    {
#if WINDOWS
        // netapi32 returns the members as data, so there is nothing to parse and
        // nothing that depends on the console language. ParseGroupMembers stays
        // as the fallback for the rare case the call itself fails.
        var native = Native.NativeAccounts.GetGroupMembers(group);
        if (native is not null)
            return native;
#endif
        var (success, output, _) = await CommandExecutor.ExecuteAsync(
            "net",
            $"localgroup \"{group}\""
        );
        return success ? ParseGroupMembers(output) : new List<string>();
    }

    /// <summary>
    /// Every ordinary local account, without its group memberships. Returns null
    /// when the list could not be read at all, so "no accounts" and "could not
    /// look" stay distinguishable.
    /// </summary>
    /// <remarks>
    /// Callers fill in <see cref="AccountInfo.IsAdmin"/> and the group list
    /// themselves, because those come from the group side.
    /// </remarks>
    public static async Task<List<AccountInfo>?> EnumerateUsersAsync()
    {
#if WINDOWS
        var native = Native.NativeUsers.Enumerate();
        if (native is not null)
        {
            return native
                .Select(u => new AccountInfo
                {
                    Username = u.Name,
                    FullName = u.FullName,
                    IsEnabled = u.IsEnabled,
                    PasswordRequired = u.PasswordRequired,
                    PasswordNeverExpires = u.PasswordNeverExpires,
                    // netapi32 reports the stamp in seconds since the Unix
                    // epoch, and 0 for "has never logged on".
                    LastLogon =
                        u.LastLogon == 0
                            ? null
                            : DateTimeOffset.FromUnixTimeSeconds(u.LastLogon).LocalDateTime,
                })
                .ToList();
        }
#endif
        var (success, output, _) = await CommandExecutor.PowerShellQueryAsync(
            "Get-LocalUser | Select-Object Name, FullName, Enabled, PasswordRequired, "
                + "PasswordNeverExpires, LastLogon | ConvertTo-Csv -NoTypeInformation"
        );
        if (!success || string.IsNullOrEmpty(output))
            return null;

        return output
            .Split(new[] { '\r', '\n' }, StringSplitOptions.RemoveEmptyEntries)
            .Skip(1)
            .Select(ParseAccountCsvLine)
            .OfType<AccountInfo>()
            .ToList();
    }

    /// <summary>
    /// Turn one <c>Get-LocalUser | ConvertTo-Csv</c> row into an account.
    /// Only reached when the Windows API is unavailable.
    /// </summary>
    private static AccountInfo? ParseAccountCsvLine(string line)
    {
        var values = line.Split("\",\"").Select(v => v.Trim().Trim('"').Trim()).ToList();
        if (values.Count < 3 || values[0].Length == 0)
            return null;

        string Field(int index) => index < values.Count ? values[index] : string.Empty;
        bool Flag(int index) => Field(index).Equals("True", StringComparison.OrdinalIgnoreCase);

        return new AccountInfo
        {
            Username = Field(0),
            FullName = Field(1),
            IsEnabled = Flag(2),
            PasswordRequired = Flag(3),
            PasswordNeverExpires = Flag(4),
            LastLogon = DateTime.TryParse(Field(5), out var logon) ? logon : null,
        };
    }

    /// <summary>The local groups an account belongs to, by name.</summary>
    public static async Task<List<string>> GroupsOfAsync(string username)
    {
#if WINDOWS
        var native = Native.NativeAccounts.GroupsOf(username);
        if (native is not null)
            return native;
#endif
        var (success, output, _) = await CommandExecutor.PowerShellQueryAsync(
            $"(Get-LocalUser {CommandExecutor.PsQuote(username)} | Get-LocalGroup).Name"
        );
        return success && !string.IsNullOrEmpty(output)
            ? output
                .Split(new[] { '\r', '\n' }, StringSplitOptions.RemoveEmptyEntries)
                .Select(l => l.Trim())
                .Where(l => l.Length > 0)
                .ToList()
            : new List<string>();
    }

    /// <summary>
    /// Split <c>net localgroup</c> output into member names.
    /// </summary>
    public static List<string> ParseGroupMembers(string output)
    {
        var members = new List<string>();
        var pastSeparator = false;

        foreach (var raw in output.Split('\n'))
        {
            var line = raw.Trim();
            if (line.Length == 0)
                continue;

            if (line.StartsWith("---", StringComparison.Ordinal))
            {
                pastSeparator = true;
                continue;
            }

            if (!pastSeparator)
                continue;

            // `net` ends the listing with a status sentence.
            if (line.StartsWith("The command completed", StringComparison.OrdinalIgnoreCase))
                break;

            members.Add(line);
        }

        return members;
    }

    /// <summary>
    /// Is <paramref name="username"/> one of <paramref name="members"/>?
    /// Handles the DOMAIN\user form that <c>net</c> prints for non-local accounts.
    /// </summary>
    public static bool IsGroupMember(IEnumerable<string> members, string username) =>
        members.Any(m =>
            m.Equals(username, StringComparison.OrdinalIgnoreCase)
            || m.Split('\\').Last().Equals(username, StringComparison.OrdinalIgnoreCase)
        );

    /// <summary>
    /// A strong password unique to each account.
    /// </summary>
    /// <remarks>
    /// Cycling a fixed list alone repeats passwords once there are more accounts
    /// than entries; the index suffix keeps every account distinct while
    /// preserving length and character-class coverage.
    /// </remarks>
    public static string GeneratePassword(int index) =>
        $"{AppConfig.SecurePasswords[index % AppConfig.SecurePasswords.Length]}#{index:D2}";

    /// <summary>
    /// One account as the machine currently reports it, or null when it does not
    /// exist or could not be read.
    /// </summary>
    /// <remarks>
    /// The evidence for every account change comes from here, so it goes through
    /// <see cref="EnumerateUsersAsync"/> rather than the API directly - that way
    /// the proof is read the same way on the fallback path as on the native one.
    /// </remarks>
    private static async Task<AccountInfo?> ReadAccountAsync(string username) =>
        (await EnumerateUsersAsync())?.FirstOrDefault(a =>
            a.Username.Equals(username, StringComparison.OrdinalIgnoreCase)
        );

    /// <summary>Whether an account exists, as evidence text.</summary>
    /// <remarks>
    /// Null means the account list could not be read at all, which the ledger
    /// must not confuse with the account being absent.
    /// </remarks>
    private static async Task<string?> ReadPresenceAsync(string username)
    {
        var accounts = await EnumerateUsersAsync();
        if (accounts is null)
            return null;

        return accounts.Any(a => a.Username.Equals(username, StringComparison.OrdinalIgnoreCase))
            ? "present"
            : "absent";
    }

    /// <summary>Set a local account's password. Returns null on success.</summary>
    public static Task<string?> SetPasswordAsync(string username, string password) =>
        Remediation.ApplyUnprovableAsync(
            target: $"Account {username}",
            intent: "a strong password that is not the competition default",
            action: "wrote a new password into the account database",
            whyUnprovable: "Windows will not hand a password back. "
                + "The account database accepted it.",
            apply: () => SetPasswordCoreAsync(username, password)
        );

    private static async Task<string?> SetPasswordCoreAsync(string username, string password)
    {
#if WINDOWS
        // netapi32 writes the password straight into the account database: no
        // PowerShell start-up per account, and no 14-character prompt to answer.
        return Native.NativeUsers.SetPassword(username, password);
#else
        var script =
            $"Set-LocalUser -Name {CommandExecutor.PsQuote(username)} "
            + $"-Password (ConvertTo-SecureString {CommandExecutor.PsQuote(password)} -AsPlainText -Force)";
        var (success, _, error) = await CommandExecutor.PowerShellAsync(script);
        return success ? null : Describe(error);
#endif
    }

    /// <summary>
    /// Delete a local account. Returns null on success. An account that is
    /// already gone is the desired end state, not a failure.
    /// </summary>
    public static Task<string?> DeleteUserAsync(string username, string? why = null) =>
        Remediation.ApplyAsync(
            target: $"Account {username}",
            intent: why is null ? "deleted" : $"deleted ({why})",
            readState: () => ReadPresenceAsync(username),
            isCompliant: state => state == "absent",
            action: "deleted the account",
            apply: () => DeleteUserCoreAsync(username)
        );

    private static async Task<string?> DeleteUserCoreAsync(string username)
    {
#if WINDOWS
        return Native.NativeUsers.Delete(username);
#else
        var (success, _, error) = await CommandExecutor.ExecuteAsync(
            "net",
            $"user \"{username}\" /delete"
        );
        return success ? null : Describe(error);
#endif
    }

    /// <summary>
    /// Enable or disable a local account. Returns null on success.
    /// </summary>
    public static Task<string?> SetEnabledAsync(string username, bool enabled, string? why = null)
    {
        var wanted = enabled ? "enabled" : "disabled";
        return Remediation.ApplyAsync(
            target: $"Account {username}",
            intent: why is null ? wanted : $"{wanted} ({why})",
            readState: async () =>
                await ReadAccountAsync(username) is { } account
                    ? account.IsEnabled
                        ? "enabled"
                        : "disabled"
                    : null,
            isCompliant: state => state == wanted,
            action: enabled ? "cleared the account-disabled flag" : "set the account-disabled flag",
            apply: () => SetEnabledCoreAsync(username, enabled)
        );
    }

    private static async Task<string?> SetEnabledCoreAsync(string username, bool enabled)
    {
#if WINDOWS
        return Native.NativeUsers.SetEnabled(username, enabled);
#else
        var (success, _, error) = await CommandExecutor.ExecuteAsync(
            "net",
            $"user \"{username}\" /active:{(enabled ? "yes" : "no")}"
        );
        return success ? null : Describe(error);
#endif
    }

    /// <summary>
    /// Subject an account's password to the maximum-age policy, or exempt it.
    /// Returns null on success.
    /// </summary>
    public static Task<string?> SetPasswordNeverExpiresAsync(string username, bool neverExpires)
    {
        var wanted = neverExpires ? "exempt from expiry" : "subject to the maximum-age policy";
        return Remediation.ApplyAsync(
            target: $"Account {username}",
            intent: $"password {wanted}",
            readState: async () =>
                await ReadAccountAsync(username) is { } account
                    ? account.PasswordNeverExpires
                        ? "exempt from expiry"
                        : "subject to the maximum-age policy"
                    : null,
            isCompliant: state => state == wanted,
            action: neverExpires
                ? "set the password-never-expires flag"
                : "cleared the password-never-expires flag",
            apply: () => SetPasswordNeverExpiresCoreAsync(username, neverExpires)
        );
    }

    private static async Task<string?> SetPasswordNeverExpiresCoreAsync(
        string username,
        bool neverExpires
    )
    {
#if WINDOWS
        return Native.NativeUsers.SetPasswordNeverExpires(username, neverExpires);
#else
        var script =
            $"Set-LocalUser -Name {CommandExecutor.PsQuote(username)} "
            + $"-PasswordNeverExpires ${neverExpires.ToString().ToLowerInvariant()}";
        var (success, _, error) = await CommandExecutor.PowerShellAsync(script);
        return success ? null : Describe(error);
#endif
    }

    /// <summary>
    /// Clear an account's "no password required" flag. Returns null on success.
    /// </summary>
    /// <remarks>
    /// There is no <c>net user</c> or <c>*-LocalUser</c> equivalent - the flag is
    /// only reachable through the account database - so the fallback can do
    /// nothing but say so.
    /// </remarks>
    public static Task<string?> RequirePasswordAsync(string username) =>
        Remediation.ApplyAsync(
            target: $"Account {username}",
            intent: "a password required to log in",
            readState: async () =>
                await ReadAccountAsync(username) is { } account
                    ? account.PasswordRequired
                        ? "password required"
                        : "no password required"
                    : null,
            isCompliant: state => state == "password required",
            action: "cleared the password-not-required flag",
            apply: () => RequirePasswordCoreAsync(username)
        );

    private static Task<string?> RequirePasswordCoreAsync(string username)
    {
#if WINDOWS
        return Task.FromResult(Native.NativeUsers.RequirePassword(username));
#else
        return Task.FromResult<string?>(
            $"the password-required flag on {username} cannot be set without the Windows API"
        );
#endif
    }

    /// <summary>Create a local account. Returns null on success.</summary>
    public static Task<string?> CreateUserAsync(
        string username,
        string password,
        string? why = null
    ) =>
        Remediation.ApplyAsync(
            target: $"Account {username}",
            intent: why is null
                ? "present, with a strong password"
                : $"present, with a strong password ({why})",
            readState: () => ReadPresenceAsync(username),
            isCompliant: state => state == "present",
            action: "created the account with New-LocalUser",
            apply: () => CreateUserCoreAsync(username, password)
        );

    private static async Task<string?> CreateUserCoreAsync(string username, string password)
    {
        var script =
            $"New-LocalUser -Name {CommandExecutor.PsQuote(username)} "
            + $"-Password (ConvertTo-SecureString {CommandExecutor.PsQuote(password)} -AsPlainText -Force) "
            + "-AccountNeverExpires -ErrorAction Stop | Out-Null";
        var (success, _, error) = await CommandExecutor.PowerShellAsync(script);
        return success ? null : Describe(error);
    }

    /// <summary>
    /// Does a local group by this name exist? Null when the question could not
    /// be answered, which is not the same as "no".
    /// </summary>
    public static async Task<bool?> GroupExistsAsync(string group)
    {
#if WINDOWS
        var native = Native.NativeAccounts.GroupExists(group);
        if (native is not null)
            return native;
#endif
        var (success, output, _) = await CommandExecutor.ExecuteAsync(
            "net",
            $"localgroup \"{group}\""
        );
        // `net` says so in the console language, so this only holds on an
        // English image - which is the whole reason the API path exists.
        if (!success)
            return output.Contains("does not exist", StringComparison.OrdinalIgnoreCase)
                ? false
                : null;
        return true;
    }

    /// <summary>
    /// Create a local group. Returns null on success. A group that already
    /// exists is the desired end state, not a failure.
    /// </summary>
    public static Task<string?> CreateGroupAsync(string group, string? why = null) =>
        Remediation.ApplyAsync(
            target: $"Group {group}",
            intent: why is null ? "present" : $"present ({why})",
            readState: async () =>
                await GroupExistsAsync(group) switch
                {
                    true => "present",
                    false => "absent",
                    null => null,
                },
            isCompliant: state => state == "present",
            action: "created the local group",
            apply: () => CreateGroupCoreAsync(group)
        );

    private static async Task<string?> CreateGroupCoreAsync(string group)
    {
#if WINDOWS
        return Native.NativeAccounts.CreateGroup(group);
#else
        var (success, _, error) = await CommandExecutor.ExecuteAsync(
            "net",
            $"localgroup \"{group}\" /add"
        );
        return success ? null : Describe(error);
#endif
    }

    /// <summary>Membership as evidence text, or null when it could not be read.</summary>
    private static async Task<string?> ReadMembershipAsync(string username, string group)
    {
        var members = await GetGroupMembersAsync(group);
        // An empty list from a group that does exist is a real answer; one from a
        // group that could not be read is not, and the two are told apart by
        // asking whether the group is there at all.
        if (members.Count == 0 && await GroupExistsAsync(group) is not true)
            return null;
        return IsGroupMember(members, username) ? "a member" : "not a member";
    }

    /// <summary>Add an account to a local group. Returns null on success.</summary>
    public static Task<string?> AddToGroupAsync(
        string username,
        string group,
        string? why = null
    ) =>
        Remediation.ApplyAsync(
            target: $"{username} in {group}",
            intent: why is null ? "a member" : $"a member ({why})",
            readState: () => ReadMembershipAsync(username, group),
            isCompliant: state => state == "a member",
            action: $"added {username} to {group}",
            apply: () => AddToGroupCoreAsync(username, group)
        );

    private static async Task<string?> AddToGroupCoreAsync(string username, string group)
    {
#if WINDOWS
        // Already a member reads as success from here, so the "already a member"
        // string match the PowerShell path needs has no equivalent.
        return Native.NativeAccounts.AddToGroup(username, group);
#else
        var script =
            $"Add-LocalGroupMember -Group {CommandExecutor.PsQuote(group)} "
            + $"-Member {CommandExecutor.PsQuote(username)}";
        var (success, _, error) = await CommandExecutor.PowerShellAsync(script);
        if (success)
            return null;

        var reason = Describe(error);
        // Already a member is the desired end state, not a failure.
        return reason.Contains("already a member", StringComparison.OrdinalIgnoreCase)
            ? null
            : reason;
#endif
    }

    /// <summary>Remove an account from a local group. Returns null on success.</summary>
    public static Task<string?> RemoveFromGroupAsync(
        string username,
        string group,
        string? why = null
    ) =>
        Remediation.ApplyAsync(
            target: $"{username} in {group}",
            intent: why is null ? "not a member" : $"not a member ({why})",
            readState: () => ReadMembershipAsync(username, group),
            isCompliant: state => state == "not a member",
            action: $"removed {username} from {group}",
            apply: () => RemoveFromGroupCoreAsync(username, group)
        );

    private static async Task<string?> RemoveFromGroupCoreAsync(string username, string group)
    {
#if WINDOWS
        return Native.NativeAccounts.RemoveFromGroup(username, group);
#else
        var script =
            $"Remove-LocalGroupMember -Group {CommandExecutor.PsQuote(group)} "
            + $"-Member {CommandExecutor.PsQuote(username)}";
        var (success, _, error) = await CommandExecutor.PowerShellAsync(script);
        return success ? null : Describe(error);
#endif
    }

    /// <summary>Names the README marks as the primary, auto-login user.</summary>
    /// <remarks>
    /// READMEs state plainly that changing this account's password may lock you
    /// out of the machine, so it is left alone.
    /// </remarks>
    public static HashSet<string> PrimaryUsers(ReadmeData? readme)
    {
        var primary = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        if (readme == null)
            return primary;

        foreach (var user in readme.Administrators.Concat(readme.Users))
        {
            if (user.IsPrimaryUser)
                primary.Add(user.Username);
        }
        return primary;
    }

    private static string Describe(string? error) =>
        string.IsNullOrWhiteSpace(error) ? "no reason reported" : error.Trim();
}
