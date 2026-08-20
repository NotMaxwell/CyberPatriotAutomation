using CyberPatriotAutomation.Core.Models;

namespace CyberPatriotAutomation.Core.Utilities;

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
        var (success, output, _) = await CommandExecutor.ExecuteAsync(
            "net",
            $"localgroup \"{group}\""
        );
        return success ? ParseGroupMembers(output) : new List<string>();
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

    /// <summary>Set a local account's password. Returns null on success.</summary>
    public static async Task<string?> SetPasswordAsync(string username, string password)
    {
        var script =
            $"Set-LocalUser -Name {CommandExecutor.PsQuote(username)} "
            + $"-Password (ConvertTo-SecureString {CommandExecutor.PsQuote(password)} -AsPlainText -Force)";
        var (success, _, error) = await CommandExecutor.PowerShellAsync(script);
        return success ? null : Describe(error);
    }

    /// <summary>Create a local account. Returns null on success.</summary>
    public static async Task<string?> CreateUserAsync(string username, string password)
    {
        var script =
            $"New-LocalUser -Name {CommandExecutor.PsQuote(username)} "
            + $"-Password (ConvertTo-SecureString {CommandExecutor.PsQuote(password)} -AsPlainText -Force) "
            + "-AccountNeverExpires -ErrorAction Stop | Out-Null";
        var (success, _, error) = await CommandExecutor.PowerShellAsync(script);
        return success ? null : Describe(error);
    }

    /// <summary>Add an account to a local group. Returns null on success.</summary>
    public static async Task<string?> AddToGroupAsync(string username, string group)
    {
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
    }

    /// <summary>Remove an account from a local group. Returns null on success.</summary>
    public static async Task<string?> RemoveFromGroupAsync(string username, string group)
    {
        var script =
            $"Remove-LocalGroupMember -Group {CommandExecutor.PsQuote(group)} "
            + $"-Member {CommandExecutor.PsQuote(username)}";
        var (success, _, error) = await CommandExecutor.PowerShellAsync(script);
        return success ? null : Describe(error);
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
