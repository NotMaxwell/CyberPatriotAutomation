namespace CyberPatriotAutomation.Core.Models;

/// <summary>
/// Represents user account information and permissions
/// </summary>
public class AccountInfo
{
    public string Username { get; set; } = string.Empty;
    public string FullName { get; set; } = string.Empty;
    public bool IsEnabled { get; set; }
    public bool IsAdmin { get; set; }
    public bool PasswordRequired { get; set; }
    public bool PasswordNeverExpires { get; set; }
    public bool CannotChangePassword { get; set; }
    public DateTime? LastLogon { get; set; }
    public DateTime? PasswordLastSet { get; set; }
    public List<string> GroupMemberships { get; set; } = new();
}

/// <summary>
/// Security standards for account permissions
/// </summary>
public static class AccountSecurityStandards
{
    /// <summary>
    /// Guest account should be disabled
    /// </summary>
    public const bool GuestAccountShouldBeDisabled = true;

    /// <summary>
    /// Administrator account should be renamed from default
    /// </summary>
    public const bool AdminAccountShouldBeRenamed = true;

    /// <summary>
    /// All users should have password required
    /// </summary>
    public const bool PasswordShouldBeRequired = true;

    /// <summary>
    /// Passwords should expire (not set to never expire)
    /// </summary>
    public const bool PasswordShouldExpire = true;

    /// <summary>
    /// Maximum days of inactivity before account should be reviewed
    /// </summary>
    public const int MaxInactiveDays = 90;

    /// <summary>
    /// Known default/insecure usernames to check
    /// </summary>
    public static readonly string[] InsecureUsernames = new[]
    {
        "Guest",
        "DefaultAccount",
        "WDAGUtilityAccount",
    };

    /// <summary>
    /// Built-in admin account name to check for rename
    /// </summary>
    public const string DefaultAdminName = "Administrator";
}
