namespace CyberPatriotAutomation.Core.Models;

/// <summary>
/// Represents password policy settings
/// </summary>
public class PasswordPolicyInfo
{
    /// <summary>
    /// Minimum password length (NIST recommends 8+, enterprise typically 12-14+)
    /// </summary>
    public int MinPasswordLength { get; set; }

    /// <summary>
    /// Maximum password age in days (0 = never expires, recommended 60-90 days)
    /// </summary>
    public int MaxPasswordAge { get; set; }

    /// <summary>
    /// Minimum password age in days (recommended 1+ to prevent rapid changes)
    /// </summary>
    public int MinPasswordAge { get; set; }

    /// <summary>
    /// Number of passwords to remember (recommended 12-24)
    /// </summary>
    public int PasswordHistoryCount { get; set; }

    /// <summary>
    /// Whether password complexity is required (upper, lower, digit, special)
    /// </summary>
    public bool ComplexityEnabled { get; set; }

    /// <summary>
    /// Lockout threshold - number of failed attempts before lockout (recommended 3-5)
    /// </summary>
    public int LockoutThreshold { get; set; }

    /// <summary>
    /// Lockout duration in minutes (recommended 15-30 minutes)
    /// </summary>
    public int LockoutDuration { get; set; }

    /// <summary>
    /// Lockout observation window in minutes
    /// </summary>
    public int LockoutObservationWindow { get; set; }

    /// <summary>
    /// Whether reversible encryption is disabled (should be disabled)
    /// </summary>
    public bool ReversibleEncryptionDisabled { get; set; }
}

/// <summary>
/// Professional security standards for password policies
/// Based on NIST SP 800-63B, CIS Benchmarks, and industry best practices
/// </summary>
public static class PasswordPolicyStandards
{
    // Password Requirements
    public const int MinPasswordLength = 14;
    public const int MaxPasswordAge = 60; // days
    public const int MinPasswordAge = 1; // days
    public const int PasswordHistoryCount = 24;
    public const bool ComplexityEnabled = true;
    public const bool ReversibleEncryptionDisabled = true;

    // Account Lockout Policy
    public const int LockoutThreshold = 5; // failed attempts
    public const int LockoutDuration = 30; // minutes
    public const int LockoutObservationWindow = 30; // minutes
}
