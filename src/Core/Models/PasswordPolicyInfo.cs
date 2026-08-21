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

    /// <summary>
    /// Read the table <c>net accounts</c> prints.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Matches an English-language console only, which is why it is the fallback
    /// for the netapi32 read rather than the primary path. It lives on the model
    /// so the task and the run log's evidence read the output the same way; two
    /// parsers that disagreed would make a change look unapplied when it was not.
    /// </para>
    /// <para>
    /// <see cref="ComplexityEnabled"/> is not set here: it is not in this
    /// output, and only <c>secedit</c> reports it.
    /// </para>
    /// </remarks>
    public static PasswordPolicyInfo ParseNetAccounts(string output)
    {
        var policy = new PasswordPolicyInfo();

        foreach (
            var line in output.Split(new[] { '\r', '\n' }, StringSplitOptions.RemoveEmptyEntries)
        )
        {
            if (line.Contains("Minimum password length"))
                policy.MinPasswordLength = ExtractNumericValue(line);
            else if (line.Contains("Maximum password age"))
            {
                var value = ExtractNumericValue(line);
                // -1 is "Never"; the rest of the tool spells that 0.
                policy.MaxPasswordAge = value == -1 ? 0 : value;
            }
            else if (line.Contains("Minimum password age"))
                policy.MinPasswordAge = ExtractNumericValue(line);
            else if (line.Contains("Length of password history"))
                policy.PasswordHistoryCount = ExtractNumericValue(line);
            else if (line.Contains("Lockout threshold"))
            {
                var value = ExtractNumericValue(line);
                policy.LockoutThreshold = value == -1 ? 0 : value;
            }
            else if (line.Contains("Lockout duration"))
                policy.LockoutDuration = ExtractNumericValue(line);
            else if (line.Contains("Lockout observation window"))
                policy.LockoutObservationWindow = ExtractNumericValue(line);
        }

        return policy;
    }

    /// <summary>
    /// The number on the right of a <c>net accounts</c> row, with its words for
    /// "no limit" mapped to numbers.
    /// </summary>
    public static int ExtractNumericValue(string line)
    {
        var parts = line.Split(':');
        if (parts.Length <= 1)
            return 0;

        var value = parts[1].Trim();

        if (
            value.Contains("Never", StringComparison.OrdinalIgnoreCase)
            || value.Contains("Unlimited", StringComparison.OrdinalIgnoreCase)
        )
            return -1;

        if (value.Contains("None", StringComparison.OrdinalIgnoreCase))
            return 0;

        // The sign is kept: some locales print "-1" where English prints "Never".
        var digits = new string(value.TakeWhile(c => char.IsDigit(c) || c == '-').ToArray());
        return int.TryParse(digits, out var parsed) ? parsed : 0;
    }
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
