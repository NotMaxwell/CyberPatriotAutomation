// =============================================================================
// PinnacleCyPat - Password and lockout policy writes
// Author: Maxwell McCormick
// Copyright 2026 Maxwell McCormick. Licensed under Apache-2.0.
// =============================================================================
namespace PinnacleCyPat.Core.Utilities;

/// <summary>
/// Password and lockout policy writes for the tasks: the Windows API where
/// available, otherwise <c>net accounts</c>.
/// </summary>
/// <remarks>
/// <para>
/// Deciding here rather than at every call site keeps the tasks readable and
/// keeps the fallback in one place. Each method returns the reason on failure
/// instead of a bare boolean, because <c>net accounts</c> reports failure only
/// through an exit code - so "that value is out of range" and "you are not an
/// administrator" looked alike - while netapi32 returns a status.
/// </para>
/// <para>
/// Every write is followed by a read of the policy, recorded in the run log as
/// the evidence for it. That matters more here than elsewhere: Windows
/// normalises several of these values silently - a lockout observation window
/// wider than the duration is narrowed to match - so a write that succeeds and a
/// policy that ends up as asked are genuinely different things.
/// </para>
/// </remarks>
public static class PolicyOps
{
    /// <summary>Set the minimum password length, in characters.</summary>
    public static Task<string?> SetMinPasswordLengthAsync(int characters) =>
        ApplyAsync(
            "Minimum password length",
            $"{characters} characters",
            p => p.MinPasswordLength,
            characters,
            () => SetMinPasswordLengthCore(characters)
        );

    /// <summary>Set the maximum password age, in days. Zero means "never expires".</summary>
    public static Task<string?> SetMaxPasswordAgeDaysAsync(int days) =>
        ApplyAsync(
            "Maximum password age",
            $"{days} days",
            p => p.MaxPasswordAgeDays,
            days,
            () => SetMaxPasswordAgeCore(days)
        );

    /// <summary>Set the minimum password age, in days.</summary>
    public static Task<string?> SetMinPasswordAgeDaysAsync(int days) =>
        ApplyAsync(
            "Minimum password age",
            $"{days} days",
            p => p.MinPasswordAgeDays,
            days,
            () => SetMinPasswordAgeCore(days)
        );

    /// <summary>Set how many previous passwords are remembered.</summary>
    public static Task<string?> SetPasswordHistoryLengthAsync(int count) =>
        ApplyAsync(
            "Password history",
            $"{count} remembered",
            p => p.PasswordHistoryLength,
            count,
            () => SetPasswordHistoryCore(count)
        );

    /// <summary>
    /// Set how many bad passwords lock an account out. Zero disables lockout.
    /// </summary>
    public static Task<string?> SetLockoutThresholdAsync(int attempts) =>
        ApplyAsync(
            "Account lockout threshold",
            $"{attempts} bad attempts",
            p => p.LockoutThreshold,
            attempts,
            () => SetLockoutThresholdCore(attempts)
        );

    /// <summary>Set how long an account stays locked out, in minutes.</summary>
    public static Task<string?> SetLockoutDurationMinutesAsync(int minutes) =>
        ApplyAsync(
            "Account lockout duration",
            $"{minutes} minutes",
            p => p.LockoutDurationMinutes,
            minutes,
            () => SetLockoutDurationCore(minutes)
        );

    /// <summary>Set how long bad attempts are counted for, in minutes.</summary>
    public static Task<string?> SetLockoutObservationMinutesAsync(int minutes) =>
        ApplyAsync(
            "Lockout observation window",
            $"{minutes} minutes",
            p => p.LockoutObservationMinutes,
            minutes,
            () => SetLockoutObservationCore(minutes)
        );

    /// <summary>
    /// Apply one policy value and prove it, reading the whole policy back and
    /// picking the one field out of it.
    /// </summary>
    private static Task<string?> ApplyAsync(
        string target,
        string intent,
        Func<PolicyValues, int> field,
        int wanted,
        Func<Task<string?>> apply
    ) =>
        Remediation.ApplyAsync(
            target: $"Password policy: {target}",
            intent: intent,
            readState: async () =>
            {
                var policy = await ReadPolicyAsync();
                return policy is null ? null : field(policy.Value).ToString();
            },
            isCompliant: state => state == wanted.ToString(),
            action: $"set it to {wanted}",
            apply: apply
        );

    /// <summary>The seven policy numbers, however they were read.</summary>
    private readonly record struct PolicyValues(
        int MinPasswordLength,
        int MaxPasswordAgeDays,
        int MinPasswordAgeDays,
        int PasswordHistoryLength,
        int LockoutThreshold,
        int LockoutDurationMinutes,
        int LockoutObservationMinutes
    );

    /// <summary>
    /// The current policy, or null when it could not be read.
    /// </summary>
    /// <remarks>
    /// The fallback re-parses <c>net accounts</c> through the task's own parser,
    /// so evidence on a machine without the API path is read exactly the way the
    /// task reads it, rather than by a second parser that could disagree.
    /// </remarks>
    private static async Task<PolicyValues?> ReadPolicyAsync()
    {
#if WINDOWS
        if (Native.NativeAccounts.GetPasswordPolicy() is { } p)
        {
            return new PolicyValues(
                p.MinPasswordLength,
                p.MaxPasswordAgeDays,
                p.MinPasswordAgeDays,
                p.PasswordHistoryLength,
                p.LockoutThreshold,
                p.LockoutDurationMinutes,
                p.LockoutObservationMinutes
            );
        }
#endif
        var (success, output, _) = await CommandExecutor.ExecuteAsync("net", "accounts");
        if (!success)
            return null;

        var parsed = Models.PasswordPolicyInfo.ParseNetAccounts(output);
        return new PolicyValues(
            parsed.MinPasswordLength,
            parsed.MaxPasswordAge,
            parsed.MinPasswordAge,
            parsed.PasswordHistoryCount,
            parsed.LockoutThreshold,
            parsed.LockoutDuration,
            parsed.LockoutObservationWindow
        );
    }

    private static async Task<string?> SetMinPasswordLengthCore(int characters)
    {
#if WINDOWS
        return Native.NativeAccounts.SetMinPasswordLength(characters);
#else
        return await NetAccountsAsync($"minpwlen:{characters}");
#endif
    }

    private static async Task<string?> SetMaxPasswordAgeCore(int days)
    {
#if WINDOWS
        return Native.NativeAccounts.SetMaxPasswordAgeDays(days);
#else
        return await NetAccountsAsync($"maxpwage:{days}");
#endif
    }

    private static async Task<string?> SetMinPasswordAgeCore(int days)
    {
#if WINDOWS
        return Native.NativeAccounts.SetMinPasswordAgeDays(days);
#else
        return await NetAccountsAsync($"minpwage:{days}");
#endif
    }

    private static async Task<string?> SetPasswordHistoryCore(int count)
    {
#if WINDOWS
        return Native.NativeAccounts.SetPasswordHistoryLength(count);
#else
        return await NetAccountsAsync($"uniquepw:{count}");
#endif
    }

    private static async Task<string?> SetLockoutThresholdCore(int attempts)
    {
#if WINDOWS
        return Native.NativeAccounts.SetLockoutThreshold(attempts);
#else
        return await NetAccountsAsync($"lockoutthreshold:{attempts}");
#endif
    }

    private static async Task<string?> SetLockoutDurationCore(int minutes)
    {
#if WINDOWS
        return Native.NativeAccounts.SetLockoutDurationMinutes(minutes);
#else
        return await NetAccountsAsync($"lockoutduration:{minutes}");
#endif
    }

    private static async Task<string?> SetLockoutObservationCore(int minutes)
    {
#if WINDOWS
        return Native.NativeAccounts.SetLockoutObservationMinutes(minutes);
#else
        return await NetAccountsAsync($"lockoutwindow:{minutes}");
#endif
    }

    private static async Task<string?> NetAccountsAsync(string argument)
    {
        var (success, _, error) = await CommandExecutor.ExecuteAsync(
            "net",
            $"accounts /{argument}"
        );
        return success ? null : error ?? $"net accounts /{argument} failed";
    }
}
