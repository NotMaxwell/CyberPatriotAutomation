// =============================================================================
// CyberPatriot Automation Tool - Registry operations
// Author: Maxwell McCormick
// Copyright (c) 2026 Maxwell McCormick. All Rights Reserved.
// =============================================================================
namespace CyberPatriotAutomation.Core.Utilities;

/// <summary>
/// Registry access for the tasks: the Windows API where available, otherwise
/// <c>reg.exe</c>.
/// </summary>
/// <remarks>
/// The choice is made here rather than at every call site, so the tasks read as
/// plain intent and there is one place that knows about the fallback. Each
/// method returns the reason on failure instead of a bare boolean, because
/// "access denied" and "the key does not exist" need different responses from
/// the caller and <c>reg.exe</c>'s exit code cannot tell them apart.
/// </remarks>
public static class RegistryOps
{
    /// <summary>
    /// Write a REG_DWORD, creating the key if needed, and prove the result.
    /// </summary>
    /// <param name="why">
    /// What the value is for, in words - it lands in the run log next to the
    /// path, so a reader does not have to know what fDenyTSConnections means.
    /// </param>
    public static Task<string?> SetDwordAsync(
        string key,
        string name,
        int value,
        string? why = null
    ) =>
        Remediation.ApplyAsync(
            target: $"{key}\\{name}",
            intent: why is null
                ? $"REG_DWORD = {value}"
                : $"REG_DWORD = {value} ({why})",
            readState: async () => (await GetDwordAsync(key, name))?.ToString(),
            isCompliant: state => state == value.ToString(),
            action: $"wrote REG_DWORD {value}",
            apply: () => WriteDwordAsync(key, name, value)
        );

    private static async Task<string?> WriteDwordAsync(string key, string name, int value)
    {
#if WINDOWS
        return Native.NativeRegistry.SetDword(key, name, value);
#else
        var (success, _, error) = await CommandExecutor.ExecuteAsync(
            "reg",
            $"add \"{key}\" /v {name} /t REG_DWORD /d {value} /f"
        );
        return success ? null : error ?? "reg add failed";
#endif
    }

    /// <summary>Write a REG_SZ, creating the key if needed, and prove the result.</summary>
    public static Task<string?> SetStringAsync(
        string key,
        string name,
        string value,
        string? why = null
    ) =>
        Remediation.ApplyAsync(
            target: $"{key}\\{name}",
            intent: why is null ? $"REG_SZ = \"{value}\"" : $"REG_SZ = \"{value}\" ({why})",
            readState: async () => await GetStringAsync(key, name),
            isCompliant: state => state == value,
            action: $"wrote REG_SZ \"{value}\"",
            apply: () => WriteStringAsync(key, name, value)
        );

    private static async Task<string?> WriteStringAsync(string key, string name, string value)
    {
#if WINDOWS
        return Native.NativeRegistry.SetString(key, name, value);
#else
        var (success, _, error) = await CommandExecutor.ExecuteAsync(
            "reg",
            $"add \"{key}\" /v {name} /t REG_SZ /d \"{value}\" /f"
        );
        return success ? null : error ?? "reg add failed";
#endif
    }

    /// <summary>Read a REG_SZ, or null when the key or value is absent.</summary>
    public static async Task<string?> GetStringAsync(string key, string name)
    {
#if WINDOWS
        return Native.NativeRegistry.GetValue(key, name) as string;
#else
        var (success, output, _) = await CommandExecutor.ExecuteAsync(
            "reg",
            $"query \"{key}\" /v {name}"
        );
        return success ? ParseRegString(output, name) : null;
#endif
    }

    /// <summary>
    /// Read a REG_SZ value out of <c>reg query</c> output.
    /// </summary>
    /// <remarks>
    /// Same shape as <see cref="ParseRegDword"/>, except the value may contain
    /// spaces, so everything after the type column is the value.
    /// </remarks>
    public static string? ParseRegString(string output, string name)
    {
        foreach (
            var line in output.Split(new[] { '\r', '\n' }, StringSplitOptions.RemoveEmptyEntries)
        )
        {
            var fields = line.Split((char[]?)null, StringSplitOptions.RemoveEmptyEntries);
            if (
                fields.Length >= 3
                && fields[0].Equals(name, StringComparison.OrdinalIgnoreCase)
                && fields[1].Equals("REG_SZ", StringComparison.OrdinalIgnoreCase)
            )
                return string.Join(' ', fields.Skip(2));
        }
        return null;
    }

    /// <summary>Create a key, with no values. Returns null on success.</summary>
    public static async Task<string?> CreateKeyAsync(string key)
    {
#if WINDOWS
        // SetValue creates the key; there is no value-less create in the managed
        // API that also reports why it failed, and writing nothing is not an
        // option, so the key is opened for write and closed again.
        return Native.NativeRegistry.CreateKey(key);
#else
        var (success, _, error) = await CommandExecutor.ExecuteAsync("reg", $"add \"{key}\" /f");
        return success ? null : error ?? "reg add failed";
#endif
    }

    /// <summary>Does a key exist?</summary>
    public static async Task<bool> KeyExistsAsync(string key)
    {
#if WINDOWS
        return Native.NativeRegistry.KeyExists(key);
#else
        var (success, _, _) = await CommandExecutor.ExecuteAsync("reg", $"query \"{key}\"");
        return success;
#endif
    }

    /// <summary>
    /// Read a REG_DWORD, or null when the key or value is absent.
    /// </summary>
    public static async Task<int?> GetDwordAsync(string key, string name)
    {
#if WINDOWS
        return Native.NativeRegistry.GetDword(key, name);
#else
        var (success, output, _) = await CommandExecutor.ExecuteAsync(
            "reg",
            $"query \"{key}\" /v {name}"
        );
        if (!success)
            return null;

        // Parsed by the same helper the tests cover, so the fallback cannot
        // drift away from the tested behaviour.
        return (int?)ParseRegDword(output, name);
#endif
    }

    /// <summary>
    /// Read a REG_DWORD value out of <c>reg query</c> output.
    /// </summary>
    /// <remarks>
    /// The value appears on its own indented line, e.g.
    /// <c>    dontdisplaylastusername    REG_DWORD    0x1</c>.
    /// </remarks>
    public static uint? ParseRegDword(string output, string name)
    {
        foreach (
            var line in output.Split(new[] { '\r', '\n' }, StringSplitOptions.RemoveEmptyEntries)
        )
        {
            var fields = line.Split((char[]?)null, StringSplitOptions.RemoveEmptyEntries);
            if (
                fields.Length >= 3
                && fields[0].Equals(name, StringComparison.OrdinalIgnoreCase)
                && fields[1].Equals("REG_DWORD", StringComparison.OrdinalIgnoreCase)
            )
            {
                var raw = fields[2];
                if (
                    raw.StartsWith("0x", StringComparison.OrdinalIgnoreCase)
                    && uint.TryParse(
                        raw[2..],
                        System.Globalization.NumberStyles.HexNumber,
                        System.Globalization.CultureInfo.InvariantCulture,
                        out var hex
                    )
                )
                    return hex;
                if (uint.TryParse(raw, out var dec))
                    return dec;
            }
        }
        return null;
    }

    /// <summary>Does a REG_DWORD hold an expected value?</summary>
    public static async Task<bool> DwordEqualsAsync(string key, string name, int expected) =>
        await GetDwordAsync(key, name) == expected;

    /// <summary>
    /// Delete a value, and prove it is gone. Already absent counts as success.
    /// </summary>
    public static Task<string?> DeleteValueAsync(string key, string name, string? why = null) =>
        Remediation.ApplyAsync(
            target: $"{key}\\{name}",
            intent: why is null ? "value removed" : $"value removed ({why})",
            // "absent" is the wanted state, so it has to be a readable one
            // rather than the null that means "could not look".
            readState: async () =>
                (await GetDwordAsync(key, name))?.ToString()
                ?? await GetStringAsync(key, name)
                ?? "absent",
            isCompliant: state => state == "absent",
            action: "deleted the value",
            apply: () => RemoveValueAsync(key, name)
        );

    private static async Task<string?> RemoveValueAsync(string key, string name)
    {
#if WINDOWS
        return Native.NativeRegistry.DeleteValue(key, name);
#else
        var (success, _, error) = await CommandExecutor.ExecuteAsync(
            "reg",
            $"delete \"{key}\" /v {name} /f"
        );
        return success ? null : error ?? "reg delete failed";
#endif
    }
}
