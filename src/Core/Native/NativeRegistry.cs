using System.Runtime.Versioning;
using Microsoft.Win32;

namespace PinnacleCyPat.Core.Native;

/// <summary>
/// Registry reads and writes, replacing <c>reg.exe</c> and PowerShell's
/// <c>Set-ItemProperty</c>.
/// </summary>
/// <remarks>
/// <para>
/// <c>reg add</c> costs a process launch per value and reports failure only
/// through an exit code, so the reason a policy did not apply was never
/// available to the caller. It also silently writes to the wrong place under
/// WOW64: a 32-bit process is redirected to <c>Wow6432Node</c>, so a hardening
/// value written there has no effect on the 64-bit system it was meant to
/// configure.
/// </para>
/// <para>
/// These calls open the 64-bit view explicitly and surface the real exception
/// message, so "access denied" and "the key does not exist" stop looking alike.
/// </para>
/// </remarks>
[SupportedOSPlatform("windows")]
public static class NativeRegistry
{
    /// <summary>
    /// Split a <c>HKLM\Path\To\Key</c> string into its hive and remainder.
    /// Accepts the long and short spellings <c>reg.exe</c> accepts.
    /// </summary>
    private static (RegistryKey Hive, string Path)? Split(string fullPath)
    {
        var trimmed = fullPath.Trim().Replace('/', '\\');
        var separator = trimmed.IndexOf('\\');
        if (separator <= 0)
            return null;

        var hiveName = trimmed[..separator].ToUpperInvariant();
        var rest = trimmed[(separator + 1)..];

        // The 64-bit view explicitly: see the WOW64 note above.
        RegistryKey? hive = hiveName switch
        {
            "HKLM" or "HKEY_LOCAL_MACHINE" => RegistryKey.OpenBaseKey(
                RegistryHive.LocalMachine,
                RegistryView.Registry64
            ),
            "HKCU" or "HKEY_CURRENT_USER" => RegistryKey.OpenBaseKey(
                RegistryHive.CurrentUser,
                RegistryView.Registry64
            ),
            "HKCR" or "HKEY_CLASSES_ROOT" => RegistryKey.OpenBaseKey(
                RegistryHive.ClassesRoot,
                RegistryView.Registry64
            ),
            "HKU" or "HKEY_USERS" => RegistryKey.OpenBaseKey(
                RegistryHive.Users,
                RegistryView.Registry64
            ),
            _ => null,
        };

        return hive is null ? null : (hive, rest);
    }

    /// <summary>
    /// Write a value, creating the key if needed. Returns null on success or the
    /// reason on failure.
    /// </summary>
    public static string? SetValue(
        string keyPath,
        string name,
        object value,
        RegistryValueKind kind
    )
    {
        if (Split(keyPath) is not var (hive, path))
            return $"unrecognised registry hive in '{keyPath}'";

        try
        {
            using (hive)
            using (var key = hive.CreateSubKey(path, writable: true))
            {
                if (key is null)
                    return $"could not open or create {keyPath}";
                key.SetValue(name, value, kind);
                return null;
            }
        }
        catch (Exception ex)
            when (ex is UnauthorizedAccessException or System.Security.SecurityException)
        {
            return $"access denied writing {keyPath}\\{name} (run as Administrator)";
        }
        catch (Exception ex)
        {
            return $"could not write {keyPath}\\{name}: {ex.Message}";
        }
    }

    /// <summary>Create a key with no values. Returns null on success.</summary>
    public static string? CreateKey(string keyPath)
    {
        if (Split(keyPath) is not var (hive, path))
            return $"unrecognised registry hive in '{keyPath}'";

        try
        {
            using (hive)
            using (var key = hive.CreateSubKey(path, writable: true))
            {
                return key is null ? $"could not create {keyPath}" : null;
            }
        }
        catch (Exception ex)
        {
            return $"could not create {keyPath}: {ex.Message}";
        }
    }

    /// <summary>Does a key exist?</summary>
    public static bool KeyExists(string keyPath)
    {
        if (Split(keyPath) is not var (hive, path))
            return false;

        try
        {
            using (hive)
            using (var key = hive.OpenSubKey(path))
            {
                return key is not null;
            }
        }
        catch (Exception ex)
            when (ex is UnauthorizedAccessException or System.Security.SecurityException)
        {
            return false;
        }
    }

    /// <summary>Write a REG_DWORD. Returns null on success.</summary>
    public static string? SetDword(string keyPath, string name, int value) =>
        SetValue(keyPath, name, value, RegistryValueKind.DWord);

    /// <summary>Write a REG_SZ. Returns null on success.</summary>
    public static string? SetString(string keyPath, string name, string value) =>
        SetValue(keyPath, name, value, RegistryValueKind.String);

    /// <summary>
    /// Read a value, or null when the key or value is absent or unreadable.
    /// </summary>
    public static object? GetValue(string keyPath, string name)
    {
        if (Split(keyPath) is not var (hive, path))
            return null;

        try
        {
            using (hive)
            using (var key = hive.OpenSubKey(path))
            {
                return key?.GetValue(name);
            }
        }
        catch (Exception ex)
            when (ex is UnauthorizedAccessException or System.Security.SecurityException)
        {
            return null;
        }
    }

    /// <summary>Read a REG_DWORD, or null when absent or not a number.</summary>
    public static int? GetDword(string keyPath, string name) =>
        GetValue(keyPath, name) is int value ? value : null;

    /// <summary>Delete a value. Returns null on success or the reason on failure.</summary>
    public static string? DeleteValue(string keyPath, string name)
    {
        if (Split(keyPath) is not var (hive, path))
            return $"unrecognised registry hive in '{keyPath}'";

        try
        {
            using (hive)
            using (var key = hive.OpenSubKey(path, writable: true))
            {
                // Absent is the desired end state, not a failure.
                if (key is null)
                    return null;
                key.DeleteValue(name, throwOnMissingValue: false);
                return null;
            }
        }
        catch (Exception ex)
        {
            return $"could not delete {keyPath}\\{name}: {ex.Message}";
        }
    }
}
