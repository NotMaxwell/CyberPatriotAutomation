using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using Windows.Win32;
using Windows.Win32.Foundation;
using Windows.Win32.Security;
using Windows.Win32.Security.Authentication.Identity;

namespace PinnacleCyPat.Core.Native;

/// <summary>How a subcategory is currently audited.</summary>
public readonly record struct AuditSubcategoryState(string Name, bool Success, bool Failure)
{
    /// <summary>True when neither success nor failure events are recorded.</summary>
    public bool IsUnaudited => !Success && !Failure;
}

/// <summary>
/// Audit policy through advapi32 rather than <c>auditpol.exe</c>.
/// </summary>
/// <remarks>
/// <para>
/// <c>auditpol /set /category:"Account Logon"</c> addresses categories by their
/// display name, and both the names it accepts and the "No Auditing" text it
/// prints are localised. On a non-English image the set silently matches nothing
/// and the verify step reads the absence of the English string as "audited", so
/// the tool reports success having configured nothing.
/// </para>
/// <para>
/// The category GUIDs below are fixed in ntsecapi.h and identical on every
/// Windows install in every language, and the API reports state as flags. So
/// nothing here depends on the console language.
/// </para>
/// </remarks>
[SupportedOSPlatform("windows6.0.6000")]
public static class NativeAuditPolicy
{
    private const uint POLICY_AUDIT_EVENT_SUCCESS = 0x1;
    private const uint POLICY_AUDIT_EVENT_FAILURE = 0x2;
    private const uint POLICY_AUDIT_EVENT_NONE = 0x4;

    /// <summary>AdjustTokenPrivileges reports this when the privilege was withheld.</summary>
    private const int ERROR_NOT_ALL_ASSIGNED = 1300;

    /// <summary>
    /// The nine top-level audit categories, keyed by the names the task already
    /// uses. The names are only keys in our own source - they are never compared
    /// against anything Windows prints.
    /// </summary>
    public static readonly IReadOnlyDictionary<string, Guid> CategoryGuids = new Dictionary<
        string,
        Guid
    >(StringComparer.OrdinalIgnoreCase)
    {
        ["System"] = new("69979848-797a-11d9-bed3-505054503030"),
        ["Logon/Logoff"] = new("69979849-797a-11d9-bed3-505054503030"),
        ["Object Access"] = new("6997984a-797a-11d9-bed3-505054503030"),
        ["Privilege Use"] = new("6997984b-797a-11d9-bed3-505054503030"),
        ["Detailed Tracking"] = new("6997984c-797a-11d9-bed3-505054503030"),
        ["Policy Change"] = new("6997984d-797a-11d9-bed3-505054503030"),
        ["Account Management"] = new("6997984e-797a-11d9-bed3-505054503030"),
        ["DS Access"] = new("6997984f-797a-11d9-bed3-505054503030"),
        ["Account Logon"] = new("69979850-797a-11d9-bed3-505054503030"),
    };

    /// <summary>
    /// Every subcategory GUID under a category. Returns null when the category is
    /// unknown or the enumeration fails.
    /// </summary>
    private static unsafe Guid[]? EnumerateSubcategories(Guid category)
    {
        Guid* array = null;
        try
        {
            var ok = PInvoke.AuditEnumerateSubCategories(category, false, out array, out var count);
            if (!ok || array == null)
                return null;

            var result = new Guid[count];
            for (uint i = 0; i < count; i++)
                result[i] = array[i];
            return result;
        }
        finally
        {
            if (array != null)
                PInvoke.AuditFree(array);
        }
    }

    /// <summary>The display name of a subcategory, or its GUID if unavailable.</summary>
    private static unsafe string SubcategoryName(Guid subcategory)
    {
        PWSTR name = default;
        try
        {
            return
                PInvoke.AuditLookupSubCategoryName(subcategory, out name) && name.Value is not null
                ? name.ToString()
                : subcategory.ToString();
        }
        finally
        {
            if (name.Value is not null)
                PInvoke.AuditFree(name.Value);
        }
    }

    /// <summary>
    /// Current auditing state for every subcategory of a category. Returns null
    /// when the category is unknown or the query fails, so "could not read" stays
    /// distinguishable from "nothing is audited".
    /// </summary>
    public static unsafe IReadOnlyList<AuditSubcategoryState>? Query(Guid category)
    {
        var subcategories = EnumerateSubcategories(category);
        if (subcategories is null || subcategories.Length == 0)
            return null;

        AUDIT_POLICY_INFORMATION* policies = null;
        try
        {
            if (!PInvoke.AuditQuerySystemPolicy(subcategories, out policies) || policies == null)
                return null;

            var states = new List<AuditSubcategoryState>(subcategories.Length);
            for (var i = 0; i < subcategories.Length; i++)
            {
                var info = policies[i].AuditingInformation;
                states.Add(
                    new AuditSubcategoryState(
                        SubcategoryName(policies[i].AuditSubCategoryGuid),
                        (info & POLICY_AUDIT_EVENT_SUCCESS) != 0,
                        (info & POLICY_AUDIT_EVENT_FAILURE) != 0
                    )
                );
            }
            return states;
        }
        finally
        {
            if (policies != null)
                PInvoke.AuditFree(policies);
        }
    }

    /// <summary>
    /// Turn on success and failure auditing for every subcategory of a category.
    /// Returns the number of subcategories set, or null with a reason on failure.
    /// </summary>
    public static unsafe int? EnableSuccessAndFailure(Guid category, out string? error)
    {
        error = null;

        if (!TryEnableSecurityPrivilege(out var privilegeError))
        {
            error = privilegeError;
            return null;
        }

        var subcategories = EnumerateSubcategories(category);
        if (subcategories is null || subcategories.Length == 0)
        {
            error = "no subcategories reported for this category";
            return null;
        }

        var policies = new AUDIT_POLICY_INFORMATION[subcategories.Length];
        for (var i = 0; i < subcategories.Length; i++)
        {
            policies[i] = new AUDIT_POLICY_INFORMATION
            {
                AuditSubCategoryGuid = subcategories[i],
                AuditCategoryGuid = category,
                AuditingInformation = POLICY_AUDIT_EVENT_SUCCESS | POLICY_AUDIT_EVENT_FAILURE,
            };
        }

        if (!PInvoke.AuditSetSystemPolicy(policies))
        {
            error = $"AuditSetSystemPolicy failed (Win32 {Marshal.GetLastWin32Error()})";
            return null;
        }

        return subcategories.Length;
    }

    /// <summary>
    /// AuditSetSystemPolicy needs SeSecurityPrivilege present *and* enabled.
    /// An elevated token carries it disabled by default, so it has to be switched
    /// on explicitly - which is what auditpol.exe does internally.
    /// </summary>
    private static unsafe bool TryEnableSecurityPrivilege(out string? error)
    {
        error = null;
        try
        {
            using var process = Process.GetCurrentProcess();
            if (
                !PInvoke.OpenProcessToken(
                    process.SafeHandle,
                    TOKEN_ACCESS_MASK.TOKEN_ADJUST_PRIVILEGES | TOKEN_ACCESS_MASK.TOKEN_QUERY,
                    out var token
                )
            )
            {
                error = "could not open the process token";
                return false;
            }

            using (token)
            {
                if (!PInvoke.LookupPrivilegeValue(null!, "SeSecurityPrivilege", out var luid))
                {
                    error = "SeSecurityPrivilege is not available to this account";
                    return false;
                }

                // One privilege, so the struct's inline array needs no extra room.
                var privileges = new TOKEN_PRIVILEGES { PrivilegeCount = 1 };
                privileges.Privileges[0] = new LUID_AND_ATTRIBUTES
                {
                    Luid = luid,
                    Attributes = TOKEN_PRIVILEGES_ATTRIBUTES.SE_PRIVILEGE_ENABLED,
                };

                if (!PInvoke.AdjustTokenPrivileges(token, false, &privileges, 0, null, null))
                {
                    error = "could not enable SeSecurityPrivilege";
                    return false;
                }

                // AdjustTokenPrivileges reports success even when it enabled
                // nothing, so the real answer is in the last error.
                if (Marshal.GetLastWin32Error() == ERROR_NOT_ALL_ASSIGNED)
                {
                    error = "SeSecurityPrivilege was not granted (run as Administrator)";
                    return false;
                }

                return true;
            }
        }
        catch (Exception ex)
        {
            error = ex.Message;
            return false;
        }
    }
}
