using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using Windows.Win32.NetworkManagement.WindowsFirewall;

namespace PinnacleCyPat.Core.Native;

/// <summary>State of one Windows Firewall profile.</summary>
public readonly record struct FirewallProfileState(
    string Profile,
    bool Enabled,
    bool BlocksInboundByDefault
);

/// <summary>
/// Windows Firewall through the INetFwPolicy2 COM object rather than
/// <c>netsh advfirewall</c> or <c>Set-NetFirewallProfile</c>.
/// </summary>
/// <remarks>
/// The profile settings are addressed by enum value, so unlike the shell paths
/// nothing here depends on the display language. It also replaces a PowerShell
/// launch per call, which dominated the runtime of this task.
/// </remarks>
[SupportedOSPlatform("windows6.0.6000")]
public static class NativeFirewall
{
    /// <summary>CLSID of the NetFwPolicy2 coclass (hnetcfg.dll).</summary>
    private static readonly Guid NetFwPolicy2Clsid = new("E2B3C97F-6AE1-41AC-817A-F6F92166D7DD");

    private static readonly (string Name, NET_FW_PROFILE_TYPE2 Type)[] Profiles =
    [
        ("Domain", NET_FW_PROFILE_TYPE2.NET_FW_PROFILE2_DOMAIN),
        ("Private", NET_FW_PROFILE_TYPE2.NET_FW_PROFILE2_PRIVATE),
        ("Public", NET_FW_PROFILE_TYPE2.NET_FW_PROFILE2_PUBLIC),
    ];

    private static INetFwPolicy2? CreatePolicy()
    {
        var type = Type.GetTypeFromCLSID(NetFwPolicy2Clsid);
        return type is null ? null : Activator.CreateInstance(type) as INetFwPolicy2;
    }

    /// <summary>
    /// Turn the firewall on for all three profiles and set the default actions to
    /// block inbound / allow outbound. Returns the profiles changed, or null and
    /// a reason on failure.
    /// </summary>
    public static IReadOnlyList<string>? EnableAllProfiles(out string? error)
    {
        error = null;
        try
        {
            var policy = CreatePolicy();
            if (policy is null)
            {
                error = "the Windows Firewall COM object is unavailable";
                return null;
            }

            var configured = new List<string>();
            foreach (var (name, type) in Profiles)
            {
                policy.put_FirewallEnabled(type, true);
                policy.put_DefaultInboundAction(type, NET_FW_ACTION.NET_FW_ACTION_BLOCK);
                policy.put_DefaultOutboundAction(type, NET_FW_ACTION.NET_FW_ACTION_ALLOW);
                configured.Add(name);
            }
            return configured;
        }
        catch (COMException ex)
        {
            error = $"firewall COM call failed (HRESULT 0x{ex.HResult:X8})";
            return null;
        }
        catch (Exception ex)
        {
            error = ex.Message;
            return null;
        }
    }

    /// <summary>
    /// Current state of each profile, or null when the policy cannot be read.
    /// </summary>
    public static IReadOnlyList<FirewallProfileState>? Query()
    {
        try
        {
            var policy = CreatePolicy();
            if (policy is null)
                return null;

            return Profiles
                .Select(p => new FirewallProfileState(
                    p.Name,
                    policy.get_FirewallEnabled(p.Type),
                    policy.get_DefaultInboundAction(p.Type) == NET_FW_ACTION.NET_FW_ACTION_BLOCK
                ))
                .ToList();
        }
        catch (COMException)
        {
            return null;
        }
    }
}
