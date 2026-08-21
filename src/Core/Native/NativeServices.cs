using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using Windows.Win32;
using Windows.Win32.System.Services;

namespace CyberPatriotAutomation.Core.Native;

/// <summary>What a service is currently doing.</summary>
public enum NativeServiceState
{
    Absent,
    Stopped,
    Running,
    Other,
}

/// <summary>
/// Service control through the service control manager, replacing <c>sc.exe</c>,
/// <c>net start</c>/<c>net stop</c> and <c>Stop-Service</c>.
/// </summary>
/// <remarks>
/// <para>
/// The shell paths each had a problem. <c>net stop</c> asks "Do you want to
/// continue this operation? (Y/N)" when a service has dependents, and with
/// stdout redirected that question is captured rather than shown, so the tool
/// appears to freeze. <c>sc config</c> reports failure only through an exit
/// code, so "no such service" and "access denied" look identical.
/// </para>
/// <para>
/// Here dependents are enumerated and stopped explicitly, so nothing prompts,
/// and every failure carries its Win32 error.
/// </para>
/// </remarks>
[SupportedOSPlatform("windows5.1.2600")]
public static class NativeServices
{
    private const uint SC_MANAGER_CONNECT = 0x0001;
    private const uint SC_MANAGER_ENUMERATE_SERVICE = 0x0004;
    private const uint SERVICE_QUERY_CONFIG = 0x0001;
    private const uint SERVICE_QUERY_STATUS = 0x0004;

    /// <summary>Every service type and every state, for the bulk enumeration.</summary>
    private const uint SERVICE_TYPE_ALL = 0x0000003F;
    private const uint SERVICE_STATE_ALL = 0x00000003;
    private const uint SERVICE_ENUMERATE_DEPENDENTS = 0x0008;
    private const uint SERVICE_START = 0x0010;
    private const uint SERVICE_STOP = 0x0020;
    private const uint SERVICE_CHANGE_CONFIG = 0x0002;
    private const uint SERVICE_CONTROL_STOP = 0x0001;

    private const uint ERROR_SERVICE_DOES_NOT_EXIST = 1060;

    /// <summary>Leave the service's existing value for a ChangeServiceConfig field.</summary>
    private const uint SERVICE_NO_CHANGE = 0xFFFFFFFF;

    /// <summary>How long to wait for a service to reach the stopped state.</summary>
    private static readonly TimeSpan StopTimeout = TimeSpan.FromSeconds(30);

    /// <summary>The current state of a service, or Absent if it is not installed.</summary>
    public static NativeServiceState GetState(string name)
    {
        using var manager = PInvoke.OpenSCManager(
            (string?)null!,
            (string?)null!,
            SC_MANAGER_CONNECT
        );
        if (manager.IsInvalid)
            return NativeServiceState.Absent;

        using var service = PInvoke.OpenService(manager, name, SERVICE_QUERY_STATUS);
        return service.IsInvalid ? NativeServiceState.Absent : QueryState(service);
    }

    private static unsafe NativeServiceState QueryState(SafeHandle service)
    {
        Span<byte> buffer = stackalloc byte[sizeof(SERVICE_STATUS_PROCESS)];
        if (
            !PInvoke.QueryServiceStatusEx(
                service,
                SC_STATUS_TYPE.SC_STATUS_PROCESS_INFO,
                buffer,
                out _
            )
        )
            return NativeServiceState.Other;

        fixed (byte* raw = buffer)
        {
            return ((SERVICE_STATUS_PROCESS*)raw)->dwCurrentState switch
            {
                SERVICE_STATUS_CURRENT_STATE.SERVICE_STOPPED => NativeServiceState.Stopped,
                SERVICE_STATUS_CURRENT_STATE.SERVICE_RUNNING => NativeServiceState.Running,
                _ => NativeServiceState.Other,
            };
        }
    }

    /// <summary>
    /// Stop a service and anything depending on it. Returns null on success, or
    /// the reason. A service that is already stopped, or absent, is success.
    /// </summary>
    public static string? Stop(string name)
    {
        using var manager = PInvoke.OpenSCManager(
            (string?)null!,
            (string?)null!,
            SC_MANAGER_CONNECT
        );
        if (manager.IsInvalid)
            return $"could not open the service control manager ({LastError()})";

        using var service = PInvoke.OpenService(
            manager,
            name,
            SERVICE_STOP | SERVICE_QUERY_STATUS | SERVICE_ENUMERATE_DEPENDENTS
        );
        if (service.IsInvalid)
        {
            // Absent is the desired end state, not a failure.
            return Marshal.GetLastWin32Error() == ERROR_SERVICE_DOES_NOT_EXIST
                ? null
                : $"could not open service {name} ({LastError()})";
        }

        // Dependents first: stopping them here is what `net stop` would have
        // asked permission to do.
        foreach (var dependent in DependentsOf(service))
        {
            var failure = Stop(dependent);
            if (failure is not null)
                return $"could not stop {dependent}, which depends on {name}: {failure}";
        }

        if (QueryState(service) == NativeServiceState.Stopped)
            return null;

        if (!PInvoke.ControlService(service, SERVICE_CONTROL_STOP, out _))
            return $"could not stop {name} ({LastError()})";

        return WaitForStopped(service, name);
    }

    private static string? WaitForStopped(SafeHandle service, string name)
    {
        var deadline = DateTime.UtcNow + StopTimeout;
        while (DateTime.UtcNow < deadline)
        {
            if (QueryState(service) == NativeServiceState.Stopped)
                return null;
            Thread.Sleep(250);
        }
        return $"{name} did not reach the stopped state within {StopTimeout.TotalSeconds:F0}s";
    }

    /// <summary>Names of the services that depend on this one.</summary>
    private static unsafe List<string> DependentsOf(SafeHandle service)
    {
        var names = new List<string>();

        // Sizing call: this is expected to fail with the required size.
        PInvoke.EnumDependentServices(
            service,
            ENUM_SERVICE_STATE.SERVICE_ACTIVE,
            null,
            0,
            out var needed,
            out _
        );
        if (needed == 0)
            return names;

        var buffer = new byte[needed];
        fixed (byte* raw = buffer)
        {
            if (
                !PInvoke.EnumDependentServices(
                    service,
                    ENUM_SERVICE_STATE.SERVICE_ACTIVE,
                    (ENUM_SERVICE_STATUSW*)raw,
                    needed,
                    out _,
                    out var count
                )
            )
                return names;

            var entries = (ENUM_SERVICE_STATUSW*)raw;
            for (uint i = 0; i < count; i++)
            {
                var serviceName = entries[i].lpServiceName.ToString();
                if (!string.IsNullOrEmpty(serviceName))
                    names.Add(serviceName);
            }
        }

        return names;
    }

    /// <summary>Start a service. Returns null on success, or the reason.</summary>
    public static string? Start(string name)
    {
        using var manager = PInvoke.OpenSCManager(
            (string?)null!,
            (string?)null!,
            SC_MANAGER_CONNECT
        );
        if (manager.IsInvalid)
            return $"could not open the service control manager ({LastError()})";

        using var service = PInvoke.OpenService(
            manager,
            name,
            SERVICE_START | SERVICE_QUERY_STATUS
        );
        if (service.IsInvalid)
            return $"could not open service {name} ({LastError()})";

        if (QueryState(service) == NativeServiceState.Running)
            return null;

        return PInvoke.StartService(service, ReadOnlySpan<Windows.Win32.Foundation.PCWSTR>.Empty)
            ? null
            : $"could not start {name} ({LastError()})";
    }

    /// <summary>
    /// Set a service's start type. Returns null on success, or the reason.
    /// A service that is not installed is not an error: there is nothing to
    /// disable, which is the state the caller wanted.
    /// </summary>
    /// <remarks>
    /// Private because SERVICE_START_TYPE is an internal generated type; callers
    /// use the intent-named wrappers below.
    /// </remarks>
    private static unsafe string? SetStartType(string name, SERVICE_START_TYPE startType)
    {
        using var manager = PInvoke.OpenSCManager(
            (string?)null!,
            (string?)null!,
            SC_MANAGER_CONNECT
        );
        if (manager.IsInvalid)
            return $"could not open the service control manager ({LastError()})";

        using var service = PInvoke.OpenService(manager, name, SERVICE_CHANGE_CONFIG);
        if (service.IsInvalid)
        {
            return Marshal.GetLastWin32Error() == ERROR_SERVICE_DOES_NOT_EXIST
                ? null
                : $"could not open service {name} ({LastError()})";
        }

        // SERVICE_NO_CHANGE everywhere else: only the start type is being set.
        return PInvoke.ChangeServiceConfig(
            service,
            (ENUM_SERVICE_TYPE)SERVICE_NO_CHANGE,
            startType,
            (SERVICE_ERROR)SERVICE_NO_CHANGE,
            null!,
            null!,
            null,
            null!,
            null!,
            null!,
            null!
        )
            ? null
            : $"could not set the start type of {name} ({LastError()})";
    }

    /// <summary>
    /// Is a service configured as disabled? Null when the service is not
    /// installed or its configuration could not be read.
    /// </summary>
    /// <remarks>
    /// Replaces parsing <c>sc qc</c>, which prints the start type as a localised
    /// word ("DISABLED") next to its number.
    /// </remarks>
    public static unsafe bool? IsDisabled(string name)
    {
        using var manager = PInvoke.OpenSCManager(
            (string?)null!,
            (string?)null!,
            SC_MANAGER_CONNECT
        );
        if (manager.IsInvalid)
            return null;

        using var service = PInvoke.OpenService(manager, name, SERVICE_QUERY_CONFIG);
        if (service.IsInvalid)
            return null;

        // Sizing call: this is expected to fail with the required size.
        PInvoke.QueryServiceConfig(service, null, 0, out var needed);
        if (needed == 0)
            return null;

        var buffer = new byte[needed];
        fixed (byte* raw = buffer)
        {
            if (!PInvoke.QueryServiceConfig(service, (QUERY_SERVICE_CONFIGW*)raw, needed, out _))
                return null;

            return ((QUERY_SERVICE_CONFIGW*)raw)->dwStartType
                == SERVICE_START_TYPE.SERVICE_DISABLED;
        }
    }

    /// <summary>
    /// Every installed service, keyed by name, with what it is doing. Returns
    /// null when the enumeration fails, so callers can tell "no services" apart
    /// from "could not read the service list".
    /// </summary>
    /// <remarks>
    /// Replaces one <c>Get-Service | ConvertTo-Csv</c> and the CSV parser over
    /// its output, which reported an English status word.
    /// </remarks>
    public static unsafe Dictionary<string, NativeServiceState>? EnumerateStates()
    {
        using var manager = PInvoke.OpenSCManager(
            (string?)null!,
            (string?)null!,
            SC_MANAGER_ENUMERATE_SERVICE
        );
        if (manager.IsInvalid)
            return null;

        // Sizing call: this is expected to fail with the required size.
        PInvoke.EnumServicesStatusEx(
            manager,
            SC_ENUM_TYPE.SC_ENUM_PROCESS_INFO,
            (ENUM_SERVICE_TYPE)SERVICE_TYPE_ALL,
            (ENUM_SERVICE_STATE)SERVICE_STATE_ALL,
            null,
            0,
            out var needed,
            out _,
            null,
            (string?)null!
        );
        if (needed == 0)
            return null;

        var buffer = new byte[needed];
        fixed (byte* raw = buffer)
        {
            if (
                !PInvoke.EnumServicesStatusEx(
                    manager,
                    SC_ENUM_TYPE.SC_ENUM_PROCESS_INFO,
                    (ENUM_SERVICE_TYPE)SERVICE_TYPE_ALL,
                    (ENUM_SERVICE_STATE)SERVICE_STATE_ALL,
                    raw,
                    needed,
                    out _,
                    out var returned,
                    null,
                    (string?)null!
                )
            )
                return null;

            var states = new Dictionary<string, NativeServiceState>(
                (int)returned,
                StringComparer.OrdinalIgnoreCase
            );
            var entries = (ENUM_SERVICE_STATUS_PROCESSW*)raw;
            for (uint i = 0; i < returned; i++)
            {
                var serviceName = entries[i].lpServiceName.ToString();
                if (string.IsNullOrEmpty(serviceName))
                    continue;

                states[serviceName] = entries[i].ServiceStatusProcess.dwCurrentState switch
                {
                    SERVICE_STATUS_CURRENT_STATE.SERVICE_STOPPED => NativeServiceState.Stopped,
                    SERVICE_STATUS_CURRENT_STATE.SERVICE_RUNNING => NativeServiceState.Running,
                    _ => NativeServiceState.Other,
                };
            }
            return states;
        }
    }

    /// <summary>Disable a service so it does not return after a reboot.</summary>
    public static string? Disable(string name) =>
        SetStartType(name, SERVICE_START_TYPE.SERVICE_DISABLED);

    /// <summary>Set a service to start automatically at boot.</summary>
    public static string? SetAutomatic(string name) =>
        SetStartType(name, SERVICE_START_TYPE.SERVICE_AUTO_START);

    private static string LastError() =>
        new System.ComponentModel.Win32Exception(Marshal.GetLastWin32Error()).Message;
}
