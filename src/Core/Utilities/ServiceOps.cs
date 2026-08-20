// =============================================================================
// CyberPatriot Automation Tool - Service operations
// Author: Maxwell McCormick
// Copyright (c) 2026 Maxwell McCormick. All Rights Reserved.
// =============================================================================
namespace CyberPatriotAutomation.Core.Utilities;

/// <summary>What a service is currently doing.</summary>
public enum ServiceState
{
    /// <summary>Not installed on this machine.</summary>
    Absent,
    Stopped,
    Running,

    /// <summary>Installed, but mid-transition or paused.</summary>
    Other,
}

/// <summary>
/// Service control for the tasks: the service control manager where available,
/// otherwise <c>sc.exe</c> and PowerShell.
/// </summary>
/// <remarks>
/// Deciding here rather than at every call site keeps the tasks readable and
/// keeps the fallback in one place. Every method returns the reason on failure
/// rather than a bare boolean, because <c>sc.exe</c>'s exit code cannot
/// distinguish "no such service" from "access denied" and the caller needs to.
/// </remarks>
public static class ServiceOps
{
    /// <summary>The current state of a service.</summary>
    public static async Task<ServiceState> GetStateAsync(string name)
    {
#if WINDOWS
        return Native.NativeServices.GetState(name) switch
        {
            Native.NativeServiceState.Absent => ServiceState.Absent,
            Native.NativeServiceState.Stopped => ServiceState.Stopped,
            Native.NativeServiceState.Running => ServiceState.Running,
            _ => ServiceState.Other,
        };
#else
        var (success, output, _) = await CommandExecutor.PowerShellQueryAsync(
            $"Get-Service -Name {CommandExecutor.PsQuote(name)} -ErrorAction SilentlyContinue "
                + "| Select-Object -ExpandProperty Status"
        );
        if (!success || string.IsNullOrWhiteSpace(output))
            return ServiceState.Absent;

        return output.Trim() switch
        {
            var s when s.Equals("Running", StringComparison.OrdinalIgnoreCase) =>
                ServiceState.Running,
            var s when s.Equals("Stopped", StringComparison.OrdinalIgnoreCase) =>
                ServiceState.Stopped,
            _ => ServiceState.Other,
        };
#endif
    }

    /// <summary>
    /// Stop a service and anything depending on it. Already stopped, or not
    /// installed, counts as success.
    /// </summary>
    public static async Task<string?> StopAsync(string name)
    {
#if WINDOWS
        return Native.NativeServices.Stop(name);
#else
        // -Force stops dependents too. Plain `net stop` would ask about them and
        // then wait for an answer that is never coming.
        var (success, _, error) = await CommandExecutor.PowerShellAsync(
            $"Stop-Service -Name {CommandExecutor.PsQuote(name)} -Force"
        );
        return success ? null : error ?? "Stop-Service failed";
#endif
    }

    /// <summary>Start a service. Already running counts as success.</summary>
    public static async Task<string?> StartAsync(string name)
    {
#if WINDOWS
        return Native.NativeServices.Start(name);
#else
        var (success, _, error) = await CommandExecutor.ExecuteAsync("net", $"start \"{name}\"");
        return success ? null : error ?? "net start failed";
#endif
    }

    /// <summary>
    /// Disable a service so it does not come back after a reboot. A service that
    /// is not installed is not an error - that is already the wanted state.
    /// </summary>
    public static async Task<string?> DisableAsync(string name)
    {
#if WINDOWS
        return Native.NativeServices.Disable(name);
#else
        var (success, _, error) = await CommandExecutor.ExecuteAsync(
            "sc",
            $"config \"{name}\" start= disabled"
        );
        return success ? null : error ?? "sc config failed";
#endif
    }

    /// <summary>Set a service to start automatically at boot.</summary>
    public static async Task<string?> SetAutomaticAsync(string name)
    {
#if WINDOWS
        return Native.NativeServices.SetAutomatic(name);
#else
        var (success, _, error) = await CommandExecutor.ExecuteAsync(
            "sc",
            $"config \"{name}\" start= auto"
        );
        return success ? null : error ?? "sc config failed";
#endif
    }
}
