// =============================================================================
// PinnacleCyPat - Service operations
// Author: Maxwell McCormick
// Copyright 2026 Maxwell McCormick. Licensed under Apache-2.0.
// =============================================================================
namespace PinnacleCyPat.Core.Utilities;

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
    /// Is a service configured as disabled? Null when the question could not be
    /// answered, which is not the same as "no".
    /// </summary>
    public static async Task<bool?> IsDisabledAsync(string name)
    {
#if WINDOWS
        return Native.NativeServices.IsDisabled(name);
#else
        // `sc qc` prints e.g. "START_TYPE : 4   DISABLED": a number the API
        // returns directly, next to a localised word.
        var (success, output, _) = await CommandExecutor.ExecuteAsync("sc", $"qc \"{name}\"");
        if (!success)
            return null;

        var line = output
            .Split(new[] { '\r', '\n' }, StringSplitOptions.RemoveEmptyEntries)
            .FirstOrDefault(l => l.Contains("START_TYPE", StringComparison.OrdinalIgnoreCase));
        return line?.Split((char[]?)null, StringSplitOptions.RemoveEmptyEntries).Contains("4");
#endif
    }

    /// <summary>
    /// Every installed service, keyed by name, with what it is doing. Null when
    /// the list could not be read at all, so "no services" and "could not look"
    /// stay distinguishable.
    /// </summary>
    public static async Task<Dictionary<string, ServiceState>?> EnumerateStatesAsync()
    {
#if WINDOWS
        var native = Native.NativeServices.EnumerateStates();
        if (native is null)
            return null;

        return native.ToDictionary(
            pair => pair.Key,
            pair =>
                pair.Value switch
                {
                    Native.NativeServiceState.Absent => ServiceState.Absent,
                    Native.NativeServiceState.Stopped => ServiceState.Stopped,
                    Native.NativeServiceState.Running => ServiceState.Running,
                    _ => ServiceState.Other,
                },
            StringComparer.OrdinalIgnoreCase
        );
#else
        var (success, output, _) = await CommandExecutor.PowerShellQueryAsync(
            "Get-Service | Select-Object Name, Status | ConvertTo-Csv -NoTypeInformation"
        );
        if (!success)
            return null;

        var states = new Dictionary<string, ServiceState>(StringComparer.OrdinalIgnoreCase);
        foreach (
            var line in output
                .Split(new[] { '\r', '\n' }, StringSplitOptions.RemoveEmptyEntries)
                .Skip(1)
        )
        {
            var fields = line.Split("\",\"");
            if (fields.Length < 2)
                continue;
            var name = fields[0].Trim().Trim('"').Trim();
            if (name.Length == 0)
                continue;
            states[name] = fields[1].Trim().Trim('"').Trim() switch
            {
                var s when s.Equals("Running", StringComparison.OrdinalIgnoreCase) =>
                    ServiceState.Running,
                var s when s.Equals("Stopped", StringComparison.OrdinalIgnoreCase) =>
                    ServiceState.Stopped,
                _ => ServiceState.Other,
            };
        }
        return states;
#endif
    }

    /// <summary>
    /// Stop a service and anything depending on it. Already stopped, or not
    /// installed, counts as success.
    /// </summary>
    public static Task<string?> StopAsync(string name, string? why = null) =>
        Remediation.ApplyAsync(
            target: $"Service {name}",
            intent: why is null ? "stopped" : $"stopped ({why})",
            readState: async () => (await GetStateAsync(name)).ToString(),
            // Absent is the wanted end state too: a service that is not
            // installed cannot be running.
            isCompliant: state =>
                state is nameof(ServiceState.Stopped) or nameof(ServiceState.Absent),
            action: "asked the service control manager to stop it, and its dependents first",
            apply: () => StopCoreAsync(name)
        );

    private static async Task<string?> StopCoreAsync(string name)
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
    public static Task<string?> StartAsync(string name, string? why = null) =>
        Remediation.ApplyAsync(
            target: $"Service {name}",
            intent: why is null ? "running" : $"running ({why})",
            readState: async () => (await GetStateAsync(name)).ToString(),
            isCompliant: state => state == nameof(ServiceState.Running),
            action: "asked the service control manager to start it",
            apply: () => StartCoreAsync(name)
        );

    private static async Task<string?> StartCoreAsync(string name)
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
    public static Task<string?> DisableAsync(string name, string? why = null) =>
        Remediation.ApplyAsync(
            target: $"Service {name}",
            intent: why is null
                ? "start type disabled, so it cannot return after a reboot"
                : $"start type disabled ({why})",
            readState: () => ReadStartTypeAsync(name),
            isCompliant: state => state is "disabled" or "not installed",
            action: "set the start type to disabled",
            apply: () => SetStartTypeAsync(name, disabled: true)
        );

    /// <summary>Set a service to start automatically at boot.</summary>
    public static Task<string?> SetAutomaticAsync(string name, string? why = null) =>
        Remediation.ApplyAsync(
            target: $"Service {name}",
            intent: why is null ? "start type automatic" : $"start type automatic ({why})",
            readState: () => ReadStartTypeAsync(name),
            isCompliant: state => state == "not disabled",
            action: "set the start type to automatic",
            apply: () => SetStartTypeAsync(name, disabled: false)
        );

    /// <summary>
    /// The start type as evidence: "disabled", "not disabled", "not installed",
    /// or null when it could not be read.
    /// </summary>
    /// <remarks>
    /// The service control manager distinguishes automatic from manual, but
    /// nothing here acts on that difference, and reporting it would make
    /// "already compliant" depend on a distinction the caller did not ask about.
    /// </remarks>
    private static async Task<string?> ReadStartTypeAsync(string name)
    {
        if (await GetStateAsync(name) == ServiceState.Absent)
            return "not installed";

        return await IsDisabledAsync(name) switch
        {
            true => "disabled",
            false => "not disabled",
            null => null,
        };
    }

    private static async Task<string?> SetStartTypeAsync(string name, bool disabled)
    {
#if WINDOWS
        return disabled
            ? Native.NativeServices.Disable(name)
            : Native.NativeServices.SetAutomatic(name);
#else
        var (success, _, error) = await CommandExecutor.ExecuteAsync(
            "sc",
            $"config \"{name}\" start= {(disabled ? "disabled" : "auto")}"
        );
        return success ? null : error ?? "sc config failed";
#endif
    }
}
