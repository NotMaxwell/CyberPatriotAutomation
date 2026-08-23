// =============================================================================
// PinnacleCyPat - Group Policy Task
// Author: Maxwell McCormick
// Copyright 2026 Maxwell McCormick. Licensed under Apache-2.0.
// =============================================================================
using System;
using System.Collections.Generic;
using System.Threading.Tasks;
using PinnacleCyPat.Core.Models;
using PinnacleCyPat.Core.Utilities;
using Spectre.Console;

namespace PinnacleCyPat.Core.Tasks;

/// <summary>
/// Configures key Group Policy (gpedit) settings for security hardening.
/// </summary>
public class GroupPolicyTask : BaseTask
{
    private ReadmeData? _readmeData;

    public GroupPolicyTask()
    {
        Name = "Group Policy";
        Description =
            "Configures Local Security Policy: hide last user, require Ctrl+Alt+Del, "
            + "disable ICS, require SMB signing, and turn off remote desktop sharing.";
    }

    /// <summary>Set the README data for this task.</summary>
    /// <remarks>
    /// Only one setting consults it - Remote Desktop, which a README can declare
    /// critical. Everything else here is unconditional hardening.
    /// </remarks>
    public void SetReadmeData(ReadmeData data) => _readmeData = data;

    private const string PoliciesSystemKey =
        @"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System";

    private const string LsaKey = @"HKLM\SYSTEM\CurrentControlSet\Control\Lsa";

    /// <summary>SMB client settings ("Microsoft network client" in gpedit).</summary>
    private const string LanmanWorkstationKey =
        @"HKLM\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters";

    /// <summary>SMB server settings ("Microsoft network server" in gpedit).</summary>
    private const string LanmanServerKey =
        @"HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters";

    /// <summary>Where Remote Desktop's listener is switched on and off.</summary>
    private const string TerminalServerKey =
        @"HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server";

    /// <summary>The policy form of the same setting, which takes precedence.</summary>
    private const string TerminalServicesPolicyKey =
        @"HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services";

    /// <summary>Render a possibly-absent registry value for the state report.</summary>
    private static string Describe(int? value) => value?.ToString() ?? "(not set)";

    public override async Task<SystemInfo> ReadSystemStateAsync()
    {
        var hideLastUser = await RegistryOps.GetDwordAsync(
            PoliciesSystemKey,
            "dontdisplaylastusername"
        );
        var disableCad = await RegistryOps.GetDwordAsync(PoliciesSystemKey, "DisableCAD");
        var restrictAnonymous = await RegistryOps.GetDwordAsync(LsaKey, "restrictanonymous");

        var state = string.Join(
            Environment.NewLine,
            $"dontdisplaylastusername = {Describe(hideLastUser)}",
            $"DisableCAD = {Describe(disableCad)}",
            $"restrictanonymous = {Describe(restrictAnonymous)}"
        );
        return new SystemInfo { RawOutput = state, ErrorOutput = string.Empty };
    }

    public override async Task<TaskResult> ExecuteAsync()
    {
        if (DryRun)
        {
            AnsiConsole.MarkupLine(
                "[yellow]DRY RUN: Previewing Group Policy changes (no changes will be made)[/]"
            );
            return new TaskResult
            {
                TaskName = Name,
                Success = true,
                Message =
                    "DRY RUN: Would apply:\n✓ Don't display last user name set\n✓ Require Ctrl+Alt+Del set\n"
                    + "✓ ICS (Internet Connection Sharing) disabled\n✓ Restrict anonymous access set\n"
                    + "✓ SMB signing required and offered, client and server\n"
                    + (
                        ReadmeServices.IsRemoteDesktopRequired(_readmeData)
                            ? "- Remote desktop left enabled (the README lists it as critical)"
                            : "✓ Remote desktop sharing turned off"
                    ),
            };
        }

        var details = new List<string>();
        bool allSuccess = true;

        // 1. Don't display last user name
        var hideUserError = await RegistryOps.SetDwordAsync(
            PoliciesSystemKey,
            "dontdisplaylastusername",
            1
        );
        details.Add(
            hideUserError is null
                ? "✓ Don't display last user name set"
                : $"✗ Failed: {hideUserError}"
        );
        allSuccess &= hideUserError is null;

        // 2. Require Ctrl+Alt+Del
        var ctrlAltDelError = await RegistryOps.SetDwordAsync(PoliciesSystemKey, "DisableCAD", 0);
        details.Add(
            ctrlAltDelError is null ? "✓ Require Ctrl+Alt+Del set" : $"✗ Failed: {ctrlAltDelError}"
        );
        allSuccess &= ctrlAltDelError is null;

        // 3. Disable ICS (Internet Connection Sharing)
        var icsError = await ServiceOps.DisableAsync("SharedAccess");
        details.Add(
            icsError is null
                ? "✓ ICS (Internet Connection Sharing) disabled"
                : $"✗ Failed: {icsError}"
        );
        allSuccess &= icsError is null;

        // 4. Additional local security policies (example: restrict anonymous access)
        var anonError = await RegistryOps.SetDwordAsync(LsaKey, "restrictanonymous", 1);
        details.Add(
            anonError is null ? "✓ Restrict anonymous access set" : $"✗ Failed: {anonError}"
        );
        allSuccess &= anonError is null;

        // Microsoft network client: digitally sign communications (always).
        //
        // Without it an SMB session can be tampered with in transit, which is
        // what makes SMB relay attacks work. The server-side setting is applied
        // with it: they are a pair in every hardening benchmark, and signing
        // only one side leaves the other able to negotiate an unsigned session.
        var clientSigningError = await RegistryOps.SetDwordAsync(
            LanmanWorkstationKey,
            "RequireSecuritySignature",
            1
        );
        details.Add(
            clientSigningError is null
                ? "✓ Microsoft network client: digitally sign communications (always)"
                : $"✗ Failed: {clientSigningError}"
        );
        allSuccess &= clientSigningError is null;

        var serverSigningError = await RegistryOps.SetDwordAsync(
            LanmanServerKey,
            "RequireSecuritySignature",
            1
        );
        details.Add(
            serverSigningError is null
                ? "✓ Microsoft network server: digitally sign communications (always)"
                : $"✗ Failed: {serverSigningError}"
        );
        allSuccess &= serverSigningError is null;

        // The "(if server/client agrees)" halves of the same four-setting group.
        //
        // Local Security Policy lists four SMB signing settings, not two, and the
        // benchmarks want all four. The "always" pair is what forces signing; the
        // "if the other side agrees" pair is what makes this machine *offer* it
        // when talking to a peer that does not require it. Setting only the
        // "always" pair leaves the negotiated case unsigned, and leaves two of
        // the four scored items unset.
        var clientAgreeError = await RegistryOps.SetDwordAsync(
            LanmanWorkstationKey,
            "EnableSecuritySignature",
            1
        );
        details.Add(
            clientAgreeError is null
                ? "✓ Microsoft network client: digitally sign communications (if server agrees)"
                : $"✗ Failed: {clientAgreeError}"
        );
        allSuccess &= clientAgreeError is null;

        var serverAgreeError = await RegistryOps.SetDwordAsync(
            LanmanServerKey,
            "EnableSecuritySignature",
            1
        );
        details.Add(
            serverAgreeError is null
                ? "✓ Microsoft network server: digitally sign communications (if client agrees)"
                : $"✗ Failed: {serverAgreeError}"
        );
        allSuccess &= serverAgreeError is null;

        // Remote desktop sharing off - unless the README says it must work.
        //
        // fDenyTSConnections is the switch the Settings UI toggles. The policy
        // key is set too: a policy value overrides the local one, so an image
        // with the policy set to "allow" would otherwise keep RDP listening no
        // matter what the local setting said.
        //
        // A README that lists Remote Desktop as critical is describing a machine
        // administered remotely, where RDP *working* is the scored condition.
        // Service management already protects TermService in that case; denying
        // connections here as well would leave the service running with every
        // connection refused - the worst of both, and a lost point.
        if (ReadmeServices.IsRemoteDesktopRequired(_readmeData))
        {
            var note = "- Remote desktop left enabled: the README lists it as a critical service";
            details.Add(note);
            RunLog.Diagnostic("grouppolicy", note.TrimStart('-', ' '));
            AnsiConsole.MarkupLine($"[yellow]{Markup.Escape(note)}[/]");
        }
        else
        {
            var rdpError = await RegistryOps.SetDwordAsync(
                TerminalServerKey,
                "fDenyTSConnections",
                1
            );
            details.Add(
                rdpError is null ? "✓ Remote desktop sharing turned off" : $"✗ Failed: {rdpError}"
            );
            allSuccess &= rdpError is null;

            var rdpPolicyError = await RegistryOps.SetDwordAsync(
                TerminalServicesPolicyKey,
                "fDenyTSConnections",
                1
            );
            details.Add(
                rdpPolicyError is null
                    ? "✓ Remote desktop sharing denied by policy"
                    : $"✗ Failed: {rdpPolicyError}"
            );
            allSuccess &= rdpPolicyError is null;
        }

        return new TaskResult
        {
            TaskName = Name,
            Success = allSuccess,
            Message = string.Join("\n", details),
        };
    }

    /// <summary>Confirm a registry value is present *and* set to the expected value.</summary>
    private static async Task<bool> RegDwordEqualsAsync(string key, string name, int expected)
    {
        return await RegistryOps.GetDwordAsync(key, name) == expected;
    }

    public override async Task<bool> VerifyAsync()
    {
        // These checks previously only asserted that `reg query` / `sc qc` exited
        // successfully, which is true whenever the value merely *exists*. A
        // setting left at the wrong value therefore verified as correct.
        const string policies =
            "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System";
        const string lsa = "HKLM\\SYSTEM\\CurrentControlSet\\Control\\Lsa";

        var hideUserOk = await RegDwordEqualsAsync(policies, "dontdisplaylastusername", 1);
        // DisableCAD = 0 means Ctrl+Alt+Del *is* required.
        var ctrlAltDelOk = await RegDwordEqualsAsync(policies, "DisableCAD", 0);
        var anonOk = await RegDwordEqualsAsync(lsa, "restrictanonymous", 1);
        var clientSigningOk = await RegDwordEqualsAsync(
            LanmanWorkstationKey,
            "RequireSecuritySignature",
            1
        );
        var serverSigningOk = await RegDwordEqualsAsync(
            LanmanServerKey,
            "RequireSecuritySignature",
            1
        );
        var clientAgreeOk = await RegDwordEqualsAsync(
            LanmanWorkstationKey,
            "EnableSecuritySignature",
            1
        );
        var serverAgreeOk = await RegDwordEqualsAsync(
            LanmanServerKey,
            "EnableSecuritySignature",
            1
        );

        // fDenyTSConnections = 1 means Remote Desktop is refused. When the README
        // requires RDP this step was deliberately skipped, so verifying it as
        // "must be denied" would report a failure for doing the right thing.
        var rdpOk =
            ReadmeServices.IsRemoteDesktopRequired(_readmeData)
            || await RegDwordEqualsAsync(TerminalServerKey, "fDenyTSConnections", 1);

        // This used to look for the word "DISABLED" in `sc qc` output, which is
        // localised; the service control manager returns the start type as a
        // number.
        var icsOk = await ServiceOps.IsDisabledAsync("SharedAccess") == true;

        if (!hideUserOk)
            AnsiConsole.MarkupLine("[red]✗ 'Don't display last user name' is not set[/]");
        if (!ctrlAltDelOk)
            AnsiConsole.MarkupLine("[red]✗ Ctrl+Alt+Del is not required at logon[/]");
        if (!anonOk)
            AnsiConsole.MarkupLine("[red]✗ Anonymous access is not restricted[/]");
        if (!icsOk)
            AnsiConsole.MarkupLine("[red]✗ Internet Connection Sharing is not disabled[/]");
        if (!clientSigningOk)
            AnsiConsole.MarkupLine(
                "[red]✗ Microsoft network client does not require SMB signing[/]"
            );
        if (!serverSigningOk)
            AnsiConsole.MarkupLine(
                "[red]✗ Microsoft network server does not require SMB signing[/]"
            );
        if (!clientAgreeOk)
            AnsiConsole.MarkupLine("[red]? Microsoft network client does not offer SMB signing[/]");
        if (!serverAgreeOk)
            AnsiConsole.MarkupLine("[red]? Microsoft network server does not offer SMB signing[/]");
        if (!rdpOk)
            AnsiConsole.MarkupLine("[red]✗ Remote desktop sharing is not turned off[/]");

        return hideUserOk
            && ctrlAltDelOk
            && anonOk
            && icsOk
            && clientSigningOk
            && serverSigningOk
            && clientAgreeOk
            && serverAgreeOk
            && rdpOk;
    }
}
