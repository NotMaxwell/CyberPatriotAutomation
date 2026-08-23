// =============================================================================
// PinnacleCyPat - DNS Settings Audit Task
// Author: Maxwell McCormick
// Copyright (c) 2026 Maxwell McCormick. All Rights Reserved.
// =============================================================================
using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.NetworkInformation;
using System.Threading.Tasks;
using PinnacleCyPat.Core.Models;
using PinnacleCyPat.Core.Utilities;
using Spectre.Console;

namespace PinnacleCyPat.Core.Tasks;

/// <summary>
/// Audits DNS settings for security compliance
/// </summary>
public class DnsSettingsAuditTask : BaseTask
{
    public DnsSettingsAuditTask()
    {
        Name = "DNS Settings Audit";
        Description = "Audits DNS settings for security compliance.";
    }

    /// <summary>
    /// The DNS servers configured on every live, non-loopback interface.
    /// </summary>
    /// <remarks>
    /// This replaced parsing <c>netsh interface ip show dns</c>, whose layout and
    /// headings are localised. It also removes a subtler bug: the old check ran
    /// <c>output.Contains("1.1.1.1")</c> over the whole blob, so a resolver at
    /// 11.1.1.10 matched the substring and was reported as public DNS. Comparing
    /// <see cref="IPAddress"/> values makes the match exact.
    /// </remarks>
    private static List<(string Interface, IPAddress Address)> ReadDnsServers() =>
        NetworkInterface
            .GetAllNetworkInterfaces()
            .Where(nic =>
                nic.OperationalStatus == OperationalStatus.Up
                && nic.NetworkInterfaceType != NetworkInterfaceType.Loopback
            )
            .SelectMany(nic =>
                nic.GetIPProperties()
                    .DnsAddresses.Select(address => (Interface: nic.Name, Address: address))
            )
            .ToList();

    /// <summary>Public resolvers a competition image is not expected to use.</summary>
    private static readonly IPAddress[] InsecureDnsServers =
    [
        IPAddress.Parse("8.8.8.8"),
        IPAddress.Parse("8.8.4.4"),
        IPAddress.Parse("1.1.1.1"),
        IPAddress.Parse("1.0.0.1"),
    ];

    private static List<IPAddress> FindInsecure(
        IEnumerable<(string Interface, IPAddress Address)> servers
    ) => servers.Select(s => s.Address).Where(InsecureDnsServers.Contains).Distinct().ToList();

    public override Task<SystemInfo> ReadSystemStateAsync()
    {
        var servers = ReadDnsServers();
        var text = string.Join(
            Environment.NewLine,
            servers.Select(s => $"{s.Interface}: {s.Address}")
        );
        return Task.FromResult(new SystemInfo { RawOutput = text, ErrorOutput = string.Empty });
    }

    public override Task<TaskResult> ExecuteAsync()
    {
        var servers = ReadDnsServers();
        var details = new List<string>();

        details.Add("DNS settings output:");
        details.AddRange(servers.Select(s => $"  {s.Interface}: {s.Address}"));

        var found = FindInsecure(servers);
        if (found.Count == 0)
        {
            details.Add("No insecure DNS servers found.");
            AnsiConsole.MarkupLine("[green]✓ No insecure DNS servers found[/]");
            return Task.FromResult(
                new TaskResult
                {
                    TaskName = Name,
                    Success = true,
                    Message = string.Join("\n", details),
                }
            );
        }
        details.Add($"Insecure DNS servers found: {string.Join(", ", found)}");
        // No dry-run support; just report
        AnsiConsole.MarkupLine($"[red]✗ Insecure DNS servers found: {string.Join(", ", found)}[/]");
        return Task.FromResult(
            new TaskResult
            {
                TaskName = Name,
                Success = false,
                Message = string.Join("\n", details),
            }
        );
    }

    public override Task<bool> VerifyAsync() =>
        Task.FromResult(FindInsecure(ReadDnsServers()).Count == 0);
}
