// =============================================================================
// CyberPatriot Automation Tool - DNS Settings Audit Task
// Author: Maxwell McCormick
// Copyright (c) 2026 Maxwell McCormick. All Rights Reserved.
// =============================================================================
using System;
using System.Linq;
using System.Threading.Tasks;
using CyberPatriotAutomation.Core.Models;
using CyberPatriotAutomation.Core.Utilities;
using Spectre.Console;

namespace CyberPatriotAutomation.Core.Tasks;

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

    public override async Task<SystemInfo> ReadSystemStateAsync()
    {
        var (success, output, error) = await CommandExecutor.ExecuteAsync(
            "netsh",
            "interface ip show dns"
        );
        return new SystemInfo { RawOutput = output, ErrorOutput = error };
    }

    public override async Task<TaskResult> ExecuteAsync()
    {
        var (success, output, error) = await CommandExecutor.ExecuteAsync(
            "netsh",
            "interface ip show dns"
        );
        if (!success)
        {
            AnsiConsole.MarkupLine($"[red]✗ Failed to read DNS settings: {error}[/]");
            return new TaskResult
            {
                TaskName = Name,
                Success = false,
                Message = error ?? "Unknown error",
            };
        }
        // Example: Check for public DNS (e.g., 8.8.8.8, 1.1.1.1) and flag as non-compliant
        var insecureDns = new[] { "8.8.8.8", "8.8.4.4", "1.1.1.1", "1.0.0.1" };
        var found = insecureDns.Where(dns => output.Contains(dns)).ToList();
        if (found.Count == 0)
        {
            AnsiConsole.MarkupLine("[green]✓ No insecure DNS servers found[/]");
            return new TaskResult
            {
                TaskName = Name,
                Success = true,
                Message = "No insecure DNS servers found.",
            };
        }
        // No dry-run support; just report
        AnsiConsole.MarkupLine($"[red]✗ Insecure DNS servers found: {string.Join(", ", found)}[/]");
        return new TaskResult
        {
            TaskName = Name,
            Success = false,
            Message = $"Insecure DNS: {string.Join(", ", found)}",
        };
    }

    public override async Task<bool> VerifyAsync()
    {
        var (success, output, error) = await CommandExecutor.ExecuteAsync(
            "netsh",
            "interface ip show dns"
        );
        var insecureDns = new[] { "8.8.8.8", "8.8.4.4", "1.1.1.1", "1.0.0.1" };
        var found = insecureDns.Where(dns => output.Contains(dns)).ToList();
        return found.Count == 0;
    }
}
