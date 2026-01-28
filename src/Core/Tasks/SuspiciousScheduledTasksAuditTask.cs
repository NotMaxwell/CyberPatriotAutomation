// =============================================================================
// CyberPatriot Automation Tool - Suspicious Scheduled Tasks Audit Task
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
/// Audits and disables suspicious scheduled tasks
/// </summary>
public class SuspiciousScheduledTasksAuditTask : BaseTask
{
    public SuspiciousScheduledTasksAuditTask()
    {
        Name = "Suspicious Scheduled Tasks Audit";
        Description = "Audits and disables suspicious scheduled tasks.";
    }

    public override async Task<SystemInfo> ReadSystemStateAsync()
    {
        var (success, output, error) = await CommandExecutor.ExecuteAsync(
            "schtasks",
            "/query /fo LIST /v"
        );
        return new SystemInfo { RawOutput = output, ErrorOutput = error };
    }

    public override async Task<TaskResult> ExecuteAsync()
    {
        var (success, output, error) = await CommandExecutor.ExecuteAsync(
            "schtasks",
            "/query /fo LIST /v"
        );
        if (!success)
        {
            AnsiConsole.MarkupLine($"[red]✗ Failed to query scheduled tasks: {error}[/]");
            return new TaskResult
            {
                TaskName = Name,
                Success = false,
                Message = error ?? "Unknown error",
            };
        }
        // Example: Flag tasks with suspicious keywords
        var suspiciousKeywords = new[]
        {
            "hack",
            "malware",
            "bitcoin",
            "crypto",
            "miner",
            "backdoor",
            "remote",
            "powershell",
            "cmd.exe",
        };
        var lines = output.Split(new[] { '\n', '\r' }, StringSplitOptions.RemoveEmptyEntries);
        var suspiciousTasks = lines
            .Where(l =>
                suspiciousKeywords.Any(k => l.IndexOf(k, StringComparison.OrdinalIgnoreCase) >= 0)
            )
            .ToList();
        if (suspiciousTasks.Count == 0)
        {
            AnsiConsole.MarkupLine("[green]✓ No suspicious scheduled tasks found[/]");
            return new TaskResult
            {
                TaskName = Name,
                Success = true,
                Message = "No suspicious scheduled tasks found.",
            };
        }
        // Attempt to disable suspicious tasks (dry-run not supported)
        foreach (var taskLine in suspiciousTasks)
        {
            var namePrefix = "TaskName: ";
            if (taskLine.StartsWith(namePrefix, StringComparison.OrdinalIgnoreCase))
            {
                var taskName = taskLine.Substring(namePrefix.Length).Trim();
                var (disableSuccess, _, disableError) = await CommandExecutor.ExecuteAsync(
                    "schtasks",
                    $"/Change /TN \"{taskName}\" /Disable"
                );
                if (disableSuccess)
                    AnsiConsole.MarkupLine($"[yellow]Disabled suspicious task: {taskName}[/]");
                else
                    AnsiConsole.MarkupLine(
                        $"[red]✗ Failed to disable task: {taskName} ({disableError})[/]"
                    );
            }
        }
        return new TaskResult
        {
            TaskName = Name,
            Success = false,
            Message = $"Suspicious tasks found: {suspiciousTasks.Count}",
        };
    }

    public override async Task<bool> VerifyAsync()
    {
        var (success, output, error) = await CommandExecutor.ExecuteAsync(
            "schtasks",
            "/query /fo LIST /v"
        );
        var suspiciousKeywords = new[]
        {
            "hack",
            "malware",
            "bitcoin",
            "crypto",
            "miner",
            "backdoor",
            "remote",
            "powershell",
            "cmd.exe",
        };
        var lines = output.Split(new[] { '\n', '\r' }, StringSplitOptions.RemoveEmptyEntries);
        var suspiciousTasks = lines
            .Where(l =>
                suspiciousKeywords.Any(k => l.IndexOf(k, StringComparison.OrdinalIgnoreCase) >= 0)
            )
            .ToList();
        return suspiciousTasks.Count == 0;
    }
}
