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

    /// <summary>
    /// One task's "Scheduled Task State", or null when it could not be read.
    /// </summary>
    /// <remarks>
    /// This is the evidence for a disable: <c>schtasks /Change</c> reports only
    /// an exit code, and a task that is still enabled after a successful-looking
    /// change is exactly the case worth catching.
    /// </remarks>
    private static async Task<string?> ReadTaskStatusAsync(string taskName)
    {
        var (success, output, _) = await CommandExecutor.ExecuteAsync(
            "schtasks",
            $"/query /tn \"{taskName}\" /fo LIST /v"
        );
        if (!success)
            return null;

        foreach (
            var line in output.Split(new[] { '\r', '\n' }, StringSplitOptions.RemoveEmptyEntries)
        )
        {
            // "Scheduled Task State:  Disabled" - the label is localised, but the
            // fallback below keeps a wrong read from reading as a right one.
            if (line.Contains("Scheduled Task State", StringComparison.OrdinalIgnoreCase))
            {
                var value = line.Split(':').Skip(1).FirstOrDefault()?.Trim();
                if (!string.IsNullOrEmpty(value))
                    return value;
            }
        }
        return null;
    }

    public override async Task<TaskResult> ExecuteAsync()
    {
        if (DryRun)
        {
            AnsiConsole.MarkupLine(
                "[yellow]DRY RUN: Previewing scheduled tasks audit (no changes will be made)[/]"
            );
            return new TaskResult
            {
                TaskName = Name,
                Success = true,
                Message = "DRY RUN: Scheduled tasks audit previewed.",
            };
        }

        var (success, output, error) = await CommandExecutor.ExecuteAsync(
            "schtasks",
            "/query /fo LIST /v"
        );
        var details = new List<string>();
        if (!success)
        {
            details.Add($"Failed to query scheduled tasks: {error}");
            AnsiConsole.MarkupLine($"[red]✗ Failed to query scheduled tasks: {error}[/]");
            return new TaskResult
            {
                TaskName = Name,
                Success = false,
                Message = string.Join("\n", details),
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
        var allTaskNames = lines
            .Where(l => l.StartsWith("TaskName:", StringComparison.OrdinalIgnoreCase))
            .Select(l => l.Substring("TaskName:".Length).Trim())
            .ToList();
        details.Add($"Total scheduled tasks found: {allTaskNames.Count}");
        var suspiciousTasks = lines
            .Where(l =>
                suspiciousKeywords.Any(k => l.IndexOf(k, StringComparison.OrdinalIgnoreCase) >= 0)
            )
            .ToList();
        details.Add($"Suspicious keywords checked: {string.Join(", ", suspiciousKeywords)}");
        if (suspiciousTasks.Count == 0)
        {
            details.Add("No suspicious scheduled tasks found.");
            AnsiConsole.MarkupLine("[green]✓ No suspicious scheduled tasks found[/]");
            return new TaskResult
            {
                TaskName = Name,
                Success = true,
                Message = string.Join("\n", details),
            };
        }
        details.Add($"Suspicious task lines: {suspiciousTasks.Count}");
        var disabledTasks = new List<string>();
        var failedToDisable = new List<string>();
        // Attempt to disable suspicious tasks (dry-run not supported)
        foreach (var taskLine in suspiciousTasks)
        {
            var namePrefix = "TaskName: ";
            if (taskLine.StartsWith(namePrefix, StringComparison.OrdinalIgnoreCase))
            {
                var taskName = taskLine.Substring(namePrefix.Length).Trim();
                var disableError = await Remediation.ApplyAsync(
                    target: $"Scheduled task {taskName}",
                    intent: "disabled - it runs from a path a scheduled task should not",
                    readState: () => ReadTaskStatusAsync(taskName),
                    isCompliant: state => state == "Disabled",
                    action: "ran schtasks /Change /Disable",
                    apply: async () =>
                    {
                        var (ok, _, error) = await CommandExecutor.ExecuteAsync(
                            "schtasks",
                            $"/Change /TN \"{taskName}\" /Disable"
                        );
                        return ok ? null : error ?? "schtasks /Change failed";
                    }
                );
                if (disableError is null)
                {
                    AnsiConsole.MarkupLine($"[yellow]Disabled suspicious task: {taskName}[/]");
                    disabledTasks.Add(taskName);
                }
                else
                {
                    AnsiConsole.MarkupLine(
                        $"[red]✗ Failed to disable task: {taskName} ({disableError})[/]"
                    );
                    failedToDisable.Add($"{taskName} ({disableError})");
                }
            }
        }
        details.Add(
            $"Disabled tasks: {(disabledTasks.Count > 0 ? string.Join(", ", disabledTasks) : "None")}"
        );
        if (failedToDisable.Count > 0)
            details.Add($"Failed to disable: {string.Join(", ", failedToDisable)}");
        return new TaskResult
        {
            TaskName = Name,
            // Success means every suspicious task was dealt with. The previous
            // `disabledTasks.Count > 0 && ...` also reported failure whenever
            // there was simply nothing to disable.
            Success = failedToDisable.Count == 0,
            Message = string.Join("\n", details),
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
