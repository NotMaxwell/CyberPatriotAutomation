// =============================================================================
// PinnacleCyPat - Shared Folders Audit Task
// Author: Maxwell McCormick
// Copyright (c) 2026 Maxwell McCormick. All Rights Reserved.
// =============================================================================
using System.Threading.Tasks;
using PinnacleCyPat.Core.Models;
using PinnacleCyPat.Core.Utilities;
using Spectre.Console;

namespace PinnacleCyPat.Core.Tasks;

/// <summary>
/// Audits shared folders to ensure only ADMIN$, C$, IPC$ exist
/// </summary>
public class SharedFoldersAuditTask : BaseTask
{
    private static readonly string[] AllowedShares = { "ADMIN$", "C$", "IPC$" };

    public SharedFoldersAuditTask()
    {
        Name = "Shared Folders Audit";
        Description = "Audits shared folders (fsmgmt.msc) to ensure only ADMIN$, C$, IPC$ exist.";
    }

    /// <summary>
    /// The shares on this machine. Returns null when the list could not be read
    /// at all, so "no shares" and "could not look" stay distinguishable.
    /// </summary>
    private static async Task<List<string>?> ReadSharesAsync()
    {
#if WINDOWS
        // netapi32 returns the share list as data, so there is nothing to parse
        // and nothing that depends on the console language. ParseShares stays as
        // the fallback for the rare case the call itself fails.
        var native = Native.NativeShares.Enumerate();
        if (native is not null)
            return native;
#endif
        var (success, output, _) = await CommandExecutor.ExecuteAsync("net", "share");
        return success ? ParseShares(output ?? string.Empty) : null;
    }

    /// <summary>Remove a share. Returns null on success, or the reason.</summary>
    private static Task<string?> RemoveShareAsync(string share) =>
        Remediation.ApplyAsync(
            target: $"Share {share}",
            intent: "removed - only ADMIN$, C$ and IPC$ belong on a competition image",
            // "absent" has to be a readable state rather than the null that means
            // "could not look", so the share list is re-read and searched.
            readState: async () =>
                await ReadSharesAsync() is { } shares
                    ? shares.Contains(share, StringComparer.OrdinalIgnoreCase)
                        ? "present"
                        : "absent"
                    : null,
            isCompliant: state => state == "absent",
            action: "removed the share",
            apply: () => RemoveShareCoreAsync(share)
        );

    private static async Task<string?> RemoveShareCoreAsync(string share)
    {
#if WINDOWS
        return Native.NativeShares.Delete(share);
#else
        var (success, _, error) = await CommandExecutor.ExecuteAsync(
            "net",
            // /y answers the "There are open files ... force them closed?
            // (Y/N)" prompt that `net share /delete` asks when the share is
            // in use. Without it the command waits on a keypress.
            $"share {share} /delete /y"
        );
        return success ? null : error ?? "net share /delete failed";
#endif
    }

    private static List<string> Unauthorized(IEnumerable<string> found) =>
        found.Except(AllowedShares, StringComparer.OrdinalIgnoreCase).ToList();

    public override async Task<SystemInfo> ReadSystemStateAsync()
    {
        var shares = await ReadSharesAsync();
        return new SystemInfo
        {
            RawOutput = shares is null ? string.Empty : string.Join(Environment.NewLine, shares),
            ErrorOutput = shares is null ? "Could not read the share list" : string.Empty,
        };
    }

    public override async Task<TaskResult> ExecuteAsync()
    {
        var found = await ReadSharesAsync();
        if (found is null)
        {
            return new TaskResult
            {
                TaskName = Name,
                Success = false,
                Message = "Could not read the share list.",
                ErrorDetails = "Neither the Windows API nor `net share` returned a share list.",
            };
        }

        var unauthorized = Unauthorized(found);

        var details = new List<string>();
        details.Add($"Shares found: {string.Join(", ", found)}");
        details.Add($"Allowed shares: {string.Join(", ", AllowedShares)}");
        if (unauthorized.Count > 0)
            details.Add($"Unauthorized shares: {string.Join(", ", unauthorized)}");
        else
            details.Add("No unauthorized shares found.");

        if (DryRun)
        {
            AnsiConsole.MarkupLine(
                "[yellow]DRY RUN: Previewing shared folders audit (no changes will be made)[/]"
            );
            if (unauthorized.Count > 0)
                details.Add($"Would remove: {string.Join(", ", unauthorized)}");
            return new TaskResult
            {
                TaskName = Name,
                Success = true,
                Message = string.Join("\n", details),
            };
        }

        var removed = new List<string>();
        var failures = new List<string>();

        foreach (var share in unauthorized)
        {
            var failure = await RemoveShareAsync(share);
            if (failure is null)
            {
                removed.Add(share);
                AnsiConsole.MarkupLine($"[green]✓ Removed share: {Markup.Escape(share)}[/]");
            }
            else
            {
                failures.Add($"{share}: {failure}");
                AnsiConsole.MarkupLine(
                    $"[red]✗ Failed to remove share: {Markup.Escape(share)} ({Markup.Escape(failure)})[/]"
                );
            }
        }

        details.Add(
            removed.Count > 0
                ? $"Removed: {string.Join(", ", removed)}"
                : "No shares needed removal."
        );
        if (failures.Count > 0)
            details.Add($"Failed to remove: {string.Join("; ", failures)}");

        return new TaskResult
        {
            TaskName = Name,
            // Success means the remediation went through. The previous
            // `unauthorized.Count == 0` reported failure precisely when the task
            // had found and removed offending shares.
            Success = failures.Count == 0,
            Message = string.Join("\n", details),
            ErrorDetails = failures.Count > 0 ? string.Join("\n", failures) : null,
        };
    }

    /// <summary>
    /// Extract share names from <c>net share</c> output.
    /// </summary>
    /// <remarks>
    /// Only reached when the Windows API is unavailable. The output is a table
    /// wrapped in a header and a trailing status line. Taking the first token of
    /// every line containing a space also picked up "Share" from the header and
    /// "The" from "The command completed successfully.", so the task tried to
    /// <c>net share Share /delete</c> on entries that were never shares. Read
    /// only the rows between the separator and the status line.
    /// </remarks>
    public static List<string> ParseShares(string output)
    {
        var shares = new List<string>();
        var pastSeparator = false;

        foreach (var raw in output.Split('\n'))
        {
            var line = raw.Trim();
            if (line.Length == 0)
                continue;

            if (line.StartsWith("---", StringComparison.Ordinal))
            {
                pastSeparator = true;
                continue;
            }

            if (!pastSeparator)
                continue;

            if (line.StartsWith("The command completed", StringComparison.OrdinalIgnoreCase))
                break;

            var name = line.Split((char[]?)null, StringSplitOptions.RemoveEmptyEntries)
                .FirstOrDefault();
            if (!string.IsNullOrWhiteSpace(name))
                shares.Add(name);
        }

        return shares;
    }

    public override async Task<bool> VerifyAsync()
    {
        var found = await ReadSharesAsync();
        // A read failure is not proof the machine is clean.
        return found is not null && Unauthorized(found).Count == 0;
    }
}
