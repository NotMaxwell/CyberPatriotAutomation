using System.Diagnostics;
using Spectre.Console;

namespace CyberPatriotAutomation.Core.Utilities;

/// <summary>
/// Handles execution of system commands and processes
/// </summary>
public class CommandExecutor
{
    /// <summary>
    /// Execute a command and return the output
    /// </summary>
    public static async Task<(bool Success, string Output, string? Error)> ExecuteAsync(
        string command,
        string? arguments = null
    )
    {
        try
        {
            var processInfo = new ProcessStartInfo
            {
                FileName = command,
                Arguments = arguments ?? string.Empty,
                UseShellExecute = false,
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                CreateNoWindow = true,
            };

            using var process = Process.Start(processInfo);
            if (process == null)
                return (false, string.Empty, "Failed to start process");

            // Read both output streams concurrently to avoid deadlocks when one stream
            // fills its buffer while the other is being read.
            var outputTask = process.StandardOutput.ReadToEndAsync();
            var errorTask = process.StandardError.ReadToEndAsync();

            // Wait for process exit with a timeout to avoid hanging indefinitely on
            // commands that may prompt for input or never return.
            using var cts = new CancellationTokenSource(TimeSpan.FromMinutes(2));
            try
            {
                var waitTask = process.WaitForExitAsync(cts.Token);
                await Task.WhenAll(outputTask, errorTask, waitTask);
            }
            catch (OperationCanceledException)
            {
                try
                {
                    if (!process.HasExited)
                        process.Kill(true);
                }
                catch { }
                return (false, await SafeGetTaskResultAsync(outputTask), "Process timed out");
            }

            var output = await SafeGetTaskResultAsync(outputTask);
            var error = await SafeGetTaskResultAsync(errorTask);

            return (process.ExitCode == 0, output, string.IsNullOrEmpty(error) ? null : error);
        }
        catch (Exception ex)
        {
            AnsiConsole.WriteException(ex);
            return (false, string.Empty, ex.Message);
        }
    }

    /// <summary>
    /// Execute a command with elevated privileges (requires admin/sudo)
    /// </summary>
    public static async Task<(bool Success, string Output, string? Error)> ExecuteElevatedAsync(
        string command,
        string? arguments = null
    )
    {
        try
        {
            // When using Verb = "runas" on Windows, UseShellExecute must be true and
            // redirecting streams is not supported. For elevated execution we start
            // the process without redirection and wait for it to exit. Output will
            // not be captured in this mode.
            var processInfo = new ProcessStartInfo
            {
                FileName = command,
                Arguments = arguments ?? string.Empty,
                UseShellExecute = true,
                CreateNoWindow = true,
                Verb = "runas",
            };

            using var process = Process.Start(processInfo);
            if (process == null)
                return (false, string.Empty, "Failed to start elevated process");

            // Wait for a reasonable amount of time for elevated operations
            using var cts = new CancellationTokenSource(TimeSpan.FromMinutes(2));
            try
            {
                await process.WaitForExitAsync(cts.Token);
            }
            catch (OperationCanceledException)
            {
                try
                {
                    if (!process.HasExited)
                        process.Kill(true);
                }
                catch { }
                return (false, string.Empty, "Elevated process timed out");
            }

            return (process.ExitCode == 0, string.Empty, null);
        }
        catch (Exception ex)
        {
            AnsiConsole.WriteException(ex);
            return (false, string.Empty, ex.Message);
        }
    }

    private static async Task<string> SafeGetTaskResultAsync(Task<string> task)
    {
        try
        {
            return await task;
        }
        catch
        {
            return string.Empty;
        }
    }
}
