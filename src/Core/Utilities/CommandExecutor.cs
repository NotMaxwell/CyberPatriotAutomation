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

            var output = await process.StandardOutput.ReadToEndAsync();
            var error = await process.StandardError.ReadToEndAsync();

            await Task.Run(() => process.WaitForExit());

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
            var processInfo = new ProcessStartInfo
            {
                FileName = command,
                Arguments = arguments ?? string.Empty,
                UseShellExecute = false,
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                CreateNoWindow = true,
                Verb =
                    "runas" // Windows elevation
                ,
            };

            using var process = Process.Start(processInfo);
            if (process == null)
                return (false, string.Empty, "Failed to start elevated process");

            var output = await process.StandardOutput.ReadToEndAsync();
            var error = await process.StandardError.ReadToEndAsync();

            await Task.Run(() => process.WaitForExit());

            return (process.ExitCode == 0, output, string.IsNullOrEmpty(error) ? null : error);
        }
        catch (Exception ex)
        {
            AnsiConsole.WriteException(ex);
            return (false, string.Empty, ex.Message);
        }
    }
}
