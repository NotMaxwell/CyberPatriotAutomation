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
    ) => await ExecuteAsync(command, arguments, DefaultTimeout);

    /// <summary>
    /// Default ceiling for a single command.
    /// </summary>
    public static readonly TimeSpan DefaultTimeout = TimeSpan.FromMinutes(2);

    /// <summary>
    /// Execute a command with an explicit timeout.
    /// </summary>
    /// <remarks>
    /// Needed for work that legitimately runs longer than <see cref="DefaultTimeout"/>.
    /// A Defender scan or a package download runs for many minutes; under the
    /// default ceiling it is killed part-way and reported as a failure.
    /// </remarks>
    public static async Task<(bool Success, string Output, string? Error)> ExecuteAsync(
        string command,
        string? arguments,
        TimeSpan timeout
    )
    {
        var (exitCode, output, error) = await ExecuteForExitCodeAsync(command, arguments, timeout);
        return (exitCode == 0, output, error);
    }

    /// <summary>
    /// Execute a command and report its exit code rather than just success.
    /// </summary>
    /// <remarks>
    /// Some tools use a non-zero exit code to mean "done, with a caveat" -
    /// Chocolatey returns 3010 and 1641 for "succeeded, reboot pending". Callers
    /// that treat those as failure roll back work that actually completed, so
    /// they need the code itself. A null exit code means the process never ran or
    /// was killed at the timeout.
    /// </remarks>
    public static async Task<(int? ExitCode, string Output, string? Error)> ExecuteForExitCodeAsync(
        string command,
        string? arguments,
        TimeSpan timeout
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
                return (null, string.Empty, "Failed to start process");

            // Read both output streams concurrently to avoid deadlocks when one stream
            // fills its buffer while the other is being read.
            var outputTask = process.StandardOutput.ReadToEndAsync();
            var errorTask = process.StandardError.ReadToEndAsync();

            // Wait for process exit with a timeout to avoid hanging indefinitely on
            // commands that may prompt for input or never return.
            using var cts = new CancellationTokenSource(timeout);
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
                return (null, await SafeGetTaskResultAsync(outputTask), "Process timed out");
            }

            var output = await SafeGetTaskResultAsync(outputTask);
            var error = await SafeGetTaskResultAsync(errorTask);

            return (process.ExitCode, output, string.IsNullOrEmpty(error) ? null : error);
        }
        catch (Exception ex)
        {
            AnsiConsole.WriteException(ex);
            return (null, string.Empty, ex.Message);
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

    /// <summary>
    /// Quote a value for safe interpolation into a single-quoted PowerShell string.
    /// </summary>
    /// <remarks>
    /// PowerShell escapes a literal <c>'</c> inside a single-quoted string by
    /// doubling it. Interpolating a raw value - an account named <c>O'Brien</c>,
    /// say - would otherwise close the string early and corrupt the rest of the
    /// script.
    /// </remarks>
    public static string PsQuote(string value) => $"'{value.Replace("'", "''")}'";

    /// <summary>
    /// Build the powershell.exe arguments used throughout the tool.
    /// </summary>
    /// <remarks>
    /// The script is embedded in a double-quoted <c>-Command</c> argument, so it
    /// must not itself contain <c>"</c>. Use single quotes (via
    /// <see cref="PsQuote"/> for interpolated values) for string literals.
    /// </remarks>
    private static string PowerShellArgs(string script, bool strict)
    {
        if (strict)
        {
            // 'Stop' promotes non-terminating cmdlet errors to terminating ones so
            // the catch block can map them onto a non-zero exit code *and* write
            // the reason to stderr. [Console]::Error is used rather than
            // Write-Error, which would itself terminate under Stop.
            return "-NoProfile -NonInteractive -Command \"$ErrorActionPreference = 'Stop'; "
                + $"try {{ {script} }} catch {{ [Console]::Error.WriteLine($_.Exception.Message); exit 1 }}\"";
        }

        // The trailing 'exit 0' is what makes a query tolerant: without it
        // PowerShell propagates the failure of the last statement, so asking for
        // an object that does not exist surfaces as a process failure rather than
        // as empty output.
        return "-NoProfile -NonInteractive -Command \"$ErrorActionPreference = 'SilentlyContinue'; "
            + $"{script}; exit 0\"";
    }

    /// <summary>
    /// Run a PowerShell script whose failure matters, reporting it via the exit code.
    /// </summary>
    /// <remarks>
    /// Replaces ad-hoc <c>-ErrorAction SilentlyContinue</c> calls, which had two
    /// problems: the error record was suppressed entirely, so the process exited
    /// non-zero but wrote nothing to stderr and callers formatting the reason
    /// produced an empty explanation; and PowerShell's exit code reflects only
    /// the final statement, so an error part-way through a multi-statement script
    /// still exited 0.
    /// </remarks>
    public static async Task<(bool Success, string Output, string? Error)> PowerShellAsync(
        string script,
        TimeSpan? timeout = null
    ) =>
        await ExecuteAsync(
            "powershell",
            PowerShellArgs(script, strict: true),
            timeout ?? DefaultTimeout
        );

    /// <summary>
    /// Run a read-only PowerShell query, tolerating missing objects.
    /// </summary>
    /// <remarks>
    /// Absence is not failure here: asking for a service or account that does not
    /// exist yields empty output and the caller decides what that means. Use
    /// <see cref="PowerShellAsync"/> for anything that changes state.
    /// </remarks>
    public static async Task<(bool Success, string Output, string? Error)> PowerShellQueryAsync(
        string script,
        TimeSpan? timeout = null
    ) =>
        await ExecuteAsync(
            "powershell",
            PowerShellArgs(script, strict: false),
            timeout ?? DefaultTimeout
        );

    /// <summary>
    /// Download <paramref name="url"/> to <paramref name="destination"/>,
    /// returning the reason on failure.
    /// </summary>
    /// <remarks>
    /// Shells out rather than using HttpClient so TLS, the certificate store and
    /// any configured proxy stay with the OS. TLS 1.2 is selected explicitly
    /// because Windows PowerShell 5.1 still negotiates older protocols that most
    /// hosts now refuse. Both transports follow redirects, so aka.ms links work.
    /// </remarks>
    public static async Task<string?> DownloadFileAsync(string url, string destination)
    {
        var script =
            "[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12; "
            + $"Invoke-WebRequest -Uri {PsQuote(url)} -OutFile {PsQuote(destination)} -UseBasicParsing";

        var (ok, _, psError) = await PowerShellAsync(script, TimeSpan.FromMinutes(10));
        if (ok && File.Exists(destination))
            return null;

        string? curlError = null;
        foreach (var program in new[] { "curl.exe", "curl" })
        {
            var (curlOk, _, err) = await ExecuteAsync(
                program,
                $"-L -s -S -o \"{destination}\" \"{url}\"",
                TimeSpan.FromMinutes(10)
            );
            if (curlOk && File.Exists(destination))
                return null;
            curlError = err;
        }

        var reason = !string.IsNullOrWhiteSpace(psError) ? psError : curlError;
        return string.IsNullOrWhiteSpace(reason) ? "no error reported" : reason.Trim();
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
