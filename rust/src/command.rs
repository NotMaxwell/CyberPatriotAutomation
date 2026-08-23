//! Handles execution of system commands and processes.

use std::time::Duration;
use tokio::io::AsyncReadExt;
use tokio::process::Command;
use tokio::time::timeout;

/// Result of a command execution: (success, stdout, optional stderr).
pub type CommandOutput = (bool, String, Option<String>);

/// Default ceiling for a single command. Enough for the query and
/// configuration utilities the tasks drive.
pub const COMMAND_TIMEOUT: Duration = Duration::from_secs(120);

/// Build a [`Command`] for the given program and raw argument string.
///
/// On Windows the argument string is passed verbatim (matching .NET's
/// `ProcessStartInfo.Arguments` behaviour). On other platforms — where these
/// Windows utilities do not exist and spawning simply fails gracefully — a
/// lightweight quote-aware split is used so the code still compiles and runs.
fn build_command(program: &str, arguments: Option<&str>) -> Command {
    let mut cmd = Command::new(program);
    let args = arguments.unwrap_or("");

    #[cfg(windows)]
    {
        // `raw_arg` is inherent on tokio's `Command`, so the
        // `std::os::windows::process::CommandExt` trait does not need importing.
        if !args.is_empty() {
            cmd.raw_arg(args);
        }
    }
    #[cfg(not(windows))]
    {
        for arg in split_arguments(args) {
            cmd.arg(arg);
        }
    }

    cmd.stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped());
    cmd
}

#[cfg(not(windows))]
fn split_arguments(input: &str) -> Vec<String> {
    let mut args = Vec::new();
    let mut current = String::new();
    let mut in_quotes = false;
    let mut has_token = false;
    for c in input.chars() {
        match c {
            '"' => {
                in_quotes = !in_quotes;
                has_token = true;
            }
            c if c.is_whitespace() && !in_quotes => {
                if has_token {
                    args.push(std::mem::take(&mut current));
                    has_token = false;
                }
            }
            c => {
                current.push(c);
                has_token = true;
            }
        }
    }
    if has_token {
        args.push(current);
    }
    args
}

/// Execute a command and return the output, under the default timeout.
///
/// Reads both output streams concurrently to avoid deadlocks, and enforces a
/// two-minute timeout so a hung child process cannot stall the tool.
pub async fn execute(command: &str, arguments: Option<&str>) -> CommandOutput {
    execute_with_timeout(command, arguments, COMMAND_TIMEOUT).await
}

/// Execute a command with an explicit timeout.
///
/// Needed for work that legitimately runs longer than [`COMMAND_TIMEOUT`] -
/// installing a package update can involve a download of hundreds of megabytes,
/// and the default ceiling would kill it part-way through, leaving the package
/// in a half-updated state and reporting a timeout rather than a real result.
pub async fn execute_with_timeout(
    command: &str,
    arguments: Option<&str>,
    limit: Duration,
) -> CommandOutput {
    let (code, output, error) = execute_for_exit_code(command, arguments, limit).await;
    (code == Some(0), output, error)
}

/// Execute a command and report its exit code rather than just success.
///
/// Some tools use a non-zero exit code to mean "done, with a caveat" -
/// Chocolatey returns 3010 and 1641 for "succeeded, reboot pending". Treating
/// those as failure would report a completed install as failed and re-run it.
/// `None` means the process never started or was killed at the timeout.
pub async fn execute_for_exit_code(
    command: &str,
    arguments: Option<&str>,
    limit: Duration,
) -> (Option<i32>, String, Option<String>) {
    // Every command is recorded, with its exit code and - when it fails - what
    // it printed. Without this a task that reports "Failed to remove X" with an
    // empty reason leaves nothing at all to investigate, which is precisely the
    // case where someone goes looking at the log.
    let started = std::time::Instant::now();
    let mut cmd = build_command(command, arguments);

    let mut child = match cmd.spawn() {
        Ok(child) => child,
        Err(e) => {
            // A missing executable lands here - `wmic` on a current Windows 11
            // image, for one - and this message is the only clue.
            crate::run_log::record_command(
                command,
                arguments,
                None,
                "",
                Some(&e.to_string()),
                started.elapsed(),
            );
            return (None, String::new(), Some(e.to_string()));
        }
    };

    let stdout = child.stdout.take();
    let stderr = child.stderr.take();

    // Read both pipes concurrently on a background task.
    let reader = tokio::spawn(async move {
        let mut out = Vec::new();
        let mut err = Vec::new();
        if let (Some(mut so), Some(mut se)) = (stdout, stderr) {
            let _ = tokio::join!(so.read_to_end(&mut out), se.read_to_end(&mut err));
        }
        (out, err)
    });

    match timeout(limit, child.wait()).await {
        Ok(Ok(status)) => {
            let (out, err) = reader.await.unwrap_or_default();
            let output = String::from_utf8_lossy(&out).into_owned();
            let error = String::from_utf8_lossy(&err).into_owned();
            let error = if error.is_empty() { None } else { Some(error) };
            crate::run_log::record_command(
                command,
                arguments,
                status.code(),
                &output,
                error.as_deref(),
                started.elapsed(),
            );
            (status.code(), output, error)
        }
        Ok(Err(e)) => {
            crate::run_log::record_command(
                command,
                arguments,
                None,
                "",
                Some(&e.to_string()),
                started.elapsed(),
            );
            (None, String::new(), Some(e.to_string()))
        }
        Err(_) => {
            let _ = child.start_kill();
            let (out, _err) = reader.await.unwrap_or_default();
            let output = String::from_utf8_lossy(&out).into_owned();
            crate::run_log::record_command(
                command,
                arguments,
                None,
                &output,
                Some(&format!("Process timed out after {:.0}s", limit.as_secs_f64())),
                started.elapsed(),
            );
            (None, output, Some("Process timed out".to_string()))
        }
    }
}

/// Quote a value for safe interpolation into a single-quoted PowerShell string.
///
/// PowerShell escapes a literal `'` inside a single-quoted string by doubling
/// it. Interpolating a raw value - an account name such as `O'Brien`, or a
/// service display name containing an apostrophe - would otherwise close the
/// string early and corrupt the remainder of the script.
pub fn ps_quote(value: &str) -> String {
    format!("'{}'", value.replace('\'', "''"))
}

/// Wrap a script in the `powershell.exe` arguments used throughout the tool.
///
/// `strict` decides how cmdlet errors are surfaced - see [`powershell`] and
/// [`powershell_query`].
///
/// The script is embedded inside a double-quoted `-Command` argument, so it must
/// not itself contain `"`. Use single quotes (via [`ps_quote`] for interpolated
/// values) for string literals.
fn powershell_args(script: &str, strict: bool) -> String {
    debug_assert!(
        !script.contains('"'),
        "PowerShell script must not contain double quotes: {script}"
    );
    if strict {
        // `$ErrorActionPreference = 'Stop'` promotes non-terminating cmdlet
        // errors to terminating ones so the catch block can map them onto a
        // non-zero exit code *and* write the reason to stderr.
        // `[Console]::Error` is used rather than `Write-Error` because the
        // latter would itself terminate under Stop.
        format!(
            "-NoProfile -NonInteractive -Command \"$ErrorActionPreference = 'Stop'; try {{ {script} }} catch {{ [Console]::Error.WriteLine($_.Exception.Message); exit 1 }}\""
        )
    } else {
        // The trailing `exit 0` is what makes a query tolerant: without it
        // PowerShell propagates the failure of the last statement, so asking
        // for an object that does not exist would surface as a process
        // failure rather than as empty output.
        format!(
            "-NoProfile -NonInteractive -Command \"$ErrorActionPreference = 'SilentlyContinue'; {script}; exit 0\""
        )
    }
}

/// Run a PowerShell script whose failure matters, reporting it via the exit code.
///
/// Replaces the previous `-ErrorAction SilentlyContinue` calls, which had two
/// problems (verified against Windows PowerShell 5.1):
///
/// - **The reason was lost.** `SilentlyContinue` suppresses the error record
///   entirely, so the process exited non-zero but wrote *nothing* to stderr.
///   Callers formatting `"...: {error}"` produced an empty explanation.
/// - **Failure was hidden unless it happened last.** PowerShell's exit code
///   reflects only the final statement, so an error part-way through a
///   multi-statement script still exited 0.
///
/// Under `Stop` + `try`/`catch` any cmdlet error becomes a non-zero exit with
/// the message on stderr, wherever in the script it occurs.
///
/// Pass the bare script - no `-Command` wrapper and no `-ErrorAction` override,
/// which would defeat the point by re-suppressing the error.
pub async fn powershell(script: &str) -> CommandOutput {
    execute("powershell", Some(&powershell_args(script, true))).await
}

/// As [`powershell`], with an explicit timeout for work that legitimately runs
/// longer than [`COMMAND_TIMEOUT`] - a malware scan, for instance.
pub async fn powershell_with_timeout(script: &str, limit: Duration) -> CommandOutput {
    execute_with_timeout("powershell", Some(&powershell_args(script, true)), limit).await
}

/// Run a read-only PowerShell query, tolerating missing objects.
///
/// Absence is not failure here: asking for a service or account that does not
/// exist should yield empty output rather than an error, and the caller decides
/// what that means. Use [`powershell`] for anything that changes state.
pub async fn powershell_query(script: &str) -> CommandOutput {
    execute("powershell", Some(&powershell_args(script, false))).await
}

/// Download `url` to `dest`, returning the reason on failure.
///
/// Shells out rather than linking an HTTP client: TLS, the certificate store
/// and any configured proxy stay with the OS, and the cross-compiled binary
/// gains no dependency. TLS 1.2 is selected explicitly because Windows
/// PowerShell 5.1 still negotiates older protocols that most hosts now refuse,
/// which otherwise fails with an unhelpful "underlying connection was closed".
/// `curl` is the fallback; both follow redirects, so `aka.ms` short links work.
pub async fn download_file(url: &str, dest: &std::path::Path) -> Result<(), String> {
    let dest_str = dest.to_string_lossy().into_owned();

    let script = format!(
        "[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12; \
         Invoke-WebRequest -Uri {} -OutFile {} -UseBasicParsing",
        ps_quote(url),
        ps_quote(&dest_str)
    );
    let (ok, _out, ps_error) = powershell(&script).await;
    if ok && dest.is_file() {
        return Ok(());
    }

    let mut curl_error = None;
    for program in ["curl.exe", "curl"] {
        let (curl_ok, _out, err) = execute(
            program,
            Some(&format!("-L -s -S -o \"{dest_str}\" \"{url}\"")),
        )
        .await;
        if curl_ok && dest.is_file() {
            return Ok(());
        }
        curl_error = err;
    }

    Err(ps_error
        .filter(|e| !e.trim().is_empty())
        .or(curl_error)
        .map(|e| e.trim().to_string())
        .unwrap_or_else(|| "no error reported".to_string()))
}

/// Execute a command with elevated privileges.
///
/// On non-Windows platforms this behaves like [`execute`] without capturing
/// output. It is retained for API parity with the original tool.
#[allow(dead_code)]
pub async fn execute_elevated(command: &str, arguments: Option<&str>) -> CommandOutput {
    let (success, _out, err) = execute(command, arguments).await;
    (success, String::new(), err)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ps_quote_wraps_and_doubles_embedded_quotes() {
        assert_eq!(ps_quote("alice"), "'alice'");
        // An apostrophe in an account name would otherwise close the string
        // early and corrupt the rest of the script.
        assert_eq!(ps_quote("O'Brien"), "'O''Brien'");
        assert_eq!(ps_quote(""), "''");
    }

    #[test]
    fn strict_args_promote_errors_and_set_a_failing_exit_code() {
        let args = powershell_args("Set-Thing -Value 1", true);
        assert!(args.contains("$ErrorActionPreference = 'Stop'"));
        assert!(args.contains("Set-Thing -Value 1"));
        assert!(
            args.contains("exit 1"),
            "failures must map to a non-zero exit"
        );
        assert!(args.contains("-NonInteractive"));
    }

    #[test]
    fn query_args_tolerate_missing_objects() {
        let args = powershell_args("Get-Thing", false);
        assert!(args.contains("$ErrorActionPreference = 'SilentlyContinue'"));
        assert!(args.contains("Get-Thing"));
        // A query must not turn "not found" into a process failure. Without the
        // explicit `exit 0`, PowerShell propagates the last statement's failure.
        assert!(args.contains("exit 0"));
        assert!(!args.contains("exit 1"));
    }

    #[test]
    fn wrapped_scripts_have_balanced_quoting() {
        for strict in [true, false] {
            let args = powershell_args("Get-Service -Name 'Spooler'", strict);
            assert_eq!(
                args.matches('"').count() % 2,
                0,
                "unbalanced double quotes in: {args}"
            );
            assert!(args.starts_with("-NoProfile"));
        }
    }
}
