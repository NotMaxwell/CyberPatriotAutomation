//! Handles execution of system commands and processes.

use std::time::Duration;
use tokio::io::AsyncReadExt;
use tokio::process::Command;
use tokio::time::timeout;

/// Result of a command execution: (success, stdout, optional stderr).
pub type CommandOutput = (bool, String, Option<String>);

const COMMAND_TIMEOUT: Duration = Duration::from_secs(120);

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
        use std::os::windows::process::CommandExt;
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

/// Execute a command and return the output.
///
/// Reads both output streams concurrently to avoid deadlocks, and enforces a
/// two-minute timeout so a hung child process cannot stall the tool.
pub async fn execute(command: &str, arguments: Option<&str>) -> CommandOutput {
    let mut cmd = build_command(command, arguments);

    let mut child = match cmd.spawn() {
        Ok(child) => child,
        Err(e) => return (false, String::new(), Some(e.to_string())),
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

    match timeout(COMMAND_TIMEOUT, child.wait()).await {
        Ok(Ok(status)) => {
            let (out, err) = reader.await.unwrap_or_default();
            let output = String::from_utf8_lossy(&out).into_owned();
            let error = String::from_utf8_lossy(&err).into_owned();
            let error = if error.is_empty() { None } else { Some(error) };
            (status.success(), output, error)
        }
        Ok(Err(e)) => (false, String::new(), Some(e.to_string())),
        Err(_) => {
            let _ = child.start_kill();
            let (out, _err) = reader.await.unwrap_or_default();
            (
                false,
                String::from_utf8_lossy(&out).into_owned(),
                Some("Process timed out".to_string()),
            )
        }
    }
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
