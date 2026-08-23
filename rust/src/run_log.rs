//! Records everything a run attempts, schedules and completes, and writes it to
//! a file when execution finishes.
//!
//! The console narrative already describes the run in full — which services
//! were queued for disabling, which users were created, which updates were
//! applied and which failed — but it scrolls away, and on a competition image
//! there is rarely an opportunity to read it as it goes. Every line the `ui`
//! module prints is therefore mirrored here, with markup stripped and a
//! timestamp attached, and flushed to disk at the end.
//!
//! The buffer is process-global because the `ui` helpers are free functions
//! called from every task; threading a logger through the whole `Task` trait
//! would change every signature to record something none of the tasks
//! themselves care about.

use chrono::Local;
use std::path::{Path, PathBuf};
use std::sync::Mutex;

/// Timestamped lines captured so far, in order.
static ENTRIES: Mutex<Vec<String>> = Mutex::new(Vec::new());

/// Append a line to the run log. Blank lines are dropped to keep the log dense.
pub fn record(text: &str) {
    let text = text.trim_end();
    if text.is_empty() {
        return;
    }
    push(format!("[{}] {}", Local::now().format("%H:%M:%S"), text));
}

/// Append a section heading, mirroring a console rule.
pub fn record_section(title: &str) {
    let title = title.trim();
    if title.is_empty() {
        return;
    }
    push(String::new());
    push(format!("=== {title} ==="));
}

/// Append a line with no timestamp, used for structured blocks at the end.
pub fn record_raw(text: &str) {
    push(text.to_string());
}

fn push(line: String) {
    // A poisoned lock would mean another thread panicked mid-log; the log is
    // diagnostic, so recover the buffer rather than propagating the panic.
    let mut entries = match ENTRIES.lock() {
        Ok(entries) => entries,
        Err(poisoned) => poisoned.into_inner(),
    };
    entries.push(line);
}

/// Everything recorded so far.
/// Record a diagnostic: something the operator does not need to see while the
/// run is happening, but needs afterwards to work out why it did what it did.
///
/// The console narrative reports outcomes - "Failed to remove: CCleaner" - but
/// not the evidence. When the reason comes back empty, which is what happens
/// whenever a tool reports failure only through an exit code, that line degrades
/// to "Failed to remove: CCleaner ()" and there is nothing left to investigate
/// with. Diagnostics carry the evidence: the exact command, its exit code, and
/// what it printed.
///
/// These go to the log only, never to the console. They exist to be read after
/// the fact, and putting them on screen would bury the narrative the operator
/// does have to follow live.
pub fn diagnostic(category: &str, detail: &str) {
    let detail = detail.trim_end();
    if detail.is_empty() {
        return;
    }

    let stamp = chrono::Local::now().format("%H:%M:%S");
    let mut lines = detail.lines();
    if let Some(first) = lines.next() {
        push(format!("[{stamp}] [{category}] {}", first.trim_end()));
    }
    // Indented continuation lines keep a multi-line payload - a captured stderr,
    // say - visibly attached to its own entry rather than reading as separate
    // events.
    for line in lines {
        push(format!("                      {}", line.trim_end()));
    }
}

/// Longest captured output kept per failed command.
const MAX_CAPTURED_OUTPUT: usize = 600;

/// Record the outcome of an external command, with enough to reproduce it.
///
/// Output is captured only on failure, and truncated. A successful command's
/// output is usually large and never interesting; a failure's first few lines
/// are almost always the whole story.
pub fn record_command(
    program: &str,
    arguments: Option<&str>,
    exit_code: Option<i32>,
    output: &str,
    error: Option<&str>,
    elapsed: std::time::Duration,
) {
    let status = match exit_code {
        Some(code) => format!("exit {code}"),
        None => "no exit code (timed out or never ran)".to_string(),
    };

    diagnostic(
        "cmd",
        format!("{program} {}", redact(arguments.unwrap_or_default())).trim_end(),
    );
    diagnostic(
        "cmd",
        &format!("  -> {status} in {:.1}s", elapsed.as_secs_f64()),
    );

    if exit_code == Some(0) {
        return;
    }

    if let Some(err) = error.filter(|e| !e.trim().is_empty()) {
        diagnostic("cmd", &format!("  stderr: {}", truncate(err)));
    }
    if !output.trim().is_empty() {
        diagnostic("cmd", &format!("  stdout: {}", truncate(output)));
    }
}

fn truncate(text: &str) -> String {
    let text = text.trim();
    if text.chars().count() <= MAX_CAPTURED_OUTPUT {
        return text.to_string();
    }
    let kept: String = text.chars().take(MAX_CAPTURED_OUTPUT).collect();
    let remaining = text.chars().count() - MAX_CAPTURED_OUTPUT;
    format!("{kept}... [{remaining} more chars]")
}

/// Blank out plaintext passwords before a command line reaches the log.
///
/// Account passwords are interpolated into `ConvertTo-SecureString` calls. The
/// log does deliberately record each generated password once, where the task
/// announces it - but that is a considered disclosure in one place, not a reason
/// to scatter the same secret through every command echo.
pub fn redact(command_line: &str) -> String {
    let Some(at) = command_line.find("ConvertTo-SecureString") else {
        return command_line.to_string();
    };

    let rest = &command_line[at..];
    let Some(open) = rest.find('\'') else {
        return command_line.to_string();
    };
    let Some(close_rel) = rest[open + 1..].find('\'') else {
        return command_line.to_string();
    };
    let close = open + 1 + close_rel;

    format!(
        "{}{}'***'{}",
        &command_line[..at],
        &rest[..open],
        &rest[close + 1..]
    )
}

pub fn entries() -> Vec<String> {
    match ENTRIES.lock() {
        Ok(entries) => entries.clone(),
        Err(poisoned) => poisoned.into_inner().clone(),
    }
}

/// Discard everything recorded so far. Used by tests to isolate cases.
pub fn clear() {
    match ENTRIES.lock() {
        Ok(mut entries) => entries.clear(),
        Err(poisoned) => poisoned.into_inner().clear(),
    }
}

/// Default log location: the desktop of the user running the tool, alongside
/// the backup folder the prohibited-media task writes.
///
/// The version is part of the file name so logs from different builds are
/// distinguishable at a glance, without opening them.
pub fn default_log_path() -> PathBuf {
    crate::app_config::desktop_dir().join(format!(
        "PinnacleCyPat_RunLog_v{}_{}.txt",
        crate::app_config::VERSION,
        Local::now().format("%Y%m%d_%H%M%S")
    ))
}

/// Write the log to `path`, creating parent directories as needed.
pub fn write_to(path: &Path) -> std::io::Result<()> {
    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() {
            std::fs::create_dir_all(parent)?;
        }
    }
    let mut body = entries().join("\r\n");
    body.push_str("\r\n");
    std::fs::write(path, body)
}

/// Build the header written at the top of every log.
pub fn header(command_line: &str) -> Vec<String> {
    vec![
        "=".repeat(79),
        "PinnacleCyPat - Run Log".to_string(),
        format!("Version:   {}", crate::app_config::version_string()),
        format!("Started:   {}", Local::now().format("%Y-%m-%d %H:%M:%S")),
        format!("Command:   {command_line}"),
        "=".repeat(79),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    // The buffer is global, so these cases must not run concurrently with each
    // other. They are grouped into one test rather than relying on test-thread
    // ordering.
    #[test]
    fn records_strips_blanks_and_writes_a_file() {
        clear();

        record("Disabling service: TlntSvr");
        record("   ");
        record("");
        record_section("Step 2");
        record("Created user: alice");

        let entries = entries();
        assert_eq!(
            entries.iter().filter(|l| l.contains("Disabling service")).count(),
            1
        );
        assert!(
            entries.iter().any(|l| l == "=== Step 2 ==="),
            "section heading missing: {entries:?}"
        );
        assert!(
            entries.iter().any(|l| l.contains("Created user: alice")),
            "entry missing: {entries:?}"
        );
        // Blank input must not produce timestamped empty lines.
        assert!(
            !entries.iter().any(|l| l.ends_with("] ")),
            "blank line recorded: {entries:?}"
        );

        let path = std::env::temp_dir().join(format!("cpa_runlog_{}.txt", std::process::id()));
        write_to(&path).expect("log should write");
        let written = std::fs::read_to_string(&path).unwrap();
        assert!(written.contains("Disabling service: TlntSvr"));
        assert!(written.contains("=== Step 2 ==="));
        let _ = std::fs::remove_file(&path);

        clear();
    }
}
