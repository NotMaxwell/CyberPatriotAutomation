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

use crate::models::{FixOutcome, FixRecord};
use chrono::Local;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Mutex;

/// Timestamped lines captured so far, in order.
static ENTRIES: Mutex<Vec<String>> = Mutex::new(Vec::new());

/// Every attempted change, in order.
static FIXES: Mutex<Vec<FixRecord>> = Mutex::new(Vec::new());

/// The task subsequent [`record_fix`] calls belong to.
static CURRENT_TASK: Mutex<String> = Mutex::new(String::new());

/// When true the `*_ops` modules record what they would have done and change
/// nothing.
static DRY_RUN: AtomicBool = AtomicBool::new(false);

tokio::task_local! {
    /// The task the currently running future belongs to.
    static TASK_NAME: String;
}

/// Attribute every fix `future` records to `name`.
///
/// The modules that record a fix - `registry_ops` and friends - are called from
/// every task and are not told which one they are serving. Rather than thread a
/// task name through every signature to carry something none of them otherwise
/// need, the runner scopes it around each task.
///
/// This is a task-local rather than the obvious global because the independent
/// audits run concurrently: with one shared slot, whichever task last started
/// would claim every change the others made, and the ledger's grouping - the
/// thing that makes it readable - would be quietly wrong.
pub async fn in_task<F: std::future::Future>(name: &str, future: F) -> F::Output {
    let name = name.trim();
    let name = if name.is_empty() {
        "(unnamed task)".to_string()
    } else {
        name.to_string()
    };
    TASK_NAME.scope(name, future).await
}

/// Name the task for code that is not inside an [`in_task`] scope, such as the
/// summary written after every task has finished.
pub fn begin_task(name: &str) {
    let name = name.trim();
    let mut current = lock(&CURRENT_TASK);
    *current = if name.is_empty() {
        "(unnamed task)".to_string()
    } else {
        name.to_string()
    };
}

/// Have the `*_ops` modules hold back from writing anything.
///
/// Tasks generally return before reaching a write in dry-run mode, so this is a
/// backstop rather than the primary guard - but it is the one that cannot be
/// forgotten in a new task, and it makes a dry run produce a full ledger of
/// intended changes rather than a silent one.
pub fn set_dry_run(value: bool) {
    DRY_RUN.store(value, Ordering::Relaxed);
}

/// Is this a dry run?
pub fn dry_run() -> bool {
    DRY_RUN.load(Ordering::Relaxed)
}

/// Record one attempted change, and mirror a one-line summary into the
/// narrative so the log reads in order.
pub fn record_fix(
    target: &str,
    intent: &str,
    before: Option<String>,
    action: &str,
    outcome: FixOutcome,
    evidence: &str,
) {
    // Inside a task the scoped name is authoritative; outside one - the summary,
    // or a test calling an op directly - fall back to the global slot.
    let task = TASK_NAME.try_with(|name| name.clone()).unwrap_or_else(|_| {
        let current = lock(&CURRENT_TASK);
        if current.is_empty() {
            "(startup)".to_string()
        } else {
            current.clone()
        }
    });

    lock(&FIXES).push(FixRecord {
        task,
        target: target.to_string(),
        intent: intent.to_string(),
        before,
        action: action.to_string(),
        outcome,
        evidence: evidence.to_string(),
    });

    record(&format!(
        "[{}] {target} - want {intent}; {evidence}",
        outcome.tag()
    ));
}

/// Every change recorded so far.
pub fn fixes() -> Vec<FixRecord> {
    lock(&FIXES).clone()
}

/// Serialises tests that touch the global buffers.
///
/// The log is process-global by design - see the module comment - so any two
/// tests that record into it will trample each other under the default
/// multi-threaded test runner. Every such test takes this first.
#[cfg(test)]
pub static TEST_GATE: Mutex<()> = Mutex::new(());

/// Take [`TEST_GATE`], recovering it if a previous test panicked while holding
/// it - otherwise one failure cascades into every later test.
#[cfg(test)]
pub fn test_gate() -> std::sync::MutexGuard<'static, ()> {
    lock(&TEST_GATE)
}

/// A poisoned lock would mean another thread panicked mid-log; the log is
/// diagnostic, so recover the buffer rather than propagating the panic.
fn lock<T>(mutex: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    match mutex.lock() {
        Ok(guard) => guard,
        Err(poisoned) => poisoned.into_inner(),
    }
}

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
    lock(&ENTRIES).push(line);
}

/// Everything recorded so far.
pub fn entries() -> Vec<String> {
    lock(&ENTRIES).clone()
}

/// Discard everything recorded so far. Used by tests to isolate cases.
pub fn clear() {
    lock(&ENTRIES).clear();
    lock(&FIXES).clear();
    lock(&CURRENT_TASK).clear();
    set_dry_run(false);
}

/// Append the remediation ledger: every change this run wanted to make, what it
/// did, and the read-back that proves it.
///
/// Grouped by task and written before the task results, so the summary at the
/// bottom of the log can be read against the detail above it.
pub fn append_ledger() {
    let fixes = fixes();

    record_raw("");
    record_raw(&"=".repeat(79));
    record_raw("REMEDIATION LEDGER");
    record_raw(&"=".repeat(79));
    record_raw("Every change this run wanted to make, what it did about it, and how it");
    record_raw("knows. \"Proof\" is a re-read of the real state taken after the write, not a");
    record_raw("restatement of what was attempted.");

    if fixes.is_empty() {
        record_raw("");
        record_raw("No changes were attempted.");
        return;
    }

    // Grouped by task, in the order the tasks first appear, so the ledger reads
    // in the order the run happened.
    let mut seen: Vec<&str> = Vec::new();
    for fix in &fixes {
        if !seen.contains(&fix.task.as_str()) {
            seen.push(&fix.task);
        }
    }

    for task in seen {
        record_raw("");
        record_raw(&format!("--- {task} ---"));

        for fix in fixes.iter().filter(|f| f.task == task) {
            record_raw("");
            record_raw(&format!("[{}] {}", fix.outcome.tag(), fix.target));
            record_raw(&format!("  Want:   {}", fix.intent));
            record_raw(&format!(
                "  Before: {}",
                fix.before.as_deref().unwrap_or("(could not read)")
            ));
            record_raw(&format!("  Did:    {}", fix.action));
            record_raw(&format!("  Proof:  {}", fix.evidence));
        }
    }

    record_raw("");
    record_raw(&ledger_totals(&fixes));
}

/// One line tallying the ledger by outcome.
pub fn ledger_totals(fixes: &[FixRecord]) -> String {
    let count = |outcome: FixOutcome| fixes.iter().filter(|f| f.outcome == outcome).count();
    format!(
        "Totals: {} fixed, {} already compliant, {} failed, {} unverified, {} skipped",
        count(FixOutcome::Fixed),
        count(FixOutcome::AlreadyCompliant),
        count(FixOutcome::Failed),
        count(FixOutcome::Unverified),
        count(FixOutcome::Skipped),
    )
}

/// Default log location: the desktop of the user running the tool, alongside
/// the backup folder the prohibited-media task writes.
///
/// The version is part of the file name so logs from different builds are
/// distinguishable at a glance, without opening them.
pub fn default_log_path() -> PathBuf {
    crate::app_config::desktop_dir().join(format!(
        "CyberPatriot_RunLog_v{}_{}.txt",
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
        "CyberPatriot Automation Tool - Run Log".to_string(),
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
        let _gate = test_gate();
        clear();

        record("Disabling service: TlntSvr");
        record("   ");
        record("");
        record_section("Step 2");
        record("Created user: alice");

        let entries = entries();
        assert_eq!(
            entries
                .iter()
                .filter(|l| l.contains("Disabling service"))
                .count(),
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

    // Also global state, so this shares the single-test-per-buffer discipline
    // above rather than racing the case before it.
    #[test]
    fn ledger_records_intent_action_and_proof_grouped_by_task() {
        let _gate = test_gate();
        clear();

        begin_task("Service Management");
        record_fix(
            "Service TlntSvr",
            "start type disabled",
            Some("not disabled".to_string()),
            "set the start type to disabled",
            FixOutcome::Fixed,
            "read back after the write: disabled",
        );
        record_fix(
            "Service RemoteRegistry",
            "start type disabled",
            Some("disabled".to_string()),
            "nothing - already in the wanted state",
            FixOutcome::AlreadyCompliant,
            "read before acting: disabled",
        );

        begin_task("User Management");
        record_fix(
            "Account hacker",
            "deleted",
            Some("present".to_string()),
            "deleted the account",
            FixOutcome::Failed,
            "reads present after the attempt; the write failed: Access is denied",
        );

        append_ledger();
        let log = entries().join("\n");

        // Every part the ledger exists to carry.
        assert!(log.contains("REMEDIATION LEDGER"), "{log}");
        assert!(log.contains("  Want:   start type disabled"), "{log}");
        assert!(
            log.contains("  Did:    set the start type to disabled"),
            "{log}"
        );
        assert!(
            log.contains("  Proof:  read back after the write: disabled"),
            "{log}"
        );
        assert!(log.contains("  Before: not disabled"), "{log}");

        // Grouped by task, in the order the tasks first ran.
        let services_at = log
            .find("--- Service Management ---")
            .expect("group missing");
        let users_at = log.find("--- User Management ---").expect("group missing");
        assert!(services_at < users_at, "groups out of order: {log}");

        assert!(
            log.contains("Totals: 1 fixed, 1 already compliant, 1 failed, 0 unverified, 0 skipped"),
            "{log}"
        );

        clear();
    }

    #[test]
    fn a_fix_with_no_readable_before_state_says_so() {
        let _gate = test_gate();
        clear();

        record_fix(
            r"HKLM\Software\Policies\Example\Value",
            "REG_DWORD = 1",
            None,
            "wrote REG_DWORD 1",
            FixOutcome::Unverified,
            "the write reported success but the state could not be read back",
        );
        append_ledger();

        let log = entries().join("\n");
        // The distinction that matters: "we looked and it was wrong" versus "we
        // could not look". A blank here would read as the former.
        assert!(log.contains("  Before: (could not read)"), "{log}");

        clear();
    }
}
