// Copyright 2026 Maxwell McCormick
// SPDX-License-Identifier: Apache-2.0

//! The run pipeline, behind an event stream.
//!
//! Every front end - the CLI, the Windows GUI, the Linux web UI - drives a run
//! through [`run`] and displays the [`RunEvent`]s it sends. The pipeline used to
//! live in the CLI's `main.rs`, writing straight to the terminal, which left a
//! second front end two choices: duplicate it, or scrape stdout. Here the
//! console output becomes [`RunEvent::Line`] through [`ui::stream`], and each
//! line is recorded in the run log as it is emitted, so the log a GUI run writes
//! is the log a CLI run writes.

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use tokio::sync::mpsc::UnboundedSender;

use crate::app_config;
use crate::directives::{self, Directive};
use crate::models::{FixOutcome, FixRecord, ReadmeData, TaskResult};
use crate::platform::{Concurrency, Platform, TaskSpec};
use crate::readme_parser;
use crate::run_log;
use crate::task::Task;
use crate::ui::{self, BarColor};

/// Where the README comes from.
#[derive(Debug, Clone)]
pub enum ReadmeChoice {
    None,
    Path(String),
    Auto,
}

/// Which tasks to run.
#[derive(Debug, Clone)]
pub enum TaskChoice {
    All,
    /// Long or short flags, e.g. `"--firewall"`. They select rows of the
    /// platform's task list; the run order is always the list's, never the
    /// order given here.
    Flags(Vec<String>),
}

pub struct RunPlan {
    pub readme: ReadmeChoice,
    /// Hand-edited data that replaces the parse when building tasks.
    pub readme_override: Option<ReadmeData>,
    pub tasks: TaskChoice,
    pub dry_run: bool,
    pub log_path: PathBuf,
    /// Stamped into the run log header.
    pub command_line: String,
    /// Checked between sequential tasks, never mid-write.
    pub cancel: Arc<AtomicBool>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Phase {
    Reading,
    Executing,
    Verifying,
}

// The large variants are sent once per run; boxing them would cost every
// front end a deref to save a few hundred bytes per line event.
#[allow(clippy::large_enum_variant)]
#[derive(Debug, Clone)]
pub enum RunEvent {
    /// Every console line, in order. Already recorded in the run log.
    Line(ui::Line),
    Readme(ReadmeInspection),
    /// `index` is the task's 0-based position among the selected tasks, in run
    /// order. A concurrent audit's start, phases and finish arrive as they
    /// happen, but its lines arrive later as one block.
    TaskStarted {
        name: String,
        index: usize,
        total: usize,
        concurrent: bool,
    },
    TaskPhase {
        name: String,
        phase: Phase,
    },
    TaskFinished(TaskResult),
    Finished(RunSummary),
}

#[derive(Debug, Clone, Default)]
pub struct ReadmeInspection {
    /// The document actually parsed.
    pub source: Option<String>,
    pub data: Option<ReadmeData>,
    pub directives: Vec<Directive>,
    /// Discovery locations checked.
    pub attempts: Vec<String>,
}

#[derive(Debug, Clone)]
pub struct RunSummary {
    pub results: Vec<TaskResult>,
    pub fixes: Vec<FixRecord>,
    pub log_path: PathBuf,
    pub log_error: Option<String>,
    pub cancelled: bool,
}

/// Find, resolve and parse the README, changing nothing.
///
/// Its narration ("Using README: ...") goes through [`ui`] like all output:
/// printed by default, collected under [`ui::capture`], streamed inside a run.
///
/// An explicitly supplied path is resolved the same way an auto-discovered one
/// is: the documented location on a competition image is
/// `C:\CyberPatriot\README.url`, so a path to a `.url` (or a `.lnk`) has to
/// follow the shortcut rather than parse the shortcut file itself as HTML. If
/// it does not resolve, the original path is kept so the parser reports "not
/// found" against what the user actually typed.
pub async fn inspect_readme(choice: &ReadmeChoice) -> ReadmeInspection {
    let mut inspection = ReadmeInspection::default();
    let file = match choice {
        ReadmeChoice::None => return inspection,
        ReadmeChoice::Path(path) => Some(path.clone()),
        ReadmeChoice::Auto => {
            app_config::find_readme_file_reporting(&mut inspection.attempts).await
        }
    };

    let Some(file) = file else {
        ui::markup_line(
            "[yellow]⚠ No README found automatically. Pass --readme <file> to specify one.[/]",
        );
        // Show where it looked, so a candidate that exists but cannot be
        // followed is visible rather than silently skipped.
        ui::markup_line("[dim]Locations checked:[/]");
        for attempt in &inspection.attempts {
            ui::markup_line(&format!("[dim]  - {}[/]", ui::escape(attempt)));
        }
        return inspection;
    };
    if file.is_empty() {
        return inspection;
    }

    let path = Path::new(&file);
    let indirect = app_config::is_remote_target(&file) || app_config::is_shortcut(path);
    let source = match app_config::resolve_readme_candidate(path).await {
        Some(resolved) => {
            // Say which document was actually used. Without this a shortcut
            // resolving to the wrong target is invisible: the run just reports
            // an empty README with nothing to point at.
            if resolved == file {
                ui::markup_line(&format!("[dim]Using README: {}[/]", ui::escape(&resolved)));
            } else {
                ui::markup_line(&format!(
                    "[dim]Using README: {} (resolved from {})[/]",
                    ui::escape(&resolved),
                    ui::escape(&file)
                ));
            }
            resolved
        }
        // A shortcut or URL that could not be followed must not be fed to the
        // HTML parser: an INI file yields a README with no title and no
        // detectable OS, reporting "Unknown" for everything and hiding the real
        // failure.
        None if indirect => {
            ui::markup_line(&format!(
                "[red]✗ Could not obtain the README from {}[/]",
                ui::escape(&file)
            ));
            ui::markup_line(
                "[yellow]If the image has no network access, open the README in a browser, \
                 save it as HTML, and pass it with --readme <file>.[/]",
            );
            return inspection;
        }
        None => {
            ui::markup_line(&format!("[dim]Using README: {}[/]", ui::escape(&file)));
            file
        }
    };

    inspection.data = Some(readme_parser::parse_html_readme_async(&source).await);
    // The directives come from the same document the parser read, rather than
    // a second resolution of the path that might disagree about which file.
    if let Ok(html) = tokio::fs::read_to_string(&source).await {
        inspection.directives = directives::extract(&html);
    }
    inspection.source = Some(source);
    inspection
}

/// Show the round-specific instructions and record them in the ledger.
///
/// Returns false when there was no README to scan, so the caller can say so
/// rather than printing an empty report.
pub fn report_directives(inspection: &ReadmeInspection) -> bool {
    let Some(source) = &inspection.source else {
        return false;
    };
    // No directives can also mean the document could not be read at all, and
    // "nothing recognised" would then be a false all-clear.
    if inspection.directives.is_empty() && std::fs::read(source).is_err() {
        ui::markup_line(&format!(
            "[yellow]⚠ Could not re-read {} to scan for round-specific instructions.[/]",
            ui::escape(source)
        ));
        return true;
    }
    directives::display(&inspection.directives);
    directives::record(&inspection.directives);
    true
}

/// Write the run log and say where it went. Returns the error, if any.
pub fn finish_log(path: &Path) -> Option<String> {
    match run_log::write_to(path) {
        Ok(()) => {
            ui::markup_line(&format!(
                "[dim]Run log written to: {}[/]",
                ui::escape(&path.to_string_lossy())
            ));
            None
        }
        Err(e) => {
            ui::markup_line(&format!(
                "[yellow]Could not write run log to {}: {}[/]",
                ui::escape(&path.to_string_lossy()),
                ui::escape(&e.to_string())
            ));
            Some(e.to_string())
        }
    }
}

/// Run the plan against platform `P`, sending every event to `events`.
///
/// A closed receiver does not stop the run: the work and the run log matter
/// more than whoever was watching.
pub async fn run<P: Platform>(plan: RunPlan, events: UnboundedSender<RunEvent>) -> RunSummary {
    let line_events = events.clone();
    let summary = ui::stream(
        move |line| {
            let _ = line_events.send(RunEvent::Line(line));
        },
        run_inner::<P>(plan, events.clone()),
    )
    .await;
    let _ = events.send(RunEvent::Finished(summary.clone()));
    summary
}

async fn run_inner<P: Platform>(plan: RunPlan, events: UnboundedSender<RunEvent>) -> RunSummary {
    // The log and ledger are process-global; a front end that runs twice must
    // not carry the first run into the second's log. `clear` also drops the
    // dry-run flag, which is set again below before any task exists.
    run_log::clear();
    run_log::set_dry_run(plan.dry_run);
    for line in run_log::header(&plan.command_line) {
        run_log::record_raw(&line);
    }

    let asked_for_readme = !matches!(plan.readme, ReadmeChoice::None);
    let inspection = inspect_readme(&plan.readme).await;
    let _ = events.send(RunEvent::Readme(inspection.clone()));

    // Show what was extracted before acting on it. The tasks are driven by this
    // data - which users are authorised, which services are critical - so seeing
    // it first is what makes the run reviewable, and it lands in the log too.
    if let Some(data) = &inspection.data {
        readme_parser::display_parsed_data(data);
        // What this round does differently, before anything is changed. The
        // by-hand list is the part of a README a competitor most often misses,
        // and it is no use at the end of the run.
        report_directives(&inspection);
        ui::write_line();
    }

    if let Some(edited) = &plan.readme_override {
        report_hand_edits(inspection.data.as_ref(), edited);
    }
    let readme = plan.readme_override.as_ref().or(inspection.data.as_ref());

    // Selected rows in the platform's order. The ordering guarantees the run
    // depends on - the README is parsed before user management, services are
    // protected before any are disabled - are properties of the task list, not
    // of how the tasks were asked for.
    let selected: Vec<&TaskSpec> = P::tasks()
        .iter()
        .filter(|spec| match &plan.tasks {
            TaskChoice::All => true,
            TaskChoice::Flags(flags) => flags.iter().any(|flag| spec.matches(flag)),
        })
        .collect();

    // A README was asked for and could not be obtained, yet tasks are about to
    // run. Say so where it cannot be missed.
    //
    // The run continues deliberately - the tasks that need a README decline on
    // their own, and the rest apply defaults that are correct on any image. But
    // a competitor who asked for a README and did not get one has lost every
    // decision it would have driven, and the two red lines about the download
    // scroll off the top of the screen long before the run ends.
    if readme.is_none() && asked_for_readme {
        warn_running_without_readme(&selected);
    }

    // The independent audits are separated out: they touch disjoint areas and
    // share no state with each other, so they are the only tasks it is safe to
    // overlap. Everything else contends for the same accounts, services and
    // configuration, where concurrent writes would race.
    let total = selected.len();
    let mut sequential: Vec<(usize, Box<dyn Task>)> = Vec::new();
    let mut concurrent: Vec<(usize, Box<dyn Task>)> = Vec::new();
    for (index, spec) in selected.iter().enumerate() {
        let mut task = (spec.build)(readme);
        task.set_dry_run(plan.dry_run);
        match spec.concurrency {
            Concurrency::Sequential => sequential.push((index, task)),
            Concurrency::Concurrent => concurrent.push((index, task)),
        }
    }

    // Start the independent audits now so their external commands overlap the
    // sequential work below instead of adding to the total wall time. Their
    // output is captured and replayed as whole blocks once they finish, so
    // concurrent tasks do not interleave line by line.
    let audit_handles: Vec<_> = concurrent
        .into_iter()
        .map(|(index, mut task)| {
            let events = events.clone();
            tokio::spawn(async move {
                let (result, lines) = ui::capture(async {
                    started(&events, task.name(), index, total, true);
                    run_task(&mut task, &events).await
                })
                .await;
                let _ = events.send(RunEvent::TaskFinished(result.clone()));
                (result, lines)
            })
        })
        .collect();

    let mut results: Vec<TaskResult> = Vec::new();
    let mut cancelled = false;
    for (index, task) in &mut sequential {
        // Let a front end on the same thread act on the previous TaskFinished
        // before the next task starts, so a cancel pressed then takes effect.
        tokio::task::yield_now().await;
        if plan.cancel.load(Ordering::Relaxed) {
            cancelled = true;
            break;
        }
        started(&events, task.name(), *index, total, false);
        let result = run_task(task, &events).await;
        let _ = events.send(RunEvent::TaskFinished(result.clone()));
        results.push(result);
    }
    if cancelled {
        ui::write_line();
        ui::markup_line("[yellow]⚠ Run cancelled - no further tasks were started.[/]");
    }

    if !audit_handles.is_empty() {
        ui::write_line();
        ui::rule("[bold blue]Independent Audits (run concurrently)[/]");
        for handle in audit_handles {
            match handle.await {
                Ok((result, lines)) => {
                    ui::replay(&lines);
                    results.push(result);
                }
                // A panicking task must not take the run's results with it.
                Err(e) => ui::markup_line(&format!(
                    "[red]✗ An audit task failed to complete: {}[/]",
                    ui::escape(&e.to_string())
                )),
            }
        }
    }

    run_log::begin_task("(summary)");
    display_summary(&results);
    display_ledger_summary();
    ui::write_line();
    ui::rule("[bold green]✓ Automation Complete[/]");
    ui::write_line();

    run_log::append_ledger();
    append_result_details(&results);
    let fixes = run_log::fixes();
    let log_error = finish_log(&plan.log_path);

    RunSummary {
        results,
        fixes,
        log_path: plan.log_path,
        log_error,
        cancelled,
    }
}

fn started(
    events: &UnboundedSender<RunEvent>,
    name: &str,
    index: usize,
    total: usize,
    concurrent: bool,
) {
    let _ = events.send(RunEvent::TaskStarted {
        name: name.to_string(),
        index,
        total,
        concurrent,
    });
}

fn warn_running_without_readme(selected: &[&TaskSpec]) {
    let declining: Vec<&str> = selected
        .iter()
        .filter(|spec| spec.needs_readme)
        .map(|spec| spec.label)
        .collect();

    ui::write_line();
    ui::rule("[bold yellow]Running without a README[/]");
    ui::markup_line(
        "[yellow]The README could not be obtained, so nothing in it is driving this run.[/]",
    );
    if !declining.is_empty() {
        ui::markup_line(
            "[yellow]These tasks cannot tell authorised from unauthorised and will \
             decline to act:[/]",
        );
        for label in &declining {
            ui::markup_line(&format!("[yellow]    {}[/]", ui::escape(label)));
        }
    }
    ui::markup_line(
        "[dim]The remaining tasks apply defaults, which are correct on any image - but \
         anything this round does differently is lost.[/]",
    );
    ui::markup_line(
        "[dim]To fix: open the README in a browser, save it as HTML, and re-run with \
         --readme <file>.[/]",
    );
    ui::write_line();
}

/// Say that the tasks are driven by hand-edited data, and how it differs.
///
/// Without this a log reviewed after the round would show the parsed README
/// and a run that disagrees with it, with nothing to explain why.
fn report_hand_edits(parsed: Option<&ReadmeData>, edited: &ReadmeData) {
    let empty = ReadmeData::default();
    let parsed_or_empty = parsed.unwrap_or(&empty);

    ui::write_line();
    ui::rule("[bold yellow]README data edited by hand[/]");
    if parsed.is_some() {
        ui::markup_line(
            "[yellow]The tasks below use hand-edited README data, not the parse shown above.[/]",
        );
    } else {
        ui::markup_line(
            "[yellow]No README was parsed; the tasks below use hand-entered README data.[/]",
        );
    }

    let mut any = false;
    for (label, before, after) in readme_lists(parsed_or_empty)
        .into_iter()
        .zip(readme_lists(edited))
        .map(|((label, before), (_, after))| (label, before, after))
    {
        let removed: Vec<&String> = before.iter().filter(|b| !after.contains(b)).collect();
        let added: Vec<&String> = after.iter().filter(|a| !before.contains(a)).collect();
        if removed.is_empty() && added.is_empty() {
            continue;
        }
        any = true;
        ui::markup_line(&format!("[bold]{label}:[/]"));
        for line in removed {
            ui::markup_line(&format!("  [red]- {}[/]", ui::escape(line)));
        }
        for line in added {
            ui::markup_line(&format!("  [green]+ {}[/]", ui::escape(line)));
        }
    }
    if !any {
        ui::markup_line("[dim]No field differs from the parsed README.[/]");
    }
    ui::write_line();
}

/// Every field a hand edit can change, as one string per entry, so the log
/// shows each difference as a removed and an added line.
///
/// Passwords are reduced to whether one is set and a short fingerprint: a
/// README password changed by hand is worth seeing in the log, the password
/// itself is not - the log is shared and pasted into help requests.
fn readme_lists(data: &ReadmeData) -> [(&'static str, Vec<String>); 12] {
    let people = |users: &[crate::models::AuthorizedUser]| {
        users
            .iter()
            .map(|u| {
                let mut flags = Vec::new();
                if u.is_admin {
                    flags.push("admin".to_string());
                }
                if u.is_primary_user {
                    flags.push("primary".to_string());
                }
                if let Some(pw) = &u.password {
                    flags.push(format!("password #{:04x}", fingerprint(pw)));
                }
                if let Some(notes) = u.notes.as_deref().filter(|n| !n.is_empty()) {
                    flags.push(format!("notes: {notes}"));
                }
                if flags.is_empty() {
                    u.username.clone()
                } else {
                    format!("{} ({})", u.username, flags.join(", "))
                }
            })
            .collect::<Vec<_>>()
    };
    let single = |s: &str| {
        if s.is_empty() {
            Vec::new()
        } else {
            vec![s.to_string()]
        }
    };
    [
        ("Title", single(&data.title)),
        ("Operating system", single(&data.operating_system)),
        ("Scenario", single(&data.scenario)),
        ("Administrators", people(&data.administrators)),
        ("Users", people(&data.users)),
        (
            "Groups",
            data.group_requirements
                .iter()
                .map(|g| format!("{}: {}", g.group_name, g.members.join(", ")))
                .collect(),
        ),
        ("Users to create", data.users_to_create.clone()),
        ("Critical services", data.critical_services.clone()),
        ("Prohibited services", data.prohibited_services.clone()),
        (
            "Required software",
            data.required_software
                .iter()
                .map(|s| {
                    let mut text = s.name.clone();
                    if let Some(v) = s.version.as_deref().filter(|v| !v.is_empty()) {
                        text.push_str(&format!(" {v}"));
                    }
                    if s.should_be_latest {
                        text.push_str(" (latest)");
                    }
                    if !s.is_required {
                        text.push_str(" (optional)");
                    }
                    if let Some(n) = s.notes.as_deref().filter(|n| !n.is_empty()) {
                        text.push_str(&format!(" - {n}"));
                    }
                    text
                })
                .collect(),
        ),
        ("Prohibited software", data.prohibited_software.clone()),
        ("Guidelines", data.guidelines.clone()),
    ]
}

/// A short, stable, non-reversible tag for a password in the log.
fn fingerprint(secret: &str) -> u16 {
    // FNV-1a folded to 16 bits: enough to see that two runs used the same or a
    // different password, far too little to recover or brute-force it from.
    let mut hash: u32 = 0x811c_9dc5;
    for b in secret.bytes() {
        hash ^= u32::from(b);
        hash = hash.wrapping_mul(0x0100_0193);
    }
    ((hash >> 16) ^ (hash & 0xffff)) as u16
}

/// Read state, remediate, then verify - the pipeline every task follows.
///
/// The whole pipeline is scoped to the task's name so every change the `*_ops`
/// modules record underneath it is attributed correctly, including for the
/// audits that run concurrently.
async fn run_task(task: &mut Box<dyn Task>, events: &UnboundedSender<RunEvent>) -> TaskResult {
    let name = task.name().to_string();
    run_log::in_task(&name, run_task_inner(task, &name, events)).await
}

async fn run_task_inner(
    task: &mut Box<dyn Task>,
    name: &str,
    events: &UnboundedSender<RunEvent>,
) -> TaskResult {
    let phase = |phase: Phase| {
        let _ = events.send(RunEvent::TaskPhase {
            name: name.to_string(),
            phase,
        });
    };

    ui::write_line();
    ui::rule(&format!("[bold blue]{}[/]", ui::escape(name)));
    ui::write_line();

    ui::markup_line("[cyan]📊 Reading current system state...[/]");
    phase(Phase::Reading);
    task.read_system_state().await;
    ui::markup_line("[green]✓ System state captured[/]");
    ui::write_line();

    ui::markup_line("[yellow]🔧 Applying security fixes...[/]");
    phase(Phase::Executing);
    let mut result = task.execute().await;
    if result.success {
        ui::markup_line(&format!("[green]✓ {}[/]", ui::escape(&result.message)));
    } else {
        ui::markup_line(&format!("[red]✗ {}[/]", ui::escape(&result.message)));
    }
    ui::write_line();

    ui::markup_line("[magenta]🔍 Verifying applied changes...[/]");
    phase(Phase::Verifying);
    let verified = task.verify().await;
    result.verified = verified;
    if !verified {
        result.confidence_percent = (result.confidence_percent - 30).max(50);
        ui::markup_line("[yellow]⚠ Some changes may need manual verification[/]");
    } else {
        ui::markup_line("[green]✓ All changes verified successfully[/]");
    }
    ui::write_line();

    result
}

/// Append a structured, per-task record to the log.
///
/// The narrative above it says what happened as it happened; this block makes
/// the outcome of each task greppable without reading the whole run.
fn append_result_details(results: &[TaskResult]) {
    run_log::record_raw("");
    run_log::record_raw(&"=".repeat(79));
    run_log::record_raw("TASK RESULTS");
    run_log::record_raw(&"=".repeat(79));

    for result in results {
        run_log::record_raw("");
        run_log::record_raw(&format!("Task:      {}", result.task_name));
        run_log::record_raw(&format!(
            "Outcome:   {}",
            if result.success { "SUCCESS" } else { "FAILED" }
        ));
        run_log::record_raw(&format!(
            "Verified:  {}",
            if result.verified { "yes" } else { "no" }
        ));
        run_log::record_raw(&format!(
            "Items:     {} attempted, {} succeeded, {} skipped",
            result.items_attempted, result.items_succeeded, result.items_skipped
        ));
        run_log::record_raw(&format!("Confidence: {}%", result.confidence_percent));
        for line in result.message.lines() {
            run_log::record_raw(&format!("           {line}"));
        }
        if let Some(details) = &result.error_details {
            run_log::record_raw("Issues:");
            for line in details.lines() {
                run_log::record_raw(&format!("  - {line}"));
            }
        }
    }
}

fn display_summary(results: &[TaskResult]) {
    ui::write_line();
    ui::rule("[bold blue]Summary[/]");
    ui::write_line();

    let mut table = ui::TableBuilder::new().columns(&[
        "[bold]Task[/]",
        "[bold]Status[/]",
        "[bold]Completion[/]",
        "[bold]Confidence[/]",
        "[bold]Message[/]",
        "[bold]Time[/]",
    ]);

    for result in results {
        let status = if result.success {
            "[green]✓ Success[/]"
        } else {
            "[red]✗ Failed[/]"
        };
        let completion_rate = result.completion_rate();
        let completion_color = if completion_rate >= 90.0 {
            "green"
        } else if completion_rate >= 70.0 {
            "yellow"
        } else {
            "red"
        };
        let confidence_color = if result.confidence_percent >= 90 {
            "green"
        } else if result.confidence_percent >= 70 {
            "yellow"
        } else {
            "red"
        };

        table.add_row([
            format!("[bold]{}[/]", ui::escape(&result.task_name)),
            status.to_string(),
            format!("[{completion_color}]{completion_rate:.1}%[/]"),
            format!("[{confidence_color}]{}%[/]", result.confidence_percent),
            ui::escape(&result.message),
            format!("[dim]{}[/]", result.executed_at.format("%H:%M:%S")),
        ]);

        if let Some(details) = &result.error_details
            && !details.is_empty()
        {
            table.add_row([
                String::new(),
                String::new(),
                String::new(),
                String::new(),
                format!("[dim italic]{}[/]", ui::escape(details)),
                String::new(),
            ]);
        }
    }

    table.print();
    ui::write_line();

    display_overall_statistics(results);
}

/// Show what the run actually changed, and how much of it was confirmed.
///
/// The task summary above answers "did each task run"; this answers "what is
/// different about this machine now, and how do we know". The two disagree more
/// often than is comfortable - a task that reports success while every change it
/// made reads back unverified is exactly the case worth surfacing before the
/// round ends, so anything not confirmed is listed by name.
fn display_ledger_summary() {
    let fixes = run_log::fixes();
    if fixes.is_empty() {
        return;
    }

    ui::write_line();
    ui::rule("[bold blue]Changes and Proof[/]");
    ui::write_line();

    let count = |outcome: FixOutcome| {
        fixes
            .iter()
            .filter(|f| f.outcome == outcome)
            .count()
            .to_string()
    };

    let mut table = ui::TableBuilder::new().columns(&[
        "[bold]Outcome[/]",
        "[bold]Count[/]",
        "[bold]Meaning[/]",
    ]);

    for (label, outcome, meaning) in [
        (
            "[green]Fixed[/]",
            FixOutcome::Fixed,
            "changed, and reading it back confirms it",
        ),
        (
            "[green]Already OK[/]",
            FixOutcome::AlreadyCompliant,
            "nothing to do; the machine was already right",
        ),
        (
            "[red]Failed[/]",
            FixOutcome::Failed,
            "attempted and did not take",
        ),
        (
            "[yellow]Unverified[/]",
            FixOutcome::Unverified,
            "the write reported success but could not be confirmed",
        ),
        ("[dim]Skipped[/]", FixOutcome::Skipped, "not attempted"),
    ] {
        table.add_row([
            label.to_string(),
            count(outcome),
            format!("[dim]{meaning}[/]"),
        ]);
    }

    table.print();

    let needs_attention: Vec<_> = fixes
        .iter()
        .filter(|f| matches!(f.outcome, FixOutcome::Failed | FixOutcome::Unverified))
        .collect();

    if !needs_attention.is_empty() {
        ui::write_line();
        ui::markup_line("[yellow]Not confirmed - check these by hand:[/]");
        for fix in needs_attention {
            ui::markup_line(&format!(
                "  [dim]{:<10}[/] {} [dim]- {}[/]",
                fix.outcome.tag(),
                ui::escape(&fix.target),
                ui::escape(&fix.evidence)
            ));
        }
    }

    ui::write_line();
    ui::markup_line(
        "[dim]Every change, with what it wanted and the read-back that proves it, \
         is in the run log.[/]",
    );
}

fn display_overall_statistics(results: &[TaskResult]) {
    if results.is_empty() {
        return;
    }

    let success_count = results.iter().filter(|r| r.success).count();
    let verified_count = results.iter().filter(|r| r.verified).count();

    let total_attempted: i32 = results.iter().map(|r| r.items_attempted).sum();
    let total_succeeded: i32 = results.iter().map(|r| r.items_succeeded).sum();
    let total_skipped: i32 = results.iter().map(|r| r.items_skipped).sum();

    // With no per-item counts reported, fall back to the share of tasks that
    // succeeded. The previous flat 100% meant the headline "Overall Completion
    // Rate" always read 100%, however many tasks had failed.
    let overall_completion_rate = if total_attempted > 0 {
        (total_succeeded + total_skipped) as f64 / total_attempted as f64 * 100.0
    } else {
        success_count as f64 / results.len() as f64 * 100.0
    };

    let mut overall_confidence = if total_attempted > 0 {
        results
            .iter()
            .map(|r| r.confidence_percent * r.items_attempted)
            .sum::<i32>() as f64
            / total_attempted as f64
    } else {
        results.iter().map(|r| r.confidence_percent).sum::<i32>() as f64 / results.len() as f64
    };

    let verification_bonus = verified_count as f64 / results.len() as f64;
    overall_confidence = (overall_confidence * (0.7 + 0.3 * verification_bonus)).min(100.0);

    ui::rule("[bold cyan]Overall Statistics[/]");
    ui::write_line();

    ui::markup_line(&format!(
        "[bold]Tasks:[/] {}/{} passed    [bold]Verified:[/] {}/{}    [bold]Items:[/] {}/{}    [bold]Skipped:[/] {}",
        success_count,
        results.len(),
        verified_count,
        results.len(),
        total_succeeded + total_skipped,
        total_attempted,
        total_skipped
    ));
    ui::write_line();

    let completion_color = bar_color(overall_completion_rate);
    ui::bar_chart(
        "[bold]Completion Rate[/]",
        &[
            (
                "Completed".to_string(),
                overall_completion_rate,
                completion_color,
            ),
            (
                "Remaining".to_string(),
                100.0 - overall_completion_rate,
                BarColor::Grey,
            ),
        ],
    );
    ui::write_line();

    let confidence_color = bar_color(overall_confidence);
    ui::bar_chart(
        "[bold]Confidence Level[/]",
        &[
            (
                "Confident".to_string(),
                overall_confidence,
                confidence_color,
            ),
            (
                "Uncertain".to_string(),
                100.0 - overall_confidence,
                BarColor::Grey,
            ),
        ],
    );
    ui::write_line();

    let completion_emoji = if overall_completion_rate >= 90.0 {
        "🎉"
    } else if overall_completion_rate >= 70.0 {
        "👍"
    } else {
        "⚠️"
    };
    let confidence_emoji = if overall_confidence >= 90.0 {
        "✅"
    } else if overall_confidence >= 70.0 {
        "🔶"
    } else {
        "❌"
    };

    let completion_word = if overall_completion_rate >= 90.0 {
        "green"
    } else if overall_completion_rate >= 70.0 {
        "yellow"
    } else {
        "red"
    };
    let confidence_word = if overall_confidence >= 90.0 {
        "green"
    } else if overall_confidence >= 70.0 {
        "yellow"
    } else {
        "red"
    };

    ui::markup_line(&format!(
        "{completion_emoji} [bold]Overall Completion Rate:[/] [{completion_word}]{overall_completion_rate:.1}%[/]"
    ));
    ui::markup_line(&format!(
        "{confidence_emoji} [bold]Overall Confidence Level:[/] [{confidence_word}]{overall_confidence:.1}%[/]"
    ));

    if overall_confidence < 90.0 {
        ui::write_line();
        ui::markup_line(
            "[dim italic]💡 Tip: Manual verification recommended for tasks with low confidence.[/]",
        );
    }
}

fn bar_color(value: f64) -> BarColor {
    if value >= 90.0 {
        BarColor::Green
    } else if value >= 70.0 {
        BarColor::Yellow
    } else {
        BarColor::Red
    }
}

#[cfg(test)]
// The run log is process-global, so each test holds its gate across the run.
// `#[tokio::test]` drives its own current-thread runtime, and a test blocked on
// the gate is blocking an OS thread, not starving a runtime that holds it.
#[allow(clippy::await_holding_lock)]
mod tests {
    use super::*;
    use crate::impl_task_meta;
    use crate::models::{AuthorizedUser, SystemInfo};
    use async_trait::async_trait;
    use std::sync::Mutex;
    use tokio::sync::mpsc;

    /// The administrators each built task was handed, so a test can see what
    /// reached the factory.
    static BUILT_WITH: Mutex<Vec<Vec<String>>> = Mutex::new(Vec::new());

    struct FakeTask {
        name: String,
        description: String,
        dry_run: bool,
    }

    impl FakeTask {
        fn boxed(name: &str, readme: Option<&ReadmeData>) -> Box<dyn Task> {
            BUILT_WITH.lock().unwrap().push(
                readme
                    .map(|r| {
                        r.administrators
                            .iter()
                            .map(|a| a.username.clone())
                            .collect()
                    })
                    .unwrap_or_default(),
            );
            Box::new(Self {
                name: name.to_string(),
                description: String::new(),
                dry_run: false,
            })
        }
    }

    #[async_trait]
    impl Task for FakeTask {
        impl_task_meta!();

        async fn read_system_state(&mut self) -> SystemInfo {
            ui::markup_line(&format!("reading {}", self.name));
            SystemInfo::new()
        }

        async fn execute(&mut self) -> TaskResult {
            TaskResult {
                task_name: self.name.clone(),
                success: true,
                message: format!("{} done", self.name),
                ..Default::default()
            }
        }

        async fn verify(&mut self) -> bool {
            true
        }
    }

    fn spec(flag: &'static str, build: crate::TaskFactory) -> TaskSpec {
        TaskSpec {
            flag,
            short: "",
            help: "",
            label: flag,
            detail: "",
            needs_readme: false,
            concurrency: Concurrency::Sequential,
            build,
        }
    }

    struct Fake;

    impl Platform for Fake {
        const NAME: &'static str = "Fake";
        const PRIVILEGED_ROLE: &'static str = "nobody";
        const ELEVATION_HINT: &'static str = "";

        fn tasks() -> &'static [TaskSpec] {
            static TASKS: std::sync::OnceLock<Vec<TaskSpec>> = std::sync::OnceLock::new();
            TASKS.get_or_init(|| {
                vec![
                    spec("--first", |r| FakeTask::boxed("First", r)),
                    spec("--second", |r| FakeTask::boxed("Second", r)),
                    spec("--unused", |r| FakeTask::boxed("Unused", r)),
                ]
            })
        }

        fn is_privileged() -> bool {
            false
        }
    }

    fn plan(name: &str) -> RunPlan {
        RunPlan {
            readme: ReadmeChoice::None,
            readme_override: None,
            // Given out of order: the platform's list decides the run order.
            tasks: TaskChoice::Flags(vec!["--second".into(), "--first".into()]),
            dry_run: true,
            log_path: std::env::temp_dir()
                .join(format!("pcp_engine_{name}_{}.txt", std::process::id())),
            command_line: "test".into(),
            cancel: Arc::new(AtomicBool::new(false)),
        }
    }

    /// Everything but the lines, as short labels.
    fn shape(events: &[RunEvent]) -> Vec<String> {
        events
            .iter()
            .filter_map(|event| match event {
                RunEvent::Line(_) => None,
                RunEvent::Readme(_) => Some("readme".to_string()),
                RunEvent::TaskStarted {
                    name, index, total, ..
                } => Some(format!("start {name} {index}/{total}")),
                RunEvent::TaskPhase { name, phase } => Some(format!("{phase:?} {name}")),
                RunEvent::TaskFinished(result) => Some(format!("finish {}", result.task_name)),
                RunEvent::Finished(_) => Some("finished".to_string()),
            })
            .collect()
    }

    async fn collect(mut receiver: mpsc::UnboundedReceiver<RunEvent>) -> Vec<RunEvent> {
        let mut events = Vec::new();
        while let Some(event) = receiver.recv().await {
            events.push(event);
        }
        events
    }

    #[tokio::test]
    async fn a_two_task_plan_reports_each_task_in_list_order_then_finishes() {
        let _gate = run_log::test_gate();
        let _dry_run = run_log::dry_run_for_test();
        let plan = plan("order");
        let log_path = plan.log_path.clone();

        let (sender, receiver) = mpsc::unbounded_channel();
        let (summary, events) = tokio::join!(run::<Fake>(plan, sender), collect(receiver));

        assert_eq!(
            shape(&events),
            [
                "readme",
                "start First 0/2",
                "Reading First",
                "Executing First",
                "Verifying First",
                "finish First",
                "start Second 1/2",
                "Reading Second",
                "Executing Second",
                "Verifying Second",
                "finish Second",
                "finished",
            ]
        );
        // The task's own output arrives as a line inside its reading phase.
        let reading_first = events
            .iter()
            .position(|e| {
                matches!(e, RunEvent::TaskPhase { name, phase: Phase::Reading } if name == "First")
            })
            .unwrap();
        assert!(matches!(
            &events[reading_first + 1],
            RunEvent::Line(ui::Line::Markup(text)) if text == "reading First"
        ));
        assert!(!summary.cancelled);
        assert_eq!(summary.results.len(), 2);
        assert_eq!(summary.log_error, None);

        let log = std::fs::read_to_string(&log_path).unwrap();
        // Recorded once, at emission - not again by whoever displayed it.
        assert_eq!(log.matches("reading First").count(), 1, "{log}");
        assert!(log.contains("TASK RESULTS"), "{log}");
        let _ = std::fs::remove_file(&log_path);
    }

    #[tokio::test]
    async fn cancel_after_the_first_task_stops_the_second_and_still_writes_the_log() {
        let _gate = run_log::test_gate();
        let _dry_run = run_log::dry_run_for_test();
        let plan = plan("cancel");
        let log_path = plan.log_path.clone();
        let cancel = plan.cancel.clone();

        let (sender, mut receiver) = mpsc::unbounded_channel();
        let engine = tokio::spawn(run::<Fake>(plan, sender));
        let mut events = Vec::new();
        while let Some(event) = receiver.recv().await {
            if matches!(event, RunEvent::TaskFinished(_)) {
                cancel.store(true, Ordering::Relaxed);
            }
            events.push(event);
        }
        let summary = engine.await.unwrap();

        assert!(summary.cancelled);
        assert_eq!(summary.results.len(), 1);
        let shape = shape(&events);
        assert!(!shape.iter().any(|e| e.contains("Second")), "{shape:?}");
        assert_eq!(shape.last().map(String::as_str), Some("finished"));
        let log = std::fs::read_to_string(&log_path).unwrap();
        assert!(log.contains("Run cancelled"), "{log}");
        assert!(log.contains("TASK RESULTS"), "{log}");
        let _ = std::fs::remove_file(&log_path);
    }

    #[test]
    fn every_editable_field_is_compared_and_passwords_never_logged() {
        let user = |name: &str, pw: Option<&str>| crate::models::AuthorizedUser {
            username: name.to_string(),
            password: pw.map(str::to_string),
            ..Default::default()
        };
        let before = ReadmeData {
            title: "Round".to_string(),
            users: vec![user("ann", Some("Secret-1"))],
            ..Default::default()
        };
        let after = ReadmeData {
            title: "Round 2".to_string(),
            scenario: "New scenario".to_string(),
            users: vec![user("ann", Some("Secret-2"))],
            prohibited_services: vec!["telnet".to_string()],
            guidelines: vec!["Do not change the clock".to_string()],
            ..Default::default()
        };
        let (b, a) = (readme_lists(&before), readme_lists(&after));
        let changed: Vec<&str> = b
            .iter()
            .zip(&a)
            .filter(|((_, x), (_, y))| x != y)
            .map(|((label, _), _)| *label)
            .collect();
        assert_eq!(
            changed,
            [
                "Title",
                "Scenario",
                "Users",
                "Prohibited services",
                "Guidelines"
            ]
        );
        let all: String = a.iter().flat_map(|(_, v)| v.clone()).collect();
        assert!(!all.contains("Secret"), "a password reached the log: {all}");
    }

    #[tokio::test]
    async fn a_readme_override_reaches_the_tasks_and_is_logged_as_a_hand_edit() {
        let _gate = run_log::test_gate();
        let _dry_run = run_log::dry_run_for_test();
        BUILT_WITH.lock().unwrap().clear();
        let mut plan = plan("override");
        let log_path = plan.log_path.clone();
        plan.readme_override = Some(ReadmeData {
            administrators: vec![AuthorizedUser {
                username: "alice".into(),
                ..Default::default()
            }],
            critical_services: vec!["ssh".into()],
            ..Default::default()
        });

        let (sender, receiver) = mpsc::unbounded_channel();
        tokio::join!(run::<Fake>(plan, sender), collect(receiver));

        assert_eq!(
            *BUILT_WITH.lock().unwrap(),
            [vec!["alice".to_string()], vec!["alice".to_string()]]
        );
        let log = std::fs::read_to_string(&log_path).unwrap();
        assert!(log.contains("=== README data edited by hand ==="), "{log}");
        assert!(log.contains("Administrators:"), "{log}");
        assert!(log.contains("+ alice"), "{log}");
        assert!(log.contains("+ ssh"), "{log}");
        let _ = std::fs::remove_file(&log_path);
    }
}
