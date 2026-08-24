// =============================================================================
// PinnacleCyPat (Rust port) - Entry point
// Author: Maxwell McCormick
// Copyright 2026 Maxwell McCormick
// SPDX-License-Identifier: Apache-2.0
// =============================================================================

use std::future::Future;
use std::time::Duration;

use indicatif::{ProgressBar, ProgressStyle};
use pinnacle_core::app_config;
use pinnacle_core::directives;
use pinnacle_core::models::{FixOutcome, ReadmeData, TaskResult};
use pinnacle_core::platform::{Concurrency, Platform, TaskSpec};
use pinnacle_core::readme_parser;
use pinnacle_core::run_log;
use pinnacle_core::task::Task;
use pinnacle_core::ui::{self, BarColor};

mod tui;

// The platform this binary was built for. Everything below is written against
// `Host::tasks()` and knows nothing else about the operating system - which is
// what lets one pipeline, one argument parser and one menu serve both.
#[cfg(target_os = "linux")]
use pinnacle_linux::Linux as Host;
#[cfg(windows)]
use pinnacle_windows::Windows as Host;

#[cfg(not(any(windows, target_os = "linux")))]
compile_error!(
    "PinnacleCyPat has no task set for this operating system. \
     Add a crate implementing `pinnacle_core::platform::Platform` and wire it up here."
);

#[tokio::main]
async fn main() {
    // Before any output: a Windows console ignores ANSI sequences until the
    // virtual-terminal flag is set.
    ui::init();
    run_automation().await;
}

/// Extract the value that follows one of the given flags.
fn extract_argument(args: &[String], flags: &[&str]) -> Option<String> {
    for i in 0..args.len() {
        if flags.contains(&args[i].as_str()) && i + 1 < args.len() {
            return Some(args[i + 1].clone());
        }
    }
    None
}

fn has_flag(args: &[String], flags: &[&str]) -> bool {
    args.iter().any(|a| flags.contains(&a.as_str()))
}

/// Every flag that is not a task, with the description shown by `--help`.
///
/// The task flags are not listed here: they come from `Host::tasks()`, so a
/// task cannot be accepted without also being documented and offered in the
/// menu. This table covers only what is true on every platform.
const GLOBAL_FLAGS: &[(&str, &str, &str)] = &[
    ("--help", "-h", "Show this help and exit"),
    ("--tui", "-i", "Open the interactive menu"),
    (
        "--version",
        "-V",
        "Print the version and build date, then exit",
    ),
    (
        "--readme <path>",
        "-r",
        "Read the competition README at <path>",
    ),
    ("--auto-readme", "-R", "Find the README automatically"),
    (
        "--parse-readme",
        "",
        "Show what the parser extracted, then exit (read-only)",
    ),
    (
        "--directives",
        "",
        "Show what this round does differently, then exit (read-only)",
    ),
    (
        "--dry-run",
        "-d",
        "Report what would change without changing it",
    ),
    (
        "--all",
        "",
        "Run every task (the default when no task is named)",
    ),
    ("--log <path>", "", "Write the run log to <path>"),
];

/// Flags that consume the following argument as their value.
const VALUE_FLAGS: &[&str] = &["--readme", "-r", "--log"];

/// The first argument that is not a flag this tool accepts, if any.
fn first_unknown_argument(args: &[String]) -> Option<String> {
    let mut known: Vec<&str> = Vec::new();
    for (long, short, _) in GLOBAL_FLAGS {
        // The table spells value-taking flags as "--readme <path>".
        known.push(long.split(' ').next().unwrap_or(long));
        if !short.is_empty() {
            known.push(short);
        }
    }
    for spec in Host::tasks() {
        known.push(spec.flag);
        if !spec.short.is_empty() {
            known.push(spec.short);
        }
    }
    // Accepted as help but deliberately absent from the table, which lists one
    // spelling per flag.
    known.extend_from_slice(&["-?", "/?"]);

    let mut skip_next = false;
    for arg in args {
        if skip_next {
            skip_next = false;
            continue;
        }
        if VALUE_FLAGS.contains(&arg.as_str()) {
            skip_next = true;
            continue;
        }
        if !known.contains(&arg.as_str()) {
            return Some(arg.clone());
        }
    }
    None
}

/// How a flag is written in the help listing: `-p, --password-policy`, or just
/// the long form when there is no short one.
fn spelling(long: &str, short: &str) -> String {
    if short.is_empty() {
        format!("    {long}")
    } else {
        format!("    {short}, {long}")
    }
}

fn print_help() {
    println!("PinnacleCyPat {}\n", app_config::version_string());
    println!("USAGE:");
    println!("    pinnacle-cypat [OPTIONS]\n");
    println!(
        "Run as {}. Name a task, or pass --all to run every task.",
        Host::PRIVILEGED_ROLE
    );
    println!("Pass --dry-run first to see what would change.");
    println!("Not sure? Run --tui for a guided menu.\n");
    println!("OPTIONS:");
    for (long, short, description) in GLOBAL_FLAGS {
        println!("{:<34}{description}", spelling(long, short));
    }
    println!("\n{} TASKS:", Host::NAME.to_uppercase());
    for spec in Host::tasks() {
        println!("{:<34}{}", spelling(spec.flag, spec.short), spec.help);
    }
    println!("\nEXAMPLES:");
    println!("    pinnacle-cypat --tui                          # guided menu");
    println!("    pinnacle-cypat --auto-readme --parse-readme   # read-only");
    println!("    pinnacle-cypat --auto-readme --all --dry-run  # preview");
    println!("    pinnacle-cypat --auto-readme --all            # apply");
}

/// Scan the README for round-specific instructions, show them, and record them.
///
/// Returns false when there was no README to scan, so the caller can say so
/// rather than printing an empty report.
async fn report_directives(path: Option<&str>) -> bool {
    let Some(path) = path else {
        return false;
    };
    let Ok(html) = tokio::fs::read_to_string(path).await else {
        // The parser already read this file successfully, so a failure here is
        // odd enough to mention rather than swallow.
        ui::markup_line(&format!(
            "[yellow]⚠ Could not re-read {} to scan for round-specific instructions.[/]",
            ui::escape(path)
        ));
        return true;
    };
    let found = directives::extract(&html);
    directives::display(&found);
    directives::record(&found);
    true
}

async fn with_spinner<T, F: Future<Output = T>>(message: &str, fut: F) -> T {
    let pb = ProgressBar::new_spinner();
    pb.enable_steady_tick(Duration::from_millis(100));
    pb.set_style(ProgressStyle::with_template("{spinner:.cyan} {msg}").unwrap());
    pb.set_message(message.to_string());
    let result = fut.await;
    pb.finish_and_clear();
    result
}

async fn run_automation() {
    let cli_args: Vec<String> = std::env::args().skip(1).collect();

    // Help before anything else, and before the run log opens.
    if has_flag(&cli_args, &["--help", "-h", "-?", "/?"]) {
        print_help();
        return;
    }

    // The interactive menu, either asked for or offered.
    //
    // A bare launch - which is what double-clicking the executable does - has
    // nothing to act on, and printing help at someone who cannot see a command
    // line does not help them. The menu is offered instead, but only with a
    // human at a terminal: redirected streams mean a script or a pipe, where a
    // prompt would wait forever for an answer that never comes. Whatever the
    // menu returns is a command line, so everything below is unchanged by it.
    let mut cli_args = cli_args;
    if has_flag(&cli_args, &["--tui", "-i"])
        || (cli_args.is_empty() && tui::is_interactive_console())
    {
        match tui::build_arguments() {
            Some(chosen) => cli_args = chosen,
            None => return,
        }
    }

    // Reject anything unrecognised rather than letting it fall through.
    //
    // Every flag used to be matched by name and anything else ignored, while
    // "no task flag given" meant "run everything" - so a typo, or `--help`
    // itself, silently began a full destructive run instead of doing nothing.
    if let Some(unknown) = first_unknown_argument(&cli_args) {
        ui::markup_line(&format!(
            "[red]Unrecognised argument: {}[/]",
            ui::escape(&unknown)
        ));
        ui::markup_line("[dim]Run with --help to see the available options.[/]");
        std::process::exit(2);
    }

    // Answer "which build is this?" without needing a log or a file listing.
    if has_flag(&cli_args, &["--version", "-V"]) {
        println!("PinnacleCyPat {}", app_config::version_string());
        return;
    }

    for line in run_log::header(&cli_args.join(" ")) {
        run_log::record_raw(&line);
    }

    let mut readme_file = extract_argument(&cli_args, &["--readme", "-r"]);
    let auto_find_readme = has_flag(&cli_args, &["--auto-readme", "-R"]);
    let dry_run = has_flag(&cli_args, &["--dry-run", "-d"]);

    // Which tasks were named, in the order a run executes them rather than the
    // order they were typed. The ordering guarantees the run depends on - the
    // README is parsed before user management, services are protected before
    // any are disabled, software management comes after the work it contends
    // with - are properties of the platform's task list, not of the command
    // line, so reading the list is what preserves them.
    let named: Vec<&TaskSpec> = Host::tasks()
        .iter()
        .filter(|spec| cli_args.iter().any(|arg| spec.matches(arg)))
        .collect();

    let parse_readme_only = has_flag(&cli_args, &["--parse-readme"]);
    let directives_only = has_flag(&cli_args, &["--directives"]);

    // Where to write the run log; `--log <path>` overrides the default.
    let log_path = extract_argument(&cli_args, &["--log"])
        .map(std::path::PathBuf::from)
        .unwrap_or_else(run_log::default_log_path);

    let any_task_named = !named.is_empty() || parse_readme_only || directives_only;

    // Running everything has to be asked for.
    //
    // "No task flag given" used to mean "run every task", so simply launching
    // the executable - by double-clicking it, or to see what it does - began a
    // full destructive run against the machine. Nothing about a bare invocation
    // says "change this system", so it now prints the help and stops.
    let run_all = has_flag(&cli_args, &["--all"]);
    if !run_all && !any_task_named {
        print_help();
        ui::markup_line(
            "\n[yellow]No task selected. Pass --all to run every task, or name individual tasks.[/]",
        );
        ui::markup_line("[dim]Pass --dry-run first to preview the changes.[/]");
        return;
    }

    // Auto-find the README if requested and none supplied.
    let mut discovery_attempts: Vec<String> = Vec::new();
    if readme_file.is_none() && auto_find_readme {
        readme_file = app_config::find_readme_file_reporting(&mut discovery_attempts).await;
    }

    // Parse README if needed.
    //
    // An explicitly supplied path is resolved the same way an auto-discovered
    // one is: the documented location on a competition image is
    // `C:\CyberPatriot\README.url`, so `--readme` pointing at a `.url` (or a
    // `.lnk`) has to follow the shortcut rather than parse the shortcut file
    // itself as HTML. If it does not resolve, the original path is kept so the
    // parser reports "not found" against what the user actually typed.
    let mut readme_data: Option<ReadmeData> = None;
    // The document the parser actually read, kept so the directive scan works
    // on the same bytes rather than re-resolving the path and possibly
    // disagreeing about which file was used.
    let mut readme_source: Option<String> = None;
    if let Some(file) = &readme_file {
        if !file.is_empty() {
            let path = std::path::Path::new(file);
            let indirect = app_config::is_remote_target(file) || app_config::is_shortcut(path);

            match app_config::resolve_readme_candidate(path).await {
                Some(resolved) => {
                    // Say which document was actually used. Without this a
                    // shortcut resolving to the wrong target is invisible: the
                    // run just reports an empty README with nothing to point at.
                    if resolved == *file {
                        ui::markup_line(&format!(
                            "[dim]Using README: {}[/]",
                            ui::escape(&resolved)
                        ));
                    } else {
                        ui::markup_line(&format!(
                            "[dim]Using README: {} (resolved from {})[/]",
                            ui::escape(&resolved),
                            ui::escape(file)
                        ));
                    }
                    readme_data = Some(readme_parser::parse_html_readme_async(&resolved).await);
                    readme_source = Some(resolved);
                }
                // A shortcut or URL that could not be followed must not be fed
                // to the HTML parser: an INI file yields a README with no title
                // and no detectable OS, reporting "Unknown" for everything and
                // hiding the real failure.
                None if indirect => {
                    ui::markup_line(&format!(
                        "[red]✗ Could not obtain the README from {}[/]",
                        ui::escape(file)
                    ));
                    ui::markup_line(
                        "[yellow]If the image has no network access, open the README in a browser, \
                         save it as HTML, and pass it with --readme <file>.[/]",
                    );
                }
                None => {
                    // A plain path that does not exist: let the parser report
                    // "not found" against exactly what was typed.
                    ui::markup_line(&format!("[dim]Using README: {}[/]", ui::escape(file)));
                    readme_data = Some(readme_parser::parse_html_readme_async(file).await);
                    readme_source = Some(file.clone());
                }
            }
        }
    } else if auto_find_readme {
        ui::markup_line(
            "[yellow]⚠ No README found automatically. Pass --readme <file> to specify one.[/]",
        );
        // Show where it looked, so a candidate that exists but cannot be
        // followed is visible rather than silently skipped.
        ui::markup_line("[dim]Locations checked:[/]");
        for attempt in &discovery_attempts {
            ui::markup_line(&format!("[dim]  - {}[/]", ui::escape(attempt)));
        }
    }

    // Directives-only mode: report what this round does differently, and stop.
    //
    // Separate from --parse-readme because they answer different questions.
    // That one asks "what did the parser get out of this document"; this one
    // asks "what about this round is not the standard checklist", which is the
    // question a competitor has ninety seconds to answer at the start.
    if directives_only {
        match report_directives(readme_source.as_deref()).await {
            true => {}
            false => ui::markup_line(
                "[yellow]No README file specified. Use --readme <file> or --auto-readme.[/]",
            ),
        }
        ui::write_line();
        finish_log(&log_path);
        return;
    }

    // Parse-only mode: display the parsed data and stop.
    if parse_readme_only {
        if let Some(data) = &readme_data {
            readme_parser::display_parsed_data(data);
            report_directives(readme_source.as_deref()).await;
        } else {
            ui::markup_line(
                "[yellow]No README file specified. Use --readme <file> to parse one.[/]",
            );
        }
        // `--parse-readme` is a report, not a run. Combining it with task flags
        // silently did nothing, which reads as the tasks having been skipped for
        // some other reason.
        if run_all || !named.is_empty() {
            ui::write_line();
            ui::markup_line(
                "[yellow]Note: --parse-readme only reports the README; no tasks were run.[/]",
            );
            ui::markup_line(
                "[yellow]Drop --parse-readme to apply them - the README is displayed either way.[/]",
            );
        }
        finish_log(&log_path);
        return;
    }

    // Show what was extracted before acting on it. The tasks are driven by this
    // data - which users are authorised, which services are critical - so seeing
    // it first is what makes the run reviewable, and it lands in the log too.
    if let Some(data) = &readme_data {
        readme_parser::display_parsed_data(data);
        // What this round does differently, before anything is changed. The
        // by-hand list is the part of a README a competitor most often misses,
        // and it is no use at the end of the run.
        report_directives(readme_source.as_deref()).await;
        ui::write_line();
    }

    // Build the task list from the platform's own table.
    //
    // The task, its flag, its help line and its menu entry all come from one
    // row there, so this block cannot fall out of step with the argument parser
    // or the menu the way three hand-maintained lists did.
    //
    // The independent audits are separated out here: they touch disjoint areas
    // and share no state with each other, so they are the only tasks it is safe
    // to overlap. Everything else contends for the same accounts, services and
    // configuration, where concurrent writes would race.
    let readme = readme_data.as_ref();
    let mut tasks: Vec<Box<dyn Task>> = Vec::new();
    let mut concurrent: Vec<Box<dyn Task>> = Vec::new();
    for spec in Host::tasks() {
        if !run_all && !named.iter().any(|s| s.flag == spec.flag) {
            continue;
        }
        let task = (spec.build)(readme);
        match spec.concurrency {
            Concurrency::Sequential => tasks.push(task),
            Concurrency::Concurrent => concurrent.push(task),
        }
    }

    for task in tasks.iter_mut().chain(concurrent.iter_mut()) {
        task.set_dry_run(dry_run);
    }

    // The `*_ops` modules record every change against whichever task is running,
    // and hold back from writing anything at all during a dry run.
    run_log::set_dry_run(dry_run);

    let mut results: Vec<TaskResult> = Vec::new();

    // Start the independent audits now so their external commands overlap the
    // sequential work below instead of adding to the total wall time. Their
    // output is captured and replayed as whole blocks once they finish, so
    // concurrent tasks do not interleave line by line.
    let audit_handles: Vec<_> = concurrent
        .into_iter()
        .map(|mut task| tokio::spawn(async move { ui::capture(run_task(&mut task)).await }))
        .collect();

    for task in &mut tasks {
        results.push(run_task(task).await);
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
    finish_log(&log_path);
}

/// Read state, remediate, then verify - the pipeline every task follows.
///
/// The whole pipeline is scoped to the task's name so every change the `*_ops`
/// modules record underneath it is attributed correctly, including for the
/// audits that run concurrently.
async fn run_task(task: &mut Box<dyn Task>) -> TaskResult {
    let name = task.name().to_string();
    run_log::in_task(&name, run_task_inner(task)).await
}

async fn run_task_inner(task: &mut Box<dyn Task>) -> TaskResult {
    ui::write_line();
    ui::rule(&format!("[bold blue]{}[/]", ui::escape(task.name())));
    ui::write_line();

    // Step 1: Read system state.
    ui::markup_line("[cyan]📊 Reading current system state...[/]");
    with_spinner("📊 Reading system state...", task.read_system_state()).await;
    ui::markup_line("[green]✓ System state captured[/]");
    ui::write_line();

    // Step 2: Execute remediation.
    ui::markup_line("[yellow]🔧 Applying security fixes...[/]");
    let mut result = with_spinner("🔧 Executing remediation...", task.execute()).await;
    if result.success {
        ui::markup_line(&format!("[green]✓ {}[/]", ui::escape(&result.message)));
    } else {
        ui::markup_line(&format!("[red]✗ {}[/]", ui::escape(&result.message)));
    }
    ui::write_line();

    // Step 3: Verify changes.
    ui::markup_line("[magenta]🔍 Verifying applied changes...[/]");
    let verified = with_spinner("🔍 Verifying changes...", task.verify()).await;
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

/// Write the run log, reporting where it went (or why it could not be written).
fn finish_log(path: &std::path::Path) {
    match run_log::write_to(path) {
        Ok(()) => ui::markup_line(&format!(
            "[dim]Run log written to: {}[/]",
            ui::escape(&path.to_string_lossy())
        )),
        Err(e) => ui::markup_line(&format!(
            "[yellow]Could not write run log to {}: {}[/]",
            ui::escape(&path.to_string_lossy()),
            ui::escape(&e.to_string())
        )),
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
mod tests {
    use super::*;

    fn args(list: &[&str]) -> Vec<String> {
        list.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn known_flags_are_accepted() {
        for flag in ["--help", "-h", "-?", "/?", "--dry-run", "--all"] {
            assert_eq!(
                first_unknown_argument(&args(&[flag])),
                None,
                "{flag} should be accepted"
            );
        }
    }

    #[test]
    fn an_unknown_flag_is_reported() {
        assert_eq!(
            first_unknown_argument(&args(&["--dry-run", "--oops"])),
            Some("--oops".to_string())
        );
    }

    #[test]
    fn a_typo_of_a_known_flag_is_not_silently_ignored() {
        // The dangerous case: this used to set no task flag, which meant "run
        // everything" rather than "you mistyped --dry-run".
        assert_eq!(
            first_unknown_argument(&args(&["--dryrun"])),
            Some("--dryrun".to_string())
        );
    }

    #[test]
    fn value_flags_consume_their_argument() {
        // The path is a value, not an unrecognised flag.
        assert_eq!(
            first_unknown_argument(&args(&["--readme", "C:\\CyberPatriot\\README.url"])),
            None
        );
        assert_eq!(
            first_unknown_argument(&args(&["--log", "run.txt", "--all"])),
            None
        );
        assert_eq!(first_unknown_argument(&args(&["-r", "readme.html"])), None);
    }

    /// `-h` is help on every platform. Which task, if any, holds `-H` is a
    /// platform question, and `no_task_flag_shadows_a_global_one` is what stops
    /// one claiming `-h` again - security hardening once did, which made
    /// `--help` begin a remediation run.
    #[test]
    fn help_keeps_its_short_flag() {
        assert_eq!(first_unknown_argument(&args(&["-h"])), None);
    }

    #[test]
    fn no_arguments_is_not_an_error() {
        assert_eq!(first_unknown_argument(&[]), None);
    }

    #[test]
    fn every_documented_flag_is_accepted_by_the_validator() {
        // The help text and the validator read the same two sources, so they
        // cannot disagree - this pins that down.
        for (long, short, _) in GLOBAL_FLAGS {
            let name = long.split(' ').next().unwrap();
            assert_eq!(first_unknown_argument(&args(&[name])), None, "{name}");
            if !short.is_empty() {
                assert_eq!(first_unknown_argument(&args(&[short])), None, "{short}");
            }
        }
    }

    /// The whole point of the platform table: a task that exists is a task the
    /// argument parser accepts and the menu offers. Before it, those were three
    /// separate lists and a task could appear in one without the others.
    #[test]
    fn every_platform_task_is_accepted_by_the_validator() {
        for spec in Host::tasks() {
            assert_eq!(
                first_unknown_argument(&args(&[spec.flag])),
                None,
                "{}",
                spec.flag
            );
            if !spec.short.is_empty() {
                assert_eq!(
                    first_unknown_argument(&args(&[spec.short])),
                    None,
                    "{}",
                    spec.short
                );
            }
        }
    }

    /// A task flag must not collide with a global one. `--security-hardening`
    /// once claimed `-h`, which made `--help` begin a remediation run.
    #[test]
    fn no_task_flag_shadows_a_global_one() {
        let globals: Vec<&str> = GLOBAL_FLAGS
            .iter()
            .flat_map(|(long, short, _)| [long.split(' ').next().unwrap_or(long), short])
            .filter(|f| !f.is_empty())
            .collect();
        for spec in Host::tasks() {
            assert!(
                !globals.contains(&spec.flag),
                "{} collides with a global flag",
                spec.flag
            );
            if !spec.short.is_empty() {
                assert!(
                    !globals.contains(&spec.short),
                    "{} claims the global flag {}",
                    spec.flag,
                    spec.short
                );
            }
        }
    }
}
