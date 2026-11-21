// =============================================================================
// PinnacleCyPat (Rust port) - Entry point
// Author: Maxwell McCormick
// Copyright 2026 Maxwell McCormick
// SPDX-License-Identifier: Apache-2.0
// =============================================================================

use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::AtomicBool;
use std::time::Duration;

use indicatif::{MultiProgress, ProgressBar, ProgressStyle};
use pinnacle_core::app_config;
use pinnacle_core::engine::{self, Phase, ReadmeChoice, RunEvent, RunPlan, TaskChoice};
use pinnacle_core::platform::{Platform, TaskSpec};
use pinnacle_core::readme_parser;
use pinnacle_core::run_log;
use pinnacle_core::ui;
use tokio::sync::mpsc;

mod web;

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
    (
        "--web",
        "",
        "Open the app in a browser, served from 127.0.0.1",
    ),
    (
        "--port <n>",
        "",
        "With --web, listen on port <n> instead of a random one",
    ),
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
const VALUE_FLAGS: &[&str] = &["--readme", "-r", "--log", "--port"];

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
    println!(
        "Prefer a window? {}\n",
        if cfg!(windows) {
            "Run pinnacle-cypat-gui.exe."
        } else {
            "Run with --web (or with no arguments on a desktop) for the web interface."
        }
    );
    println!("OPTIONS:");
    for (long, short, description) in GLOBAL_FLAGS {
        println!("{:<34}{description}", spelling(long, short));
    }
    println!("\n{} TASKS:", Host::NAME.to_uppercase());
    for spec in Host::tasks() {
        println!("{:<34}{}", spelling(spec.flag, spec.short), spec.help);
    }
    println!("\nEXAMPLES:");
    if !cfg!(windows) {
        println!("    pinnacle-cypat --web                          # web interface");
    }
    println!("    pinnacle-cypat --auto-readme --parse-readme   # read-only");
    println!("    pinnacle-cypat --auto-readme --all --dry-run  # preview");
    println!("    pinnacle-cypat --auto-readme --all            # apply");
}

/// Open the graphical front end for a bare launch. True if one was opened.
///
/// Windows: the desktop GUI, when `pinnacle-cypat-gui.exe` ships beside this
/// executable (as `publish.sh` arranges). Linux: the web UI, when there is a
/// desktop session to show a browser in - a bare launch over SSH, or from a
/// script, still gets the help text rather than a server nobody can reach.
async fn open_front_end() -> bool {
    #[cfg(windows)]
    {
        let Some(gui) = std::env::current_exe()
            .ok()
            .and_then(|exe| exe.parent().map(|d| d.join("pinnacle-cypat-gui.exe")))
            .filter(|p| p.is_file())
        else {
            return false;
        };
        match std::process::Command::new(&gui).spawn() {
            Ok(_) => true,
            Err(e) => {
                ui::markup_line(&format!(
                    "[yellow]Could not open {}: {}[/]",
                    ui::escape(&gui.to_string_lossy()),
                    ui::escape(&e.to_string())
                ));
                false
            }
        }
    }
    #[cfg(not(windows))]
    {
        if !has_desktop_session(|name| std::env::var(name).ok()) {
            return false;
        }
        if let Err(e) = web::serve::<Host>(None).await {
            ui::markup_line(&format!(
                "[red]Could not start the web interface: {}[/]",
                ui::escape(&e.to_string())
            ));
            std::process::exit(1);
        }
        true
    }
}

/// Is there a graphical session a browser could open in? Either this process
/// has one, or it runs under sudo for a user who does. `sudo` strips `DISPLAY`
/// by default, so the second case is the usual one on a competition image.
#[cfg_attr(windows, allow(dead_code))]
fn has_desktop_session(var: impl Fn(&str) -> Option<String>) -> bool {
    let set = |name: &str| var(name).is_some_and(|v| !v.is_empty());
    if set("DISPLAY") || set("WAYLAND_DISPLAY") {
        return true;
    }
    var("SUDO_UID")
        .filter(|uid| !uid.is_empty())
        .is_some_and(|uid| std::path::Path::new(&format!("/run/user/{uid}/bus")).exists())
}

async fn run_automation() {
    let cli_args: Vec<String> = std::env::args().skip(1).collect();

    // Help before anything else, and before the run log opens.
    if has_flag(&cli_args, &["--help", "-h", "-?", "/?"]) {
        print_help();
        return;
    }

    // The web UI owns the whole session: everything below is the command-line
    // run, which it replaces. The arguments are still validated first, so a
    // typo next to --web is reported rather than ignored.
    if has_flag(&cli_args, &["--web"]) {
        if let Some(unknown) = first_unknown_argument(&cli_args) {
            ui::markup_line(&format!(
                "[red]Unrecognised argument: {}[/]",
                ui::escape(&unknown)
            ));
            std::process::exit(2);
        }
        let port = match extract_argument(&cli_args, &["--port"]).map(|p| p.parse::<u16>()) {
            None => None,
            Some(Ok(port)) => Some(port),
            Some(Err(_)) => {
                ui::markup_line("[red]--port needs a number from 0 to 65535.[/]");
                std::process::exit(2);
            }
        };
        if let Err(e) = web::serve::<Host>(port).await {
            ui::markup_line(&format!(
                "[red]Could not start the web interface: {}[/]",
                ui::escape(&e.to_string())
            ));
            std::process::exit(1);
        }
        return;
    }

    // A bare launch - double-clicking the executable, or typing its name - has
    // nothing to act on, and printing help at someone who cannot see a command
    // line helps nobody. Open the graphical front end when there is one to
    // open; otherwise fall through to the help below. This replaced the old
    // terminal menu, which the GUI and the web UI made redundant.
    if cli_args.is_empty() && open_front_end().await {
        return;
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

    // The report modes write a log of their own; a run gets its header from
    // the engine, which starts the log afresh.
    let command_line = cli_args.join(" ");
    for line in run_log::header(&command_line) {
        run_log::record_raw(&line);
    }

    let readme_file = extract_argument(&cli_args, &["--readme", "-r"]);
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

    let readme = match readme_file {
        Some(path) => ReadmeChoice::Path(path),
        None if auto_find_readme => ReadmeChoice::Auto,
        None => ReadmeChoice::None,
    };

    // Directives-only mode: report what this round does differently, and stop.
    //
    // Separate from --parse-readme because they answer different questions.
    // That one asks "what did the parser get out of this document"; this one
    // asks "what about this round is not the standard checklist", which is the
    // question a competitor has ninety seconds to answer at the start.
    if directives_only {
        let inspection = engine::inspect_readme(&readme).await;
        if !engine::report_directives(&inspection) {
            ui::markup_line(
                "[yellow]No README file specified. Use --readme <file> or --auto-readme.[/]",
            );
        }
        ui::write_line();
        engine::finish_log(&log_path);
        return;
    }

    // Parse-only mode: display the parsed data and stop.
    if parse_readme_only {
        let inspection = engine::inspect_readme(&readme).await;
        if let Some(data) = &inspection.data {
            readme_parser::display_parsed_data(data);
            engine::report_directives(&inspection);
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
        engine::finish_log(&log_path);
        return;
    }

    let plan = RunPlan {
        readme,
        readme_override: None,
        tasks: if run_all {
            TaskChoice::All
        } else {
            TaskChoice::Flags(named.iter().map(|spec| spec.flag.to_string()).collect())
        },
        dry_run,
        log_path,
        command_line,
        cancel: Arc::new(AtomicBool::new(false)),
    };
    let (sender, receiver) = mpsc::unbounded_channel();
    tokio::join!(engine::run::<Host>(plan, sender), show_events(receiver));
}

/// Print the engine's lines and draw a spinner while each task works.
///
/// The engine has already recorded every line in the run log, so they are
/// printed with `print_line`, which does not record them again.
async fn show_events(mut receiver: mpsc::UnboundedReceiver<RunEvent>) {
    // Concurrent audits report their phases while a sequential task is also
    // running, so each task gets its own spinner under one MultiProgress -
    // separate bars would draw over each other.
    let multi = MultiProgress::new();
    let mut spinners: HashMap<String, ProgressBar> = HashMap::new();

    while let Some(event) = receiver.recv().await {
        match event {
            RunEvent::Line(line) => multi.suspend(|| ui::print_line(&line)),
            RunEvent::TaskPhase { name, phase } => {
                if let Some(old) = spinners.remove(&name) {
                    old.finish_and_clear();
                }
                let message = match phase {
                    Phase::Reading => "📊 Reading system state...",
                    Phase::Executing => "🔧 Executing remediation...",
                    Phase::Verifying => "🔍 Verifying changes...",
                };
                let spinner = multi.add(ProgressBar::new_spinner());
                spinner.set_style(ProgressStyle::with_template("{spinner:.cyan} {msg}").unwrap());
                spinner.set_message(message);
                spinner.enable_steady_tick(Duration::from_millis(100));
                spinners.insert(name, spinner);
            }
            RunEvent::TaskFinished(result) => {
                if let Some(old) = spinners.remove(&result.task_name) {
                    old.finish_and_clear();
                }
            }
            // A task whose result carries a different name, or an audit that
            // panicked, would otherwise leave its spinner running.
            RunEvent::Finished(_) => {
                for (_, old) in spinners.drain() {
                    old.finish_and_clear();
                }
            }
            RunEvent::Readme(_) | RunEvent::TaskStarted { .. } => {}
        }
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
    fn the_task_table_is_well_formed_for_every_front_end() {
        // Moved from the old terminal menu: the GUI and web UI list tasks by
        // these rows, so each needs a long flag, a label, and to appear once.
        let mut seen: Vec<&str> = Vec::new();
        for spec in Host::tasks() {
            assert!(
                spec.flag.starts_with("--"),
                "{} is not long-form",
                spec.flag
            );
            assert!(!spec.label.is_empty(), "{} has no label", spec.flag);
            assert!(!seen.contains(&spec.flag), "{} listed twice", spec.flag);
            seen.push(spec.flag);
        }
        assert!(!seen.is_empty(), "the platform offers no tasks at all");
    }

    #[test]
    fn a_desktop_session_is_found_from_the_display_but_not_from_nothing() {
        let env = |pairs: &'static [(&'static str, &'static str)]| {
            move |name: &str| {
                pairs
                    .iter()
                    .find(|(k, _)| *k == name)
                    .map(|(_, v)| v.to_string())
            }
        };
        assert!(has_desktop_session(env(&[("DISPLAY", ":0")])));
        assert!(has_desktop_session(env(&[(
            "WAYLAND_DISPLAY",
            "wayland-0"
        )])));
        assert!(!has_desktop_session(env(&[])));
        assert!(!has_desktop_session(env(&[("DISPLAY", "")])));
        // A sudo user whose session bus does not exist: no desktop.
        assert!(!has_desktop_session(env(&[("SUDO_UID", "65000")])));
    }

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
