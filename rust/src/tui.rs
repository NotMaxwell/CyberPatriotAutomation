// =============================================================================
// PinnacleCyPat - Interactive terminal UI
// Author: Maxwell McCormick
// Copyright (c) 2026 Maxwell McCormick. All Rights Reserved.
// =============================================================================

//! The interactive front end: a guided menu that asks which README to use, which
//! tasks to run and whether to preview or apply, then hands the answers back as
//! a command line.
//!
//! It deliberately produces *arguments* rather than running anything itself. The
//! command line is the single execution path, and every ordering guarantee the
//! run depends on - the README is parsed before user management, service
//! protection happens before service disabling, the independent audits run
//! concurrently and the rest do not - lives there. A menu that drove the tasks
//! directly would be a second copy of that logic, free to drift from the first.
//!
//! It is also the answer to the double-click problem. Launching the executable
//! with no arguments used to begin a full destructive run; it now prints help
//! and stops. That is safe but unhelpful to the competitor who just wants to get
//! going, so a bare launch on a real console opens this menu instead - which
//! changes nothing until an explicit confirmation.
//!
//! Prompts are numbered rather than arrow-driven, so this needs no raw terminal
//! mode and no extra dependency. The C# port uses Spectre.Console's selection
//! prompts for the same flow; the questions and their order match.

use std::io::{self, BufRead, IsTerminal, Write};

use crate::app_config;
use crate::ui;

/// One selectable task: the flag that runs it, and how it is described.
struct TaskChoice {
    flag: &'static str,
    label: &'static str,
    detail: &'static str,
}

/// Every task the menu offers, in the order the run executes them.
///
/// Kept in run order rather than alphabetical so the confirmation summary reads
/// as the sequence that is about to happen.
const TASKS: &[TaskChoice] = &[
    TaskChoice {
        flag: "--password-policy",
        label: "Password Policy",
        detail: "length, age, history, lockout",
    },
    TaskChoice {
        flag: "--account-permissions",
        label: "Account Permissions",
        detail: "Guest, password expiry, admins",
    },
    TaskChoice {
        flag: "--user-management",
        label: "User Management",
        detail: "needs a README",
    },
    TaskChoice {
        flag: "--service-management",
        label: "Service Management",
        detail: "disable insecure, protect critical",
    },
    TaskChoice {
        flag: "--audit-policy",
        label: "Audit Policy",
        detail: "event logging and security settings",
    },
    TaskChoice {
        flag: "--firewall",
        label: "Firewall",
        detail: "profiles, blocked ports, risky rules",
    },
    TaskChoice {
        flag: "--security-hardening",
        label: "Security Hardening",
        detail: "registry hardening, features",
    },
    TaskChoice {
        flag: "--media-scan",
        label: "Prohibited Media",
        detail: "deletes matching files permanently",
    },
    TaskChoice {
        flag: "--group-policy",
        label: "Local Security Policy",
        detail: "SMB signing, logon, RDP",
    },
    TaskChoice {
        flag: "--software-updates",
        label: "Software Updates",
        detail: "update installed applications",
    },
    TaskChoice {
        flag: "--software-management",
        label: "Software Management",
        detail: "remove, install, Defender scan",
    },
    TaskChoice {
        flag: "--shared-folders",
        label: "Shared Folders Audit",
        detail: "removes non-default shares",
    },
    TaskChoice {
        flag: "--hosts-file",
        label: "Hosts File Audit",
        detail: "removes unauthorised entries",
    },
    TaskChoice {
        flag: "--dns-settings",
        label: "DNS Settings Audit",
        detail: "reports public resolvers",
    },
    TaskChoice {
        flag: "--scheduled-tasks",
        label: "Scheduled Tasks Audit",
        detail: "disables suspicious tasks",
    },
];

/// Tasks that do nothing useful without a parsed README.
const NEED_README: &[&str] = &["--user-management", "--software-management"];

/// Should a bare invocation open the menu rather than print help?
///
/// Only when there is a human at a terminal. Redirected streams mean a script or
/// a pipe, where a prompt would block forever waiting for an answer that is
/// never coming.
pub fn is_interactive_console() -> bool {
    io::stdin().is_terminal() && io::stdout().is_terminal()
}

/// Run the menu. Returns the command line to execute, or `None` if the user
/// chose to quit or declined the confirmation.
pub fn build_arguments() -> Option<Vec<String>> {
    show_banner();

    let mode = select(
        "What would you like to do?",
        &[
            "Inspect the README only  [dim](read-only, changes nothing)[/]",
            "Preview every task  [dim](dry run, changes nothing)[/]",
            "Run every task  [dim](applies changes)[/]",
            "Choose individual tasks",
            "Quit",
        ],
    )?;

    if mode == 4 {
        return None;
    }

    let parse_only = mode == 0;
    let mut args: Vec<String> = Vec::new();

    // Every path needs a README except the one that explicitly declines it, so
    // it is asked for first and the answer reused below.
    let readme_args = ask_for_readme(parse_only)?;
    args.extend(readme_args.iter().cloned());

    if parse_only {
        args.push("--parse-readme".to_string());
        return Some(args);
    }

    let (chosen, dry_run) = if mode == 3 {
        let chosen = ask_for_tasks()?;
        if chosen.is_empty() {
            ui::markup_line("[yellow]No tasks selected - nothing to do.[/]");
            return None;
        }
        let dry_run = select(
            "Preview or apply?",
            &[
                "Preview  [dim](dry run - reports what would change)[/]",
                "Apply  [dim](makes the changes)[/]",
            ],
        )? == 0;
        (chosen, dry_run)
    } else {
        // "--all" rather than the fourteen flags: it is what the help documents,
        // and it is what appears in the run log's Command line.
        (vec!["--all".to_string()], mode == 1)
    };

    args.extend(chosen.iter().cloned());
    if dry_run {
        args.push("--dry-run".to_string());
    }

    warn_about_missing_readme(&readme_args, &chosen);

    confirm(&args, dry_run).then_some(args)
}

fn show_banner() {
    // Clear and home, so the menu starts from a clean screen the way the C#
    // port's AnsiConsole.Clear() does.
    print!("\x1b[2J\x1b[H");
    let _ = io::stdout().flush();

    ui::markup_line("[bold cyan]╭────────────────────────────────────────────────────╮[/]");
    ui::markup_line(&format!(
        "[bold cyan]│[/]  [bold cyan]PinnacleCyPat[/]{:<37}[bold cyan]│[/]",
        ""
    ));
    ui::markup_line(&format!(
        "[bold cyan]│[/]  [dim]{:<50}[/][bold cyan]│[/]",
        app_config::version_string()
    ));
    ui::markup_line(&format!(
        "[bold cyan]│[/]  [dim]{:<50}[/][bold cyan]│[/]",
        "Windows security hardening for CyberPatriot images"
    ));
    ui::markup_line("[bold cyan]╰────────────────────────────────────────────────────╯[/]");
    ui::write_line();

    // Almost everything the tool does needs elevation, and the failure mode
    // without it is a long run in which every change is denied - which reads as
    // the tool not working rather than as a missing privilege.
    if cfg!(windows) && !is_administrator() {
        ui::markup_line("[yellow]! Not running as Administrator. Most changes will be refused.[/]");
        ui::markup_line(
            "[dim]  Close this, right-click the executable and choose 'Run as administrator'.[/]",
        );
        ui::write_line();
    }
}

/// Is this process elevated?
///
/// Probed by writing to a machine-wide registry key rather than by inspecting
/// the token: the answer wanted here is "can this process actually change the
/// machine", and a token check would also have to account for UAC virtualisation
/// to give it. Non-Windows always reports false, where the question is moot.
#[cfg(windows)]
fn is_administrator() -> bool {
    crate::native::registry::can_write_machine_policy()
}

#[cfg(not(windows))]
fn is_administrator() -> bool {
    false
}

/// Ask where the README comes from, as command-line arguments.
fn ask_for_readme(parse_only: bool) -> Option<Vec<String>> {
    let mut choices = vec![
        "Find it automatically  [dim](recommended)[/]",
        "Enter a path or URL",
    ];
    if !parse_only {
        choices.push("Continue without a README");
    }

    match select("Which competition README should drive the run?", &choices)? {
        0 => Some(vec!["--auto-readme".to_string()]),
        2 => Some(Vec::new()),
        _ => {
            // Accepts what --readme accepts: a .url or .lnk shortcut, an .html
            // file, or an https:// address. Resolution happens in the run.
            let path = prompt_line("Path or URL: ")?;
            let path = path.trim().trim_matches('"').to_string();
            if path.is_empty() {
                ui::markup_line("[yellow]No path given - continuing without a README.[/]");
                Some(Vec::new())
            } else {
                Some(vec!["--readme".to_string(), path])
            }
        }
    }
}

/// Ask which tasks to run. Everything is selected unless the user narrows it.
///
/// Entering nothing keeps all of them, because the common case - "everything
/// except the media scan" - should be one line of typing rather than fourteen
/// confirmations.
fn ask_for_tasks() -> Option<Vec<String>> {
    ui::write_line();
    ui::markup_line("[bold]Which tasks should run?[/]");
    for (index, task) in TASKS.iter().enumerate() {
        ui::markup_line(&format!(
            "  [cyan]{:>2}[/]  {}  [dim]{}[/]",
            index + 1,
            task.label,
            task.detail
        ));
    }
    ui::markup_line("[dim]Enter numbers separated by spaces or commas, or press enter for all.[/]");

    let answer = prompt_line("Tasks: ")?;
    let answer = answer.trim();
    if answer.is_empty() {
        return Some(TASKS.iter().map(|t| t.flag.to_string()).collect());
    }

    let mut chosen: Vec<String> = Vec::new();
    for token in answer.split([' ', ',', '\t']).filter(|t| !t.is_empty()) {
        match token.parse::<usize>() {
            // De-duplicated so "3 3" does not pass the same flag twice.
            Ok(n) if (1..=TASKS.len()).contains(&n) => {
                let flag = TASKS[n - 1].flag.to_string();
                if !chosen.contains(&flag) {
                    chosen.push(flag);
                }
            }
            _ => ui::markup_line(&format!(
                "[yellow]Ignoring '{}': not a task number.[/]",
                ui::escape(token)
            )),
        }
    }
    Some(chosen)
}

/// Say so when a chosen task depends on a README that was declined.
///
/// Without the warning the run simply reports "No README data provided" part way
/// through, by which point the other tasks have already made changes.
fn warn_about_missing_readme(readme_args: &[String], chosen: &[String]) {
    if !readme_args.is_empty() {
        return;
    }

    let all = chosen.iter().any(|c| c == "--all");
    let affected: Vec<&str> = NEED_README
        .iter()
        .copied()
        .filter(|flag| all || chosen.iter().any(|c| c == flag))
        .collect();
    if affected.is_empty() {
        return;
    }

    ui::write_line();
    ui::markup_line(
        "[yellow]! Without a README these tasks cannot tell authorised accounts and software \
         from unauthorised ones, and will decline to act:[/]",
    );
    for flag in affected {
        if let Some(task) = TASKS.iter().find(|t| t.flag == flag) {
            ui::markup_line(&format!("[yellow]    {}[/]", task.label));
        }
    }
}

/// Show what is about to happen and require an explicit yes.
///
/// The default answer is no for a run that applies changes and yes for a dry
/// run, so pressing enter without reading can only ever be the harmless choice.
fn confirm(args: &[String], dry_run: bool) -> bool {
    let readme = match args.iter().position(|a| a == "--readme") {
        Some(i) => args.get(i + 1).cloned().unwrap_or_default(),
        None if args.iter().any(|a| a == "--auto-readme") => "found automatically".to_string(),
        None => "none".to_string(),
    };

    let tasks = if args.iter().any(|a| a == "--all") {
        "every task".to_string()
    } else {
        args.iter()
            .filter_map(|a| TASKS.iter().find(|t| t.flag == a))
            .map(|t| t.label)
            .collect::<Vec<_>>()
            .join(", ")
    };

    ui::write_line();
    let mut summary = ui::TableBuilder::new().columns(&["Setting", "Value"]);
    summary.add_row(["README".to_string(), readme]);
    summary.add_row(["Tasks".to_string(), tasks]);
    summary.add_row([
        "Mode".to_string(),
        if dry_run {
            "preview - nothing is changed".to_string()
        } else {
            "apply - changes this machine".to_string()
        },
    ]);
    summary.add_row([
        "Command".to_string(),
        format!("pinnacle-cypat.exe {}", args.join(" ")),
    ]);
    summary.print();

    if !dry_run {
        ui::markup_line(
            "[yellow]This deletes files, removes accounts and disables services. \
             Run a preview first if you have not.[/]",
        );
    }

    let question = if dry_run {
        "Start the preview? [Y/n]: "
    } else {
        "Apply these changes? [y/N]: "
    };

    match prompt_line(question) {
        Some(answer) => match answer.trim().to_ascii_lowercase().as_str() {
            "y" | "yes" => true,
            "n" | "no" => false,
            // Enter alone takes the safe default for the mode.
            "" => dry_run,
            _ => false,
        },
        None => false,
    }
}

/// Print a numbered list and read a choice. Returns the zero-based index, or
/// `None` on end-of-input.
fn select(title: &str, choices: &[&str]) -> Option<usize> {
    loop {
        ui::write_line();
        ui::markup_line(&format!("[bold]{title}[/]"));
        for (index, choice) in choices.iter().enumerate() {
            ui::markup_line(&format!("  [cyan]{}[/]  {}", index + 1, choice));
        }

        let answer = prompt_line(&format!("Choice [1-{}]: ", choices.len()))?;
        match answer.trim().parse::<usize>() {
            Ok(n) if (1..=choices.len()).contains(&n) => return Some(n - 1),
            _ => ui::markup_line("[yellow]Enter one of the numbers above.[/]"),
        }
    }
}

/// Write a prompt and read one line. `None` means end-of-input, which is a
/// closed stdin rather than an answer - treated as "quit" by every caller.
fn prompt_line(prompt: &str) -> Option<String> {
    print!("{prompt}");
    let _ = io::stdout().flush();

    let mut line = String::new();
    match io::stdin().lock().read_line(&mut line) {
        Ok(0) | Err(_) => None,
        Ok(_) => Some(line),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Every menu entry has to name a flag the CLI accepts, or picking it prints
    // "Unrecognised argument" and exits 2. The flag table lives in main.rs, so
    // this at least pins the shape: non-empty, long-form, no duplicates.
    #[test]
    fn task_flags_are_well_formed_and_unique() {
        let mut seen: Vec<&str> = Vec::new();
        for task in TASKS {
            assert!(
                task.flag.starts_with("--"),
                "{} is not long-form",
                task.flag
            );
            assert!(!task.label.is_empty());
            assert!(!seen.contains(&task.flag), "{} listed twice", task.flag);
            seen.push(task.flag);
        }
    }

    #[test]
    fn readme_dependent_tasks_are_offered_by_the_menu() {
        for flag in NEED_README {
            assert!(
                TASKS.iter().any(|t| t.flag == *flag),
                "{flag} is warned about but never offered"
            );
        }
    }
}
