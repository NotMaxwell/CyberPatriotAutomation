// =============================================================================
// PinnacleCyPat (Rust port) - Entry point
// Author: Maxwell McCormick
// Copyright (c) 2026 Maxwell McCormick. All Rights Reserved.
// =============================================================================

use std::future::Future;
use std::time::Duration;

use pinnacle_cypat::app_config;
use pinnacle_cypat::models::{FixOutcome, ReadmeData, TaskResult};
use pinnacle_cypat::readme_parser;
use pinnacle_cypat::run_log;
use pinnacle_cypat::tasks::*;
use pinnacle_cypat::tui;
use pinnacle_cypat::ui::{self, BarColor};
use indicatif::{ProgressBar, ProgressStyle};

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

/// Every accepted flag, with the description shown by `--help`.
///
/// This is the single source of truth for both the help text and the
/// unrecognised-argument check, so a new flag cannot be accepted without also
/// being documented.
const FLAGS: &[(&str, &str, &str)] = &[
    ("--help", "-h", "Show this help and exit"),
    ("--tui", "-i", "Open the interactive menu"),
    ("--version", "-V", "Print the version and build date, then exit"),
    ("--readme <path>", "-r", "Read the competition README at <path>"),
    ("--auto-readme", "-R", "Find the README automatically"),
    ("--parse-readme", "", "Show what the parser extracted, then exit (read-only)"),
    ("--dry-run", "-d", "Report what would change without changing it"),
    ("--all", "", "Run every task (the default when no task is named)"),
    ("--password-policy", "-p", "Password and lockout policy"),
    (
        "--account-permissions",
        "-a",
        "Account permissions and group membership",
    ),
    (
        "--user-management",
        "-u",
        "Create, remove and correct user accounts",
    ),
    (
        "--service-management",
        "-s",
        "Enable required and disable insecure services",
    ),
    (
        "--audit-policy",
        "-t",
        "Audit policy and security event logging",
    ),
    ("--firewall", "-f", "Windows Firewall profiles and rules"),
    ("--security-hardening", "-H", "General security hardening"),
    ("--media-scan", "-m", "Find and remove prohibited media"),
    ("--software-updates", "", "Update installed software"),
    ("--software-management", "", "Remove prohibited and install required software"),
    ("--shared-folders", "", "Remove shares beyond ADMIN$, C$ and IPC$"),
    ("--hosts-file", "", "Remove unauthorised hosts file entries"),
    ("--dns-settings", "", "Report public DNS resolvers"),
    ("--scheduled-tasks", "", "Disable suspicious scheduled tasks"),
    ("--group-policy", "-g", "Local Security Policy: SMB signing, logon, RDP"),
    ("--log <path>", "", "Write the run log to <path>"),
];

/// Flags that consume the following argument as their value.
const VALUE_FLAGS: &[&str] = &["--readme", "-r", "--log"];

/// The first argument that is not a flag this tool accepts, if any.
fn first_unknown_argument(args: &[String]) -> Option<String> {
    let mut known: Vec<&str> = Vec::new();
    for (long, short, _) in FLAGS {
        // The table spells value-taking flags as "--readme <path>".
        known.push(long.split(' ').next().unwrap_or(long));
        if !short.is_empty() {
            known.push(short);
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

fn print_help() {
    println!(
        "PinnacleCyPat {}\n",
        app_config::version_string()
    );
    println!("USAGE:");
    println!("    pinnacle-cypat [OPTIONS]\n");
    println!("Run as Administrator. Name a task, or pass --all to run every task.");
    println!("Pass --dry-run first to see what would change.");
    println!("Not sure? Run --tui for a guided menu.\n");
    println!("OPTIONS:");
    for (long, short, description) in FLAGS {
        let flag = if short.is_empty() {
            format!("    {long}")
        } else {
            format!("    {short}, {long}")
        };
        println!("{flag:<34}{description}");
    }
    println!("\nEXAMPLES:");
    println!("    pinnacle-cypat --tui                          # guided menu");
    println!("    pinnacle-cypat --auto-readme --parse-readme   # read-only");
    println!("    pinnacle-cypat --auto-readme --all --dry-run  # preview");
    println!("    pinnacle-cypat --auto-readme --all            # apply");
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
    if has_flag(&cli_args, &["--tui", "-i"]) || (cli_args.is_empty() && tui::is_interactive_console())
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
        println!(
            "PinnacleCyPat {}",
            app_config::version_string()
        );
        return;
    }

    for line in run_log::header(&cli_args.join(" ")) {
        run_log::record_raw(&line);
    }

    let mut readme_file = extract_argument(&cli_args, &["--readme", "-r"]);
    let auto_find_readme = has_flag(&cli_args, &["--auto-readme", "-R"]);
    let dry_run = has_flag(&cli_args, &["--dry-run", "-d"]);
    let run_password_policy = has_flag(&cli_args, &["--password-policy", "-p"]);
    let run_account_permissions = has_flag(&cli_args, &["--account-permissions", "-a"]);
    let run_user_management = has_flag(&cli_args, &["--user-management", "-u"]);
    let run_service_management = has_flag(&cli_args, &["--service-management", "-s"]);
    let run_audit_policy = has_flag(&cli_args, &["--audit-policy", "-t"]);
    let run_firewall = has_flag(&cli_args, &["--firewall", "-f"]);
    let run_security_hardening = has_flag(&cli_args, &["--security-hardening", "-H"]);
    let run_media_scan = has_flag(&cli_args, &["--media-scan", "-m"]);
    let run_software_updates = has_flag(&cli_args, &["--software-updates"]);

    // These five used to run only under --all, so there was no way to run one on
    // its own - or to offer them individually in the menu, which is what
    // prompted giving them flags.
    let run_software_management = has_flag(&cli_args, &["--software-management"]);
    let run_shared_folders = has_flag(&cli_args, &["--shared-folders"]);
    let run_hosts_file = has_flag(&cli_args, &["--hosts-file"]);
    let run_dns_settings = has_flag(&cli_args, &["--dns-settings"]);
    let run_scheduled_tasks = has_flag(&cli_args, &["--scheduled-tasks"]);
    let run_group_policy = has_flag(&cli_args, &["--group-policy", "-g"]);

    let parse_readme_only = has_flag(&cli_args, &["--parse-readme"]);

    // Where to write the run log; `--log <path>` overrides the default.
    let log_path = extract_argument(&cli_args, &["--log"])
        .map(std::path::PathBuf::from)
        .unwrap_or_else(run_log::default_log_path);

    let any_task_named = run_password_policy
        || run_account_permissions
        || run_user_management
        || run_service_management
        || run_audit_policy
        || run_firewall
        || run_security_hardening
        || run_media_scan
        || run_software_updates
        || run_software_management
        || run_shared_folders
        || run_hosts_file
        || run_dns_settings
        || run_scheduled_tasks
        || run_group_policy
        || parse_readme_only;

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

    // Parse-only mode: display the parsed data and stop.
    if parse_readme_only {
        if let Some(data) = &readme_data {
            readme_parser::display_parsed_data(data);
        } else {
            ui::markup_line(
                "[yellow]No README file specified. Use --readme <file> to parse one.[/]",
            );
        }
        // `--parse-readme` is a report, not a run. Combining it with task flags
        // silently did nothing, which reads as the tasks having been skipped for
        // some other reason.
        if run_all
            || run_password_policy
            || run_account_permissions
            || run_user_management
            || run_service_management
            || run_audit_policy
            || run_firewall
            || run_security_hardening
            || run_media_scan
            || run_software_updates
            || run_software_management
            || run_shared_folders
            || run_hosts_file
            || run_dns_settings
            || run_scheduled_tasks
            || run_group_policy
        {
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
        ui::write_line();
    }

    // Build task list.
    let mut tasks: Vec<Box<dyn Task>> = Vec::new();
    if run_password_policy || run_all {
        tasks.push(Box::new(PasswordPolicyTask::new()));
    }
    if run_account_permissions || run_all {
        tasks.push(Box::new(AccountPermissionsTask::new()));
    }
    if run_user_management || run_all {
        let mut task = UserManagementTask::new();
        if let Some(rd) = &readme_data {
            task.set_readme_data(rd.clone());
        }
        tasks.push(Box::new(task));
    }
    if run_service_management || run_all {
        let mut task = ServiceManagementTask::new();
        if let Some(rd) = &readme_data {
            task.set_readme_data(rd.clone());
        }
        tasks.push(Box::new(task));
    }
    if run_audit_policy || run_all {
        tasks.push(Box::new(AuditPolicyTask::new()));
    }
    if run_firewall || run_all {
        tasks.push(Box::new(FirewallConfigurationTask::new()));
    }
    if run_security_hardening || run_all {
        let mut task = SecurityHardeningTask::new();
        if let Some(rd) = &readme_data {
            task.set_readme_data(rd.clone());
        }
        tasks.push(Box::new(task));
    }
    if run_group_policy || run_all {
        let mut task = GroupPolicyTask::new();
        if let Some(rd) = &readme_data {
            task.set_readme_data(rd.clone());
        }
        tasks.push(Box::new(task));
    }
    if run_media_scan || run_all {
        let mut task = ProhibitedMediaTask::new();
        if let Some(rd) = &readme_data {
            task.set_readme_data(rd.clone());
        }
        tasks.push(Box::new(task));
    }
    if run_software_updates || run_all {
        let mut task = SoftwareUpdateTask::new();
        if let Some(rd) = &readme_data {
            task.set_readme_data(rd.clone());
        }
        tasks.push(Box::new(task));
    }
    // Independent audits: these touch disjoint areas (shares, the hosts file,
    // DNS, scheduled tasks) and share no state with each other, so they are the
    // only tasks it is safe to overlap. Everything above them contends for the
    // same accounts, services and registry keys, where concurrent writes would
    // race - user management and account permissions both rewrite accounts, and
    // service management and security hardening both rewrite services.
    let mut concurrent: Vec<Box<dyn Task>> = Vec::new();
    if run_shared_folders || run_all {
        concurrent.push(Box::new(SharedFoldersAuditTask::new()));
    }
    if run_hosts_file || run_all {
        concurrent.push(Box::new(HostsFileAuditTask::new()));
    }
    if run_dns_settings || run_all {
        concurrent.push(Box::new(DnsSettingsAuditTask::new()));
    }
    if run_scheduled_tasks || run_all {
        concurrent.push(Box::new(SuspiciousScheduledTasksAuditTask::new()));
    }
    if run_software_management || run_all {
        // Sequential, not concurrent: it uninstalls, installs and runs a
        // Defender scan, all of which contend with the service and software
        // work above.
        let mut task = SoftwareManagementTask::new();
        if let Some(rd) = &readme_data {
            task.set_readme_data(rd);
        }
        tasks.push(Box::new(task));
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

        if let Some(details) = &result.error_details {
            if !details.is_empty() {
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
        for flag in ["--help", "-h", "-?", "/?", "--dry-run", "--all", "-H"] {
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

    #[test]
    fn security_hardening_no_longer_claims_the_help_flag() {
        assert_eq!(first_unknown_argument(&args(&["-H"])), None);
        assert_eq!(first_unknown_argument(&args(&["-h"])), None);
    }

    #[test]
    fn no_arguments_is_not_an_error() {
        assert_eq!(first_unknown_argument(&[]), None);
    }

    #[test]
    fn every_documented_flag_is_accepted_by_the_validator() {
        // The help text and the validator share FLAGS, so they cannot disagree -
        // this pins that down.
        for (long, short, _) in FLAGS {
            let name = long.split(' ').next().unwrap();
            assert_eq!(first_unknown_argument(&args(&[name])), None, "{name}");
            if !short.is_empty() {
                assert_eq!(first_unknown_argument(&args(&[short])), None, "{short}");
            }
        }
    }
}
