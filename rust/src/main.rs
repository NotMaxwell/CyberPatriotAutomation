// =============================================================================
// CyberPatriot Automation Tool (Rust port) - Entry point
// Author: Maxwell McCormick
// Copyright (c) 2026 Maxwell McCormick. All Rights Reserved.
// =============================================================================

use std::future::Future;
use std::time::Duration;

use cyberpatriot_automation::app_config;
use cyberpatriot_automation::models::{ReadmeData, TaskResult};
use cyberpatriot_automation::readme_parser;
use cyberpatriot_automation::tasks::*;
use cyberpatriot_automation::ui::{self, BarColor};
use indicatif::{ProgressBar, ProgressStyle};

#[tokio::main]
async fn main() {
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

    let mut readme_file = extract_argument(&cli_args, &["--readme", "-r"]);
    let auto_find_readme = has_flag(&cli_args, &["--auto-readme", "-R"]);
    let dry_run = has_flag(&cli_args, &["--dry-run", "-d"]);
    let run_password_policy = has_flag(&cli_args, &["--password-policy", "-p"]);
    let run_account_permissions = has_flag(&cli_args, &["--account-permissions", "-a"]);
    let run_user_management = has_flag(&cli_args, &["--user-management", "-u"]);
    let run_service_management = has_flag(&cli_args, &["--service-management", "-s"]);
    let run_audit_policy = has_flag(&cli_args, &["--audit-policy", "-t"]);
    let run_firewall = has_flag(&cli_args, &["--firewall", "-f"]);
    let run_security_hardening = has_flag(&cli_args, &["--security-hardening", "-h"]);
    let run_media_scan = has_flag(&cli_args, &["--media-scan", "-m"]);
    let parse_readme_only = has_flag(&cli_args, &["--parse-readme"]);

    let run_all = has_flag(&cli_args, &["--all"])
        || (!run_password_policy
            && !run_account_permissions
            && !run_user_management
            && !run_service_management
            && !run_audit_policy
            && !run_firewall
            && !run_security_hardening
            && !run_media_scan
            && !parse_readme_only);

    // Auto-find the README if requested and none supplied.
    if readme_file.is_none() && auto_find_readme {
        readme_file = app_config::find_readme_file().await;
    }

    // Parse README if needed.
    let mut readme_data: Option<ReadmeData> = None;
    if let Some(file) = &readme_file {
        if !file.is_empty() {
            readme_data = Some(readme_parser::parse_html_readme_async(file).await);
        }
    }

    // Parse-only mode: display the parsed data and stop.
    if parse_readme_only {
        if let Some(data) = &readme_data {
            readme_parser::display_parsed_data(data);
        } else {
            ui::markup_line("[yellow]No README file specified. Use --readme <file> to parse one.[/]");
        }
        return;
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
        tasks.push(Box::new(SecurityHardeningTask::new()));
    }
    if run_media_scan || run_all {
        let mut task = ProhibitedMediaTask::new();
        if let Some(rd) = &readme_data {
            task.set_readme_data(rd.clone());
        }
        tasks.push(Box::new(task));
    }
    if run_all {
        tasks.push(Box::new(SharedFoldersAuditTask::new()));
        tasks.push(Box::new(HostsFileAuditTask::new()));
        tasks.push(Box::new(DnsSettingsAuditTask::new()));
        tasks.push(Box::new(SuspiciousScheduledTasksAuditTask::new()));
        let mut task = SoftwareManagementTask::new();
        if let Some(rd) = &readme_data {
            task.set_readme_data(rd);
        }
        tasks.push(Box::new(task));
    }

    for task in &mut tasks {
        task.set_dry_run(dry_run);
    }

    let mut results: Vec<TaskResult> = Vec::new();

    for task in &mut tasks {
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

        results.push(result);
    }

    display_summary(&results);
    ui::write_line();
    ui::rule("[bold green]✓ Automation Complete[/]");
    ui::write_line();
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
            ("Completed".to_string(), overall_completion_rate, completion_color),
            ("Remaining".to_string(), 100.0 - overall_completion_rate, BarColor::Grey),
        ],
    );
    ui::write_line();

    let confidence_color = bar_color(overall_confidence);
    ui::bar_chart(
        "[bold]Confidence Level[/]",
        &[
            ("Confident".to_string(), overall_confidence, confidence_color),
            ("Uncertain".to_string(), 100.0 - overall_confidence, BarColor::Grey),
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
        ui::markup_line("[dim italic]💡 Tip: Manual verification recommended for tasks with low confidence.[/]");
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
