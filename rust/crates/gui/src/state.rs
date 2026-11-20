// =============================================================================
// PinnacleCyPat GUI - Application state
// Copyright 2026 Maxwell McCormick
// SPDX-License-Identifier: Apache-2.0
// =============================================================================

//! Everything the screens read and write, and nothing that draws.
//!
//! Kept free of egui and of the platform crates so the rules that matter - which
//! tasks a plan runs, what a README edit does, how events update the run view -
//! are plain functions with unit tests. Screens take `&mut AppState` and return
//! an [`Action`] for `app.rs` to carry out; they never start work themselves.

use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::AtomicBool;

use pinnacle_core::engine::{
    Phase, ReadmeChoice, ReadmeInspection, RunEvent, RunPlan, RunSummary, TaskChoice,
};
use pinnacle_core::models::{ReadmeData, TaskResult};
use pinnacle_core::platform::{Concurrency, TaskSpec};
use pinnacle_core::{run_log, ui};

/// The steps, in the order a run walks through them.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Screen {
    Readme,
    Tasks,
    Confirm,
    Run,
    Results,
}

impl Screen {
    pub const ALL: [Screen; 5] = [
        Screen::Readme,
        Screen::Tasks,
        Screen::Confirm,
        Screen::Run,
        Screen::Results,
    ];

    pub fn title(self) -> &'static str {
        match self {
            Screen::Readme => "README",
            Screen::Tasks => "Tasks",
            Screen::Confirm => "Confirm",
            Screen::Run => "Run",
            Screen::Results => "Results",
        }
    }
}

/// What a screen asks `app.rs` to do. Screens only change state they own
/// (inputs, selections); anything that starts work goes through here.
#[derive(Debug, Clone)]
pub enum Action {
    Go(Screen),
    /// Find or read the README and parse it, changing nothing.
    Inspect(ReadmeChoice),
    /// Build the plan from the current state and start the run.
    StartRun,
    /// Stop between tasks; never mid-write.
    Cancel,
    OpenLog(PathBuf),
    /// Back to the README screen with a fresh selection, keeping the README.
    NewRun,
}

#[derive(Debug, Clone)]
pub enum TaskStatus {
    Waiting,
    Running(Phase),
    Done(TaskResult),
}

#[derive(Debug, Clone)]
pub struct TaskRow {
    pub name: String,
    pub concurrent: bool,
    pub status: TaskStatus,
}

/// One line of run output, as plain text: markup and ANSI removed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OutputLine {
    Text(String),
    Section(String),
}

pub struct RunView {
    pub dry_run: bool,
    pub rows: Vec<TaskRow>,
    pub output: Vec<OutputLine>,
    pub cancel: Arc<AtomicBool>,
    pub cancel_requested: bool,
    pub finished: bool,
}

pub struct AppState {
    pub screen: Screen,

    /// The platform's task table, in run order.
    pub tasks: &'static [TaskSpec],
    pub privileged: bool,
    pub privileged_role: &'static str,
    pub elevation_hint: &'static str,

    // --- README ----------------------------------------------------------
    /// What the user typed or browsed to; empty means "find it automatically".
    pub readme_path: String,
    pub inspecting: bool,
    pub inspection: Option<ReadmeInspection>,
    /// Hand-edited README data. When set, it replaces the parse for the run
    /// (`RunPlan::readme_override`) and the run log records the difference.
    pub edited: Option<ReadmeData>,

    // --- selection -------------------------------------------------------
    /// One entry per `tasks` row.
    pub selected: Vec<bool>,
    /// Preview by default: the harmless choice is the one you get by not
    /// reading.
    pub dry_run: bool,
    /// The second, explicit confirmation an applying run needs.
    pub apply_confirmed: bool,

    // --- run -------------------------------------------------------------
    pub run: Option<RunView>,
    pub summary: Option<RunSummary>,
    /// Set when a run could not start or the README could not be inspected.
    pub error: Option<String>,
}

impl AppState {
    pub fn new(
        tasks: &'static [TaskSpec],
        privileged: bool,
        privileged_role: &'static str,
        elevation_hint: &'static str,
    ) -> Self {
        Self {
            screen: Screen::Readme,
            tasks,
            privileged,
            privileged_role,
            elevation_hint,
            readme_path: String::new(),
            inspecting: false,
            inspection: None,
            edited: None,
            selected: vec![false; tasks.len()],
            dry_run: true,
            apply_confirmed: false,
            run: None,
            summary: None,
            error: None,
        }
    }

    /// The README the run will use: the hand-edited copy if there is one,
    /// otherwise what was parsed.
    pub fn readme_data(&self) -> Option<&ReadmeData> {
        self.edited
            .as_ref()
            .or_else(|| self.inspection.as_ref()?.data.as_ref())
    }

    pub fn readme_choice(&self) -> ReadmeChoice {
        let path = self.readme_path.trim();
        if path.is_empty() {
            ReadmeChoice::Auto
        } else {
            ReadmeChoice::Path(path.to_string())
        }
    }

    /// The selected task rows, in run order.
    pub fn selected_specs(&self) -> Vec<&'static TaskSpec> {
        self.tasks
            .iter()
            .zip(&self.selected)
            .filter(|(_, on)| **on)
            .map(|(spec, _)| spec)
            .collect()
    }

    /// May this run change the machine? Only elevated, only after the second
    /// confirmation. Anything else runs as a preview whatever `dry_run` says.
    pub fn effective_dry_run(&self) -> bool {
        self.dry_run || !self.privileged || !self.apply_confirmed
    }

    /// The command line this plan corresponds to, stamped into the run log so
    /// a GUI run can be repeated from a terminal.
    pub fn command_line(&self) -> String {
        let mut parts = vec!["(gui)".to_string()];
        match self.readme_choice() {
            ReadmeChoice::Auto => parts.push("--auto-readme".to_string()),
            ReadmeChoice::Path(p) => parts.push(format!("--readme \"{p}\"")),
            ReadmeChoice::None => {}
        }
        parts.extend(self.selected_specs().iter().map(|s| s.flag.to_string()));
        if self.effective_dry_run() {
            parts.push("--dry-run".to_string());
        }
        parts.join(" ")
    }

    /// The plan the engine runs. `None` with nothing selected.
    pub fn plan(&self, log_path: PathBuf, cancel: Arc<AtomicBool>) -> Option<RunPlan> {
        let specs = self.selected_specs();
        if specs.is_empty() {
            return None;
        }
        let readme = match &self.inspection {
            // Re-resolve exactly the document that was inspected, so the run
            // cannot quietly pick a different README than the one on screen.
            Some(ReadmeInspection {
                source: Some(source),
                ..
            }) => ReadmeChoice::Path(source.clone()),
            _ => ReadmeChoice::None,
        };
        Some(RunPlan {
            readme,
            readme_override: self.edited.clone(),
            tasks: TaskChoice::Flags(specs.iter().map(|s| s.flag.to_string()).collect()),
            dry_run: self.effective_dry_run(),
            log_path,
            command_line: self.command_line(),
            cancel,
        })
    }

    /// Start the run view for a plan that is about to be handed to the engine.
    pub fn begin_run(&mut self, plan: &RunPlan) {
        let rows = self
            .selected_specs()
            .iter()
            .map(|spec| TaskRow {
                name: spec.label.to_string(),
                concurrent: spec.concurrency == Concurrency::Concurrent,
                status: TaskStatus::Waiting,
            })
            .collect();
        self.run = Some(RunView {
            dry_run: plan.dry_run,
            rows,
            output: Vec::new(),
            cancel: plan.cancel.clone(),
            cancel_requested: false,
            finished: false,
        });
        self.summary = None;
        self.error = None;
        self.screen = Screen::Run;
    }

    /// Fold one engine event into the run view.
    pub fn apply_event(&mut self, event: RunEvent) {
        let Some(run) = self.run.as_mut() else {
            return;
        };
        match event {
            RunEvent::Line(line) => {
                if let Some(out) = output_line(&line) {
                    run.output.push(out);
                }
            }
            RunEvent::Readme(_) => {}
            RunEvent::TaskStarted { name, .. } => {
                row_for(&mut run.rows, &name).status = TaskStatus::Running(Phase::Reading);
            }
            RunEvent::TaskPhase { name, phase } => {
                row_for(&mut run.rows, &name).status = TaskStatus::Running(phase);
            }
            RunEvent::TaskFinished(result) => {
                let name = result.task_name.clone();
                row_for(&mut run.rows, &name).status = TaskStatus::Done(result);
            }
            RunEvent::Finished(summary) => {
                run.finished = true;
                self.summary = Some(summary);
                self.screen = Screen::Results;
            }
        }
    }

    /// Back to the start for another run, keeping the README and any edits.
    pub fn new_run(&mut self) {
        self.selected = vec![false; self.tasks.len()];
        self.dry_run = true;
        self.apply_confirmed = false;
        self.run = None;
        self.summary = None;
        self.error = None;
        self.screen = Screen::Readme;
    }
}

/// The row a task's events belong to. Matched on the task's own name, which
/// is what `TaskStarted` and `TaskResult` carry; a name the table did not
/// predict (a task that renames itself) gets a row of its own rather than
/// being dropped.
fn row_for<'a>(rows: &'a mut Vec<TaskRow>, name: &str) -> &'a mut TaskRow {
    let at = match rows.iter().position(|r| r.name == name) {
        Some(at) => at,
        None => {
            rows.push(TaskRow {
                name: name.to_string(),
                concurrent: false,
                status: TaskStatus::Waiting,
            });
            rows.len() - 1
        }
    };
    &mut rows[at]
}

fn output_line(line: &ui::Line) -> Option<OutputLine> {
    match line {
        ui::Line::Markup(text) => Some(OutputLine::Text(for_display(&ui::plain(text)))),
        ui::Line::Section(title) => Some(OutputLine::Section(for_display(&ui::plain(title)))),
        // Drawn tables and charts: the plain form is what the log keeps, and
        // what reads correctly without a terminal's box-drawing alignment.
        ui::Line::Rendered { plain, .. } if plain.is_empty() => None,
        ui::Line::Rendered { plain, .. } => Some(OutputLine::Text(for_display(plain))),
    }
}

/// The console's symbols, made readable in egui's default font.
///
/// The CLI decorates its output with emoji and dingbats (📊 ✓ ⚠ ❌ 💡) that
/// egui's bundled fonts lack, so they drew as empty boxes. The status marks
/// carry meaning and become words; the decorative ones are dropped. The run
/// log is untouched - this is display only.
pub fn for_display(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for c in text.chars() {
        match c {
            '✓' | '✔' | '✅' => out.push_str("OK"),
            '✗' | '✘' | '❌' => out.push('X'),
            '⚠' => out.push('!'),
            '\u{FE0F}' => {}
            c if is_decorative(c) => {}
            c => out.push(c),
        }
    }
    // Dropping a leading emoji leaves the space that followed it.
    match out.strip_prefix(' ') {
        Some(rest) if text.starts_with(|c: char| is_decorative(c)) => rest.to_string(),
        _ => out,
    }
}

fn is_decorative(c: char) -> bool {
    matches!(c as u32, 0x1F300..=0x1FAFF | 0x2600..=0x26FF | 0x2700..=0x27BF)
}

/// Where a GUI run writes its log: the same default the CLI uses.
pub fn default_log_path() -> PathBuf {
    run_log::default_log_path()
}

#[cfg(test)]
mod tests {
    use super::*;
    use pinnacle_core::models::SystemInfo;
    use pinnacle_core::task::Task;

    struct Nothing;

    #[async_trait::async_trait]
    impl Task for Nothing {
        fn name(&self) -> &str {
            "nothing"
        }
        fn description(&self) -> &str {
            ""
        }
        fn dry_run(&self) -> bool {
            true
        }
        fn set_dry_run(&mut self, _: bool) {}
        async fn read_system_state(&mut self) -> SystemInfo {
            SystemInfo::default()
        }
        async fn execute(&mut self) -> TaskResult {
            TaskResult::default()
        }
        async fn verify(&mut self) -> bool {
            true
        }
    }

    fn build(_: Option<&ReadmeData>) -> Box<dyn Task> {
        Box::new(Nothing)
    }

    static TASKS: [TaskSpec; 3] = [
        TaskSpec {
            flag: "--password-policy",
            short: "-p",
            help: "",
            label: "Password Policy",
            detail: "",
            needs_readme: false,
            concurrency: Concurrency::Sequential,
            build,
        },
        TaskSpec {
            flag: "--user-management",
            short: "-u",
            help: "",
            label: "User Management",
            detail: "",
            needs_readme: true,
            concurrency: Concurrency::Sequential,
            build,
        },
        TaskSpec {
            flag: "--dns-settings",
            short: "",
            help: "",
            label: "DNS Settings Audit",
            detail: "",
            needs_readme: false,
            concurrency: Concurrency::Concurrent,
            build,
        },
    ];

    fn state(privileged: bool) -> AppState {
        AppState::new(&TASKS, privileged, "root", "use sudo")
    }

    fn plan(s: &AppState) -> Option<RunPlan> {
        s.plan(PathBuf::from("log.txt"), Arc::new(AtomicBool::new(false)))
    }

    #[test]
    fn nothing_selected_makes_no_plan() {
        assert!(plan(&state(true)).is_none());
    }

    #[test]
    fn the_plan_names_the_selected_flags_in_table_order() {
        let mut s = state(true);
        s.selected = vec![true, false, true];
        let p = plan(&s).unwrap();
        match p.tasks {
            TaskChoice::Flags(flags) => assert_eq!(flags, ["--password-policy", "--dns-settings"]),
            TaskChoice::All => panic!("expected named flags"),
        }
    }

    /// The harmless default must hold unless every gate is passed.
    #[test]
    fn a_run_applies_only_when_elevated_unticked_and_confirmed() {
        let mut s = state(true);
        s.selected = vec![true, false, false];
        assert!(plan(&s).unwrap().dry_run, "dry run is the default");

        s.dry_run = false;
        assert!(
            plan(&s).unwrap().dry_run,
            "applying needs the second confirmation"
        );

        s.apply_confirmed = true;
        assert!(!plan(&s).unwrap().dry_run);

        let mut unprivileged = state(false);
        unprivileged.selected = vec![true, false, false];
        unprivileged.dry_run = false;
        unprivileged.apply_confirmed = true;
        assert!(
            plan(&unprivileged).unwrap().dry_run,
            "never applies unelevated"
        );
    }

    #[test]
    fn the_run_uses_the_document_that_was_inspected_and_the_edits() {
        let mut s = state(true);
        s.selected = vec![true, false, false];
        s.inspection = Some(ReadmeInspection {
            source: Some("/opt/CyberPatriot/README.html".to_string()),
            data: Some(ReadmeData::default()),
            ..Default::default()
        });
        let edited = ReadmeData {
            critical_services: vec!["ssh".to_string()],
            ..Default::default()
        };
        s.edited = Some(edited.clone());
        let p = plan(&s).unwrap();
        assert!(
            matches!(p.readme, ReadmeChoice::Path(ref path) if path == "/opt/CyberPatriot/README.html")
        );
        assert_eq!(
            p.readme_override.unwrap().critical_services,
            edited.critical_services
        );
        assert_eq!(s.readme_data().unwrap().critical_services, ["ssh"]);
    }

    #[test]
    fn the_command_line_repeats_the_plan() {
        let mut s = state(true);
        s.readme_path = "C:\\CyberPatriot\\README.url".to_string();
        s.selected = vec![true, true, false];
        assert_eq!(
            s.command_line(),
            "(gui) --readme \"C:\\CyberPatriot\\README.url\" --password-policy --user-management --dry-run"
        );
    }

    #[test]
    fn events_drive_the_rows_and_finish_on_the_results_screen() {
        let mut s = state(true);
        s.selected = vec![true, false, true];
        let p = plan(&s).unwrap();
        s.begin_run(&p);
        assert_eq!(s.screen, Screen::Run);
        assert!(s.run.as_ref().unwrap().rows[1].concurrent);

        s.apply_event(RunEvent::TaskStarted {
            name: "Password Policy".to_string(),
            index: 0,
            total: 2,
            concurrent: false,
        });
        s.apply_event(RunEvent::TaskPhase {
            name: "Password Policy".to_string(),
            phase: Phase::Verifying,
        });
        assert!(matches!(
            s.run.as_ref().unwrap().rows[0].status,
            TaskStatus::Running(Phase::Verifying)
        ));

        s.apply_event(RunEvent::Line(ui::Line::Markup(
            "[green]✓ done[/]".to_string(),
        )));
        assert_eq!(
            s.run.as_ref().unwrap().output,
            [OutputLine::Text("OK done".to_string())]
        );

        s.apply_event(RunEvent::TaskFinished(TaskResult {
            task_name: "Password Policy".to_string(),
            success: true,
            ..Default::default()
        }));
        assert!(matches!(
            s.run.as_ref().unwrap().rows[0].status,
            TaskStatus::Done(_)
        ));

        s.apply_event(RunEvent::Finished(RunSummary {
            results: Vec::new(),
            fixes: Vec::new(),
            log_path: PathBuf::from("log.txt"),
            log_error: None,
            cancelled: false,
        }));
        assert_eq!(s.screen, Screen::Results);
        assert!(s.run.as_ref().unwrap().finished);
        assert!(s.summary.is_some());
    }

    #[test]
    fn console_symbols_become_readable_text() {
        assert_eq!(
            for_display("✓ All changes verified"),
            "OK All changes verified"
        );
        assert_eq!(
            for_display("⚠️ Overall Completion Rate: 0.0%"),
            "! Overall Completion Rate: 0.0%"
        );
        assert_eq!(
            for_display("❌ Overall Confidence Level"),
            "X Overall Confidence Level"
        );
        assert_eq!(for_display("💡 Tip: verify by hand"), "Tip: verify by hand");
        assert_eq!(
            for_display("📊 Reading current system state..."),
            "Reading current system state..."
        );
        assert_eq!(
            for_display("plain - 8.8.8.8 = Google"),
            "plain - 8.8.8.8 = Google"
        );
    }

    #[test]
    fn a_new_run_keeps_the_readme_and_resets_the_rest() {
        let mut s = state(true);
        s.edited = Some(ReadmeData::default());
        s.selected = vec![true, true, true];
        s.dry_run = false;
        s.apply_confirmed = true;
        s.new_run();
        assert!(s.edited.is_some());
        assert_eq!(s.selected, [false, false, false]);
        assert!(s.dry_run && !s.apply_confirmed);
        assert_eq!(s.screen, Screen::Readme);
    }
}
