// =============================================================================
// PinnacleCyPat GUI - Application state
// Copyright 2026 Maxwell McCormick
// SPDX-License-Identifier: Apache-2.0
// =============================================================================

//! Everything the tabs read and write, and nothing that draws.
//!
//! The workflow is: find the README (a picker of every location found, or a
//! path typed by hand) -> check and edit what was parsed -> choose tasks ->
//! **dry run** -> **real run** -> results. The rule that matters most lives
//! here, as a plain function with tests: a real run is offered only after a
//! completed dry run of exactly the same selection and README, so what the
//! person approves is what they previewed.
//!
//! Kept free of egui and of the platform crates. Tabs take `&mut AppState` and
//! return an [`Action`] for `app.rs` to carry out; they never start work.

use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::AtomicBool;
use std::time::{Duration, Instant};

use pinnacle_core::app_config::ReadmeCandidate;
use pinnacle_core::directives::Directive;
use pinnacle_core::engine::{
    Phase, ReadmeChoice, ReadmeInspection, RunEvent, RunPlan, RunSummary, TaskChoice,
};
use pinnacle_core::models::{ReadmeData, TaskResult};
use pinnacle_core::platform::{Concurrency, TaskSpec};
use pinnacle_core::{run_log, ui};

/// The three places in the app. README first: nothing else is meaningful until
/// it is right.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Tab {
    Readme,
    Run,
    Results,
}

impl Tab {
    pub const ALL: [Tab; 3] = [Tab::Readme, Tab::Run, Tab::Results];

    pub fn title(self) -> &'static str {
        match self {
            Tab::Readme => "README",
            Tab::Run => "Run",
            Tab::Results => "Results",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RunKind {
    /// Changes nothing; shows what a real run would do.
    Preview,
    /// Changes the machine.
    Real,
}

impl RunKind {
    pub fn title(self) -> &'static str {
        match self {
            RunKind::Preview => "Dry run",
            RunKind::Real => "Real run",
        }
    }
}

/// What a tab asks `app.rs` to do.
#[derive(Debug, Clone)]
pub enum Action {
    OpenTab(Tab),
    /// Look for every README location and open the picker.
    DiscoverReadme,
    /// Open or close the README locations picker.
    ShowLocations(bool),
    /// Parse this README (a location from the picker, or a typed path).
    UseReadme(String),
    /// Close the picker and carry on with no README.
    ContinueWithoutReadme,
    StartPreview,
    /// Open the confirmation for a real run. Only offered when
    /// [`AppState::real_run_gate`] allows it.
    OpenApplyDialog,
    CloseApplyDialog,
    /// Start the real run. Refused unless the gate allows it and the
    /// confirmation was ticked.
    StartReal,
    /// Stop between tasks; never mid-write.
    Cancel,
    OpenLog(PathBuf),
    CopyText(String),
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
    pub started: Option<Instant>,
    pub elapsed: Option<Duration>,
}

impl TaskRow {
    /// Time spent so far, or in total once finished.
    pub fn time(&self, now: Instant) -> Option<Duration> {
        self.elapsed
            .or_else(|| self.started.map(|s| now.duration_since(s)))
    }
}

/// One line of run output, as plain text: markup and ANSI removed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OutputLine {
    Text(String),
    Section(String),
}

/// One run, preview or real, from start to summary.
pub struct RunRecord {
    pub kind: RunKind,
    pub rows: Vec<TaskRow>,
    pub output: Vec<OutputLine>,
    pub cancel: Arc<AtomicBool>,
    pub cancel_requested: bool,
    pub started: Instant,
    pub ended: Option<Instant>,
    pub summary: Option<RunSummary>,
    /// What was run, to compare against when a real run is asked for.
    pub selection: Vec<bool>,
    pub readme_fingerprint: String,
}

impl RunRecord {
    pub fn finished(&self) -> bool {
        self.summary.is_some()
    }

    pub fn elapsed(&self, now: Instant) -> Duration {
        self.ended.unwrap_or(now).duration_since(self.started)
    }

    /// Tasks finished out of tasks in the run.
    pub fn progress(&self) -> (usize, usize) {
        let done = self
            .rows
            .iter()
            .filter(|r| matches!(r.status, TaskStatus::Done(_)))
            .count();
        (done, self.rows.len())
    }
}

/// A short message that fades after a few seconds.
pub struct Toast {
    pub text: String,
    pub success: bool,
    pub shown: Instant,
}

pub const TOAST_SECONDS: u64 = 6;

pub struct AppState {
    pub tab: Tab,

    /// The platform's task table, in run order.
    pub tasks: &'static [TaskSpec],
    pub privileged: bool,
    pub privileged_role: &'static str,
    pub elevation_hint: &'static str,

    // --- README ----------------------------------------------------------
    pub discovering: bool,
    /// Every README location found; `None` until discovery has run.
    pub candidates: Option<Vec<ReadmeCandidate>>,
    /// The README locations picker is open.
    pub locations_open: bool,
    /// The path typed by hand in the picker or on the README tab.
    pub readme_path: String,
    pub inspecting: bool,
    pub inspection: Option<ReadmeInspection>,
    /// Hand-edited README data. When set, it replaces the parse for the run
    /// (`RunPlan::readme_override`) and the run log records the difference.
    pub edited: Option<ReadmeData>,
    /// Ticks for the README's by-hand instructions, one per manual directive.
    pub hand_done: Vec<bool>,

    // --- runs ------------------------------------------------------------
    /// One entry per `tasks` row.
    pub selected: Vec<bool>,
    pub preview: Option<RunRecord>,
    pub real: Option<RunRecord>,
    /// The run in progress, if any.
    pub active: Option<RunKind>,
    pub apply_dialog_open: bool,
    /// The tick in the real-run confirmation.
    pub apply_confirmed: bool,
    /// Which run the Results tab shows.
    pub results_kind: RunKind,

    pub toast: Option<Toast>,
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
            tab: Tab::Readme,
            tasks,
            privileged,
            privileged_role,
            elevation_hint,
            discovering: false,
            candidates: None,
            locations_open: false,
            readme_path: String::new(),
            inspecting: false,
            inspection: None,
            edited: None,
            hand_done: Vec::new(),
            // Everything a README is not needed for is ticked by default: the
            // usual run is all of it, and a dry run comes first anyway.
            selected: tasks.iter().map(|t| !t.needs_readme).collect(),
            preview: None,
            real: None,
            active: None,
            apply_dialog_open: false,
            apply_confirmed: false,
            results_kind: RunKind::Preview,
            toast: None,
            error: None,
        }
    }

    // --- README ------------------------------------------------------------

    /// The README the run will use: the hand-edited copy if there is one,
    /// otherwise what was parsed.
    pub fn readme_data(&self) -> Option<&ReadmeData> {
        self.edited
            .as_ref()
            .or_else(|| self.inspection.as_ref()?.data.as_ref())
    }

    /// The document that was parsed, if any.
    pub fn readme_source(&self) -> Option<&str> {
        self.inspection.as_ref()?.source.as_deref()
    }

    /// The README's by-hand instructions, forensics first: they must be done
    /// before any task runs, because a remediation can destroy the evidence.
    pub fn manual_directives(&self) -> Vec<&Directive> {
        let mut manual: Vec<&Directive> = self
            .inspection
            .iter()
            .flat_map(|i| &i.directives)
            .filter(|d| d.handling.needs_a_person())
            .collect();
        manual.sort_by_key(|d| !d.subject.to_lowercase().contains("forensic"));
        manual
    }

    /// Install a finished inspection, enabling README-dependent tasks it makes
    /// possible and resetting the checklist to match its instructions.
    pub fn set_inspection(&mut self, inspection: ReadmeInspection) {
        let had_readme = self.readme_data().is_some();
        self.inspection = Some(inspection);
        self.edited = None;
        self.inspecting = false;
        self.hand_done = vec![false; self.manual_directives().len()];
        let has_readme = self.readme_data().is_some();
        for (on, spec) in self.selected.iter_mut().zip(self.tasks) {
            if spec.needs_readme {
                *on = has_readme && (*on || !had_readme);
            }
        }
    }

    /// Something that identifies the README a run used, so a real run can be
    /// refused when the edits changed after the dry run.
    pub fn readme_fingerprint(&self) -> String {
        format!("{:?}|{:?}", self.readme_source(), self.edited)
    }

    // --- planning ---------------------------------------------------------

    /// The selected task rows, in run order.
    pub fn selected_specs(&self) -> Vec<&'static TaskSpec> {
        self.tasks
            .iter()
            .zip(&self.selected)
            .filter(|(_, on)| **on)
            .map(|(spec, _)| spec)
            .collect()
    }

    /// May a real run be started now? `Err` says why not, for the screen to
    /// show next to the disabled button.
    pub fn real_run_gate(&self) -> Result<(), String> {
        if !self.privileged {
            return Err(format!(
                "Not running as {}. {}",
                self.privileged_role, self.elevation_hint
            ));
        }
        if self.active.is_some() {
            return Err("A run is in progress.".to_string());
        }
        let Some(preview) = &self.preview else {
            return Err(
                "Run a dry run first: a real run does what the dry run showed.".to_string(),
            );
        };
        if !preview.finished() {
            return Err("The dry run has not finished.".to_string());
        }
        if preview.summary.as_ref().is_some_and(|s| s.cancelled) {
            return Err("The dry run was cancelled. Run it again to completion.".to_string());
        }
        if preview.selection != self.selected {
            return Err("The task selection changed since the dry run. Run it again.".to_string());
        }
        if preview.readme_fingerprint != self.readme_fingerprint() {
            return Err(
                "The README or its edits changed since the dry run. Run it again.".to_string(),
            );
        }
        Ok(())
    }

    /// The command line a plan corresponds to, stamped into the run log so a
    /// GUI run can be repeated from a terminal.
    pub fn command_line(&self, kind: RunKind) -> String {
        let mut parts = vec!["(gui)".to_string()];
        if let Some(source) = self.readme_source() {
            parts.push(format!("--readme \"{source}\""));
        }
        parts.extend(self.selected_specs().iter().map(|s| s.flag.to_string()));
        if kind == RunKind::Preview {
            parts.push("--dry-run".to_string());
        }
        parts.join(" ")
    }

    /// The plan the engine runs, or why there is none.
    ///
    /// A real plan is built only when [`Self::real_run_gate`] passes and the
    /// confirmation is ticked: this is the second lock, independent of what any
    /// screen enabled.
    pub fn plan(
        &self,
        kind: RunKind,
        log_path: PathBuf,
        cancel: Arc<AtomicBool>,
    ) -> Result<RunPlan, String> {
        let specs = self.selected_specs();
        if specs.is_empty() {
            return Err("No tasks selected.".to_string());
        }
        if self.active.is_some() {
            return Err("A run is in progress.".to_string());
        }
        if kind == RunKind::Real {
            self.real_run_gate()?;
            if !self.apply_confirmed {
                return Err("Confirm the real run first.".to_string());
            }
        }
        let readme = match self.readme_source() {
            // Re-resolve exactly the document that was inspected, so the run
            // cannot quietly pick a different README than the one on screen.
            Some(source) => ReadmeChoice::Path(source.to_string()),
            None => ReadmeChoice::None,
        };
        Ok(RunPlan {
            readme,
            readme_override: self.edited.clone(),
            tasks: TaskChoice::Flags(specs.iter().map(|s| s.flag.to_string()).collect()),
            dry_run: kind == RunKind::Preview,
            log_path,
            command_line: self.command_line(kind),
            cancel,
        })
    }

    // --- running ----------------------------------------------------------

    /// Record a run that is about to be handed to the engine.
    pub fn begin_run(&mut self, kind: RunKind, plan: &RunPlan, now: Instant) {
        let rows = self
            .selected_specs()
            .iter()
            .map(|spec| TaskRow {
                name: spec.label.to_string(),
                concurrent: spec.concurrency == Concurrency::Concurrent,
                status: TaskStatus::Waiting,
                started: None,
                elapsed: None,
            })
            .collect();
        let record = RunRecord {
            kind,
            rows,
            output: Vec::new(),
            cancel: plan.cancel.clone(),
            cancel_requested: false,
            started: now,
            ended: None,
            summary: None,
            selection: self.selected.clone(),
            readme_fingerprint: self.readme_fingerprint(),
        };
        match kind {
            RunKind::Preview => {
                self.preview = Some(record);
                // A new preview supersedes the real run it would have unlocked.
                self.real = None;
            }
            RunKind::Real => self.real = Some(record),
        }
        self.active = Some(kind);
        self.apply_dialog_open = false;
        self.apply_confirmed = false;
        self.error = None;
        self.tab = Tab::Run;
    }

    pub fn active_record(&self) -> Option<&RunRecord> {
        match self.active? {
            RunKind::Preview => self.preview.as_ref(),
            RunKind::Real => self.real.as_ref(),
        }
    }

    pub fn active_record_mut(&mut self) -> Option<&mut RunRecord> {
        match self.active? {
            RunKind::Preview => self.preview.as_mut(),
            RunKind::Real => self.real.as_mut(),
        }
    }

    /// The run the Results tab should show by default: the real one if there
    /// is one, else the preview.
    pub fn latest_finished(&self) -> Option<RunKind> {
        if self.real.as_ref().is_some_and(RunRecord::finished) {
            Some(RunKind::Real)
        } else if self.preview.as_ref().is_some_and(RunRecord::finished) {
            Some(RunKind::Preview)
        } else {
            None
        }
    }

    pub fn record(&self, kind: RunKind) -> Option<&RunRecord> {
        match kind {
            RunKind::Preview => self.preview.as_ref(),
            RunKind::Real => self.real.as_ref(),
        }
    }

    /// Fold one engine event into the active run.
    pub fn apply_event(&mut self, event: RunEvent, now: Instant) {
        let Some(kind) = self.active else {
            return;
        };
        let Some(run) = self.active_record_mut() else {
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
                let row = row_for(&mut run.rows, &name);
                row.status = TaskStatus::Running(Phase::Reading);
                row.started = Some(now);
            }
            RunEvent::TaskPhase { name, phase } => {
                let row = row_for(&mut run.rows, &name);
                row.status = TaskStatus::Running(phase);
                row.started.get_or_insert(now);
            }
            RunEvent::TaskFinished(result) => {
                let name = result.task_name.clone();
                let row = row_for(&mut run.rows, &name);
                row.elapsed = row.started.map(|s| now.duration_since(s));
                row.status = TaskStatus::Done(result);
            }
            RunEvent::Finished(summary) => {
                let cancelled = summary.cancelled;
                let failed = summary.results.iter().filter(|r| !r.success).count();
                run.summary = Some(summary);
                run.ended = Some(now);
                self.active = None;
                self.results_kind = kind;
                self.tab = Tab::Results;
                self.toast = Some(Toast {
                    text: finish_message(kind, cancelled, failed),
                    success: !cancelled && failed == 0,
                    shown: now,
                });
            }
        }
    }

    /// Drop the toast once it has been up long enough.
    pub fn expire_toast(&mut self, now: Instant) {
        if self
            .toast
            .as_ref()
            .is_some_and(|t| now.duration_since(t.shown) >= Duration::from_secs(TOAST_SECONDS))
        {
            self.toast = None;
        }
    }
}

fn finish_message(kind: RunKind, cancelled: bool, failed: usize) -> String {
    match (cancelled, failed) {
        (true, _) => format!(
            "{} cancelled - no further tasks were started.",
            kind.title()
        ),
        (false, 0) => format!("{} finished.", kind.title()),
        (false, 1) => format!("{} finished - 1 task failed.", kind.title()),
        (false, n) => format!("{} finished - {n} tasks failed.", kind.title()),
    }
}

/// The row a task's events belong to, matched on the task's own name; a name
/// the table did not predict gets a row of its own rather than being dropped.
fn row_for<'a>(rows: &'a mut Vec<TaskRow>, name: &str) -> &'a mut TaskRow {
    let at = match rows.iter().position(|r| r.name == name) {
        Some(at) => at,
        None => {
            rows.push(TaskRow {
                name: name.to_string(),
                concurrent: false,
                status: TaskStatus::Waiting,
                started: None,
                elapsed: None,
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
        Some(rest) if text.starts_with(is_decorative) => rest.to_string(),
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
    use pinnacle_core::directives::Handling;
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

    fn cancel() -> Arc<AtomicBool> {
        Arc::new(AtomicBool::new(false))
    }

    fn summary(cancelled: bool) -> RunSummary {
        RunSummary {
            results: Vec::new(),
            fixes: Vec::new(),
            log_path: PathBuf::from("log.txt"),
            log_error: None,
            cancelled,
        }
    }

    fn inspection() -> ReadmeInspection {
        ReadmeInspection {
            source: Some("/opt/CyberPatriot/README.html".to_string()),
            data: Some(ReadmeData::default()),
            directives: vec![
                Directive {
                    subject: "the clock",
                    sentence: "Do not change the time".to_string(),
                    handling: Handling::SafeByInaction("no task touches it"),
                },
                Directive {
                    subject: "display manager",
                    sentence: "Keep GDM3".to_string(),
                    handling: Handling::Manual("check by hand"),
                },
                Directive {
                    subject: "forensics questions",
                    sentence: "Answer them".to_string(),
                    handling: Handling::Manual("answer first"),
                },
            ],
            attempts: Vec::new(),
        }
    }

    /// Run a preview to completion, as the engine would.
    fn finish_preview(s: &mut AppState, cancelled: bool) {
        let now = Instant::now();
        let plan = s
            .plan(RunKind::Preview, PathBuf::from("log.txt"), cancel())
            .unwrap();
        s.begin_run(RunKind::Preview, &plan, now);
        s.apply_event(RunEvent::Finished(summary(cancelled)), now);
    }

    #[test]
    fn readme_free_tasks_start_ticked_and_readme_tasks_wait_for_one() {
        let mut s = state(true);
        assert_eq!(s.selected, [true, false, true]);
        s.set_inspection(inspection());
        assert_eq!(
            s.selected,
            [true, true, true],
            "a README enables what needs it"
        );
    }

    #[test]
    fn the_checklist_lists_by_hand_items_forensics_first() {
        let mut s = state(true);
        s.set_inspection(inspection());
        let subjects: Vec<&str> = s.manual_directives().iter().map(|d| d.subject).collect();
        assert_eq!(subjects, ["forensics questions", "display manager"]);
        assert_eq!(s.hand_done, [false, false]);
    }

    #[test]
    fn a_real_run_needs_a_finished_matching_dry_run() {
        let mut s = state(true);
        assert!(s.real_run_gate().is_err(), "no dry run yet");

        finish_preview(&mut s, true);
        assert!(s.real_run_gate().err().unwrap().contains("cancelled"));

        finish_preview(&mut s, false);
        assert!(s.real_run_gate().is_ok());

        s.selected[0] = false;
        assert!(
            s.real_run_gate()
                .err()
                .unwrap()
                .contains("selection changed")
        );
        s.selected[0] = true;

        s.edited = Some(ReadmeData {
            critical_services: vec!["ssh".to_string()],
            ..Default::default()
        });
        assert!(s.real_run_gate().err().unwrap().contains("README"));
    }

    #[test]
    fn a_real_plan_needs_the_gate_and_the_tick_and_is_not_a_dry_run() {
        let mut s = state(true);
        finish_preview(&mut s, false);
        let log = || PathBuf::from("log.txt");
        assert!(
            s.plan(RunKind::Real, log(), cancel())
                .err()
                .unwrap()
                .contains("Confirm")
        );
        s.apply_confirmed = true;
        let plan = s.plan(RunKind::Real, log(), cancel()).unwrap();
        assert!(!plan.dry_run);
        assert!(!plan.command_line.contains("--dry-run"));
    }

    #[test]
    fn never_a_real_run_unelevated() {
        let mut s = state(false);
        finish_preview(&mut s, false);
        s.apply_confirmed = true;
        assert!(
            s.real_run_gate()
                .err()
                .unwrap()
                .contains("Not running as root")
        );
        assert!(s.plan(RunKind::Real, PathBuf::from("l"), cancel()).is_err());
        assert!(
            s.plan(RunKind::Preview, PathBuf::from("l"), cancel())
                .unwrap()
                .dry_run
        );
    }

    #[test]
    fn a_new_preview_supersedes_the_previous_real_run() {
        let mut s = state(true);
        finish_preview(&mut s, false);
        s.apply_confirmed = true;
        let now = Instant::now();
        let plan = s.plan(RunKind::Real, PathBuf::from("l"), cancel()).unwrap();
        s.begin_run(RunKind::Real, &plan, now);
        s.apply_event(RunEvent::Finished(summary(false)), now);
        assert!(s.real.is_some());
        finish_preview(&mut s, false);
        assert!(s.real.is_none());
    }

    #[test]
    fn the_run_uses_the_document_that_was_inspected_and_the_edits() {
        let mut s = state(true);
        s.set_inspection(inspection());
        let edited = ReadmeData {
            critical_services: vec!["ssh".to_string()],
            ..Default::default()
        };
        s.edited = Some(edited.clone());
        let p = s
            .plan(RunKind::Preview, PathBuf::from("l"), cancel())
            .unwrap();
        assert!(
            matches!(p.readme, ReadmeChoice::Path(ref path) if path == "/opt/CyberPatriot/README.html")
        );
        assert_eq!(
            p.readme_override.unwrap().critical_services,
            edited.critical_services
        );
        assert!(p.dry_run);
    }

    #[test]
    fn events_drive_rows_timings_and_finish_on_results_with_a_toast() {
        let mut s = state(true);
        let t0 = Instant::now();
        let plan = s
            .plan(RunKind::Preview, PathBuf::from("l"), cancel())
            .unwrap();
        s.begin_run(RunKind::Preview, &plan, t0);
        assert_eq!(s.tab, Tab::Run);
        assert_eq!(s.active, Some(RunKind::Preview));

        s.apply_event(
            RunEvent::TaskStarted {
                name: "Password Policy".to_string(),
                index: 0,
                total: 2,
                concurrent: false,
            },
            t0,
        );
        s.apply_event(
            RunEvent::Line(ui::Line::Markup("[green]✓ done[/]".to_string())),
            t0,
        );
        let t1 = t0 + Duration::from_secs(3);
        s.apply_event(
            RunEvent::TaskFinished(TaskResult {
                task_name: "Password Policy".to_string(),
                success: true,
                ..Default::default()
            }),
            t1,
        );
        let run = s.preview.as_ref().unwrap();
        assert_eq!(run.rows[0].elapsed, Some(Duration::from_secs(3)));
        assert_eq!(run.output, [OutputLine::Text("OK done".to_string())]);
        assert_eq!(run.progress(), (1, 2));

        s.apply_event(RunEvent::Finished(summary(false)), t1);
        assert_eq!(s.tab, Tab::Results);
        assert_eq!(s.active, None);
        assert_eq!(s.results_kind, RunKind::Preview);
        assert_eq!(s.toast.as_ref().unwrap().text, "Dry run finished.");
        s.expire_toast(t1 + Duration::from_secs(TOAST_SECONDS));
        assert!(s.toast.is_none());
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
}
