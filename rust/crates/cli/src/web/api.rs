// Copyright 2026 Maxwell McCormick
// SPDX-License-Identifier: Apache-2.0

//! The JSON the page and the server exchange: the action it posts and the
//! snapshot it is sent.
//!
//! The snapshot is built afresh from [`AppState`] every time rather than kept
//! in step with it, so the page can never show a state the session is not in.
//! The key names are the contract the page is written against
//! (`.scratch/web-api.md`); the tests at the bottom pin them.

use std::time::Instant;

use pinnacle_core::app_config::{self, ReadmeCandidate};
use pinnacle_core::directives::{Directive, Handling};
use pinnacle_core::engine::{Phase, RunSummary};
use pinnacle_core::models::{FixOutcome, ReadmeData};
use pinnacle_core::platform::Concurrency;
use pinnacle_core::session::{AppState, OutputLine, RunKind, RunRecord, Tab, TaskStatus};
use serde::{Deserialize, Serialize};

/// Output lines kept in a snapshot. A full run prints thousands, and the
/// snapshot is re-sent on every change; the run log keeps all of them.
pub const OUTPUT_LINES: usize = 400;

/// Shown next to a task that cannot be ticked without a README; the desktop
/// GUI's wording, so the two front ends read the same.
const NEEDS_README: &str = "Needs a README: load one on the README tab first.";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum TabName {
    Readme,
    Run,
    Results,
}

impl From<TabName> for Tab {
    fn from(t: TabName) -> Self {
        match t {
            TabName::Readme => Tab::Readme,
            TabName::Run => Tab::Run,
            TabName::Results => Tab::Results,
        }
    }
}

impl From<Tab> for TabName {
    fn from(t: Tab) -> Self {
        match t {
            Tab::Readme => TabName::Readme,
            Tab::Run => TabName::Run,
            Tab::Results => TabName::Results,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum KindName {
    Preview,
    Real,
}

impl From<KindName> for RunKind {
    fn from(k: KindName) -> Self {
        match k {
            KindName::Preview => RunKind::Preview,
            KindName::Real => RunKind::Real,
        }
    }
}

impl From<RunKind> for KindName {
    fn from(k: RunKind) -> Self {
        match k {
            RunKind::Preview => KindName::Preview,
            RunKind::Real => KindName::Real,
        }
    }
}

/// What the page asks for. Mirrors `session::Action` plus the edits the
/// desktop GUI makes directly on `AppState`, which a browser cannot.
#[derive(Debug, Clone, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum WebAction {
    Discover,
    UseReadme { path: String },
    ContinueWithoutReadme,
    SetSelected { index: usize, on: bool },
    SelectAll { on: bool },
    SetReadme { data: Box<ReadmeData> },
    RevertReadme,
    SetHandDone { index: usize, on: bool },
    StartPreview,
    OpenApply,
    CloseApply,
    SetApplyConfirmed { on: bool },
    StartReal,
    Cancel,
    SetTab { tab: TabName },
    SetResultsKind { kind: KindName },
    DismissError,
}

#[derive(Debug, Serialize)]
pub struct Snapshot {
    pub version: String,
    pub platform: &'static str,
    pub privileged: bool,
    pub privileged_role: &'static str,
    pub elevation_hint: &'static str,
    pub tab: TabName,
    pub discovering: bool,
    pub candidates: Option<Vec<ReadmeCandidate>>,
    pub locations_open: bool,
    pub readme_path: String,
    pub inspecting: bool,
    pub readme: Option<ReadmeView>,
    pub hand_done: Vec<bool>,
    pub manual: Vec<ManualItem>,
    pub tasks: Vec<TaskView>,
    pub gate: Gate,
    pub apply_dialog_open: bool,
    pub apply_confirmed: bool,
    pub active: Option<KindName>,
    pub preview: Option<RunView>,
    pub real: Option<RunView>,
    pub results_kind: KindName,
    pub latest_finished: Option<KindName>,
    pub command_line: CommandLines,
    pub toast: Option<ToastView>,
    pub error: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct ReadmeView {
    pub source: Option<String>,
    pub parsed: Option<ReadmeData>,
    pub effective: Option<ReadmeData>,
    pub edited: bool,
    pub attempts: Vec<String>,
    pub directives: Vec<DirectiveView>,
}

#[derive(Debug, Serialize)]
pub struct DirectiveView {
    pub subject: &'static str,
    pub sentence: String,
    pub handling: &'static str,
    pub detail: &'static str,
}

#[derive(Debug, Serialize)]
pub struct ManualItem {
    pub subject: &'static str,
    pub detail: &'static str,
}

#[derive(Debug, Serialize)]
pub struct TaskView {
    pub index: usize,
    pub flag: &'static str,
    pub label: &'static str,
    pub detail: &'static str,
    pub needs_readme: bool,
    pub concurrent: bool,
    pub selected: bool,
    pub enabled: bool,
    pub disabled_reason: Option<&'static str>,
}

#[derive(Debug, Serialize)]
pub struct Gate {
    pub ok: bool,
    pub reason: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct CommandLines {
    pub preview: String,
    pub real: String,
}

#[derive(Debug, Serialize)]
pub struct ToastView {
    pub text: String,
    pub success: bool,
}

#[derive(Debug, Serialize)]
pub struct RunView {
    pub kind: KindName,
    pub finished: bool,
    pub cancel_requested: bool,
    pub elapsed_secs: f64,
    pub progress: (usize, usize),
    pub rows: Vec<RowView>,
    pub output: Vec<LineView>,
    pub summary: Option<SummaryView>,
}

#[derive(Debug, Serialize)]
pub struct RowView {
    pub name: String,
    pub concurrent: bool,
    pub status: &'static str,
    pub message: Option<String>,
    pub secs: Option<f64>,
    pub success: Option<bool>,
}

#[derive(Debug, Serialize)]
pub struct LineView {
    pub section: bool,
    pub text: String,
}

#[derive(Debug, Serialize)]
pub struct SummaryView {
    pub cancelled: bool,
    pub log_path: String,
    pub log_error: Option<String>,
    pub results: Vec<ResultView>,
    pub fixes: Vec<FixView>,
}

#[derive(Debug, Serialize)]
pub struct ResultView {
    pub task: String,
    pub success: bool,
    pub verified: bool,
    pub attempted: i32,
    pub succeeded: i32,
    pub skipped: i32,
    pub confidence: i32,
    pub message: String,
    pub error_details: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct FixView {
    pub task: String,
    pub target: String,
    pub intent: String,
    pub before: Option<String>,
    pub action: String,
    pub outcome: &'static str,
    pub evidence: String,
}

/// Why task `i` cannot be ticked now, if it cannot. The same rule
/// [`crate::web::controller`] enforces when the page asks to tick it.
pub fn task_blocked(state: &AppState, i: usize) -> Option<&'static str> {
    (state.tasks[i].needs_readme && state.readme_data().is_none()).then_some(NEEDS_README)
}

pub fn snapshot(state: &AppState, platform: &'static str, now: Instant) -> Snapshot {
    let gate = state.real_run_gate();
    Snapshot {
        version: app_config::version_string(),
        platform,
        privileged: state.privileged,
        privileged_role: state.privileged_role,
        elevation_hint: state.elevation_hint,
        tab: state.tab.into(),
        discovering: state.discovering,
        candidates: state.candidates.clone(),
        locations_open: state.locations_open,
        readme_path: state.readme_path.clone(),
        inspecting: state.inspecting,
        readme: state.inspection.as_ref().map(|i| ReadmeView {
            source: i.source.clone(),
            parsed: i.data.clone(),
            effective: state.readme_data().cloned(),
            edited: state.edited.is_some(),
            attempts: i.attempts.clone(),
            directives: i.directives.iter().map(directive).collect(),
        }),
        hand_done: state.hand_done.clone(),
        manual: state
            .manual_directives()
            .iter()
            .map(|d| ManualItem {
                subject: d.subject,
                detail: d.handling.detail(),
            })
            .collect(),
        tasks: state
            .tasks
            .iter()
            .enumerate()
            .map(|(index, spec)| {
                let blocked = task_blocked(state, index);
                TaskView {
                    index,
                    flag: spec.flag,
                    label: spec.label,
                    detail: spec.detail,
                    needs_readme: spec.needs_readme,
                    concurrent: spec.concurrency == Concurrency::Concurrent,
                    selected: state.selected.get(index).copied().unwrap_or(false),
                    enabled: blocked.is_none(),
                    disabled_reason: blocked,
                }
            })
            .collect(),
        gate: Gate {
            ok: gate.is_ok(),
            reason: gate.err(),
        },
        apply_dialog_open: state.apply_dialog_open,
        apply_confirmed: state.apply_confirmed,
        active: state.active.map(Into::into),
        preview: state.preview.as_ref().map(|r| run_view(r, now)),
        real: state.real.as_ref().map(|r| run_view(r, now)),
        results_kind: state.results_kind.into(),
        latest_finished: state.latest_finished().map(Into::into),
        command_line: CommandLines {
            preview: state.command_line(RunKind::Preview),
            real: state.command_line(RunKind::Real),
        },
        toast: state.toast.as_ref().map(|t| ToastView {
            text: t.text.clone(),
            success: t.success,
        }),
        error: state.error.clone(),
    }
}

fn directive(d: &Directive) -> DirectiveView {
    DirectiveView {
        subject: d.subject,
        sentence: d.sentence.clone(),
        handling: match d.handling {
            Handling::Automated(_) => "automated",
            Handling::SafeByInaction(_) => "not_touched",
            Handling::Manual(_) => "manual",
        },
        detail: d.handling.detail(),
    }
}

fn run_view(run: &RunRecord, now: Instant) -> RunView {
    let skip = run.output.len().saturating_sub(OUTPUT_LINES);
    RunView {
        kind: run.kind.into(),
        finished: run.finished(),
        cancel_requested: run.cancel_requested,
        elapsed_secs: run.elapsed(now).as_secs_f64(),
        progress: run.progress(),
        rows: run
            .rows
            .iter()
            .map(|row| {
                let (status, message, success) = match &row.status {
                    TaskStatus::Waiting => ("waiting", None, None),
                    TaskStatus::Running(Phase::Reading) => ("reading", None, None),
                    TaskStatus::Running(Phase::Executing) => ("executing", None, None),
                    TaskStatus::Running(Phase::Verifying) => ("verifying", None, None),
                    TaskStatus::Done(r) => (
                        if r.success { "done" } else { "failed" },
                        Some(r.message.clone()),
                        Some(r.success),
                    ),
                };
                RowView {
                    name: row.name.clone(),
                    concurrent: row.concurrent,
                    status,
                    message,
                    secs: row.time(now).map(|d| d.as_secs_f64()),
                    success,
                }
            })
            .collect(),
        output: run.output[skip..]
            .iter()
            .map(|line| match line {
                OutputLine::Text(text) => LineView {
                    section: false,
                    text: text.clone(),
                },
                OutputLine::Section(text) => LineView {
                    section: true,
                    text: text.clone(),
                },
            })
            .collect(),
        summary: run.summary.as_ref().map(summary_view),
    }
}

fn summary_view(s: &RunSummary) -> SummaryView {
    SummaryView {
        cancelled: s.cancelled,
        log_path: s.log_path.to_string_lossy().into_owned(),
        log_error: s.log_error.clone(),
        results: s
            .results
            .iter()
            .map(|r| ResultView {
                task: r.task_name.clone(),
                success: r.success,
                verified: r.verified,
                attempted: r.items_attempted,
                succeeded: r.items_succeeded,
                skipped: r.items_skipped,
                confidence: r.confidence_percent,
                message: r.message.clone(),
                error_details: r.error_details.clone(),
            })
            .collect(),
        fixes: s
            .fixes
            .iter()
            .map(|f| FixView {
                task: f.task.clone(),
                target: f.target.clone(),
                intent: f.intent.clone(),
                before: f.before.clone(),
                action: f.action.clone(),
                outcome: match f.outcome {
                    FixOutcome::Fixed => "fixed",
                    FixOutcome::AlreadyCompliant => "already_ok",
                    FixOutcome::Failed => "failed",
                    FixOutcome::Unverified => "unverified",
                    FixOutcome::Skipped => "skipped",
                },
                evidence: f.evidence.clone(),
            })
            .collect(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::web::test_support::{TASKS, state};
    use pinnacle_core::engine::RunEvent;
    use pinnacle_core::models::{FixRecord, TaskResult};
    use pinnacle_core::ui;
    use std::path::PathBuf;
    use std::sync::Arc;
    use std::sync::atomic::AtomicBool;

    fn parse(json: &str) -> WebAction {
        serde_json::from_str(json).unwrap_or_else(|e| panic!("{json}: {e}"))
    }

    #[test]
    fn every_action_in_the_contract_parses() {
        let cases = [
            r#"{"type":"discover"}"#,
            r#"{"type":"use_readme","path":"/opt/CyberPatriot/README.html"}"#,
            r#"{"type":"continue_without_readme"}"#,
            r#"{"type":"set_selected","index":3,"on":true}"#,
            r#"{"type":"select_all","on":true}"#,
            r#"{"type":"set_readme","data":{"title":"t","operating_system":"","scenario":"",
                "administrators":[],"users":[],"required_software":[],"prohibited_software":[],
                "critical_services":["ssh"],"prohibited_services":[],"group_requirements":[],
                "users_to_create":[],"guidelines":[],"actionable_items":[],"sections":{}}}"#,
            r#"{"type":"revert_readme"}"#,
            r#"{"type":"set_hand_done","index":0,"on":true}"#,
            r#"{"type":"start_preview"}"#,
            r#"{"type":"open_apply"}"#,
            r#"{"type":"close_apply"}"#,
            r#"{"type":"set_apply_confirmed","on":true}"#,
            r#"{"type":"start_real"}"#,
            r#"{"type":"cancel"}"#,
            r#"{"type":"set_tab","tab":"results"}"#,
            r#"{"type":"set_results_kind","kind":"real"}"#,
            r#"{"type":"dismiss_error"}"#,
        ];
        let parsed: Vec<WebAction> = cases.iter().map(|c| parse(c)).collect();
        assert!(
            matches!(&parsed[1], WebAction::UseReadme { path } if path.ends_with("README.html"))
        );
        assert!(matches!(
            parsed[3],
            WebAction::SetSelected { index: 3, on: true }
        ));
        assert!(
            matches!(&parsed[5], WebAction::SetReadme { data } if data.critical_services == ["ssh"])
        );
        assert!(matches!(parsed[12], WebAction::StartReal));
        assert!(matches!(
            parsed[14],
            WebAction::SetTab {
                tab: TabName::Results
            }
        ));
        assert!(matches!(
            parsed[15],
            WebAction::SetResultsKind {
                kind: KindName::Real
            }
        ));
    }

    #[test]
    fn malformed_or_unknown_actions_are_rejected() {
        for bad in [
            r#"{"type":"start_rea"}"#,
            r#"{"type":"set_selected","index":"x","on":true}"#,
            r#"{"type":"set_tab","tab":"elsewhere"}"#,
            r#"{"path":"/x"}"#,
            "not json",
        ] {
            assert!(serde_json::from_str::<WebAction>(bad).is_err(), "{bad}");
        }
    }

    fn keys(v: &serde_json::Value) -> Vec<&str> {
        let mut k: Vec<&str> = v.as_object().unwrap().keys().map(String::as_str).collect();
        k.sort_unstable();
        k
    }

    #[test]
    fn the_snapshot_has_the_contract_keys() {
        let s = state(true);
        let v = serde_json::to_value(snapshot(&s, "Linux", Instant::now())).unwrap();
        let mut want = vec![
            "version",
            "platform",
            "privileged",
            "privileged_role",
            "elevation_hint",
            "tab",
            "discovering",
            "candidates",
            "locations_open",
            "readme_path",
            "inspecting",
            "readme",
            "hand_done",
            "manual",
            "tasks",
            "gate",
            "apply_dialog_open",
            "apply_confirmed",
            "active",
            "preview",
            "real",
            "results_kind",
            "latest_finished",
            "command_line",
            "toast",
            "error",
        ];
        want.sort_unstable();
        assert_eq!(keys(&v), want);
        assert_eq!(v["tab"], "readme");
        assert_eq!(v["results_kind"], "preview");
        assert!(v["readme"].is_null() && v["preview"].is_null() && v["active"].is_null());
        assert_eq!(v["gate"]["ok"], false);
        assert!(v["gate"]["reason"].as_str().unwrap().contains("dry run"));
        assert_eq!(
            keys(&v["tasks"][0]),
            [
                "concurrent",
                "detail",
                "disabled_reason",
                "enabled",
                "flag",
                "index",
                "label",
                "needs_readme",
                "selected"
            ]
        );
        assert_eq!(v["tasks"].as_array().unwrap().len(), TASKS.len());
        assert_eq!(v["tasks"][1]["enabled"], false, "needs a README");
        assert!(v["tasks"][1]["disabled_reason"].is_string());
        assert_eq!(keys(&v["command_line"]), ["preview", "real"]);
    }

    #[test]
    fn a_run_serialises_with_rows_output_and_summary() {
        let mut s = state(true);
        let now = Instant::now();
        let plan = s
            .plan(
                RunKind::Preview,
                PathBuf::from("log.txt"),
                Arc::new(AtomicBool::new(false)),
            )
            .unwrap();
        s.begin_run(RunKind::Preview, &plan, now);
        for i in 0..(OUTPUT_LINES + 5) {
            s.apply_event(RunEvent::Line(ui::Line::Markup(format!("line {i}"))), now);
        }
        let v = serde_json::to_value(snapshot(&s, "Linux", now)).unwrap();
        assert_eq!(v["active"], "preview");
        let run = &v["preview"];
        assert_eq!(
            keys(run),
            [
                "cancel_requested",
                "elapsed_secs",
                "finished",
                "kind",
                "output",
                "progress",
                "rows",
                "summary"
            ]
        );
        let output = run["output"].as_array().unwrap();
        assert_eq!(output.len(), OUTPUT_LINES, "only the tail is sent");
        assert_eq!(
            output.last().unwrap()["text"],
            format!("line {}", OUTPUT_LINES + 4)
        );
        assert_eq!(output[0]["section"], false);
        assert_eq!(run["progress"], serde_json::json!([0, 2]));
        assert_eq!(run["rows"][0]["status"], "waiting");

        s.apply_event(
            RunEvent::TaskFinished(TaskResult {
                task_name: "Password Policy".to_string(),
                success: false,
                message: "nope".to_string(),
                ..Default::default()
            }),
            now,
        );
        s.apply_event(
            RunEvent::Finished(RunSummary {
                results: vec![TaskResult::default()],
                fixes: vec![FixRecord {
                    task: "t".to_string(),
                    target: "x".to_string(),
                    intent: "i".to_string(),
                    before: None,
                    action: "a".to_string(),
                    outcome: FixOutcome::AlreadyCompliant,
                    evidence: "e".to_string(),
                }],
                log_path: PathBuf::from("log.txt"),
                log_error: None,
                cancelled: false,
            }),
            now,
        );
        let v = serde_json::to_value(snapshot(&s, "Linux", now)).unwrap();
        let run = &v["preview"];
        assert_eq!(run["finished"], true);
        assert_eq!(run["rows"][0]["status"], "failed");
        assert_eq!(run["rows"][0]["message"], "nope");
        assert_eq!(run["rows"][0]["success"], false);
        let summary = &run["summary"];
        assert_eq!(
            keys(summary),
            ["cancelled", "fixes", "log_error", "log_path", "results"]
        );
        assert_eq!(
            keys(&summary["results"][0]),
            [
                "attempted",
                "confidence",
                "error_details",
                "message",
                "skipped",
                "succeeded",
                "success",
                "task",
                "verified"
            ]
        );
        assert_eq!(summary["fixes"][0]["outcome"], "already_ok");
        assert_eq!(v["latest_finished"], "preview");
        assert_eq!(v["tab"], "results");
        assert_eq!(v["toast"]["success"], false);
        assert_eq!(v["gate"]["ok"], true);
    }
}
