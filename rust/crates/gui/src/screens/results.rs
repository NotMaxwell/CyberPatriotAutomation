// =============================================================================
// PinnacleCyPat GUI - Results tab
// Copyright 2026 Maxwell McCormick
// SPDX-License-Identifier: Apache-2.0
// =============================================================================

//! What a run did, and the proof. Everything that decides what is shown
//! (ordering, filtering, counts, the comparison, the copied summary) is a pure
//! function over a [`RunSummary`] so it is tested without a window.

use std::collections::HashSet;
use std::time::{Duration, Instant};

use eframe::egui::{self, RichText};
use pinnacle_core::engine::RunSummary;
use pinnacle_core::models::{FixOutcome, FixRecord};

use crate::state::{Action, AppState, RunKind, RunRecord, Tab};
use crate::theme::{self, Tone};

/// Rows drawn before "Show more": a few hundred expandable rows would make
/// every frame slow, and nobody reads past the first screens of a sorted list.
const PAGE: usize = 200;

// --- pure logic ---------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Filter {
    All,
    Outcome(FixOutcome),
}

impl Filter {
    const CHOICES: [Filter; 6] = [
        Filter::All,
        Filter::Outcome(FixOutcome::Failed),
        Filter::Outcome(FixOutcome::Unverified),
        Filter::Outcome(FixOutcome::Fixed),
        Filter::Outcome(FixOutcome::AlreadyCompliant),
        Filter::Outcome(FixOutcome::Skipped),
    ];

    fn matches(self, outcome: FixOutcome) -> bool {
        match self {
            Filter::All => true,
            Filter::Outcome(o) => o == outcome,
        }
    }
}

/// In a dry run "Skipped" is what a real run would change, so it reads
/// "Would change" there.
fn outcome_label(outcome: FixOutcome, kind: RunKind) -> &'static str {
    match outcome {
        FixOutcome::Failed => "Failed",
        FixOutcome::Unverified => "Unverified",
        FixOutcome::Fixed => "Fixed",
        FixOutcome::AlreadyCompliant => "Already OK",
        FixOutcome::Skipped if kind == RunKind::Preview => "Would change",
        FixOutcome::Skipped => "Skipped",
    }
}

fn outcome_tone(outcome: FixOutcome) -> Tone {
    match outcome {
        FixOutcome::Failed => Tone::Danger,
        FixOutcome::Unverified => Tone::Warning,
        FixOutcome::Fixed => Tone::Success,
        FixOutcome::AlreadyCompliant => Tone::Accent,
        FixOutcome::Skipped => Tone::Neutral,
    }
}

/// Lower sorts first: what needs a person's attention leads. Unverified sits
/// right under Failed because an unconfirmed write may or may not have worked.
fn severity(outcome: FixOutcome) -> u8 {
    match outcome {
        FixOutcome::Failed => 0,
        FixOutcome::Unverified => 1,
        FixOutcome::Fixed => 2,
        FixOutcome::AlreadyCompliant => 3,
        FixOutcome::Skipped => 4,
    }
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
struct Counts {
    failed: usize,
    unverified: usize,
    fixed: usize,
    already_ok: usize,
    skipped: usize,
}

impl Counts {
    fn of(fixes: &[FixRecord]) -> Self {
        let mut c = Counts::default();
        for f in fixes {
            *c.slot(f.outcome) += 1;
        }
        c
    }

    fn slot(&mut self, outcome: FixOutcome) -> &mut usize {
        match outcome {
            FixOutcome::Failed => &mut self.failed,
            FixOutcome::Unverified => &mut self.unverified,
            FixOutcome::Fixed => &mut self.fixed,
            FixOutcome::AlreadyCompliant => &mut self.already_ok,
            FixOutcome::Skipped => &mut self.skipped,
        }
    }

    fn get(&self, outcome: FixOutcome) -> usize {
        let mut copy = *self;
        *copy.slot(outcome)
    }

    fn total(&self) -> usize {
        self.failed + self.unverified + self.fixed + self.already_ok + self.skipped
    }

    fn for_filter(&self, filter: Filter) -> usize {
        match filter {
            Filter::All => self.total(),
            Filter::Outcome(o) => self.get(o),
        }
    }
}

/// Case-insensitive match on what a person would search a ledger for.
fn matches_query(f: &FixRecord, query: &str) -> bool {
    let q = query.trim().to_lowercase();
    q.is_empty()
        || [&f.target, &f.intent, &f.evidence, &f.task]
            .iter()
            .any(|s| s.to_lowercase().contains(&q))
}

/// Indexes into `fixes`, most severe first. The sort is stable so records keep
/// the engine's order within an outcome.
fn visible(fixes: &[FixRecord], filter: Filter, query: &str) -> Vec<usize> {
    let mut idx: Vec<usize> = (0..fixes.len())
        .filter(|&i| filter.matches(fixes[i].outcome) && matches_query(&fixes[i], query))
        .collect();
    idx.sort_by_key(|&i| severity(fixes[i].outcome));
    idx
}

/// Tasks that succeeded, out of tasks that reported.
fn tasks_ok(summary: &RunSummary) -> (usize, usize) {
    (
        summary.results.iter().filter(|r| r.success).count(),
        summary.results.len(),
    )
}

/// The headline for a run, and the tone it is shown in.
fn banner(kind: RunKind, summary: &RunSummary) -> (Tone, String) {
    let c = Counts::of(&summary.fixes);
    if let Some(error) = &summary.log_error {
        return (
            Tone::Danger,
            format!("The run log could not be written: {error}"),
        );
    }
    if summary.cancelled {
        return (
            Tone::Warning,
            "This run was cancelled: tasks after the stop point did not run.".to_string(),
        );
    }
    match kind {
        RunKind::Preview => {
            let would = if c.skipped == 1 {
                "1 change would be made.".to_string()
            } else {
                format!("{} changes would be made.", c.skipped)
            };
            (
                Tone::Accent,
                format!("Dry run - nothing was changed. {would}"),
            )
        }
        RunKind::Real if c.failed + c.unverified == 0 => (
            Tone::Success,
            format!(
                "Real run complete. {} fixed, {} already correct, nothing failed.",
                c.fixed, c.already_ok
            ),
        ),
        RunKind::Real => (
            Tone::Danger,
            format!(
                "Real run finished with {} failed and {} unverified. Check them below.",
                c.failed, c.unverified
            ),
        ),
    }
}

/// Per-outcome counts of the dry run beside the real run. The dry run's
/// "would change" is its prediction, so a gap against the real run is worth a
/// look.
fn comparison(dry: &Counts, real: &Counts) -> Vec<(&'static str, usize, usize)> {
    [
        ("Failed", FixOutcome::Failed),
        ("Unverified", FixOutcome::Unverified),
        ("Fixed", FixOutcome::Fixed),
        ("Already OK", FixOutcome::AlreadyCompliant),
        ("Skipped / would change", FixOutcome::Skipped),
    ]
    .into_iter()
    .map(|(label, o)| (label, dry.get(o), real.get(o)))
    .collect()
}

/// Plain text for the clipboard: the counts, then every failed or unverified
/// item, which is what someone pasting this somewhere needs.
fn summary_text(kind: RunKind, summary: &RunSummary, elapsed: Duration) -> String {
    let c = Counts::of(&summary.fixes);
    let (ok, total) = tasks_ok(summary);
    let skipped = outcome_label(FixOutcome::Skipped, kind);
    let mut out = format!(
        "{} summary\nTasks succeeded: {ok}/{total}\nFixed: {}\nAlready OK: {}\n{skipped}: {}\nFailed: {}\nUnverified: {}\nTime: {}\n",
        kind.title(),
        c.fixed,
        c.already_ok,
        c.skipped,
        c.failed,
        c.unverified,
        theme::duration(elapsed),
    );
    if summary.cancelled {
        out.push_str("The run was cancelled.\n");
    }
    let mut bad: Vec<&FixRecord> = summary
        .fixes
        .iter()
        .filter(|f| matches!(f.outcome, FixOutcome::Failed | FixOutcome::Unverified))
        .collect();
    bad.sort_by_key(|f| severity(f.outcome));
    if !bad.is_empty() {
        out.push_str("\nNeeds attention:\n");
        for f in bad {
            out.push_str(&format!(
                "- {} {} ({}): {}\n",
                f.outcome.tag(),
                f.target,
                f.task,
                f.evidence
            ));
        }
    }
    out.push_str(&format!("\nRun log: {}\n", summary.log_path.display()));
    out
}

// --- screen-local state ---------------------------------------------------------

#[derive(Clone)]
struct Local {
    query: String,
    filter: Filter,
    expanded: HashSet<usize>,
    shown: usize,
}

impl Default for Local {
    fn default() -> Self {
        Self {
            query: String::new(),
            filter: Filter::All,
            expanded: HashSet::new(),
            shown: PAGE,
        }
    }
}

// --- screen ---------------------------------------------------------------------

pub fn show(ui: &mut egui::Ui, state: &mut AppState) -> Option<Action> {
    let Some(latest) = state.latest_finished() else {
        return empty_state(ui);
    };

    theme::page_title(
        ui,
        "Results",
        "What the run did, task by task, with the proof for every change.",
    );

    let finished = |s: &AppState, k| s.record(k).is_some_and(RunRecord::finished);
    let (has_dry, has_real) = (
        finished(state, RunKind::Preview),
        finished(state, RunKind::Real),
    );
    if !finished(state, state.results_kind) {
        state.results_kind = latest;
    }
    if has_dry && has_real {
        ui.horizontal(|ui| {
            for kind in [RunKind::Preview, RunKind::Real] {
                let on = state.results_kind == kind;
                if ui.selectable_label(on, kind.title()).clicked() {
                    state.results_kind = kind;
                }
            }
        });
        ui.add_space(theme::GAP - 4.0);
    }
    let kind = state.results_kind;

    let now = Instant::now();
    let record = state.record(kind)?;
    let summary = record.summary.as_ref()?;
    let elapsed = record.elapsed(now);
    let comparison_rows = match (state.preview.as_ref(), state.real.as_ref()) {
        (Some(d), Some(r)) if has_dry && has_real => Some(comparison(
            &Counts::of(&d.summary.as_ref()?.fixes),
            &Counts::of(&r.summary.as_ref()?.fixes),
        )),
        _ => None,
    };

    let local_id = ui.scope_id().with(("results_local", kind.title()));
    let mut local: Local = ui.data(|d| d.get_temp(local_id)).unwrap_or_default();
    let mut action = None;

    egui::ScrollArea::vertical()
        .auto_shrink([false, false])
        .show(ui, |ui| {
            let (tone, text) = banner(kind, summary);
            theme::callout(ui, tone, |ui| {
                ui.label(
                    RichText::new(text)
                        .family(theme::bold_family())
                        .color(tone.fg()),
                );
            });
            ui.add_space(theme::GAP);

            stat_row(ui, kind, summary, elapsed);
            ui.add_space(theme::GAP);

            if let Some(rows) = &comparison_rows {
                theme::card(ui, |ui| comparison_card(ui, rows));
                ui.add_space(theme::GAP);
            }

            theme::card(ui, |ui| tasks_card(ui, record, summary, now));
            ui.add_space(theme::GAP);

            theme::card(ui, |ui| ledger_card(ui, &summary.fixes, &mut local, kind));
            ui.add_space(theme::GAP);

            ui.horizontal(|ui| {
                if ui.add(theme::secondary_button("Open run log")).clicked() {
                    action = Some(Action::OpenLog(summary.log_path.clone()));
                }
                if ui.add(theme::secondary_button("Copy summary")).clicked() {
                    action = Some(Action::CopyText(summary_text(kind, summary, elapsed)));
                }
                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    if ui.add(theme::primary_button("New dry run")).clicked() {
                        action = Some(Action::OpenTab(Tab::Run));
                    }
                });
            });
            ui.add_space(theme::GAP);
        });

    ui.data_mut(|d| d.insert_temp(local_id, local));
    action
}

fn empty_state(ui: &mut egui::Ui) -> Option<Action> {
    let mut action = None;
    theme::page_title(ui, "Results", "Nothing has run yet.");
    theme::card(ui, |ui| {
        ui.add_space(12.0);
        ui.vertical_centered(|ui| {
            ui.label(
                RichText::new("Run a dry run to see what would change")
                    .size(18.0)
                    .family(theme::bold_family()),
            );
            ui.label(theme::muted(
                "A dry run reads this machine and reports every change it would make. It changes nothing.",
            ));
            ui.add_space(8.0);
            if ui.add(theme::primary_button("Go to Run")).clicked() {
                action = Some(Action::OpenTab(Tab::Run));
            }
        });
        ui.add_space(12.0);
    });
    action
}

fn stat_row(ui: &mut egui::Ui, kind: RunKind, summary: &RunSummary, elapsed: Duration) {
    let c = Counts::of(&summary.fixes);
    let (ok, total) = tasks_ok(summary);
    let nonzero = |n: usize, tone: Tone| if n == 0 { Tone::Neutral } else { tone };
    ui.horizontal_wrapped(|ui| {
        ui.spacing_mut().item_spacing = egui::vec2(10.0, 10.0);
        theme::stat(
            ui,
            "Fixed",
            c.fixed.to_string(),
            nonzero(c.fixed, Tone::Success),
        );
        theme::stat(ui, "Already OK", c.already_ok.to_string(), Tone::Accent);
        theme::stat(
            ui,
            outcome_label(FixOutcome::Skipped, kind),
            c.skipped.to_string(),
            Tone::Neutral,
        );
        theme::stat(
            ui,
            "Failed",
            c.failed.to_string(),
            nonzero(c.failed, Tone::Danger),
        );
        theme::stat(
            ui,
            "Unverified",
            c.unverified.to_string(),
            nonzero(c.unverified, Tone::Warning),
        );
        theme::stat(
            ui,
            "Tasks succeeded",
            format!("{ok}/{total}"),
            if ok == total {
                Tone::Success
            } else {
                Tone::Danger
            },
        );
        theme::stat(ui, "Total time", theme::duration(elapsed), Tone::Neutral);
    });
}

fn comparison_card(ui: &mut egui::Ui, rows: &[(&'static str, usize, usize)]) {
    theme::section(
        ui,
        "Dry run vs real run",
        Some("The dry run's prediction beside what the real run did."),
    );
    egui::Grid::new("results_compare")
        .num_columns(3)
        .spacing([28.0, 6.0])
        .show(ui, |ui| {
            ui.label(
                RichText::new("Outcome")
                    .family(theme::bold_family())
                    .color(theme::MUTED),
            );
            ui.label(
                RichText::new("Dry run")
                    .family(theme::bold_family())
                    .color(theme::MUTED),
            );
            ui.label(
                RichText::new("Real run")
                    .family(theme::bold_family())
                    .color(theme::MUTED),
            );
            ui.end_row();
            for (label, dry, real) in rows {
                ui.label(*label);
                ui.label(dry.to_string());
                ui.label(real.to_string());
                ui.end_row();
            }
        });
}

/// One fixed-width cell, so header and rows line up without a Grid: a Grid
/// sizes rows from the tallest wrapped message and stretched the pills.
fn cell(ui: &mut egui::Ui, width: f32, add: impl FnOnce(&mut egui::Ui)) {
    ui.allocate_ui_with_layout(
        egui::vec2(width, 26.0),
        egui::Layout::left_to_right(egui::Align::Center),
        |ui| {
            ui.set_width(width);
            add(ui);
        },
    );
}

fn tasks_card(ui: &mut egui::Ui, record: &RunRecord, summary: &RunSummary, now: Instant) {
    const W: [f32; 6] = [160.0, 74.0, 74.0, 120.0, 82.0, 48.0];
    theme::section(ui, "Tasks", None);
    ui.spacing_mut().item_spacing.y = 4.0;
    let heads = [
        "Task",
        "Result",
        "Verified",
        "Tried / ok / skip",
        "Confidence",
        "Time",
    ];
    ui.horizontal(|ui| {
        for (head, w) in heads.iter().zip(W) {
            cell(ui, w, |ui| {
                ui.label(
                    RichText::new(*head)
                        .family(theme::bold_family())
                        .size(12.5)
                        .color(theme::MUTED),
                );
            });
        }
    });
    for r in &summary.results {
        ui.separator();
        ui.horizontal(|ui| {
            cell(ui, W[0], |ui| {
                ui.add(
                    egui::Label::new(RichText::new(&r.task_name).family(theme::bold_family()))
                        .truncate(),
                );
            });
            cell(ui, W[1], |ui| {
                if r.success {
                    theme::pill(ui, "Success", Tone::Success);
                } else {
                    theme::pill(ui, "Failed", Tone::Danger);
                }
            });
            cell(ui, W[2], |ui| {
                if r.verified {
                    theme::pill(ui, "Yes", Tone::Success);
                } else {
                    theme::pill(ui, "No", Tone::Warning);
                }
            });
            cell(ui, W[3], |ui| {
                ui.label(format!(
                    "{} / {} / {}",
                    r.items_attempted, r.items_succeeded, r.items_skipped
                ));
            });
            cell(ui, W[4], |ui| {
                ui.label(format!("{}%", r.confidence_percent));
            });
            let time = record
                .rows
                .iter()
                .find(|row| row.name == r.task_name)
                .and_then(|row| row.time(now));
            cell(ui, W[5], |ui| {
                ui.label(time.map(theme::duration).unwrap_or_else(|| "-".into()));
            });
        });
        ui.add(egui::Label::new(theme::muted(&r.message)).wrap());
    }
}

fn ledger_card(ui: &mut egui::Ui, fixes: &[FixRecord], local: &mut Local, kind: RunKind) {
    theme::section(
        ui,
        "Changes and proof",
        Some(
            "Each record says what was wanted, what was there, what was done, and how it was checked.",
        ),
    );
    if fixes.is_empty() {
        ui.label(theme::muted("No changes were recorded."));
        return;
    }
    let counts = Counts::of(fixes);

    ui.add(
        egui::TextEdit::singleline(&mut local.query)
            .hint_text("Search target, intent, evidence or task")
            .desired_width(f32::INFINITY),
    );
    ui.horizontal_wrapped(|ui| {
        for choice in Filter::CHOICES {
            let label = match choice {
                Filter::All => "All",
                Filter::Outcome(o) => outcome_label(o, kind),
            };
            let text = format!("{label}  {}", counts.for_filter(choice));
            if ui.selectable_label(local.filter == choice, text).clicked() {
                local.filter = choice;
                local.shown = PAGE;
            }
        }
    });
    ui.add_space(4.0);

    let rows = visible(fixes, local.filter, &local.query);
    if rows.is_empty() {
        ui.label(theme::muted("Nothing matches."));
        return;
    }
    for &i in rows.iter().take(local.shown) {
        ledger_row(ui, i, &fixes[i], local, kind);
    }
    if rows.len() > local.shown {
        ui.add_space(6.0);
        let more = rows.len() - local.shown;
        if ui
            .add(theme::secondary_button(&format!("Show more ({more} left)")))
            .clicked()
        {
            local.shown += PAGE;
        }
    }
}

fn ledger_row(ui: &mut egui::Ui, i: usize, f: &FixRecord, local: &mut Local, kind: RunKind) {
    let open = local.expanded.contains(&i);
    let frame = egui::Frame::new()
        .fill(if open {
            ui.visuals().faint_bg_color
        } else {
            theme::SURFACE
        })
        .stroke(egui::Stroke::new(1.0, theme::BORDER))
        .corner_radius(egui::CornerRadius::same(8))
        .inner_margin(egui::Margin::symmetric(10, 7))
        .show(ui, |ui| {
            ui.set_width(ui.available_width());
            ui.horizontal(|ui| {
                theme::pill(ui, outcome_label(f.outcome, kind), outcome_tone(f.outcome));
                ui.add(
                    egui::Label::new(RichText::new(&f.target).family(theme::bold_family()))
                        .truncate(),
                );
                ui.label(theme::muted(&f.task));
            });
            if open {
                ui.add_space(4.0);
                field(ui, "Wanted", &f.intent);
                field(
                    ui,
                    "Before",
                    f.before.as_deref().unwrap_or("(could not be read)"),
                );
                field(ui, "Did", &f.action);
                field(ui, "Evidence", &f.evidence);
            }
        });
    let click = ui.interact(
        frame.response.rect,
        ui.scope_id().with(("ledger_row", i)),
        egui::Sense::click(),
    );
    if click.hovered() {
        ui.ctx().set_cursor_icon(egui::CursorIcon::PointingHand);
    }
    if click.clicked() && !local.expanded.remove(&i) {
        local.expanded.insert(i);
    }
    ui.add_space(2.0);
}

fn field(ui: &mut egui::Ui, name: &str, text: &str) {
    ui.horizontal_top(|ui| {
        ui.add_sized(
            [64.0, 0.0],
            egui::Label::new(RichText::new(name).size(12.5).color(theme::MUTED)),
        );
        ui.add(egui::Label::new(text).wrap());
    });
}

// --- tests ------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use FixOutcome::*;

    fn fix(outcome: FixOutcome, target: &str) -> FixRecord {
        FixRecord {
            task: "Services".to_string(),
            target: target.to_string(),
            intent: "Disable it".to_string(),
            before: None,
            action: String::new(),
            outcome,
            evidence: "read back: disabled".to_string(),
        }
    }

    fn summary(outcomes: &[FixOutcome]) -> RunSummary {
        RunSummary {
            results: Vec::new(),
            fixes: outcomes
                .iter()
                .map(|&o| fix(o, &format!("{o:?}")))
                .collect(),
            log_path: "/tmp/run.log".into(),
            log_error: None,
            cancelled: false,
        }
    }

    fn sample() -> RunSummary {
        summary(&[Fixed, AlreadyCompliant, Skipped, Failed, Unverified, Fixed])
    }

    #[test]
    fn severity_orders_failed_unverified_fixed_ok_skipped() {
        let s = sample();
        let order: Vec<_> = visible(&s.fixes, Filter::All, "")
            .into_iter()
            .map(|i| s.fixes[i].outcome)
            .collect();
        assert_eq!(
            order,
            [Failed, Unverified, Fixed, Fixed, AlreadyCompliant, Skipped]
        );
    }

    #[test]
    fn a_filter_shows_only_its_outcome() {
        let s = sample();
        let v = visible(&s.fixes, Filter::Outcome(Fixed), "");
        assert_eq!(v.len(), 2);
        assert!(v.iter().all(|&i| s.fixes[i].outcome == Fixed));
    }

    #[test]
    fn search_is_case_insensitive_across_fields() {
        let mut s = sample();
        s.fixes[0].target = "HKLM\\Software\\Telnet".into();
        s.fixes[1].evidence = "Value is TELNET-off".into();
        s.fixes[2].task = "telnet task".into();
        s.fixes[3].intent = "Turn Telnet off".into();
        assert_eq!(visible(&s.fixes, Filter::All, "telnet").len(), 4);
        assert_eq!(visible(&s.fixes, Filter::All, "  ").len(), 6);
        assert!(visible(&s.fixes, Filter::All, "nonesuch").is_empty());
        assert_eq!(
            visible(&s.fixes, Filter::Outcome(Failed), "telnet").len(),
            1
        );
    }

    #[test]
    fn counts_add_up() {
        let c = Counts::of(&sample().fixes);
        assert_eq!(
            c,
            Counts {
                failed: 1,
                unverified: 1,
                fixed: 2,
                already_ok: 1,
                skipped: 1
            }
        );
        assert_eq!(c.total(), 6);
        assert_eq!(c.for_filter(Filter::All), 6);
        assert_eq!(c.for_filter(Filter::Outcome(Fixed)), 2);
    }

    #[test]
    fn dry_run_banner_counts_would_be_changes() {
        let (tone, text) = banner(RunKind::Preview, &summary(&[Skipped, Skipped, Fixed]));
        assert_eq!(tone, Tone::Accent);
        assert!(text.contains("nothing was changed"));
        assert!(text.contains("2 changes would be made"));
        let (_, one) = banner(RunKind::Preview, &summary(&[Skipped]));
        assert!(one.contains("1 change would be made"));
    }

    #[test]
    fn real_run_banner_follows_failures() {
        assert_eq!(banner(RunKind::Real, &summary(&[Fixed])).0, Tone::Success);
        assert_eq!(
            banner(RunKind::Real, &summary(&[Fixed, Failed])).0,
            Tone::Danger
        );
        assert_eq!(
            banner(RunKind::Real, &summary(&[Unverified])).0,
            Tone::Danger
        );
    }

    #[test]
    fn cancelled_and_log_errors_override_the_headline() {
        let mut s = summary(&[Fixed]);
        s.cancelled = true;
        assert_eq!(banner(RunKind::Real, &s).0, Tone::Warning);
        s.log_error = Some("disk full".into());
        let (tone, text) = banner(RunKind::Real, &s);
        assert_eq!(tone, Tone::Danger);
        assert!(text.contains("disk full"));
    }

    #[test]
    fn comparison_puts_dry_and_real_counts_side_by_side() {
        let dry = Counts::of(&summary(&[Skipped, Skipped, AlreadyCompliant]).fixes);
        let real = Counts::of(&summary(&[Fixed, Failed, AlreadyCompliant]).fixes);
        let rows = comparison(&dry, &real);
        assert_eq!(rows.len(), 5);
        assert!(rows.contains(&("Skipped / would change", 2, 0)));
        assert!(rows.contains(&("Fixed", 0, 1)));
        assert!(rows.contains(&("Failed", 0, 1)));
        assert!(rows.contains(&("Already OK", 1, 1)));
    }

    #[test]
    fn summary_text_lists_counts_and_failures_only() {
        let mut s = sample();
        s.fixes[3].target = "sshd PermitRootLogin".into();
        let text = summary_text(RunKind::Real, &s, Duration::from_secs(75));
        assert!(text.contains("Real run summary"));
        assert!(text.contains("Fixed: 2"));
        assert!(text.contains("Failed: 1"));
        assert!(text.contains("Time: 1:15"));
        assert!(text.contains("FAILED sshd PermitRootLogin"));
        assert!(text.contains("UNVERIFIED"));
        assert!(!text.contains("ALREADY OK"));
        assert!(text.contains("/tmp/run.log"));
        let dry = summary_text(RunKind::Preview, &s, Duration::ZERO);
        assert!(dry.contains("Would change: 1"));
    }
}
