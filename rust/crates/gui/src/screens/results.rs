// =============================================================================
// PinnacleCyPat GUI - Results screen
// Copyright 2026 Maxwell McCormick
// SPDX-License-Identifier: Apache-2.0
// =============================================================================

use eframe::egui::{self, Color32, RichText};
use pinnacle_core::engine::RunSummary;
use pinnacle_core::models::{FixOutcome, FixRecord};

use crate::state::{Action, AppState};

const GREEN: Color32 = Color32::from_rgb(90, 200, 120);
const RED: Color32 = Color32::from_rgb(240, 100, 100);
const AMBER: Color32 = Color32::from_rgb(230, 190, 80);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Filter {
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

    fn label(self) -> &'static str {
        match self {
            Filter::All => "All",
            Filter::Outcome(o) => outcome_label(o),
        }
    }

    pub fn matches(self, outcome: FixOutcome) -> bool {
        match self {
            Filter::All => true,
            Filter::Outcome(o) => o == outcome,
        }
    }
}

fn outcome_label(outcome: FixOutcome) -> &'static str {
    match outcome {
        FixOutcome::Failed => "Failed",
        FixOutcome::Unverified => "Unverified",
        FixOutcome::Fixed => "Fixed",
        FixOutcome::AlreadyCompliant => "Already OK",
        FixOutcome::Skipped => "Skipped",
    }
}

fn outcome_color(outcome: FixOutcome) -> Color32 {
    match outcome {
        FixOutcome::Failed => RED,
        FixOutcome::Unverified => AMBER,
        FixOutcome::Fixed | FixOutcome::AlreadyCompliant => GREEN,
        FixOutcome::Skipped => Color32::GRAY,
    }
}

/// Lower sorts first: what needs a person's attention leads the ledger.
/// Unverified ranks below Failed but above everything that is fine, because an
/// unconfirmed write may or may not have worked.
pub fn severity(outcome: FixOutcome) -> u8 {
    match outcome {
        FixOutcome::Failed => 0,
        FixOutcome::Unverified => 1,
        FixOutcome::Skipped => 2,
        FixOutcome::Fixed => 3,
        FixOutcome::AlreadyCompliant => 4,
    }
}

/// Counts in `Filter::CHOICES[1..]` order: failed, unverified, fixed,
/// already OK, skipped.
pub fn counts(fixes: &[FixRecord]) -> [usize; 5] {
    let mut out = [0; 5];
    for f in fixes {
        let at = Filter::CHOICES[1..]
            .iter()
            .position(|c| c.matches(f.outcome))
            .expect("every outcome has a filter");
        out[at] += 1;
    }
    out
}

/// Indexes into `fixes` that pass the filter, most severe first. The sort is
/// stable so records keep the order the engine produced within an outcome.
pub fn visible(fixes: &[FixRecord], filter: Filter) -> Vec<usize> {
    let mut idx: Vec<usize> = (0..fixes.len())
        .filter(|&i| filter.matches(fixes[i].outcome))
        .collect();
    idx.sort_by_key(|&i| severity(fixes[i].outcome));
    idx
}

pub fn show(ui: &mut egui::Ui, state: &mut AppState) -> Option<Action> {
    let Some(summary) = state.summary.as_ref() else {
        ui.label("No results yet.");
        return None;
    };
    let mut action = None;
    let filter_id = ui.scope_id().with("results_filter");
    let mut filter = ui
        .data(|d| d.get_temp::<Filter>(filter_id))
        .unwrap_or(Filter::All);

    ui.horizontal(|ui| {
        ui.heading("Results");
        ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
            if ui.button("New run").clicked() {
                action = Some(Action::NewRun);
            }
            if ui.button("Open run log").clicked() {
                action = Some(Action::OpenLog(summary.log_path.clone()));
            }
        });
    });
    if summary.cancelled {
        ui.colored_label(
            AMBER,
            "This run was cancelled: tasks after the stop point did not run.",
        );
    }
    if let Some(error) = &summary.log_error {
        ui.colored_label(RED, format!("The run log could not be written: {error}"));
    }
    ui.weak(format!("Log: {}", summary.log_path.display()));
    ui.add_space(4.0);

    egui::ScrollArea::vertical()
        .auto_shrink([false, false])
        .show(ui, |ui| {
            results_table(ui, summary);
            ui.add_space(10.0);
            ledger(ui, &summary.fixes, &mut filter);
        });

    ui.data_mut(|d| d.insert_temp(filter_id, filter));
    action
}

fn results_table(ui: &mut egui::Ui, summary: &RunSummary) {
    ui.label(RichText::new("Tasks").strong().size(15.0));
    egui::Grid::new("results_table")
        .striped(true)
        .num_columns(6)
        .spacing([14.0, 4.0])
        .show(ui, |ui| {
            for head in [
                "Task",
                "Result",
                "Verified",
                "Attempted / ok / skipped",
                "Confidence",
                "Message",
            ] {
                ui.label(RichText::new(head).strong());
            }
            ui.end_row();
            for r in &summary.results {
                ui.label(&r.task_name);
                if r.success {
                    ui.colored_label(GREEN, "Success");
                } else {
                    ui.colored_label(RED, "Failed");
                }
                if r.verified {
                    ui.colored_label(GREEN, "Yes");
                } else {
                    ui.colored_label(AMBER, "No");
                }
                ui.label(format!(
                    "{} / {} / {}",
                    r.items_attempted, r.items_succeeded, r.items_skipped
                ));
                ui.label(format!("{}%", r.confidence_percent));
                ui.add(egui::Label::new(&r.message).wrap());
                ui.end_row();
            }
        });
}

fn ledger(ui: &mut egui::Ui, fixes: &[FixRecord], filter: &mut Filter) {
    ui.label(RichText::new("Remediation ledger").strong().size(15.0));
    if fixes.is_empty() {
        ui.weak("No changes were recorded.");
        return;
    }
    let n = counts(fixes);
    ui.horizontal_wrapped(|ui| {
        for (choice, count) in Filter::CHOICES[1..].iter().zip(n) {
            if let Filter::Outcome(o) = choice {
                ui.label(
                    RichText::new(format!("{count} {}", outcome_label(*o)))
                        .color(outcome_color(*o)),
                );
                ui.add_space(8.0);
            }
        }
    });
    ui.horizontal_wrapped(|ui| {
        ui.label("Show:");
        for choice in Filter::CHOICES {
            ui.selectable_value(filter, choice, choice.label());
        }
    });
    ui.add_space(4.0);

    let rows = visible(fixes, *filter);
    if rows.is_empty() {
        ui.weak("Nothing matches this filter.");
    }
    for i in rows {
        let f = &fixes[i];
        ui.horizontal_wrapped(|ui| {
            ui.label(
                RichText::new(f.outcome.tag())
                    .monospace()
                    .strong()
                    .color(outcome_color(f.outcome)),
            );
            ui.label(RichText::new(&f.target).strong());
            ui.label(format!("({})", f.task));
        });
        ui.indent(("ledger", i), |ui| {
            field(ui, "Wanted", &f.intent);
            field(
                ui,
                "Before",
                f.before.as_deref().unwrap_or("(could not be read)"),
            );
            field(ui, "Did", &f.action);
            field(ui, "Evidence", &f.evidence);
        });
        ui.add_space(4.0);
        ui.separator();
    }
}

fn field(ui: &mut egui::Ui, name: &str, text: &str) {
    ui.horizontal_wrapped(|ui| {
        ui.label(RichText::new(format!("{name}:")).strong());
        ui.label(text);
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fix(outcome: FixOutcome) -> FixRecord {
        FixRecord {
            task: "t".to_string(),
            target: format!("{outcome:?}"),
            intent: String::new(),
            before: None,
            action: String::new(),
            outcome,
            evidence: String::new(),
        }
    }

    fn sample() -> Vec<FixRecord> {
        use FixOutcome::*;
        [Fixed, AlreadyCompliant, Skipped, Failed, Unverified, Fixed]
            .into_iter()
            .map(fix)
            .collect()
    }

    #[test]
    fn failed_then_unverified_lead_the_ledger() {
        let fixes = sample();
        let order: Vec<_> = visible(&fixes, Filter::All)
            .into_iter()
            .map(|i| fixes[i].outcome)
            .collect();
        assert_eq!(order[0], FixOutcome::Failed);
        assert_eq!(order[1], FixOutcome::Unverified);
        assert_eq!(*order.last().unwrap(), FixOutcome::AlreadyCompliant);
    }

    #[test]
    fn severity_is_a_strict_order_over_every_outcome() {
        let mut all = Filter::CHOICES[1..]
            .iter()
            .filter_map(|c| match c {
                Filter::Outcome(o) => Some(severity(*o)),
                Filter::All => None,
            })
            .collect::<Vec<_>>();
        all.sort();
        all.dedup();
        assert_eq!(all.len(), 5);
    }

    #[test]
    fn a_filter_shows_only_its_outcome() {
        let fixes = sample();
        let fixed = visible(&fixes, Filter::Outcome(FixOutcome::Fixed));
        assert_eq!(fixed.len(), 2);
        assert!(fixed.iter().all(|&i| fixes[i].outcome == FixOutcome::Fixed));
        assert_eq!(visible(&fixes, Filter::All).len(), fixes.len());
    }

    #[test]
    fn outcome_counts_add_up_to_the_ledger() {
        // failed, unverified, fixed, already ok, skipped
        assert_eq!(counts(&sample()), [1, 1, 2, 1, 1]);
    }

    #[test]
    fn records_keep_engine_order_within_an_outcome() {
        let mut fixes = vec![fix(FixOutcome::Fixed), fix(FixOutcome::Fixed)];
        fixes[0].target = "first".to_string();
        fixes[1].target = "second".to_string();
        assert_eq!(visible(&fixes, Filter::All), [0, 1]);
    }
}
