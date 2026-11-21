// =============================================================================
// PinnacleCyPat GUI - Run tab
// Copyright 2026 Maxwell McCormick
// SPDX-License-Identifier: Apache-2.0
// =============================================================================

//! The Run tab: choose tasks, dry run, real run, and watching a run in
//! progress. The real-run confirmation dialog lives here too.

use std::time::Instant;

use eframe::egui::{self, Color32, RichText};
use pinnacle_core::engine::Phase;
use pinnacle_core::models::FixOutcome;
use pinnacle_core::platform::Concurrency;

use crate::state::{Action, AppState, OutputLine, RunKind, RunRecord, Tab, TaskRow, TaskStatus};
use crate::theme::{self, Tone};

const STEPS: [&str; 4] = ["Select tasks", "Dry run", "Real run", "Results"];
const NEEDS_README: &str = "Needs a README: load one on the README tab first.";

// --- pure decisions ----------------------------------------------------------

/// Which workflow step (1-4) the user is at.
///
/// A dry run that no longer matches the selection or README does not count: the
/// user has to do it again, so they are back at step 1.
pub fn workflow_step(active: Option<RunKind>, real_finished: bool, preview_current: bool) -> usize {
    match active {
        Some(RunKind::Preview) => 2,
        Some(RunKind::Real) => 3,
        None if real_finished => 4,
        None if preview_current => 3,
        None => 1,
    }
}

/// Is the finished dry run still valid for what is selected now? Ignores
/// privilege and the "run in progress" part of the gate, which say nothing
/// about the dry run itself.
fn preview_is_current(state: &AppState) -> bool {
    state.preview.as_ref().is_some_and(|p| {
        p.finished()
            && !p.summary.as_ref().is_some_and(|s| s.cancelled)
            && p.selection == state.selected
            && p.readme_fingerprint == state.readme_fingerprint()
    })
}

fn step_of(state: &AppState) -> usize {
    workflow_step(
        state.active,
        state.real.as_ref().is_some_and(RunRecord::finished),
        preview_is_current(state),
    )
}

/// Label and tone for a task row's status.
pub fn status_pill(status: &TaskStatus) -> (&'static str, Tone) {
    match status {
        TaskStatus::Waiting => ("Waiting", Tone::Neutral),
        TaskStatus::Running(Phase::Reading) => ("Reading", Tone::Accent),
        TaskStatus::Running(Phase::Executing) => ("Applying", Tone::Accent),
        TaskStatus::Running(Phase::Verifying) => ("Verifying", Tone::Accent),
        TaskStatus::Done(r) if r.success => ("Done", Tone::Success),
        TaskStatus::Done(_) => ("Failed", Tone::Danger),
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct PreviewCounts {
    pub would_change: usize,
    pub already_ok: usize,
    pub failed: usize,
}

/// A dry run attempts nothing, so every change it would make is recorded as
/// `Skipped`.
pub fn preview_counts(outcomes: impl IntoIterator<Item = FixOutcome>) -> PreviewCounts {
    let mut c = PreviewCounts::default();
    for o in outcomes {
        match o {
            FixOutcome::Skipped => c.would_change += 1,
            FixOutcome::AlreadyCompliant => c.already_ok += 1,
            FixOutcome::Failed | FixOutcome::Unverified => c.failed += 1,
            FixOutcome::Fixed => {}
        }
    }
    c
}

/// Why the dry run cannot start, if it cannot.
pub fn start_blocked(selected: usize, active: bool) -> Option<&'static str> {
    if active {
        Some("A run is in progress.")
    } else if selected == 0 {
        Some("Select at least one task.")
    } else {
        None
    }
}

/// The second lock on the dialog: the gate AND the tick.
pub fn apply_enabled(gate_ok: bool, confirmed: bool) -> bool {
    gate_ok && confirmed
}

/// Why task `i` cannot be ticked, if it cannot.
fn task_blocked(state: &AppState, i: usize) -> Option<&'static str> {
    (state.tasks[i].needs_readme && state.readme_data().is_none()).then_some(NEEDS_README)
}

fn set_all(state: &mut AppState, on: bool) {
    for i in 0..state.tasks.len() {
        state.selected[i] = on && task_blocked(state, i).is_none();
    }
}

// --- the tab -------------------------------------------------------------------

pub fn show(ui: &mut egui::Ui, state: &mut AppState) -> Option<Action> {
    let mut action = None;
    egui::ScrollArea::vertical()
        .auto_shrink([false; 2])
        .show(ui, |ui| {
            if state.active_record().is_some() {
                action = monitoring(ui, state);
            } else {
                action = setup(ui, state);
            }
        });
    action
}

// --- setup ---------------------------------------------------------------------

fn setup(ui: &mut egui::Ui, state: &mut AppState) -> Option<Action> {
    let mut action = None;
    // A README that went away must not leave a task ticked that the screen
    // shows as off.
    for i in 0..state.tasks.len() {
        if task_blocked(state, i).is_some() {
            state.selected[i] = false;
        }
    }

    theme::page_title(
        ui,
        "Run",
        "Choose what to check, preview it, then apply it. Nothing changes until a real run.",
    );

    theme::card(ui, |ui| {
        theme::section(ui, "Workflow", None);
        stepper(ui, step_of(state));
    });
    ui.add_space(theme::GAP);

    theme::card(ui, |ui| tasks_card(ui, state));
    ui.add_space(theme::GAP);

    theme::card(ui, |ui| {
        action = actions_card(ui, state);
    });
    ui.add_space(theme::GAP);
    action
}

fn stepper(ui: &mut egui::Ui, current: usize) {
    ui.horizontal_wrapped(|ui| {
        ui.spacing_mut().item_spacing.x = 10.0;
        for (i, label) in STEPS.iter().enumerate() {
            let n = i + 1;
            let (fill, fg, text) = if n < current {
                (theme::SUCCESS, Color32::WHITE, theme::TEXT)
            } else if n == current {
                (theme::ACCENT, Color32::WHITE, theme::TEXT)
            } else {
                (Tone::Neutral.bg(), theme::MUTED, theme::MUTED)
            };
            let (rect, _) = ui.allocate_exact_size(egui::vec2(24.0, 24.0), egui::Sense::hover());
            ui.painter().circle_filled(rect.center(), 12.0, fill);
            ui.painter().text(
                rect.center(),
                egui::Align2::CENTER_CENTER,
                n.to_string(),
                egui::FontId::proportional(13.0),
                fg,
            );
            let mut t = RichText::new(*label).color(text);
            if n == current {
                t = t.family(theme::bold_family());
            }
            ui.label(t);
            if n < STEPS.len() {
                let (line, _) =
                    ui.allocate_exact_size(egui::vec2(28.0, 24.0), egui::Sense::hover());
                ui.painter().hline(
                    line.x_range(),
                    line.center().y,
                    egui::Stroke::new(1.5, theme::BORDER),
                );
            }
        }
    });
}

fn tasks_card(ui: &mut egui::Ui, state: &mut AppState) {
    theme::section(
        ui,
        "Tasks",
        Some("Tasks that need the README are available once one is loaded."),
    );
    ui.horizontal(|ui| {
        if ui.add(theme::secondary_button("Select all")).clicked() {
            set_all(state, true);
        }
        if ui.add(theme::secondary_button("Select none")).clicked() {
            set_all(state, false);
        }
        let count = state.selected.iter().filter(|on| **on).count();
        ui.label(theme::muted(format!(
            "{count} of {} selected",
            state.tasks.len()
        )));
    });
    ui.add_space(4.0);

    let n = state.tasks.len();
    if ui.available_width() >= 640.0 {
        let half = n.div_ceil(2);
        ui.columns(2, |cols| {
            for (c, range) in [(0, 0..half), (1, half..n)] {
                for i in range {
                    task_row(&mut cols[c], state, i);
                }
            }
        });
    } else {
        for i in 0..n {
            task_row(ui, state, i);
        }
    }
}

fn task_row(ui: &mut egui::Ui, state: &mut AppState, i: usize) {
    ui.spacing_mut().item_spacing.y = 2.0;
    let spec = &state.tasks[i];
    let blocked = task_blocked(state, i);
    ui.horizontal(|ui| {
        let r = ui
            .add_enabled_ui(blocked.is_none(), |ui| {
                ui.checkbox(
                    &mut state.selected[i],
                    RichText::new(spec.label).family(theme::bold_family()),
                )
            })
            .inner;
        if let Some(reason) = blocked {
            r.on_disabled_hover_text(reason);
        }
        if spec.concurrency == Concurrency::Concurrent {
            theme::pill(ui, "runs alongside", Tone::Neutral);
        }
    });
    let detail = blocked.unwrap_or(spec.detail);
    if !detail.is_empty() {
        ui.horizontal(|ui| {
            ui.add_space(26.0);
            ui.add(egui::Label::new(RichText::new(detail).size(12.5).color(theme::MUTED)).wrap());
        });
    }
    ui.add_space(8.0);
}

fn actions_card(ui: &mut egui::Ui, state: &mut AppState) -> Option<Action> {
    let mut action = None;
    let selected = state.selected.iter().filter(|on| **on).count();

    theme::section(ui, "Run", None);

    let blocked = start_blocked(selected, state.active.is_some());
    ui.horizontal(|ui| {
        let b = ui.add_enabled(blocked.is_none(), theme::primary_button("Start dry run"));
        if b.clicked() {
            action = Some(Action::StartPreview);
        }
        if let Some(why) = blocked {
            ui.label(theme::muted(why));
        }
    });
    ui.label(theme::muted(
        "Changes nothing. Shows exactly what a real run would do.",
    ));

    if let Some(p) = &state.preview
        && let Some(summary) = &p.summary
        && !summary.cancelled
    {
        ui.add_space(8.0);
        let c = preview_counts(summary.fixes.iter().map(|f| f.outcome));
        let current = preview_is_current(state);
        ui.horizontal(|ui| {
            theme::stat(ui, "would change", c.would_change.to_string(), Tone::Accent);
            theme::stat(ui, "already OK", c.already_ok.to_string(), Tone::Success);
            let tone = if c.failed > 0 {
                Tone::Danger
            } else {
                Tone::Neutral
            };
            theme::stat(ui, "failed findings", c.failed.to_string(), tone);
            ui.vertical(|ui| {
                if !current {
                    theme::pill(ui, "selection changed since", Tone::Warning);
                }
                if ui
                    .add(theme::secondary_button("View dry-run results"))
                    .clicked()
                {
                    state.results_kind = RunKind::Preview;
                    action = Some(Action::OpenTab(Tab::Results));
                }
            });
        });
    }

    ui.add_space(6.0);
    ui.separator();
    ui.add_space(6.0);

    let gate = state.real_run_gate();
    ui.horizontal_wrapped(|ui| {
        let b = ui.add_enabled(gate.is_ok(), theme::danger_button("Run for real..."));
        if b.clicked() {
            action = Some(Action::OpenApplyDialog);
        }
        match &gate {
            Err(why) => {
                ui.label(theme::muted(why));
            }
            Ok(()) => {
                ui.label(theme::muted(
                    "Changes this machine. You confirm on the next screen.",
                ));
            }
        }
    });

    ui.add_space(8.0);
    ui.label(theme::muted("Equivalent command"));
    let cmd = state.command_line(RunKind::Preview);
    ui.horizontal(|ui| {
        egui::Frame::new()
            .fill(Color32::from_rgb(0xF1, 0xF4, 0xF9))
            .corner_radius(egui::CornerRadius::same(6))
            .inner_margin(egui::Margin::symmetric(10, 6))
            .show(ui, |ui| {
                ui.set_max_width((ui.available_width() - 90.0).max(120.0));
                ui.add(egui::Label::new(RichText::new(&cmd).monospace()).wrap());
            });
        if ui.add(theme::secondary_button("Copy")).clicked() {
            action = Some(Action::CopyText(cmd));
        }
    });
    action
}

// --- monitoring ----------------------------------------------------------------

fn monitoring(ui: &mut egui::Ui, state: &mut AppState) -> Option<Action> {
    let mut action = None;
    let now = Instant::now();
    let run = state.active_record()?;
    let tone = if run.kind == RunKind::Real {
        Tone::Danger
    } else {
        Tone::Accent
    };

    theme::card(ui, |ui| {
        ui.horizontal(|ui| {
            ui.label(
                RichText::new(run.kind.title())
                    .size(20.0)
                    .family(theme::bold_family())
                    .color(tone.fg()),
            );
            theme::pill(ui, theme::duration(run.elapsed(now)), Tone::Neutral);
            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                let b = ui.add_enabled(!run.cancel_requested, theme::secondary_button("Cancel"));
                if b.clicked() {
                    action = Some(Action::Cancel);
                }
            });
        });
        let (done, total) = run.progress();
        let fraction = if total == 0 {
            0.0
        } else {
            done as f32 / total as f32
        };
        ui.add(
            egui::ProgressBar::new(fraction)
                .fill(tone.fg())
                .text(RichText::new(format!("{done} of {total} tasks")).color(Color32::WHITE)),
        );
        if run.cancel_requested {
            ui.label(
                RichText::new(
                    "Stopping after the current task - nothing is interrupted mid-change",
                )
                .color(theme::WARNING),
            );
        }
    });
    ui.add_space(theme::GAP);

    theme::card(ui, |ui| {
        theme::section(ui, "Tasks", None);
        let (main, alongside): (Vec<&TaskRow>, Vec<&TaskRow>) =
            run.rows.iter().partition(|r| !r.concurrent);
        for row in main {
            task_status_row(ui, row, now);
        }
        if !alongside.is_empty() {
            ui.add_space(6.0);
            ui.label(
                RichText::new("Independent audits (run alongside)").family(theme::bold_family()),
            );
            for row in alongside {
                task_status_row(ui, row, now);
            }
        }
    });
    ui.add_space(theme::GAP);

    theme::card(ui, |ui| {
        egui::CollapsingHeader::new(
            RichText::new("Live output")
                .size(16.5)
                .family(theme::bold_family()),
        )
        .default_open(true)
        .show(ui, |ui| output_view(ui, &run.output));
    });
    ui.add_space(theme::GAP);
    action
}

fn task_status_row(ui: &mut egui::Ui, row: &TaskRow, now: Instant) {
    let (text, tone) = status_pill(&row.status);
    ui.horizontal_top(|ui| {
        ui.allocate_ui_with_layout(
            egui::vec2(86.0, 22.0),
            egui::Layout::left_to_right(egui::Align::Center),
            |ui| {
                theme::pill(ui, text, tone);
            },
        );
        ui.vertical(|ui| {
            ui.spacing_mut().item_spacing.y = 1.0;
            ui.horizontal(|ui| {
                ui.label(RichText::new(&row.name).family(theme::bold_family()));
                if let Some(t) = row.time(now) {
                    ui.label(theme::muted(theme::duration(t)));
                }
            });
            if let TaskStatus::Done(r) = &row.status
                && !r.message.is_empty()
            {
                ui.add(
                    egui::Label::new(RichText::new(&r.message).size(12.5).color(theme::MUTED))
                        .wrap(),
                );
            }
        });
    });
    ui.add_space(2.0);
}

fn output_view(ui: &mut egui::Ui, lines: &[OutputLine]) {
    egui::Frame::new()
        .fill(Color32::from_rgb(0xF6, 0xF8, 0xFB))
        .corner_radius(egui::CornerRadius::same(6))
        .inner_margin(egui::Margin::same(8))
        .show(ui, |ui| {
            egui::ScrollArea::vertical()
                .id_salt("run-output")
                .max_height(260.0)
                .auto_shrink([false, true])
                .stick_to_bottom(true)
                .show(ui, |ui| {
                    ui.set_width(ui.available_width());
                    for line in lines {
                        match line {
                            OutputLine::Text(t) => {
                                ui.add(egui::Label::new(RichText::new(t).monospace()).wrap());
                            }
                            OutputLine::Section(t) => {
                                ui.add_space(4.0);
                                ui.label(RichText::new(t).monospace().family(theme::bold_family()));
                            }
                        }
                    }
                });
        });
}

// --- apply dialog ----------------------------------------------------------------

/// The real-run confirmation, drawn over every tab while
/// `state.apply_dialog_open`.
pub fn apply_dialog(ui: &mut egui::Ui, state: &mut AppState) -> Option<Action> {
    let mut action = None;
    let gate_ok = state.real_run_gate().is_ok();
    let modal = egui::Modal::new(egui::Id::unique("apply-dialog"))
        .frame(
            egui::Frame::popup(ui.style())
                .fill(theme::SURFACE)
                .inner_margin(egui::Margin::same(22))
                .corner_radius(egui::CornerRadius::same(12)),
        )
        .show(ui.ctx(), |ui| {
            ui.set_width(480.0_f32.min(ui.ctx().content_rect().width() - 80.0));
            ui.label(
                RichText::new("Run for real?")
                    .size(20.0)
                    .family(theme::bold_family())
                    .color(theme::DANGER),
            );
            ui.add_space(6.0);
            theme::callout(ui, Tone::Danger, |ui| {
                ui.label(
                    RichText::new(
                        "This changes the machine and most changes cannot be undone: accounts are \
                     deleted, passwords reset, packages purged, services masked, files deleted.",
                    )
                    .color(theme::DANGER),
                );
            });
            ui.add_space(8.0);
            ui.label(RichText::new("Tasks that will run").family(theme::bold_family()));
            let names: Vec<&str> = state.selected_specs().iter().map(|s| s.label).collect();
            egui::ScrollArea::vertical()
                .max_height(110.0)
                .auto_shrink([false, true])
                .show(ui, |ui| {
                    ui.add(egui::Label::new(names.join(", ")).wrap());
                });
            ui.add_space(4.0);
            let readme = state.readme_source().unwrap_or("none");
            ui.label(theme::muted(format!("README in use: {readme}")));
            if gate_ok {
                ui.label(theme::muted("Matches the dry run you just reviewed."));
            }
            ui.add_space(8.0);
            ui.checkbox(
                &mut state.apply_confirmed,
                "I have answered the forensics questions and I want to change this machine",
            );
            ui.add_space(8.0);
            ui.horizontal(|ui| {
                if ui.add(theme::secondary_button("Cancel")).clicked() {
                    action = Some(Action::CloseApplyDialog);
                }
                let ok = apply_enabled(gate_ok, state.apply_confirmed);
                if ui
                    .add_enabled(ok, theme::danger_button("Apply changes"))
                    .clicked()
                {
                    action = Some(Action::StartReal);
                }
            });
        });
    if modal.should_close() && action.is_none() {
        action = Some(Action::CloseApplyDialog);
    }
    action
}

#[cfg(test)]
mod tests {
    use super::*;
    use pinnacle_core::models::TaskResult;

    #[test]
    fn workflow_step_follows_the_run() {
        assert_eq!(workflow_step(None, false, false), 1);
        assert_eq!(workflow_step(Some(RunKind::Preview), false, false), 2);
        assert_eq!(workflow_step(None, false, true), 3);
        assert_eq!(workflow_step(Some(RunKind::Real), false, true), 3);
        assert_eq!(workflow_step(None, true, true), 4);
    }

    #[test]
    fn status_pills_say_what_is_happening() {
        let ok = TaskResult {
            success: true,
            ..Default::default()
        };
        let bad = TaskResult::default();
        assert_eq!(
            status_pill(&TaskStatus::Waiting),
            ("Waiting", Tone::Neutral)
        );
        assert_eq!(
            status_pill(&TaskStatus::Running(Phase::Executing)),
            ("Applying", Tone::Accent)
        );
        assert_eq!(
            status_pill(&TaskStatus::Running(Phase::Reading)).0,
            "Reading"
        );
        assert_eq!(
            status_pill(&TaskStatus::Running(Phase::Verifying)).0,
            "Verifying"
        );
        assert_eq!(status_pill(&TaskStatus::Done(ok)), ("Done", Tone::Success));
        assert_eq!(
            status_pill(&TaskStatus::Done(bad)),
            ("Failed", Tone::Danger)
        );
    }

    #[test]
    fn preview_counts_treat_skipped_as_would_change() {
        use FixOutcome::*;
        let c = preview_counts([
            Skipped,
            Skipped,
            AlreadyCompliant,
            Failed,
            Unverified,
            Fixed,
        ]);
        assert_eq!(
            c,
            PreviewCounts {
                would_change: 2,
                already_ok: 1,
                failed: 2
            }
        );
    }

    #[test]
    fn start_needs_a_task_and_no_run_in_progress() {
        assert!(start_blocked(0, false).is_some());
        assert!(start_blocked(3, true).is_some());
        assert!(start_blocked(3, false).is_none());
    }

    #[test]
    fn apply_needs_the_gate_and_the_tick() {
        assert!(!apply_enabled(true, false));
        assert!(!apply_enabled(false, true));
        assert!(apply_enabled(true, true));
    }
}
