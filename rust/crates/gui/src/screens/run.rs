// =============================================================================
// PinnacleCyPat GUI - Run screen
// Copyright 2026 Maxwell McCormick
// SPDX-License-Identifier: Apache-2.0
// =============================================================================

use eframe::egui::{self, Color32, RichText};
use pinnacle_core::directives;
use pinnacle_core::engine::Phase;

use crate::state::{Action, AppState, OutputLine, RunView, TaskRow, TaskStatus};

const GREEN: Color32 = Color32::from_rgb(90, 200, 120);
const RED: Color32 = Color32::from_rgb(240, 100, 100);
const AMBER: Color32 = Color32::from_rgb(230, 190, 80);

/// (finished, total) over every row, concurrent audits included.
pub fn progress(rows: &[TaskRow]) -> (usize, usize) {
    let done = rows
        .iter()
        .filter(|r| matches!(r.status, TaskStatus::Done(_)))
        .count();
    (done, rows.len())
}

fn phase_word(phase: Phase) -> &'static str {
    match phase {
        Phase::Reading => "Reading",
        Phase::Executing => "Executing",
        Phase::Verifying => "Verifying",
    }
}

pub fn show(ui: &mut egui::Ui, state: &mut AppState) -> Option<Action> {
    let mut action = None;
    let manual_directives: Vec<_> = state
        .inspection
        .as_ref()
        .map(|i| {
            directives::manual(&i.directives)
                .into_iter()
                .map(|d| (d.subject, d.sentence.clone(), d.handling.detail()))
                .collect()
        })
        .unwrap_or_default();
    let Some(run) = state.run.as_mut() else {
        ui.label("No run in progress.");
        return None;
    };

    let (done, total) = progress(&run.rows);
    ui.horizontal(|ui| {
        let title = if run.dry_run {
            "Preview (dry run)"
        } else {
            "Applying changes"
        };
        ui.heading(title);
        ui.label(format!("{done} of {total} done"));
        ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
            let stoppable = !run.cancel_requested && !run.finished;
            if ui
                .add_enabled(stoppable, egui::Button::new("Cancel"))
                .clicked()
            {
                action = Some(Action::Cancel);
            }
        });
    });
    let fraction = if total == 0 {
        0.0
    } else {
        done as f32 / total as f32
    };
    ui.add(egui::ProgressBar::new(fraction).show_percentage());
    if run.cancel_requested {
        ui.colored_label(
            AMBER,
            "Stopping after the current task \u{2014} nothing is interrupted mid-change",
        );
    }
    ui.add_space(4.0);

    if !manual_directives.is_empty() {
        egui::CollapsingHeader::new(
            RichText::new(format!(
                "Do these by hand ({} from the README)",
                manual_directives.len()
            ))
            .color(AMBER),
        )
        .id_salt("run_by_hand")
        .show(ui, |ui| {
            egui::ScrollArea::vertical()
                .id_salt("run_by_hand_scroll")
                .max_height(140.0)
                .show(ui, |ui| {
                    for (subject, sentence, detail) in &manual_directives {
                        ui.label(RichText::new(*subject).strong());
                        ui.label(sentence);
                        ui.label(*detail);
                        ui.add_space(4.0);
                    }
                });
        });
    }

    task_list(ui, run);
    ui.add_space(6.0);
    ui.label(RichText::new("Live output").strong());
    output(ui, run);
    action
}

fn task_list(ui: &mut egui::Ui, run: &RunView) {
    let height = (ui.available_height() * 0.5).clamp(90.0, 400.0);
    egui::ScrollArea::vertical()
        .id_salt("run_tasks")
        .max_height(height)
        .auto_shrink([false, true])
        .show(ui, |ui| {
            for row in run.rows.iter().filter(|r| !r.concurrent) {
                task_row(ui, row);
            }
            if run.rows.iter().any(|r| r.concurrent) {
                ui.add_space(4.0);
                ui.label(RichText::new("Independent audits (run alongside)").strong());
                for row in run.rows.iter().filter(|r| r.concurrent) {
                    task_row(ui, row);
                }
            }
        });
}

fn task_row(ui: &mut egui::Ui, row: &TaskRow) {
    ui.horizontal_wrapped(|ui| {
        ui.label(&row.name);
        match &row.status {
            TaskStatus::Waiting => {
                ui.weak("Waiting");
            }
            TaskStatus::Running(phase) => {
                ui.add(egui::Spinner::new().size(12.0));
                ui.colored_label(AMBER, format!("Running: {}", phase_word(*phase)));
            }
            TaskStatus::Done(result) => {
                if result.success {
                    ui.colored_label(GREEN, "Done: success");
                } else {
                    ui.colored_label(RED, "Done: failed");
                }
                if !result.message.is_empty() {
                    ui.label(&result.message);
                }
            }
        }
    });
}

fn output(ui: &mut egui::Ui, run: &RunView) {
    egui::ScrollArea::vertical()
        .id_salt("run_output")
        .stick_to_bottom(true)
        .auto_shrink([false, false])
        .show(ui, |ui| {
            for line in &run.output {
                match line {
                    OutputLine::Section(title) => {
                        ui.add_space(6.0);
                        ui.label(RichText::new(title).strong().size(15.0));
                    }
                    OutputLine::Text(text) => {
                        ui.label(RichText::new(text).monospace());
                    }
                }
            }
        });
}

#[cfg(test)]
mod tests {
    use super::*;
    use pinnacle_core::models::TaskResult;

    fn row(status: TaskStatus) -> TaskRow {
        TaskRow {
            name: "t".to_string(),
            concurrent: false,
            status,
        }
    }

    #[test]
    fn progress_counts_only_finished_rows() {
        let rows = [
            row(TaskStatus::Done(TaskResult::default())),
            row(TaskStatus::Running(Phase::Executing)),
            row(TaskStatus::Waiting),
            row(TaskStatus::Done(TaskResult::default())),
        ];
        assert_eq!(progress(&rows), (2, 4));
    }

    #[test]
    fn progress_of_an_empty_run_is_zero_of_zero() {
        assert_eq!(progress(&[]), (0, 0));
    }
}
