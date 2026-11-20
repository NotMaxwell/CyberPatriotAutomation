// =============================================================================
// PinnacleCyPat GUI - Confirm screen
// Copyright 2026 Maxwell McCormick
// SPDX-License-Identifier: Apache-2.0
// =============================================================================

//! The last stop before a run. A preview starts with one click; changing the
//! machine needs a warning read and a separate tick.

use eframe::egui;

use crate::state::{Action, AppState, Screen};

/// Whether the run would change the machine. `state.rs` enforces the same at
/// plan time; checking it here too keeps the button honest.
pub fn applying(state: &AppState) -> bool {
    !state.effective_dry_run()
}

fn wants_apply(state: &AppState) -> bool {
    state.privileged && !state.dry_run
}

pub fn can_start(state: &AppState) -> bool {
    if state.selected.iter().all(|on| !*on) {
        return false;
    }
    !wants_apply(state) || applying(state)
}

pub fn start_label(state: &AppState) -> &'static str {
    if wants_apply(state) {
        "Apply changes"
    } else {
        "Start preview"
    }
}

fn readme_summary(state: &AppState) -> String {
    let source = state.inspection.as_ref().and_then(|i| i.source.clone());
    match (source, state.edited.is_some()) {
        (Some(s), true) => format!("{s} (edited by hand)"),
        (Some(s), false) => s,
        (None, true) => "edited by hand".to_string(),
        (None, false) => "none".to_string(),
    }
}

pub fn show(ui: &mut egui::Ui, state: &mut AppState) -> Option<Action> {
    let mut action = None;
    // A tick left over from an earlier visit must not survive a switch back
    // to preview.
    if !wants_apply(state) {
        state.apply_confirmed = false;
    }

    ui.heading("Confirm");
    egui::Grid::new("confirm-summary")
        .num_columns(2)
        .spacing([16.0, 6.0])
        .show(ui, |ui| {
            ui.strong("README");
            ui.label(readme_summary(state));
            ui.end_row();

            ui.strong("Mode");
            if wants_apply(state) {
                ui.colored_label(egui::Color32::LIGHT_RED, "Apply changes to this machine");
            } else {
                ui.label("Preview only (nothing is changed)");
            }
            ui.end_row();
        });

    ui.add_space(6.0);
    ui.strong("Tasks, in run order");
    for (n, spec) in state.selected_specs().iter().enumerate() {
        ui.label(format!("{}. {}", n + 1, spec.label));
    }

    ui.add_space(8.0);
    ui.label("Equivalent command line:");
    let mut line = state.command_line();
    ui.add(
        egui::TextEdit::multiline(&mut line)
            .font(egui::TextStyle::Monospace)
            .desired_width(f32::INFINITY)
            .desired_rows(2),
    );

    ui.add_space(8.0);
    if wants_apply(state) {
        egui::Frame::group(ui.style())
            .stroke(egui::Stroke::new(1.5, egui::Color32::LIGHT_RED))
            .show(ui, |ui| {
                ui.colored_label(
                    egui::Color32::LIGHT_RED,
                    egui::RichText::new("This changes the machine and is largely irreversible.")
                        .strong(),
                );
                ui.label(
                    "Accounts, files and packages can be deleted, and passwords and \
                     services are changed. Run a preview first if you have not.",
                );
                ui.checkbox(
                    &mut state.apply_confirmed,
                    "I have answered the forensics questions and I want to change this machine",
                );
            });
    }

    ui.add_space(8.0);
    ui.horizontal(|ui| {
        if ui.button("Back").clicked() {
            action = Some(Action::Go(Screen::Tasks));
        }
        let mut button = egui::Button::new(start_label(state));
        if wants_apply(state) {
            button = button.fill(egui::Color32::DARK_RED);
        }
        if ui.add_enabled(can_start(state), button).clicked() {
            action = Some(Action::StartRun);
        }
    });
    action
}

#[cfg(test)]
mod tests {
    use super::*;
    use pinnacle_core::engine::ReadmeInspection;
    use pinnacle_core::models::{ReadmeData, SystemInfo, TaskResult};
    use pinnacle_core::platform::{Concurrency, TaskSpec};
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

    static TASKS: [TaskSpec; 1] = [TaskSpec {
        flag: "--a",
        short: "",
        help: "",
        label: "A",
        detail: "",
        needs_readme: false,
        concurrency: Concurrency::Sequential,
        build,
    }];

    fn state(privileged: bool) -> AppState {
        let mut s = AppState::new(&TASKS, privileged, "root", "use sudo");
        s.selected = vec![true];
        s
    }

    #[test]
    fn a_preview_starts_without_a_second_confirmation() {
        let s = state(true);
        assert!(can_start(&s));
        assert_eq!(start_label(&s), "Start preview");
        assert!(!applying(&s));
    }

    #[test]
    fn applying_is_unreachable_without_the_second_confirmation() {
        let mut s = state(true);
        s.dry_run = false;
        assert_eq!(start_label(&s), "Apply changes");
        assert!(!can_start(&s));
        assert!(!applying(&s));
        s.apply_confirmed = true;
        assert!(can_start(&s));
        assert!(applying(&s));
    }

    #[test]
    fn unelevated_runs_only_preview_even_if_everything_is_ticked() {
        let mut s = state(false);
        s.dry_run = false;
        s.apply_confirmed = true;
        assert_eq!(start_label(&s), "Start preview");
        assert!(!applying(&s));
    }

    #[test]
    fn nothing_selected_cannot_start() {
        let mut s = state(true);
        s.selected = vec![false];
        assert!(!can_start(&s));
    }

    #[test]
    fn the_summary_says_when_the_readme_was_edited_by_hand() {
        let mut s = state(true);
        assert_eq!(readme_summary(&s), "none");
        s.inspection = Some(ReadmeInspection {
            source: Some("README.html".to_string()),
            data: Some(ReadmeData::default()),
            ..Default::default()
        });
        assert_eq!(readme_summary(&s), "README.html");
        s.edited = Some(ReadmeData::default());
        assert_eq!(readme_summary(&s), "README.html (edited by hand)");
    }
}
