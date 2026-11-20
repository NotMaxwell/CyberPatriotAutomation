// =============================================================================
// PinnacleCyPat GUI - Tasks screen
// Copyright 2026 Maxwell McCormick
// SPDX-License-Identifier: Apache-2.0
// =============================================================================

//! Choose which tasks run and whether they change the machine.

use eframe::egui;
use pinnacle_core::platform::Concurrency;

use crate::state::{Action, AppState, Screen};

const NEEDS_README: &str = "Needs a README: load one on the README screen first.";

/// Whether task `i` may be ticked; the error is the reason shown on hover.
pub fn task_enabled(state: &AppState, i: usize) -> Result<(), &'static str> {
    if state.tasks[i].needs_readme && state.readme_data().is_none() {
        Err(NEEDS_README)
    } else {
        Ok(())
    }
}

/// Tick (or clear) every task that is allowed to be ticked.
pub fn set_all(state: &mut AppState, on: bool) {
    for i in 0..state.tasks.len() {
        state.selected[i] = on && task_enabled(state, i).is_ok();
    }
}

/// A task that became unavailable (README dropped) must not stay selected,
/// or the run would start a task the screen shows as off.
fn drop_unavailable(state: &mut AppState) {
    for i in 0..state.tasks.len() {
        if task_enabled(state, i).is_err() {
            state.selected[i] = false;
        }
    }
}

pub fn can_continue(state: &AppState) -> bool {
    state.selected.iter().any(|on| *on)
}

/// Without elevation the preview is the only mode, whatever the box says.
fn force_preview(state: &mut AppState) {
    if !state.privileged {
        state.dry_run = true;
    }
    if state.dry_run {
        state.apply_confirmed = false;
    }
}

pub fn show(ui: &mut egui::Ui, state: &mut AppState) -> Option<Action> {
    drop_unavailable(state);
    force_preview(state);
    let mut action = None;

    ui.heading("Choose tasks");
    ui.horizontal(|ui| {
        if ui.button("Select all").clicked() {
            set_all(state, true);
        }
        if ui.button("Select none").clicked() {
            set_all(state, false);
        }
        let count = state.selected.iter().filter(|on| **on).count();
        ui.weak(format!("{count} of {} selected", state.tasks.len()));
    });
    ui.add_space(4.0);

    egui::ScrollArea::vertical()
        .max_height((ui.available_height() - 170.0).max(120.0))
        .show(ui, |ui| {
            for i in 0..state.tasks.len() {
                let spec = &state.tasks[i];
                let enabled = task_enabled(state, i);
                let response = ui
                    .add_enabled_ui(enabled.is_ok(), |ui| {
                        ui.checkbox(&mut state.selected[i], spec.label)
                    })
                    .inner;
                if let Err(reason) = enabled {
                    response.on_disabled_hover_text(reason);
                }
                ui.horizontal(|ui| {
                    ui.add_space(24.0);
                    ui.weak(spec.detail);
                    if spec.concurrency == Concurrency::Concurrent {
                        ui.weak("(runs alongside others)");
                    }
                });
            }
        });

    ui.add_space(8.0);
    ui.separator();
    ui.strong("Mode");
    if state.privileged {
        if ui
            .checkbox(&mut state.dry_run, "Preview only (dry run)")
            .changed()
            && state.dry_run
        {
            state.apply_confirmed = false;
        }
        if !state.dry_run {
            ui.colored_label(
                egui::Color32::LIGHT_RED,
                "Changes will be applied to this machine. You confirm on the next screen.",
            );
        }
    } else {
        ui.add_enabled_ui(false, |ui| {
            ui.checkbox(&mut true, "Preview only (dry run)");
        });
        ui.colored_label(
            egui::Color32::LIGHT_YELLOW,
            format!(
                "Not running as {} - preview only. {}",
                state.privileged_role, state.elevation_hint
            ),
        );
    }

    ui.add_space(8.0);
    ui.horizontal(|ui| {
        if ui.button("Back").clicked() {
            action = Some(Action::Go(Screen::Readme));
        }
        if ui
            .add_enabled(can_continue(state), egui::Button::new("Next"))
            .clicked()
        {
            action = Some(Action::Go(Screen::Confirm));
        }
    });
    action
}

#[cfg(test)]
mod tests {
    use super::*;
    use pinnacle_core::engine::{ReadmeInspection, TaskChoice};
    use pinnacle_core::models::{ReadmeData, SystemInfo, TaskResult};
    use pinnacle_core::platform::TaskSpec;
    use pinnacle_core::task::Task;
    use std::path::PathBuf;
    use std::sync::Arc;
    use std::sync::atomic::AtomicBool;

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

    const fn spec(flag: &'static str, needs_readme: bool) -> TaskSpec {
        TaskSpec {
            flag,
            short: "",
            help: "",
            label: flag,
            detail: "",
            needs_readme,
            concurrency: Concurrency::Sequential,
            build,
        }
    }

    static TASKS: [TaskSpec; 3] = [spec("--a", false), spec("--b", true), spec("--c", false)];

    fn state(privileged: bool, with_readme: bool) -> AppState {
        let mut s = AppState::new(&TASKS, privileged, "root", "use sudo");
        if with_readme {
            s.inspection = Some(ReadmeInspection {
                source: Some("README.html".to_string()),
                data: Some(ReadmeData::default()),
                ..Default::default()
            });
        }
        s
    }

    #[test]
    fn ticked_rows_become_the_plan_flags_in_table_order() {
        let mut s = state(true, true);
        s.selected = vec![true, false, true];
        let plan = s
            .plan(PathBuf::new(), Arc::new(AtomicBool::new(false)))
            .unwrap();
        match plan.tasks {
            TaskChoice::Flags(f) => assert_eq!(f, ["--a", "--c"]),
            TaskChoice::All => panic!("expected flags"),
        }
    }

    #[test]
    fn readme_tasks_are_disabled_without_a_readme() {
        let s = state(true, false);
        assert!(task_enabled(&s, 0).is_ok());
        assert!(task_enabled(&s, 1).is_err());
        assert!(task_enabled(&state(true, true), 1).is_ok());
    }

    #[test]
    fn select_all_skips_tasks_that_need_a_missing_readme() {
        let mut s = state(true, false);
        set_all(&mut s, true);
        assert_eq!(s.selected, [true, false, true]);
        set_all(&mut s, false);
        assert_eq!(s.selected, [false, false, false]);
    }

    #[test]
    fn dropping_the_readme_unticks_tasks_that_need_it() {
        let mut s = state(true, false);
        s.selected = vec![true, true, true];
        drop_unavailable(&mut s);
        assert_eq!(s.selected, [true, false, true]);
    }

    #[test]
    fn unelevated_runs_are_forced_to_preview() {
        let mut s = state(false, true);
        s.dry_run = false;
        s.apply_confirmed = true;
        force_preview(&mut s);
        assert!(s.dry_run && !s.apply_confirmed);
    }

    #[test]
    fn returning_to_preview_clears_the_apply_confirmation() {
        let mut s = state(true, true);
        s.apply_confirmed = true;
        force_preview(&mut s);
        assert!(!s.apply_confirmed);
    }

    #[test]
    fn next_needs_at_least_one_task() {
        let mut s = state(true, true);
        assert!(!can_continue(&s));
        s.selected[2] = true;
        assert!(can_continue(&s));
    }
}
