// =============================================================================
// PinnacleCyPat GUI - The application shell
// Copyright 2026 Maxwell McCormick
// SPDX-License-Identifier: Apache-2.0
// =============================================================================

//! Routing, the step bar, and carrying out the [`Action`]s screens return.
//!
//! **Test hooks.** A GUI nobody can look at is checked by screenshot, so a few
//! environment variables drive the app to a given state without a person:
//!
//! | Variable | Effect |
//! |---|---|
//! | `PINNACLE_GUI_README=<path>` | inspect this README at start-up |
//! | `PINNACLE_GUI_SELECT=all` | tick every task |
//! | `PINNACLE_GUI_SCREEN=<readme\|tasks\|confirm>` | open that screen once the README is in |
//! | `PINNACLE_GUI_DRY_RUN=1` | start a dry run once the README is in; capture after it finishes |
//! | `PINNACLE_GUI_SCREENSHOT=<png>` | save a screenshot once the app has settled, then exit |
//!
//! The dry-run hook forces a preview whatever else is set: no hook can make the
//! GUI change the machine.

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{Receiver, TryRecvError};

use eframe::egui;
use pinnacle_core::app_config;
use pinnacle_core::engine::{ReadmeChoice, ReadmeInspection, RunEvent};
use pinnacle_core::platform::Platform;

use crate::backend::Backend;
use crate::screens;
use crate::screenshot::Screenshot;
use crate::state::{Action, AppState, Screen};

struct Hooks {
    screen: Option<Screen>,
    dry_run: bool,
    /// The hooked screen or run has been reached; nothing more to drive.
    done: bool,
}

impl Hooks {
    fn from_env() -> Self {
        let screen = std::env::var("PINNACLE_GUI_SCREEN")
            .ok()
            .and_then(|s| match s.as_str() {
                "readme" => Some(Screen::Readme),
                "tasks" => Some(Screen::Tasks),
                "confirm" => Some(Screen::Confirm),
                _ => None,
            });
        Self {
            screen,
            dry_run: std::env::var("PINNACLE_GUI_DRY_RUN").is_ok_and(|v| v == "1"),
            done: false,
        }
    }
}

pub struct App<P: Platform> {
    state: AppState,
    backend: Backend,
    inspection: Option<Receiver<ReadmeInspection>>,
    events: Option<Receiver<RunEvent>>,
    hooks: Hooks,
    shot: Option<Screenshot>,
    _platform: std::marker::PhantomData<P>,
}

impl<P: Platform + 'static> App<P> {
    pub fn new(ctx: &egui::Context) -> std::io::Result<Self> {
        let mut state = AppState::new(
            P::tasks(),
            P::is_privileged(),
            P::PRIVILEGED_ROLE,
            P::ELEVATION_HINT,
        );
        if std::env::var("PINNACLE_GUI_SELECT").is_ok_and(|v| v == "all") {
            state.selected = vec![true; state.tasks.len()];
        }
        let mut app = Self {
            state,
            backend: Backend::new(ctx.clone())?,
            inspection: None,
            events: None,
            hooks: Hooks::from_env(),
            shot: Screenshot::from_env(),
            _platform: std::marker::PhantomData,
        };
        if let Ok(path) = std::env::var("PINNACLE_GUI_README") {
            app.state.readme_path = path.clone();
            app.perform(Action::Inspect(ReadmeChoice::Path(path)));
        }
        Ok(app)
    }

    fn perform(&mut self, action: Action) {
        match action {
            Action::Go(screen) => self.state.screen = screen,
            Action::Inspect(choice) => {
                self.state.inspecting = true;
                self.state.inspection = None;
                self.state.edited = None;
                self.inspection = Some(self.backend.inspect(choice));
            }
            Action::StartRun => {
                if self.events.is_some() {
                    return;
                }
                let cancel = Arc::new(AtomicBool::new(false));
                match self.state.plan(crate::state::default_log_path(), cancel) {
                    Some(plan) => {
                        self.state.begin_run(&plan);
                        self.events = Some(self.backend.run::<P>(plan));
                    }
                    None => self.state.error = Some("No tasks selected.".to_string()),
                }
            }
            Action::Cancel => {
                if let Some(run) = &mut self.state.run {
                    run.cancel.store(true, Ordering::Relaxed);
                    run.cancel_requested = true;
                }
            }
            Action::OpenLog(path) => {
                if let Err(e) = open_file(&path) {
                    self.state.error = Some(format!("Could not open {}: {e}", path.display()));
                }
            }
            Action::NewRun => {
                if self.events.is_none() {
                    self.state.new_run();
                }
            }
        }
    }

    fn poll(&mut self) {
        if let Some(rx) = &self.inspection {
            match rx.try_recv() {
                Ok(inspection) => {
                    self.state.inspection = Some(inspection);
                    self.state.inspecting = false;
                    self.inspection = None;
                }
                Err(TryRecvError::Empty) => {}
                Err(TryRecvError::Disconnected) => {
                    self.state.inspecting = false;
                    self.state.error = Some("README inspection stopped unexpectedly.".to_string());
                    self.inspection = None;
                }
            }
        }
        if let Some(rx) = &self.events {
            loop {
                match rx.try_recv() {
                    Ok(event) => self.state.apply_event(event),
                    Err(TryRecvError::Empty) => break,
                    Err(TryRecvError::Disconnected) => {
                        self.events = None;
                        break;
                    }
                }
            }
        }
    }

    fn drive_hooks(&mut self) {
        if self.hooks.done || self.state.inspecting {
            return;
        }
        if self.hooks.dry_run {
            self.state.dry_run = true;
            self.state.apply_confirmed = false;
            self.perform(Action::StartRun);
        } else if let Some(screen) = self.hooks.screen {
            self.state.screen = screen;
        }
        self.hooks.done = true;
    }

    /// Nothing still in flight: what a screenshot should wait for.
    fn settled(&self) -> bool {
        !self.state.inspecting
            && self.inspection.is_none()
            && self.events.is_none()
            && (!self.hooks.dry_run || self.state.summary.is_some())
    }

    fn step_bar(&self, ui: &mut egui::Ui) {
        ui.horizontal(|ui| {
            for (i, screen) in Screen::ALL.iter().enumerate() {
                if i > 0 {
                    ui.weak("›");
                }
                if *screen == self.state.screen {
                    ui.strong(screen.title());
                } else {
                    ui.weak(screen.title());
                }
            }
            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                if self.state.privileged {
                    ui.colored_label(
                        egui::Color32::LIGHT_GREEN,
                        format!("Running as {}", self.state.privileged_role),
                    );
                } else {
                    ui.colored_label(
                        egui::Color32::LIGHT_RED,
                        format!("Not {} - preview only", self.state.privileged_role),
                    )
                    .on_hover_text(self.state.elevation_hint);
                }
                ui.weak(app_config::version_string());
            });
        });
    }
}

impl<P: Platform + 'static> eframe::App for App<P> {
    fn ui(&mut self, ui: &mut egui::Ui, _frame: &mut eframe::Frame) {
        self.poll();
        self.drive_hooks();

        self.step_bar(ui);
        ui.separator();
        if let Some(error) = self.state.error.clone() {
            ui.horizontal(|ui| {
                ui.colored_label(egui::Color32::LIGHT_RED, &error);
                if ui.small_button("dismiss").clicked() {
                    self.state.error = None;
                }
            });
        }

        let action = match self.state.screen {
            Screen::Readme => screens::readme::show(ui, &mut self.state),
            Screen::Tasks => screens::tasks::show(ui, &mut self.state),
            Screen::Confirm => screens::confirm::show(ui, &mut self.state),
            Screen::Run => screens::run::show(ui, &mut self.state),
            Screen::Results => screens::results::show(ui, &mut self.state),
        };
        if let Some(action) = action {
            self.perform(action);
        }

        if self.state.inspecting || self.events.is_some() {
            // Keep the spinner and elapsed state moving between events.
            ui.ctx()
                .request_repaint_after(std::time::Duration::from_millis(250));
        }
        let settled = self.settled();
        if let Some(shot) = &mut self.shot {
            shot.update(ui.ctx(), settled);
        }
    }
}

/// Open a file with whatever the desktop uses for it.
fn open_file(path: &std::path::Path) -> std::io::Result<()> {
    #[cfg(windows)]
    let mut command = {
        let mut c = std::process::Command::new("notepad.exe");
        c.arg(path);
        c
    };
    #[cfg(not(windows))]
    let mut command = {
        let mut c = std::process::Command::new("xdg-open");
        c.arg(path);
        c
    };
    command.spawn().map(|_| ())
}
