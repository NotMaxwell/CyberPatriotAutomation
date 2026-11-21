// =============================================================================
// PinnacleCyPat GUI - The application shell
// Copyright 2026 Maxwell McCormick
// SPDX-License-Identifier: Apache-2.0
// =============================================================================

//! Layout (top bar, sidebar, status bar), carrying out [`Action`]s, and the
//! dialogs and toast drawn over every tab.
//!
//! On launch the app looks for every README location and opens the picker, so
//! the first thing a competitor sees is the question that matters first.
//!
//! **Test hooks.** A GUI nobody can look at is checked by screenshot, so a few
//! environment variables drive the app to a given state without a person:
//!
//! | Variable | Effect |
//! |---|---|
//! | `PINNACLE_GUI_README=<path>` | parse this README at start-up instead of opening the picker |
//! | `PINNACLE_GUI_SELECT=all` | tick every task |
//! | `PINNACLE_GUI_TAB=<readme\|run\|results>` | open that tab once the README is in |
//! | `PINNACLE_GUI_DRY_RUN=1` | start a dry run once the README is in; capture after it finishes |
//! | `PINNACLE_GUI_STAY=run` | stay on the Run tab after a run finishes |
//! | `PINNACLE_GUI_MIDRUN=<seconds>` | with the dry-run hook, capture this long into the run instead of after it |
//! | `PINNACLE_GUI_SHOW=apply` | after the dry run, open the real-run confirmation (never starts it) |
//! | `PINNACLE_GUI_SCREENSHOT=<png>` | save a screenshot once the app has settled, then exit |
//!
//! No hook can start a real run.

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{Receiver, TryRecvError};
use std::time::Instant;

use eframe::egui::{self, RichText};
use pinnacle_core::app_config::{self, ReadmeCandidate};
use pinnacle_core::engine::{ReadmeChoice, ReadmeInspection, RunEvent};
use pinnacle_core::platform::Platform;

use crate::backend::Backend;
use crate::screens;
use crate::screenshot::Screenshot;
use crate::state::{Action, AppState, RunKind, Tab};
use crate::theme::{self, Tone};

struct Hooks {
    tab: Option<Tab>,
    dry_run: bool,
    stay_on_run: bool,
    show_apply: bool,
    midrun: Option<std::time::Duration>,
    /// The hooked state has been reached; nothing more to drive.
    done: bool,
}

impl Hooks {
    fn from_env() -> Self {
        let var = |name: &str| std::env::var(name).ok();
        Self {
            tab: var("PINNACLE_GUI_TAB").and_then(|s| match s.as_str() {
                "readme" => Some(Tab::Readme),
                "run" => Some(Tab::Run),
                "results" => Some(Tab::Results),
                _ => None,
            }),
            dry_run: var("PINNACLE_GUI_DRY_RUN").is_some_and(|v| v == "1"),
            stay_on_run: var("PINNACLE_GUI_STAY").is_some_and(|v| v == "run"),
            show_apply: var("PINNACLE_GUI_SHOW").is_some_and(|v| v == "apply"),
            midrun: var("PINNACLE_GUI_MIDRUN")
                .and_then(|v| v.parse().ok())
                .map(std::time::Duration::from_secs),
            done: false,
        }
    }
}

pub struct App<P: Platform> {
    state: AppState,
    backend: Backend,
    discovery: Option<Receiver<Vec<ReadmeCandidate>>>,
    inspection: Option<Receiver<ReadmeInspection>>,
    events: Option<Receiver<RunEvent>>,
    hooks: Hooks,
    shot: Option<Screenshot>,
    _platform: std::marker::PhantomData<P>,
}

impl<P: Platform + 'static> App<P> {
    pub fn new(ctx: &egui::Context) -> std::io::Result<Self> {
        theme::apply(ctx);
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
            discovery: None,
            inspection: None,
            events: None,
            hooks: Hooks::from_env(),
            shot: Screenshot::from_env(),
            _platform: std::marker::PhantomData,
        };
        match std::env::var("PINNACLE_GUI_README") {
            Ok(path) => app.perform(Action::UseReadme(path)),
            Err(_) => app.perform(Action::DiscoverReadme),
        }
        Ok(app)
    }

    fn perform(&mut self, action: Action) {
        let now = Instant::now();
        match action {
            Action::OpenTab(tab) => self.state.tab = tab,
            Action::DiscoverReadme => {
                self.state.discovering = true;
                self.state.locations_open = true;
                self.discovery = Some(self.backend.discover());
            }
            Action::ShowLocations(open) => self.state.locations_open = open,
            Action::UseReadme(path) => {
                self.state.readme_path = path.clone();
                self.state.locations_open = false;
                self.state.inspecting = true;
                self.state.tab = Tab::Readme;
                self.inspection = Some(self.backend.inspect(ReadmeChoice::Path(path)));
            }
            Action::ContinueWithoutReadme => {
                self.state.locations_open = false;
                self.state.set_inspection(ReadmeInspection::default());
                self.state.tab = Tab::Run;
            }
            Action::StartPreview => self.start(RunKind::Preview, now),
            Action::OpenApplyDialog => {
                if self.state.real_run_gate().is_ok() {
                    self.state.apply_confirmed = false;
                    self.state.apply_dialog_open = true;
                }
            }
            Action::CloseApplyDialog => {
                self.state.apply_dialog_open = false;
                self.state.apply_confirmed = false;
            }
            Action::StartReal => self.start(RunKind::Real, now),
            Action::Cancel => {
                if let Some(run) = self.state.active_record_mut() {
                    run.cancel.store(true, Ordering::Relaxed);
                    run.cancel_requested = true;
                }
            }
            Action::OpenLog(path) => {
                if let Err(e) = open_file(&path) {
                    self.state.error = Some(format!("Could not open {}: {e}", path.display()));
                }
            }
            Action::CopyText(text) => {
                self.backend.ctx().copy_text(text);
                self.state.toast = Some(crate::state::Toast {
                    text: "Copied.".to_string(),
                    success: true,
                    shown: now,
                });
            }
        }
    }

    fn start(&mut self, kind: RunKind, now: Instant) {
        if self.events.is_some() {
            return;
        }
        let cancel = Arc::new(AtomicBool::new(false));
        match self
            .state
            .plan(kind, crate::state::default_log_path(), cancel)
        {
            Ok(plan) => {
                self.state.begin_run(kind, &plan, now);
                self.events = Some(self.backend.run::<P>(plan));
            }
            Err(why) => self.state.error = Some(why),
        }
    }

    fn poll(&mut self) {
        let now = Instant::now();
        if let Some(rx) = &self.discovery {
            match rx.try_recv() {
                Ok(found) => {
                    if let [only] = found.as_slice()
                        && self.state.readme_path.is_empty()
                    {
                        self.state.readme_path = only.location.clone();
                    }
                    self.state.candidates = Some(found);
                    self.state.discovering = false;
                    self.discovery = None;
                }
                Err(TryRecvError::Empty) => {}
                Err(TryRecvError::Disconnected) => {
                    self.state.discovering = false;
                    self.state.candidates = Some(Vec::new());
                    self.discovery = None;
                }
            }
        }
        if let Some(rx) = &self.inspection {
            match rx.try_recv() {
                Ok(inspection) => {
                    self.state.set_inspection(inspection);
                    self.inspection = None;
                }
                Err(TryRecvError::Empty) => {}
                Err(TryRecvError::Disconnected) => {
                    self.state.inspecting = false;
                    self.state.error = Some("README parsing stopped unexpectedly.".to_string());
                    self.inspection = None;
                }
            }
        }
        if let Some(rx) = &self.events {
            loop {
                match rx.try_recv() {
                    Ok(event) => {
                        self.state.apply_event(event, now);
                        if self.hooks.stay_on_run && self.state.tab == Tab::Results {
                            self.state.tab = Tab::Run;
                        }
                    }
                    Err(TryRecvError::Empty) => break,
                    Err(TryRecvError::Disconnected) => {
                        self.events = None;
                        break;
                    }
                }
            }
        }
        self.state.expire_toast(now);
    }

    fn drive_hooks(&mut self) {
        if self.hooks.done || self.state.inspecting || self.discovery.is_some() {
            return;
        }
        if self.hooks.dry_run {
            if self.state.preview.is_none() {
                self.perform(Action::StartPreview);
                return;
            }
            if self.events.is_some() {
                return;
            }
            if self.hooks.show_apply {
                self.perform(Action::OpenApplyDialog);
            }
        } else if let Some(tab) = self.hooks.tab {
            self.state.tab = tab;
        }
        self.hooks.done = true;
    }

    /// Nothing still in flight: what a screenshot should wait for.
    fn settled(&self) -> bool {
        if let (Some(after), Some(run)) = (self.hooks.midrun, self.state.active_record()) {
            return run.elapsed(Instant::now()) >= after;
        }
        self.discovery.is_none()
            && self.inspection.is_none()
            && self.events.is_none()
            && !self.state.inspecting
            && self.hooks.done
    }

    fn top_bar(&self, ui: &mut egui::Ui) {
        ui.horizontal(|ui| {
            ui.label(
                RichText::new("PinnacleCyPat")
                    .size(18.0)
                    .family(theme::bold_family())
                    .color(theme::TEXT),
            );
            ui.label(theme::muted(app_config::version_string()).size(12.0));
            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                match self.state.active {
                    Some(RunKind::Real) => theme::pill(ui, "Real run in progress", Tone::Danger),
                    Some(RunKind::Preview) => theme::pill(ui, "Dry run in progress", Tone::Accent),
                    None => theme::pill(ui, "Idle", Tone::Neutral),
                };
                let readme = match (self.state.readme_data(), &self.state.edited) {
                    (Some(_), Some(_)) => ("README edited", Tone::Warning),
                    (Some(_), None) => ("README loaded", Tone::Success),
                    (None, _) if self.state.inspecting => ("Parsing README", Tone::Accent),
                    (None, _) => ("No README", Tone::Warning),
                };
                theme::pill(ui, readme.0, readme.1);
                if self.state.privileged {
                    theme::pill(
                        ui,
                        format!("Running as {}", self.state.privileged_role),
                        Tone::Success,
                    );
                } else {
                    theme::pill(
                        ui,
                        format!("Not {} - preview only", self.state.privileged_role),
                        Tone::Danger,
                    )
                    .on_hover_text(self.state.elevation_hint);
                }
            });
        });
    }

    fn sidebar(&mut self, ui: &mut egui::Ui) -> Option<Action> {
        let mut action = None;
        ui.add_space(6.0);
        for tab in Tab::ALL {
            let selected = self.state.tab == tab;
            let badge = self.tab_badge(tab);
            let text = RichText::new(tab.title())
                .size(15.0)
                .color(if selected { theme::ACCENT } else { theme::TEXT })
                .family(theme::bold_family());
            let fill = if selected {
                theme::ACCENT_SOFT
            } else {
                egui::Color32::TRANSPARENT
            };
            let response = egui::Frame::new()
                .fill(fill)
                .corner_radius(egui::CornerRadius::same(8))
                .inner_margin(egui::Margin::symmetric(12, 8))
                .show(ui, |ui| {
                    ui.set_width(ui.available_width());
                    ui.horizontal(|ui| {
                        ui.label(text);
                        if let Some((badge, tone)) = badge {
                            ui.with_layout(
                                egui::Layout::right_to_left(egui::Align::Center),
                                |ui| {
                                    theme::pill(ui, badge, tone);
                                },
                            );
                        }
                    });
                })
                .response
                .interact(egui::Sense::click());
            if response.clicked() {
                action = Some(Action::OpenTab(tab));
            }
        }

        ui.add_space(theme::GAP);
        ui.separator();
        ui.add_space(4.0);
        self.checklist(ui);
        action
    }

    fn tab_badge(&self, tab: Tab) -> Option<(String, Tone)> {
        match tab {
            Tab::Readme => match (&self.state.edited, self.state.readme_data()) {
                (Some(_), _) => Some(("edited".to_string(), Tone::Warning)),
                (None, Some(_)) => Some(("ok".to_string(), Tone::Success)),
                (None, None) => None,
            },
            Tab::Run => self.state.active_record().map(|r| {
                let (done, total) = r.progress();
                (format!("{done}/{total}"), Tone::Accent)
            }),
            Tab::Results => {
                let kind = self.state.latest_finished()?;
                let record = self.state.record(kind)?;
                let failed = record
                    .summary
                    .as_ref()
                    .map(|s| s.results.iter().filter(|r| !r.success).count())
                    .unwrap_or(0);
                Some(if failed > 0 {
                    (format!("{failed} failed"), Tone::Danger)
                } else {
                    ("done".to_string(), Tone::Success)
                })
            }
        }
    }

    /// The README's by-hand instructions as a checklist, visible on every tab:
    /// they are the part of a round most often missed, and no task does them.
    fn checklist(&mut self, ui: &mut egui::Ui) {
        let items: Vec<(String, String)> = self
            .state
            .manual_directives()
            .iter()
            .map(|d| (d.subject.to_string(), d.handling.detail().to_string()))
            .collect();
        let done = self.state.hand_done.iter().filter(|d| **d).count();
        ui.horizontal(|ui| {
            ui.label(RichText::new("Do by hand").family(theme::bold_family()));
            if !items.is_empty() {
                theme::pill(
                    ui,
                    format!("{done}/{}", items.len()),
                    if done == items.len() {
                        Tone::Success
                    } else {
                        Tone::Warning
                    },
                );
            }
        });
        if items.is_empty() {
            ui.label(theme::muted("Load a README to see what it asks for by hand.").size(12.5));
            return;
        }
        egui::ScrollArea::vertical()
            .id_salt("checklist")
            .auto_shrink([false, true])
            .show(ui, |ui| {
                for (i, (subject, detail)) in items.iter().enumerate() {
                    if let Some(tick) = self.state.hand_done.get_mut(i) {
                        let label = RichText::new(subject).color(if *tick {
                            theme::MUTED
                        } else {
                            theme::TEXT
                        });
                        ui.checkbox(tick, label).on_hover_text(detail);
                    }
                }
            });
    }

    fn status_bar(&self, ui: &mut egui::Ui) {
        let now = Instant::now();
        ui.horizontal(|ui| {
            let text = if let Some(run) = self.state.active_record() {
                let (done, total) = run.progress();
                let current = run
                    .rows
                    .iter()
                    .find(|r| matches!(r.status, crate::state::TaskStatus::Running(_)))
                    .map(|r| r.name.as_str())
                    .unwrap_or("starting");
                format!(
                    "{} - {done} of {total} tasks - {current} - {}",
                    run.kind.title(),
                    theme::duration(run.elapsed(now))
                )
            } else if self.state.discovering {
                "Looking for the README...".to_string()
            } else if self.state.inspecting {
                "Parsing the README...".to_string()
            } else if let Some(source) = self.state.readme_source() {
                format!("README: {source}")
            } else {
                "No README loaded".to_string()
            };
            ui.label(theme::muted(text).size(12.5));
        });
    }

    fn toast(&self, ctx: &egui::Context) {
        let Some(toast) = &self.state.toast else {
            return;
        };
        let tone = if toast.success {
            Tone::Success
        } else {
            Tone::Warning
        };
        egui::Area::new(egui::Id::unique("toast"))
            .anchor(egui::Align2::RIGHT_BOTTOM, egui::vec2(-20.0, -44.0))
            .order(egui::Order::Foreground)
            .show(ctx, |ui| {
                egui::Frame::new()
                    .fill(theme::SURFACE)
                    .stroke(egui::Stroke::new(1.0, tone.fg()))
                    .corner_radius(egui::CornerRadius::same(10))
                    .inner_margin(egui::Margin::symmetric(16, 12))
                    .shadow(ctx.global_style().visuals.popup_shadow)
                    .show(ui, |ui| {
                        ui.label(
                            RichText::new(&toast.text)
                                .color(tone.fg())
                                .family(theme::bold_family()),
                        );
                    });
            });
    }
}

impl<P: Platform + 'static> eframe::App for App<P> {
    fn ui(&mut self, ui: &mut egui::Ui, _frame: &mut eframe::Frame) {
        self.poll();
        self.drive_hooks();
        let mut actions: Vec<Action> = Vec::new();

        egui::Panel::top("top")
            .frame(
                egui::Frame::new()
                    .fill(theme::SURFACE)
                    .inner_margin(egui::Margin::symmetric(18, 10))
                    .stroke(egui::Stroke::new(1.0, theme::BORDER)),
            )
            .show(ui, |ui| self.top_bar(ui));

        egui::Panel::bottom("status")
            .frame(
                egui::Frame::new()
                    .fill(theme::SURFACE)
                    .inner_margin(egui::Margin::symmetric(18, 6))
                    .stroke(egui::Stroke::new(1.0, theme::BORDER)),
            )
            .show(ui, |ui| self.status_bar(ui));

        egui::Panel::left("nav")
            .exact_size(220.0)
            .resizable(false)
            .frame(
                egui::Frame::new()
                    .fill(theme::SIDEBAR)
                    .inner_margin(egui::Margin::same(12))
                    .stroke(egui::Stroke::new(1.0, theme::BORDER)),
            )
            .show(ui, |ui| {
                if let Some(a) = self.sidebar(ui) {
                    actions.push(a);
                }
            });

        egui::CentralPanel::default()
            .frame(
                egui::Frame::new()
                    .fill(theme::BG)
                    .inner_margin(egui::Margin::symmetric(24, 18)),
            )
            .show(ui, |ui| {
                if let Some(error) = self.state.error.clone() {
                    theme::callout(ui, Tone::Danger, |ui| {
                        ui.horizontal(|ui| {
                            ui.label(RichText::new(&error).color(theme::DANGER));
                            if ui.small_button("Dismiss").clicked() {
                                self.state.error = None;
                            }
                        });
                    });
                    ui.add_space(theme::GAP);
                }
                let action = match self.state.tab {
                    Tab::Readme => screens::readme::show(ui, &mut self.state),
                    Tab::Run => screens::run::show(ui, &mut self.state),
                    Tab::Results => screens::results::show(ui, &mut self.state),
                };
                actions.extend(action);
            });

        if self.state.locations_open {
            actions.extend(screens::readme::locations_dialog(ui, &mut self.state));
        }
        if self.state.apply_dialog_open {
            actions.extend(screens::run::apply_dialog(ui, &mut self.state));
        }
        self.toast(ui.ctx());

        for action in actions {
            self.perform(action);
        }

        if self.state.inspecting
            || self.discovery.is_some()
            || self.events.is_some()
            || self.state.toast.is_some()
        {
            // Keep spinners, timers and the toast's expiry moving between events.
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
