// =============================================================================
// PinnacleCyPat GUI - Entry point (toolkit spike)
// Copyright 2026 Maxwell McCormick
// SPDX-License-Identifier: Apache-2.0
// =============================================================================

// No console window. The CLI keeps its console; this is why the GUI is a
// separate binary rather than a mode of it.
#![cfg_attr(windows, windows_subsystem = "windows")]

use eframe::egui;
use pinnacle_core::app_config;
use pinnacle_core::platform::Platform;

mod screenshot;

#[cfg(target_os = "linux")]
use pinnacle_linux::Linux as Host;
#[cfg(windows)]
use pinnacle_windows::Windows as Host;

#[cfg(not(any(windows, target_os = "linux")))]
compile_error!("PinnacleCyPat has no task set for this operating system.");

struct App {
    privileged: bool,
    shot: Option<screenshot::Screenshot>,
}

impl eframe::App for App {
    fn ui(&mut self, ui: &mut egui::Ui, _frame: &mut eframe::Frame) {
        ui.heading(format!("PinnacleCyPat {}", app_config::version_string()));
        if self.privileged {
            ui.colored_label(
                egui::Color32::LIGHT_GREEN,
                format!("Running as {}", Host::PRIVILEGED_ROLE),
            );
        } else {
            ui.colored_label(
                egui::Color32::LIGHT_RED,
                format!(
                    "Not running as {}. {}",
                    Host::PRIVILEGED_ROLE,
                    Host::ELEVATION_HINT
                ),
            );
        }
        ui.separator();
        egui::ScrollArea::vertical()
            .auto_shrink([false; 2])
            .show(ui, |ui| {
                for t in Host::tasks() {
                    ui.horizontal_wrapped(|ui| {
                        ui.strong(t.label);
                        ui.label(t.detail);
                        ui.monospace(t.flag);
                        if t.needs_readme {
                            ui.colored_label(egui::Color32::GOLD, "needs README");
                        }
                    });
                }
            });
        if let Some(shot) = &mut self.shot {
            shot.update(ui.ctx());
        }
    }
}

fn main() -> eframe::Result {
    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default().with_inner_size([900.0, 640.0]),
        ..Default::default()
    };
    eframe::run_native(
        "PinnacleCyPat",
        options,
        Box::new(|_cc| {
            Ok(Box::new(App {
                privileged: Host::is_privileged(),
                shot: screenshot::Screenshot::from_env(),
            }))
        }),
    )
}
