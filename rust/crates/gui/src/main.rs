// =============================================================================
// PinnacleCyPat GUI - Entry point
// Copyright 2026 Maxwell McCormick
// SPDX-License-Identifier: Apache-2.0
// =============================================================================

// No console window. The CLI keeps its console; this is why the GUI is a
// separate binary rather than a mode of it.
#![cfg_attr(windows, windows_subsystem = "windows")]

use eframe::egui;

mod app;
mod backend;
mod screens;
mod screenshot;
mod state;
mod theme;

#[cfg(target_os = "linux")]
use pinnacle_linux::Linux as Host;
#[cfg(windows)]
use pinnacle_windows::Windows as Host;

#[cfg(not(any(windows, target_os = "linux")))]
compile_error!("PinnacleCyPat has no task set for this operating system.");

fn main() -> eframe::Result {
    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_title("PinnacleCyPat")
            .with_inner_size([1240.0, 820.0])
            .with_min_inner_size([960.0, 600.0]),
        ..Default::default()
    };
    eframe::run_native(
        "PinnacleCyPat",
        options,
        Box::new(|cc| {
            let app = app::App::<Host>::new(&cc.egui_ctx)?;
            Ok(Box::new(app))
        }),
    )
}
