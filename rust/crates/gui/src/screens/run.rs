// =============================================================================
// PinnacleCyPat GUI - Run screen
// Copyright 2026 Maxwell McCormick
// SPDX-License-Identifier: Apache-2.0
// =============================================================================

use eframe::egui;

use crate::state::{Action, AppState};

/// Placeholder until the screen's issue lands.
pub fn show(ui: &mut egui::Ui, _state: &mut AppState) -> Option<Action> {
    ui.label("Run screen: not built yet");
    None
}
