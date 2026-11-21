// =============================================================================
// PinnacleCyPat GUI - Run tab
// Copyright 2026 Maxwell McCormick
// SPDX-License-Identifier: Apache-2.0
// =============================================================================

use eframe::egui;

use crate::state::{Action, AppState};

/// Placeholder until the tab is built.
pub fn show(ui: &mut egui::Ui, _state: &mut AppState) -> Option<Action> {
    ui.label("Run tab: not built yet");
    None
}

/// The real-run confirmation, drawn over every tab while
/// `state.apply_dialog_open`. Placeholder until the tab is built.
pub fn apply_dialog(ui: &mut egui::Ui, state: &mut AppState) -> Option<Action> {
    let _ = (ui, state);
    None
}
