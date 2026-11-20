// =============================================================================
// PinnacleCyPat GUI - Screens
// Copyright 2026 Maxwell McCormick
// SPDX-License-Identifier: Apache-2.0
// =============================================================================

//! One module per step. Every screen has the same shape:
//!
//! ```ignore
//! pub fn show(ui: &mut egui::Ui, state: &mut AppState) -> Option<Action>
//! ```
//!
//! A screen may change the state it owns (text inputs, ticks, filters) and
//! returns an [`Action`](crate::state::Action) for anything that starts work or
//! moves to another screen. It never touches the backend directly, which is
//! what keeps a screen testable without a running engine.

pub mod confirm;
pub mod readme;
pub mod results;
pub mod run;
pub mod tasks;
