// =============================================================================
// PinnacleCyPat GUI - Tabs
// Copyright 2026 Maxwell McCormick
// SPDX-License-Identifier: Apache-2.0
// =============================================================================

//! One module per tab, plus the dialog each tab owns. Every entry point has the
//! same shape:
//!
//! ```ignore
//! pub fn show(ui: &mut egui::Ui, state: &mut AppState) -> Option<Action>
//! ```
//!
//! A tab may change the state it owns (inputs, ticks, filters) and returns an
//! [`Action`](crate::state::Action) for anything that starts work or moves
//! elsewhere. It never touches the backend, which is what keeps a tab testable
//! without a running engine. Build with [`crate::theme`]'s components.

pub mod readme;
pub mod results;
pub mod run;
