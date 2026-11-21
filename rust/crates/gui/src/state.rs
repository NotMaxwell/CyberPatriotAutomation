// =============================================================================
// PinnacleCyPat GUI - Application state
// Copyright 2026 Maxwell McCormick
// SPDX-License-Identifier: Apache-2.0
// =============================================================================

//! The session state lives in `pinnacle-core`, shared with the web UI so the
//! two front ends cannot disagree about the rules. Re-exported here so the
//! GUI's modules keep naming it `crate::state`.

pub use pinnacle_core::session::*;
