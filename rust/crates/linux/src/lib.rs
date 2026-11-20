// =============================================================================
// pinnacle-linux
// Author: Maxwell McCormick
// Copyright 2026 Maxwell McCormick
// SPDX-License-Identifier: Apache-2.0
// =============================================================================

//! The Linux platform, in the same shape as the Windows one.
//!
//! Where Windows has the registry, the service control manager and netapi32,
//! Linux has text files under `/etc`, systemd and the shadow suite. The
//! difference is mostly in the mechanism: the decisions - which accounts are
//! authorised, which services are critical, what the README asked for - come
//! from `pinnacle-core` and are identical on both.
//!
//! Every write goes through [`pinnacle_core::remediation`], so a change here is
//! held to the same standard as one on Windows: read the state, skip if it is
//! already right, write, then read it back as proof.
//!
//! [`file_ops`], [`systemd_ops`], [`user_ops`], [`apt`], [`pam_ops`] and [`sudo_ops`] are the
//! proved-write layer - the counterparts of `registry_ops` and `service_ops` -
//! and every task in `platform.rs` is built on them. A task is listed only once
//! it is implemented: an entry that did nothing would be worse than its
//! absence, because the run would report success having changed nothing.

pub mod apt;
pub mod file_ops;
pub mod knowledge;
pub mod pam_ops;
pub mod readme_services;
pub mod sudo_ops;
pub mod systemd_ops;
pub mod tasks;
pub mod user_ops;

mod platform;
pub use platform::Linux;
