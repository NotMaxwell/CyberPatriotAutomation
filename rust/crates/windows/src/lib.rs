// =============================================================================
// pinnacle-windows
// Author: Maxwell McCormick
// Copyright 2026 Maxwell McCormick
// SPDX-License-Identifier: Apache-2.0
// =============================================================================

//! The Windows platform: Win32 bindings, the proved-write wrappers built on
//! them, the hardening tables, and the fifteen tasks that use all three.
//!
//! Prefer the native path over parsing command output, and keep the shell-out
//! as the fallback. The command-line tools print localised tables: a parser
//! written against English output returns nothing on a non-English image, and
//! "nothing" reads as *already compliant* rather than as a failure.

pub mod account_ops;
pub mod chocolatey;
pub mod knowledge;
pub mod native;
pub mod policy_ops;
pub mod readme_services;
pub mod registry_ops;
pub mod service_ops;
pub mod tasks;

mod platform;
pub use platform::Windows;
