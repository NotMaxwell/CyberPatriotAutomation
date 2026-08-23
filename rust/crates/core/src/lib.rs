// =============================================================================
// pinnacle-core
// Author: Maxwell McCormick
// Copyright 2026 Maxwell McCormick
// SPDX-License-Identifier: Apache-2.0
// =============================================================================

//! Everything in PinnacleCyPat that does not depend on an operating system.
//!
//! The README parser, the remediation ledger, the run log, the data models and
//! the console layer all live here. None of them names Windows or Linux, and
//! all of them are exercised by the test suite on any host - which is why the
//! hardest component in the project, the parser, needed no work at all when a
//! second platform was added.
//!
//! A platform crate depends on this one, implements [`platform::Platform`], and
//! is selected by the binary at compile time.

pub mod app_config;
pub mod command;
pub mod html;
pub mod models;
pub mod platform;
pub mod readme_parser;
pub mod readme_services;
pub mod remediation;
pub mod run_log;
pub mod software_matching;
pub mod task;
pub mod ui;

pub use platform::{Concurrency, Platform, TaskFactory, TaskSpec};
pub use task::Task;
