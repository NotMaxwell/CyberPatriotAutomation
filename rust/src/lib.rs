// =============================================================================
// PinnacleCyPat (Rust port)
// Author: Maxwell McCormick
// Copyright (c) 2026 Maxwell McCormick. All Rights Reserved.
// =============================================================================

//! Library crate exposing the core of the PinnacleCyPat so it can
//! be exercised by integration tests, mirroring the C# `Core` namespace.

pub mod app_config;
pub mod command;
pub mod models;
pub mod native;
pub mod readme_parser;
pub mod readme_services;
pub mod registry_ops;
pub mod run_log;
pub mod service_ops;
pub mod software_matching;
pub mod tasks;
pub mod tui;
pub mod ui;
