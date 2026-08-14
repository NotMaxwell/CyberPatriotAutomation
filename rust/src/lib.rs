// =============================================================================
// CyberPatriot Automation Tool (Rust port)
// Author: Maxwell McCormick
// Copyright (c) 2026 Maxwell McCormick. All Rights Reserved.
// =============================================================================

//! Library crate exposing the core of the CyberPatriot Automation Tool so it can
//! be exercised by integration tests, mirroring the C# `Core` namespace.

pub mod app_config;
pub mod command;
pub mod models;
pub mod readme_parser;
pub mod run_log;
pub mod tasks;
pub mod ui;
