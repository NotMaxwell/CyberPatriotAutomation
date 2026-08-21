// =============================================================================
// CyberPatriot Automation Tool (Rust port)
// Author: Maxwell McCormick
// Copyright (c) 2026 Maxwell McCormick. All Rights Reserved.
// =============================================================================

//! Library crate exposing the core of the CyberPatriot Automation Tool so it can
//! be exercised by integration tests, mirroring the C# `Core` namespace.

pub mod account_ops;
pub mod app_config;
pub mod command;
pub mod models;
pub mod native;
pub mod policy_ops;
pub mod readme_parser;
pub mod registry_ops;
pub mod remediation;
pub mod run_log;
pub mod service_ops;
pub mod tasks;
pub mod ui;
