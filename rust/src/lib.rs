// =============================================================================
// PinnacleCyPat (Rust port)
// Author: Maxwell McCormick
// Copyright 2026 Maxwell McCormick
// SPDX-License-Identifier: Apache-2.0
// =============================================================================

//! Library crate exposing the core of the PinnacleCyPat so it can
//! be exercised by integration tests, mirroring the C# `Core` namespace.

pub mod account_ops;
pub mod app_config;
pub mod chocolatey;
pub mod command;
pub mod html;
pub mod knowledge;
pub mod models;
pub mod native;
pub mod policy_ops;
pub mod readme_parser;
pub mod readme_services;
pub mod registry_ops;
pub mod remediation;
pub mod run_log;
pub mod service_ops;
pub mod software_matching;
pub mod tasks;
pub mod tui;
pub mod ui;
