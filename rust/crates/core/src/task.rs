// =============================================================================
// PinnacleCyPat - The task contract
// Author: Maxwell McCormick
// Copyright 2026 Maxwell McCormick
// SPDX-License-Identifier: Apache-2.0
// =============================================================================

//! What every remediation task looks like, independent of the operating system
//! it runs against.
//!
//! Nothing here mentions Windows or Linux, and that is the point: the run
//! pipeline in the CLI drives `read_system_state` -> `execute` -> `verify` for
//! whichever platform crate supplied the task, so adding a second platform did
//! not require touching the pipeline at all.

use crate::models::{SystemInfo, TaskResult};
use async_trait::async_trait;

/// One unit of remediation: read the machine, change it, prove the change.
#[async_trait]
pub trait Task: Send {
    fn name(&self) -> &str;
    fn description(&self) -> &str;

    /// When true, only preview changes without applying them.
    fn dry_run(&self) -> bool;
    fn set_dry_run(&mut self, value: bool);

    /// Read current system state for this task area.
    async fn read_system_state(&mut self) -> SystemInfo;

    /// Execute the remediation for this task.
    async fn execute(&mut self) -> TaskResult;

    /// Verify that the remediation was successful.
    async fn verify(&mut self) -> bool;
}

/// Implements the metadata accessors of [`Task`] for a struct that has
/// `name: String`, `description: String`, and `dry_run: bool` fields.
#[macro_export]
macro_rules! impl_task_meta {
    () => {
        fn name(&self) -> &str {
            &self.name
        }
        fn description(&self) -> &str {
            &self.description
        }
        fn dry_run(&self) -> bool {
            self.dry_run
        }
        fn set_dry_run(&mut self, value: bool) {
            self.dry_run = value;
        }
    };
}
