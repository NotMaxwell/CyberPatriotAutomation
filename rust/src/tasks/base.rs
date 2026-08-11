//! Base trait for remediation tasks.

use crate::models::{SystemInfo, TaskResult};
use async_trait::async_trait;

/// Base trait for remediation tasks (mirrors the C# `BaseTask`).
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
