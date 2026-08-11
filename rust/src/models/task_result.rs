use chrono::{DateTime, Local};

/// Represents the result of executing a remediation task.
#[derive(Debug, Clone)]
pub struct TaskResult {
    pub task_name: String,
    pub success: bool,
    pub message: String,
    pub error_details: Option<String>,
    pub executed_at: DateTime<Local>,

    /// Number of items/actions attempted in this task.
    pub items_attempted: i32,
    /// Number of items/actions that succeeded.
    pub items_succeeded: i32,
    /// Number of items that were skipped (already compliant or N/A).
    pub items_skipped: i32,

    /// Confidence level (0-100) based on verification results.
    pub confidence_percent: i32,
    /// Whether verification passed after execution.
    pub verified: bool,
}

impl Default for TaskResult {
    fn default() -> Self {
        Self {
            task_name: String::new(),
            success: false,
            message: String::new(),
            error_details: None,
            executed_at: Local::now(),
            items_attempted: 0,
            items_succeeded: 0,
            items_skipped: 0,
            confidence_percent: 100,
            verified: false,
        }
    }
}

impl TaskResult {
    /// Calculates completion rate as a percentage.
    pub fn completion_rate(&self) -> f64 {
        if self.items_attempted > 0 {
            (self.items_succeeded + self.items_skipped) as f64 / self.items_attempted as f64 * 100.0
        } else {
            100.0
        }
    }
}
