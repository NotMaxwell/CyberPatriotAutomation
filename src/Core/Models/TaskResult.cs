namespace CyberPatriotAutomation.Core.Models;

/// <summary>
/// Represents the result of executing a remediation task
/// </summary>
public class TaskResult
{
    public string TaskName { get; set; } = string.Empty;
    public bool Success { get; set; }
    public string Message { get; set; } = string.Empty;
    public string? ErrorDetails { get; set; }
    public DateTime ExecutedAt { get; set; } = DateTime.Now;

    /// <summary>
    /// Number of items/actions attempted in this task
    /// </summary>
    public int ItemsAttempted { get; set; }

    /// <summary>
    /// Number of items/actions that succeeded
    /// </summary>
    public int ItemsSucceeded { get; set; }

    /// <summary>
    /// Number of items that were skipped (already compliant or N/A)
    /// </summary>
    public int ItemsSkipped { get; set; }

    /// <summary>
    /// Confidence level (0-100) based on verification results
    /// </summary>
    public int ConfidencePercent { get; set; } = 100;

    /// <summary>
    /// Whether verification passed after execution
    /// </summary>
    public bool Verified { get; set; }

    /// <summary>
    /// Calculates completion rate as a percentage
    /// </summary>
    /// <remarks>
    /// When a task reports no per-item counts, fall back to whether the task
    /// itself succeeded. Returning a flat 100% in that case reported full
    /// completion for tasks that had failed outright - and since no task
    /// populates <see cref="ItemsAttempted"/>, that was every task.
    /// </remarks>
    public double CompletionRate =>
        ItemsAttempted > 0 ? (double)(ItemsSucceeded + ItemsSkipped) / ItemsAttempted * 100
        : Success ? 100
        : 0;
}
