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
}
