using CyberPatriotAutomation.Core.Models;

namespace CyberPatriotAutomation.Core.Tasks;

/// <summary>
/// Base class for remediation tasks
/// </summary>
public abstract class BaseTask
{
    public string Name { get; protected set; } = string.Empty;
    public string Description { get; protected set; } = string.Empty;

    /// <summary>
    /// Read current system state for this task area
    /// </summary>
    public abstract Task<SystemInfo> ReadSystemStateAsync();

    /// <summary>
    /// Execute the remediation for this task
    /// </summary>
    public abstract Task<TaskResult> ExecuteAsync();

    /// <summary>
    /// Verify that the remediation was successful
    /// </summary>
    public abstract Task<bool> VerifyAsync();
}
