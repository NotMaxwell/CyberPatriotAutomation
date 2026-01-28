namespace CyberPatriotAutomation.Core.Models;

/// <summary>
/// Represents current system state information
/// </summary>
public class SystemInfo
{
    public string? OSVersion { get; set; }
    public List<string> RunningServices { get; set; } = new();
    public List<string> InstalledApplications { get; set; } = new();
    public List<string> UserAccounts { get; set; } = new();
    public List<string> FirewallRules { get; set; } = new();
    public Dictionary<string, string> RegistrySettings { get; set; } = new();

    // Added for audit task output
    public string? RawOutput { get; set; }
    public string? ErrorOutput { get; set; }
}
