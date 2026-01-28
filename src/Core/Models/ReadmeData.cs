namespace CyberPatriotAutomation.Core.Models;

/// <summary>
/// Represents parsed data from a CyberPatriot README file
/// </summary>
public class ReadmeData
{
    /// <summary>
    /// Title of the competition round
    /// </summary>
    public string Title { get; set; } = string.Empty;

    /// <summary>
    /// Operating system specified in the README
    /// </summary>
    public string OperatingSystem { get; set; } = string.Empty;

    /// <summary>
    /// Competition scenario description
    /// </summary>
    public string Scenario { get; set; } = string.Empty;

    /// <summary>
    /// List of authorized administrators with their passwords
    /// </summary>
    public List<AuthorizedUser> Administrators { get; set; } = new();

    /// <summary>
    /// List of authorized standard users
    /// </summary>
    public List<AuthorizedUser> Users { get; set; } = new();

    /// <summary>
    /// Software that should be installed/updated
    /// </summary>
    public List<SoftwareRequirement> RequiredSoftware { get; set; } = new();

    /// <summary>
    /// Software that should be removed (prohibited)
    /// </summary>
    public List<string> ProhibitedSoftware { get; set; } = new();

    /// <summary>
    /// Services that must be running
    /// </summary>
    public List<string> CriticalServices { get; set; } = new();

    /// <summary>
    /// Services that should not be running
    /// </summary>
    public List<string> ProhibitedServices { get; set; } = new();

    /// <summary>
    /// Groups that need to be created with their members
    /// </summary>
    public List<GroupRequirement> GroupRequirements { get; set; } = new();

    /// <summary>
    /// New user accounts that need to be created
    /// </summary>
    public List<string> UsersToCreate { get; set; } = new();

    /// <summary>
    /// Competition guidelines and warnings
    /// </summary>
    public List<string> Guidelines { get; set; } = new();

    /// <summary>
    /// Actionable items extracted from paragraph tags
    /// </summary>
    public List<ActionableItem> ActionableItems { get; set; } = new();

    /// <summary>
    /// Raw sections extracted from the README
    /// </summary>
    public Dictionary<string, string> Sections { get; set; } = new();
}

/// <summary>
/// Represents an actionable item extracted from the README
/// </summary>
public class ActionableItem
{
    public ActionableItemType Type { get; set; }
    public string Description { get; set; } = string.Empty;
    public string RawText { get; set; } = string.Empty;
    public Dictionary<string, string> Details { get; set; } = new();
}

/// <summary>
/// Types of actionable items that can be extracted
/// </summary>
public enum ActionableItemType
{
    CreateUser,
    CreateGroup,
    AddUserToGroup,
    RemoveUserFromGroup,
    EnableService,
    DisableService,
    InstallSoftware,
    RemoveSoftware,
    ConfigureSetting,
    SecurityPolicy,
    FileOperation,
    Other,
}

/// <summary>
/// Represents an authorized user from the README
/// </summary>
public class AuthorizedUser
{
    public string Username { get; set; } = string.Empty;
    public string? Password { get; set; }
    public bool IsAdmin { get; set; }
    public bool IsPrimaryUser { get; set; }
    public string? Notes { get; set; }
}

/// <summary>
/// Represents a software requirement from the README
/// </summary>
public class SoftwareRequirement
{
    public string Name { get; set; } = string.Empty;
    public string? Version { get; set; }
    public bool ShouldBeLatest { get; set; }
    public bool IsRequired { get; set; } = true;
    public string? Notes { get; set; }
}

/// <summary>
/// Represents a group that needs to be created
/// </summary>
public class GroupRequirement
{
    public string GroupName { get; set; } = string.Empty;
    public List<string> Members { get; set; } = new();
}
