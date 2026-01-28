# AI Assistant Instructions for CyberPatriot Automation

This file provides guidance for AI assistants (Claude, GitHub Copilot, ChatGPT, etc.) when working with this codebase.

## Project Overview

This is a **CyberPatriot competition automation tool** written in C# (.NET 10.0). It automates security hardening tasks for Windows systems based on competition README files.

## Architecture

```
CyberPatriotAutomation/
├── Program.cs              # Entry point, CLI argument parsing
├── AppConfig.cs            # Configuration constants and defaults
├── Models/                 # Data transfer objects
│   ├── SystemInfo.cs       # System state information
│   ├── TaskResult.cs       # Task execution results
│   └── ReadmeData models   # Parsed README data structures
├── Tasks/                  # Security remediation tasks
│   ├── BaseTask.cs         # Abstract base class for all tasks
│   ├── PasswordPolicyTask.cs
│   ├── AccountPermissionsTask.cs
│   ├── UserManagementTask.cs
│   ├── ServiceManagementTask.cs
│   ├── AuditPolicyTask.cs
│   ├── FirewallConfigurationTask.cs
│   ├── SecurityHardeningTask.cs
│   └── ProhibitedMediaTask.cs
├── Utilities/              # Helper classes
│   ├── CommandExecutor.cs  # Execute system commands
│   └── ReadmeParser.cs     # Parse HTML README files
└── Tests/                  # Unit tests (xUnit)
```

## Coding Standards

### General
- Use C# 12 features (file-scoped namespaces, records, pattern matching)
- Follow Microsoft C# coding conventions
- Use `async/await` for all I/O operations
- Use meaningful variable and method names

### Tasks
All security tasks must:
1. Inherit from `BaseTask`
2. Implement `ReadSystemStateAsync()` - gather current state
3. Implement `ExecuteAsync()` - perform remediation
4. Implement `VerifyAsync()` - confirm changes were applied
5. Return `TaskResult` with success/failure and message

### Example Task Structure
```csharp
public class MyNewTask : BaseTask
{
    public MyNewTask()
    {
        Name = "My New Task";
        Description = "What this task does";
    }

    public override async Task<SystemInfo> ReadSystemStateAsync()
    {
        // Gather current system state
        return new SystemInfo();
    }

    public override async Task<TaskResult> ExecuteAsync()
    {
        var result = new TaskResult { TaskName = Name, Success = true };
        // Perform remediation
        return result;
    }

    public override async Task<bool> VerifyAsync()
    {
        // Verify changes were applied
        return true;
    }
}
```

### Command Execution
Use `CommandExecutor` for running system commands:
```csharp
var (success, output, error) = await CommandExecutor.ExecuteAsync("net", "user");
```

### UI Output
Use Spectre.Console for all console output:
```csharp
AnsiConsole.MarkupLine("[green]✓ Success[/]");
AnsiConsole.MarkupLine("[red]✗ Failed[/]");
AnsiConsole.MarkupLine("[yellow]⚠ Warning[/]");
```

## Testing Requirements

### All new features must have unit tests
- Place tests in `Tests/` directory
- Use xUnit framework
- Use FluentAssertions for assertions
- Test file naming: `{ClassName}Tests.cs`

### Test Structure
```csharp
[Fact]
public void MethodName_Scenario_ExpectedBehavior()
{
    // Arrange
    var task = new MyTask();

    // Act
    var result = task.DoSomething();

    // Assert
    result.Should().NotBeNull();
}
```

### Running Tests
```powershell
dotnet test                           # Run all tests
dotnet test -v n                      # Verbose output with test names
dotnet test --filter "ClassName"      # Run specific test class
```

## Adding New Tasks

1. Create task file in `Tasks/` directory
2. Inherit from `BaseTask`
3. Add command line flag in `Program.cs`
4. Add to task list in `Program.cs`
5. Create unit tests in `Tests/`
6. Update README.md with new flag
7. Update TASK_ANALYSIS.md

## Important Considerations

### CyberPatriot Specific
- **NEVER disable CCS Client** - this is the scoring engine
- Prioritize README instructions over defaults
- Always check for admin privileges before system changes
- Support dry-run mode for previewing changes

### Security
- Don't hardcode sensitive passwords
- Use secure password generation
- Back up files before deletion
- Log all changes made

### Windows-Specific
- Use PowerShell or cmd for system commands
- Registry changes via `reg add`
- Service management via `sc` or `net`
- User management via `net user`

## Common Patterns

### Reading README Data
```csharp
private ReadmeData? _readmeData;

public void SetReadmeData(ReadmeData data)
{
    _readmeData = data;
}
```

### Progress Reporting
```csharp
await AnsiConsole.Progress()
    .StartAsync(async ctx =>
    {
        var task = ctx.AddTask("[cyan]Processing...[/]", maxValue: items.Count);
        foreach (var item in items)
        {
            // Process item
            task.Increment(1);
        }
    });
```

### Error Handling
```csharp
try
{
    // Risky operation
}
catch (Exception ex)
{
    result.Success = false;
    result.ErrorDetails = ex.Message;
    AnsiConsole.WriteException(ex);
}
```

## Files to Update When Adding Features

1. `Program.cs` - Add CLI flags and task registration
2. `README.md` - Document new features and usage
3. `TASK_ANALYSIS.md` - Add to implemented tasks list
4. `Tests/*.cs` - Add unit tests

## Do NOT

- Modify files in `bin/` or `obj/` directories
- Disable Windows Update or Windows Defender (unless explicitly required)
- Make changes without dry-run support
- Skip unit tests for new features
- Ignore README data when available
