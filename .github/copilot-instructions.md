# GitHub Copilot Instructions

## Project Context
This is a CyberPatriot competition automation tool in C# (.NET 9.0) that automates Windows security hardening.

## Key Patterns

### Task Implementation
All tasks inherit from `BaseTask` and implement:
- `ReadSystemStateAsync()` - Read current system state
- `ExecuteAsync()` - Apply security fixes
- `VerifyAsync()` - Verify fixes were applied

### Command Execution
```csharp
var (success, output, error) = await CommandExecutor.ExecuteAsync("command", "args");
```

### Console Output (Spectre.Console)
```csharp
AnsiConsole.MarkupLine("[green]✓ Success[/]");
AnsiConsole.MarkupLine("[red]✗ Failed[/]");
```

## Testing
- Use xUnit with FluentAssertions
- All new features need unit tests
- Test file naming: `{ClassName}Tests.cs`

## Important Rules
1. Never disable CCS Client service
2. Always support dry-run mode
3. Back up files before deletion
4. Use async/await for I/O
5. Follow Microsoft C# conventions
