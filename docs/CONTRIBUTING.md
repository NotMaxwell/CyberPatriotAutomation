# Contributing to PinnacleCyPat

Thank you for your interest in contributing to the PinnacleCyPat tool! This document provides guidelines and instructions for contributing.

## 📜 Canonical Source & Attribution

> **This repository is the canonical and official source of the PinnacleCyPat, authored and maintained by Maxwell McCormick.**
>
> PinnacleCyPat is **proprietary software** — see [LICENSE](../LICENSE). It is not open source, and unsolicited contributions are not accepted. This document is retained as the coding standard for work done **with the copyright holder's written permission**; forking, modifying and redistributing the project are prohibited regardless of how well the result follows it.

## Contributor License Agreement

If you submit any suggestion, patch, code or other material relating to this project, you agree that:

1. Your contribution is your original work, and you have the right to submit it
2. You **assign to Maxwell McCormick all right, title and interest** in that material, as required by Section 5 of the [LICENSE](../LICENSE)
3. You will be credited in the project's contributor list (if you wish)

## Table of Contents

- [Code of Conduct](#code-of-conduct)
- [Getting Started](#getting-started)
- [Development Setup](#development-setup)
- [Making Changes](#making-changes)
- [Testing](#testing)
- [Pull Request Process](#pull-request-process)
- [Coding Standards](#coding-standards)
- [Adding New Tasks](#adding-new-tasks)

## Code of Conduct

- Be respectful and inclusive
- Focus on constructive feedback
- Help others learn and grow
- Keep discussions on topic

## Getting Started

1. **Fork** the repository on GitHub
2. **Clone** your fork locally:
   ```powershell
   git clone https://github.com/YOUR_USERNAME/PinnacleCyPat.git
   cd PinnacleCyPat
   ```
3. **Add upstream** remote:
   ```powershell
   git remote add upstream https://github.com/ORIGINAL_OWNER/PinnacleCyPat.git
   ```

## Development Setup

### Prerequisites

- [.NET 10.0 SDK](https://dotnet.microsoft.com/download/dotnet/10.0)
- Visual Studio 2022, VS Code, or JetBrains Rider
- Git

### Building

```powershell
# Restore dependencies
dotnet restore

# Build
dotnet build

# Run tests
dotnet test
```

### Running

```powershell
# Run with dry-run mode
dotnet run -- --all --dry-run

# Run specific task
dotnet run -- --password-policy
```

## Making Changes

1. **Create a branch** for your feature or fix:
   ```powershell
   git checkout -b feature/your-feature-name
   # or
   git checkout -b fix/your-bug-fix
   ```

2. **Make your changes** following the coding standards

3. **Write tests** for new functionality

4. **Run tests** to ensure nothing is broken:
   ```powershell
   dotnet test
   ```

5. **Commit** your changes with a meaningful message:
   ```powershell
   git commit -m "Add feature: description of your feature"
   ```

6. **Push** to your fork:
   ```powershell
   git push origin feature/your-feature-name
   ```

## Testing

All new features and bug fixes must include tests.

### Running Tests

```powershell
# Run all tests
dotnet test

# Run with verbose output
dotnet test -v n

# Run specific test class
dotnet test --filter "ClassName"

# Run specific test method
dotnet test --filter "MethodName"
```

### Writing Tests

```csharp
using Xunit;
using FluentAssertions;

public class MyFeatureTests
{
    [Fact]
    public void MethodName_Scenario_ExpectedBehavior()
    {
        // Arrange
        var sut = new MyClass();

        // Act
        var result = sut.DoSomething();

        // Assert
        result.Should().NotBeNull();
        result.Value.Should().Be(expected);
    }

    [Theory]
    [InlineData("input1", "expected1")]
    [InlineData("input2", "expected2")]
    public void MethodName_WithVariousInputs_ReturnsExpected(string input, string expected)
    {
        // Test with multiple data sets
    }
}
```

## Pull Request Process

1. **Update documentation** if you've changed functionality
2. **Ensure all tests pass** locally
3. **Update the README** if you've added new features or commands
4. **Create a Pull Request** with a clear description:
   - What does this PR do?
   - Why is this change needed?
   - How was it tested?

### PR Checklist

- [ ] Tests added/updated
- [ ] Documentation updated
- [ ] README updated (if applicable)
- [ ] Code follows project standards
- [ ] All tests pass

## Coding Standards

### General

- Use C# 12 features where appropriate
- Follow [Microsoft C# Coding Conventions](https://docs.microsoft.com/en-us/dotnet/csharp/fundamentals/coding-style/coding-conventions)
- Use meaningful names for variables, methods, and classes
- Keep methods small and focused
- Use `async/await` for I/O operations

### File Organization

```csharp
// 1. Using statements (sorted alphabetically)
using System;
using System.Collections.Generic;
using PinnacleCyPat.Models;

// 2. Namespace
namespace PinnacleCyPat.Tasks;

// 3. Class declaration
public class MyTask : BaseTask
{
    // 4. Constants and static fields
    private const int MaxRetries = 3;

    // 5. Instance fields
    private readonly List<string> _items = new();

    // 6. Constructor
    public MyTask()
    {
        Name = "My Task";
        Description = "What this task does";
    }

    // 7. Public methods
    public override async Task<TaskResult> ExecuteAsync()
    {
        // Implementation
    }

    // 8. Private methods
    private void HelperMethod()
    {
        // Implementation
    }
}
```

### Naming Conventions

| Type | Convention | Example |
|------|------------|---------|
| Classes | PascalCase | `UserManagementTask` |
| Interfaces | IPascalCase | `ICommandExecutor` |
| Methods | PascalCase | `ExecuteAsync` |
| Properties | PascalCase | `TaskName` |
| Private fields | _camelCase | `_readmeData` |
| Local variables | camelCase | `userList` |
| Constants | PascalCase | `MaxRetries` |

### Console Output

Use Spectre.Console for all console output:

```csharp
// Success message
AnsiConsole.MarkupLine("[green]✓ Operation completed[/]");

// Error message
AnsiConsole.MarkupLine("[red]✗ Operation failed[/]");

// Warning message
AnsiConsole.MarkupLine("[yellow]⚠ Warning message[/]");

// Info message
AnsiConsole.MarkupLine("[cyan]ℹ Information[/]");
```

## Adding New Tasks

### Step 1: Create the Task Class

Create a new file in `Tasks/` directory:

```csharp
using PinnacleCyPat.Models;
using PinnacleCyPat.Utilities;
using Spectre.Console;

namespace PinnacleCyPat.Tasks;

public class MyNewTask : BaseTask
{
    public MyNewTask()
    {
        Name = "My New Task";
        Description = "Description of what this task does";
    }

    public override async Task<SystemInfo> ReadSystemStateAsync()
    {
        var systemInfo = new SystemInfo();
        // Read current system state
        return systemInfo;
    }

    public override async Task<TaskResult> ExecuteAsync()
    {
        var result = new TaskResult
        {
            TaskName = Name,
            Success = true,
            Message = "Task completed"
        };

        try
        {
            // Perform the task
            AnsiConsole.MarkupLine("[green]✓ Task completed successfully[/]");
        }
        catch (Exception ex)
        {
            result.Success = false;
            result.ErrorDetails = ex.Message;
        }

        return result;
    }

    public override async Task<bool> VerifyAsync()
    {
        // Verify changes were applied
        return true;
    }
}
```

### Step 2: Add CLI Flag

In `Program.cs`, add the command line argument:

```csharp
var runMyTask = cliArgs.Contains("--my-task") || cliArgs.Contains("-x");
```

And in the task registration section:

```csharp
if (runAll || runMyTask)
{
    tasks.Add(new MyNewTask());
}
```

### Step 3: Add Unit Tests

Create tests in `Tests/` directory:

```csharp
public class MyNewTaskTests
{
    [Fact]
    public void Constructor_ShouldInitializeNameAndDescription()
    {
        var task = new MyNewTask();

        task.Name.Should().Be("My New Task");
        task.Description.Should().NotBeNullOrEmpty();
    }

    [Fact]
    public async Task ExecuteAsync_ShouldReturnTaskResult()
    {
        var task = new MyNewTask();

        var result = await task.ExecuteAsync();

        result.Should().NotBeNull();
        result.TaskName.Should().Be("My New Task");
    }
}
```

### Step 4: Update Documentation

1. Update `README.md` with new command line flag
2. Update `TASK_ANALYSIS.md` with new task details
3. Add any new configuration to `CLAUDE.md`

## Questions?

If you have questions, feel free to:
- Open an issue on GitHub
- Check existing issues and discussions
- Review the codebase and existing tasks for examples

## 📜 License & Attribution

### Your Contributions

Contributions are governed by the [LICENSE](../LICENSE). By contributing, you:
- Assign copyright in the contribution to Maxwell McCormick (Section 5)
- Confirm you have the right to do so
- Agree to the Contributor License Agreement above

### Trademark and Forking

"PinnacleCyPat" is an unregistered trademark of Maxwell McCormick.

**Forking, modifying and redistributing this project are prohibited** by the LICENSE, with or without renaming. No right to use the name or any associated branding is granted for any purpose.

### Reporting Attribution Violations

If you discover a fork or derivative that:
- Has removed copyright notices
- Is using the "PinnacleCyPat" name without permission
- Has stripped the NOTICE file

Please report it by opening an issue titled "Attribution Violation Report" with:
- Link to the infringing content
- Screenshot/evidence of the violation
- Date discovered

Thank you for contributing! 🎉
