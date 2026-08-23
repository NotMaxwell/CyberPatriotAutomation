# AI Assistant Instructions for PinnacleCyPat

This file provides guidance for AI assistants (Claude, GitHub Copilot, ChatGPT, etc.) when working with this codebase.

## Project Overview

**PinnacleCyPat** automates Windows security hardening for CyberPatriot
competition images, driven by the round's own README.

There are **two complete implementations**: C# (.NET 10) under `src/` and Rust
under `rust/`. A behavioural change generally belongs in both.

**The project is proprietary — see [LICENSE](../LICENSE).** It is not open
source. Both projects are deliberately marked unpublishable (`IsPackable=false`,
`publish = false`); do not suggest publishing them.

The full reference — every task, why it exists, what it changes and how — is
[ARCHITECTURE.md](ARCHITECTURE.md). Read it before changing a task.

## Architecture

```
PinnacleCyPat/
├── Program.cs              # Entry point, CLI parsing, run pipeline
├── Tui.cs                  # Interactive menu (--tui)
├── AppConfig.cs            # README discovery, defaults, version
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

1. Create the task file in `Tasks/` (C#) or `src/tasks/` (Rust)
2. Inherit `BaseTask` / implement the `Task` trait
3. Add the flag to the `Flags` / `FLAGS` table - it is the single source of truth
   for both the help text and the unknown-argument check, so a flag cannot be
   accepted without also being documented
4. Register the task in the task-list builder
5. Add it to the menu's task list in `Core/Tui.cs` and `rust/src/tui.rs`
6. Create unit tests
7. Update `README.md`, `docs/ARCHITECTURE.md` and `docs/TASK_ANALYSIS.md`

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

Prefer the **native Win32 path** over parsing command output, and keep the
shell-out path as the fallback. The command-line tools print localised tables: a
parser written against English output returns nothing on a non-English image, and
"nothing" reads as *"already compliant"* rather than as a failure.

| Instead of | Use | Via |
|---|---|---|
| `reg add` | `RegistryOps` | `NativeRegistry` (64-bit view explicitly) |
| `sc` / `net start` / `net stop` | `ServiceOps` | `NativeServices` (stops dependents, never prompts) |
| `net user` / `net localgroup` | `LocalAccounts` | `NativeAccounts` + `*-LocalUser` cmdlets |
| `net accounts` | `PolicyOps` | password and lockout policy |
| `auditpol.exe` | - | `NativeAuditPolicy` (category GUIDs) |
| `netsh advfirewall` | - | `NativeFirewall` (`INetFwPolicy2`) |
| `wmic product` | - | `NativeInstalledSoftware` (uninstall keys) |

Never use `net user` to set a password: it interactively confirms anything over
14 characters, and with no console to answer it the command aborts.

## Every Change Must Prove Itself

A write that returns success is not evidence that the machine changed. A value
written to the wrong key, a service reconfigured but still running, a policy
Windows silently normalised — all of them return success. Reporting those as
fixed is the failure mode the run log exists to prevent.

So the utilities above do not expose a bare write. Each mutating call goes
through `Remediation.ApplyAsync` (`remediation::apply` in Rust), which:

1. reads the current state, and returns early if it is already right —
   "already compliant" and "fixed" are different facts,
2. performs the write,
3. **reads the state again**, and records that second read as the proof.

The result is one `FixRecord` per change, carrying `Target`, `Intent`, `Before`,
`Action`, `Outcome` and `Evidence`. `RunLog.AppendLedger` renders them grouped by
task. Outcomes are `Fixed`, `AlreadyCompliant`, `Failed`, `Unverified` and
`Skipped`; `Unverified` means the write reported success and the machine
disagrees, or could not be read back.

**When you add a remediation, route it through `Remediation` rather than calling
the API directly.** If the result genuinely cannot be read back — setting a
password, which Windows will not hand back — use `ApplyUnprovableAsync` and say
why, rather than claiming a proof that was never taken. Audit-only tasks use
`RecordFinding` so their conclusions land in the same ledger.

Two rules for the `readState` callback:

- Return `null`/`None` **only** when the state could not be read. "Absent" is a
  readable state and must be spelled as one, or a failed read will be recorded
  as a successful removal.
- Read through the same code path the task's own verify step uses. Two parsers
  that disagree make a change look unapplied when it was not.

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

Only from code that is *not* already inside one. `Program.cs` runs every task's
`ExecuteAsync` inside an `AnsiConsole.Progress()`, and Spectre throws on a second
concurrent dynamic display — an exception the task's own catch reports as a
plain failure, having applied nothing.

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

1. `Program.cs` / `main.rs` - CLI flags and task registration
2. `Core/Tui.cs` / `src/tui.rs` - the menu's task list, if it is a task
3. `README.md` - the flag table and the task table
4. `docs/ARCHITECTURE.md` - the detailed entry
5. `docs/TASK_ANALYSIS.md` - the implemented-tasks list
6. Tests

## Do NOT

- Add a task to the CLI without also adding it to the menu, or vice versa
- Compute a task's success from the *pre*-remediation state - "found nothing to
  fix" and "fixed everything" are both successes; "failed to fix" is not
- Return a bare boolean from an operation that can fail for different reasons
- Modify files in `bin/` or `obj/` directories
- Disable Windows Update or Windows Defender (unless explicitly required)
- Make changes without dry-run support
- Skip unit tests for new features
- Ignore README data when available
