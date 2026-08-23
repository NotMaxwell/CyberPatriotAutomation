# GitHub Copilot Instructions

## Project Context

PinnacleCyPat: a Windows security-hardening tool for CyberPatriot competition
images. One Rust implementation under `rust/`; the retired C# port is frozen
under `archive/csharp/` and must not be changed. Formerly written as
Rust under `rust/`. Changes to behaviour generally belong in both.

**This project is proprietary (see LICENSE).** Do not add code copied from
elsewhere without checking its licence, and do not suggest publishing the package
to NuGet or crates.io — both projects are deliberately marked unpublishable.

## Key Patterns

### Task implementation

All tasks inherit `BaseTask` (C#) / implement the `Task` trait (Rust) and provide:

- `ReadSystemStateAsync()` — read current state, display it, change nothing
- `ExecuteAsync()` — apply remediation, return a `TaskResult`
- `VerifyAsync()` — **re-read the machine** and confirm; never trust `Execute`'s report

### Command execution

```csharp
var (success, output, error) = await CommandExecutor.ExecuteAsync("command", "args");
await CommandExecutor.PowerShellAsync(script);       // state changes; errors surface
await CommandExecutor.PowerShellQueryAsync(script);  // reads; absence is not failure
```

Interpolated values go through `CommandExecutor.PsQuote`.

### Console output (Spectre.Console)

```csharp
AnsiConsole.MarkupLine("[green]✓ Success[/]");
AnsiConsole.MarkupLine("[red]✗ Failed[/]");
```

Escape untrusted text with `Markup.Escape`. Everything printed is mirrored into
the run log automatically — do not add separate logging calls.

## Adding a task

1. Create the task under `Core/Tasks/` (C#) or `src/tasks/` (Rust)
2. Add its flag to `Program.Flags` / `FLAGS` — the single source of truth for
   both the help text and the unknown-argument check
3. Register it in the task-list builder
4. Add it to the menu's task list in `rust/src/tui.rs`
5. Add tests
6. Update `README.md` and `docs/ARCHITECTURE.md`

## Testing

- xUnit + FluentAssertions (C#), built-in test harness (Rust)
- Unit tests live beside the code in `#[cfg(test)] mod tests`; cross-module
  tests in `rust/tests/`. Parser changes go through the corpus snapshots.
- Tests run on Linux, so anything under `Core/Native/` (`#if WINDOWS`) is not
  covered by them — check Windows paths with
  `cargo check --target x86_64-pc-windows-gnu` on the Rust side

## Important rules

1. Never disable the CCS Client service — it is the scoring engine
2. Every task must honour `--dry-run` and change nothing under it
3. Never delete accounts when the authorised set is empty (a parsing failure)
4. A service named critical must never also be queued for disabling
5. Return the *reason* for a failure, not a bare boolean
6. Prefer the native Win32 path over parsing localised command output
