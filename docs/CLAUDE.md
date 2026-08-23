# AI Assistant Instructions for PinnacleCyPat

This file provides guidance for AI assistants (Claude, GitHub Copilot, ChatGPT, etc.) when working with this codebase.

## Project Overview

**PinnacleCyPat** automates Windows security hardening for CyberPatriot
competition images, driven by the round's own README.

**The tool is the Rust program under `rust/`.** A C# implementation lived
alongside it until 2026-08-23 and is now frozen under `archive/csharp/`. Do not
change it, do not mirror changes into it, and do not treat it as a second
target — it is kept only as the reference the Rust port was written against.

**The project is proprietary — see [LICENSE](../LICENSE).** It is not open
source. The crate is deliberately marked unpublishable (`publish = false`); do
not suggest publishing it.

The full reference — every task, why it exists, what it changes and how — is
[ARCHITECTURE.md](ARCHITECTURE.md). Read it before changing a task.

## Architecture

```
rust/
├── src/
│   ├── main.rs             # Entry point, CLI parsing, run pipeline
│   ├── tui.rs              # Interactive menu (--tui)
│   ├── app_config.rs       # README discovery, defaults, version
│   ├── knowledge.rs        # The tables: registry settings, packages, services
│   ├── html.rs             # HTML structure, via html5ever
│   ├── readme_parser.rs    # README prose -> ReadmeData
│   ├── remediation.rs      # Prove-and-record wrapper for every change
│   ├── run_log.rs          # Transcript, diagnostics, remediation ledger
│   ├── command.rs          # Process execution
│   ├── chocolatey.rs       # Package installs and upgrades
│   ├── models/             # Data models
│   ├── tasks/              # The fourteen tasks
│   ├── native/             # Win32 APIs (#[cfg(windows)] only)
│   └── {account,policy,registry,service}_ops.rs   # Native-or-shell wrappers
└── tests/
    ├── corpus/             # README fixtures
    └── snapshots/          # What each fixture parses to
```

## Coding Standards

### General
- Rust 2021. `cargo fmt` and `cargo clippy --all-targets -- -D warnings` both
  gate the build; `./scripts/check.sh` runs everything CI does.
- `async`/`await` for all I/O
- Comments explain *why*, and name the failure that motivated the code. A
  comment restating what the line does is noise.

### Tasks
All security tasks must:
1. Implement the `Task` trait
2. `read_system_state()` - gather current state
3. `execute()` - perform remediation
4. `verify()` - confirm changes were applied
5. Return `TaskResult` with success/failure and message

### Example task structure
```rust
pub struct MyNewTask {
    name: String,
    description: String,
    dry_run: bool,
}

impl MyNewTask {
    pub fn new() -> Self {
        Self {
            name: "My New Task".to_string(),
            description: "What this task does".to_string(),
            dry_run: false,
        }
    }
}

#[async_trait]
impl Task for MyNewTask {
    impl_task_meta!();

    async fn read_system_state(&mut self) -> SystemInfo {
        SystemInfo::new()
    }

    async fn execute(&mut self) -> TaskResult {
        if self.dry_run {
            // Preview only. Honour this: a task that ignores it and writes
            // anyway is the worst bug this codebase can have.
            return TaskResult { /* ... */ ..Default::default() };
        }
        TaskResult { task_name: self.name.clone(), success: true, ..Default::default() }
    }

    async fn verify(&mut self) -> bool {
        // Read the machine back. Returning true because the write returned
        // success is what the remediation ledger exists to stop.
        true
    }
}
```

### Command execution
```rust
let (success, output, error) = command::execute("net", Some("user")).await;
```

Prefer the `*_ops` wrappers over shelling out — see **Windows-Specific** below.

### Console output
```rust
ui::markup_line("[green]✓ Success[/]");
ui::markup_line("[red]✗ Failed[/]");
ui::markup_line(&format!("[yellow]⚠ {}[/]", ui::escape(untrusted)));
```

`ui::escape` anything that came from the machine or the README — a display name
containing `[` is otherwise read as markup.

## Testing Requirements

### All new behaviour must have tests
- Unit tests live beside the code in `#[cfg(test)] mod tests`
- Cross-module tests live in `rust/tests/`
- Name the test after the behaviour, not the function:
  `group_members_exclude_the_connective_prose`, not `test_parse_groups`

### Parser changes go through the corpus

`rust/tests/corpus/` holds README fixtures; every one is parsed and snapshotted.
A parser change that alters any fixture's output shows as a diff to review.

```bash
cargo test --test corpus_tests                       # check
INSTA_UPDATE=always cargo test --test corpus_tests   # accept new output
cargo insta review                                   # step through diffs
```

**Read the diff before accepting it.** The snapshot is the record of what the
parser does; accepting a diff without reading it discards the only check there
is. Adding a real competition README to `tests/corpus/` is the single most
valuable contribution to the parser.

### Table changes are tested too

`knowledge.rs` holds the registry settings, package ids and service-name
mappings, with tests over the tables themselves — duplicate keys, contradictory
mappings, malformed paths. A table is the one kind of code where a typo compiles
perfectly.

### Running tests
```bash
./scripts/check.sh                    # everything CI runs
cargo test                            # just the suite
cargo test group_members              # by name
```

## Adding New Tasks

1. Create the task file in `rust/src/tasks/`
2. Implement the `Task` trait
3. Add the flag to the `FLAGS` table in `main.rs` - it is the single source of
   truth for both the help text and the unknown-argument check, so a flag cannot
   be accepted without also being documented
4. Register the task in the task-list builder
5. Add it to the menu's task list in `rust/src/tui.rs`
6. Write tests
7. Update `README.md`, `docs/ARCHITECTURE.md` and `docs/TASK_ANALYSIS.md`

> Steps 3-5 are three places for one fact, and that is a known wart: the flag,
> the registration and the menu entry can disagree. Making each task declare its
> own metadata, with the parser and the menu both reading from that, is the
> obvious fix and has not been done.

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

### Reading README data
```rust
pub struct MyTask {
    readme_data: Option<ReadmeData>,
}

pub fn set_readme_data(&mut self, data: ReadmeData) {
    self.readme_data = Some(data);
}
```

Register the call in `main.rs` too. A task with a `set_readme_data` that nobody
invokes silently behaves as if no README was given — which is exactly how
security hardening came to deny Remote Desktop on an image that required it.

Ask the README questions through `readme_services`, never by matching strings:
`is_remote_desktop_required`, `is_critical`, `resolve`. Two tasks that parse the
same README differently is a bug class this codebase has already had twice.

### Progress reporting

Only from code that is *not* already inside one. `main.rs` runs every task
inside a progress bar; a task that opens a second one draws over it.

```rust
let bar = ProgressBar::new(items.len() as u64);
for item in items {
    // process
    bar.inc(1);
}
bar.finish_and_clear();
```

### Error handling
```rust
match registry_ops::set_dword(key, name, value).await {
    Ok(()) => fixes.push(format!("Set {description}")),
    Err(e) => {
        // Record it. A failure counted for the on-screen tally but never
        // pushed into `issues` never reaches the summary or the run log.
        issues.push(format!("Failed to set {description} ({key}\\{name}): {e}"));
    }
}
```


## Files to Update When Adding Features

1. `main.rs` - CLI flags and task registration
2. `src/tui.rs` - the menu's task list, if it is a task
3. `README.md` - the flag table and the task table
4. `docs/ARCHITECTURE.md` - the detailed entry
5. `docs/TASK_ANALYSIS.md` - the implemented-tasks list
6. Tests

## Do NOT

- Add a task to the CLI without also adding it to the menu, or vice versa
- Compute a task's success from the *pre*-remediation state - "found nothing to
  fix" and "fixed everything" are both successes; "failed to fix" is not
- Return a bare boolean from an operation that can fail for different reasons
- Modify anything under `archive/` — the C# port is frozen
- Accept a corpus snapshot diff without reading it
- Disable Windows Update or Windows Defender (unless explicitly required)
- Make changes without dry-run support
- Skip tests for new behaviour
- Ignore README data when available
