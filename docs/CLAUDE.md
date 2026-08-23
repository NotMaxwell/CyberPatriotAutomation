# AI Assistant Instructions for PinnacleCyPat

This file provides guidance for AI assistants (Claude, GitHub Copilot, ChatGPT, etc.) when working with this codebase.

## Project Overview

**PinnacleCyPat** automates security hardening for CyberPatriot competition
images, driven by the round's own README. It targets **Windows and Linux**: one
binary, one pipeline, one README parser, with a per-platform task set selected
at compile time (see **The platform seam** below).

**The tool is the Rust program under `rust/`.** A C# implementation lived
alongside it until 2026-08-23 and is now frozen under `archive/csharp/`. Do not
change it, do not mirror changes into it, and do not treat it as a second
target — it is kept only as the reference the Rust port was written against.

**Licensed under Apache 2.0 — see [LICENSE](../LICENSE).** `publish = false`
in `Cargo.toml` is a choice, not a licence restriction: this is an application,
not a library, so there is nothing for another crate to depend on.

Keep `LICENSE` byte-identical to the canonical Apache 2.0 text — a reworded
licence stops being detectable by scanners, and a previous edit to it had
already drifted from upstream. New source files carry the two-line header:
`Copyright 2026 Maxwell McCormick` and `SPDX-License-Identifier: Apache-2.0`.

The full reference — every task, why it exists, what it changes and how — is
[ARCHITECTURE.md](ARCHITECTURE.md). Read it before changing a task.

## Architecture

`rust/` is a Cargo workspace of four crates. The split is along the line that
already existed in the code, and it is what makes a second operating system
additive rather than a set of `#[cfg]` branches threaded through every task.

```
rust/
├── Cargo.toml                     workspace root; the release profile lives here
└── crates/
    ├── core/          pinnacle-core     — no operating system named
    │   ├── platform.rs                  the seam: TaskSpec, Concurrency, Platform
    │   ├── task.rs                      the Task trait and impl_task_meta!
    │   ├── readme_parser.rs · html.rs   README prose -> ReadmeData
    │   ├── readme_services.rs           service-name matching, table as a parameter
    │   ├── remediation.rs               prove-and-record wrapper for every change
    │   ├── run_log.rs                   transcript, diagnostics, remediation ledger
    │   ├── app_config.rs · command.rs · ui.rs · software_matching.rs
    │   ├── models/                      data models
    │   └── tests/                       README corpus and snapshots
    ├── windows/       pinnacle-windows  — fifteen tasks
    │   ├── platform.rs                  the task table
    │   ├── native/                      Win32 APIs (#[cfg(windows)] only)
    │   ├── {account,policy,registry,service}_ops.rs   proved writes
    │   ├── knowledge.rs · chocolatey.rs · readme_services.rs
    │   └── tasks/
    ├── linux/         pinnacle-linux    — thirteen tasks
    │   ├── platform.rs                  the task table
    │   ├── file_ops.rs                  proved writes to /etc (what registry_ops is)
    │   ├── systemd_ops.rs               proved systemctl (what service_ops is)
    │   ├── user_ops.rs                  /etc/passwd, shadow, group; useradd, chage
    │   ├── apt.rs · knowledge.rs · readme_services.rs
    │   └── tasks/
    └── cli/           pinnacle-cypat    — the binary
        ├── main.rs                      argument parsing and the run pipeline
        └── tui.rs                       the interactive menu
```

**Which crate does a change belong in?** If it names Windows or Linux, it is not
core. If it would be true on both, it is not a platform crate. When a piece of
logic is shared but its *data* is not — service-name matching, for one — put the
logic in core and take the table as a parameter, the way
`core::readme_services::resolve` does.

**Do not reintroduce `#[cfg(windows)] / #[cfg(unix)]` pairs of the same
function.** Two implementations sitting next to each other look symmetrical and
nothing checks that they still mean the same thing; that is precisely how the C#
port came to disagree with the Rust one about Remote Desktop. Put each in its
platform crate.

## The platform seam

A platform crate's entire public surface is one `Platform` impl:

```rust
pub trait Platform {
    const NAME: &'static str;               // "Windows" / "Linux"
    const PRIVILEGED_ROLE: &'static str;    // "Administrator" / "root"
    fn tasks() -> &'static [TaskSpec];
    fn is_privileged() -> bool;
}
```

`TaskSpec` describes one task **once**: flag, short flag, `--help` line, menu
label, menu detail, whether it needs a README, whether it may run concurrently,
and how to construct it. `main.rs` and `tui.rs` name no operating system — they
read `Host::tasks()`, where `Host` is selected by one `cfg` at the top of
`main.rs`.

This replaced three hand-maintained lists that were free to disagree, and did: a
task could reach the CLI without reaching the menu, making it invisible to
anyone who double-clicks `RUN.bat`. **Adding a task is now one row.**

A task with no counterpart on the other platform simply has no row there —
Group Policy has none on Linux. Do not add a stub that reports success.

## Coding Standards

### General
- Rust 2024. `cargo fmt` and `cargo clippy --all-targets -- -D warnings` both
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
- Cross-module tests live in `rust/crates/*/tests/`
- Name the test after the behaviour, not the function:
  `group_members_exclude_the_connective_prose`, not `test_parse_groups`

### Parser changes go through the corpus

`rust/crates/core/tests/corpus/` holds README fixtures; every one is parsed and snapshotted.
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

**One row, in one file.** Add a `TaskSpec` to the platform's `platform.rs` —
`crates/windows/src/platform.rs` or `crates/linux/src/platform.rs` — and the
flag, the `--help` line, the menu entry and the constructor all come from it.

1. Create the task file in `crates/<platform>/src/tasks/` and register the
   module in that directory's `mod.rs`
2. Implement the `Task` trait (`pinnacle_core::Task`)
3. Add one `TaskSpec` row to the platform's `platform.rs`, in the order a run
   should execute it
4. Write tests
5. Update `README.md`, `docs/ARCHITECTURE.md` and `docs/TASK_ANALYSIS.md`

There is nothing to change in `main.rs` or `tui.rs`, and there is no way to add
a task that the CLI accepts but the menu does not offer — two tests in
`main.rs` pin that.

**Keep the flag consistent across platforms.** If Windows spells it
`--password-policy` / `-p`, Linux does too. A run log from a Linux round should
read next to a Windows one, and muscle memory should not become a hazard.
`shared_flags_keep_their_windows_spelling` in `crates/linux/src/platform.rs`
enforces it.

**If the task has no counterpart on the other platform, leave the row out
there.** Group Policy has no Linux analogue and has no row. A stub that reports
success is worse than an absence, because the run then claims to have done
something.

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

### Linux-Specific

Route every write through the `*_ops` modules for the same reason, though the
hazards are different ones:

| Instead of | Use | Why |
|---|---|---|
| editing `/etc/*` by hand | `file_ops::set` | duplicate definitions mean opposite things in `sshd_config` (first wins) and `sysctl.conf` (last wins); `file_ops` leaves exactly one, and writes atomically so an interruption cannot truncate `/etc/shadow` |
| `systemctl disable` | `systemd_ops::disable` | disable alone is not enough — socket activation and a `Wants=` from another unit both restart it. It stops, disables **and masks** |
| parsing `net`-style output | reading `/etc/passwd`, `/etc/group` | these are POSIX-fixed colon records with no locale near them, so unlike Windows the file is the better source. **Writes** still go through `useradd`/`usermod`/`gpasswd`, which take the lock and keep `/etc/shadow` in step |
| `apt-get` directly | `apt::install` / `apt::purge` | needs `DEBIAN_FRONTEND=noninteractive` or it opens a dialog and hangs until the timeout, and `--force-confold` or an upgrade silently reverts the hardening applied earlier in the same run |
| `remove` | `purge` | a removed package keeps its configuration and unit file, so a reinstall restores the attacker's settings |

Write SSH and sysctl settings to the **drop-in** files (`sshd_config.d/`,
`sysctl.d/`), never the main file. Ubuntu 22.04+ puts the `Include` first in
`sshd_config` and sshd obeys the first definition it sees, so editing the main
file is overridden by any drop-in already present — the run looks applied and
changes nothing.

Two orderings are load-bearing and both end a round if reversed:

- **Open firewall ports before enabling `ufw`.** Enabling a default-deny
  firewall with no allow rule drops the SSH session the run is happening over.
- **Protect the README's critical services before masking anything.** The
  prohibited list and the critical list overlap by design.

Never pass a password on a command line — it reaches the process table and the
run log's record of the command. `user_ops::set_password` feeds `chpasswd` on
stdin.

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

1. `crates/<platform>/src/platform.rs` — the `TaskSpec` row
2. `crates/<platform>/src/tasks/mod.rs` — the module declaration
3. `README.md` — the flag table and the task table
4. `docs/ARCHITECTURE.md` — the detailed entry
5. `docs/TASK_ANALYSIS.md` — the implemented-tasks list
6. Tests

## Do NOT

- Put anything that names an operating system in `pinnacle-core`
- Write `#[cfg(windows)]` / `#[cfg(unix)]` arms of the same function where a
  platform crate would do — they drift silently, which is the whole reason the
  workspace exists
- Add a `TaskSpec` row for a task that is not implemented, or that would report
  success without doing anything
- Compute a task's success from the *pre*-remediation state - "found nothing to
  fix" and "fixed everything" are both successes; "failed to fix" is not
- Return a bare boolean from an operation that can fail for different reasons
- Modify anything under `archive/` — the C# port is frozen
- Accept a corpus snapshot diff without reading it
- Disable Windows Update or Windows Defender (unless explicitly required)
- Make changes without dry-run support
- Skip tests for new behaviour
- Ignore README data when available
