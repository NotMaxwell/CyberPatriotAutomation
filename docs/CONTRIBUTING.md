# Contributing to PinnacleCyPat

Thank you for your interest in contributing to the PinnacleCyPat tool! This document provides guidelines and instructions for contributing.

## 📜 Canonical Source & Attribution

> **This repository is the canonical and official source of the PinnacleCyPat, authored and maintained by Maxwell McCormick.**
>
> PinnacleCyPat is licensed under **[Apache 2.0](../LICENSE)**. Contributions are welcome; under Section 5 of the licence, anything you deliberately submit for inclusion is licensed under the same terms unless you say otherwise in writing.

## Contributor License Agreement

If you submit any suggestion, patch, code or other material relating to this project, you agree that:

1. Your contribution is your original work, and you have the right to submit it
2. It is licensed under Apache 2.0, as Section 5 of the [LICENSE](../LICENSE) provides, unless you state otherwise in writing
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

- [Rust](https://rustup.rs) — stable, 1.88 or newer (the 2024 edition and
  let-chains)
- Git
- For the Windows binary from a Linux host: `rustup target add
  x86_64-pc-windows-gnu` and `mingw-w64`

### Building and testing

```bash
./scripts/check.sh      # fmt, clippy, tests, and the Windows type-check
./scripts/publish.sh    # -> publish-win-x64/pinnacle-cypat.exe
```

`check.sh` is everything CI runs, ordered so it fails fastest. Run it before
committing; `check.ps1` is the same on Windows. By hand:

```bash
cd rust
cargo build --workspace
cargo test --workspace
```

`--workspace` matters: without it cargo builds only the crate whose directory
you are in, so a change to `pinnacle-core` that breaks a platform crate goes
unnoticed. Individual crates are addressable with `-p pinnacle-linux` and so on.

> The Windows pass in `check.sh` is not optional. A Linux host builds
> `pinnacle-core`, `pinnacle-linux` and the CLI in full, but checks
> `pinnacle-windows` only against its non-Windows fallbacks — the whole of
> `crates/windows/src/native` is `#[cfg(windows)]` and is never seen. A clean
> `cargo test` on Linux proves nothing about it.

### Running

```bash
cd rust
cargo run -p pinnacle-cypat -- --all --dry-run   # preview everything, change nothing
cargo run -p pinnacle-cypat -- --password-policy # one task
cargo run -p pinnacle-cypat -- --parse-readme -r path/to/README.html   # read-only
```

The binary builds for whichever platform you are on and offers that platform's
tasks. `--help` lists them under a `WINDOWS TASKS:` or `LINUX TASKS:` heading.

## Making Changes

1. **Create a branch** for your feature or fix:
   ```powershell
   git checkout -b feature/your-feature-name
   # or
   git checkout -b fix/your-bug-fix
   ```

2. **Make your changes** following the coding standards

3. **Write tests** for new functionality

4. **Run the checks** to ensure nothing is broken:
   ```bash
   ./scripts/check.sh
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

### Running tests

```bash
./scripts/check.sh                   # everything CI runs
cargo test --workspace               # just the suite
cargo test -p pinnacle-linux         # one crate
cargo test group_members             # by name
cargo test -p pinnacle-core --test corpus_tests
```

### The README corpus

Parser changes go through `rust/crates/core/tests/corpus/`: every fixture is parsed and the
whole result snapshotted, so a change that alters any of them shows as a diff.

```bash
INSTA_UPDATE=always cargo test --test corpus_tests   # accept new output
cargo insta review                                   # step through diffs
```

**Read the diff before accepting it** — the snapshot is the only record of what
the parser does. And if you have a real competition README, adding it to
`tests/corpus/` is the single most valuable contribution you can make to the
parser: real documents have found bugs that reading the code did not.

### Writing tests

Name the test after the behaviour, not the function. `test_parse_groups` says
nothing when it fails; `group_members_exclude_the_connective_prose` says exactly
what broke.

```rust
#[cfg(test)]
mod tests {
    use super::*;

    /// The sentence is verbatim from a competition README, and the run it
    /// produced recorded `Members: users, ggoddard, ..., group`.
    #[test]
    fn group_members_exclude_the_connective_prose() {
        assert_eq!(
            extract_group_members("the users ggoddard, ealderson into the group"),
            ["ggoddard", "ealderson"]
        );
    }

    #[test]
    fn a_table_driven_case() {
        for (input, expected) in [("Notepad++ (64-bit x64)", "notepadplusplus.install")] {
            assert_eq!(
                resolve_package_id(input, PACKAGE_IDS).as_deref(),
                Some(expected),
                "input: {input}"
            );
        }
    }
}
```

A doc comment on a regression test saying *what went wrong in the field* is
worth more than the assertion itself — it is what stops the next person
"simplifying" the fix away.

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

- Rust 2024; `cargo fmt` and `clippy -D warnings` both gate the build
- Prefer a let-chain (`if let Some(x) = a && x.ok()`) to nested `if let`;
  clippy will tell you where
- Comments explain *why*, and name the failure that motivated the code
- Meaningful names for variables, functions and types
- Small, focused functions
- `async`/`await` for I/O

### File organisation

```rust
//! Module doc: what this file is for, and the failure that shaped it.

use crate::file_ops;              // 1. this crate
use pinnacle_core::models::*;     // 2. the core crate
use pinnacle_core::task::Task;
use async_trait::async_trait;     // 3. external crates
use std::time::Duration;          // 4. std

const MAX_RETRIES: u32 = 3;   // 4. constants

pub struct MyTask {           // 5. types
    name: String,
}

impl MyTask {                 // 6. inherent impls
    pub fn new() -> Self { /* ... */ }
}

#[async_trait]
impl Task for MyTask { /* ... */ }   // 7. trait impls

#[cfg(test)]
mod tests { /* ... */ }              // 8. tests, last
```

### Naming

| Item | Convention | Example |
|------|------------|---------|
| Types, traits | `PascalCase` | `UserManagementTask` |
| Functions, methods | `snake_case` | `read_system_state` |
| Fields, locals | `snake_case` | `readme_data` |
| Constants, statics | `SCREAMING_SNAKE_CASE` | `MAX_RETRIES` |
| Modules, files | `snake_case` | `software_management.rs` |

### Console output

```rust
ui::markup_line("[green]✓ Operation completed[/]");
ui::markup_line("[red]✗ Operation failed[/]");
ui::markup_line("[yellow]⚠ Warning message[/]");
ui::markup_line("[cyan]ℹ Information[/]");
```

Anything that came from the machine or the README goes through `ui::escape`
first — a program whose display name contains `[` is otherwise read as markup:

```rust
ui::markup_line(&format!("[green]✓ Removed: {}[/]", ui::escape(&program.name)));
```

## Adding a task

A task lives in a platform crate — `crates/windows` or `crates/linux` — and is
described by exactly one row in that crate's `platform.rs`.

### Step 1: The task

Create a file in `crates/<platform>/src/tasks/` and register it in that
directory's `mod.rs`:

```rust
//! What this task does, and why it exists.

use pinnacle_core::models::{SystemInfo, TaskResult};
use pinnacle_core::task::Task;
use pinnacle_core::{impl_task_meta, ui};
use async_trait::async_trait;

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
        let mut result = TaskResult {
            task_name: self.name.clone(),
            success: true,
            ..Default::default()
        };

        if self.dry_run {
            result.message = "DRY RUN: nothing was changed.".to_string();
            return result;
        }

        // Route every write through the *_ops wrappers so it is proved and
        // lands in the remediation ledger. See CLAUDE.md, "Every Change Must
        // Prove Itself".
        result
    }

    async fn verify(&mut self) -> bool {
        // Read the machine back. Returning true because the write returned
        // success is the failure mode the ledger exists to catch.
        true
    }
}
```

### Step 2: The row

Add one `TaskSpec` to the platform's `platform.rs`, positioned where a full run
should execute it:

```rust
TaskSpec {
    flag: "--my-task",
    short: "-x",
    help: "What this task does",          // --help
    label: "My New Task",                 // the menu
    detail: "what it changes, briefly",   // the menu
    needs_readme: false,
    concurrency: Sequential,
    build: plain!(MyNewTask),             // or with_readme!(MyNewTask)
},
```

That is the whole registration. The flag, the help text, the menu entry and the
constructor all come from this row, so there is no way to add a task the CLI
accepts but the menu does not offer — which used to be three separate lists,
free to disagree, and they did.

Two rules for the row:

- **`concurrency: Concurrent` only for a read-mostly audit over an area nothing
  else touches.** Everything else contends for the same accounts, services and
  configuration, where overlapping writes race.
- **Match the other platform's spelling** if the concept exists there. If
  Windows has `--password-policy` / `-p`, Linux uses the same. A test enforces
  it.

### Step 3: Tests

```rust
#[tokio::test]
async fn my_new_task_dry_run_changes_nothing() {
    let mut task = MyNewTask::new();
    task.set_dry_run(true);
    let result = task.execute().await;
    assert!(result.success);
}
```

Test the decisions, not the plumbing. `should_have_correct_name_and_description`
passes forever and catches nothing. The tests worth writing are the ones about
what the task *decides*: which accounts it considers unauthorised, which
services it refuses to touch, what it does when the README is silent.

### Step 4: Documentation

1. `README.md` — the flag table and the task table
2. `docs/ARCHITECTURE.md` — the detailed entry: why, what it changes, what it
   refuses to touch
3. `docs/TASK_ANALYSIS.md` — the implemented-tasks list

## Questions?

If you have questions, feel free to:
- Open an issue on GitHub
- Check existing issues and discussions
- Review the codebase and existing tasks for examples

## 📜 License & Attribution

### Your Contributions

Contributions are governed by the [LICENSE](../LICENSE). By contributing, you:
- License the contribution under Apache 2.0 (Section 5)
- Confirm you have the right to do so
- Agree to the Contributor License Agreement above

### Trademark and Forking

"PinnacleCyPat" is an unregistered trademark of Maxwell McCormick. No right to use the name or any associated branding is granted by the licence — see Section 6 of the [LICENSE](../LICENSE).

Forking, modifying and redistributing the code itself are permitted under Apache 2.0, provided you keep the copyright notice, the licence, and the NOTICE file, and state what you changed.

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
