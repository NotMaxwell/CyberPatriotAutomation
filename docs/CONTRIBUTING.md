# Contributing to PinnacleCyPat

Thank you for your interest in contributing to the PinnacleCyPat tool! This document provides guidelines and instructions for contributing.

## 📜 Canonical Source & Attribution

> **This repository is the canonical and official source of the PinnacleCyPat, authored and maintained by Maxwell McCormick.**
>
> PinnacleCyPat is licensed under **[Apache 2.0](../LICENSE)**. Contributions are welcome; under Section 5 of the licence, anything you deliberately submit for inclusion is licensed under the same terms unless you say otherwise in writing.

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

- [Rust](https://rustup.rs) (2021 edition, stable)
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
cargo build
cargo test
```

> The Windows type-check in `check.sh` is not optional. A Linux build never
> compiles the `#[cfg(windows)]` branches — which is the whole of `src/native`
> plus several call sites — so a clean `cargo test` on Linux proves nothing
> about them.

### Running

```bash
cd rust
cargo run -- --all --dry-run        # preview everything, change nothing
cargo run -- --password-policy      # one task
cargo run -- --parse-readme -r path/to/README.html   # read-only
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
./scripts/check.sh            # everything CI runs
cargo test                    # just the suite
cargo test group_members      # by name
cargo test --test corpus_tests
```

### The README corpus

Parser changes go through `rust/tests/corpus/`: every fixture is parsed and the
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

- Rust 2021; `cargo fmt` and `clippy -D warnings` both gate the build
- Comments explain *why*, and name the failure that motivated the code
- Meaningful names for variables, functions and types
- Small, focused functions
- `async`/`await` for I/O

### File organisation

```rust
//! Module doc: what this file is for, and the failure that shaped it.

use crate::command;          // 1. crate imports
use crate::models::*;
use async_trait::async_trait; // 2. external crates
use std::time::Duration;      // 3. std

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

### Step 1: The task

Create a file in `rust/src/tasks/` and register it in `rust/src/tasks/mod.rs`:

```rust
//! What this task does, and why it exists.

use crate::impl_task_meta;
use crate::models::{SystemInfo, TaskResult};
use crate::tasks::Task;
use crate::ui;
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

### Step 2: The flag

In `main.rs`, add it to the `FLAGS` table — the single source of truth for both
the help text and the unknown-argument check, so a flag cannot be accepted
without also being documented:

```rust
("--my-task", "-x", "What this task does"),
```

Then read it and register the task:

```rust
let run_my_task = has_flag(&cli_args, &["--my-task", "-x"]);

if run_my_task || run_all {
    tasks.push(Box::new(MyNewTask::new()));
}
```

### Step 3: The menu

Add it to the task list in `rust/src/tui.rs`. A task reachable from the CLI but
not the menu is invisible to anyone who double-clicks `RUN.bat`, which is most
users.

### Step 4: Tests

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
passes forever and catches nothing.

### Step 5: Documentation

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
