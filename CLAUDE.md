# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

PinnacleCyPat hardens CyberPatriot competition images (Windows and Linux), driven
by the round's own README. It makes destructive, largely irreversible changes:
it deletes accounts and files, masks services, rewrites `/etc` or the registry.
The only implementation is the Rust workspace under `rust/`. Comments mentioning
"the C# original" refer to the earlier implementation, which was removed in
commit `39e381d`. Don't restore it.

The long-form references are `docs/CLAUDE.md` (coding rules, patterns and the
"Do NOT" list) and `docs/ARCHITECTURE.md` (every task: why it exists, what it
changes, what it refuses to touch). Read the relevant ARCHITECTURE section
before changing a task.

## Commands

Run cargo from `rust/` (the workspace root):

```bash
./scripts/check.sh                       # everything CI runs: fmt, clippy -D warnings, tests, Windows type-check
cd rust && cargo test --workspace        # always --workspace: a core change can break a platform crate
cargo test --workspace group_members     # tests whose name matches
cargo test -p pinnacle-linux --test answer_key            # one integration-test file
cargo clippy --workspace --all-targets -- -D warnings
cargo fmt --check
./scripts/publish.sh                     # -> publish-win-x64/*.exe, publish-linux-x64/pinnacle-cypat
```

- **Windows code is invisible to a Linux build.** `crates/windows/src/native/`
  and every `#[cfg(windows)]` branch are skipped, so a clean `cargo test` on
  Linux says nothing about them. After touching Windows code, run
  `cargo clippy -p pinnacle-core -p pinnacle-windows -p pinnacle-cypat --all-targets --target x86_64-pc-windows-gnu -- -D warnings`
  (needs `rustup target add x86_64-pc-windows-gnu`; `check.sh` skips this
  step if the target is missing).
- **The Linux release binary must be musl** (`x86_64-unknown-linux-musl`).
  A glibc build won't start on Ubuntu 22.04 (glibc 2.35), and `publish.sh`
  fails if the artefact references glibc.
- **Parser snapshots:** `crates/core/tests/corpus/*.html` are parsed and
  snapshotted with insta. Accept new output with
  `INSTA_UPDATE=always cargo test -p pinnacle-core --test corpus_tests` or
  `cargo insta review`, and read the diff before accepting it.
- Run the tool read-only with
  `cargo run -p pinnacle-cypat -- -r <README> --parse-readme` (or
  `--directives`). Never run a non-`--dry-run` task on a development machine:
  the tasks really do change the host.

## Architecture

Cargo workspace, five crates:

- **`core` (`pinnacle-core`)** must never name an operating system. It holds the
  README parser (`readme_parser.rs`, `html.rs`), README discovery
  (`app_config.rs`: `.url`/`.lnk`/`.desktop` shortcut chains, downloads),
  `directives.rs` (README prose sorted into automated / not touched / do by
  hand), the `Task` trait, `remediation.rs`, `run_log.rs`, `engine.rs` and
  `session.rs`.
- **`windows` / `linux`** are the only crates that name an OS. Each exposes one
  `Platform` impl whose `tasks()` returns a `&'static [TaskSpec]` table in
  `platform.rs`. Writes go through the `*_ops.rs` wrappers (`registry_ops`,
  `service_ops`, `account_ops`, `policy_ops` on Windows; `file_ops`,
  `systemd_ops`, `user_ops`, `apt` on Linux). Hardening tables (registry
  values, services, packages) live in `knowledge.rs` and have their own tests.
- **`cli` (`pinnacle-cypat`)** is the binary. `main.rs` picks `Host` with one
  `cfg` and otherwise names no OS. `src/web/` is the Linux web UI (`--web`): an
  HTTP server on loopback with a per-run token, Host/Origin checks, SSE updates
  and a single `index.html`.
- **`gui` (`pinnacle-cypat-gui`)** is the Windows desktop app (eframe/egui). It
  also builds and runs its tests on Linux for development.

**One engine, three thin front ends.** `engine::run` takes a `RunPlan` (README
choice, task flags, dry run, cancel flag) and emits `RunEvent`s. The CLI, GUI
and web UI only build plans and display events. The GUI and web UI share
`session.rs` (`AppState`, `Action`, `real_run_gate`). The real run stays locked
until a finished, uncancelled dry run of the same task selection and README.
Run logic goes in `engine` and run-permission rules go in `session`, never in a
single front end.

**A task is one `TaskSpec` row.** The row supplies the flag, short flag,
`--help` line, GUI/web label, `needs_readme`, concurrency and the constructor.
The constructor is `plain!(T)` or `with_readme!(T)`; README data reaches a task
through `with_readme!`, not through `main.rs`. Adding a task means a file in
`crates/<platform>/src/tasks/`, a `mod.rs` entry and a row in the order it
should run. Nothing changes in `main.rs`, the GUI or the web UI. Shared flags
must be spelled the same on both platforms (a test enforces this). A task with
no counterpart on the other platform gets no row there, not a stub.

**Every write proves itself.** Mutations go through `remediation::apply`, which
reads the state, skips it if already compliant, writes, then reads the state
back as evidence. That produces a `FixRecord` (Fixed / AlreadyCompliant /
Failed / Unverified / Skipped) in the run log's ledger. If a result can't be
read back (passwords), use `apply_unprovable`. Audit-only conclusions use
`record_finding`. In the `readState` callback, return `None` only for "could not
read"; "absent" is a readable state.

## Rules that are easy to break

- `--dry-run` must never write, in every task.
- Never disable the CCS Client service. It is the scoring engine.
- Never delete accounts when the parsed authorised set is empty. That means the
  parse failed, not that every account is unauthorised.
- Ask README questions through `readme_services` (`is_critical`, `resolve`,
  `is_remote_desktop_required`), never ad-hoc string matching.
- Logic shared across OSes but with per-OS data goes in core, with the table
  passed as a parameter (`core::readme_services::resolve`). Don't write paired
  `#[cfg(windows)]`/`#[cfg(unix)]` versions of one function.
- Windows: prefer the native Win32 path (`native/`) over parsing localised
  command output. Never set a password with `net user`.
- Linux: write SSH/sysctl settings to the drop-in directories, never the main
  file. Use `apt` purge, not remove. Open firewall ports before enabling `ufw`,
  and protect critical services before masking anything. Never put a password
  on a command line.
- Pass anything that came from the machine or the README through `ui::escape`
  before `ui::markup_line`.
- Answer keys are the spec: `crates/linux/tests/answer_key*.rs` encode
  published Exhibition Round answer keys, one test per scored item. Test the
  tool's *decisions* (which accounts, services or packages it targets), not
  `execute()`. Add the round's README to the corpus at the same time.
- Directive patterns in `directives.rs` must be anchored on wording seen in a
  real README, with a test against that corpus fixture. Only mark a pattern
  `Automated` if a task actually handles it.

## Conventions

- Bump `version` in `rust/Cargo.toml` with every behavioural change (patch for
  fixes, minor for new behaviour) and add an entry to `rust/CHANGELOG.md`. The
  version is stamped into the run log's name and header.
- New source files start with `// Copyright 2026 Maxwell McCormick` and
  `// SPDX-License-Identifier: Apache-2.0`. Keep `LICENSE` byte-identical to
  the canonical Apache 2.0 text.
- Name tests after the behaviour (`group_members_exclude_the_connective_prose`).
  Unit tests go in `#[cfg(test)] mod tests`, cross-module tests in
  `crates/*/tests/`.
- Comments explain why, and name the failure that motivated the code.
- When a task changes, also update `README.md` (flag and task tables),
  `docs/ARCHITECTURE.md` and `docs/TASK_ANALYSIS.md`.
