# GitHub Copilot Instructions

## Project Context

PinnacleCyPat: a security-hardening tool for CyberPatriot competition images,
targeting **Windows and Linux**. One Rust implementation under `rust/`, built as
a four-crate Cargo workspace. The retired C# port is frozen under
`archive/csharp/` and must not be changed, mirrored into, or treated as a second
target.

**Apache 2.0 (see LICENSE).** Contributions are covered by Section 5 of the
licence. Do not add code copied from elsewhere without checking its licence, and
do not suggest publishing to crates.io — the crates are deliberately marked
`publish = false`.

## The workspace

| Crate | Holds | Rule |
|---|---|---|
| `crates/core` | README parser, remediation ledger, run log, models, console, the `Task` trait, the platform seam | **Nothing here may name an operating system** |
| `crates/windows` | Win32 `native/`, `*_ops.rs`, `knowledge.rs`, `chocolatey.rs`, fifteen tasks | Windows only |
| `crates/linux` | `file_ops.rs`, `systemd_ops.rs`, `user_ops.rs`, `apt.rs`, `knowledge.rs`, thirteen tasks | Linux only |
| `crates/cli` | `main.rs`, `tui.rs` | Names no OS; reads `Host::tasks()` |

**Do not suggest `#[cfg(windows)] / #[cfg(unix)]` arms of the same function**
where a platform crate would do. Two implementations sitting next to each other
look symmetrical and nothing checks that they still agree — that is exactly how
the C# port came to disagree with the Rust one, and it is why the workspace
exists.

Where logic is shared but its *data* is not, put the logic in core and take the
table as a parameter — `core::readme_services::resolve` is the model.

## Key Patterns

### Task implementation

Tasks implement `pinnacle_core::Task`:

- `read_system_state()` — read current state, display it, change nothing
- `execute()` — apply remediation, return a `TaskResult`
- `verify()` — **re-read the machine** and confirm; never trust `execute`'s report

### Every change must prove itself

Never call a write API directly from a task. Route it through
`pinnacle_core::remediation::apply`, which reads the state, skips if it is
already right, writes, then reads it back as the evidence. Use the `*_ops`
wrappers, which already do this:

| Windows | Linux |
|---|---|
| `registry_ops::set_dword` | `file_ops::set` |
| `service_ops` | `systemd_ops::disable` / `enable` |
| `account_ops` | `user_ops` |
| `chocolatey` | `apt` |

If a result genuinely cannot be read back — setting a password — use
`remediation::apply_unprovable` and say why, rather than claiming a proof that
was never taken. Audit-only conclusions use `remediation::record_finding`.

### Console output

```rust
ui::markup_line("[green]✓ Success[/]");
ui::markup_line(&format!("[yellow]⚠ {}[/]", ui::escape(untrusted)));
```

Escape anything from the machine or the README with `ui::escape` — a name
containing `[` is otherwise read as markup. Everything printed is mirrored into
the run log automatically; do not add separate logging calls.

## Adding a task

**One row, in one file.**

1. Create the task under `crates/<platform>/src/tasks/`, register it in that
   directory's `mod.rs`
2. Add one `TaskSpec` row to that crate's `platform.rs` — it supplies the flag,
   the `--help` line, the menu label and the constructor
3. Add tests
4. Update `README.md`, `docs/ARCHITECTURE.md` and `docs/TASK_ANALYSIS.md`

Nothing changes in `main.rs` or `tui.rs`. Keep the flag spelling identical to the
other platform's where the concept exists; a test enforces it. If there is no
counterpart — Group Policy on Linux — leave the row out rather than adding a stub
that reports success.

## Testing

- Unit tests live beside the code in `#[cfg(test)] mod tests`; cross-module
  tests in `crates/*/tests/`
- Name tests after the behaviour: `group_members_exclude_the_connective_prose`,
  not `test_parse_groups`
- Parser changes go through the corpus snapshots in `crates/core/tests/corpus/`
- `cargo test --workspace` — without `--workspace`, a change to core that breaks
  a platform crate goes unnoticed
- A Linux host never compiles `crates/windows/src/native/`. Check it with
  `cargo clippy --target x86_64-pc-windows-gnu -p pinnacle-windows -p pinnacle-cypat`

## Important rules

1. Never disable the CCS Client service — it is the scoring engine
2. Every task must honour `--dry-run` and change nothing under it
3. Never delete accounts when the authorised set is empty (a parsing failure)
4. A service named critical must never also be queued for disabling
5. Return the *reason* for a failure, not a bare boolean
6. Prefer the native Win32 path over parsing localised command output
7. On Linux, write SSH and sysctl settings to the drop-in directories, never the
   main file — `sshd_config` reads its `Include` first, so editing the main file
   is silently overridden
8. Open firewall ports **before** enabling `ufw`, and protect critical services
   **before** masking anything — both orderings end a round if reversed
