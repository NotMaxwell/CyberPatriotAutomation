# GUI Roadmap

Plan for replacing the terminal menu (`--tui`) with a graphical front end.

**Status (1.23.0):** M0 to M6 are done; M7 (release) is in progress. The terminal
menu is gone. The front ends went further than this plan: a light theme, a
README-locations picker on launch, a workflow gated by the dry run, **every**
README field editable (the plan had only the lists), and a file browser in both
front ends. The checkboxes below record what the plan asked for; the code is the
record of what was built. See [the README](../README.md#the-gui) for the result.

| Platform | Front end | Why |
|---|---|---|
| Windows | Native window (Rust, `eframe`/egui) | Preferred. Windows images have a desktop, the binary already runs elevated, and no extra runtime is needed. |
| Linux | Local web UI served by the binary, opened in the image's browser | A native window is a poor fit on Linux, for two reasons: (1) the shipped binary is static musl (`scripts/publish.sh`), and a GUI toolkit loads X11/Wayland/GL libraries at runtime, which a static musl binary cannot do; (2) the tool must run as root, and on Ubuntu 22.04's default Wayland session a window opened from `sudo` is refused by the display server. A web UI avoids both: the root binary serves HTTP on loopback and the browser runs as the normal user. |

Both front ends sit on one shared run engine (M2), so the task pipeline and the
run log stay identical whichever one a run uses.

Size estimates are rough guesses, not measurements.

---

## M0 — Linux build blockers (do first)

These are needed whether or not the GUI happens. Details are under
[Linux build: what is left](#linux-build-what-is-left).

- [x] Fix the dry-run test race that writes to `/etc` when tests run as root
- [x] Fix the stale task and test counts in the docs
- [x] Add `RUN.sh`, the Linux launcher

**Done when:** `cargo test --workspace` passes as root and as a normal user.

## M1 — Windows toolkit spike (about 1–2 days)

Prove the toolkit works on a competition-like VM before building screens on it.

- [x] New crate `rust/crates/gui` → `pinnacle-cypat-gui.exe`. It has to be a separate binary because `#![windows_subsystem = "windows"]` removes the console, which would break the CLI.
- [x] Embed a `requireAdministrator` manifest so Windows shows the UAC prompt on launch. (Checked on a Windows VM: no UAC prompt appeared, because UAC was off there. Windows then starts the process elevated silently, so the GUI shows an elevation pill at the top right rather than assuming a prompt happened.)
- [x] Open one window on Windows 10/11 and Server 2019/2022 VMs **with no GPU acceleration** (VMware/VirtualBox basic display adapter). Confirm egui's renderer falls back to software. If it doesn't, switch toolkit now (Slint has a software renderer) instead of after M3.
- [x] Cross-compile with `x86_64-pc-windows-gnu`, as `publish.sh` does. Record the binary size against the current 2.12 MB.

**Done when:** an elevated window opens on every target VM, and the size is recorded.

## M2 — Shared run engine in `pinnacle-core` (about 3–5 days)

Today the pipeline lives in `rust/crates/cli/src/main.rs` (`main`, `run_task`, the task table, the summary) and prints straight to the console. Move it behind an interface that every front end can drive.

- [x] `RunPlan`: README source, chosen task flags, dry-run flag. This is what the TUI builds as an argument list today.
- [x] `Runner::start(plan) -> Receiver<RunEvent>`, run on the tokio runtime, with events:
  `ReadmeParsed(ReadmeData)`, `Directives(..)`, `TaskStarted(name)`, `Line(task, text)`,
  `Fix(FixRecord)`, `TaskFinished(TaskResult)`, `Finished { log_path }`.
- [x] Send task output (the `ui::*` calls, about 545 call sites in the platform crates) to the event channel through the existing `ui::capture` mechanism (`core/src/ui.rs:196`), not by rewriting each call site.
- [x] Move the `set_readme_data` wiring out of `main.rs` together with the pipeline. `docs/CLAUDE.md` warns that a task whose `set_readme_data` is never called silently acts as if there were no README, and that bug has happened before.
- [x] The CLI becomes one consumer that prints events exactly as it does now.

**Done when:** CLI console output and the run log are unchanged (add a snapshot test of a dry run first, then refactor), and all tests pass.

## M3 — Windows GUI screens (about 1–2 weeks)

1. [x] **README:** auto-detect (`--auto-readme`) or browse for a file. Show the parsed admins, users, groups, critical services, and required and prohibited software. **Refuse to continue when no admins or users were parsed**, the same guard the CLI has.
2. [x] **Directives:** the three groups from `--directives`. The "do these by hand" list stays visible for the whole run, starting with forensics questions.
3. [x] **Tasks:** one checkbox per task from `Host::tasks()`, labelled with each `TaskSpec`'s existing menu label and detail. Reading the list from `TaskSpec` keeps it automatic: a new task appears in the GUI without editing GUI code. Tasks that need a README are disabled when none is loaded.
4. [x] **Mode and confirm:** dry run selected by default. Applying changes requires an explicit second confirmation that lists what will run.
5. [x] **Run:** status per task (waiting, running, done, failed), live output, and the concurrent audits shown separately. Cancelling stops between tasks, never in the middle of a write.
6. [x] **Results:** a `TaskResult` table plus the remediation ledger, filterable by outcome (Failed and Unverified first), and a button to open the run log.

**Done when:** a full dry run and a full apply run on a Windows VM, and the ledger matches the CLI's for the same plan.

## M4 — Edit the parsed README before running (about 3–5 days)

The main thing a GUI adds over the CLI: a teammate can fix a bad parse instead of re-running.

- [x] Admin, user and group lists in the README screen are editable.
- [x] `RunPlan` accepts an edited `ReadmeData` in place of re-parsing the file.
- [x] The run log records that the data was edited by hand, with a diff from the parsed version, so a log still explains its own run.

**Done when:** an edited list changes what User Management does, and the log shows the diff.

## M5 — Linux web UI (about 1–2 weeks)

- [x] `--web` (and launching with no arguments in a desktop session) starts an HTTP server on `127.0.0.1` on a random port.
- [x] Open the browser **as the invoking user**, not root (`sudo -u "$SUDO_USER" xdg-open URL`; the README discovery code already reads `SUDO_USER`). Always print the URL too.
- [x] Same screens as M3, as one static HTML/JS page embedded with `include_str!`. Live updates over Server-Sent Events from the M2 event stream.
- [x] **Security.** This server makes root changes, so:
  - bind to loopback only;
  - require a random per-run token in the URL on every request;
  - check the `Host` header (blocks DNS rebinding) and the `Origin` on POSTs (blocks cross-site requests);
  - accept one client at a time;
  - exit when the run finishes or the page is closed.
- [x] Use only pure-Rust dependencies, so the binary stays static musl. `publish.sh`'s glibc check must still pass.

**Done when:** a dry run and an apply run work on an Ubuntu 22.04 image from Firefox, and the binary is still statically linked.

## M6 — Remove the TUI (about 1 day)

Only once M3 and M5 cover everything the menu does.

- [x] Delete `rust/crates/cli/src/tui.rs` (416 lines) and the `--tui`/`-i` flag (`cli/src/main.rs:66`, `:227–230`).
- [x] Move its tests (one task flag per menu entry, README-dependent tasks offered) to the engine or GUI. Repoint the two `main.rs` tests that guarantee every CLI task is offered in the menu so they check the GUI's task list instead.
- [x] Rename `TaskSpec`'s menu label and detail fields to GUI terms, and update "Adding New Tasks" in `docs/CLAUDE.md` (it says there is nothing to change in `tui.rs`). (The fields keep the names `label` and `detail`; their doc comments and the docs now say GUI and web.)
- [x] Launching with no arguments: Windows opens the GUI; Linux opens the web UI in a desktop session and prints `--help` otherwise.
- [x] `RUN.bat` / `RUN.ps1` launch the GUI.
- [x] README: replace "The menu" section and the `--tui` lines in Quick start and Flags with a "The GUI" section. Update `docs/ARCHITECTURE.md` and `docs/CLAUDE.md`.

## M7 — Release (about 2–3 days) — in progress

The lead is doing this: launchers (`RUN.bat`, `RUN.ps1` launch the GUI; `RUN.sh` defaults to `--web`), the version bump, the CHANGELOG and `publish.sh`.

- [ ] `publish.sh` builds `pinnacle-cypat-gui.exe` next to the CLI exe.
- [ ] Version bump (minor) and a CHANGELOG entry.
- [ ] Full runs on Windows 10, Server, and Ubuntu 22.04 images. Keep the run logs in `ReferenceMaterial/`.

---

## Linux build: what is left

State checked on 2026-11-20 in a Linux container (x86_64, running as root, no Windows host):

| Check | Result |
|---|---|
| `cargo fmt --check` | pass |
| `cargo clippy --workspace --all-targets -D warnings` | pass |
| `cargo clippy --target x86_64-pc-windows-gnu` (Windows type-check) | pass |
| `cargo build --release --target x86_64-unknown-linux-musl` | pass: static-pie, 3,654,688 bytes, no GLIBC symbols |
| `cargo test --workspace` (parallel, as root) | **FAIL**: `security_hardening::tests::a_dry_run_writes_nothing` |
| `cargo test --workspace -- --test-threads=1` | pass: 395 passed, 0 failed |
| Windows `.exe` cross-build | not run (mingw linker not installed here) |

### 1. Dry-run tests race on a global, and wrote to `/etc` as root (bug) — FIXED

`run_log::DRY_RUN` is one process-wide `AtomicBool`. Six Linux tests set it to
`true`, run a task, then set it back to `false`:
`password_policy`, `security_hardening`, `audit_policy`, `service_management`,
`software_management`, `software_update`. Tests run in parallel, so one test
resetting the flag turns another test's dry run into a real run partway through.

Seen here, running as root: the test run created `/etc/sysctl.d/99-pinnacle.conf`
and rewrote `/etc/login.defs` (`PASS_MAX_DAYS 90`, `UMASK 027`, and so on).
I restored both. As a non-root user the writes fail with permission errors and
the test passes, which is why this goes unnoticed.

The shipped binary is **not** affected: a real run sets the flag once and never
changes it.

**Fix:** hold `run_log::test_gate()` (it already exists for this, `core/src/run_log.rs:141`)
for the whole of each of those six tests. Optionally, add a check that fails any
test that touches `/etc` while running as root.

### 2. No CI — not wanted

There is no CI by choice. `scripts/check.sh` and `scripts/publish.sh` are run by
hand. When checking a change to a task, also run the suite once as root, since
only root sees a dry run that writes:

```bash
sudo -E env "PATH=$PATH" cargo test --workspace --manifest-path rust/Cargo.toml
sudo find /etc -name '*.pinnacle.bak'      # must print nothing
```

### 3. No Linux run log for the current version — skipped by the maintainer's decision

The real image run described below will not be done for this release. Until it is, the web UI and 1.20.0 to 1.21.0 Linux changes have been exercised in containers only.

`ReferenceMaterial/` has two run logs, both Windows v1.8.0. The CHANGELOG
records one real Ubuntu run (1.19.2). 1.20.0 then changed README discovery
(`.desktop` launchers, `/opt/CyberPatriot`, `SUDO_USER`), and the repo has no
log showing that version on a real image. 1.21.0 adds PAM and sudoers changes,
tested only in an Ubuntu 24.04 container. Run `./RUN.sh --auto-readme --all
--dry-run` on an Ubuntu 22.04 image, then a real run, and keep both logs. After
the real run, check by hand: log in as an admin with the correct password, run
`sudo -k; sudo true` (should ask for the password), and change a password.

A dry run of 1.20.0 against `ReferenceMaterial/README-Linux.html` in the dev
container completed with exit 0 and changed nothing (every file under `/etc`
and the account list checksummed before and after). That is a pipeline check,
not a substitute for the image.

### 4. No Linux launcher — ADDED (`RUN.sh`)

Windows has `RUN.bat` / `RUN.ps1`. Linux has nothing equivalent. Add a
`RUN.sh` that checks for root, re-runs itself under `sudo` (keeping
`SUDO_USER`), and sets the executable bit on the binary.

### 5. Docs say thirteen Linux tasks; there are fifteen — FIXED

- "thirteen": `docs/CLAUDE.md` (layout tree), `docs/ARCHITECTURE.md:195`, `README.md:429`
- "fifteen": `README.md` task table, `docs/ARCHITECTURE.md:254`
- `rust/README.md` says "182 tests" in one place and "381 tests" in another. The actual count is 395.

### 6. Reported-only gaps — FIXED in 1.21.0

- PAM lockout (`pam_faillock`) and password history (`pam_pwhistory`) are now
  enabled through `pam-auth-update` profiles, with a structural order check
  and rollback (`crates/linux/src/pam_ops.rs`).
- sudo `NOPASSWD` / `!authenticate` removed, rule kept, `visudo -c` guarded
  (`crates/linux/src/sudo_ops.rs`).
- Reported: PAM lines that skip the password check, GDM/LightDM auto-login,
  LightDM guest sessions.

### 7. Prohibited Media could delete `/opt/CyberPatriot` files — FIXED in 1.20.1

### 8. Only one Linux answer key

`crates/linux/tests/answer_key.rs` encodes the Ubuntu 22.04 Exhibition Round.
Add more Ubuntu READMEs to `crates/core/tests/corpus/` as they become available.
The parser is where the past Linux point losses came from (Perl, `firesidegirls`).
