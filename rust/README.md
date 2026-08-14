# CyberPatriot Automation Tool — Rust port

A Rust port of the C# `CyberPatriotAutomation` tool. It automates CyberPatriot
Windows security-hardening tasks and preserves the original CLI flags, task
pipeline, and console UI.

It does **not** preserve the original behaviour in every respect: a number of
logic bugs found during the port were fixed rather than reproduced. See
[Deliberate divergences](#deliberate-divergences-from-the-c-original).

> Like the original, this is a **Windows** tool: it shells out to `net`,
> `secedit`, `netsh`, `reg`, `auditpol`, `schtasks`, `sc`, `wmic`, and
> PowerShell. It builds and its parser/model logic is unit-tested on any
> platform, but the hardening tasks only do real work on Windows (as
> Administrator). On non-Windows hosts the underlying commands simply fail
> gracefully.

## Build & test

```bash
cd rust
cargo test                 # 102 tests
cargo clippy --all-targets # clean
```

### Producing a Windows `.exe`

Tests and lints run on any host, but the shipping artefact is a Windows binary.
Cross-compiling from Linux/WSL needs the GNU target and the mingw linker — the
`x86_64-pc-windows-msvc` target requires Microsoft's linker and libraries, which
are not available on Linux:

```bash
rustup target add x86_64-pc-windows-gnu
sudo apt install -y mingw-w64                        # Debian/Ubuntu
cargo build --release --target x86_64-pc-windows-gnu
# -> target/x86_64-pc-windows-gnu/release/cyberpatriot-automation.exe
```

Building natively on Windows instead (rustup plus VS Build Tools with "Desktop
development with C++") yields an MSVC binary at
`target\release\cyberpatriot-automation.exe`.

Two things to know when cross-compiling:

- `cargo test --target x86_64-pc-windows-gnu` builds test binaries a Linux host
  cannot execute. Run the suite on the host; use the cross build only for the
  artefact.
- A Linux build never compiles the `#[cfg(windows)]` branches (`raw_arg` in
  `command.rs`, `file_attributes` in `tasks/prohibited_media.rs`, `USERPROFILE`
  in `app_config.rs`). `cargo check --target x86_64-pc-windows-gnu` type-checks
  them and needs no linker, so it is worth running even without mingw installed.

## Usage

Run **as Administrator** — the tasks shell out to `net`, `sc`, `netsh`, `reg`
and `auditpol`.

```powershell
# 1. Read-only: show what the parser extracted from the README
.\cyberpatriot-automation.exe --auto-readme --parse-readme

# 2. Preview every task; changes nothing
.\cyberpatriot-automation.exe --auto-readme --all --dry-run

# 3. Apply
.\cyberpatriot-automation.exe --auto-readme --all
```

Steps 2 and 3 display the parsed README first and then act on it, so the run
shows the requirements it is working from. `--parse-readme` is a *report only* —
it exits without running any task, so combining it with `--all` runs nothing.

Do step 1 first. If it lists no administrators or users the README did not
parse, and user management will refuse to act rather than treat every account on
the image as unauthorised.

`--auto-readme` follows the README shortcut a competition image ships —
`C:\CyberPatriot\README.url`, plus the copy on the current user's desktop.

> [!IMPORTANT]
> **On a standard image the README is not on disk.** `README.url` is an Internet
> Shortcut naming an `https://` document (an S3 object), which is what the
> competitor's browser opens — `C:\CyberPatriot\` contains no `README.html`. The
> tool reads that address from the shortcut **at run time** and downloads it; the
> URL is unique per image and changes every competition, so nothing about it is
> baked in. This requires network access. If the image is isolated, open the
> README in a browser, save it as HTML, and pass it with `--readme <file>`.

Shortcuts also **chain** (desktop `.lnk` → `README.url` → the document) and are
followed to the end. `--readme` accepts a `.url`, a `.lnk`, an `.html` file, or
an `https://` address directly.

Either way the tool prints which document it settled on:

```
Using README: C:\CyberPatriot\README.html (resolved from C:\Users\you\Desktop\CyberPatriot README.lnk)
```

If that line names a `.url` or shows no administrators, discovery landed on the
wrong file — pass `--readme` explicitly.

### Flags

| Flag | Effect |
|------|--------|
| `-r`, `--readme <file>` | Parse this README |
| `-R`, `--auto-readme` | Locate the README automatically (desktop shortcut first) |
| `--parse-readme` | Parse and display the README, then exit — makes no changes |
| `-d`, `--dry-run` | Preview only |
| `--all` | Run every task |
| `-p`, `--password-policy` | Password and lockout policy |
| `-a`, `--account-permissions` | Guest account, password expiry, admin review |
| `-u`, `--user-management` | Users, groups and passwords (requires a README) |
| `-s`, `--service-management` | Services (uses README critical/prohibited lists) |
| `-t`, `--audit-policy` | Audit policy and security registry settings |
| `-f`, `--firewall` | Firewall profiles, ports and rules |
| `-h`, `--security-hardening` | Registry hardening and Windows features |
| `-m`, `--media-scan` | Prohibited media and hacking-tool scan |
| `--software-updates` | Check installed apps against latest versions and update |
| `--log <path>` | Write the run log here instead of the default desktop path |
| `-V`, `--version` | Print version and build date, then exit |

> [!WARNING]
> **`-h` means `--security-hardening`, not help.** There is no help flag, and
> unrecognised arguments are ignored. Because "no task flag given" is treated as
> "run everything", `--help`, `-?` or **no arguments at all** begin a full
> destructive run. Pass `--dry-run` first.

> [!NOTE]
> Five tasks have no individual flag and run **only** under `--all`: software
> management, shared-folders audit, hosts-file audit, DNS settings audit, and
> suspicious scheduled-tasks audit.

### Software updates

`--software-updates` answers two questions from two different sources:

- **What is installed, and at what version?** Read from the Windows uninstall
  registry keys (64-bit, 32-bit and per-user). This works offline and covers far
  more than `wmic product`, which sees only MSI packages and is slow enough to be
  disruptive.
- **What is the latest version?** Requires a package catalogue, which means
  `winget`. `winget upgrade` reports installed and available versions side by
  side — exactly the comparison needed — and updates are applied per package so
  one failure does not abort the rest.

Software the README marks as needing the latest version is updated **first**, so
if a run is cut short the scored items are the ones already done.

> [!IMPORTANT]
> `winget` ships with Windows 11 and recent Windows 10 builds but **not with
> LTSC images**, which CyberPatriot uses. Without it the task still reports the
> full installed inventory but cannot determine latest versions, and says so
> rather than reporting a vacuous success. Install "App Installer" from the
> Microsoft Store to enable update checking.

OS patches are deliberately out of scope here — Windows Update settings are owned
by the audit-policy task.

### Run log

Every run writes a log recording what was attempted, queued and completed:

```
C:\Users\<you>\Desktop\CyberPatriot_RunLog_20260813_144949.txt
```

Override the location with `--log <path>`. Every line the tool prints is
mirrored into it with markup stripped and a timestamp attached, including table
contents (services disabled, accounts found, updates applied), followed by a
structured per-task block giving outcome, verification state, item counts and
any issues. The log is written on the normal exit path and on the
`--parse-readme` path.

### Versioning

The version in `Cargo.toml` is stamped into the log's header **and** its file
name, so a log always identifies the build that produced it:

```
CyberPatriot_RunLog_v1.4.0_20260813_195543.txt

Version:   v1.4.0 (build 2026-08-13)
```

The build date comes from `build.rs` and distinguishes two builds of the same
version. Check a binary directly with `--version`. Bump the version with every
behavioural change and record it in [CHANGELOG.md](CHANGELOG.md).

## Layout (mirrors the C# `Core` namespace)

| Rust | C# |
|------|----|
| `src/main.rs` | `Program.cs` |
| `src/app_config.rs` | `Core/AppConfig.cs` |
| `src/command.rs` | `Core/Utilities/CommandExecutor.cs` |
| `src/readme_parser.rs` | `Core/Utilities/ReadmeParser.cs` |
| `src/models/` | `Core/Models/` |
| `src/tasks/` | `Core/Tasks/` |
| `src/ui.rs` | Spectre.Console replacement |
| `src/run_log.rs` | *(new)* run log written at end of execution |
| `src/tasks/software_update.rs` | *(new)* version checking and updating |

## Notable porting decisions

- **Async runtime:** `tokio`; the `BaseTask` abstract class becomes an
  `async_trait` `Task` trait.
- **Console UI:** Spectre.Console is replaced by a small `ui` module —
  `[style]...[/]` markup → ANSI, tables via `comfy-table`, progress bars/
  spinners via `indicatif`, colored bars via `owo-colors`.
- **Regex:** Rust's `regex` crate has no lookaround. The three `(?=<h2|$)`
  lookahead patterns are reproduced by explicit section scanning, and the
  `(?<!do not )disable` negative lookbehind by checking the preceding text.
- **Command execution:** on Windows the argument string is passed verbatim via
  `raw_arg` to match .NET's `ProcessStartInfo.Arguments`; both stdout/stderr
  are read concurrently under a 2-minute timeout.
- **PowerShell invocation:** two helpers in `command.rs` replace ad-hoc
  `-ErrorAction SilentlyContinue` calls. `powershell()` runs state-changing
  scripts under `$ErrorActionPreference = 'Stop'` inside `try`/`catch`, so any
  cmdlet error becomes a non-zero exit *with the message on stderr* (the C#
  original suppressed the error record, leaving failure reasons blank, and hid
  failures entirely when they occurred before the final statement).
  `powershell_query()` runs read-only scripts and ends with `exit 0`, so a
  missing object yields empty output rather than a process failure. Interpolated
  values go through `ps_quote()`, which doubles embedded `'` — an account named
  `O'Brien` previously produced a malformed script.
- **README auto-discovery:** a standard competition image ships the README at
  `C:\CyberPatriot\README.url` — a **`.url` Internet Shortcut** naming the HTML
  document, not the document itself — with a shortcut to it on the desktop of
  the user running the tool. `app_config::find_readme_file` therefore resolves
  shortcuts before falling back to literal paths: `.url` is parsed as INI (the
  `URL=` key) and its `file:///C:/...` URI converted to a Windows path, needing
  no shell interop and so unit-testable; `.lnk` is resolved via the
  `WScript.Shell` COM object. The C# `AppConfig.FindReadmeFile` checks only
  literal `.html` paths and finds nothing on a real image.

## Deliberate divergences from the C# original

These are fixed here and still present in `../src`. Grouped by what went wrong.

**Could destroy a scored image**

- User management deleted every enabled non-system account when the authorised
  set came back empty — i.e. whenever README parsing failed. It now refuses and
  explains, since a real README always names at least one administrator.
- `IsUserAdmin` substring-searched the whole `net localgroup Administrators`
  output, so an account named `admin` matched the word "Administrators" in the
  header and `command` matched the trailing status line. Membership is now
  parsed and matched exactly (`tasks::local_group_members`).
- The scheduled-task audit matched keywords (`powershell`, `cmd.exe`, `remote`)
  against *any* line of `schtasks` output and disabled by task name, hitting
  built-in Windows tasks. It now parses per-task records and skips `\Microsoft\`.
- The hosts-file audit compared `ALLOWED_ENTRIES` as exact strings, so a tab or
  a different run of spaces made the legitimate `127.0.0.1 localhost` mapping
  "unauthorised" and deleted it. Comparison is now whitespace-normalised.
- "Do not stop **or** disable the X service" still queued X for disabling: the
  negative lookbehind only covered a literal `do not ` immediately before
  `disable`. Such services are now recorded as critical, and a final pass
  guarantees no service appears in both the critical and prohibited lists.
- `--dry-run` was ignored entirely by the account-permissions task, which still
  disabled Guest and rewrote password-expiry flags.

**Reported the wrong result**

- Four tasks computed `success` from the *pre*-remediation state
  (`success: unauthorized.is_empty()`), so successfully cleaning up reported
  failure and only "nothing to do" counted as success.
- `Overall Completion Rate` was derived from `items_attempted`, which no task
  populates, so it always printed 100% — including when every task failed.
- Verification was weaker than it appeared: services were sampled 5-at-a-time
  and reported as a full pass; the audit-policy check passed if *any*
  subcategory had Success and a *different* one had Failure; the group-policy
  check only confirmed `reg query` exited 0, so a value present with the wrong
  contents verified as correct.
- Several places recorded a fix without checking the command's result, and
  registry failures were counted for the on-screen tally but never surfaced.
- README critical services were never actually protected: the routine iterated
  only the first ten entries of its own hard-coded list, so CCS Client was never
  started.

**Parsing**

- User lists separated by `<br>` rather than `<pre>` newlines collapsed to a
  single line and yielded zero users.
- `ShouldBeLatest` tested whether the *whole document* contained "latest", so one
  mention flagged every package.
- Ordinary prose became software requirements; only the first group requirement
  was ever parsed; `net share` header and status lines were treated as shares.
- OS detection matched raw HTML, so `Windows&nbsp;10` (a U+00A0, not a space)
  or `Windows <b>10</b>` reported "Unknown". It now strips markup and
  normalises whitespace, reads the `<title>`/`<h1>` before the body so a
  Windows 11 image warning against "going back to Windows 10" is not
  misidentified, and recognises Server 2012–2025, Windows 7/8.1 and Fedora.

Author: Maxwell McCormick · Apache-2.0 · "CyberPatriot Automation Tool" is an
unregistered trademark of Maxwell McCormick (see `../NOTICE`).
