# PinnacleCyPat

Automates CyberPatriot security-hardening tasks on **Windows and Linux**, driven
by the round's own README.

This began as a port of a C# implementation, which is now frozen under
[`../archive/csharp/`](../archive/csharp/). It did not reproduce that
implementation faithfully: a number of logic bugs found during the port were
fixed rather than carried over, and those are listed under
[Fixes made during the port](#fixes-made-during-the-port) — worth reading, since
several are the kind of mistake that is easy to reintroduce.

> **Two platforms, one binary shape.** The build targets whichever host it runs
> on and carries only that platform's tasks: Win32 and `net`/`secedit`/`netsh`
> on Windows, `/etc` and systemd and `apt` on Linux. Everything above the
> platform line — the README parser, the remediation ledger, the run log, the
> CLI and the menu — is shared and identical.
>
> The split is a Cargo workspace rather than `#[cfg]` branches inside one crate,
> deliberately: two implementations kept in one place drift silently, which is
> the same lesson that retired the C# port. See
> [Layout](#layout).

## Build & test

```bash
./scripts/check.sh         # fmt, clippy, 182 tests, and the Windows type-check
```

Or by hand:

```bash
cd rust
cargo test --workspace     # 354 tests
cargo clippy --workspace --all-targets -- -D warnings
cargo fmt --check
```

`--workspace` matters: without it cargo builds only the crate whose directory
you are in, so a change to `pinnacle-core` that breaks a platform crate goes
unnoticed. Individual crates take `-p pinnacle-linux` and so on.

**Parser changes go through the corpus.** Every README in `crates/core/tests/corpus/` is
parsed and the whole result snapshotted, so a change that alters any of them
shows as a reviewable diff:

```bash
INSTA_UPDATE=always cargo test -p pinnacle-core --test corpus_tests   # accept new output
cargo insta review                                                    # step through diffs
```

Adding a real competition README to `crates/core/tests/corpus/` is the most useful thing you
can do for the parser — it found two bugs on its first run.

### Producing a Windows `.exe`

Tests and lints run on any host, but the shipping artefact is a Windows binary.
Cross-compiling from Linux/WSL needs the GNU target and the mingw linker — the
`x86_64-pc-windows-msvc` target requires Microsoft's linker and libraries, which
are not available on Linux:

```bash
rustup target add x86_64-pc-windows-gnu
sudo apt install -y mingw-w64                        # Debian/Ubuntu
cargo build --release -p pinnacle-cypat --target x86_64-pc-windows-gnu
# -> target/x86_64-pc-windows-gnu/release/pinnacle-cypat.exe
```

Building natively on Windows instead (rustup plus VS Build Tools with "Desktop
development with C++") yields an MSVC binary at
`target\release\pinnacle-cypat.exe`.

Two things to know when cross-compiling:

- `cargo test --target x86_64-pc-windows-gnu` builds test binaries a Linux host
  cannot execute. Run the suite on the host; use the cross build only for the
  artefact.
- A Linux host builds `pinnacle-core`, `pinnacle-linux` and the CLI in full, but
  checks `pinnacle-windows` only against its non-Windows fallbacks — **the whole
  of `crates/windows/src/native`** is `#[cfg(windows)]` and is never seen. Run
  `cargo clippy --target x86_64-pc-windows-gnu -p pinnacle-windows -p pinnacle-cypat`
  after touching any of it; it type-checks those paths and needs no linker. A
  clean `cargo test` on Linux proves nothing about them.

## Windows APIs

Everything that talks to Windows goes through Microsoft's official [`windows`
crate][windows-crate] rather than parsing the output of `net`, `auditpol` or
`netsh`. Those tools print localised, human-formatted tables: a parser written
against the English output returns nothing on a non-English image, and "nothing"
reads to the caller as *"the group is empty"* rather than as a failure. The call
sites choose between the native and shell-out paths with `#[cfg(windows)]`.

[windows-crate]: https://crates.io/crates/windows

| Module | Replaces | API |
| --- | --- | --- |
| `native::accounts` | `net localgroup`, `net accounts` | netapi32 |
| `native::audit_policy` | `auditpol.exe` | advapi32 |
| `native::firewall` | `Set-NetFirewallProfile` | `INetFwPolicy2` (COM) |
| `native::dns` | `netsh interface ip show dns` | IP helper |
| `native::installed_software` | a PowerShell registry query | uninstall keys |
| `native::registry` | `reg.exe`, `Set-ItemProperty` | advapi32 |
| `native::services` | `sc.exe`, `net start`, `Get-Service` | service control manager |
| `native::shares` | `net share` | netapi32 |
| `native::users` | `net user`, the `*-LocalUser` cmdlets | netapi32 |

The call sites do not reach into `native` directly. Four modules make the
native-or-shell choice once, so a task reads as plain intent and there is a
single place that knows about the fallback - mirroring the C# `Core/Utilities`:

| Module | C# equivalent | Covers |
| --- | --- | --- |
| `account_ops` | `LocalAccounts` | accounts and local groups |
| `policy_ops` | `PolicyOps` | password and lockout policy |
| `registry_ops` | `RegistryOps` | registry reads and writes |
| `service_ops` | `ServiceOps` | service state and control |

The reason is not tidiness. Those tools print localised, human-formatted tables:
a parser written against the English output returns nothing on a non-English
image, and "nothing" reads to the caller as *"the group is empty"* or *"the
policy is already compliant"* rather than as a failure — so the tool reports
success having done nothing. These APIs return structured data and a status code.

Each native call returns `None`/`Err` on failure rather than an empty result, and
the shell-out path remains as the fallback.

> [!NOTE]
> Audit policy needs `SeSecurityPrivilege` **enabled**, not merely present. An
> elevated token carries it disabled, so `native::audit_policy` switches it on
> explicitly — which is what `auditpol.exe` does internally.

## Usage

Run **as Administrator** — the tasks shell out to `net`, `sc`, `netsh`, `reg`
and `auditpol`.

```powershell
# 1. Read-only: show what the parser extracted from the README
.\pinnacle-cypat.exe --auto-readme --parse-readme

# 2. Preview every task; changes nothing
.\pinnacle-cypat.exe --auto-readme --all --dry-run

# 3. Apply
.\pinnacle-cypat.exe --auto-readme --all
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
| `-i`, `--tui` | Open the interactive menu |
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
| `-H`, `--security-hardening` | Registry hardening and Windows features |
| `-m`, `--media-scan` | Prohibited media and hacking-tool scan |
| `--software-updates` | Check installed apps against latest versions and update |
| `--software-management` | Remove prohibited and install required software |
| `--shared-folders` | Remove shares beyond `ADMIN$`, `C$`, `IPC$` |
| `--hosts-file` | Remove unauthorised hosts file entries |
| `--dns-settings` | Report public DNS resolvers |
| `--scheduled-tasks` | Disable suspicious scheduled tasks |
| `--log <path>` | Write the run log here instead of the default desktop path |
| `-V`, `--version` | Print version and build date, then exit |

Add `-h`, `--help`, `-?` or `/?` to print this table and exit.

> [!IMPORTANT]
> **Running everything must be asked for: pass `--all`.** A bare invocation opens
> the interactive menu at a real terminal, and prints this help otherwise. Either
> way it changes nothing on its own. It used to mean "run every task", so
> double-clicking the executable — or running it to see what it did — began a
> full destructive run against the machine.
>
> An *unrecognised* argument is likewise rejected, with exit code 2, and changes
> nothing. It used to be ignored, and because "no task flag given" meant "run
> everything", a typo — or `--help`, which was not a flag — started that same
> destructive run.
>
> Pass `--dry-run` first on an unfamiliar image.

> [!NOTE]
> `-h` is **help**. Security hardening moved to `-H` when the help flag was
> added; `--security-hardening` is unchanged.

> [!NOTE]
> Every task now has its own flag. The five that once ran only under `--all` -
> software management and the four audits - were given flags so the interactive
> menu could offer them individually. The independent audits still run
> concurrently with each other when selected.

### The interactive menu

`--tui`, or just running the executable with no arguments at a terminal — which
is what double-clicking it does.

```
What would you like to do?
  1  Inspect the README only  (read-only, changes nothing)
  2  Preview every task  (dry run, changes nothing)
  3  Run every task  (applies changes)
  4  Choose individual tasks
  5  Quit
```

It asks which README to use, which tasks to run and whether to preview or apply,
then shows a summary and waits for an explicit yes. The default answer is **no**
for a run that applies changes and **yes** for a preview, so pressing enter
without reading is always the harmless choice. Declining exits without changing
anything.

Prompts are numbered rather than arrow-driven, so this needs no raw terminal mode
and no extra dependency.

The menu **builds a command line** and hands it to the normal run pipeline rather
than driving tasks itself. The pipeline holds every ordering guarantee the run
depends on — the README parsed before user management, critical services
protected before insecure ones are disabled, the independent audits concurrent
and the rest not — and a second copy of that logic would be free to drift. It
also means the log's `Command:` line records exactly what a menu-driven run did,
so it can be repeated non-interactively.

Choosing "continue without a README" names the tasks that will then decline to
act *before* the run starts, rather than reporting it part-way through once other
tasks have already made changes. Not being Administrator is reported up front for
the same reason.

### Software updates

`--software-updates` answers two questions from two different sources:

- **What is installed, and at what version?** Read from the Windows uninstall
  registry keys (64-bit, 32-bit and per-user). This works offline and covers far
  more than `wmic product`, which sees only MSI packages and is slow enough to be
  disruptive.
- **What is the latest version?** Requires a package catalogue, which means
  **Chocolatey**. `choco outdated` reports installed and available versions side
  by side — exactly the comparison needed — and updates are applied per package
  so one failure does not abort the rest.

Software the README marks as needing the latest version is updated **first**, so
if a run is cut short the scored items are the ones already done.

> [!IMPORTANT]
> If Chocolatey is missing it is **installed automatically** from the official
> bootstrap script (`https://community.chocolatey.org/install.ps1`), which needs
> network access and Administrator. This is why Chocolatey is used rather than
> `winget`: winget ships as the "App Installer" package, which is absent from the
> **LTSC images** CyberPatriot uses and awkward to add offline, whereas
> Chocolatey installs from a script on any supported Windows.
>
> If the bootstrap fails the task still reports the full installed inventory but
> cannot determine latest versions, and says so rather than reporting a vacuous
> success.

> [!NOTE]
> Chocolatey is added to the machine `PATH` by its installer, but a process that
> is already running keeps the environment it started with. The tool therefore
> also resolves `choco.exe` at its standard location under `%ProgramData%`, so a
> freshly installed Chocolatey is usable in the same run.

OS patches are deliberately out of scope here — Windows Update settings are owned
by the audit-policy task.

### Run log

Every run writes a log recording what was attempted, queued and completed:

```
C:\Users\<you>\Desktop\PinnacleCyPat_RunLog_20260813_144949.txt
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
PinnacleCyPat_RunLog_v1.4.0_20260813_195543.txt

Version:   v1.4.0 (build 2026-08-13)
```

The build date comes from `build.rs` and distinguishes two builds of the same
version. Check a binary directly with `--version`. Bump the version with every
behavioural change and record it in [CHANGELOG.md](CHANGELOG.md).

## Layout

A Cargo workspace of four crates. `pinnacle-core` holds everything that does not
name an operating system; each platform crate implements
`pinnacle_core::platform::Platform` and is selected by one `cfg` in the binary.

| Crate | Holds |
|---|---|
| `crates/core` | `platform.rs` (the seam), `task.rs`, `readme_parser.rs`, `html.rs`, `remediation.rs`, `run_log.rs`, `app_config.rs`, `command.rs`, `ui.rs`, `software_matching.rs`, `models/`, the README corpus |
| `crates/windows` | `native/` (Win32), `{account,policy,registry,service}_ops.rs`, `knowledge.rs`, `chocolatey.rs`, `tasks/` — fifteen tasks |
| `crates/linux` | `file_ops.rs`, `systemd_ops.rs`, `user_ops.rs`, `apt.rs`, `knowledge.rs`, `tasks/` — thirteen tasks |
| `crates/cli` | `main.rs` (flags and the run pipeline), `tui.rs` (the menu) |

Where the C# port's files ended up:

| C# | Rust |
|----|------|
| `Program.cs` | `crates/cli/src/main.rs` |
| `Core/AppConfig.cs` | `crates/core/src/app_config.rs` |
| `Core/Utilities/CommandExecutor.cs` | `crates/core/src/command.rs` |
| `Core/Utilities/ReadmeParser.cs` | `crates/core/src/readme_parser.rs` |
| `Core/Models/` | `crates/core/src/models/` |
| `Core/Tasks/` | `crates/windows/src/tasks/` |
| `Core/Tui.cs` | `crates/cli/src/tui.rs` |
| Spectre.Console | `crates/core/src/ui.rs` |
| *(new)* | `crates/core/src/run_log.rs` — run log and remediation ledger |
| *(new)* | `crates/core/src/platform.rs` — the per-OS task table |
| *(new)* | `crates/linux/` — the Linux platform |

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

## Fixes made during the port

Each of these was a real defect in the original, fixed here rather than
reproduced. They are grouped by what went wrong, and are worth reading before
changing the code they describe.

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

Author: Maxwell McCormick · Apache 2.0, see `../LICENSE` · "PinnacleCyPat" is
an unregistered trademark of Maxwell McCormick (see `../NOTICE`).
