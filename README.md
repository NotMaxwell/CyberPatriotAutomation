# PinnacleCyPat

[![Rust](https://img.shields.io/badge/Rust-2024-000000)](https://www.rust-lang.org/)
[![License](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](LICENSE)
[![Tests](https://img.shields.io/badge/Tests-726-brightgreen)]()
[![Platforms](https://img.shields.io/badge/Platforms-Windows%20%7C%20Linux-informational)]()

**Author:** Maxwell McCormick · **Copyright:** © 2026 Maxwell McCormick

Automated security hardening for CyberPatriot competition images, on **Windows
and Linux**. It reads the round's own README, applies the mechanical part of the
checklist, and tells you exactly what it changed.

> [!CAUTION]
> **This tool makes largely irreversible changes.** It deletes files permanently,
> deletes user accounts, changes passwords, disables services, rewrites the
> registry and security policy (or `/etc` and systemd), and uninstalls software.
> Run `--dry-run` first. Run it only on images you can afford to lose.

---

## Quick start

**Easiest.** On **Windows**, double-click `RUN.bat`, or `pinnacle-cypat-gui.exe`
directly. It opens the desktop GUI (see [The GUI](#the-gui)). On **Linux**, run
`./RUN.sh`, or `sudo ./pinnacle-cypat --web`. It opens the web UI in your browser
(see [The web UI](#the-web-ui)). `RUN.sh` re-runs itself under `sudo` if needed
and defaults to `--web`; any arguments you give it go straight to the tool.

**From a terminal:**

```powershell
pinnacle-cypat-gui.exe           # Windows: the desktop GUI
sudo ./pinnacle-cypat --web      # Linux: the web UI (add --port 8080 to pin the port)
```

**Straight to the point:**

```powershell
# 1. Read-only: confirm the README parsed
PinnacleCyPat.exe --auto-readme --parse-readme

# 2. Preview everything; changes nothing
PinnacleCyPat.exe --auto-readme --all --dry-run

# 3. Apply
PinnacleCyPat.exe --auto-readme --all
```

> [!IMPORTANT]
> **Do step 1.** If it lists no administrators or users, the README did not parse
> — and user management will refuse to act rather than treat every account on the
> image as unauthorised.

---

## The GUI

Windows. `pinnacle-cypat-gui.exe`, which `RUN.bat` launches. It sits next to the
CLI exe and drives the same engine, so a GUI run writes the same run log as
`pinnacle-cypat.exe --all`.

The workflow is the order the decisions should be made in:

1. **README locations.** On launch it finds every README on the machine and lists
   them, so you pick the right one rather than trusting a guess. You can also
   type a path, browse for a file, or continue without a README.
2. **README tab.** What the parser extracted: administrators, users, groups,
   services, software. **Every field is editable**, because a bad parse is
   better fixed on screen than by re-running. Edits are recorded in the run log
   as a difference from the parsed version; passwords appear there only as a
   fingerprint, never in the clear. The "Do by hand" checklist in the sidebar
   lists what the README asks for that the tool will not do, forensics
   questions first.
3. **Run tab.** Tick the tasks, then **dry run**. A dry run never writes.
4. **Real run.** The button unlocks only after a dry run of the *same* task
   selection and the *same* README has finished without being cancelled. Change
   either and it locks again. It then opens a confirmation dialog, where you
   tick that you have answered the forensics questions before it starts.
5. **Live monitor.** Per-task status, elapsed time and output as it happens.
   Cancel stops between tasks, never mid-write.
6. **Results tab.** A dry/real toggle, statistics, a comparison of the two, a
   searchable ledger of every change and its proof, copy-summary, and a button to
   open the run log.

The window is a light theme with the system font. It renders through
wgpu (Direct3D 12), falling back to the WARP software renderer on a VM with no
GPU driver.

**Administrator.** The executable's manifest requests it. If UAC is off, Windows
starts it elevated without asking. Either way the pill at the top right says
whether the GUI is elevated, and the real run stays locked if it is not.

---

## The web UI

Linux. `pinnacle-cypat --web [--port N]`, which `RUN.sh` runs by default. The
screens and rules are the GUI's: README picker with a file browser, editable
README, tasks, dry run, gated real run, live monitor, results.

Why a browser rather than a window: the shipped binary is static musl and cannot
load X11, Wayland or GL, and Ubuntu's Wayland session refuses a window opened by
root. A browser running as you, talking to this process running as root, has
neither problem.

It makes root changes, so the server is locked down:

- **Loopback only** (`127.0.0.1`). The URL it prints carries a **per-run token**,
  required on every request.
- The `Host` header is checked (DNS rebinding) and so is `Origin` on every POST
  (cross-site requests). A Content-Security-Policy is set on every page.
- Live updates arrive over server-sent events.

It exits on Ctrl+C, on the page's **Quit** button, or after **120 seconds with no
page connected and no run in progress**. It never exits in the middle of a run: a
quit during one cancels it after the current task, and a second Ctrl+C leaves
immediately.

A **bare launch** (no arguments) opens a front end rather than doing anything
destructive. On Windows that is the GUI, if `pinnacle-cypat-gui.exe` is next to
the CLI exe; on Linux it is the web UI when there is a desktop session
(`DISPLAY`, `WAYLAND_DISPLAY`, or a `sudo` from a user with one). Otherwise it
prints help.

---

## Requirements

**Windows** — 10/11 or Server 2016+, run as **Administrator**. Nothing to
install: the shipped `pinnacle-cypat.exe` is self-contained and carries no
runtime.

**Linux** — Debian or Ubuntu, run as **root**. Package management assumes `apt`;
everything else works on any systemd distribution.

Either way, building from source needs [Rust](https://rustup.rs), and
`--auto-readme` or software installation needs network access.

---

## What it does

Each task reads the current state, applies its changes, then re-reads the machine
to verify. The flags are the same on both platforms wherever the concept exists,
so `--help` and a run log read the same way on either.

### Windows — fifteen tasks

| Task | Flag | What it does |
|---|---|---|
| Password Policy | `-p` | 14-char minimum, 60-day age, 24 history, 5-attempt lockout (a threshold of 1–4 is raised to 5), complexity on, no reversible encryption |
| Account Permissions | `-a` | Disables Guest, turns off "password never expires", reports surplus admins |
| User Management | `-u` | Deletes unauthorised accounts, fixes admin membership, resets passwords, creates required users and groups |
| Service Management | `-s` | Disables 60+ insecure services, protects 20 critical ones, kills SMB1 and Telnet |
| Audit Policy | `-t` | All 9 audit categories to success+failure, 20 security registry values, PowerShell logging, event log sizing |
| Firewall | `-f` | Enables all profiles, blocks 26 ports, disables risky rules, turns on logging |
| Security Hardening | `-H` | 46 registry values — UAC, AutoRun, RDP, Defender, LSA, WinRM, memory, browser; Apache `ServerSignature Off` / `ServerTokens Prod` when `httpd.conf` is found |
| Local Security Policy | `-g` | SMB signing, anonymous enumeration, logon banners, RDP encryption |
| Prohibited Media | `-m` | Finds and permanently deletes media, games and hacking tools under `C:\Users` |
| Software Management | `--software-management` | Removes prohibited software (including leftover Program Files folders and shortcuts), installs required software, runs a Defender scan |
| Software Updates | `--software-updates` | Updates installed applications via Chocolatey, including ones Chocolatey did not install; warns if an app moves from its install location |
| Shared Folders Audit | `--shared-folders` | Removes shares beyond `ADMIN$`, `C$`, `IPC$` (plus `NETLOGON` and `SYSVOL` on a domain controller) |
| Hosts File Audit | `--hosts-file` | Removes unauthorised `hosts` entries |
| DNS Settings Audit | `--dns-settings` | Reports public resolvers (report only — never changes DNS) |
| Scheduled Tasks Audit | `--scheduled-tasks` | Disables tasks matching suspicious keywords |

### Linux — sixteen tasks

| Task | Flag | What it does |
|---|---|---|
| Password Policy | `-p` | `pam_pwquality` complexity (installed if missing), `PASS_MIN_LEN`; `faillock` lockout and `pwhistory` password history via `pam-auth-update`, rolled back if the order is unsafe; strips `nullok`; puts `minlen` and `remember` on the PAM lines; reports PAM lines that skip the password check |
| Account Permissions | `-a` | Locks passwordless accounts (root included), applies ageing, removes sudo `NOPASSWD` (keeping the rule), turns off LightDM guest sessions; reports duplicate uid 0, service accounts with shells and display-manager auto-login |
| User Management | `-u` | Deletes unauthorised accounts (keeping home directories), including people hidden below uid 1000; fixes `sudo` membership; creates required users and groups and adds the README's group members |
| Service Management | `-s` | Masks 58 insecure units, protects the README's critical ones and the scoring engine |
| Audit Policy | `-t` | Installs and enables `auditd` and `rsyslog`, writes 34 audit rules and tunes retention |
| Firewall | `-f` | Enables `ufw` with default-deny inbound, opening only what the README needs |
| Security Hardening | `-H` | 72 settings across `sysctl.d`, `sshd_config.d` and `login.defs`, overriding contrary values in `sysctl.conf` and `sshd_config`; 14 kernel modules blocked, login banners, Apache banner hardening |
| Prohibited Media | `-m` | Finds media under `/home`, `/root` and other user-writable roots, deleting only if the README prohibits it; deletes hacking-tool archives and scripts; never deletes from a critical service's data directory |
| File Permissions Audit | `--file-permissions` | Corrects 16 scored file modes; reports world-writable, unowned, setuid and `.rhosts` findings |
| Shared Folders Audit | `--shared-folders` | Reports Samba shares and NFS exports, grading their options |
| Software Updates | `--software-updates` | `apt upgrade`, then enables `unattended-upgrades` (and Update Manager's automatic updates on Linux Mint) |
| Backdoor Listeners | `--backdoors` | Kills listening backdoors (netcat, scripts and binaries no package owns), deletes their files where safe, disables the cron lines and units that start them |
| Software Management | `--software-management` | Purges prohibited packages, installs required ones |
| Hosts File Audit | `--hosts-file` | Removes unauthorised `/etc/hosts` entries |
| DNS Settings Audit | `--dns-settings` | Reports the resolvers in use, via `resolv.conf` and `resolvectl` |
| Scheduled Tasks Audit | `--scheduled-tasks` | Reports suspicious jobs across all six cron locations |

Several Linux findings are deliberately **reported and not fixed** — a second
uid 0 account, suspicious cron jobs, the resolvers in use, world-writable and
setuid files, and every share — because acting automatically on any of them is
more likely to break the image than help it. Group Policy has no Linux
equivalent, so there is no such task there.

The tables are CIS Ubuntu 22.04 derived and now match the Windows ones in size:
72 hardening settings against Windows' 46, 58 prohibited services against 55.

**Full detail on every one — why it exists, what it changes, how, and what it
refuses to touch — is in [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md).**

---

## What this round does differently

Most of a hardening run is the same every round. What loses points is the other
part: the sentence in paragraph four saying this machine is administered over
SSH, or that Firefox must come from a PPA rather than a snap, or that the
display manager must stay as it is. A generic script does the standard thing and
quietly gets those wrong.

`--directives` reads the prose and sorts every such instruction into three
groups — and it runs automatically at the start of every real run, before
anything is changed.

```
$ pinnacle-cypat --directives -r README.html

Handled by a task - the README changed what the run does
  ✓ a critical service - Service Management protects it and never masks it
      "Therefore, sshd is a critical service and needs to remain enabled"
  ✓ a group membership - User Management adds the named members
      "Please add the user "candace" to the "firesidegirls" group"

Not touched - no task has code that would break these
  ✓ the clock - no task calls timedatectl, date or the time-zone APIs
      "Please do not change the time zone, date, or time on this image"

Do these by hand (5) - this tool cannot, and a missed one is a lost item
  ! forensics questions - read them from the Desktop and answer them BEFORE
      running any task - a remediation can destroy the evidence
  ! install source - apt installs the snap transitional package on Ubuntu
      22.04; add the PPA and pin it by hand
      "Firefox must remain installed using the official Mozilla PPA, and NOT
       as a SNAP package"
  ! the display manager - verify with `cat /etc/X11/default-display-manager`
      "The display manager should remain set to GDM3"
```

**The last group is the point.** The parser already extracts what the tool can
act on; everything it *cannot* act on used to vanish silently. Every directive
quotes the sentence it came from, so the classification can be checked rather
than taken on trust, and all of them land in the run log.

---

## How the README is found

> [!IMPORTANT]
> **On a standard competition image the README is not a file on disk.**
> `C:\CyberPatriot\README.url` is an *Internet Shortcut* naming an `https://`
> document, which is what the competitor's browser opens — `C:\CyberPatriot\`
> contains no `README.html`.

`--auto-readme` resolves shortcuts rather than looking only for literal paths. It
checks, in order:

1. A README shortcut on the current user's desktop, then the public desktop
2. `C:\CyberPatriot\README.url`, then `README.html`
3. The public desktop and documents folders
4. Every user's desktop (`C:\Users\*\Desktop\README.*`)

Shortcuts **chain** on a real image (desktop `.lnk` → `README.url` → the
document) and are followed to the end. A remote target is downloaded. The URL is
unique per image and changes every competition, so it is read from the shortcut
at run time and never hard-coded.

The run says which document it settled on:

```
Using README: C:\Users\you\AppData\Local\Temp\pinnaclecypat_readme.html
              (resolved from C:\CyberPatriot\README.url)
```

If discovery fails it lists every location it checked, distinguishing "not found"
from "exists but could not be resolved".

**No network?** Open the README in a browser, save it as HTML, and pass it with
`--readme <file>`. `--readme` also accepts a `.url`, a `.lnk`, or an `https://`
address directly.

**On Linux the resources live in `/opt/CyberPatriot`** — the counterpart of
`C:\CyberPatriot` — and the README there is a `.desktop` launcher, not a file
and not a `.url`. That directory is scanned rather than probed by file name,
because the launcher is named after the round ("Exhibition Round Ubuntu 22.04
README"), not `README.desktop`.
Both launcher shapes are followed — `Type=Link` with a `URL=`, and
`Type=Application` whose `Exec=` opens the address in a browser. Field codes
(`%u`, `%U`, `%f`, `%F`) are placeholders the desktop environment substitutes
and are not part of the address.

> [!TIP]
> `sudo` rewrites `HOME` to `/root`, so a search that trusts it looks in
> `/root/Desktop` while the launcher sits on `/home/you/Desktop`. `SUDO_USER` is
> checked first for exactly this reason, and every other home directory after
> it.

---

## Flags

These are the same on both platforms:

| Flag | Short | Effect |
|---|---|---|
| `--help` | `-h` | Show the flag table and exit |
| `--web` | | Open the web UI in a browser, served from `127.0.0.1` (Linux) |
| `--port <n>` | | With `--web`, listen on port `<n>` instead of a random one |
| `--version` | `-V` | Print version and build date, then exit |
| `--readme <path>` | `-r` | Read the competition README at `<path>` |
| `--auto-readme` | `-R` | Find the README automatically |
| `--parse-readme` | | Show what the parser extracted, then exit (read-only) |
| `--directives` | | Show what this round does differently, then exit (read-only) |
| `--dry-run` | `-d` | Report what would change without changing it |
| `--all` | | Run every task |
| `--log <path>` | | Write the run log to `<path>` |

The task flags come from the platform the binary was built for, and `--help`
lists them under a `WINDOWS TASKS:` or `LINUX TASKS:` heading. Where the concept
exists on both, the spelling matches:

| Flag | Short | Windows | Linux |
|---|---|---|---|
| `--password-policy` | `-p` | ✓ | ✓ |
| `--account-permissions` | `-a` | ✓ | ✓ |
| `--user-management` | `-u` | ✓ | ✓ |
| `--service-management` | `-s` | ✓ | ✓ |
| `--audit-policy` | `-t` | ✓ | ✓ |
| `--firewall` | `-f` | ✓ | ✓ |
| `--security-hardening` | `-H` | ✓ | ✓ |
| `--media-scan` | `-m` | ✓ | ✓ |
| `--software-management` | | ✓ | ✓ |
| `--software-updates` | | ✓ | ✓ |
| `--hosts-file` | | ✓ | ✓ |
| `--dns-settings` | | ✓ | ✓ |
| `--scheduled-tasks` | | ✓ | ✓ |
| `--file-permissions` | | — | ✓ |
| `--backdoors` | | — | ✓ |
| `--group-policy` | `-g` | ✓ | — no equivalent |
| `--shared-folders` | | ✓ | ✓ |

> [!NOTE]
> `-h` is **help**. Security hardening is `-H`; `--security-hardening` is
> unchanged.

> [!IMPORTANT]
> **Running everything must be asked for: pass `--all`.** A bare invocation opens
> a front end if one is available (see [The web UI](#the-web-ui)), and prints
> help otherwise. It used to mean "run every task", so double-clicking the
> executable began a full destructive run.
>
> An **unrecognised** argument is rejected with exit code 2 and changes nothing.
> It used to be ignored — and because "no task flag" meant "run everything", a
> typo started that same run.

---

## The run log

Every run writes a log to your desktop:

```
C:\Users\<you>\Desktop\PinnacleCyPat_RunLog_v1.8.0_20260822_213024.txt
```

Every line the tool prints is mirrored into it, markup stripped and timestamped —
table contents included — followed by a structured per-task block giving outcome,
verification state, item counts and any issues.

**Generated passwords are in this log.** They are the only way back into the
accounts the tool resets. Override the location with `--log <path>`.

### Diagnostics

The log also records every external command with its arguments, exit code and
elapsed time, plus the first 600 characters of output when one fails. Tasks add
their own reasoning on top.

When something did not happen and you want to know why, grep the log:

```powershell
Select-String '\[cmd\]'      .\PinnacleCyPat_RunLog_*.txt   # every command run
Select-String '\[software\]' .\PinnacleCyPat_RunLog_*.txt   # what matched, what was tried
```

A removal that failed now shows the uninstaller it ran, the exit code, and what
the uninstaller printed — rather than an empty reason. Passwords are redacted
from the command echo.

---

## Implementation

One Rust program, `rust/`, built as a five-crate workspace: an OS-agnostic core,
a crate per platform, the Windows GUI, and the binary. The README parser, the
remediation ledger, the run log and the whole run pipeline live in the core and
are identical on both platforms — adding Linux needed no change to any of them.

The tool began as a C# implementation, which ran alongside the Rust port until
2026-08-23, was then frozen as an archive, and has since been removed from the
repo (it remains in git history). Keeping two implementations at parity meant
every change landed twice and drift was silent, which is also why the platform
split is two crates rather than `#[cfg]` branches in one.

---

## Building

```bash
./scripts/check.sh      # fmt, clippy, 726 tests, and the Windows type-check
./scripts/publish.sh    # -> publish-win-x64/pinnacle-cypat.exe
                        # -> publish-linux-x64/pinnacle-cypat
```

> [!IMPORTANT]
> **The Linux binary is built against musl, not glibc, and has to be.** A glibc
> build links against whatever the *build* machine has: built on a current
> distribution it requires `GLIBC_2.39`, while Ubuntu 22.04 — the image a round
> actually runs on — ships 2.35. It refuses to start, with an error naming a
> symbol version rather than the problem.
>
> glibc cannot be upgraded past what an Ubuntu release ships (`libc6` is pinned
> to the release, and forcing a newer one breaks the system), so the fix has to
> be on the build side. musl links statically: no libc dependency at all, and
> the same binary runs on any Linux. It costs about 200 KB, and `publish.sh`
> fails the build if the artefact turns out to reference glibc anyway.
>
> ```bash
> rustup target add x86_64-unknown-linux-musl
> ```

`check.sh` is everything CI runs, ordered so it fails fastest; `check.ps1` is the
same on Windows. By hand:

```bash
cd rust
cargo test --workspace
cargo build --release -p pinnacle-cypat
```

The build targets whichever platform you are on, and includes only that
platform's tasks — a Windows build carries no Linux code and vice versa.

Cross-compiling the Windows binary from Linux needs the GNU target
(`x86_64-pc-windows-msvc` requires Microsoft's linker) — `publish.sh` handles it.
A Linux host never compiles the `#[cfg(windows)]` branches, so run
`cargo clippy --target x86_64-pc-windows-gnu -p pinnacle-windows -p pinnacle-cypat`
after touching any of them; a clean `cargo test` on Linux proves nothing about
those paths.

Details in [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md#11-build-test-publish).

---

## Project layout

`rust/` is a Cargo workspace of five crates, split so that adding an operating
system is additive rather than a set of `#[cfg]` branches through every task.

```
PinnacleCyPat/
├── RUN.bat / RUN.ps1              Windows launchers → the desktop GUI
├── RUN.sh                         Linux launcher → the web UI
├── LICENSE                        Apache License 2.0
├── NOTICE                         Attribution, trademark, third-party components
├── rust/
│   └── crates/
│       ├── core/                  pinnacle-core — nothing here names an OS
│       │   ├── platform.rs        The seam: TaskSpec, Concurrency, Platform
│       │   ├── task.rs            The Task trait
│       │   ├── readme_parser.rs   README prose -> ReadmeData
│       │   ├── remediation.rs     Prove-and-record wrapper for every change
│       │   ├── run_log.rs         Transcript, diagnostics, remediation ledger
│       │   ├── engine.rs          RunPlan in, RunEvent stream out
│       │   ├── session.rs         AppState, Action, real_run_gate (GUI and web)
│       │   ├── files.rs           Directory listing for both file browsers
│       │   ├── models/            Data models
│       │   └── tests/corpus/      README fixtures — add real ones here
│       ├── windows/               pinnacle-windows — the fifteen Windows tasks
│       │   ├── native/            Win32 APIs (Windows only)
│       │   ├── knowledge.rs       The tables: registry, packages, services
│       │   └── *_ops.rs           Proved writes
│       ├── linux/                 pinnacle-linux — the sixteen Linux tasks
│       │   ├── file_ops.rs        Proved writes to /etc
│       │   ├── systemd_ops.rs     Proved systemctl operations
│       │   ├── user_ops.rs        /etc/passwd, shadow, group
│       │   └── apt.rs             Package installs and upgrades
│       ├── gui/                   pinnacle-cypat-gui — the Windows desktop GUI
│       │   ├── app.rs             Layout, actions, dialogs, screenshot hooks
│       │   ├── screens/           README, Run, Results, file browser
│       │   └── theme.rs           Light theme
│       └── cli/                   pinnacle-cypat — the binary
│           ├── main.rs            Flag parsing, bare-launch front end
│           └── web/               The Linux web UI: server, api, controller, index.html
├── scripts/                       check.sh / check.ps1 / publish.sh
└── docs/
    ├── ARCHITECTURE.md            Full reference — every task and utility
    ├── CONTRIBUTING.md            Coding standards
    ├── CLAUDE.md                  AI assistant instructions
    └── TASK_ANALYSIS.md           Task roadmap
```

The CLI names no operating system: it reads the platform crate's task table,
which is selected by one `cfg` at compile time. Adding a task is one row in that
table, which is also what supplies its `--help` line and its entry in the GUI and web
task lists.

---

## For developers

The core is OS-agnostic: `pinnacle-core` holds the README parser, the remediation
ledger, the run log and `engine`, which takes a `RunPlan` and emits a stream of
`RunEvent`s. The platform crates (`windows`, `linux`) hold the tasks and are the
only code that names an OS. There are three thin front ends over the one engine:
the CLI, the Windows GUI and the Linux web UI. The last two share their state
machine and the real-run gate through `pinnacle_core::session`.

The rules that matter:

- **Every write proves itself.** A change goes through `remediation::apply`,
  which reads the state back and records that as evidence.
- **A dry run never writes.** Every task honours it.
- **The README drives decisions.** Nothing is deleted or disabled on a guess.

```bash
./scripts/check.sh            # fmt, clippy, 726 tests, Windows type-check
cd rust && cargo test --workspace
```

The GUI ships for Windows (the web UI is the Linux front end), but the crate also
builds and runs its tests on Linux for development. Start
with [docs/CLAUDE.md](docs/CLAUDE.md) and [docs/CONTRIBUTING.md](docs/CONTRIBUTING.md).

---

## Licence

Licensed under the **[Apache License 2.0](LICENSE)**.

Use it, modify it, redistribute it, run it in a competition, build something else
out of it. Keep the licence and NOTICE with any copy you pass on, and state what
you changed. See [NOTICE](NOTICE) for attribution and third-party components.

**It comes with no warranty of any kind, and the author is not liable for what it
does to your machine.** Sections 7 and 8 of the licence say so in the formal
words; the plain version is in [NOTICE](NOTICE) and in the disclaimer below, and
neither is boilerplate for a tool that deletes accounts and uninstalls software.

> This project was briefly relicensed as proprietary in August 2026 and returned
> to Apache 2.0 on 2026-08-23. Every release, before and since, is Apache 2.0.

CyberPatriot is a program of the Air & Space Forces Association. This tool is an
independent work and is not affiliated with, endorsed by, or sponsored by the Air
& Space Forces Association or the CyberPatriot program.

---

## Disclaimer

Provided "as is", without warranty of any kind. It makes extensive, largely
irreversible changes to the system it runs on and may render a system unbootable
or unusable. The entire risk is yours.

- **Run `--dry-run` first**, every time
- **Snapshot the VM** before applying
- **Run as Administrator** (or root), or most changes are silently refused
- **Never disable CCS Client** — it is the scoring engine (the tool protects it)
