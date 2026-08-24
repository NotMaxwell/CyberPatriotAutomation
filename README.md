# PinnacleCyPat

[![Rust](https://img.shields.io/badge/Rust-2024-000000)](https://www.rust-lang.org/)
[![License](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](LICENSE)
[![Tests](https://img.shields.io/badge/Tests-354-brightgreen)]()
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

**Easiest:** double-click `RUN.bat`. It checks for Administrator, then opens the
built-in menu.

**From a terminal:**

```powershell
PinnacleCyPat.exe --tui          # guided menu — pick README, tasks, preview/apply
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

## The menu

`--tui`, or just launching the executable with no arguments at a terminal.

```
╭──────────────────────────────────────────────────────╮
│  PinnacleCyPat                                       │
│  v1.8.0 (build 2026-08-22)                           │
│  Windows security hardening for CyberPatriot images  │
╰──────────────────────────────────────────────────────╯

What would you like to do?
> Inspect the README only  (read-only, changes nothing)
  Preview every task  (dry run, changes nothing)
  Run every task  (applies changes)
  Choose individual tasks
  Quit
```

It asks which README to use, which tasks to run, and whether to preview or apply
— then shows a summary and waits for an explicit yes. The default answer is **no**
for a run that applies changes and **yes** for a preview, so pressing enter
without reading is always the harmless choice.

The menu builds a command line and hands it to the normal run pipeline, so the
run log records exactly what it did and you can repeat it non-interactively.

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
| Password Policy | `-p` | 14-char minimum, 60-day age, 24 history, 5-attempt lockout, complexity on |
| Account Permissions | `-a` | Disables Guest, turns off "password never expires", reports surplus admins |
| User Management | `-u` | Deletes unauthorised accounts, fixes admin membership, resets passwords, creates required users and groups |
| Service Management | `-s` | Disables 60+ insecure services, protects 20 critical ones, kills SMB1 and Telnet |
| Audit Policy | `-t` | All 9 audit categories to success+failure, 20 security registry values, PowerShell logging, event log sizing |
| Firewall | `-f` | Enables all profiles, blocks 26 ports, disables risky rules, turns on logging |
| Security Hardening | `-H` | 41 registry values — UAC, AutoRun, RDP, Defender, LSA, memory, browser |
| Local Security Policy | `-g` | SMB signing, anonymous enumeration, logon banners, RDP encryption |
| Prohibited Media | `-m` | Finds and permanently deletes media, games and hacking tools under `C:\Users` |
| Software Management | `--software-management` | Removes prohibited software, installs required software, runs a Defender scan |
| Software Updates | `--software-updates` | Updates installed applications via Chocolatey |
| Shared Folders Audit | `--shared-folders` | Removes shares beyond `ADMIN$`, `C$`, `IPC$` |
| Hosts File Audit | `--hosts-file` | Removes unauthorised `hosts` entries |
| DNS Settings Audit | `--dns-settings` | Reports public resolvers (report only — never changes DNS) |
| Scheduled Tasks Audit | `--scheduled-tasks` | Disables tasks matching suspicious keywords |

### Linux — thirteen tasks

| Task | Flag | What it does |
|---|---|---|
| Password Policy | `-p` | `pam_pwquality` complexity, `faillock` lockout, reports missing password history |
| Account Permissions | `-a` | Locks passwordless accounts, applies ageing, reports duplicate uid 0 and service accounts with shells |
| User Management | `-u` | Deletes unauthorised accounts (keeping home directories), fixes `sudo` membership, creates required users |
| Service Management | `-s` | Masks 28 insecure units, protects the README's critical ones and the scoring engine |
| Audit Policy | `-t` | Installs and enables `auditd` and `rsyslog`, writes 13 audit rules |
| Firewall | `-f` | Enables `ufw` with default-deny inbound, opening only what the README needs |
| Security Hardening | `-H` | 36 settings across `sysctl.d`, `sshd_config.d` and `login.defs` |
| Prohibited Media | `-m` | Finds media under `/home` and `/root`; deletes only if the README prohibits it |
| Software Updates | `--software-updates` | `apt upgrade`, then enables `unattended-upgrades` |
| Software Management | `--software-management` | Purges prohibited packages, installs required ones |
| Hosts File Audit | `--hosts-file` | Removes unauthorised `/etc/hosts` entries |
| DNS Settings Audit | `--dns-settings` | Reports the resolvers in use, via `resolv.conf` and `resolvectl` |
| Scheduled Tasks Audit | `--scheduled-tasks` | Reports suspicious jobs across all six cron locations |

Three Linux findings are deliberately **reported and not fixed** — a second uid 0
account, suspicious cron jobs, and the resolvers in use — because acting
automatically on any of them is more likely to break the image than help it.
Group Policy has no Linux equivalent, so there is no such task there.

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

---

## Flags

These are the same on both platforms:

| Flag | Short | Effect |
|---|---|---|
| `--help` | `-h` | Show the flag table and exit |
| `--tui` | `-i` | Open the interactive menu |
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
| `--group-policy` | `-g` | ✓ | — no equivalent |
| `--shared-folders` | | ✓ | — |

> [!NOTE]
> `-h` is **help**. Security hardening is `-H`; `--security-hardening` is
> unchanged.

> [!IMPORTANT]
> **Running everything must be asked for: pass `--all`.** A bare invocation opens
> the menu at a terminal, and prints help otherwise. It used to mean "run every
> task", so double-clicking the executable began a full destructive run.
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

One Rust program, `rust/`, built as a four-crate workspace: an OS-agnostic core,
a crate per platform, and the binary. The README parser, the remediation ledger,
the run log and the whole run pipeline live in the core and are identical on
both platforms — adding Linux needed no change to any of them.

A complete C# implementation lived alongside the Rust one until 2026-08-23 and is
now frozen under [`archive/csharp/`](archive/csharp/) — it still builds and
passes its 202 tests, but it is not shipped and not kept in step. Keeping two
implementations at parity meant every change landed twice and drift was silent,
which is also why the platform split is two crates rather than `#[cfg]` branches
in one. [The archive README](archive/csharp/README.md) has the full reasoning.

---

## Building

```bash
./scripts/check.sh      # fmt, clippy, 354 tests, and the Windows type-check
./scripts/publish.sh    # -> publish-win-x64/pinnacle-cypat.exe
```

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

`rust/` is a Cargo workspace of four crates, split so that adding an operating
system is additive rather than a set of `#[cfg]` branches through every task.

```
PinnacleCyPat/
├── RUN.bat / RUN.ps1              Double-click launchers → the built-in menu
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
│       │   ├── models/            Data models
│       │   └── tests/corpus/      README fixtures — add real ones here
│       ├── windows/               pinnacle-windows — the fifteen Windows tasks
│       │   ├── native/            Win32 APIs (Windows only)
│       │   ├── knowledge.rs       The tables: registry, packages, services
│       │   └── *_ops.rs           Proved writes
│       ├── linux/                 pinnacle-linux — the thirteen Linux tasks
│       │   ├── file_ops.rs        Proved writes to /etc
│       │   ├── systemd_ops.rs     Proved systemctl operations
│       │   ├── user_ops.rs        /etc/passwd, shadow, group
│       │   └── apt.rs             Package installs and upgrades
│       └── cli/                   pinnacle-cypat — the binary
│           ├── main.rs            Flag parsing and the run pipeline
│           └── tui.rs             Interactive menu
├── archive/csharp/                The retired C# port, frozen
├── scripts/                       check.sh / check.ps1 / publish.sh
└── docs/
    ├── ARCHITECTURE.md            Full reference — every task and utility
    ├── CONTRIBUTING.md            Coding standards
    ├── CLAUDE.md                  AI assistant instructions
    └── TASK_ANALYSIS.md           Task roadmap
```

The CLI names no operating system: it reads the platform crate's task table,
which is selected by one `cfg` at compile time. Adding a task is one row in that
table, which is also what supplies its `--help` line and its menu entry.

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
