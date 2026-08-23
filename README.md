# PinnacleCyPat

[![.NET](https://img.shields.io/badge/.NET-10.0-512BD4)](https://dotnet.microsoft.com/)
[![Rust](https://img.shields.io/badge/Rust-2021-000000)](https://www.rust-lang.org/)
[![License](https://img.shields.io/badge/License-Proprietary-red.svg)](LICENSE)
[![Tests](https://img.shields.io/badge/Tests-172%20C%23%20%2B%20139%20Rust-brightgreen)]()

**Author:** Maxwell McCormick · **Copyright:** © 2026 Maxwell McCormick, all rights reserved

Automated Windows security hardening for CyberPatriot competition images. It
reads the round's own README, applies the mechanical part of the checklist, and
tells you exactly what it changed.

> [!CAUTION]
> **This tool makes largely irreversible changes.** It deletes files permanently,
> deletes user accounts, changes passwords, disables services, rewrites registry
> and security policy, and uninstalls software. Run `--dry-run` first. Run it only
> on images you can afford to lose.

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

- Windows 10/11 or Windows Server 2016+
- **Administrator privileges** — nearly everything needs them
- [.NET 10.0 SDK](https://dotnet.microsoft.com/download/dotnet/10.0), unless you
  use the self-contained published build
- Network access, if you want `--auto-readme` (the README lives on the web) or
  software installation (Chocolatey)

---

## What it does

Thirteen tasks. Each reads the current state, applies its changes, then re-reads
the machine to verify.

| Task | Flag | What it does |
|---|---|---|
| Password Policy | `-p` | 14-char minimum, 60-day age, 24 history, 5-attempt lockout, complexity on |
| Account Permissions | `-a` | Disables Guest, turns off "password never expires", reports surplus admins |
| User Management | `-u` | Deletes unauthorised accounts, fixes admin membership, resets passwords, creates required users and groups |
| Service Management | `-s` | Disables 60+ insecure services, protects 20 critical ones, kills SMB1 and Telnet |
| Audit Policy | `-t` | All 9 audit categories to success+failure, 20 security registry values, PowerShell logging, event log sizing |
| Firewall | `-f` | Enables all profiles, blocks 26 ports, disables risky rules, turns on logging |
| Security Hardening | `-H` | 41 registry values — UAC, AutoRun, RDP, Defender, LSA, memory, browser |
| Prohibited Media | `-m` | Finds and permanently deletes media, games and hacking tools under `C:\Users` |
| Software Management | `--software-management` | Removes prohibited software, installs required software, runs a Defender scan |
| Shared Folders Audit | `--shared-folders` | Removes shares beyond `ADMIN$`, `C$`, `IPC$` |
| Hosts File Audit | `--hosts-file` | Removes unauthorised `hosts` entries |
| DNS Settings Audit | `--dns-settings` | Reports public resolvers (report only — never changes DNS) |
| Scheduled Tasks Audit | `--scheduled-tasks` | Disables tasks matching suspicious keywords |

**Full detail on every one — why it exists, what it changes, how, and what it
refuses to touch — is in [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md).**

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

| Flag | Short | Effect |
|---|---|---|
| `--help` | `-h` | Show the flag table and exit |
| `--tui` | `-i` | Open the interactive menu |
| `--version` | `-V` | Print version and build date, then exit |
| `--readme <path>` | `-r` | Read the competition README at `<path>` |
| `--auto-readme` | `-R` | Find the README automatically |
| `--parse-readme` | | Show what the parser extracted, then exit (read-only) |
| `--dry-run` | `-d` | Report what would change without changing it |
| `--all` | | Run every task |
| `--password-policy` | `-p` | Password and lockout policy |
| `--account-permissions` | `-a` | Account permissions and group membership |
| `--user-management` | `-u` | Create, remove and correct user accounts |
| `--service-management` | `-s` | Enable required and disable insecure services |
| `--audit-policy` | `-t` | Audit policy and security event logging |
| `--firewall` | `-f` | Windows Firewall profiles and rules |
| `--security-hardening` | `-H` | General security hardening |
| `--media-scan` | `-m` | Find and remove prohibited media |
| `--software-management` | | Remove prohibited and install required software |
| `--shared-folders` | | Remove shares beyond `ADMIN$`, `C$`, `IPC$` |
| `--hosts-file` | | Remove unauthorised hosts file entries |
| `--dns-settings` | | Report public DNS resolvers |
| `--scheduled-tasks` | | Disable suspicious scheduled tasks |
| `--log <path>` | | Write the run log to `<path>` |

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

## Two implementations

| | C# | Rust |
|---|---|---|
| Location | `src/`, `tests/` | `rust/` |
| Version | 1.8.0 | 1.13.0 |
| Tests | 172 | 139 |
| Published size | ~42 MB self-contained | ~2.1 MB |

Same flags, same tasks, same run-log format. The Rust port additionally has a
`--software-updates` task, runs the four independent audits concurrently, and has
a more precise scheduled-task audit. See [rust/README.md](rust/README.md).

---

## Building

```bash
# C#
dotnet build src/PinnacleCyPat.csproj
dotnet test  tests/PinnacleCyPat.Tests.csproj

dotnet publish src/PinnacleCyPat.csproj -c Release \
  -f net10.0-windows -o publish-win-x64

# Rust
cd rust
cargo test
cargo build --release
```

The C# project multi-targets `net10.0` and `net10.0-windows` on purpose: the
Windows TFM is the real build, and the plain one exists so the parser, model and
reporting tests run on a non-Windows dev box.

Details — including why trimming is deliberately disabled and how to
cross-compile the Rust binary — are in
[docs/ARCHITECTURE.md](docs/ARCHITECTURE.md#11-build-test-publish).

---

## Project layout

```
PinnacleCyPat/
├── RUN.bat / RUN.ps1              Double-click launchers → the built-in menu
├── LICENSE                        Proprietary licence
├── NOTICE                         Attribution, trademark, third-party components
├── src/                           C# implementation
│   ├── Program.cs                 Entry point, flag parsing, run pipeline
│   ├── NativeMethods.txt          CsWin32 P/Invoke manifest
│   └── Core/
│       ├── AppConfig.cs           README discovery, defaults, version
│       ├── Tui.cs                 Interactive menu
│       ├── Models/                Data models
│       ├── Tasks/                 The thirteen tasks
│       ├── Utilities/             Command execution, parsing, logging, packages
│       └── Native/                Win32 APIs (Windows TFM only)
├── tests/                         xUnit suite
├── rust/                          Rust implementation
├── scripts/                       Build, test and format helpers
└── docs/
    ├── ARCHITECTURE.md            Full reference — every task and utility
    ├── CONTRIBUTING.md            Coding standards
    ├── CLAUDE.md                  AI assistant instructions
    └── TASK_ANALYSIS.md           Task roadmap
```

---

## Licence

**PinnacleCyPat is proprietary software. It is not open source.**

You may install and run unmodified copies on systems you own or are authorized to
administer. You may **not** copy (beyond installation and one backup), modify,
fork, redistribute, sublicense, host, mirror, sell, reverse engineer, or
re-implement it elsewhere. Source is published for review and auditing only; its
visibility grants no right to reuse it.

See [LICENSE](LICENSE) for the full terms and [NOTICE](NOTICE) for attribution
and third-party components. Written permission from Maxwell McCormick is required
for any use beyond running the software.

Releases before 2026-08-22 were distributed under the Apache License 2.0. Copies
lawfully obtained under that licence remain governed by it; everything from that
date forward is governed by the LICENSE file here.

"PinnacleCyPat" is an unregistered trademark of Maxwell McCormick.

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
- **Run as Administrator**, or most changes are silently refused
- **Never disable CCS Client** — it is the scoring engine (the tool protects it)
