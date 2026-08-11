# CyberPatriot Automation Tool — Rust port

A faithful Rust port of the C# `CyberPatriotAutomation` tool. It automates
CyberPatriot Windows security-hardening tasks and preserves the original
behaviour, CLI flags, task pipeline, and console UI.

> Like the original, this is a **Windows** tool: it shells out to `net`,
> `secedit`, `netsh`, `reg`, `auditpol`, `schtasks`, `sc`, `wmic`, and
> PowerShell. It builds and its parser/model logic is unit-tested on any
> platform, but the hardening tasks only do real work on Windows (as
> Administrator). On non-Windows hosts the underlying commands simply fail
> gracefully.

## Build & test

```bash
cd rust
cargo build --release      # binary: target/release/cyberpatriot-automation
cargo test                 # 59 tests
cargo clippy --all-targets # clean
```

## Usage

Same flags as the original (`Program.cs`):

```bash
cyberpatriot-automation --all --dry-run
cyberpatriot-automation --readme "C:\Users\Public\Desktop\README.html" --all
cyberpatriot-automation --auto-readme --all
cyberpatriot-automation --parse-readme -r README.html
cyberpatriot-automation --password-policy   # -p
cyberpatriot-automation --firewall          # -f
# -r/--readme, -R/--auto-readme, -d/--dry-run, -p, -a, -u, -s, -t, -f, -h, -m, --all
```

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

Author: Maxwell McCormick · Apache-2.0 · "CyberPatriot Automation Tool" is an
unregistered trademark of Maxwell McCormick (see `../NOTICE`).
