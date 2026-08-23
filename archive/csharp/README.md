# C# port — archived

This is the original .NET implementation of PinnacleCyPat. **It is no longer
maintained and is not built, tested or shipped.** The Rust port under
[`../../rust/`](../../rust/) is the tool.

It is kept because it is the reference the Rust port was written against: when
the Rust behaviour is unclear, this is what it was mirroring, and the comments
here record why several non-obvious decisions were made.

## Why it was retired

Two complete implementations of the same tool had to be kept at parity, and
every behavioural change had to land twice in two languages. Drift was silent —
it surfaced only when someone read both files side by side. The last instance
before archiving: security hardening consulted the README before denying Remote
Desktop in C# and did not in Rust, so on an image whose scenario required RDP
the Rust port denied it while service management kept the service running, and
every connection to it was refused.

The Rust port was chosen to survive because it had already run ahead:

| | C# | Rust |
|---|---|---|
| Tasks | 13 | 14 (`--software-updates`) |
| Independent audits | sequential | concurrent |
| Scheduled-task audit | keyword match per line | parses per-task records |
| Published size | ~42 MB self-contained | ~2.1 MB |
| Startup | JIT + runtime | immediate, no runtime |

The C# port's advantages — `RUN.bat` launched it, and Spectre.Console renders
more prettily than the hand-rolled `ui` module — did not justify a permanent
double cost on every future change.

## State at archival

Last commit before the archive built cleanly and passed **202 tests** on
.NET 10. It contains the remediation ledger, the native CsWin32 layer, the
README-aware Remote Desktop handling and the group-member parser fix — i.e. it
is behaviourally level with the Rust port at the point it was frozen, not a
stale snapshot from earlier.

## Building it anyway

Nothing here is wired into the repo's build. If you need to run it:

```bash
cd archive/csharp
dotnet build src/PinnacleCyPat.csproj -f net10.0-windows
dotnet test tests/PinnacleCyPat.Tests.csproj -f net10.0
```

`global.json` and `Directory.Build.props` moved with it, so the SDK pin and the
shared MSBuild properties still apply within this directory.
