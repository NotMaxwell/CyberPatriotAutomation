# Changelog — CyberPatriot Automation Tool (Rust port)

The version in `Cargo.toml` is stamped into the run log's header and file name,
so every log ties back to the build that produced it. Check a binary with:

```powershell
cyberpatriot-automation.exe --version
```

**Bump the version in `Cargo.toml` with every behavioural change and add an
entry here.** Patch for fixes, minor for new behaviour or tasks.

## 1.8.0

- **Fixed password changes and account creation, which failed for every
  account.** `net user` interactively confirms any password longer than 14
  characters, and these commands run with stdin closed — so the prompt reached
  EOF and `net` aborted. Every generated password is 37+ characters, so every
  password set and every `net user /add` failed. Account operations now use
  `Set-LocalUser`, `New-LocalUser` and `Add-LocalGroupMember`, which have no
  prompt and report a real reason on failure.
- **The primary auto-login account is no longer touched.** READMEs state plainly
  that changing its password may lock you out of the machine.
- **Administrators get generated strong passwords rather than the README's.**
  The README lists the passwords an audit *found*, not passwords to preserve;
  several are trivial ("root", "data") and were rejected outright by the
  complexity and length policy this tool enforces moments earlier, which
  guaranteed failure. Assigned passwords are printed and recorded in the run log
  — they are the only way back into the accounts.
- Passwords are now unique per account; the fixed list repeated once there were
  more accounts than entries.
- **winget is installed when missing.** Re-registration is tried first (cheap),
  then the App Installer package and its VCLibs dependency are fetched from
  Microsoft's permanent `aka.ms` redirects, so no version is pinned.
- **Independent audits run concurrently.** Shared folders, hosts file, DNS and
  scheduled tasks touch disjoint areas and now overlap instead of running one
  after another. Everything else stays sequential deliberately: user management
  and account permissions both rewrite accounts, and service management and
  security hardening both rewrite services, so concurrent writes would race.
  Each concurrent task's output is captured and replayed whole, so the
  transcript and log stay readable.
- **Fixed two operations that were being killed mid-flight.** The Defender scan
  and `wmic product` both ran under the default two-minute ceiling despite
  taking far longer, and were reported as failures when the timeout fired.

## 1.7.0

- **ANSI now renders from the first line.** A Windows console ignores escape
  sequences until a program sets `ENABLE_VIRTUAL_TERMINAL_PROCESSING`.
  `indicatif` did that, but only when it created its first progress bar — so
  anything printed before then (notably the README download message) appeared as
  raw `←[36m…` text. The flag is now set at startup, before any output.
- **A normal run displays the parsed README before executing.** The tasks are
  driven by that data — authorised users, critical services — so seeing it first
  is what makes a run reviewable. Previously it was only visible via
  `--parse-readme`, which exits without running anything.
- `--parse-readme` combined with task flags now says the tasks were not run.
  It previously ignored them silently, which read as the tasks having been
  skipped for some other reason.

## 1.6.0

- **The README is downloaded when it is hosted remotely.** A standard
  competition image does not ship the document at all:
  `C:\CyberPatriot\README.url` names an `https://` object (an S3 URL, unique per
  image and different every competition), which is what the competitor's browser
  opens. That address is read from the shortcut at run time — nothing about the
  host or path is baked into the tool — and fetched via `Invoke-WebRequest`,
  falling back to `curl`. Shelling out keeps TLS, the certificate store and any
  proxy configuration with the OS and adds no dependency to the cross-compiled
  binary.
- `--readme` also accepts an `https://` address directly, for when the shortcut
  is unreadable but the address is known.
- **A shortcut that cannot be followed is no longer parsed as HTML.** On failure
  the `.url` itself was handed to the parser, which produced a README with no
  title and no detectable OS — reporting "Unknown" for everything and hiding the
  real cause. The failure is now reported, with guidance to save the page
  locally and pass it with `--readme` if the image has no network access.

## 1.5.1

- Failed discovery now reports *why* a shortcut could not be followed, naming
  the target: "shortcut points to 'https://…', which is not a local file" versus
  "shortcut points to 'C:\…', which does not exist". Distinguishing those two is
  the difference between a fixable path problem and a document that is not on
  disk at all.

## 1.5.0

- **`.url` shortcuts are no longer discarded when they are not UTF-8.** Windows
  tools routinely write UTF-16 with a BOM; `read_to_string` rejects that
  outright, so `resolve_url_shortcut` returned `None` and discovery reported
  "no README found" with nothing to explain it. Files are now decoded by BOM
  (UTF-16 LE/BE, UTF-8 with or without BOM) and read lossily as a last resort.
- **Failed auto-discovery now lists every location it checked**, distinguishing
  "not found" from "exists but could not be resolved to a readable file" — the
  case that was previously invisible.

## 1.4.0

- **Fixed the "Operating System: Unknown" bug seen on a live competition VM.**
  README shortcuts chain — the desktop `.lnk` points at
  `C:\CyberPatriot\README.url`, which in turn names the HTML document.
  Resolution stopped after a single hop and handed the `.url` to the HTML
  parser; an INI file has no `<title>` and no "Windows 10", so both the title
  and the OS came back "Unknown". Shortcuts are now followed repeatedly (bounded
  at 5 hops, so a shortcut loop terminates).
- The resolved README path is now printed (`Using README: … (resolved from …)`),
  and auto-discovery finding nothing says so instead of failing silently. The
  original bug was invisible precisely because neither was reported.
- Added `--version` / `-V`.
- Run log header now records version *and* build date; the log file name
  includes the version.

## 1.3.0

- Support `.url` Internet Shortcuts in README discovery, and put
  `C:\CyberPatriot\README.url` — the canonical location on a standard image —
  first in the search order. Previously only `.lnk` and literal `.html` paths
  were considered, so discovery found nothing on a real image.
- `--readme` also resolves shortcuts, so pointing it at a `.url` or `.lnk` works.
- Fixed absolute POSIX targets being corrupted into relative paths when
  converting a `file:` URI.

## 1.2.0

- **New task: Software Updates** (`--software-updates`, also in `--all`).
  Inventories installed applications from the uninstall registry keys, compares
  against `winget upgrade`, and applies updates one package at a time.
  README-mandated software is updated first. Reports honestly when `winget` is
  absent (it does not ship with the LTSC images CyberPatriot uses) rather than
  claiming everything is current.
- **New: run log.** Everything attempted, queued and completed is written to
  `Desktop\CyberPatriot_RunLog_*.txt` at the end of execution, including table
  contents and a structured per-task outcome block. Override with `--log`.
- Added `command::execute_with_timeout`; the fixed two-minute ceiling would have
  killed package downloads mid-install.
- Fixed winget table parsing to slice by terminal display width rather than
  character count — CJK package names are double-width and drifted off the
  column boundaries.

## 1.1.0

Correctness fixes found while auditing the port against the C# original. Full
detail in `README.md` under "Deliberate divergences from the C# original".

- **Refuse to delete all users when README parsing yields nothing.** An empty
  authorised set meant every enabled non-system account was treated as
  unauthorised.
- **Exact local-group membership matching.** `is_user_admin` substring-searched
  the whole `net localgroup` output, so an account named `admin` matched the word
  "Administrators" in the header.
- **Do not disable built-in Windows scheduled tasks.** Keyword matching against
  every line of `schtasks` output flagged Microsoft tasks running `powershell`.
- **Do not delete the localhost hosts entry.** Exact-string comparison against a
  fixed-spacing constant classified a tab-separated entry as unauthorised.
- Handle "do not stop **or** disable the X service"; critical services can never
  also be queued for disabling.
- `--dry-run` is honoured by the account-permissions task, which previously
  disabled Guest and rewrote password-expiry flags regardless.
- Success is computed from the remediation outcome, not the pre-remediation
  state — four tasks reported failure precisely when they had done their job.
- Verification no longer samples: all services are checked, audit subcategories
  are checked individually, and registry values are compared rather than merely
  probed for existence.
- PowerShell invocation goes through `command::powershell` /
  `powershell_query`, so cmdlet failures surface with their message instead of a
  blank reason; interpolated values are quoted via `ps_quote`.
- Fixed OS detection through markup and `&nbsp;`, reading `<title>`/`<h1>` first.
- Fixed the `C:\Users\*\Desktop\README.html` wildcard, which never matched.

## 1.0.0

Initial Rust port of the C# tool: same CLI flags, task pipeline and console UI.
