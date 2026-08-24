# Changelog — PinnacleCyPat (Rust port)

The version in `Cargo.toml` is stamped into the run log's header and file name,
so every log ties back to the build that produced it. Check a binary with:

```powershell
pinnacle-cypat.exe --version
```

**Bump the version in `Cargo.toml` with every behavioural change and add an
entry here.** Patch for fixes, minor for new behaviour or tasks.

## 1.19.1

### Fixed

- **The Linux binary is now built against musl and runs on Ubuntu 22.04.**

  A glibc build links against whatever the *build* machine has. Built on a
  current distribution it required `GLIBC_2.39`; Ubuntu 22.04 - the image a
  round actually runs on - ships 2.35, so the binary refused to start, with an
  error naming a symbol version rather than the problem. Worse, the failure
  appeared on the competition image rather than at build time.

  glibc cannot be upgraded past what an Ubuntu release ships: `libc6` is pinned
  to the release, and forcing a newer one is a well-known way to break the
  system. So the fix has to be on the build side. musl links statically - no
  libc dependency at all, and the same binary runs on any Linux. It costs about
  200 KB.

- **`publish.sh` builds both platforms and refuses to ship a glibc-linked Linux
  binary.** It checks the artefact for glibc symbol versions and fails the build
  if it finds any, because that failure is otherwise invisible until the worst
  possible moment.

## 1.19.0

Linux brought to parity with Windows: fifteen tasks, and tables the same size.

### Added

- **Two tasks, taking Linux from thirteen to fifteen - the same count as
  Windows.**

  **File Permissions Audit (`--file-permissions`).** Windows hides its access
  control behind ACLs that nothing prints by default; Linux puts it in twelve
  bits per file, which makes it both easy to get wrong and easy to check. The
  one that matters most is `/etc/shadow`: at `0644` every user on the machine
  can read the password hashes and take them away to crack offline, and nothing
  about the system behaves differently - no error, no warning, no failed login.

  Sixteen scored file modes are corrected. World-writable files, unowned files,
  unexpected setuid binaries, `.rhosts`/`.netrc`/`.forward` in home directories,
  and a missing sticky bit on `/tmp` are **reported and not touched**: a
  world-writable file under `/opt` may be a vendor's installer doing something
  ugly but necessary, and breaking working software to score nothing is the
  worse trade.

  Corrections accept a *stricter* mode than the benchmark asks for. An image
  whose `/etc/shadow` is `0600` rather than `0640` is more locked down than CIS
  requires, and loosening it to match would be a downgrade dressed up as a fix.

  **Shared Folders Audit (`--shared-folders`).** The counterpart of the Windows
  share audit, and a harder problem: Windows has three default shares and
  anything else is a finding, while a stock Linux image exports nothing at all,
  so every share is something somebody configured. `smb.conf` and `/etc/exports`
  are both read and their options graded - `no_root_squash` lets a client's root
  write as root here, `guest ok = yes` needs no credential. Nothing is removed,
  because a share may be exactly what the round requires.

- **Kernel module blocking.** Fourteen unused filesystem drivers and network
  protocols, written to `/etc/modprobe.d/99-pinnacle.conf` with both `install
  ... /bin/false` and `blacklist`: the second alone only stops *automatic*
  loading and is bypassed by an explicit `modprobe`.

  `vfat` is deliberately absent, as it is from CIS. A UEFI machine mounts
  `/boot/efi` as vfat, and blocking the module there stops the image booting.
  "Unused filesystem" has to mean unused, not merely unfamiliar.

- **Login banners.** `/etc/issue`, `/etc/issue.net` and `/etc/motd` are replaced
  with a legal notice containing no escapes. Ubuntu's stock `/etc/issue` is
  `Ubuntu 22.04 LTS \n \l`, which prints the distribution and kernel version
  *before* anyone has authenticated - which is what a scored check looks for the
  absence of.

### Changed

- **The tables now match the Windows ones in size**, and in several places
  exceed them:

  | Table | Was | Now | Windows |
  |---|--:|--:|--:|
  | Hardening settings | 37 | **72** | 42 |
  | Prohibited services | 28 | **58** | 55 |
  | Audit rules | 13 | **34** | 9 categories |
  | Kernel modules blocked | - | **14** | n/a |
  | Scored file modes | - | **16** | n/a |

  The additions are the CIS Ubuntu 22.04 benchmark's: strong SSH crypto
  (dropping CBC, arcfour, MD5 and the SHA-1 key exchanges), `ptrace_scope`,
  `kptr_restrict`, `perf_event_paranoid`, unprivileged BPF, IPv6 router
  advertisements, `protected_fifos` and `protected_regular`, and the
  `login.defs` retry and timeout limits.

- **`auditd` is configured, not just started.** The defaults quietly discard the
  oldest records; `keep_logs` keeps the history, which is the part of an
  incident worth having.

  CIS asks for `admin_space_left_action = halt`. That is right for a server with
  an administrator watching and **wrong** for a competition image: a disk that
  fills mid-round would power the machine off and end the round with whatever
  score it had. `single` is loud, recoverable, and does not stop the scoring
  engine reporting. A test pins that.

- **The firewall configures loopback explicitly and turns on logging.** A
  default-deny policy without an explicit loopback allow breaks every service
  that talks to itself over `127.0.0.1`, which on a desktop image includes the
  display manager and the resolver. Traffic claiming to come *from* loopback but
  arriving on a real interface is spoofed and is denied.

### Fixed

- **The setuid baseline matched full paths, and so reported twenty-one
  legitimate binaries** the first time it ran on a machine that was not Ubuntu.
  `unix_chkpwd` is in `/usr/sbin` on Debian and `/usr/bin` on Arch;
  `ssh-keysign` is under `/usr/lib/openssh` on one and `/usr/lib/ssh` on the
  other. This is the same mistake as matching `nologin` by path, found the same
  way - by running it.

  Now matched by file **name**, plus a requirement that the path be under a
  system directory. The name alone would excuse a planted `/home/alice/sudo`,
  which is exactly what the task exists to find.

- **The permissions scan made three full traversals of `/usr`**, which took long
  enough to look like a hang with four tasks still to go. One pass with tagged
  output now costs what a single check used to, and it is bounded by an explicit
  timeout.

- **The `find` expressions were backslash-escaped as they would be at a shell
  prompt.** No shell is involved, so every one of them failed.

## 1.18.0

`--directives`: what this round does differently.

### Added

- **`crates/core/src/directives.rs` and the `--directives` flag.** Most of a
  hardening run is the same every round, and the tasks handle that part. What
  loses points is the other part: the sentence in paragraph four saying this
  machine is administered over SSH, or that Firefox must come from a PPA rather
  than a snap, or that the display manager must stay as it is. A generic script
  does the standard thing and quietly gets those wrong.

  The parser already extracted what the tool could *act* on. Everything it could
  not act on vanished silently - which is precisely the material a competitor
  most needs and most often misses.

  Each recognised instruction is sorted into one of three groups:

  | Group | Meaning |
  |---|---|
  | `AUTOMATED` | a task acts on it, and the entry names which task and how |
  | `NOT TOUCHED` | the tool has no code that would violate it |
  | `BY HAND` | a person has to do it, and the entry says what |

  The `BY HAND` group is the point. On the Ubuntu 22.04 Exhibition Round it
  contains five items, including the one this module was written for: *Firefox
  must remain installed using the official Mozilla PPA, and NOT as a SNAP
  package*. `apt install firefox` on 22.04 installs a transitional package that
  pulls the snap, so a tool reporting "installed Firefox" would satisfy nothing
  and the competitor would never know.

  `NOT TOUCHED` exists because *"we do not do that"* is only reassuring when it
  is written down and checkable. *Do not change the time zone* is a promise this
  tool can keep only because it has no code that would.

  The report runs on `--directives` as a read-only summary, on `--parse-readme`
  alongside the parsed data, and automatically at the start of every real run -
  after the README is displayed and **before** any task executes, because the
  by-hand list is no use at the end. Every directive is recorded in the
  remediation ledger, with the by-hand ones marked non-compliant: they are
  outstanding work, and a ledger that marked them done would be lying about the
  state of the machine.

### Notes on the implementation

- **Sentences are split on punctuation only, never on a line break.** READMEs
  wrap prose mid-sentence - the Ubuntu one breaks *Please add the / user
  "candace"* across two lines - so treating a newline as a boundary would cut
  exactly the sentences worth matching in half. A test pins it.

- **Excerpts are centred on the phrase that matched**, not taken from the start
  of the sentence. The `<pre>` block of usernames has no punctuation, so it
  merges with the guideline after it, and the instruction about the primary
  user's password was being shown as twenty-four usernames and an ellipsis.

- **One directive per sentence.** Two patterns can describe the same
  instruction from different angles - the PPA requirement and the "not a snap"
  requirement are one sentence - and printing it twice makes a short report look
  padded.

- **The patterns are deliberately conservative.** One that fires on prose it
  does not understand produces a confident, wrong classification, which is read
  and believed - worse than the sentence going unmentioned. A README with no
  such prose produces an empty report, and a test asserts that.

## 1.17.0

The Ubuntu 22.04 Exhibition Round answer key, as a test suite - and the four
bugs it found.

### Added

- **`crates/linux/tests/answer_key.rs`.** CyberPatriot publishes an answer key
  for its Exhibition Rounds: every scored item, what it is worth, and how it was
  meant to be solved. That document is the closest thing this project has to a
  specification, and nothing connected it to the code.

  All sixteen scored items and four penalties are now tests, each named after
  its item and carrying its point value, so a failure says exactly what it would
  have cost. They are written against the *decisions* the tool makes from the
  parsed README - which accounts it counts as unauthorised, which services it
  refuses to mask, which packages it purges - because that is the layer where
  the bugs are.

  84 of the 100 points are automatable; the remaining 16 are the two forensics
  questions, which need a person to read a file and answer a question. A test
  asserts that split, so it cannot quietly stop being true.

- **The round's README is now a corpus fixture**
  (`06-ubuntu-22-exhibition-round.html`), so the parser's output for a real
  Ubuntu README is snapshotted alongside the Windows ones.

- **Daily update checks.** `APT::Periodic::Update-Package-Lists "1"` and the
  three settings around it, written to `/etc/apt/apt.conf.d/20auto-upgrades`.
  This is what the Software & Updates dialog sets, and it is worth six points.
  The task previously installed `unattended-upgrades` and stopped - which leaves
  the machine exactly as unpatched as before, and reports success.

  `file_ops` gained a `Style::AptConf` for it: the value is quoted and the line
  ends in a semicolon, and apt rejects the whole file if either is missing,
  which disables *all* automatic updating rather than just the setting being
  written.

- **Weak-password detection**, wired into user management. A README publishes
  its administrators' passwords and CyberPatriot scores noticing that one of
  them is bad.

  The round's own password set calibrates the rule, and says the discriminator
  is character classes rather than length: `grilledcheese` (scored as weak) and
  `Go0glyMo0gly!` (accepted) are both thirteen characters. A length rule that
  caught the first would have caught the second, and resetting a password the
  README published as valid locks the competitor out of an account they were
  told they could use - a worse outcome than the six points. The primary
  auto-login user is excluded outright, because the README says so in as many
  words.

### Fixed

Four items, worth 20 points between them, that reading the code had not found:

- **Quoted names were dropped from group requirements (8 pts).**
  `extract_group_members` trimmed commas and periods but not quotes, so
  `"candace"` failed username validation, the member list came back empty, and
  an empty list is discarded. Curly quotes are handled too - a README pasted out
  of a word processor has them, and they are the harder case to spot by eye.

- **The user-first group phrasing matched nothing (same 8 pts).** The parser
  handled *make a group called X and add a, b*, but not *add the user "candace"
  to the "firesidegirls" group*, which was the only group requirement in this
  document.

  The new pattern has an ambiguity Rust's regex crate cannot express away, since
  it has no lookahead: in *add the users a, b into the group*, the optional
  `the` can be skipped and `the` itself captured as the group name. The corpus
  caught exactly that - a fixture that had parsed correctly for months grew a
  second, bogus requirement named `the` - and connectives are now rejected as
  group names.

- **Only the first program in a sentence was extracted (-5 penalty).**
  `latest version of X` captured one name, and the README said *the latest
  stable version of Thunderbird and Perl*. Perl was silently lost, and removing
  required software is a penalty. The pattern now captures a conjunction list,
  anchored on the name shape so it stops at `Perl` rather than running on
  through the rest of the sentence.

- **`perl` was not in the Linux package table**, so even once extracted it
  resolved to nothing. Added, along with the other scripting runtimes a README
  is likely to name.

### Changed

- **The Linux task modules are public**, so the answer-key suite can reach the
  functions that make the decisions. Testing those through `execute()` would
  mean running against a real image.

## 1.16.0

Linux support, and the restructure that made it possible.

### Added

- **A Linux platform: thirteen tasks.** Password Policy (`pam_pwquality`,
  `faillock`), Account Permissions, User Management, Service Management
  (systemd), Audit Policy (`auditd` and `rsyslog`), Firewall (`ufw`), Security
  Hardening (36 settings across `sysctl.d`, `sshd_config.d` and `login.defs`),
  Prohibited Media, Software Updates and Software Management (`apt`), and the
  Hosts File, DNS Settings and Scheduled Tasks audits.

  The flags and short flags match the Windows ones wherever the concept exists,
  so a run log from a Linux round reads next to a Windows one. Group Policy has
  no Linux analogue and deliberately has no task - a stub that reported success
  would be worse than its absence, and a test asserts the row is not there.

- **`file_ops` - proved writes to `/etc`, the counterpart of `registry_ops`.**
  Two details make hand-editing these files unreliable, and both are handled in
  one place:

  - **Duplicate definitions mean opposite things depending on the file.** `sshd`
    obeys the *first* value for a keyword; `sysctl` applies them in order so the
    *last* wins. A tool that appends its setting to the end is therefore correct
    for one and silently wrong for the other. A write replaces the first active
    definition and comments out every later one, leaving exactly one - after
    which both rules agree.
  - **Writes are atomic**: a temporary file in the same directory, renamed over
    the original, with the original's mode preserved. The naive path leaves a
    zero-length `/etc/shadow` or `sshd_config` if interrupted, which locks the
    machine out of the very thing being hardened. The pre-change contents are
    kept once per file as `<path>.pinnacle.bak`.

  SSH and sysctl settings go to drop-in files rather than the main config.
  Ubuntu 22.04+ puts `Include /etc/ssh/sshd_config.d/*.conf` as the first line
  of `sshd_config` and sshd obeys the first definition it sees, so editing the
  main file is overridden by any drop-in already present - the run looks applied
  and changes nothing.

- **`systemd_ops`, `user_ops` and `apt`** - the counterparts of `service_ops`,
  `account_ops` and `chocolatey`. Three notes:

  - Disabling a unit is stop, disable **and mask**. Disable alone is not enough:
    socket activation and a `Wants=` from another unit both restart it, and the
    audit that follows would then find it running with no explanation.
  - Account *reads* go straight to `/etc/passwd` and `/etc/group`. Unlike
    Windows, where localised `net` output forced the move to netapi32, these are
    POSIX-fixed colon records with no locale near them. Writes still go through
    `useradd`/`usermod`/`gpasswd`, which take the lock and keep `/etc/shadow` in
    step.
  - `apt` runs with `DEBIAN_FRONTEND=noninteractive` (or it opens a full-screen
    dialog and hangs until the timeout) and `--force-confold` (or an upgrade
    silently reverts the hardening applied earlier in the same run). It purges
    rather than removes, so a package's configuration and unit file go too.

- **Two orderings that end a round if reversed**, both now enforced:

  - The firewall opens ports **before** enabling `ufw`. Enabling a default-deny
    firewall with no allow rule drops the SSH session the run is happening over,
    and no further command reaches the machine. Port 22 is opened whether or not
    the README mentions SSH, and the task refuses to enable the firewall at all
    if no allow rule landed.
  - Service protection runs **before** anything is masked. The prohibited list
    and the README's critical list overlap by design - a round may require Apache
    or Samba - and resolving that afterwards leaves a window where a scored check
    sees the service down.

### Changed

- **`rust/` is now a Cargo workspace of four crates**: `pinnacle-core` (the
  OS-agnostic half), `pinnacle-windows`, `pinnacle-linux`, and `pinnacle-cypat`
  (the binary). The platform crates are `cfg`-gated dependencies, so a Windows
  build never compiles the Linux tasks and a Linux build never compiles the
  Win32 bindings.

  A workspace rather than `#[cfg]` branches inside one crate, deliberately: two
  implementations kept in one place drift silently, which is precisely how the
  C# port came to disagree with the Rust one about Remote Desktop. Two crates
  cannot pretend to be one.

  No task behaviour changed. The corpus snapshots are byte-identical and all 182
  pre-existing tests still pass.

- **A task is now described in one place.** `TaskSpec` carries the flag, the
  short flag, the `--help` line, the menu label and detail, whether it needs a
  README, whether it may run concurrently, and how to construct the task.
  `main.rs` and `tui.rs` name no operating system - they read `Host::tasks()`.

  This closed a wart that had been recorded in `CLAUDE.md` since the menu was
  added: a flag table in `main.rs`, a registration block a few hundred lines
  below it, and a menu table in `tui.rs` were three places for one fact, free to
  disagree. A task could reach the CLI without reaching the menu, making it
  invisible to anyone who double-clicks `RUN.bat` - which is most users. Two
  tests now pin it (`every_platform_task_is_accepted_by_the_validator`,
  `no_task_flag_shadows_a_global_one`).

- **`readme_services` takes its name table as a parameter.** The matching logic
  is identical on both platforms; only the table differs. Each platform crate
  wraps it with its own, so the existing `is_remote_desktop_required` API is
  unchanged for the Windows tasks.

- **The privilege check moved onto the platform seam.** `Platform::is_privileged`
  is a machine-policy write probe on Windows and the effective uid on Linux, and
  `PRIVILEGED_ROLE` / `ELEVATION_HINT` supply the wording - telling a Linux user
  to right-click an executable is worse than saying nothing.

- **`command::execute_for_exit_code_with_env`**, for child processes that decide
  whether to prompt from the environment rather than from a switch. The
  variables are deliberately not written to the run log: they are process
  configuration, and one of them will eventually hold something that should not
  be recorded.

### Fixed

- **`nologin` was matched by full path, not by file name.** Debian and Ubuntu
  ship `/usr/sbin/nologin`; Arch and Fedora `/usr/bin/nologin`. The account
  audit reported *every* system account on the wrong distribution as able to log
  in - fourteen false positives in a single run, which is exactly how a reader
  learns to ignore a finding. Found by running the audit, not by reading it.

### Documentation

- `docs/ARCHITECTURE.md` gains §3.1 (the workspace and the platform seam) and
  §3.2 (Linux: what carried over unchanged, what is reported rather than fixed,
  and where the platforms differ in substance rather than mechanism).
- `docs/CONTRIBUTING.md`'s licence section no longer says forking and
  redistribution are prohibited. That text predated the return to Apache 2.0 and
  contradicted the licence it linked to.

## 1.15.2

### Changed

- **Migrated to the Rust 2024 edition.** `cargo fix --edition` had nothing to
  rewrite - the code was already compatible - and the corpus snapshots are
  byte-identical afterwards, so parser behaviour is unchanged. The toolchain was
  already current (1.98.0); the edition was the part left behind.

- **Nested `if let` collapsed into let-chains**, which the 2024 edition
  stabilises. 27 nested `if` statements across 23 files, in the parser, the
  tasks and the native layer. The line count barely moves - the win is depth,
  not length. The parser's actionable-item classification went from four levels
  of nesting to a flat condition:

  ```rust
  if contains_user_creation_pattern(&lower)
      && let Some(item) = parse_user_creation_item(&paragraph_text)
      && !is_duplicate_action_item(data, &item)
  {
  ```

  Three of those sites are `#[cfg(windows)]` and needed the migration run
  against the Windows target as well - a Linux `cargo fix` never compiles them.

  No `unsafe_op_in_unsafe_fn` breakage, which 2024 makes deny-by-default: the
  native layer already used explicit `unsafe` blocks rather than relying on the
  enclosing `unsafe fn`.

## 1.15.1

### Changed

- **Back to the Apache License 2.0.** The proprietary licence adopted on
  2026-08-22 is withdrawn; every release before and since is Apache-2.0.

  `LICENSE` is now byte-identical to the canonical text from apache.org. The
  copy that had been in this repository before the proprietary switch was not:
  it read "submitted to the Licensor" where upstream reads "submitted to
  Licensor". A reworded licence is a different licence, and it stops automated
  scanners recognising it.

  `NOTICE` carries the copyright, the trademark disclaimer and the third-party
  attributions. Source headers now carry `SPDX-License-Identifier: Apache-2.0`
  in place of "All Rights Reserved", and `Cargo.toml` declares
  `license = "Apache-2.0"`. `publish = false` stays, now as a choice rather than
  a restriction: this is an application, and nothing here is worth depending on.

## 1.15.0

### Changed

- **This is now the only implementation.** The C# port is frozen under
  `archive/csharp/`, where it still builds and passes its 202 tests but is not
  shipped or kept in step. Keeping two implementations at parity meant every
  behavioural change landed twice, in two languages, and drift was silent - it
  surfaced only when someone read both files side by side. `RUN.bat`, `RUN.ps1`
  and the scripts now build and launch this crate.
- **HTML is parsed with `scraper` (html5ever), not regex.** Structure - the
  title, the `<h2>` sections, the paragraphs, the list items, where one line
  ends - moves to the new `html` module; prose stays regex, because there is no
  parser for how a person writes English.

  `<[^>]+>` does not know that `<b>` inside `Windows <b>10</b>` is not a word
  boundary, that `&nbsp;` is a space, that an unclosed `<p>` ends at the next
  one, or that an unclosed `<li>` still ends where the next begins. Every one of
  those is ordinary in hand-written HTML. Output on the real training-round
  README is byte-identical; malformed markup is where the difference shows.

  Costs ~470 KB in the shipped binary (2.16 -> 2.71 MB), which is a deliberate
  trade against a release profile tuned to save 900 KB.
- **The knowledge tables live in one module** (`knowledge`): the 42 hardening
  registry settings, the features to disable, the README service-name map, the
  Chocolatey package ids, the default prohibitions, the Remote Desktop skip
  list. They are tested as tables - duplicate keys, contradictory mappings,
  malformed paths, values that do not parse.
- The `wmic product` inventory fallback is gone. It was deprecated and absent on
  current Windows 11 images, blind to everything not installed by MSI, minutes
  slow because enumerating `Win32_Product` reconfigures every installed product,
  and it yielded no uninstall string - so a program it did find could not then
  be removed. A partial MSI-only list also looks like a successful read, so
  verification would pass judgement on an inventory missing most of the machine.

### Added

- **A README corpus with snapshot tests** (`tests/corpus/`, `insta`). Every
  fixture is parsed and the whole result snapshotted, so a parser change that
  alters any document shows as a reviewable diff instead of silence. Five
  fixtures seeded: the real training-round README, a `<br>`-separated user list,
  both phrasings of the group sentence, malformed markup, and software named in
  prose. Adding a real README is the highest-value contribution to the parser.
- `scripts/check.sh` and `check.ps1` - fmt, clippy, tests and the Windows
  type-check, in the order that fails fastest - and `scripts/publish.sh`.

### Fixed

- **The service-name table had drifted.** It was written out twice, and the copy
  inside service management was missing `"Remote Desktop Service"` and
  `"Terminal Services"`, so a README using either spelling was understood by
  security hardening and group policy but *not* by the task responsible for
  keeping the service running. The feature list had drifted the same way, by two
  entries. Both now have one definition.
- **`choco upgrade all` could upgrade software the run had just removed.** The
  guard excluded prohibited software by resolving it to a package id, and
  CCleaner and Jellyfin had no id - so the exclusion list came back empty and
  the guard passed. It now asks the post-removal inventory whether anything
  prohibited survived, rather than trusting the package table to be complete;
  the missing ids were added as well.
- **`Notepad++` parsed as `Notepad`** - and `7-Zip` as `7`. The software-name
  pattern was `[A-Za-z0-9]+`, and a truncated name resolves to the wrong
  Chocolatey package or to none at all. Found by the corpus on its first run.
- **An unclosed `<h2>` swallowed its whole section.** HTML5 nests the following
  paragraphs inside the heading, so the heading came out as the entire section
  and the scenario came out empty. Also found by the corpus on its first run.
- `cargo fmt --check` now passes and gates the build; it had never been enforced.

## 1.14.0

### Added

- **Remediation ledger.** Every change now records what it wanted, what it did,
  and the read-back that proves it. `remediation::apply` reads the state before
  acting, skips the write when the machine is already right, performs the
  change, then reads the state again — and that second read is what lands in the
  log as `Proof`. The run log gains a `REMEDIATION LEDGER` section grouped by
  task, and the console gains a `Changes and Proof` summary that names anything
  it could not confirm.
- Five outcomes replace the old pass/fail: `FIXED`, `ALREADY OK`, `FAILED`,
  `UNVERIFIED` (the write reported success and the machine disagrees, or could
  not be read back) and `SKIPPED`. `UNVERIFIED` is the case the ledger exists
  for — it was previously indistinguishable from success.
- `registry_ops`, `service_ops`, `account_ops` and `policy_ops` route every
  write through the ledger, so coverage does not depend on each task
  remembering to log. The shared-folder, scheduled-task and hosts-file changes,
  which write outside those modules, are wired individually.
- Fixes are attributed with a `tokio` task-local rather than a global, so the
  independent audits that run concurrently are grouped under the task that
  actually made each change.
- **Chocolatey support** (`chocolatey`), ported from the C# `Chocolatey`
  utility. Required software the README names is now installed rather than
  reported as needing a manual install, and installed software is upgraded by
  package name. Chocolatey is bootstrapped when absent and resolved by absolute
  path as well as by name, because a running process keeps the environment block
  it started with and would not see the freshly installed `choco` on PATH.

### Changed

- The 42 hardening registry settings go through `registry_ops` instead of
  shelling out to `reg add`, so they use the Windows API where available and
  each one is proved. A non-DWORD entry added to the table now fails loudly
  rather than being written as a number.
- `SecurityHardeningTask` read the registry with `output.contains("0x1")`, which
  also matched `0x10` and `0x1a`, so a setting could read as correct whatever it
  held. It now compares the value exactly through `registry_ops::dword_equals`.
- The `net accounts` parser moved onto `PasswordPolicyInfo`, so the task and the
  ledger's evidence read the output through one parser rather than two that
  could disagree.
- Registry-write failures in the hardening task are recorded in the task's
  issues; they were counted for the on-screen tally but never surfaced.
- Software management verifies against the uninstall registry rather than a
  second `wmic product` call, and an inventory that cannot be read now fails
  verification instead of passing on an empty list.
- Prohibited software is excluded from the update candidates. `choco upgrade`
  *installs* a package that is absent, and the candidate list is built from the
  inventory read before removal — so a run that removed Python put a newer
  Python back four minutes later.

### Fixed

- **Security hardening ignored the README**, denying Remote Desktop even on an
  image whose scenario requires it — while service management protected
  `TermService` in the same run, leaving the service running with every
  connection refused. Group policy then verified `fDenyTSConnections=1`
  unconditionally, reporting a failure for having done the right thing.
- **Group members were parsed out of the surrounding prose.** "add the users a,
  b and c into the group" yielded `users` and `group` as members, and the run
  issued `net localgroup allsafe "group" /add`.
- 219 status glyphs across both ports rendered as a literal `?` — `✓`, `✗` and
  `⚠` had been flattened by an encoding round-trip. Since the run log mirrors
  console output, these were in the log too.

## 1.13.0

### Fixed

- **Prohibited software was not being removed** - CCleaner, Python and Jellyfin
  Media Player all survived a run. Four separate causes:

  - `wmic product call uninstall` reads `Win32_Product`, which lists **only
    MSI-installed** software. All three of those ship NSIS installers, so they
    were never in it. Worse, `wmic` exits **0** when its `where` clause matches
    nothing, so the run reported "Removed: CCleaner" while CCleaner sat
    untouched. Removal now runs the uninstaller the program actually registered,
    made unattended per installer family (NSIS `/S`, Inno `/VERYSILENT`, MSI
    rewritten to `/x {code} /qn`, Python's bundle `/quiet`). `wmic` is gone from
    the removal path entirely.
  - The uninstall registry reader did not read `UninstallString` at all, so
    there was nothing to run even had the caller wanted to. It now reads it,
    preferring `QuietUninstallString` where the publisher provides one.
  - The default prohibitions (Python, CCleaner, Jellyfin) were applied only
    inside `set_readme_data`, which the caller invokes only when a README
    parsed. A run without one left the prohibited list **empty** and removed
    nothing. They are seeded in the constructor now, so they survive the README
    being absent - which is the whole point of a default.
  - The inventory came from `wmic product get name` unconditionally, ignoring
    the native uninstall-registry reader. On a current Windows 11 image, where
    `wmic` is no longer present, the task failed before it started.

- **Removals are verified against a fresh inventory** rather than trusting exit
  codes, so software that reports removal but is still installed is reported as
  a failure instead of a success.

- Matching between Windows display names and package ids is no longer exact.
  Real names carry version, bitness and locale suffixes - `Notepad++ (64-bit
  x64)`, `Mozilla Firefox (x64 en-US)` - and an exact lookup matched almost
  nothing.

### Added

- **Diagnostics in the run log.** Every external command is recorded with its
  arguments, exit code and elapsed time, and on failure the first 600 characters
  of stderr and stdout. The software task additionally records what it matched,
  which mechanism it chose, and what survived removal.

  This is what a failure investigation needs and did not have: the console said
  `✗ Failed to remove: CCleaner ()` - with an empty reason, because the tool
  reported failure only through an exit code - and there was nothing else to go
  on. Diagnostics go to the log only, never the console.

  Passwords interpolated into `ConvertTo-SecureString` are redacted from the
  command echo. The log still records each generated password once where the
  task announces it; that is a considered disclosure in one place, not a reason
  to scatter it through every command line.

## 1.12.0

### Added

- **An interactive menu** (`--tui`, `-i`). It asks which README to use, which
  tasks to run and whether to preview or apply, then shows a summary and waits
  for an explicit yes. It also opens on a bare launch at a real terminal - which
  is what double-clicking the executable does - so that case is useful again
  rather than merely safe. The confirmation defaults to *no* for a run that
  applies changes and *yes* for a preview, so pressing enter without reading is
  always the harmless choice.

  It builds a command line and hands it to the normal run pipeline rather than
  driving tasks itself: the pipeline holds every ordering guarantee the run
  depends on, and a second copy of that logic would be free to drift. It also
  means the log's `Command:` line records exactly what a menu-driven run did.

- Flags for the five tasks that previously ran only under `--all`:
  `--software-management`, `--shared-folders`, `--hosts-file`, `--dns-settings`
  and `--scheduled-tasks`. Without them the menu could not offer those tasks
  individually. The independent audits still run concurrently when selected.

- `native::registry::can_write_machine_policy`, the elevation check behind the
  menu's "not running as Administrator" warning. It asks whether this process can
  write machine policy - the question that actually matters - rather than
  inspecting the token for Administrators membership, which is true for an
  unelevated member of the group whose every write will still be refused. The key
  is opened, never written, and closed immediately.

### Changed

- **Renamed to PinnacleCyPat.** The crate is `pinnacle-cypat`, the binary is
  `pinnacle-cypat`, the library is `pinnacle_cypat`, and the run log is
  `PinnacleCyPat_RunLog_v<version>_<timestamp>.txt`. References to *CyberPatriot*
  the competition are unchanged - the competition is not the tool.

- **The licence is now proprietary** (see `../LICENSE`); `publish = false` stops
  `cargo publish` from uploading a crate whose licence forbids redistribution.
  Releases before 2026-08-22 remain under Apache-2.0 for copies already
  distributed under it.

  > Reverted in 1.15.1 - the project is Apache-2.0 again, and always was either
  > side of this one-day window.

- The help text no longer claims that every task runs when none is named. That
  stopped being true when a bare invocation was made safe, and the line had not
  caught up.

## 1.11.0

### Added

- `-h`, `--help`, `-?` and `/?` print the flag table and exit. Security hardening
  moved from `-h` to `-H`; `--security-hardening` is unchanged.
- Microsoft network client **and** server: digitally sign communications
  (always). Scored on the CP19 exhibition answer key and previously unhandled.
  Both sides are set, since signing one leaves the other able to negotiate an
  unsigned session.
- Remote desktop sharing is turned off, via `fDenyTSConnections` and its policy
  key. Also scored and previously unhandled; the policy key overrides the local
  one, so setting only the local value leaves RDP listening.
- Python, CCleaner and Jellyfin Media Player are prohibited by default, unless
  the README explicitly requires them.

### Changed

- **Running every task now requires `--all`.** A bare invocation prints the help
  and changes nothing. It used to mean "run every task", so double-clicking the
  executable began a full destructive run against the machine.
- An unrecognised argument is rejected with exit code 2 instead of being
  ignored. Combined with the above, a typo - or `--help`, which was not a flag -
  used to start that same destructive run.
- Service control goes through the service control manager rather than `sc.exe`,
  `net start` and `Stop-Service`; dependents are enumerated and stopped
  explicitly, so nothing prompts.
- Registry access goes through the Windows API rather than `reg.exe`, and asks
  for the 64-bit view explicitly so a value is not silently redirected to
  `Wow6432Node`.

### Fixed

- `net share <name> /delete` now passes `/y`. It asks "force them closed? (Y/N)"
  when the share has open files, and aborted having deleted nothing.
- `command::execute_for_exit_code` reports the real exit code, so callers can
  tell a timeout from a failure.

## 1.10.0

### Changed

- Windows work now goes through Microsoft's official **`windows` crate** instead
  of parsing the console output of `net`, `auditpol` and `netsh`. The new
  `src/native` module mirrors the C# port's `Core/Native`, which is generated by
  CsWin32: the same four areas, the same fallbacks, and the same split between a
  native path and a shell-out path. Call sites select between them with
  `#[cfg(windows)]`, matching the C# `#if WINDOWS`.
  - `native::accounts` - local group membership and password/lockout policy from
    netapi32, replacing `net localgroup` and `net accounts`.
  - `native::audit_policy` - audit categories addressed by their fixed
    `ntsecapi.h` GUIDs, replacing `auditpol.exe`. Includes enabling
    `SeSecurityPrivilege`, which `AuditSetSystemPolicy` requires and which an
    elevated token carries *disabled*.
  - `native::firewall` - the `INetFwPolicy2` COM object, replacing
    `Set-NetFirewallProfile`.
  - `native::installed_software` - the uninstall registry keys, replacing a
    PowerShell query and its CSV round-trip.
- `windows-sys` is replaced by `windows`, so there is a single binding crate and
  one place to add an API. The console virtual-terminal setup in `ui` moved
  across with it.

### Why

The command-line tools print localised, human-formatted tables. A parser written
against the English output returns nothing on a non-English image, and "nothing"
reads to the caller as "the group is empty" or "the policy is already compliant"
rather than as a failure - so the tool reported success having done nothing.
These APIs return structured data and a status code, so that confusion cannot
arise.

## 1.9.0

### Changed

- Software updates now use **Chocolatey** instead of winget, for both querying
  and applying updates. Chocolatey installs from a script on any supported
  Windows, including the LTSC images CyberPatriot uses, where winget's "App
  Installer" package is absent and awkward to add. If Chocolatey is missing it is
  bootstrapped from the official install script rather than leaving the update
  check unavailable.
- Removed the fixed-width table parser written against `winget upgrade`. Its
  replacement reads `choco outdated --limit-output`, which prints one
  pipe-delimited record per package, so locating columns by header offset and
  measuring text by terminal display width are no longer needed. This drops the
  `unicode-width` dependency.
- `command::execute_for_exit_code` reports a process's exit code rather than only
  success. Chocolatey returns 3010 and 1641 for "succeeded, reboot pending";
  treating those as failure would report a completed install as failed.

### Fixed

- Chocolatey is resolved by absolute path as well as by name. The bootstrap adds
  it to the machine PATH, but an already-running process keeps the environment it
  started with, so a freshly installed `choco` was otherwise unusable until the
  tool restarted.

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
- **`--dry-run` no longer installs the package manager.** The winget install ran
  from `read_system_state`, before `execute` reached its dry-run check, so a
  "changes nothing" run could install software. Detection now happens in the
  read phase and installation only in `execute`, never under `--dry-run`.
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
  `Desktop\PinnacleCyPat_RunLog_*.txt` at the end of execution, including table
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
