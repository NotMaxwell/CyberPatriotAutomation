# PinnacleCyPat — Reference

Copyright (c) 2026 Maxwell McCormick. All Rights Reserved. See [LICENSE](../LICENSE).

This is the long-form reference: what every task does, why it exists, and how it
does it; then every utility, and how the pieces fit together. [README.md](../README.md)
is the short version — start there if you only want to run the thing.

---

## Contents

- [1. What the tool is](#1-what-the-tool-is)
- [2. Run pipeline](#2-run-pipeline)
- [3. The two ports](#3-the-two-ports)
- [4. Tasks](#4-tasks)
  - [4.1 Password Policy](#41-password-policy)
  - [4.2 Account Permissions](#42-account-permissions)
  - [4.3 User Management](#43-user-management)
  - [4.4 Service Management](#44-service-management)
  - [4.5 Audit Policy](#45-audit-policy)
  - [4.6 Firewall Configuration](#46-firewall-configuration)
  - [4.7 Security Hardening](#47-security-hardening)
  - [4.8 Prohibited Media](#48-prohibited-media)
  - [4.9 Software Management](#49-software-management)
  - [4.10 Software Updates (Rust only)](#410-software-updates-rust-only)
  - [4.11 Shared Folders Audit](#411-shared-folders-audit)
  - [4.12 Hosts File Audit](#412-hosts-file-audit)
  - [4.13 DNS Settings Audit](#413-dns-settings-audit)
  - [4.14 Suspicious Scheduled Tasks Audit](#414-suspicious-scheduled-tasks-audit)
  - [4.15 Group Policy](#415-group-policy)
- [5. Utilities](#5-utilities)
- [6. Native layer](#6-native-layer)
- [7. Models](#7-models)
- [8. The interactive menu](#8-the-interactive-menu)
- [9. Reporting and the run log](#9-reporting-and-the-run-log)
- [10. Safety design](#10-safety-design)
- [11. Build, test, publish](#11-build-test-publish)

---

## 1. What the tool is

A CyberPatriot round hands you a Windows image and a README. The README names the
authorised users, which of them are administrators, which services must stay
running, and what software is required. Scoring is automated: an agent on the
image checks a fixed list of conditions and awards points as you satisfy them.

Most of that list is the same every round — the Guest account should be off, SMB1
should be gone, the firewall should be on, audit policy should log both success
and failure. That part is mechanical, and doing it by hand costs most of the
clock. PinnacleCyPat does the mechanical part, driven by the round's own README
for the parts that vary, and leaves the competitor with the forensics questions
and the judgement calls.

**It is not a scoring engine and it does not talk to one.** It reads the README,
changes the machine, and reports what it changed.

---

## 2. Run pipeline

Every run is the same five phases.

```
  argv  ──▶  ①  Parse and validate flags
             │      unknown flag       → exit 2, nothing runs
             │      no task named      → help (or the menu), nothing runs
             │
             ▼
             ②  Locate and parse the README
             │      shortcut → shortcut → document, downloading if remote
             │      display everything extracted, before acting on it
             │
             ▼
             ③  Build the task list  ── from the flags given, in fixed order
             │
             ▼
             ④  For each task:   ReadSystemState → Execute → Verify
             │                       ▲                          │
             │                       └─ dry run stops here ─────┘
             ▼
             ⑤  Summary table, per-task statistics, write the run log
```

**Phase order is a correctness property, not a presentation choice.** The README
is parsed before any task runs because user management deletes accounts the
README does not authorise. Within service management, critical services are
protected before insecure ones are disabled, so a service on both lists survives.

### The three task methods

Every task implements the same three, defined by `BaseTask` (C#) / the `Task`
trait (Rust):

| Method | Purpose | Must not |
|---|---|---|
| `ReadSystemStateAsync` | Capture the current state; display it | Change anything |
| `ExecuteAsync` | Apply remediation; return a `TaskResult` | Throw past its own catch |
| `VerifyAsync` | Re-read the system and confirm | Trust `Execute`'s own report |

`Verify` deliberately re-reads the machine rather than trusting what `Execute`
believed it did. A `reg add` that exits 0 having written to `Wow6432Node`, or an
`auditpol` call that matched no category on a non-English image, both report
success; only reading the value back catches them.

Verification failure is not fatal. It reduces the task's confidence score by 30
points and prints a warning, because a task can genuinely succeed while
verification cannot confirm it — a service that will not stop until reboot, for
instance.

---

## 3. The two ports

The repository holds two complete implementations of the same tool.

| | C# | Rust |
|---|---|---|
| Location | `src/`, `tests/` | `rust/` |
| Version | 1.8.0 | 1.13.0 |
| Framework | .NET 10 (`net10.0` + `net10.0-windows`) | Rust 2021 |
| Win32 bindings | CsWin32, generated from `NativeMethods.txt` | `windows` crate |
| Console UI | Spectre.Console | hand-rolled `ui` module |
| Tests | 172 (xUnit) | 139 (built-in) |
| Published size | ~42 MB self-contained | ~2.1 MB |

They share the flag set, the task pipeline, the parser behaviour and the run-log
format. The Rust port has run ahead in a few places — it has an extra task
(Software Updates), it runs the four independent audits concurrently, and its
scheduled-task audit parses per-task records rather than matching keywords line
by line. Those differences are noted against each task below and listed in
[rust/README.md](../rust/README.md#deliberate-divergences-from-the-c-original).

**Neither port is the "real" one.** The C# build is what `RUN.bat` launches and
what most competitors will use; the Rust build is what you want when the image is
slow, because it starts instantly and carries no runtime.

---

## 4. Tasks

Thirteen tasks in the C# port, fourteen in Rust. Each section below covers: why
the task exists, what it changes, how it does it, and what it refuses to touch.

### 4.1 Password Policy

`--password-policy`, `-p` · `src/Core/Tasks/PasswordPolicyTask.cs`

**Why.** Password and lockout policy is scored on essentially every Windows
image, and it is scored as individual settings — minimum length, maximum age,
history depth, lockout threshold — so each one is worth doing even if the others
fail.

**Target values** (`PasswordPolicyStandards`), from NIST SP 800-63B and the CIS
benchmarks:

| Setting | Value | Why that value |
|---|---|---|
| Minimum length | 14 | The CIS Level 1 figure and the usual answer-key value |
| Maximum age | 60 days | Non-zero matters more than the exact number; 0 means "never expires" and scores nothing |
| Minimum age | 1 day | Stops a user cycling straight back to the old password |
| History | 24 | CIS Level 1 |
| Complexity | enabled | |
| Lockout threshold | 5 attempts | |
| Lockout duration | 30 minutes | |
| Observation window | 30 minutes | |

**How it reads the current policy.** On Windows it calls `NetUserModalsGet`
through the native layer — levels 0 and 3, for the password and lockout halves
respectively. It falls back to parsing `net accounts` only when that call fails.

> The fallback is a fallback for a reason. `net accounts` prints a localised
> table, so on a non-English image every line match fails, the policy stays at
> its zero defaults, and zero reads as "already compliant" — the tool would
> report success having changed nothing. The API returns numbers.

Complexity is the exception: there is no API for it, so it is read by exporting
security policy with `secedit /export` and looking for `PasswordComplexity = 1`.

**How it applies changes.** Six `net accounts` calls, one per setting, each
issued only when the current value falls short. Complexity needs a different
mechanism — `secedit` has no command-line setter — so it is done by export,
text-edit, re-import:

```
secedit /export /cfg %TEMP%\secpol_temp.inf
  → replace "PasswordComplexity = 0" with "= 1"     (or insert under [System Access])
  → replace "ClearTextPassword = 1"    with "= 0"   (reversible encryption off)
secedit /configure /db ... /cfg ... /areas SECURITYPOLICY
```

Both temp files are deleted afterwards, on the success and failure paths.

**Verify.** Re-reads the policy and checks minimum length, maximum age (non-zero
*and* within target), complexity, and lockout threshold (non-zero *and* within
target). The non-zero checks matter: 0 means "no limit" for both, which would
otherwise pass a naive `<=` comparison.

---

### 4.2 Account Permissions

`--account-permissions`, `-a` · `src/Core/Tasks/AccountPermissionsTask.cs`

**Why.** The per-account settings that are scored regardless of what the README
says: Guest disabled, no blank-password accounts, passwords that expire, no
surplus administrators.

**What it changes.**

1. **Disables Guest** — `net user Guest /active:no`, if enabled.
2. **Turns off "password never expires"** — `Set-LocalUser -PasswordNeverExpires
   $false`, for every enabled account except `Administrator` and the built-in
   service accounts.

**What it only reports**, because acting would do more harm than good:

- *Accounts with no password required.* Setting one would lock a user out of an
  account they may need. Reported for a human to decide.
- *Administrator count.* More than two admins is flagged for review, not fixed —
  the README is the authority on who should be an admin, and that is user
  management's job (§4.3).
- *The default `Administrator` name.* Renaming it is suggested, never done.
- *Inactive accounts* — no logon in 90 days (`AccountSecurityStandards.MaxInactiveDays`).

**How it reads accounts.** One `Get-LocalUser | ConvertTo-Csv` call, parsed with
a quote-aware CSV splitter. Administrators membership is read **once**, through
`LocalAccounts.GetGroupMembersAsync`, and matched exactly.

> Matching exactly is the point. The original substring-searched the whole
> `net localgroup Administrators` output, so an account named `admin` matched the
> word "Administrators" in the header and was treated as an administrator — and
> then had its privileges "corrected" accordingly.

**Dry run.** Fully honoured: it prints what it would disable and whose expiry it
would change, then runs only the reporting steps.

**Protected always:** `Guest` (from expiry changes), `DefaultAccount`,
`WDAGUtilityAccount`, `Administrator`.

---

### 4.3 User Management

`--user-management`, `-u` · `src/Core/Tasks/UserManagementTask.cs` · **requires a README**

The most destructive task in the tool, and the one most directly worth points.

**Why.** Unauthorised accounts, wrong administrator membership and missing
required accounts are each scored, and all three are stated in the README rather
than being derivable from the machine.

**Five steps, in this order:**

**Step 1 — Delete unauthorised users.** Every enabled account that is neither in
the README's authorised set nor a built-in system account is deleted with
`net user <name> /delete`.

> **The guard that matters.** If the authorised set comes back *empty*, the task
> refuses to delete anything and says why. An empty set means the README failed
> to parse, not that every account on the machine is unauthorised — a real README
> always names at least one administrator. Without this guard a parsing failure
> wipes every account on a scored image.

**Step 2 — Fix permissions.** Accounts the README lists as administrators are
added to `Administrators`; accounts that are administrators but shouldn't be are
removed. Both go through `LocalAccounts`, which uses the `*-LocalGroupMember`
cmdlets and treats "already a member" as success.

**Step 3 — Reset passwords.** Every authorised, enabled, non-system account gets
a freshly generated strong password.

> Administrators included, and the README's own passwords deliberately ignored.
> The README lists the passwords an audit *found*, not passwords to keep — several
> are trivial ("root", "data"), and setting one would both weaken the machine and
> be rejected outright by the length and complexity policy this run enforced
> minutes earlier.

The generated passwords are **printed to the console and written to the run log**.
That is deliberate: they are the only way back into the accounts, and the log
stays on the competitor's own desktop.

The exception is the **primary auto-login account**, the one the README marks
"(you)". READMEs state plainly that changing its password can lock you out of the
machine, so it is skipped and the skip is announced.

**Step 4 — Create required users.** Accounts named in `UsersToCreate` are created
with `New-LocalUser`, and added to `Administrators` if the README says so.

**Step 5 — Configure groups.** For each `GroupRequirement`: create the group if
absent, then add each member.

**Never touched:** `Administrator`, `DefaultAccount`, `WDAGUtilityAccount`,
`SYSTEM`, `LocalService`, `NetworkService`, `Guest`.

**Dry run** reports the counts (authorised admins, authorised users, users to
create) and returns without touching anything.

---

### 4.4 Service Management

`--service-management`, `-s` · `src/Core/Tasks/ServiceManagementTask.cs`

**Why.** Insecure services are scored individually — Remote Registry, Telnet,
FTP, SNMP — and so is the *failure* to keep a critical service running. Disabling
one the README names as critical is one of the costliest mistakes available.

**Three lists, built before anything runs** (`BuildServiceLists`):

```
doNotTouch  =  20 hard-coded critical services  +  everything the README calls critical
toEnable    =  the README's critical services   (so they are actively started)
toDisable   =  60 hard-coded insecure services  +  the README's prohibited services
                  ── minus anything in doNotTouch ──
```

The subtraction is the safety property: a service on both lists always ends up
protected. The parser enforces the same invariant independently (§5.2).

**The default disable list** (60+), grouped by why:

| Group | Services |
|---|---|
| Remote access | `TermService`, `SessionEnv`, `UmRdpService`, `RemoteRegistry`, `RemoteAccess`, `RasMan`, `RasAuto` |
| Insecure protocols | `TlntSvr`, `ftpsvc`, `Msftpsvc`, `Smtpsvc`, `simptcp`, `SNMP`, `SNMPTRAP` |
| Discovery | `SSDPSRV`, `upnphost` |
| Sharing | `SharedAccess` (ICS), `HomeGroupProvider`, `HomeGroupListener`, `LanmanServer` |
| Web/IIS | `W3SVC`, `IISADMIN`, `WAS` |
| Peer networking | `p2pimsvc`, `p2psvc`, `PNRPsvc`, `NetTcpPortSharing` |
| Xbox | `XblAuthManager`, `XblGameSave`, `XboxGipSvc`, `XboxNetApiSvc` |
| Telemetry | `DiagTrack`, `dmwappushservice`, `RetailDemo` |
| Legacy/other | `Messenger`, `mnmsrvc`, `Fax`, `IPRIP`, `Dfs`, `MSDTC`, `ERSvc`, `WerSvc`, `helpsvc`, `seclogon`, `SENS`, `SCardSvr`, `SCPolicySvc`, `TapiSrv`, `TabletInputService`, `WMPNetworkSvc`, `icssvc`, `lfsvc`, `MapsBroker`, `PhoneSvc`, `WalletService` |

**The default protect list** (20): `wuauserv`, `WinDefend`, `SecurityHealthService`,
`wscsvc`, `MpsSvc`, `EventLog`, `Schedule`, `Winmgmt`, `CryptSvc`, `DcomLaunch`,
`RpcSs`, `RpcEptMapper`, `Dhcp`, `Dnscache`, `NlaSvc`, `nsi`, `BFE`, `BITS`,
`TrustedInstaller`, `Spooler`.

**Display-name mapping.** A README says "Remote Desktop"; the service is
`TermService`. `MapServiceName` covers the common ones, including `CCS Client →
CCSClient` — the scoring engine, which must never be stopped.

**Four execution steps:**

1. **Protect** — for every service in `doNotTouch` that is installed and not
   running: set start type to automatic, then start it. Setting the start type
   first matters, because a disabled service cannot be started.
2. **Enable** — the README's critical services, set automatic and started.
3. **Disable** — stop, then set start type to disabled. A service that will not
   stop is still disabled, so it does not come back after a reboot; the stop
   failure is recorded as an issue rather than aborting.
4. **Disable Windows features** — `TelnetClient`, `TelnetServer`, `TFTP`,
   `SMB1Protocol` and its client/server halves, plus
   `Set-SmbServerConfiguration -EnableSMB1Protocol $false`.

**How it stops services.** Through the service control manager, which enumerates
dependents and stops them explicitly.

> `net stop` asks "Do you want to continue this operation? (Y/N)" when a service
> has dependents. Standard output is redirected, so the question is captured
> instead of shown and the tool simply appears to hang. The non-Windows fallback
> uses `Stop-Service -Force` for the same reason.

**State queries are bulk.** `GetServiceStatusesAsync` reads every service in one
call. Spawning a PowerShell process per service is why the original only ever
sampled the first five and reported that partial result as a full verification.

**Verify.** Every protected service must be running, and every disabled service
must be stopped — all of them, from the same single bulk query.

---

### 4.5 Audit Policy

`--audit-policy`, `-t` · `src/Core/Tasks/AuditPolicyTask.cs`

**Why.** "Audit policy is configured to log success and failure" is a scored
item, usually per category. PowerShell logging and event-log sizing are scored
separately again.

**Four steps:**

**1. Configure the nine audit categories.** System, Logon/Logoff, Object Access,
Privilege Use, Detailed Tracking, Policy Change, Account Management, DS Access,
Account Logon — each set to Success **and** Failure.

On Windows this goes through advapi32, addressing each category by its GUID and
setting every subcategory beneath it in a single `AuditSetSystemPolicy` call.

> The GUIDs are fixed in `ntsecapi.h` and identical on every Windows install in
> every language. `auditpol /set /category:"Account Logon"` addresses the
> category by *display name*, and both the name it accepts and the "No Auditing"
> text it prints are localised — so on a non-English image the set matches
> nothing and the verify reads the absence of an English string as "audited". The
> tool reported success having configured nothing.

`auditpol.exe` remains the fallback.

**2. Advanced subcategories.** On the native path, step 1 already set all ~50
subcategories, so this step *reads back* what is actually audited and reports the
count, rather than re-issuing ~120 `auditpol` processes that would change
nothing. On the fallback path it does issue them.

**3. Security registry settings** (20 values):

| Area | Values |
|---|---|
| Auditing | `auditbaseobjects=1`, `fullprivilegeauditing=1`, `crashonauditfail=0` |
| LSA protection | `RunAsPPL=1`, LSASS `AuditLevel=8` |
| Logon | `dontdisplaylastusername=1`, `DisableCAD=0` |
| Anonymous | `restrictanonymous=1`, `restrictanonymoussam=1`, `everyoneincludesanonymous=0` |
| Credentials | `LimitBlankPasswordUse=1`, `disabledomaincreds=1` |
| SMB | `requiresecuritysignature=1`, `enablesecuritysignature=1`, `NullSessionPipes=0`, `NullSessionShares=0` |
| Sessions | `autodisconnect=15`, `EnablePlainTextPassword=0` |
| Memory | `ClearPageFileAtShutdown=1`, `CrashDumpEnabled=0` |

Note `DisableCAD = 0` and `crashonauditfail = 0` — for both, zero *is* the
hardened value. `DisableCAD=0` means Ctrl+Alt+Del **is** required;
`crashonauditfail=1` would halt the machine when the audit log fills.

**4. Event logs and PowerShell logging.** Security log to 192 MB, Application and
System to 32 MB, all `OverwriteAsNeeded`. Then script-block logging, module
logging and transcription, and `ProcessCreationIncludeCmdLine_Enabled=1` so
process-creation events carry the command line.

**Verify.** Four representative categories are re-read, and a category passes
only when **no** subcategory is left unaudited.

> The original tested the whole `auditpol` blob for "Success" *and* "Failure",
> which passed as soon as one subcategory audited Success and a different one
> audited Failure — with others still at "No Auditing".

---

### 4.6 Firewall Configuration

`--firewall`, `-f` · `src/Core/Tasks/FirewallConfigurationTask.cs`

**Why.** "Firewall enabled on all profiles" is scored, and so are individual
blocked ports on some images.

**Five steps:**

**1. Enable all three profiles.** Through the `INetFwPolicy2` COM object, which
addresses profiles by enum value — language-independent, reports a real HRESULT,
and avoids a PowerShell launch that dominated this task's runtime. Falls back to
`Set-NetFirewallProfile`.

**2. Default actions.** Block inbound, allow outbound, on all profiles. Then
`Set-NetConnectionProfile -NetworkCategory Public`, because the Public profile is
the most restrictive.

**3. Block 26 ports.** One inbound Block rule each, named
`PinnacleCyPat_Block_<service>_<proto>_<port>` so the tool's own rules are
identifiable. If the rule exists already it is enabled instead of recreated.

| Port(s) | Proto | Service |
|---|---|---|
| 20, 21 | TCP | FTP data, FTP control |
| 22 | TCP | SSH |
| 23 | TCP | Telnet |
| 25 | TCP | SMTP |
| 69 | UDP | TFTP |
| 110 | TCP | POP3 |
| 135 | TCP | RPC |
| 137, 138 | UDP | NetBIOS name, datagram |
| 139 | TCP | NetBIOS session |
| 143 | TCP | IMAP |
| 161, 162 | UDP | SNMP, SNMP trap |
| 389 | TCP | LDAP |
| 445 | TCP | SMB |
| 512, 513, 514 | TCP | rexec, rlogin, rsh/syslog |
| 1433 | TCP | MS SQL |
| 1434 | UDP | MS SQL Browser |
| 3306 | TCP | MySQL |
| 3389 | TCP | RDP |
| 5900–5902 | TCP | VNC |

**4. Disable risky rules and groups.** Eight named rules (the Remote Assistance
family, Telnet Server, netcat) and eight rule groups (Network Discovery, File and
Printer Sharing, Remote Desktop, Remote Assistance, Remote Event Log/Service/
Volume Management, WinRM). Then explicit in and out block rules bound to the
`RemoteRegistry` service.

**5. Logging.** Dropped connections logged to
`%SystemRoot%\System32\LogFiles\Firewall\pfirewall.log`, 32 MB cap, allowed
connections not logged. `netsh advfirewall` is the fallback.

**Verify.** All three profiles report enabled.

---

### 4.7 Security Hardening

`--security-hardening`, `-H` · `src/Core/Tasks/SecurityHardeningTask.cs`

> `-H`, not `-h`. `-h` is help. `--security-hardening` is unchanged.

**Why.** The long tail of individually-scored registry settings.

**41 registry values**, applied under a progress bar:

| Area | Values |
|---|---|
| UAC | `EnableLUA=1`, `ConsentPromptBehaviorAdmin=5`, `PromptOnSecureDesktop=1`, `EnableInstallerDetection=1` |
| Logon | `DisableCAD=0`, `dontdisplaylastusername=1`, `undockwithoutlogon=0`, `AutoAdminLogon=0` |
| AutoRun | `NoAutorun=1`, `NoDriveTypeAutoRun=255` |
| Remote Desktop | `fDenyTSConnections=1`, `fAllowToGetHelp=0`, `AllowTSConnections=0` |
| Defender | `DisableAntiSpyware=0`, `ServiceKeepAlive=1`, `DisableRealtimeMonitoring=0`, `DisableIOAVProtection=0` |
| Windows Update | `NoAutoUpdate=0`, `AUOptions=4`, `AutoInstallMinorUpdates=1` |
| LSA | `RunAsPPL=1`, `LimitBlankPasswordUse=1`, `restrictanonymous=1`, `restrictanonymoussam=1`, `everyoneincludesanonymous=0`, `disabledomaincreds=1`, `auditbaseobjects=1`, `fullprivilegeauditing=1`, LSASS `AuditLevel=8` |
| Memory | `ClearPageFileAtShutdown=1`, `CrashDumpEnabled=0` |
| Removable media | `AllocateCDRoms=1`, `AllocateFloppies=1` |
| SMB | `EnablePlainTextPassword=0` |
| Explorer | `Hidden=1`, `ShowSuperHidden=1` — show hidden and system files, so a later manual sweep can see them |
| Browser | SmartScreen `EnabledV9=1`, `DisablePasswordCaching=1`, `WarnonBadCertRecving=1`, `WarnOnPostRedirect=1`, `DoNotTrack=1` |
| WinRM | `AllowRemoteShellAccess=0` |

Several overlap with the audit-policy task deliberately. Both are idempotent, and
running either alone should leave the machine in the hardened state.

**Windows features disabled:** Telnet client and server, TFTP, all three SMB1
features, and PowerShell v2 (`MicrosoftWindowsPowerShellV2`,
`MicrosoftWindowsPowerShellV2Root`) — v2 is a downgrade path around v5's script
block logging.

**System settings:** flush DNS cache, re-enable Defender real-time monitoring,
update Defender definitions, start `wuauserv`.

**Startup review.** Enumerates `Win32_StartupCommand` and the four Run/RunOnce
keys and logs them. It **reports only** — deciding what belongs in a Run key
needs judgement the tool does not have.

**Verify.** Spot-checks UAC (`EnableLUA=0x1`) and RDP (`fDenyTSConnections=0x1`).

---

### 4.8 Prohibited Media

`--media-scan`, `-m` · `src/Core/Tasks/ProhibitedMediaTask.cs`

**Why.** Removing prohibited media and hacking tools from user directories is
scored per file on most images.

> **This task deletes files permanently.** Not to the recycle bin, not to a backup
> folder. A backup left the content on the machine — just moved — which does not
> clear the finding it was flagged for, and doubled the disk written during a
> scan. Every deletion is recorded in the run log with its path, size and
> modification time.

**What counts as prohibited:**

*Media extensions* — audio (`.mp3 .wav .wma .aac .flac .ogg .m4a .m4p .aiff .ac3
.midi .mid .vqf`), video (`.mp4 .avi .mkv .mov .wmv .flv .mpeg .mpg .mpeg4 .m4v
.webm .3gp`), `.gif`, playlists (`.m3u .m3u8 .pls .wpl`), `.torrent`.

`.wav` files under 10 KB are skipped — those are system sounds.

*Hacking-tool name patterns* (40+) — `cain`, `abel`, `wireshark`, `nmap`,
`metasploit`, `burp`, `sqlmap`, `hydra`, `john`, `hashcat`, `aircrack`,
`ettercap`, `nikto`, `netcat`, `nc.exe`, `nc64.exe`, `mimikatz`, `pwdump`,
`fgdump`, `wce`, `gsecdump`, `lsadump`, `procdump`, `keylogger`, `keylog`,
`trojan`, `backdoor`, `rootkit`, `exploit`, `payload`, `hack`, `crack`, `keygen`,
`patch`, `loader`, `injector`, `cheat`, `aimbot`, `wallhack`, `speedhack`,
`godmode`, `trainer`.

*Game patterns* — `steam`, `minecraft`, `fortnite`, `valorant`, `csgo`, `riot`,
and similar, but **only** for `.exe` and `.msi` files under `C:\Users`.

*README additions* — anything in `ProhibitedSoftware`.

**Where it scans.** `C:\Users`, recursively, skipping `Windows`, `Program Files`,
`Program Files (x86)`, `ProgramData`, `$Recycle.Bin`, `System Volume
Information`, `Recovery`, `AppData\Local\Microsoft`, `AppData\Local\Packages`,
and any hidden or system directory. Access-denied directories are skipped
silently.

**Self-protection.** The scanner never deletes its own executable or anything in
the same folder.

> Not hypothetical: the game list contains `riot`, which is a substring of
> `cyberPATRIOTautomation.exe`. Run from a folder under `C:\Users` — which is
> exactly where a competitor runs it — the scanner classified its own binary as a
> game and queued it for deletion. Windows locks a running executable so the
> delete would have failed and been reported as an error, but the sibling check
> also protects the run log and anything shipped alongside.

**Flow.** `ReadSystemState` scans and displays a summary by category (count and
total size) plus the first 20 files. `Execute` deletes. `Verify` re-scans and
passes only when nothing matches.

`ItemsAttempted` / `ItemsSucceeded` are populated here, so this task contributes
real numbers to the completion rate rather than a bare pass/fail.

---

### 4.9 Software Management

`--software-management` · `src/Core/Tasks/SoftwareManagementTask.cs`

**Why.** Prohibited software removal, required software installation and a
malware scan are three separate scored items on most images.

**Prohibited by default**, even when the README is silent: **Python**,
**CCleaner**, **Jellyfin**. These are seeded in the constructor, so they apply
whether or not a README was parsed.

> They used to be applied only inside `SetReadmeData`, behind an early return on
> a null README — so a run without one, or with one that failed to parse, left
> the prohibited list empty and removed nothing at all. A default that only
> applies when the README is present is not a default.

> From the CP19 exhibition answer key, which scored removing Jellyfin Media
> Player and Python 3 as separate items while the README named neither. A README
> that *requires* one of them wins — an image that legitimately needs Python must
> not have it uninstalled.

**Reading the inventory.** The Windows uninstall registry keys — 64-bit, 32-bit
(`WOW6432Node`) and per-user — skipping `SystemComponent` entries and patches
(those with a `ParentKeyName`).

> This replaced `wmic product get name`, which was wrong three ways: it is
> deprecated and already disabled by default on current Windows 11 images; it
> only ever saw MSI-installed products, missing everything installed by an EXE
> bundle; and enumerating `Win32_Product` makes the installer service
> *reconfigure every installed product*, which takes minutes and has been known
> to re-trigger repairs. The uninstall keys are what Add/Remove Programs itself
> lists.

**Removal.** Three mechanisms, in order of reliability:

1. **Chocolatey**, when it owns the package — silent, with real error messages.
2. **The uninstaller the program registered**, made unattended. This is what
   actually removes NSIS and Inno software.
3. **`msiexec` by product name**, only when the inventory came from the `wmic`
   fallback and so carries no uninstall string.

Silent switches are derived per installer family:

| Family | Detected by | Switch |
|---|---|---|
| MSI | `msiexec` in the program name | rewritten to `/x {code} /qn /norestart` |
| Inno Setup | `unins000.exe`, numbered | `/VERYSILENT /SUPPRESSMSGBOXES /NORESTART` |
| Bundle | `/uninstall` already in the arguments (Python) | `/quiet /norestart` |
| NSIS | everything else | `/S` |

A `QuietUninstallString` is used verbatim — the publisher has already made it
unattended, and adding a switch can break it.

> **`wmic product call uninstall` used to be the fallback, and it never worked.**
> `Win32_Product` lists only MSI-installed software, and CCleaner, Notepad++ and
> Jellyfin Media Player all ship NSIS installers — none of them were ever in it.
> Worse, `wmic` exits **0** when its `where` clause matches nothing, so the run
> printed "Removed: CCleaner" while CCleaner sat untouched on disk. The MSI
> rewrite matters for the same reason: the registered string uses `/I`, which is
> *install*, so passing it through opens the repair dialog rather than removing
> anything.

Removals are then **verified against a fresh inventory**. An uninstaller that
exits 0 having shown a dialog nobody answered, or that needs a reboot to finish,
both report success; only re-reading the registry catches it.

**Installation.** Through Chocolatey, bootstrapping it if absent. Display names
are mapped to package ids — a README says "Mozilla Firefox", the package is
`firefox`:

| README name | Package |
|---|---|
| Mozilla Firefox / Firefox | `firefox` |
| Google Chrome / Chrome | `googlechrome` |
| 7-Zip | `7zip.install` |
| Notepad++ | `notepadplusplus.install` |
| VLC | `vlc` |
| Wireshark | `wireshark` |
| PuTTY | `putty` |
| Adobe Acrobat Reader DC | `adobereader` |
| Thunderbird | `thunderbird` |
| LibreOffice | `libreoffice-fresh` |
| Microsoft Edge, Git, Python, Malwarebytes | `microsoft-edge`, `git`, `python`, `malwarebytes` |

Names not listed fall through to a lower-cased, unspaced form of the display
name, which is right often enough to be worth trying before reporting a failure.

> The `.install` suffixes are not cosmetic. Those packages run the vendor
> installer, which puts the program under `Program Files`; the bare ids are
> portable packages that unpack under `ProgramData`. The CP19 answer key deducts
> points when 7-Zip, Notepad++, Chrome or Wireshark are "not installed at the
> default location".

**Updating.** Every README-required package plus every installed package with a
recognised id is upgraded **by name**, then `choco upgrade all` catches the rest.

Chocolatey is **ensured** here, not merely detected.

> It used to be only detected, while the bootstrap lived in the install branch —
> which runs only when something is missing. On the common image, where the
> required software is present and merely out of date, nothing was missing, so
> Chocolatey was never installed and the whole update step was skipped in
> silence. That is why Chrome and Notepad++ were never updated.

Display names are matched to package ids **fuzzily**, stripping version, bitness
and locale decoration.

> An exact dictionary lookup on the full display name matched `Google Chrome`,
> whose registered name happens to carry no suffix, and essentially nothing else.
> `Notepad++ (64-bit x64)`, `Mozilla Firefox (x64 en-US)` and `7-Zip 23.01 (x64)`
> all missed. The longest matching key wins, so a short key cannot shadow a more
> specific one.

> Upgrading by name matters because `choco upgrade all` only touches packages
> Chocolatey itself installed — so software that came with the image, which is
> exactly what a competition asks you to update, is never considered. `choco
> upgrade <name>` runs the newer vendor installer over the top regardless of how
> the software got there.

**Malware scan.** Update definitions, run a Defender QuickScan (one-hour
timeout), count `Get-MpThreatDetection` results, and attempt `Remove-MpThreat` if
anything is found.

**Success** means removals and installs succeeded, the scan ran, and no threats
remain — not that there was nothing to do.

---

### 4.10 Software Updates (Rust only)

`--software-updates` · `rust/src/tasks/software_update.rs`

A dedicated version-checking task with no C# equivalent. Out-of-date third-party
software is scored separately from missing software, and answering it needs two
different sources:

- **What is installed, and at what version?** The uninstall registry keys. Works
  offline; covers far more than `wmic product`.
- **What is the latest version?** A package catalogue — Chocolatey. `choco
  outdated --limit-output` prints `name|current|available|pinned` per line, which
  is exactly the comparison needed.

Software the README marks as needing the latest version is updated **first**, so
if a run is cut short the scored items are the ones already done. Each package is
upgraded individually, so one failure does not abort the rest.

OS patches are deliberately out of scope — Windows Update settings belong to the
audit-policy task.

> Chocolatey rather than winget because winget ships as the "App Installer"
> package, which is absent from the LTSC images CyberPatriot uses and awkward to
> add offline, whereas Chocolatey installs from a script on any supported
> Windows. And `--limit-output` is delimited, where the winget path needed
> fixed-width column parsing measured in terminal display width so a CJK package
> name would not shift every following field.

---

### 4.11 Shared Folders Audit

`--shared-folders` · `src/Core/Tasks/SharedFoldersAuditTask.cs`

**Why.** "Only the default administrative shares exist" is a standard checklist
item (`fsmgmt.msc`). Anything else is a file-sharing exposure.

**Allowed:** `ADMIN$`, `C$`, `IPC$`. Everything else is deleted with
`net share <name> /delete /y`.

> The `/y` answers "There are open files ... force them closed? (Y/N)", which the
> command asks when the share is in use. Without it the command waits on a
> keypress that never arrives.

**Parsing.** `ParseShares` reads only the rows between the dashed separator and
the trailing status line.

> Taking the first token of every line containing a space also picked up "Share"
> from the header and "The" from "The command completed successfully.", so the
> task tried to `net share Share /delete` on things that were never shares.

**Success** means every removal succeeded — not that there was nothing to remove.
The original returned `unauthorized.Count == 0`, which reported failure precisely
when the task had found and fixed something.

---

### 4.12 Hosts File Audit

`--hosts-file` · `src/Core/Tasks/HostsFileAuditTask.cs`

**Why.** A modified `hosts` file is a common planted misconfiguration: it can
redirect update servers or security vendors to nowhere.

**Allowed:** `127.0.0.1 localhost` and `::1 localhost`, plus comments and blanks.
Everything else is removed and the file rewritten.

**Whitespace-normalised comparison.** Entries are compared as content, not
formatting.

> The allowed entries are written with a fixed run of spaces. Comparing raw
> strings meant a hosts file using a tab, or a different number of spaces —
> entirely normal — failed to match, so the *legitimate* localhost mapping was
> classified as unauthorised and deleted.

If nothing needs removing the file is not rewritten at all: there is no reason to
touch a system file for no change.

---

### 4.13 DNS Settings Audit

`--dns-settings` · `src/Core/Tasks/DnsSettingsAuditTask.cs`

**Why.** A resolver pointed at an attacker-controlled or unexpected public server
is a planted misconfiguration.

**Report only.** It never changes DNS — replacing a resolver can disconnect the
machine from the scoring engine, and the correct value depends on the network the
image is on.

**How.** Reads `NetworkInterface.GetAllNetworkInterfaces()` for every operational
non-loopback adapter and compares each `IPAddress` against `8.8.8.8`, `8.8.4.4`,
`1.1.1.1`, `1.0.0.1`.

> This replaced parsing `netsh interface ip show dns`, whose layout and headings
> are localised, and fixed a subtler bug: the old check ran
> `output.Contains("1.1.1.1")` over the whole blob, so a resolver at `11.1.1.10`
> matched the substring and was reported as public DNS. Comparing `IPAddress`
> values makes the match exact.

---

### 4.14 Suspicious Scheduled Tasks Audit

`--scheduled-tasks` · `src/Core/Tasks/SuspiciousScheduledTasksAuditTask.cs`

**Why.** Scheduled tasks are a standard persistence mechanism, and a planted one
is worth points to find.

**How.** `schtasks /query /fo LIST /v`, matched against `hack`, `malware`,
`bitcoin`, `crypto`, `miner`, `backdoor`, `remote`, `powershell`, `cmd.exe`.
Matching tasks are disabled with `schtasks /Change /TN "<name>" /Disable`.

> **The C# version matches keywords against any line of output** and is therefore
> noisy — `powershell` and `cmd.exe` appear in the command line of legitimate
> built-in tasks. **The Rust port parses per-task records and skips anything
> under `\Microsoft\`**, which is the behaviour to prefer. Review this task's
> output rather than trusting it.

**Success** means every suspicious task was disabled successfully — including the
case where there were none.

---

### 4.15 Group Policy

`src/Core/Tasks/GroupPolicyTask.cs` — implemented and tested; not currently wired
to a CLI flag in either port. Its settings are covered by the audit-policy and
security-hardening tasks, which is why it does not run separately.

What it sets:

| Setting | Value | Meaning |
|---|---|---|
| `dontdisplaylastusername` | 1 | Don't show the last user on the logon screen |
| `DisableCAD` | 0 | Ctrl+Alt+Del **is** required |
| `restrictanonymous` | 1 | Restrict anonymous enumeration |
| `SharedAccess` start type | disabled | ICS off, via `sc config` |
| Workstation `RequireSecuritySignature` | 1 | SMB client signing (always) |
| Server `RequireSecuritySignature` | 1 | SMB server signing (always) |
| `fDenyTSConnections` (local + policy key) | 1 | Remote Desktop refused |

Two details worth carrying over:

- **Both SMB signing halves are set.** They are a pair in every hardening
  benchmark; signing one side leaves the other able to negotiate an unsigned
  session, which is what makes SMB relay work.
- **RDP is denied in the local key *and* the policy key.** A policy value
  overrides the local one, so an image with the policy set to "allow" would keep
  RDP listening no matter what the local setting said.

**Verify** confirms each value equals its expected number.

> Not just that it exists. These checks previously only asserted that `reg query`
> exited 0, which is true whenever the value is *present* — so a setting left at
> the wrong value verified as correct.

---

## 5. Utilities

### 5.1 AppConfig — README discovery

`src/Core/AppConfig.cs` · `rust/src/app_config.rs`

The single hardest thing the tool does, and the reason `--auto-readme` works at
all.

> **On a standard competition image the README is not a file on disk.**
> `C:\CyberPatriot\README.url` is an *Internet Shortcut* naming an `https://`
> document, which is what the competitor's browser opens. `C:\CyberPatriot\`
> contains no `README.html`.

**Search order:**

1. A README shortcut on the current user's desktop, then the public desktop
2. `C:\CyberPatriot\README.url`, then `README.html`
3. `C:\Users\Public\Desktop\README.*`, `C:\Users\Public\Documents\README.html`
4. The current user's desktop
5. `C:\Users\*\Desktop\README.*` — every profile

**Shortcuts chain and are followed to the end.** On a real image: desktop `.lnk`
→ `C:\CyberPatriot\README.url` → the document. Bounded at 5 hops, which also
terminates a shortcut that points at itself.

> Stopping after one hop returns the `.url` itself, and parsing that INI file as
> HTML yields a README with no title and no detectable OS — the "Unknown /
> Unknown" symptom.

- `.url` is parsed as INI (the `URL=` key), needing no shell interop, which is
  why it is unit-testable.
- `.lnk` is resolved through the `WScript.Shell` COM object.
- A remote target is downloaded to `%TEMP%\pinnaclecypat_readme.html`. **The URL
  is read from the shortcut at run time and never hard-coded** — it is unique per
  image and changes every competition.
- Files are read leniently: UTF-16 LE/BE and UTF-8 BOMs are all handled, because
  Windows tools routinely write UTF-16.

**Wildcard expansion** enumerates the starred position only.

> Stripping the `*` and searching recursively — as this once did — turned
> `C:\Users\*\Desktop\README.html` into a search under `C:\Users\Desktop`, which
> does not exist, so the fallback silently never matched. Had it existed,
> recursing all of `C:\Users` would have been worse: it would return the first
> `README.html` found anywhere in any profile, downloads included.

**Failure reporting.** Every location examined is recorded, distinguishing "not
found" from "exists but could not be resolved" — and in the latter case, saying
what the shortcut actually points at.

Also here: `SecurePasswords` (10 complexity-compliant base passwords),
`CCSClientServiceName`, and the version string, which reads the assembly version
and stamps the executable's build date.

### 5.2 ReadmeParser

`src/Core/Utilities/ReadmeParser.cs` (1,813 lines) · `rust/src/readme_parser.rs`

Turns competition README HTML into the `ReadmeData` that drives every
README-aware task. Regex-based, because the input is hand-written HTML that no
strict parser survives.

**What it extracts:**

| Field | How |
|---|---|
| `Title` | `<h1>`, falling back to `<title>` |
| `OperatingSystem` | Needle list, most specific first |
| `Sections` | `<h2>` headers and the content up to the next one |
| `Administrators` / `Users` | The "Authorized Administrators/Users" block |
| `RequiredSoftware` | Four phrasing patterns |
| `CriticalServices` / `ProhibitedServices` | "do not disable X" vs "disable X" |
| `GroupRequirements` | "Make a new group called X and add ..." |
| `UsersToCreate` | "Make a new account named X" |
| `ActionableItems` | Per-`<p>` classification into 11 types |
| `Guidelines`, `Scenario` | List items and the scenario section |

**OS detection** consults `<title>` and `<h1>` *before* the body.

> A whole-document scan matches prose such as "do not go back to Windows 10" in a
> Windows 11 image. Markup and whitespace are also normalised first, because
> `Windows&nbsp;10` decodes to a U+00A0 that never equals a plain space, and
> `Windows <b>10</b>` has a tag in the middle — both ordinary in hand-written
> HTML, and both produced "Unknown". Server 2012–2025, Windows 7/8.1, Ubuntu,
> Debian, Fedora are recognised.

**User-block parsing** converts `<br>`, `</p>`, `</li>`, `</div>`, `</tr>` and
`</hN>` to newlines *before* stripping tags.

> Only a `<pre>` block carries real newlines. A list written with `<br>`, or one
> `<p>` per user, collapses to a single line once tags are removed — and the
> whole block is then rejected as one over-long "username", so such a README
> yielded no users at all.

`(you)` marks the primary auto-login account. Any parenthetical is stripped
before validation, so `bob (Admin)` yields `bob`.

**Username validation** is deliberately permissive:

- 20 characters maximum — the Windows limit. (Allowing 50 let whole sentences be
  recorded as users.)
- No characters Windows forbids in an account name
- Not containing "password" or "authorized"
- At most two words, none of them a common English word
- At least one letter

> Erring permissive is deliberate. A real user wrongly rejected is absent from the
> authorised set and gets **deleted**; a junk entry only ever protects an account
> that would otherwise be removed.

**Service classification** is the highest-stakes part:

```
"disable the X service"                 → prohibited
"do not stop or disable the X service"  → CRITICAL
"X service should be disabled"          → prohibited
"do not stop" + "ccs client"            → CRITICAL, and scrubbed from prohibited
```

The negation regex allows an intervening verb (`(?:\w+\s+or\s+)?`).

> The original lookbehind only covered a literal "do not " immediately before
> "disable", so the very common phrasing "do not stop **or** disable the X
> service" slipped through and queued a critical service for disabling.

Critical services are collected **before** any prohibited entry is added, and a
final pass removes anything from the prohibited list that also appears in the
critical list — whichever pattern matched first. Disabling a scored critical
service is the costliest mistake in competition, so the invariant is enforced
twice.

**Software-name plausibility.** Real product names are proper nouns, so a
candidate must start with a capital, not be a common word, not be one of ~25
generic nouns (`tool`, `browser`, `application`, `system`...), and have every word
capitalised if multi-word.

> The broad "access to ... ." pattern happily captures ordinary prose: "access to
> administrative tools." was being recorded as required software named
> "administrative tools".

`ShouldBeLatest` is decided from **the matched phrase**, not the whole document.

> Testing the document meant one mention of "latest" anywhere flagged every
> package as needing the latest version.

**Group requirements** iterate every match.

> A single `Regex.Match` meant a README asking for two groups only ever produced
> the first.

### 5.3 CommandExecutor

`src/Core/Utilities/CommandExecutor.cs` · `rust/src/command.rs`

Every external process goes through here.

**Standard input is redirected and closed immediately.**

> Without it the child inherits the console, and any tool that asks a question
> waits for a human forever — `net stop` prompts when a service has dependents,
> and because stdout is redirected the prompt is *captured* rather than shown, so
> the tool simply appears to freeze. Closing the handle makes the prompt read EOF
> and the command abort.

**Both output streams are read concurrently**, to avoid the deadlock where one
stream fills its buffer while the other is being read.

**The timeout covers the wait for exit, and only that.**

> The read tasks finish when the child's pipes close, which happens when it
> exits — so a child that never exits keeps them pending forever. Including them
> in the same `Task.WhenAll` meant cancelling the exit-wait left the whole await
> pending, the catch block never ran, and the timeout did nothing in precisely
> the case it exists for.

On timeout the process tree is killed, and the stream reads are then bounded at
5 s each, because a grandchild that inherited the handle can still hold the pipes
open.

**Default timeout: 2 minutes.** Overridable, and overridden where it matters — a
Defender scan gets an hour, Chocolatey installs 20 minutes, `choco upgrade all`
60 minutes, downloads 10 minutes, `wmic product` 10 minutes.

**`ExecuteForExitCodeAsync` reports the code, not just success.**

> Some tools use a non-zero exit to mean "done, with a caveat" — Chocolatey
> returns 3010 and 1641 for "succeeded, reboot pending". A caller treating those
> as failure rolls back work that actually completed.

**Two PowerShell helpers**, replacing ad-hoc `-ErrorAction SilentlyContinue`:

- `PowerShellAsync` — for state changes. Runs under `$ErrorActionPreference =
  'Stop'` inside try/catch, so any cmdlet error becomes a non-zero exit **with
  the message on stderr**.

  > The old form suppressed the error record entirely, so the process exited
  > non-zero but wrote nothing to stderr and callers formatting the reason
  > produced an empty explanation. And PowerShell's exit code reflects only the
  > final statement, so an error part-way through a multi-statement script still
  > exited 0.

- `PowerShellQueryAsync` — for reads. Ends with `exit 0`, so a missing object
  yields empty output rather than a process failure.

**`PsQuote`** doubles embedded `'` for single-quoted PowerShell strings. An
account named `O'Brien` would otherwise close the string early and corrupt the
rest of the script.

**`DownloadFileAsync`** shells out rather than using `HttpClient`, so TLS, the
certificate store and any configured proxy stay with the OS. TLS 1.2 is selected
explicitly because Windows PowerShell 5.1 still negotiates older protocols that
most hosts now refuse. `curl.exe` is the fallback; both follow redirects.

### 5.4 RunLog

`src/Core/Utilities/RunLog.cs` · `rust/src/run_log.rs`

> The console narrative already describes the run in full — which services were
> queued, which users were created, which passwords were set — but it scrolls
> away, and on a competition image there is rarely a chance to read it as it
> goes.

**Default location:** the desktop of the user running the tool,
`PinnacleCyPat_RunLog_v<version>_<timestamp>.txt`. The version is in the file
name so logs from different builds are distinguishable without opening them.
`--log <path>` overrides.

**How it captures everything.** `AttachToConsole` replaces Spectre's
`IAnsiConsoleOutput` with a tee that buffers to a newline, strips ANSI escapes,
timestamps, and appends.

> Hooking the console once is far less error-prone than editing every one of the
> hundreds of `MarkupLine` call sites, and it cannot fall out of sync as tasks
> change. It captures the *rendered* text, from which markup has already been
> resolved, so the log holds exactly what the operator saw — table contents
> included.

**Diagnostics.** Every external command is recorded with its arguments, exit code
and elapsed time, and on failure the first 600 characters of stderr and stdout.
Tasks add their own: the software task records what it matched, which uninstall
mechanism it chose, and what survived removal.

> This is what a failure investigation needs and did not have. The console said
> `✗ Failed to remove: CCleaner ()` — with an empty reason, because the tool
> reported failure only through an exit code — and there was nothing else to go
> on. Diagnostics go to the log only, never the console: putting them on screen
> would bury the narrative the operator has to follow live.

Passwords interpolated into `ConvertTo-SecureString` are redacted from the
command echo. The log still records each generated password once, where the task
announces it — a considered disclosure in one place, not a reason to scatter the
same secret through every command line.

Grep a log for `[cmd]` to see every command, or `[software]` for the software
task's own reasoning.

**Structure:** a header (version, start time, full command line), the timestamped
narrative interleaved with diagnostics, then a structured per-task block — outcome, verified, item counts,
confidence, message, issues — so the outcome of each task is greppable without
reading the whole run.

Written on the normal exit path **and** on the `--parse-readme` path.

### 5.5 LocalAccounts

`src/Core/Utilities/LocalAccounts.cs`

Account and group operations, shared by the account-related tasks. **These go
through PowerShell rather than `net`.**

> `net user` interactively confirms any password longer than 14 characters ("Do
> you want to continue this operation? (Y/N)"), and these commands run without a
> console to answer it, so the prompt reaches EOF and `net` aborts. Every
> generated password is longer than that, so **every password change and every
> account creation failed**. The `*-LocalUser` cmdlets have no prompt and report a
> real reason on failure.

- `GetGroupMembersAsync` — netapi32 where available, `net localgroup` parsing
  otherwise
- `ParseGroupMembers` — reads only the rows between the dashed separator and the
  status line
- `IsGroupMember` — exact match, handling the `DOMAIN\user` form
- `GeneratePassword(index)` — cycles `AppConfig.SecurePasswords` with an index
  suffix, so no two accounts share a password even past the tenth
- `SetPasswordAsync`, `CreateUserAsync`, `AddToGroupAsync`, `RemoveFromGroupAsync`
  — all return `null` on success or the reason as a string. "Already a member" is
  treated as success, being the desired end state.
- `PrimaryUsers(readme)` — the accounts marked `(you)`, which must not have their
  passwords changed

### 5.6 RegistryOps and ServiceOps

`src/Core/Utilities/RegistryOps.cs`, `ServiceOps.cs` · `rust/src/registry_ops.rs`, `service_ops.rs`

Thin façades that pick the native path where available and the shell-out path
otherwise, so tasks read as plain intent and there is one place that knows about
the fallback.

Both return **the reason on failure** rather than a bare boolean, because
"access denied" and "the key does not exist" need different responses and
`reg.exe`/`sc.exe` exit codes cannot tell them apart.

`RegistryOps` also exposes `ParseRegDword`, shared by the fallback and the tests
so the two cannot drift.

`ServiceOps` exposes a `ServiceState` enum — `Absent`, `Stopped`, `Running`,
`Other` — where `Absent` is explicitly *not* a failure: a service that is not
installed is already in the state the caller wanted.

### 5.7 Chocolatey

`src/Core/Utilities/Chocolatey.cs`

> Chocolatey is the default package source because it is scriptable without a
> console prompt, installable onto every supported image, and its package names
> are stable across Windows editions. If it is missing it is bootstrapped from
> the official install script rather than leaving required software uninstalled.

**The one sharp edge is PATH.**

> The bootstrap adds Chocolatey to the machine PATH, but an already-running
> process keeps the environment block it started with, so `choco` stays
> unresolvable in this process until it restarts. Every call therefore resolves
> the executable by absolute path (`%ProgramData%\chocolatey\bin\choco.exe`) as
> well as by name.

**Success exit codes:** `0, 1605, 1614, 1641, 3010` — the last three mean
"succeeded, reboot pending".

`ListInstalledAsync` uses `--limit-output`, which prints `name|version` per line
and nothing else, so there is no banner to skip and no localised text to match.

---

## 6. Native layer

`src/Core/Native/` (CsWin32) · `rust/src/native/` (`windows` crate)

Windows-only; compiled for `net10.0-windows` / `#[cfg(windows)]`. The non-Windows
build falls back to shell-out paths, which is what lets the parser and model
tests run on a Linux dev box.

**The reason for all of it:**

> The command-line tools print localised, human-formatted tables. A parser
> written against the English output returns nothing on a non-English image, and
> "nothing" reads to the caller as *"the group is empty"* or *"the policy is
> already compliant"* rather than as a failure — so the tool reports success
> having done nothing. These APIs return structured data and a status code.

| Module | Replaces | API | Notes |
|---|---|---|---|
| `NativeAccounts` | `net localgroup`, `net accounts` | netapi32 | `NetLocalGroupGetMembers` level 3 returns `DOMAIN\user` directly. `NetUserModalsGet` levels 0 and 3 for password and lockout policy; seconds normalised to days/minutes |
| `NativeAuditPolicy` | `auditpol.exe` | advapi32 | Category GUIDs from `ntsecapi.h`. **Enables `SeSecurityPrivilege` explicitly** — an elevated token carries it *present but disabled*, which is what `auditpol.exe` does internally |
| `NativeFirewall` | `Set-NetFirewallProfile` | `INetFwPolicy2` COM | Profiles addressed by enum; real HRESULTs |
| `NativeInstalledSoftware` | `wmic product get name` | uninstall keys | Four hives (HKLM/HKCU × 64-bit/WOW). Returns `null` only if *nothing* could be read, so an empty machine stays distinguishable from a failure |
| `NativeRegistry` | `reg.exe` | Registry API | **Opens the 64-bit view explicitly** |
| `NativeServices` | `sc.exe`, `net start/stop` | SCM | Enumerates and stops dependents explicitly, so nothing prompts; 30-second stop timeout |

Two of those deserve their own note:

**WOW64 redirection.** `reg add` from a 32-bit process is silently redirected to
`Wow6432Node`, so a hardening value written there has no effect on the 64-bit
system it was meant to configure — and the command still exits 0.

**`AdjustTokenPrivileges` lies.** It reports success even when it enabled
nothing; the real answer is in `GetLastError() == ERROR_NOT_ALL_ASSIGNED`, which
is checked.

Every native call returns `null`/`Err` on failure rather than an empty result,
and the shell-out path remains as the fallback.

---

## 7. Models

`src/Core/Models/` · `rust/src/models/`

| Type | Purpose |
|---|---|
| `ReadmeData` | Everything parsed from the README |
| `AuthorizedUser` | Username, password, `IsAdmin`, `IsPrimaryUser` |
| `SoftwareRequirement` | Name, version, `ShouldBeLatest`, notes |
| `GroupRequirement` | Group name and members |
| `ActionableItem` | Type, description, raw text, details — 11 `ActionableItemType` values |
| `AccountInfo` | One local account's state and group memberships |
| `PasswordPolicyInfo` | The eight policy values |
| `SystemInfo` | Pre-change state captured by `ReadSystemState` |
| `TaskResult` | Outcome, message, error details, item counts, confidence, verified |

Two constant blocks live with the models: `PasswordPolicyStandards` (§4.1) and
`AccountSecurityStandards` (Guest disabled, passwords required and expiring, 90-day
inactivity threshold, the insecure-username list).

**`TaskResult.CompletionRate`** falls back to the task's own success when no
per-item counts were reported.

> Returning a flat 100% in that case reported full completion for tasks that had
> failed outright — and since almost no task populates `ItemsAttempted`, that was
> almost every task.

---

## 8. The interactive menu

`src/Core/Tui.cs` · `rust/src/tui.rs` — `--tui`, `-i`

A guided menu for people who would rather not memorise flags. It opens when
`--tui` is passed, and also on a **bare launch at a real terminal** — which is
what double-clicking the executable does.

> Redirected streams mean a script or a pipe, where a prompt would block forever
> waiting for an answer that never comes, so the bare-launch behaviour is gated
> on both stdin and stdout being a terminal.

**The flow:**

```
  banner + version + Administrator check
      │
      ▼
  What would you like to do?
      ├─ Inspect the README only   (read-only)
      ├─ Preview every task        (dry run)
      ├─ Run every task            (applies changes)
      ├─ Choose individual tasks
      └─ Quit
      │
      ▼
  Which README?   auto-discover │ type a path or URL │ continue without one
      │
      ▼
  [if choosing]  which tasks, then preview or apply
      │
      ▼
  warn if a chosen task needs the README that was declined
      │
      ▼
  summary table + explicit confirmation   ── declining exits, changing nothing
      │
      ▼
  hand the assembled command line to the normal run pipeline
```

**It builds arguments; it does not run tasks.**

> The command line is the single execution path, and every ordering guarantee the
> run depends on lives there. A menu that drove the tasks directly would be a
> second copy of that logic, free to drift from the first. It also means the run
> log's `Command:` line records exactly what a menu-driven run did, so it can be
> repeated non-interactively.

**Safety details:**

- The confirmation's **default answer is No for apply and Yes for preview**, so
  pressing enter without reading can only ever be the harmless choice.
- Applying prints an explicit warning about deleting files, removing accounts and
  disabling services.
- Choosing "continue without a README" names the tasks that will then decline to
  act, *before* the run starts — otherwise the run reports "No README data
  provided" part-way through, by which point other tasks have already made
  changes.
- Not being Administrator is reported up front, because the failure mode
  otherwise is a long run in which every change is denied, which reads as the
  tool not working.

**Presentation differs by port.** C# uses Spectre.Console's arrow-key selection
and multi-select prompts (everything pre-selected). Rust uses numbered prompts —
no raw terminal mode, no extra dependency — where entering nothing keeps all
tasks. The questions and their order match.

Adding the menu is also what prompted giving `--software-management`,
`--shared-folders`, `--hosts-file`, `--dns-settings` and `--scheduled-tasks`
their own flags. They previously ran only under `--all`, so the menu could not
have offered them individually.

---

## 9. Reporting and the run log

After every run:

**Per-task summary table** — task, status, completion rate, confidence, message,
time, with error details on a continuation row. Colour-coded at 90% and 70%.

**Overall statistics** — tasks passed, tasks verified, item totals, and two bar
charts.

**How confidence is computed:**

```
per task:     starts at 100, −30 if verification failed          (floor 50)
overall:      weighted by items attempted, else the plain average
              then scaled by (0.7 + 0.3 × fraction of tasks verified)
```

So a run where nothing verified caps out at 70%, and the closing tip recommends
manual verification below 90%.

**Completion rate** is `(succeeded + skipped) / attempted`, falling back to the
task's own success where no counts were reported.

---

## 10. Safety design

Collected in one place, because most of it exists in response to something that
actually went wrong.

| Guard | What it prevents |
|---|---|
| **Bare launch does nothing destructive** | "No task flag" used to mean "run every task", so double-clicking the executable began a full destructive run. It now opens the menu, or prints help. |
| **Unknown arguments are rejected (exit 2)** | Combined with the above, a typo — or `--help`, which was not a flag — started that same run. |
| **Empty authorised set aborts user deletion** | A README that failed to parse would otherwise delete every account on the image. |
| **Critical ∩ prohibited = ∅** | Enforced in the parser *and* when the service lists are built. Disabling a scored critical service is the costliest available mistake. |
| **CCS Client is never stopped** | Special-cased by name in the parser and the service-name map. It is the scoring engine. |
| **The primary `(you)` account keeps its password** | READMEs state plainly that changing it can lock you out of the machine. |
| **System accounts are never modified** | `Administrator`, `DefaultAccount`, `WDAGUtilityAccount`, `SYSTEM`, `LocalService`, `NetworkService`, `Guest`. |
| **The scanner will not delete itself** | The game pattern `riot` matches `cyberPATRIOTautomation.exe`. |
| **`--dry-run` is honoured by every task** | The account-permissions task once ignored it entirely and still disabled Guest. |
| **Verification re-reads the machine** | A `reg add` that exits 0 having written to the wrong hive reports success. |
| **Every generated password is logged** | They are the only way back into the accounts. |
| **DNS is reported, never changed** | Replacing a resolver can disconnect the machine from the scoring engine. |

**The recommended sequence** — and the order the menu presents:

```
1.  --auto-readme --parse-readme      read-only; confirms the README parsed
2.  --auto-readme --all --dry-run     preview; changes nothing
3.  --auto-readme --all               apply
```

Step 1 is not optional in spirit. If it lists no administrators or users, the
README did not parse, and user management will refuse to act rather than treat
every account on the image as unauthorised.

---

## 11. Build, test, publish

### C#

```bash
dotnet build src/PinnacleCyPat.csproj              # both TFMs
dotnet test  tests/PinnacleCyPat.Tests.csproj      # 172 tests
dotnet csharpier .                                  # format (scripts/format.ps1)
```

**Why it multi-targets.** `net10.0-windows` is the real build. Plain `net10.0`
exists so the parser, model and reporting tests run on a Linux dev box — which is
why `Core/Native/**` is excluded from that TFM and every native call site is
`#if WINDOWS`.

**Publish:**

```bash
dotnet publish src/PinnacleCyPat.csproj -c Release \
  -f net10.0-windows -o publish-win-x64
```

Self-contained, single-file, ReadyToRun, English resources only. The framework
must be named explicitly because the project multi-targets.

`RuntimeIdentifier` is gated on `_IsPublishing` so `build` and `test` stay
RID-agnostic — the test project references this one, and a global RID would make
the test assemblies win-x64 and therefore unrunnable on the host the suite runs
on.

> **Trimming is deliberately off**, despite being the single largest size win
> available (38 MB → 12 MB, with no IL2xxx warnings today). Spectre.Console 0.47
> and System.CommandLine both resolve types by reflection and neither is fully
> trim-annotated, so an absence of warnings is weak evidence rather than proof. A
> trimmed build that loses Spectre's markup rendering fails at run time, during a
> scored round, with nothing said at build time. Enable it once it has been
> exercised end to end on a real Windows host.

Release builds run the test suite automatically, skipped during publish.

### Rust

```bash
cd rust
cargo test                              # 139 tests
cargo clippy --all-targets
cargo build --release
```

**Cross-compiling from Linux** needs the GNU target — `x86_64-pc-windows-msvc`
requires Microsoft's linker:

```bash
rustup target add x86_64-pc-windows-gnu
sudo apt install -y mingw-w64
cargo build --release --target x86_64-pc-windows-gnu
```

> A Linux build never compiles the `#[cfg(windows)]` branches — which is the
> whole of `src/native`, plus `raw_arg` in `command.rs`, `file_attributes` in
> `tasks/prohibited_media.rs` and `USERPROFILE` in `app_config.rs`. Run
> `cargo check --target x86_64-pc-windows-gnu` after touching any of it; it
> type-checks those paths and needs no linker. A clean `cargo test` on Linux
> proves nothing about them.

Release profile: LTO, one codegen unit, `opt-level = "z"`, `panic = "abort"`,
symbols stripped — 2.50 MB → 2.12 MB. Optimising for size rather than speed costs
nothing measurable, because the run is dominated by process spawns, network
fetches and Defender scans.

### Versioning

Bump `<Version>` in the csproj / `version` in `Cargo.toml` with **every**
behavioural change, and record it in `rust/CHANGELOG.md`. The version is stamped
into the run log's header *and* its file name, so a log always identifies the
build that produced it. The build date distinguishes two builds of the same
version. Check a binary with `--version`.
