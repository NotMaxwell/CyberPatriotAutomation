﻿# PinnacleCyPat - Task Analysis

## Implemented Tasks

### 1. Password Policy Task ✅
- Enforces password complexity requirements
- Sets minimum/maximum password age
- Configures password history
- Sets account lockout policy

### 2. Account Permissions Task ✅
- Audits user account permissions
- Checks for unauthorized admin accounts
- Verifies account security settings

### 3. User Management Task ✅
- Deletes unauthorized users
- Creates required users
- Fixes admin/user permissions
- Updates passwords
- Configures group memberships

### 4. Service Management Task ✅
- Disables insecure services (60+ services)
- Protects critical services
- Disables Windows features (SMB1, Telnet, etc.)

### 5. Audit Policy Task ✅
- Enables all audit categories
- Configures PowerShell logging
- Sets event log sizes
- Configures security registry settings

### 6. Firewall Configuration Task ✅
- Enables firewall for all profiles
- Blocks 26+ insecure ports
- Disables risky firewall rules
- Configures firewall logging

### 7. Security Hardening Task ✅
- 40+ registry security settings
- UAC configuration
- Remote Desktop/Assistance disable
- Windows Defender configuration
- LSA protection
- AutoRun/AutoPlay disable
- Memory protection

### 8. Prohibited Media Task ✅

### 9. Group Policy Task ✅
- Hides last user name on login screen
- Requires Ctrl+Alt+Del for login
- Disables Internet Connection Sharing (ICS)
- Sets additional local security policies (e.g., restrict anonymous access)


## Tests

| Suite | Tests | Covers |
|-------|------:|--------|
| `src/**` unit tests | 95 | tables, matching, HTML, command, config, engine, session |
| `main.rs` | 7 | flag parsing and the unknown-argument check |
| `tests/readme_parser_tests.rs` | 20 | parser behaviour, case by case |
| `tests/tasks_tests.rs` | 26 | task construction and dry-run |
| `tests/audit_tasks_tests.rs` | 14 | the four independent audits |
| `tests/app_config_tests.rs` | 9 | README discovery |
| `tests/models_tests.rs` | 8 | data models |
| `tests/corpus_tests.rs` | 2 | **every README fixture, snapshotted** |
| `tests/ledger_sample.rs` | 1 | remediation-ledger rendering |
| **Total** | **182** | |

> The corpus suite counts as two tests but covers five whole documents, and it
> is the one to extend: `cargo test --test corpus_tests` re-parses every README
> in `rust/crates/core/tests/corpus/` and diffs the entire result against its snapshot.
> Adding a real competition README there is the highest-value thing anyone can
> do for the parser — it found two bugs on its first run.

---

## Documentation Files

| File | Purpose |
|------|---------|
| `README.md` | Main documentation, usage, installation |
| `ARCHITECTURE.md` | Full reference: every task and utility, in detail |
| `CONTRIBUTING.md` | How to contribute, coding standards |
| `CLAUDE.md` | AI assistant instructions (Claude) |
| `.github/copilot-instructions.md` | GitHub Copilot instructions |
| `TASK_ANALYSIS.md` | This file - task roadmap |
| `LICENSE` | Apache License 2.0 |

---

## Gaps from the CP18 Training Round 2 answer keys

Four answer keys added to `ReferenceMaterial/` on 2026-11-23: Ubuntu 22
(`CP18_Ubuntu22_Training2_Answer_Key.pdf`), Mint 21
(`CP18_Mint21_Training2_Answer_Key.pdf`), Windows 11 (`windowsAnswereKey.pdf`)
and Server 2019 (`windowsServer.pdf`). The two Windows PDFs are scanned images.
Each item below was a scored item or penalty the tool missed or got wrong. All
are implemented in 1.24.0 (see `docs/ARCHITECTURE.md` §4.16–4.17). Items the tool
already handled are not listed. Their READMEs were not
supplied, so README-driven items are tested against synthetic README data.

### Linux: accounts and groups
- [x] **Apply README group requirements.** `linux/tasks/user_management.rs`
  parses `group_requirements` but never acts on them: no group is created and
  no member is added. Scored on Ubuntu 22 T2 (mariya → pioneers, 5 pts), Mint 21
  T2 (create spider, 3 pts; add may/peni/stan/miguel, 4 pts) and the CP19
  Exhibition Round (candace → firesidegirls, 8 pts, whose existing test only
  checks the parser).
- [x] **Hidden users with uid < 1000.** Mint 21 T2 plants an unauthorised user
  below uid 1000. `Account::is_human` excludes it, so it is never considered for
  removal.
- [x] **Lock root when its password is blank** (`passwd -l root`). Mint 21 T2,
  4 pts. Account Permissions locks only passwordless *human* accounts.
- [x] **Minimum password age 1–3 days.** The key says `PASS_MIN_DAYS` must be 1–3
  inclusive (Ubuntu 22 T2, 3 pts). The tool writes 7.

### Linux: PAM
- [x] **Remove `nullok` from `common-auth`.** Ubuntu 22 T2 (3 pts), Mint 21 T2
  (4 pts). Must run after the task's own `pam-auth-update` calls, which restore it.
- [x] **`minlen` on the PAM line itself.** Ubuntu's key appends `minlen=10` to the
  `pam_pwquality` line, Mint's to the `pam_unix` line. The tool sets it only in
  `pwquality.conf`.
- [x] **`remember=` on `pam_unix`.** Mint 21 T2 (3 pts) scores `remember=3` on the
  `pam_unix` line. The tool enforces history only through `pam_pwhistory`.

### Linux: system hardening
- [x] **Contrary values in `/etc/sysctl.conf`.** Both keys plant
  `net.ipv4.ip_forward=1` / `tcp_syncookies=0` in `/etc/sysctl.conf`. That file
  is read after `sysctl.d` (`sysctl --system`, and `99-sysctl.conf` sorts after
  `99-pinnacle.conf`), so the drop-in loses at boot. Ubuntu 22 T2 items 11–12
  (8 pts), Mint 21 T2 items 15–16 (8 pts).
- [x] **Contrary values in `sshd_config`.** Ubuntu 22 T2 sets
  `PermitRootLogin yes` in the main file (5 pts). Rewrite contrary active lines
  in the main file and in earlier drop-ins, since sshd takes the first value.
- [x] **Packages.** Purge `aisleriot` (Ubuntu 22 T2, 4 pts), `doona` and `xprobe`
  (Mint 21 T2, 3 pts each). Map README "X2Go" to `x2goserver` (Ubuntu 22 T2,
  5 pts).
- [x] **Mint: Update Manager applies updates automatically** (Mint 21 T2, 3 pts).
- [x] **Apache: `ServerSignature Off`, `ServerTokens Prod`** when Apache is
  installed (the same item is scored on Windows 11 T2).

### Linux: backdoors and prohibited files
- [x] **Backdoor listeners.** Ubuntu 22 T2: `nc.traditional` listening on 1337,
  launched from `/etc/crontab` (5 pts). Mint 21 T2: `/usr/share/zod/kneelB4zod.py`
  listening on 1337 (6 pts). Nothing detects a listening process today.
- [x] **Hacking-tool archives outside `/home`.** Mint 21 T2:
  `/usr/games/pyrdp-master.zip` (4 pts). The Linux media scan has no
  hacking-tool patterns at all.
- [x] **Don't delete a critical service's data.** Mint 21 T2 penalty (−5): "Important
  files removed from public FTP directories". `/srv` is a media search root, and
  vsftpd is critical on that image.

### Windows
- [x] **WinRM service refuses unencrypted traffic** (`AllowUnencryptedTraffic = 0`).
  Windows 11 T2.
- [x] **Lockout threshold below 5 is a penalty** (Windows 11 T2, Server 2019 T2,
  −4). `password_policy.rs` treats 1–4 as compliant and leaves them.
- [x] **Apache `ServerSignature Off`** in `C:\Apache24\conf\httpd.conf` (Windows 11 T2).
- [x] **Prohibited software:** BitTorrent (Server 2019 T2), Burp Suite and Nmap
  (Windows 11 T2), Wireshark (Server 2019 T2; *required* on Windows 11 T2, so the
  README must win).
- [x] **Folder-only installs.** Jellyfin in `C:\Program Files\Jellyfin` and Nmap in
  `C:\Program Files (x86)\Nmap` are removed by deleting the folder. Burp Suite and
  Python by deleting a desktop shortcut. Removal through uninstall registry entries
  alone misses them.
- [x] **Update apps Chocolatey did not install.** Chrome, Notepad++ (Windows 11 T2)
  and Firefox (Server 2019 T2). `choco outdated` lists only choco-managed packages.
  Penalty if the app ends up outside its default location.
- [x] **Hacking-tool files:** `brutus-aet2-darknet.zip` in Public Downloads (Server
  2019 T2) matches no pattern. README-required software (Wireshark) must be exempt
  from the file patterns.
- [x] **Domain controller shares.** The share audit would remove `NETLOGON` and
  `SYSVOL` on a Server image that is a DC.

### Tests
- [x] Encode each of the four keys as an answer-key test file, one test per
  scored item, like `crates/linux/tests/answer_key.rs`: `answer_key_*_training2.rs`
  in `crates/linux/tests/` and `crates/windows/tests/`. A few Windows items (the
  authorised-account diff, Guest and password-expiry checks, SMB signing and
  firewall profiles) are still pinned at the task row, because their decisions
  live inside `execute()`. The files' `PRIVATE_DECISION` lists name them.

---

## Tasks Identified from Checklists (Not Yet Implemented)

These tasks were identified from the Windows Checklist and waffleWindowsScript but may need manual intervention or future implementation:

### Network/Shares
- [x] Check shared folders (fsmgmt.msc) - only ADMIN$, C$, IPC$ should exist
- [x] Check hosts file for suspicious entries
- [x] Verify DNS settings

### Browser Security
- [ ] Firefox cookie settings
- [ ] Browser updates (Firefox, Chrome, Edge)
- [ ] Clear browser data

### Software Management
- [x] Remove prohibited software via Programs and Features
- [x] Install/update required software
- [x] Malware scan with Windows Defender

### Group Policy (gpedit.msc)
- [x] Don't display last user name
- [x] Require Ctrl+Alt+Del
- [x] ICS (Internet Connection Sharing) disable via GPO
- [x] Additional local security policies

### Forensic Questions
- [ ] Hash calculation helper
- [ ] Base64/Hex decoder
- [ ] Hidden file finder
- [ ] Image steganography detection

### IIS/Web Server
- [ ] Disable IIS features (already partially covered in Security Hardening)
- [ ] Remove web server components if not needed

### Scheduled Tasks
- [x] Review and disable suspicious scheduled tasks
- [x] Check Task Scheduler for unauthorized entries

### Advanced
- [ ] Process analysis with Process Explorer
- [ ] Network monitoring with TCPView
- [ ] Registry analysis for persistence mechanisms

---

## Ports Blocked by Firewall Task

| Port | Protocol | Service |
|------|----------|---------|
| 20 | TCP | FTP Data |
| 21 | TCP | FTP Control |
| 22 | TCP | SSH |
| 23 | TCP | Telnet |
| 25 | TCP | SMTP |
| 69 | UDP | TFTP |
| 110 | TCP | POP3 |
| 135 | TCP | RPC |
| 137-139 | TCP/UDP | NetBIOS |
| 143 | TCP | IMAP |
| 161-162 | UDP | SNMP |
| 389 | TCP | LDAP |
| 445 | TCP | SMB |
| 512-514 | TCP | rexec/rlogin/rsh |
| 1433-1434 | TCP/UDP | MS SQL |
| 3306 | TCP | MySQL |
| 3389 | TCP | RDP |
| 5900-5902 | TCP | VNC |

---

## Services Disabled

The Service Management Task disables 60+ potentially insecure services including:
- Remote Desktop (TermService, SessionEnv, UmRdpService)
- Remote Registry
- Telnet (TlntSvr)
- FTP (ftpsvc, Msftpsvc)
- SNMP
- Network Discovery (SSDPSRV, upnphost)
- File Sharing (SharedAccess, HomeGroup)
- Xbox services
- And many more...

---

## Media File Extensions Scanned

The Prohibited Media Task scans for:

**Audio:** .mp3, .wav, .wma, .aac, .flac, .ogg, .m4a, .aiff, .midi

**Video:** .mp4, .avi, .mkv, .mov, .wmv, .flv, .mpeg, .webm

**Other:** .gif (animated), .m3u (playlists), .torrent

---

## Hacking Tool Patterns Detected

The scanner looks for files containing:
- cain, abel, wireshark, nmap, metasploit
- mimikatz, pwdump, hashcat, aircrack
- keylogger, trojan, backdoor, rootkit
- hack, crack, keygen, exploit, payload
- cheat, aimbot, trainer

---

## Usage Examples

```powershell
# Run all tasks
cargo run -- --all --readme "README.html"

# Run specific tasks
cargo run -- --firewall --security-hardening

# Scan for prohibited media only
cargo run -- --media-scan --readme "README.html"

# Dry run to preview changes
cargo run -- --all --dry-run

# Auto-find README in common locations
cargo run -- --auto-readme --all
```

---

## Default README Locations

On a standard competition image the README is **not a file on disk**:
`C:\CyberPatriot\README.url` is an Internet Shortcut naming a remote `https://`
document, which is what the competitor's browser opens — `C:\CyberPatriot\`
contains no `README.html`. Auto-discovery therefore resolves shortcuts rather
than looking only for literal paths. Search order:

1. A README shortcut (`.url` or `.lnk`) on the current user's desktop, then the
   common/Public desktop
2. `C:\CyberPatriot\README.url`, then `C:\CyberPatriot\README.html`
3. `C:\Users\Public\Desktop\README.*` and `C:\Users\Public\Documents\README.html`
4. The current user's desktop, then every user's desktop

Shortcuts **chain** (desktop `.lnk` → `README.url` → the document) and are
followed to the end, bounded so a shortcut loop terminates. A remote target is
downloaded. The URL is unique per image and changes every competition, so it is
read from the shortcut at run time and never hard-coded.

> Note: shortcut resolution is implemented
> (`app_config::find_readme_file`). The retired C# `AppConfig.FindReadmeFile`
> only checks the literal paths above.
