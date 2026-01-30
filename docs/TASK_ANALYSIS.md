﻿# CyberPatriot Automation - Task Analysis

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


## Unit Tests

All tasks have comprehensive unit tests:

| Test File | Tests | Status |
|-----------|-------|--------|
| `ReadmeParserTests.cs` | 13 | ✅ |
| `ModelsTests.cs` | 12 | ✅ |
| `AppConfigTests.cs` | 8 | ✅ |
| `TasksTests.cs` | 19 | ✅ |
| `SharedFoldersAuditTaskTests.cs` | 2 | ✅ |
| `HostsFileAuditTaskTests.cs` | 2 | ✅ |
| `DnsSettingsAuditTaskTests.cs` | 2 | ✅ |
| `SuspiciousScheduledTasksAuditTaskTests.cs` | 2 | ✅ |
| `NewTasksTests.cs` | 22 | ✅ |
| **Total** | **82** | ✅ |

---

## Documentation Files

| File | Purpose |
|------|---------|
| `README.md` | Main documentation, usage, installation |
| `CONTRIBUTING.md` | How to contribute, coding standards |
| `CLAUDE.md` | AI assistant instructions (Claude) |
| `.github/copilot-instructions.md` | GitHub Copilot instructions |
| `TASK_ANALYSIS.md` | This file - task roadmap |
| `LICENSE` | MIT License |

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
dotnet run -- --all --readme "README.html"

# Run specific tasks
dotnet run -- --firewall --security-hardening

# Scan for prohibited media only
dotnet run -- --media-scan --readme "README.html"

# Dry run to preview changes
dotnet run -- --all --dry-run

# Auto-find README in common locations
dotnet run -- --auto-readme --all
```

---

## Default README Locations

The tool automatically searches for README in:
- C:\Users\Public\Desktop\README.html
- C:\CyberPatriot\README.html
- C:\Users\Public\Documents\README.html
- Current user's desktop
