# CyberPatriot Automation Tool

[![.NET](https://img.shields.io/badge/.NET-10.0-512BD4)](https://dotnet.microsoft.com/)
[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](LICENSE)
[![Tests](https://img.shields.io/badge/Tests-Passing-brightgreen)]()
[![Author](https://img.shields.io/badge/Author-Maxwell%20McCormick-blue)]()

**Author:** Maxwell McCormick  
**Copyright:** © 2026 Maxwell McCormick  
**License:** Apache License 2.0

A comprehensive C# console application that automates CyberPatriot competition security hardening tasks for Windows systems.

---

## 📜 Canonical Source & Trademark Notice

> **This repository is the canonical and official source of the CyberPatriot Automation Tool, authored and maintained by Maxwell McCormick.**
>
> Forks and derivative works are permitted under the Apache License 2.0 but are **not endorsed or maintained by the author** unless explicitly stated.
>
> **Trademark:** "CyberPatriot Automation Tool" is an unregistered trademark of Maxwell McCormick. Use of the name or branding in derivative works is not permitted without permission. See [NOTICE](NOTICE) for details.

---

## 🚀 Quick Start

**Easy Mode (Recommended):**
Simply double-click `RUN.bat` and follow the menu!

**Command Line:**
```powershell
git clone https://github.com/maxwellmccormick/CyberPatriotAutomation.git
cd CyberPatriotAutomation

# Build and run
dotnet build
cd src
dotnet run -- --all --dry-run
```

# Clone the repository
git clone https://github.com/NotMaxwell/CyberPatriotAutomation.git
cd CyberPatriotAutomation

# Build and run
dotnet build
cd src
dotnet run -- --all --dry-run
```

## ✨ Features

| Feature | Description |
|---------|-------------|
| **README Parser** | Extracts users, services, software from competition README |
| **Password Policy** | Enforces NIST SP 800-63B compliant password policies |
| **User Management** | Creates, deletes, and fixes user permissions |
| **Service Hardening** | Disables 60+ insecure services |
| **Firewall Config** | Blocks 26+ dangerous ports |
| **Security Hardening** | Applies 40+ registry security settings |
| **Media Scanner** | Finds and removes prohibited files with backup |
| **Audit Policies** | Enables comprehensive Windows auditing |

## 📋 Prerequisites

- [.NET 10.0 SDK](https://dotnet.microsoft.com/download/dotnet/10.0) or later
- Windows 10/11 or Windows Server 2019+
- Administrator privileges

## 🔧 Installation

### Option 1: Clone and Build

```powershell
git clone https://github.com/yourusername/CyberPatriotAutomation.git
cd CyberPatriotAutomation

# Restore dependencies
dotnet restore

# Build
dotnet build --configuration Release

# Run tests
dotnet test
```

# Clone
git clone https://github.com/NotMaxwell/CyberPatriotAutomation.git
cd CyberPatriotAutomation

# Restore dependencies
dotnet restore

# Build
dotnet build --configuration Release

# Run tests
dotnet test
```

### Option 2: Download Release

Download the latest release from the [Releases](https://github.com/NotMaxwell/CyberPatriotAutomation/releases) page.

## 📖 Usage

### Basic Commands

```powershell
# Run all tasks (dry run - preview only)
dotnet run -- --all --dry-run

# Run all tasks with README
dotnet run -- --readme "C:\Users\Public\Desktop\README.html" --all

# Auto-find README and run all tasks
dotnet run -- --auto-readme --all

# Parse README only (don't run tasks)
dotnet run -- --readme "README.html" --parse-readme
```

### Run Specific Tasks

```powershell
# Password policy enforcement
dotnet run -- --password-policy

# User management (requires README)
dotnet run -- --readme "README.html" --user-management

# Service management
dotnet run -- --service-management

# Firewall configuration
dotnet run -- --firewall

# Security hardening
dotnet run -- --security-hardening

# Media scanner
dotnet run -- --media-scan
```

### Command Line Arguments

| Argument | Short | Description |
|----------|-------|-------------|
| `--readme <file>` | `-r` | Path to competition README file |
| `--auto-readme` | `-R` | Auto-find README in common locations |
| `--parse-readme` | | Only parse and display README data |
| `--dry-run` | `-d` | Preview changes without applying |
| `--no-interactive` | | Run without confirmation prompts |
| `--password-policy` | `-p` | Password policy enforcement |
| `--account-permissions` | `-a` | Account permissions check |
| `--user-management` | `-u` | User management (requires README) |
| `--service-management` | `-s` | Service management |
| `--audit-policy` | `-t` | Audit policy configuration |
| `--firewall` | `-f` | Firewall configuration |
| `--security-hardening` | `-h` | Security hardening |
| `--media-scan` | `-m` | Prohibited media scanner |
| `--all` | | Run all tasks |

## 🧪 Testing

```powershell
# Run all tests
dotnet test

# Run with detailed output
dotnet test -v n

# Run specific test class
dotnet test --filter "FirewallConfigurationTaskTests"

# Generate coverage report
dotnet test --collect:"XPlat Code Coverage"
```

Tests are automatically run on Release builds.

## 📁 Project Structure

```
CyberPatriotAutomation/
├── 📄 RUN.bat                    # Easy-run script (double-click to use!)
├── 📄 RUN.ps1                    # PowerShell run script
├── 📄 LICENSE                    # Apache License 2.0
├── 📄 NOTICE                     # Attribution & trademark notice
├── 📄 README.md                  # This file
├── 📄 .editorconfig              # Code style settings
├── 📁 src/                       # Source code
│   ├── 📄 Program.cs             # Entry point
│   ├── 📄 CyberPatriotAutomation.csproj
│   └── 📁 Core/
│       ├── 📄 AppConfig.cs       # Configuration and defaults
│       ├── 📁 Models/            # Data models
│       ├── 📁 Tasks/             # Security task implementations
│       └── 📁 Utilities/         # Helper classes
├── 📁 tests/                     # Unit tests (xUnit)
├── 📁 scripts/                   # Build and format scripts
│   ├── format.bat                # Code formatter (like Spotless)
│   └── format.ps1
├── 📁 docs/                      # Documentation
│   ├── CLAUDE.md                 # AI assistant instructions
│   ├── CONTRIBUTING.md           # How to contribute
│   └── TASK_ANALYSIS.md          # Task roadmap
└── 📁 SampleData/                # Sample README files
```

## 🔒 Security Features

### Password Policy (NIST SP 800-63B Compliant)

| Setting | Value | Description |
|---------|-------|-------------|
| Minimum Length | 14 chars | Strong password minimum |
| Maximum Age | 60 days | Forced password change |
| History | 24 passwords | Prevents password reuse |
| Lockout Threshold | 5 attempts | Account lockout trigger |
| Lockout Duration | 30 minutes | Auto-unlock time |

### Ports Blocked by Firewall

| Port | Service |
|------|---------|
| 20-21 | FTP |
| 22 | SSH |
| 23 | Telnet |
| 25 | SMTP |
| 69 | TFTP |
| 135 | RPC |
| 137-139 | NetBIOS |
| 161-162 | SNMP |
| 445 | SMB |
| 3389 | RDP |
| 5900-5902 | VNC |

### Services Disabled (60+)

- Remote Desktop, Remote Registry, Remote Access
- Telnet, FTP, SMTP, SNMP
- Xbox services, HomeGroup
- Network Discovery (SSDP, UPnP)
- And many more...

## 🤝 Contributing

We welcome contributions! Please follow these steps:

1. **Fork** the repository
2. **Create** a feature branch: `git checkout -b feature/amazing-feature`
3. **Write tests** for your changes
4. **Commit** your changes: `git commit -m 'Add amazing feature'`
5. **Push** to the branch: `git push origin feature/amazing-feature`
6. **Open** a Pull Request

### Development Guidelines

- Follow Microsoft C# coding conventions
- Use `async/await` for I/O operations
- All new features require unit tests
- Use Spectre.Console for UI output
- Tasks must inherit from `BaseTask`

### Adding a New Task

1. Create task in `Tasks/` directory
2. Inherit from `BaseTask`
3. Implement `ReadSystemStateAsync()`, `ExecuteAsync()`, `VerifyAsync()`
4. Add CLI flag in `Program.cs`
5. Add unit tests in `Tests/`
6. Update this README

## 🤖 AI Assistant Instructions

This project includes instructions for AI assistants:

- **`CLAUDE.md`** - Comprehensive instructions for Claude AI
- **`.github/copilot-instructions.md`** - GitHub Copilot instructions

These files help AI assistants understand the project structure, coding patterns, and contribute effectively.

## 📝 License

This project is licensed under the **Apache License 2.0** - see the [LICENSE](LICENSE) file for details.

### Attribution Requirements

Under Apache 2.0, you must:
- **Retain** all copyright notices and attributions
- **Include** the [NOTICE](NOTICE) file with any distribution
- **State changes** made to the original code

### Trademark

"CyberPatriot Automation Tool" is an unregistered trademark of Maxwell McCormick. Derivative works must be renamed and may not use this branding without permission.

## ⚠️ Disclaimer

This tool is designed for CyberPatriot competition use. Always:

- **Run with `--dry-run` first** to preview changes
- **Backup important data** before running
- **Run as Administrator** for full functionality
- **Never disable CCS Client** - it's the scoring engine

## 📚 Additional Documentation

- [TASK_ANALYSIS.md](TASK_ANALYSIS.md) - Detailed task analysis and roadmap
- [CLAUDE.md](CLAUDE.md) - AI assistant development guide

## 🙏 Acknowledgments

- [Spectre.Console](https://spectreconsole.net/) - Beautiful console UI
- [xUnit](https://xunit.net/) - Testing framework
- [FluentAssertions](https://fluentassertions.com/) - Assertion library
- CyberPatriot community for checklists and best practices
