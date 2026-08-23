// =============================================================================
// PinnacleCyPat - The Windows task list
// Author: Maxwell McCormick
// Copyright 2026 Maxwell McCormick
// SPDX-License-Identifier: Apache-2.0
// =============================================================================

//! Every Windows task, described once.
//!
//! This table is the single source of truth for the flag, the `--help` line,
//! the menu entry and the constructor. It replaced three separate lists - a
//! flag table in `main.rs`, a registration block below it, and a menu table in
//! `tui.rs` - which were free to disagree, and did: a task could reach the CLI
//! without reaching the menu, making it invisible to anyone who double-clicks
//! `RUN.bat`.
//!
//! The order is the order a full run executes them, so the confirmation summary
//! reads as the sequence that is about to happen.

use pinnacle_core::models::ReadmeData;
use pinnacle_core::platform::{Concurrency::*, Platform, TaskSpec};

use crate::tasks::*;

/// The Windows platform.
pub struct Windows;

impl Platform for Windows {
    const NAME: &'static str = "Windows";
    const PRIVILEGED_ROLE: &'static str = "Administrator";
    const ELEVATION_HINT: &'static str =
        "Close this, right-click the executable and choose 'Run as administrator'.";

    fn tasks() -> &'static [TaskSpec] {
        TASKS
    }

    /// Probed by writing to a machine-wide registry key rather than by
    /// inspecting the token - see the trait method for why.
    fn is_privileged() -> bool {
        #[cfg(windows)]
        {
            crate::native::registry::can_write_machine_policy()
        }
        // Off Windows there is no machine to change and nothing this build
        // could do with the answer.
        #[cfg(not(windows))]
        {
            false
        }
    }
}

/// Build a task that wants the README, handing it over when there is one.
macro_rules! with_readme {
    ($task:ty) => {
        |readme: Option<&ReadmeData>| {
            let mut task = <$task>::new();
            if let Some(data) = readme {
                task.set_readme_data(data.clone());
            }
            Box::new(task)
        }
    };
}

/// Build a task that does not read the README.
macro_rules! plain {
    ($task:ty) => {
        |_readme: Option<&ReadmeData>| Box::new(<$task>::new())
    };
}

const TASKS: &[TaskSpec] = &[
    TaskSpec {
        flag: "--password-policy",
        short: "-p",
        help: "Password and lockout policy",
        label: "Password Policy",
        detail: "length, age, history, lockout",
        needs_readme: false,
        concurrency: Sequential,
        build: plain!(PasswordPolicyTask),
    },
    TaskSpec {
        flag: "--account-permissions",
        short: "-a",
        help: "Account permissions and group membership",
        label: "Account Permissions",
        detail: "Guest, password expiry, admins",
        needs_readme: false,
        concurrency: Sequential,
        build: plain!(AccountPermissionsTask),
    },
    TaskSpec {
        flag: "--user-management",
        short: "-u",
        help: "Create, remove and correct user accounts",
        label: "User Management",
        detail: "needs a README",
        needs_readme: true,
        concurrency: Sequential,
        build: with_readme!(UserManagementTask),
    },
    TaskSpec {
        flag: "--service-management",
        short: "-s",
        help: "Enable required and disable insecure services",
        label: "Service Management",
        detail: "disable insecure, protect critical",
        needs_readme: false,
        concurrency: Sequential,
        build: with_readme!(ServiceManagementTask),
    },
    TaskSpec {
        flag: "--audit-policy",
        short: "-t",
        help: "Audit policy and security event logging",
        label: "Audit Policy",
        detail: "event logging and security settings",
        needs_readme: false,
        concurrency: Sequential,
        build: plain!(AuditPolicyTask),
    },
    TaskSpec {
        flag: "--firewall",
        short: "-f",
        help: "Windows Firewall profiles and rules",
        label: "Firewall",
        detail: "profiles, blocked ports, risky rules",
        needs_readme: false,
        concurrency: Sequential,
        build: plain!(FirewallConfigurationTask),
    },
    TaskSpec {
        flag: "--security-hardening",
        short: "-H",
        help: "General security hardening",
        label: "Security Hardening",
        detail: "registry hardening, features",
        needs_readme: false,
        concurrency: Sequential,
        build: with_readme!(SecurityHardeningTask),
    },
    TaskSpec {
        flag: "--group-policy",
        short: "-g",
        help: "Local Security Policy: SMB signing, logon, RDP",
        label: "Local Security Policy",
        detail: "SMB signing, logon, RDP",
        needs_readme: false,
        concurrency: Sequential,
        build: with_readme!(GroupPolicyTask),
    },
    TaskSpec {
        flag: "--media-scan",
        short: "-m",
        help: "Find and remove prohibited media",
        label: "Prohibited Media",
        detail: "deletes matching files permanently",
        needs_readme: false,
        concurrency: Sequential,
        build: with_readme!(ProhibitedMediaTask),
    },
    TaskSpec {
        flag: "--software-updates",
        short: "",
        help: "Update installed software",
        label: "Software Updates",
        detail: "update installed applications",
        needs_readme: false,
        concurrency: Sequential,
        build: with_readme!(SoftwareUpdateTask),
    },
    TaskSpec {
        flag: "--software-management",
        short: "",
        help: "Remove prohibited and install required software",
        label: "Software Management",
        detail: "remove, install, Defender scan",
        needs_readme: true,
        // Sequential, not concurrent: it uninstalls, installs and runs a
        // Defender scan, all of which contend with the service and software
        // work above. Last in the list so that work has finished first.
        concurrency: Sequential,
        // Takes the README by reference rather than by value, so it cannot use
        // the `with_readme!` macro.
        build: |readme| {
            let mut task = SoftwareManagementTask::new();
            if let Some(data) = readme {
                task.set_readme_data(data);
            }
            Box::new(task)
        },
    },
    // The independent audits. These touch disjoint areas - shares, the hosts
    // file, DNS, scheduled tasks - and share no state with each other, so they
    // are the only tasks it is safe to overlap. Everything above them contends
    // for the same accounts, services and registry keys, where concurrent
    // writes would race.
    TaskSpec {
        flag: "--shared-folders",
        short: "",
        help: "Remove shares beyond ADMIN$, C$ and IPC$",
        label: "Shared Folders Audit",
        detail: "removes non-default shares",
        needs_readme: false,
        concurrency: Concurrent,
        build: plain!(SharedFoldersAuditTask),
    },
    TaskSpec {
        flag: "--hosts-file",
        short: "",
        help: "Remove unauthorised hosts file entries",
        label: "Hosts File Audit",
        detail: "removes unauthorised entries",
        needs_readme: false,
        concurrency: Concurrent,
        build: plain!(HostsFileAuditTask),
    },
    TaskSpec {
        flag: "--dns-settings",
        short: "",
        help: "Report public DNS resolvers",
        label: "DNS Settings Audit",
        detail: "reports public resolvers",
        needs_readme: false,
        concurrency: Concurrent,
        build: plain!(DnsSettingsAuditTask),
    },
    TaskSpec {
        flag: "--scheduled-tasks",
        short: "",
        help: "Disable suspicious scheduled tasks",
        label: "Scheduled Tasks Audit",
        detail: "disables suspicious tasks",
        needs_readme: false,
        concurrency: Concurrent,
        build: plain!(SuspiciousScheduledTasksAuditTask),
    },
];

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_task_is_reachable_by_a_well_formed_flag() {
        let mut seen: Vec<&str> = Vec::new();
        for spec in TASKS {
            assert!(
                spec.flag.starts_with("--"),
                "{} is not a long flag",
                spec.flag
            );
            assert!(!spec.label.is_empty(), "{} has no menu label", spec.flag);
            assert!(!spec.help.is_empty(), "{} has no help text", spec.flag);
            assert!(!seen.contains(&spec.flag), "{} is listed twice", spec.flag);
            seen.push(spec.flag);
            if !spec.short.is_empty() {
                assert!(
                    spec.short.starts_with('-') && !spec.short.starts_with("--"),
                    "{} has a malformed short flag: {}",
                    spec.flag,
                    spec.short
                );
                assert!(
                    !seen.contains(&spec.short),
                    "{} reuses the short flag {}",
                    spec.flag,
                    spec.short
                );
                seen.push(spec.short);
            }
        }
    }

    /// `-h` is help. A task claiming it would make `--help` run a remediation,
    /// which is exactly what `--security-hardening` used to do.
    #[test]
    fn no_task_claims_a_reserved_short_flag() {
        for spec in TASKS {
            assert!(
                !matches!(spec.short, "-h" | "-i" | "-V" | "-r" | "-R" | "-d"),
                "{} claims the reserved flag {}",
                spec.flag,
                spec.short
            );
        }
    }

    #[test]
    fn the_tasks_that_are_useless_without_a_readme_say_so() {
        for flag in ["--user-management", "--software-management"] {
            let spec = TASKS.iter().find(|s| s.flag == flag).expect(flag);
            assert!(spec.needs_readme, "{flag} should be marked needs_readme");
        }
    }
}
