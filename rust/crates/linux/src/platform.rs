// =============================================================================
// PinnacleCyPat - The Linux task list
// Copyright 2026 Maxwell McCormick
// SPDX-License-Identifier: Apache-2.0
// =============================================================================

//! Every Linux task, described once - the counterpart of
//! `pinnacle_windows::platform`, and read by the same argument parser, help
//! text and menu.
//!
//! The list is deliberately shorter than the Windows one. A task appears here
//! when it is implemented and proved, not when its Windows equivalent exists:
//! an entry whose task does nothing would be worse than its absence, because
//! the run would report success having changed nothing.

use pinnacle_core::models::ReadmeData;
use pinnacle_core::platform::{Concurrency::*, Platform, TaskSpec};

use crate::tasks::*;

/// The Linux platform.
pub struct Linux;

impl Platform for Linux {
    const NAME: &'static str = "Linux";
    const PRIVILEGED_ROLE: &'static str = "root";
    const ELEVATION_HINT: &'static str = "Re-run with: sudo pinnacle-cypat ...";

    fn tasks() -> &'static [TaskSpec] {
        TASKS
    }

    /// The effective uid, which is the whole answer: `/etc` is root-owned, and
    /// a non-root process cannot write any of it. There is no equivalent of
    /// UAC virtualisation to account for.
    fn is_privileged() -> bool {
        #[cfg(unix)]
        {
            // SAFETY: `geteuid` takes no arguments, touches no memory and
            // cannot fail. It is unsafe only because it is an extern "C" call.
            unsafe { libc_geteuid() == 0 }
        }
        #[cfg(not(unix))]
        {
            false
        }
    }
}

#[cfg(unix)]
unsafe extern "C" {
    /// Declared directly rather than pulling in the `libc` crate for one call.
    #[link_name = "geteuid"]
    fn libc_geteuid() -> u32;
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
        help: "Password complexity, history and lockout, via PAM",
        label: "Password Policy",
        detail: "length, classes, history, lockout",
        needs_readme: false,
        concurrency: Sequential,
        build: plain!(PasswordPolicyTask),
    },
    TaskSpec {
        flag: "--account-permissions",
        short: "-a",
        help: "Passwordless logins, duplicate root, password ageing",
        label: "Account Permissions",
        detail: "empty passwords, uid 0, ageing",
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
        help: "Mask insecure services, protect critical ones",
        label: "Service Management",
        detail: "systemd: mask insecure, protect critical",
        needs_readme: false,
        concurrency: Sequential,
        build: with_readme!(ServiceManagementTask),
    },
    TaskSpec {
        flag: "--audit-policy",
        short: "-t",
        help: "Enable auditd and system logging",
        label: "Audit Policy",
        detail: "auditd, rsyslog, audit rules",
        needs_readme: false,
        concurrency: Sequential,
        build: plain!(AuditPolicyTask),
    },
    TaskSpec {
        flag: "--firewall",
        short: "-f",
        help: "Enable ufw, deny inbound, open what the README needs",
        label: "Firewall",
        detail: "ufw: default deny, allow what is needed",
        needs_readme: false,
        concurrency: Sequential,
        build: with_readme!(FirewallTask),
    },
    TaskSpec {
        flag: "--security-hardening",
        short: "-H",
        help: "Kernel, SSH and account-ageing hardening",
        label: "Security Hardening",
        detail: "sysctl, sshd_config, login.defs",
        needs_readme: false,
        concurrency: Sequential,
        build: with_readme!(SecurityHardeningTask),
    },
    TaskSpec {
        flag: "--media-scan",
        short: "-m",
        help: "Find media files in user directories",
        label: "Prohibited Media",
        detail: "reports; deletes only if the README prohibits",
        needs_readme: false,
        concurrency: Sequential,
        build: with_readme!(ProhibitedMediaTask),
    },
    TaskSpec {
        flag: "--software-updates",
        short: "",
        help: "Upgrade installed packages and enable security updates",
        label: "Software Updates",
        detail: "apt upgrade, unattended-upgrades",
        needs_readme: false,
        concurrency: Sequential,
        build: with_readme!(SoftwareUpdateTask),
    },
    TaskSpec {
        flag: "--software-management",
        short: "",
        help: "Purge prohibited packages, install required ones",
        label: "Software Management",
        detail: "apt purge and install",
        needs_readme: true,
        // Last of the sequential tasks: it purges and installs, both of which
        // contend with the service and update work above.
        concurrency: Sequential,
        // Takes the README by reference, so it cannot use `with_readme!`.
        build: |readme| {
            let mut task = SoftwareManagementTask::new();
            if let Some(data) = readme {
                task.set_readme_data(data);
            }
            Box::new(task)
        },
    },
    TaskSpec {
        flag: "--file-permissions",
        short: "",
        help: "Fix the modes on scored files; report world-writable, setuid and unowned",
        label: "File Permissions Audit",
        detail: "/etc/shadow and friends; reports the rest",
        needs_readme: false,
        // Sequential: it corrects modes on files other tasks are also writing.
        concurrency: Sequential,
        build: plain!(FilePermissionsAuditTask),
    },
    // The independent audits. These read disjoint parts of the machine and
    // share no state, so they are the only tasks it is safe to overlap.
    TaskSpec {
        flag: "--shared-folders",
        short: "",
        help: "Report Samba shares and NFS exports",
        label: "Shared Folders Audit",
        detail: "reports; removes nothing",
        needs_readme: false,
        concurrency: Concurrent,
        build: plain!(SharedFoldersAuditTask),
    },
    TaskSpec {
        flag: "--hosts-file",
        short: "",
        help: "Remove unauthorised /etc/hosts entries",
        label: "Hosts File Audit",
        detail: "removes unauthorised entries",
        needs_readme: false,
        concurrency: Concurrent,
        build: plain!(HostsFileAuditTask),
    },
    TaskSpec {
        flag: "--dns-settings",
        short: "",
        help: "Report the resolvers in use",
        label: "DNS Settings Audit",
        detail: "reports public resolvers",
        needs_readme: false,
        concurrency: Concurrent,
        build: plain!(DnsSettingsAuditTask),
    },
    TaskSpec {
        flag: "--scheduled-tasks",
        short: "",
        help: "Report cron jobs and timers that look like persistence",
        label: "Scheduled Tasks Audit",
        detail: "reports; disables nothing",
        needs_readme: false,
        concurrency: Concurrent,
        build: plain!(ScheduledTasksAuditTask),
    },
];

#[cfg(test)]
mod tests {
    use super::*;

    /// The same shape check the Windows table gets. Both platforms feed one
    /// argument parser, so a malformed row breaks the CLI rather than just this
    /// crate.
    #[test]
    fn every_task_is_reachable_by_a_well_formed_flag() {
        let mut seen: Vec<&str> = Vec::new();
        for spec in TASKS {
            assert!(
                spec.flag.starts_with("--"),
                "{} is not long-form",
                spec.flag
            );
            assert!(!spec.label.is_empty(), "{} has no menu label", spec.flag);
            assert!(!spec.help.is_empty(), "{} has no help text", spec.flag);
            assert!(!seen.contains(&spec.flag), "{} is listed twice", spec.flag);
            seen.push(spec.flag);
        }
        assert!(!seen.is_empty(), "the platform offers no tasks at all");
    }

    /// A flag that means one thing on Windows must not mean something else
    /// here. Someone moving between images should not have to relearn it, and
    /// the run log of a Linux round should be readable next to a Windows one.
    #[test]
    fn shared_flags_keep_their_windows_spelling() {
        for (flag, label) in [
            ("--hosts-file", "Hosts File Audit"),
            ("--password-policy", "Password Policy"),
            ("--account-permissions", "Account Permissions"),
            ("--user-management", "User Management"),
            ("--service-management", "Service Management"),
            ("--audit-policy", "Audit Policy"),
            ("--firewall", "Firewall"),
            ("--security-hardening", "Security Hardening"),
            ("--media-scan", "Prohibited Media"),
            ("--software-updates", "Software Updates"),
            ("--software-management", "Software Management"),
            ("--dns-settings", "DNS Settings Audit"),
            ("--shared-folders", "Shared Folders Audit"),
            ("--scheduled-tasks", "Scheduled Tasks Audit"),
        ] {
            let spec = TASKS
                .iter()
                .find(|s| s.flag == flag)
                .unwrap_or_else(|| panic!("{flag} is missing"));
            assert_eq!(spec.label, label, "{flag} is labelled differently here");
        }
    }

    /// Short flags must mean the same thing on both platforms too - `-p` for
    /// password policy, `-f` for firewall - or muscle memory becomes a hazard.
    #[test]
    fn shared_short_flags_match_the_windows_ones() {
        for (flag, short) in [
            ("--password-policy", "-p"),
            ("--account-permissions", "-a"),
            ("--user-management", "-u"),
            ("--service-management", "-s"),
            ("--audit-policy", "-t"),
            ("--firewall", "-f"),
            ("--security-hardening", "-H"),
            ("--media-scan", "-m"),
        ] {
            let spec = TASKS.iter().find(|s| s.flag == flag).unwrap();
            assert_eq!(spec.short, short, "{flag} has the wrong short flag");
        }
    }

    /// Group Policy has no Linux equivalent, and the seam exists precisely so
    /// that its absence can be honest rather than a stub reporting success.
    #[test]
    fn there_is_no_group_policy_task() {
        assert!(!TASKS.iter().any(|s| s.flag == "--group-policy"));
    }

    /// Only tasks that read the machine without writing may overlap. Anything
    /// that changes accounts, services or packages contends with the rest.
    #[test]
    fn only_read_mostly_audits_run_concurrently() {
        let concurrent: Vec<&str> = TASKS
            .iter()
            .filter(|s| s.concurrency == Concurrent)
            .map(|s| s.flag)
            .collect();
        assert_eq!(
            concurrent,
            [
                "--shared-folders",
                "--hosts-file",
                "--dns-settings",
                "--scheduled-tasks"
            ]
        );
    }
}
