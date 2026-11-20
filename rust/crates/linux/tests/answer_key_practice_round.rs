// =============================================================================
// PinnacleCyPat - A Linux practice round's scoring report, as tests
// Copyright 2026 Maxwell McCormick
// SPDX-License-Identifier: Apache-2.0
// =============================================================================

//! The passed checks from a real Linux practice round's scoring report. Its
//! README is not available, so only the items that do not depend on README
//! text are automated here; README-driven ones (unauthorised users, admins,
//! insecure password) are covered by `answer_key.rs`.
//!
//! Written against the tool's decisions (tables, pure functions, task
//! constructors), not `execute()`, like `answer_key.rs`.

use pinnacle_core::models::ReadmeData;
use pinnacle_linux::knowledge::{ALWAYS_PROHIBITED, HARDENING_SETTINGS, PROHIBITED_SERVICES};
use pinnacle_linux::tasks::{firewall, prohibited_media, software_management};

fn prohibited_without_readme() -> Vec<String> {
    software_management::prohibited_packages(None)
        .into_iter()
        .map(|(name, _)| name)
        .collect()
}

/// **Guest account is disabled: 5 pts.**
///
/// Pending: another agent owns the account tasks. It must make the tool turn
/// off LightDM `allow-guest` (and GDM guest login) and the guest session.
#[test]
#[ignore = "pending: account_permissions agent must disable the guest account (lightdm allow-guest=false)"]
fn item_guest_account_is_disabled() {
    unimplemented!("expose the guest-account decision and assert it here");
}

/// **A minimum password length is required: 6 pts.**
///
/// Pending: another agent owns password_policy. It must make the tool require
/// a minimum length (pam_unix/pam_pwquality `minlen`, login.defs `PASS_MIN_LEN`).
#[test]
#[ignore = "pending: password_policy agent must set a minimum password length (pam_pwquality minlen)"]
fn item_minimum_password_length_is_required() {
    unimplemented!("expose the minlen decision and assert it here");
}

/// **UFW protection enabled: 6 pts.**
///
/// The enable is `ufw --force enable`, gated on ssh staying open so enabling
/// default-deny cannot cut the competitor off.
#[test]
fn item_ufw_protection_is_enabled() {
    let task = firewall::FirewallTask::new();
    assert!(task.ports_to_open().contains(&"22/tcp"));
    assert!(firewall::is_active("Status: active\n"));
    assert!(!firewall::is_active("Status: inactive\n"));
}

/// **FTP service has been disabled or removed: 6 pts.**
///
/// Any of the three common FTP daemons may be the planted one.
#[test]
fn item_ftp_service_is_disabled_or_removed() {
    for unit in ["vsftpd.service", "proftpd.service", "pure-ftpd.service"] {
        assert!(
            PROHIBITED_SERVICES.iter().any(|(u, _)| *u == unit),
            "{unit} must be on the mask list"
        );
    }
}

/// **Prohibited MP3 files are removed: 5 pts.**
///
/// Deletion is only authorised by a README that prohibits media; the
/// extension itself must always be recognised.
#[test]
fn item_prohibited_mp3_files_are_removed() {
    assert!(prohibited_media::is_media(std::path::Path::new(
        "/home/user/Music/song.mp3"
    )));
    assert!(prohibited_media::is_media(std::path::Path::new(
        "/home/user/Music/SONG.MP3"
    )));
}

/// **Prohibited software Ettercap removed: 5 pts.**
///
/// `ettercap-common` ships /usr/bin/ettercap, so purging only the front ends
/// does not remove the tool.
#[test]
fn item_prohibited_software_ettercap_is_removed() {
    let all = prohibited_without_readme();
    for package in [
        "ettercap-common",
        "ettercap-text-only",
        "ettercap-graphical",
    ] {
        assert!(all.iter().any(|p| p == package), "{package} not prohibited");
    }
}

/// **Prohibited software Freeciv removed: 5 pts.**
///
/// Without a README, and with one that names it, every freeciv package goes.
#[test]
fn item_prohibited_software_freeciv_is_removed() {
    let all = prohibited_without_readme();
    for package in [
        "freeciv",
        "freeciv-client-gtk3",
        "freeciv-server",
        "freeciv-data",
    ] {
        assert!(all.iter().any(|p| p == package), "{package} not prohibited");
    }
    let readme = ReadmeData {
        prohibited_software: vec!["Freeciv".to_string(), "Ettercap".to_string()],
        ..Default::default()
    };
    let with_readme: Vec<String> = software_management::prohibited_packages(Some(&readme))
        .into_iter()
        .map(|(n, _)| n)
        .collect();
    assert!(with_readme.iter().any(|p| p == "freeciv-client-gtk3"));
    assert!(with_readme.iter().any(|p| p == "ettercap-common"));
}

/// **SSH does not permit empty passwords: 6 pts.**
#[test]
fn item_ssh_does_not_permit_empty_passwords() {
    let setting = HARDENING_SETTINGS
        .iter()
        .find(|s| s.key == "PermitEmptyPasswords")
        .expect("PermitEmptyPasswords must be a hardening setting");
    assert_eq!(setting.value, "no");
}

/// The ALWAYS_PROHIBITED entries this report relies on exist exactly once.
#[test]
fn the_report_packages_are_each_listed_once() {
    for package in ["ettercap-common", "freeciv"] {
        let n = ALWAYS_PROHIBITED
            .iter()
            .filter(|(p, _)| *p == package)
            .count();
        assert_eq!(n, 1, "{package}");
    }
}
