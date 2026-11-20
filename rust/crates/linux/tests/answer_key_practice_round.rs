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
use pinnacle_linux::tasks::{
    account_permissions, firewall, password_policy, prohibited_media, software_management,
};

fn prohibited_without_readme() -> Vec<String> {
    software_management::prohibited_packages(None)
        .into_iter()
        .map(|(name, _)| name)
        .collect()
}

/// **Guest account is disabled: 5 pts.**
///
///
/// LightDM allows guests unless told otherwise, and `lightdm.conf` is read
/// after every drop-in - so the drop-in the tool writes is not enough alone
/// when `lightdm.conf` says true, which is why the task also rewrites it.
#[test]
fn item_guest_account_is_disabled() {
    let dropin = (
        "50-pinnacle-no-guest.conf".to_string(),
        "[Seat:*]\nallow-guest=false\n".to_string(),
    );
    let planted = (
        "lightdm.conf".to_string(),
        "[Seat:*]\nallow-guest=true\n".to_string(),
    );
    let fixed = (
        "lightdm.conf".to_string(),
        "[Seat:*]\nallow-guest=false\n".to_string(),
    );

    assert!(
        account_permissions::effective_allow_guest(&[]),
        "LightDM's default allows guests"
    );
    assert!(account_permissions::effective_allow_guest(&[
        dropin.clone(),
        planted
    ]));
    assert!(!account_permissions::effective_allow_guest(&[
        dropin, fixed
    ]));
}

/// **A minimum password length is required: 6 pts.**
///
///
/// `minlen` in `pwquality.conf` does nothing unless `pam_pwquality` is in the
/// password stack, and Debian does not install it - so the task installs it,
/// and its verify step treats a minlen without the module as not enforced.
#[test]
fn item_minimum_password_length_is_required() {
    let without = "password\t[success=1 default=ignore]\tpam_unix.so obscure yescrypt\n";
    let with = "password\trequisite\tpam_pwquality.so retry=3\n\
                password\t[success=1 default=ignore]\tpam_unix.so obscure use_authtok yescrypt\n";
    assert!(!password_policy::minlen_is_effective(without, Some("14")));
    assert!(!password_policy::minlen_is_effective(with, Some("8")));
    assert!(password_policy::minlen_is_effective(with, Some("14")));
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
