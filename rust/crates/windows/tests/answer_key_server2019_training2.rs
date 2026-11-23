// =============================================================================
// PinnacleCyPat - The CP18 Server 2019 Training Round 2 answer key, as tests
// Copyright 2026 Maxwell McCormick
// SPDX-License-Identifier: Apache-2.0
// =============================================================================

//! Every scored item and penalty from the Windows Server 2019 Training answer
//! key (`windowsServer.pdf`, a scanned image read by OCR): 23 items and three
//! penalties.
//!
//! **The README is synthetic.** No README was supplied for this round, so
//! [`readme`] builds the `ReadmeData` the key says it contained: authorised
//! users and administrators (`lydia` and `balgruuf` are authorised users,
//! `lydia` not an administrator), Remote Desktop as a critical service, and
//! Firefox as required software. The OCR spells two names inconsistently
//! (`ancano`/`anacano`); the account the key plants is read as `ancano`. Names
//! the key does not give are invented.
//!
//! Windows tests compile and run on Linux, so nothing here is Windows-only.
//!
//! ## What can and cannot be reached from here
//!
//! The Windows crate keeps its task modules private, so the pure decision
//! functions this key exercises (`allowed_shares` and `unauthorized` for the
//! `greybeard` and `C` shares, `lockout_threshold_compliant`, the service
//! tables, the file patterns, `location_shift`) cannot be called from an
//! integration test; their in-module unit tests cover them. This file tests
//! everything public - the `knowledge` tables, the password standards,
//! `readme_services`, `software_matching` and the platform's task table - and
//! pins each other item at its task row, listed in [`PRIVATE_DECISION`] with the
//! function that decides. Making those modules `pub` is all it takes to turn
//! the pins into real decision tests.

use pinnacle_core::Task;
use pinnacle_core::models::{
    AuthorizedUser, PasswordPolicyStandards, ReadmeData, SoftwareRequirement,
};
use pinnacle_core::platform::{Platform, TaskSpec};
use pinnacle_core::software_matching::{matches, resolve_package_id};
use pinnacle_windows::Windows;
use pinnacle_windows::knowledge::{
    ALWAYS_PROHIBITED, PACKAGE_IDS, REGISTRY_SETTINGS, REMOTE_DESKTOP_VALUES, SERVICE_NAME_MAP,
};
use pinnacle_windows::readme_services;

// =============================================================================
// The synthetic README and its helpers
// =============================================================================

fn user(name: &str, password: Option<&str>, is_admin: bool) -> AuthorizedUser {
    AuthorizedUser {
        username: name.to_string(),
        password: password.map(str::to_string),
        is_admin,
        is_primary_user: false,
        notes: None,
    }
}

fn readme() -> ReadmeData {
    ReadmeData {
        title: "CyberPatriot Windows Server 2019 Training README (synthetic)".to_string(),
        operating_system: "Windows Server 2019".to_string(),
        administrators: vec![user("jarl", Some("Whiter0und#Pal@ce"), true)],
        users: vec![
            // The key: "User lydia is not an administrator".
            user("lydia", None, false),
            user("balgruuf", None, false),
        ],
        required_software: vec![SoftwareRequirement {
            name: "Firefox".to_string(),
            should_be_latest: true,
            ..Default::default()
        }],
        critical_services: vec!["Remote Desktop".to_string()],
        ..Default::default()
    }
}

fn task_row(flag: &str) -> &'static TaskSpec {
    Windows::tasks()
        .iter()
        .find(|t| t.flag == flag)
        .unwrap_or_else(|| panic!("no task registered for {flag}"))
}

fn build(flag: &str) -> Box<dyn Task> {
    (task_row(flag).build)(Some(&readme()))
}

fn registry_value(path: &str, name: &str) -> Option<&'static str> {
    REGISTRY_SETTINGS
        .iter()
        .find(|(p, n, ..)| p.eq_ignore_ascii_case(path) && n.eq_ignore_ascii_case(name))
        .map(|(_, _, _, value, _)| *value)
}

const LSA: &str = r"HKLM\SYSTEM\CurrentControlSet\Control\Lsa";
const WINDOWS_UPDATE_AU: &str = r"HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU";
const TERMINAL_SERVER: &str = r"HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server";

fn prohibited_by_default(display_name: &str) -> bool {
    ALWAYS_PROHIBITED
        .iter()
        .any(|term| matches(display_name, term))
}

fn required_by_readme(display_name: &str) -> bool {
    readme()
        .required_software
        .iter()
        .any(|r| matches(display_name, &r.name))
}

fn is_authorised(name: &str) -> bool {
    let data = readme();
    data.administrators
        .iter()
        .chain(&data.users)
        .any(|u| u.username.eq_ignore_ascii_case(name))
}

// =============================================================================
// Scored items
// =============================================================================

/// **3) Removed unauthorized user ancano.** In no README list. User Management
/// removes what the README does not authorise; the diff is private, so this
/// pins the README fact and that the task exists and needs the README.
#[test]
fn item_03_ancano_is_unauthorised() {
    assert!(!is_authorised("ancano"));
    assert!(task_row("--user-management").needs_readme);
    assert!(!build("--user-management").name().is_empty());
}

/// **4) Removed unauthorized user tolfdir.**
#[test]
fn item_04_tolfdir_is_unauthorised() {
    assert!(!is_authorised("tolfdir"));
    assert!(task_row("--user-management").needs_readme);
}

/// **5) User lydia is not an administrator.** An authorised user who is not an
/// authorised administrator: she keeps her account and loses `Administrators`.
#[test]
fn item_05_lydia_is_a_user_but_not_an_administrator() {
    let data = readme();
    assert!(data.users.iter().any(|u| u.username == "lydia"));
    assert!(!data.administrators.iter().any(|u| u.username == "lydia"));
}

/// **6) User balgruuf has a password.** Account Permissions finds enabled
/// accounts with no password; pinned at the task row (the check is inside
/// `execute()`).
#[test]
fn item_06_blank_passwords_are_handled_by_account_permissions() {
    let row = task_row("--account-permissions");
    assert!(!row.detail.is_empty());
    assert!(
        is_authorised("balgruuf"),
        "so he is kept and given a password"
    );
    assert!(!build("--account-permissions").name().is_empty());
}

/// **7) A secure maximum password age exists** (the key sets 90 days). The
/// standard is at most 90, and not "never".
#[test]
fn item_07_maximum_password_age_is_at_most_ninety_days() {
    assert!((1..=90).contains(&PasswordPolicyStandards::MAX_PASSWORD_AGE));
}

/// **8) Store passwords using reversible encryption [Disabled].**
#[test]
fn item_08_reversible_encryption_is_disabled() {
    const { assert!(PasswordPolicyStandards::REVERSIBLE_ENCRYPTION_DISABLED) };
}

/// **9) A secure lockout threshold exists** (the key sets 10; the scored range
/// is 5-50). The standard is inside it.
#[test]
fn item_09_lockout_threshold_is_within_five_to_fifty() {
    assert!((5..=50).contains(&PasswordPolicyStandards::LOCKOUT_THRESHOLD));
}

/// **10) A secure account lockout observation window exists** ("at least 4
/// minutes").
#[test]
fn item_10_lockout_window_and_duration_are_at_least_four_minutes() {
    const { assert!(PasswordPolicyStandards::LOCKOUT_OBSERVATION_WINDOW >= 4) };
    const { assert!(PasswordPolicyStandards::LOCKOUT_DURATION >= 4) };
}

/// **11) Limit local use of blank passwords to console only [enabled].**
#[test]
fn item_11_blank_passwords_are_limited_to_the_console() {
    assert_eq!(registry_value(LSA, "LimitBlankPasswordUse"), Some("1"));
}

/// **12) Do not allow anonymous enumeration of SAM accounts and shares
/// [enabled].** Two values: SAM accounts and shares.
#[test]
fn item_12_anonymous_enumeration_is_refused() {
    assert_eq!(registry_value(LSA, "restrictanonymoussam"), Some("1"));
    assert_eq!(registry_value(LSA, "restrictanonymous"), Some("1"));
}

/// **13) Audit Security State Change [Success].** Advanced audit policy,
/// Policy Change / System subcategories; the subcategory list is private to the
/// Audit Policy task, pinned at its row.
#[test]
fn item_13_audit_policy_task_is_registered() {
    let row = task_row("--audit-policy");
    assert!(!row.detail.is_empty());
    assert!(!build("--audit-policy").name().is_empty());
}

/// **14) Firewall protection has been enabled.** Private and Public (and
/// Domain); pinned at the Firewall task row.
#[test]
fn item_14_firewall_task_is_registered() {
    let row = task_row("--firewall");
    assert!(row.detail.contains("profiles"), "{}", row.detail);
    assert!(!build("--firewall").name().is_empty());
}

/// **15) Windows automatically checks for updates.** The image sets
/// `Configure Automatic Updates` to Disabled; the tool writes `NoAutoUpdate = 0`
/// and an auto-install option.
#[test]
fn item_15_windows_update_is_enabled() {
    assert_eq!(registry_value(WINDOWS_UPDATE_AU, "NoAutoUpdate"), Some("0"));
    assert_eq!(registry_value(WINDOWS_UPDATE_AU, "AUOptions"), Some("4"));
}

/// **16) File share greybeard disabled.** A share outside the allowed set
/// (`ADMIN$`, `C$`, `IPC$`; plus `NETLOGON`/`SYSVOL` on a domain controller).
/// The decision (`unauthorized`) is private to `shared_folders_audit.rs`;
/// pinned at the task row.
#[test]
fn item_16_greybeard_share_is_handled_by_the_shared_folders_audit() {
    let row = task_row("--shared-folders");
    assert!(!row.label.is_empty());
    assert!(!build("--shared-folders").name().is_empty());
}

/// **17) File share disabled for C drive.** The share named `C` (not the
/// administrative `C$`). Same decision, same pin as item 16.
#[test]
fn item_17_c_share_is_handled_by_the_shared_folders_audit() {
    assert!(!build("--shared-folders").description().is_empty());
}

/// **18) Simple Mail Transfer Protocol (SMTP) service has been stopped and
/// disabled.** `Smtpsvc` is in Service Management's disable list (a private
/// table); the README does not protect it. Pinned at the task row.
#[test]
fn item_18_smtp_is_handled_by_service_management() {
    assert!(!readme_services::is_critical(Some(&readme()), "Smtpsvc"));
    assert!(!build("--service-management").name().is_empty());
}

/// **19) FTP service has been stopped and disabled.** Microsoft FTP Service is
/// `ftpsvc`; the README does not call FTP critical, so it is not protected.
#[test]
fn item_19_ftp_is_not_protected_by_this_readme() {
    assert_eq!(readme_services::resolve("FTP"), "ftpsvc");
    assert!(!readme_services::is_critical(Some(&readme()), "ftpsvc"));
}

/// **20) Firefox has been updated.** `Mozilla Firefox (x64 en-US)` must resolve
/// to the `firefox` package so the upgrade reaches it.
#[test]
fn item_20_firefox_is_updated_by_its_package() {
    assert_eq!(
        resolve_package_id("Mozilla Firefox (x64 en-US)", PACKAGE_IDS).as_deref(),
        Some("firefox")
    );
    assert!(!prohibited_by_default("Mozilla Firefox (x64 en-US)"));
}

/// **21) Removed BitTorrent.** Prohibited by default; the README does not
/// require it.
#[test]
fn item_21_bittorrent_is_prohibited() {
    assert!(prohibited_by_default("BitTorrent"));
    assert!(prohibited_by_default("BitTorrent 7.11.0"));
    assert!(!required_by_readme("BitTorrent"));
}

/// **22) Removed Wireshark.** Prohibited by default, and - unlike the Windows 11
/// round - this README does *not* require it, so the override must not spare it.
#[test]
fn item_22_wireshark_is_prohibited_and_not_spared() {
    assert!(prohibited_by_default("Wireshark 4.2.5 x64"));
    assert!(!required_by_readme("Wireshark 4.2.5 x64"));
}

/// **23) Removed Brutus password cracker archive.**
/// `C:\Users\Public\Public Downloads\brutus-aet2-darknet.zip`. The file patterns
/// (`brutus`, `darknet`) are private to `tasks/prohibited_media.rs`; pinned at
/// the media-scan row, and the name carries nothing this README requires.
#[test]
fn item_23_brutus_archive_is_handled_by_the_media_scan() {
    assert!(!task_row("--media-scan").label.is_empty());
    assert!(!build("--media-scan").name().is_empty());
    assert!(!required_by_readme("brutus-aet2-darknet.zip"));
}

// =============================================================================
// Penalties - things the tool must NOT do
// =============================================================================

/// **Penalty 1) Account lockout policy less than 5 is deprecated: -4 pts.**
/// The tool's threshold is within the scored 5-50 range.
#[test]
fn penalty_01_the_lockout_threshold_the_tool_sets_is_within_five_to_fifty() {
    assert!((5..=50).contains(&PasswordPolicyStandards::LOCKOUT_THRESHOLD));
}

/// **Penalty 2) Remote Desktop is disabled: -5 pts.** "The README states that
/// Remote Desktop is a critical service." Hardening writes `fDenyTSConnections`
/// and the service list disables `TermService`; both are skipped when
/// `is_remote_desktop_required` is true, which the README's own words must make
/// it.
#[test]
fn penalty_02_remote_desktop_is_protected_when_the_readme_requires_it() {
    for spelling in [
        "Remote Desktop",
        "Remote Desktop Services",
        "RDP",
        "Terminal Services",
    ] {
        let data = ReadmeData {
            critical_services: vec![spelling.to_string()],
            ..Default::default()
        };
        assert!(
            readme_services::is_remote_desktop_required(Some(&data)),
            "{spelling}"
        );
    }
    assert!(readme_services::is_remote_desktop_required(Some(&readme())));
    assert_eq!(readme_services::resolve("Remote Desktop"), "TermService");
    // The default the README is overriding exists, so the protection matters.
    assert_eq!(
        registry_value(TERMINAL_SERVER, "fDenyTSConnections"),
        Some("1")
    );
    assert!(REMOTE_DESKTOP_VALUES.contains(&"fDenyTSConnections"));
    assert!(
        SERVICE_NAME_MAP
            .iter()
            .any(|(display, service)| *display == "Remote Desktop" && *service == "TermService")
    );
}

/// **Penalty 3) Firefox is not installed at the default location: -5 pts.**
/// Firefox resolves to Chocolatey's installer package, which keeps it under
/// Program Files, and the README's requirement beats any removal.
#[test]
fn penalty_03_firefox_stays_installed_at_its_default_location() {
    let resolved = resolve_package_id("Firefox", PACKAGE_IDS).expect("a package id");
    assert_eq!(resolved, "firefox");
    assert!(!resolved.contains("portable"));
    assert!(required_by_readme("Mozilla Firefox (x64 en-US)"));
    assert!(!prohibited_by_default("Firefox"));
}

// =============================================================================
// Not automatable
// =============================================================================

/// **1) Forensics Question 1** (the folder path of the unauthorised share
/// `greybeard`) and **2) Forensics Question 2** (the SHA256 of `jarlsberg.png`).
/// Both need a person. The shares task prints each share's path before removing
/// it, which is the answer to question 1.
#[test]
fn items_01_and_02_forensics_questions_are_for_a_human() {}

// =============================================================================
// Coverage
// =============================================================================

/// (number, title, automated)
const SCORING: &[(u32, &str, bool)] = &[
    (1, "Forensics Question 1", false),
    (2, "Forensics Question 2", false),
    (3, "Removed unauthorized user ancano", true),
    (4, "Removed unauthorized user tolfdir", true),
    (5, "lydia is not an administrator", true),
    (6, "balgruuf has a password", true),
    (7, "Secure maximum password age", true),
    (8, "Reversible encryption disabled", true),
    (9, "Secure lockout threshold", true),
    (10, "Secure lockout observation window", true),
    (11, "Limit blank passwords to console", true),
    (12, "No anonymous SAM/share enumeration", true),
    (13, "Audit Security State Change", true),
    (14, "Firewall enabled", true),
    (15, "Windows checks for updates automatically", true),
    (16, "File share greybeard disabled", true),
    (17, "File share for C drive disabled", true),
    (18, "SMTP stopped and disabled", true),
    (19, "FTP stopped and disabled", true),
    (20, "Firefox updated", true),
    (21, "Removed BitTorrent", true),
    (22, "Removed Wireshark", true),
    (23, "Removed Brutus archive", true),
];

const PENALTIES: &[&str] = &[
    "Account lockout threshold less than 5",
    "Remote Desktop disabled",
    "Firefox not at the default location",
];

const NOT_AUTOMATED: &[(u32, &str)] = &[
    (1, "forensics: folder path of the greybeard share"),
    (2, "forensics: SHA256 of jarlsberg.png"),
];

/// Items whose deciding function is private to the crate; each is pinned at the
/// closest public point. Remove an entry when its module is made public and
/// the test is upgraded to call the function.
const PRIVATE_DECISION: &[(&str, &str)] = &[
    (
        "3, 4, 5",
        "user_management.rs: the authorised-set diff inside execute()",
    ),
    ("6", "account_permissions.rs: passwordless-account check"),
    ("13", "audit_policy.rs: subcategory table"),
    ("14", "firewall.rs: profile list"),
    (
        "16, 17",
        "shared_folders_audit.rs: allowed_shares, unauthorized",
    ),
    ("18", "service_management.rs: SERVICES_TO_DISABLE (Smtpsvc)"),
    (
        "23",
        "prohibited_media.rs: HACKING_TOOL_PATTERNS / is_prohibited_file",
    ),
    (
        "penalty 1",
        "password_policy.rs: lockout_threshold_compliant",
    ),
    ("penalty 3", "software_update.rs: location_shift"),
];

#[test]
fn the_scoring_table_matches_the_key() {
    assert_eq!(SCORING.len(), 23);
    let manual: Vec<u32> = SCORING
        .iter()
        .filter(|(.., automated)| !automated)
        .map(|(n, ..)| *n)
        .collect();
    let listed: Vec<u32> = NOT_AUTOMATED.iter().map(|(n, _)| *n).collect();
    assert_eq!(manual, listed);
    assert_eq!(PENALTIES.len(), 3);
    assert!(
        PRIVATE_DECISION
            .iter()
            .all(|(_, reason)| !reason.is_empty())
    );
}

/// Every automatable item has an `item_NN_*` test and every penalty a
/// `penalty_NN_*` test.
#[test]
fn every_automatable_item_has_a_test() {
    let source = include_str!("answer_key_server2019_training2.rs");
    for (number, title, automated) in SCORING {
        if !automated {
            continue;
        }
        let prefix = format!("fn item_{number:02}_");
        assert!(
            source.contains(&prefix),
            "item {number} ({title}) is automatable but has no {prefix}* test"
        );
    }
    for (index, title) in PENALTIES.iter().enumerate() {
        let prefix = format!("fn penalty_{:02}_", index + 1);
        assert!(
            source.contains(&prefix),
            "penalty {title} has no {prefix}* test"
        );
    }
}
