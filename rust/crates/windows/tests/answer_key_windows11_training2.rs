// =============================================================================
// PinnacleCyPat - The CP18 Windows 11 Training Round 2 answer key, as tests
// Copyright 2026 Maxwell McCormick
// SPDX-License-Identifier: Apache-2.0
// =============================================================================

//! Every scored item and penalty from the Windows 11 Training Round 2 answer
//! key (`windowsAnswereKey.pdf`, a scanned image read by OCR): 25 items and
//! five penalties.
//!
//! **The README is synthetic.** No README was supplied for this round, so
//! [`readme`] builds the `ReadmeData` the key says it contained: authorised
//! users and administrators (`penguru` is to be created; `jchutney` and
//! `sjacobs` are authorised users who must not be administrators), Chrome,
//! Notepad++, 7-Zip and Wireshark as required software, and Remote Desktop
//! left unmentioned. Names the key does not give are invented.
//!
//! Windows tests compile and run on Linux, so nothing here is Windows-only.
//!
//! ## What is a real decision test and what is a task-row pin
//!
//! The task modules are `pub`, so the deciding functions are called directly:
//! `lockout_threshold_compliant`, `harden_httpd_conf`, `folder_candidates`,
//! `shortcut_candidates`, `location_shift`, the version and choco helpers, the
//! media task's `is_prohibited_file`, plus the `knowledge` tables and
//! `readme_services`. The exceptions, pinned at the task row and listed in
//! [`PRIVATE_DECISION`], are the decisions that live inside `execute()` or in
//! async methods that also change the machine (the authorised-account diff, the
//! Guest and password-expiry steps, SMB signing and firewall profiles).

use pinnacle_core::Task;
use pinnacle_core::models::{
    AuthorizedUser, PasswordPolicyStandards, ReadmeData, SoftwareRequirement,
};
use pinnacle_core::platform::{Platform, TaskSpec};
use pinnacle_core::software_matching::{matches, resolve_package_id};
use pinnacle_windows::Windows;
use pinnacle_windows::knowledge::{ALWAYS_PROHIBITED, PACKAGE_IDS, REGISTRY_SETTINGS};
use pinnacle_windows::readme_services;
use pinnacle_windows::tasks::prohibited_media::{FoundFile, ProhibitedMediaTask};
use pinnacle_windows::tasks::software_update::InstalledApp;
use pinnacle_windows::tasks::{
    parse_choco_outdated, password_policy, security_hardening, software_management, software_update,
};

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

fn required(name: &str) -> SoftwareRequirement {
    SoftwareRequirement {
        name: name.to_string(),
        should_be_latest: true,
        ..Default::default()
    }
}

fn readme() -> ReadmeData {
    ReadmeData {
        title: "CyberPatriot Windows 11 Training Round 2 README (synthetic)".to_string(),
        operating_system: "Windows 11".to_string(),
        administrators: vec![
            user("ealderson", Some("Wh0@reY0u?"), true),
            user("wellick", Some("Tyr3ll#Is#Gone"), true),
        ],
        users: vec![
            // Authorised users who must not be administrators (items 7, 8).
            user("jchutney", None, false),
            user("sjacobs", None, false),
            user("sswailem", None, false),
        ],
        users_to_create: vec!["penguru".to_string()],
        required_software: vec![
            required("Google Chrome"),
            required("Notepad++"),
            required("7-Zip"),
            required("Wireshark"),
        ],
        ..Default::default()
    }
}

/// The row for `flag` in the platform's task table.
fn task_row(flag: &str) -> &'static TaskSpec {
    Windows::tasks()
        .iter()
        .find(|t| t.flag == flag)
        .unwrap_or_else(|| panic!("no task registered for {flag}"))
}

/// The task for `flag`, built the way the engine builds it, from the synthetic
/// README.
fn build(flag: &str) -> Box<dyn Task> {
    (task_row(flag).build)(Some(&readme()))
}

/// The registry row for `(path, name)`, as its value.
fn registry_value(path: &str, name: &str) -> Option<&'static str> {
    REGISTRY_SETTINGS
        .iter()
        .find(|(p, n, ..)| p.eq_ignore_ascii_case(path) && n.eq_ignore_ascii_case(name))
        .map(|(_, _, _, value, _)| *value)
}

const POLICIES_SYSTEM: &str = r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System";
const WINRM: &str = r"HKLM\SOFTWARE\Policies\Microsoft\Windows\WinRM";
const TERMINAL_SERVER: &str = r"HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server";

fn strings(items: &[&str]) -> Vec<String> {
    items.iter().map(|s| s.to_string()).collect()
}

fn app(name: &str, version: &str) -> InstalledApp {
    InstalledApp {
        name: name.to_string(),
        version: version.to_string(),
        publisher: String::new(),
    }
}

/// The prohibited terms in force for this README: the defaults minus anything
/// it requires (so Wireshark is not among them).
fn prohibited_terms() -> Vec<String> {
    software_update::prohibited_terms(Some(&readme()))
}

fn required_terms() -> Vec<String> {
    readme()
        .required_software
        .iter()
        .map(|r| r.name.clone())
        .collect()
}

fn task_with_readme() -> ProhibitedMediaTask {
    let mut task = ProhibitedMediaTask::new();
    task.set_readme_data(readme());
    task
}

fn found(directory: &str, name: &str) -> FoundFile {
    FoundFile {
        full_name: std::path::PathBuf::from(format!(r"{directory}\{name}")),
        name: name.to_string(),
        extension: std::path::Path::new(name)
            .extension()
            .map(|e| format!(".{}", e.to_string_lossy()))
            .unwrap_or_default(),
        length: 1 << 20,
        last_write_time: None,
        directory_name: Some(directory.to_string()),
    }
}

fn prohibited_by_default(display_name: &str) -> bool {
    ALWAYS_PROHIBITED
        .iter()
        .any(|term| matches(display_name, term))
}

/// Would the README's requirement protect this display name? This is the same
/// `matches` the software task applies to every README requirement before it
/// removes anything.
fn required_by_readme(display_name: &str) -> bool {
    readme()
        .required_software
        .iter()
        .any(|r| matches(display_name, &r.name))
}

// =============================================================================
// Scored items
// =============================================================================

/// **3) The Guest account is not enabled.** Account Permissions disables
/// `Guest` through `account_ops::set_enabled` when it finds it enabled.
/// Pinned at the task row; the decision is inside `execute()`.
#[test]
fn item_03_guest_account_is_handled_by_account_permissions() {
    let row = task_row("--account-permissions");
    assert!(row.detail.contains("Guest"), "{}", row.detail);
    assert!(!build("--account-permissions").name().is_empty());
}

/// **4) Remove unauthorized user darkarmy.** The user is in no README list.
/// User Management removes every non-system account the README does not
/// authorise; the diff is private, so this pins that the task exists, wants the
/// README, and that neither name is authorised by the synthetic README.
#[test]
fn item_04_darkarmy_is_unauthorised_and_user_management_needs_the_readme() {
    assert_unauthorised("darkarmy");
}

/// **5) Remove unauthorized user fsociety.** As item 4.
#[test]
fn item_05_fsociety_is_unauthorised_and_user_management_needs_the_readme() {
    assert_unauthorised("fsociety");
}

fn assert_unauthorised(name: &str) {
    let data = readme();
    let authorised: Vec<&str> = data
        .administrators
        .iter()
        .chain(&data.users)
        .map(|u| u.username.as_str())
        .chain(data.users_to_create.iter().map(String::as_str))
        .collect();
    assert!(!authorised.contains(&name), "{name} must not be authorised");
    assert!(
        task_row("--user-management").needs_readme,
        "the diff needs the README or it would delete everyone"
    );
    assert!(!build("--user-management").name().is_empty());
}

/// **6) Create user account for user penguru.** The README asks for the
/// account to be created: it reaches the task through `users_to_create`.
#[test]
fn item_06_penguru_is_to_be_created() {
    assert_eq!(readme().users_to_create, ["penguru"]);
    assert!(task_row("--user-management").needs_readme);
}

/// **7) Change unauthorized administrator jchutney to standard user.** An
/// authorised *user* who is not an authorised administrator: he keeps his
/// account, loses `Administrators`. Pinned at the README shape and task row.
#[test]
fn item_07_jchutney_is_a_user_but_not_an_administrator() {
    assert_user_not_admin("jchutney");
}

/// **8) Change unauthorized administrator sjacobs to standard user.**
#[test]
fn item_08_sjacobs_is_a_user_but_not_an_administrator() {
    assert_user_not_admin("sjacobs");
}

fn assert_user_not_admin(name: &str) {
    let data = readme();
    assert!(data.users.iter().any(|u| u.username == name));
    assert!(!data.administrators.iter().any(|u| u.username == name));
    assert!(task_row("--user-management").needs_readme);
}

/// **9) User sswailem password expires.** Account Permissions clears
/// "Password never expires" on human accounts; pinned at the task row, whose
/// detail names password expiry.
#[test]
fn item_09_password_expiry_is_handled_by_account_permissions() {
    let row = task_row("--account-permissions");
    assert!(row.detail.to_lowercase().contains("password expiry"));
}

/// **10) A secure minimum password length is required** (the key sets 10).
#[test]
fn item_10_minimum_password_length_is_at_least_ten() {
    const { assert!(PasswordPolicyStandards::MIN_PASSWORD_LENGTH >= 10) };
}

/// **11) Passwords are not stored using reversible encryption.**
#[test]
fn item_11_reversible_encryption_is_disabled() {
    const { assert!(PasswordPolicyStandards::REVERSIBLE_ENCRYPTION_DISABLED) };
}

/// **12) Passwords must meet complexity requirements.**
#[test]
fn item_12_complexity_is_required() {
    const { assert!(PasswordPolicyStandards::COMPLEXITY_ENABLED) };
}

/// **13) Microsoft network client: Digitally sign communications (always)
/// [enabled].** Set by the Local Security Policy task (`RequireSecuritySignature`
/// under `LanmanWorkstation`, a private constant there); pinned at its row.
#[test]
fn item_13_smb_client_signing_is_handled_by_local_security_policy() {
    let row = task_row("--group-policy");
    assert!(row.detail.contains("SMB signing"), "{}", row.detail);
}

/// **14) Do not require CTRL+ALT+DEL [disabled].** "Disabled" means CTRL+ALT+DEL
/// *is* required: `DisableCAD = 0`.
#[test]
fn item_14_ctrl_alt_del_is_required() {
    assert_eq!(registry_value(POLICIES_SYSTEM, "DisableCAD"), Some("0"));
}

/// **15) Windows Remote Management service does not send or receive
/// unencrypted traffic.** The key sets the service policy; the client side and
/// Basic authentication go with it.
#[test]
fn item_15_winrm_refuses_unencrypted_traffic() {
    for side in ["Service", "Client"] {
        let path = format!(r"{WINRM}\{side}");
        assert_eq!(
            registry_value(&path, "AllowUnencryptedTraffic"),
            Some("0"),
            "{side}"
        );
        assert_eq!(registry_value(&path, "AllowBasic"), Some("0"), "{side}");
    }
}

/// **16) Firewall protection has been enabled.** Domain, Private and Public.
/// The profile list is inside the Firewall task; pinned at its row.
#[test]
fn item_16_firewall_task_is_registered() {
    let row = task_row("--firewall");
    assert!(row.detail.contains("profiles"), "{}", row.detail);
    assert!(!build("--firewall").name().is_empty());
}

/// **17) Remote desktop sharing is turned off.** `fDenyTSConnections = 1`, and
/// because this README does *not* call Remote Desktop critical the hardening
/// default is not overridden.
#[test]
fn item_17_remote_desktop_is_denied_when_the_readme_does_not_need_it() {
    assert_eq!(
        registry_value(TERMINAL_SERVER, "fDenyTSConnections"),
        Some("1")
    );
    assert!(!readme_services::is_remote_desktop_required(
        Some(&readme())
    ));
}

/// **18) Notepad++ has been updated.** The installed app is named
/// `Notepad++ (64-bit x64)`; it must resolve to the installer package (so the
/// upgrade runs the vendor installer and keeps the default location), a
/// `choco outdated` line for that id is an update, and an old installed version
/// is read as older than the latest.
#[test]
fn item_18_notepad_plus_plus_is_updated_by_its_installer_package() {
    assert_eq!(
        resolve_package_id("Notepad++ (64-bit x64)", PACKAGE_IDS).as_deref(),
        Some("notepadplusplus.install")
    );
    let updates = parse_choco_outdated("notepadplusplus.install|8.5.0|8.7.1|false\n");
    assert_eq!(updates.len(), 1);
    assert_eq!(updates[0].id, "notepadplusplus.install");
    assert!(software_update::is_older("8.5", "8.7.1"));
    assert!(!software_update::is_older("8.7.1", "8.7.1"));
    // An app Chocolatey did not install is still offered for update.
    let installed = vec![app("Notepad++ (64-bit x64)", "8.5")];
    let found = software_update::unmanaged_candidates(
        &installed,
        &[],
        &software_update::prohibited_terms(Some(&readme())),
    );
    assert_eq!(found.len(), 1);
    assert_eq!(found[0].id, "notepadplusplus.install");
}

/// **19) Google Chrome has been updated.** As item 18, with `googlechrome`; the
/// key reinstalls Chrome, so an app Chocolatey did not install must be offered.
#[test]
fn item_19_chrome_is_updated_by_its_installer_package() {
    assert_eq!(
        resolve_package_id("Google Chrome", PACKAGE_IDS).as_deref(),
        Some("googlechrome")
    );
    let updates = parse_choco_outdated("googlechrome|120.0.1|126.0.2|false\n");
    assert_eq!(updates[0].id, "googlechrome");
    assert!(software_update::is_older(
        "120.0.6099.109",
        "126.0.6478.127"
    ));
    assert_eq!(
        software_update::parse_choco_search("googlechrome|126.0.6478.127\n", "googlechrome")
            .as_deref(),
        Some("126.0.6478.127")
    );
    let found = software_update::unmanaged_candidates(
        &[app("Google Chrome", "120.0.6099.109")],
        &[],
        &software_update::prohibited_terms(Some(&readme())),
    );
    assert_eq!(found[0].id, "googlechrome");
}

/// **20) Removed shellshock exploit script.** `shellshock-exploit.py` in a
/// user's Downloads: the `exploit` file pattern flags it. An unrelated file
/// beside it is left alone.
#[test]
fn item_20_shellshock_script_is_flagged_by_the_media_scan() {
    let task = task_with_readme();
    assert!(task.is_prohibited_file(&found(
        r"C:\Users\ealderson\Downloads",
        "shellshock-exploit.py"
    )));
    assert!(!task.is_prohibited_file(&found(r"C:\Users\ealderson\Downloads", "notes.txt")));
}

/// **21) Remove Jellyfin Media Player.** A folder in `C:\Program Files` with
/// nothing in the uninstall registry: `folder_candidates` selects it, and never
/// a system folder.
#[test]
fn item_21_jellyfin_is_prohibited_by_name_and_by_folder() {
    assert!(prohibited_by_default("Jellyfin Media Player"));
    let dirs = strings(&["Jellyfin", "Common Files", "Windows Defender", "7-Zip"]);
    assert_eq!(
        software_management::folder_candidates(&prohibited_terms(), &dirs, &required_terms()),
        ["Jellyfin"]
    );
    // The registry pass misses it, so the folder hunt is for exactly this term.
    assert_eq!(
        software_management::terms_without_entries(
            &strings(&["Jellyfin"]),
            &strings(&["Google Chrome", "7-Zip 24.08 (x64)"])
        ),
        ["Jellyfin"]
    );
}

/// **22) Remove Burp Suite Community Edition.** A desktop shortcut and no
/// registry entry: `shortcut_candidates` selects the shortcut.
#[test]
fn item_22_burp_suite_is_prohibited_by_name_and_by_shortcut() {
    assert!(prohibited_by_default("Burp Suite Community Edition"));
    let shortcuts = strings(&["Burp Suite Community Edition", "Google Chrome", "Notepad++"]);
    assert_eq!(
        software_management::shortcut_candidates(
            &prohibited_terms(),
            &shortcuts,
            &required_terms()
        ),
        ["Burp Suite Community Edition"]
    );
}

/// **23) Remove Python3.** A desktop shortcut named `Python 313 (64-bit)`.
#[test]
fn item_23_python_is_prohibited_by_name_and_by_shortcut() {
    assert!(prohibited_by_default("Python 3.13.0 (64-bit)"));
    let shortcuts = strings(&["Python 313 (64-bit)", "Google Chrome"]);
    assert_eq!(
        software_management::shortcut_candidates(
            &prohibited_terms(),
            &shortcuts,
            &required_terms()
        ),
        ["Python 313 (64-bit)"]
    );
}

/// **24) Remove Nmap.** A folder in `C:\Program Files (x86)`.
#[test]
fn item_24_nmap_is_prohibited_by_name_and_by_folder() {
    assert!(prohibited_by_default("Nmap 7.94"));
    let dirs = strings(&["Nmap", "Microsoft", "Notepad++"]);
    assert_eq!(
        software_management::folder_candidates(&prohibited_terms(), &dirs, &required_terms()),
        ["Nmap"]
    );
}

/// **25) Disable Apache server signature.** `ServerSignature On` on line 61 of
/// `C:\Apache24\conf\httpd.conf` becomes `Off`; `ServerTokens` is added, a
/// commented line is left alone, and a second pass changes nothing.
#[test]
fn item_25_apache_server_signature_is_turned_off() {
    let conf = "Listen 80\r\n# ServerSignature On\r\nServerSignature On\r\n";
    let fixed = security_hardening::harden_httpd_conf(conf);
    assert!(fixed.contains("\r\nServerSignature Off\r\n"), "{fixed:?}");
    assert!(!fixed.contains("\r\nServerSignature On"));
    assert!(fixed.contains("# ServerSignature On"), "comments are kept");
    assert!(fixed.contains("ServerTokens Prod"));
    assert_eq!(security_hardening::harden_httpd_conf(&fixed), fixed);
}

// =============================================================================
// Penalties - things the tool must NOT do
// =============================================================================

/// **Penalty 1) Account lockout threshold less than 5 is deprecated.** 1-4 is
/// the penalty and 0 is lockout off; neither counts as compliant, so the tool
/// resets them, and the value it sets is within the scored 5-50 range.
#[test]
fn penalty_01_a_lockout_threshold_below_five_is_not_left_in_place() {
    for threshold in 0..=4 {
        assert!(
            !password_policy::lockout_threshold_compliant(threshold),
            "{threshold}"
        );
    }
    assert!(password_policy::lockout_threshold_compliant(5));
    assert!(!password_policy::lockout_threshold_compliant(60));
    assert!((5..=50).contains(&PasswordPolicyStandards::LOCKOUT_THRESHOLD));
}

/// **Penalties 2-5) Chrome, Notepad++, 7-Zip, Wireshark "not installed at the
/// default location".** Reinstalling or upgrading must run the vendor
/// installer. Every one of the four resolves to an installer package, none to a
/// portable one (which unpacks under `ProgramData`).
#[test]
fn penalty_02_to_05_required_software_resolves_to_installer_packages() {
    for (display, id) in [
        ("Google Chrome", "googlechrome"),
        ("Notepad++", "notepadplusplus.install"),
        ("7-Zip", "7zip.install"),
        ("Wireshark", "wireshark"),
    ] {
        let resolved = resolve_package_id(display, PACKAGE_IDS)
            .unwrap_or_else(|| panic!("{display} has no package id"));
        assert_eq!(resolved, id, "{display}");
        assert!(!resolved.contains("portable"), "{display} -> {resolved}");
        assert!(
            readme().required_software.iter().any(|r| r.name == display),
            "{display} is required by the synthetic README"
        );
    }
}

/// **Penalties 2-5, the other half.** Upgrading must not move the program:
/// `location_shift` flags an upgrade whose recorded install location changed
/// (the penalty), and not one that stayed put.
#[test]
fn penalty_02_to_05_an_upgrade_that_moves_the_install_is_flagged() {
    let pair = |name: &str, location: &str| vec![(name.to_string(), location.to_string())];
    for (before, after, id) in [
        (
            pair("7-Zip 24.08 (x64)", r"C:\Program Files\7-Zip\"),
            pair("7-Zip 25.01 (x64)", r"C:\ProgramData\chocolatey\lib\7zip"),
            "7zip.install",
        ),
        (
            pair(
                "Google Chrome",
                r"C:\Program Files\Google\Chrome\Application",
            ),
            pair(
                "Google Chrome",
                r"C:\Users\student\AppData\Local\Google\Chrome",
            ),
            "googlechrome",
        ),
    ] {
        assert!(
            software_update::location_shift(&before, &after, id).is_some(),
            "{id}"
        );
    }
    let before = pair("Wireshark 4.0.3 x64", r"C:\Program Files\Wireshark");
    let after = pair("Wireshark 4.2.5 x64", r"C:\Program Files\Wireshark\");
    assert_eq!(
        software_update::location_shift(&before, &after, "wireshark"),
        None
    );
    let before = pair("Notepad++ (64-bit x64)", r"C:\Program Files\Notepad++");
    let after = pair("Notepad++ (64-bit x64)", r"C:\Program Files\Notepad++");
    assert_eq!(
        software_update::location_shift(&before, &after, "notepadplusplus.install"),
        None
    );
}

/// **Penalty 5, the override.** Wireshark is on the always-prohibited list, so
/// the only thing between the tool and the penalty is the README's own
/// requirement beating that default.
#[test]
fn penalty_05_wireshark_is_prohibited_by_default_but_required_here() {
    assert!(prohibited_by_default("Wireshark"));
    assert!(required_by_readme("Wireshark 4.2.5 x64"));
    assert!(required_by_readme("Wireshark"));
    // Burp Suite is not required, so it is not spared.
    assert!(!required_by_readme("Burp Suite Community Edition"));
}

// =============================================================================
// Not automatable
// =============================================================================

/// **1) Forensics Question 1** (the host IP in `attack.pcap`) and **2)
/// Forensics Question 2** (decrypt a one-time pad). Both need a person.
#[test]
fn items_01_and_02_forensics_questions_are_for_a_human() {}

// =============================================================================
// Coverage
// =============================================================================

/// (number, title, automated)
const SCORING: &[(u32, &str, bool)] = &[
    (1, "Forensics Question 1", false),
    (2, "Forensics Question 2", false),
    (3, "Guest account not enabled", true),
    (4, "Remove unauthorized user darkarmy", true),
    (5, "Remove unauthorized user fsociety", true),
    (6, "Create user penguru", true),
    (7, "jchutney to standard user", true),
    (8, "sjacobs to standard user", true),
    (9, "sswailem password expires", true),
    (10, "Minimum password length", true),
    (11, "No reversible encryption", true),
    (12, "Password complexity", true),
    (13, "Network client signs communications", true),
    (14, "CTRL+ALT+DEL required", true),
    (15, "WinRM no unencrypted traffic", true),
    (16, "Firewall enabled", true),
    (17, "Remote desktop sharing off", true),
    (18, "Notepad++ updated", true),
    (19, "Chrome updated", true),
    (20, "Removed shellshock exploit script", true),
    (21, "Remove Jellyfin Media Player", true),
    (22, "Remove Burp Suite Community Edition", true),
    (23, "Remove Python3", true),
    (24, "Remove Nmap", true),
    (25, "Disable Apache server signature", true),
];

/// Penalties: lockout below 5, then four default-location penalties.
const PENALTIES: &[&str] = &[
    "Account lockout threshold less than 5",
    "Google Chrome not at the default location",
    "Notepad++ not at the default location",
    "7-Zip not at the default location",
    "Wireshark not at the default location",
];

/// Items the tool does not attempt.
const NOT_AUTOMATED: &[(u32, &str)] = &[
    (1, "forensics: host address in attack.pcap"),
    (2, "forensics: decrypt a one-time-pad ciphertext"),
];

/// Items whose deciding logic is still not a callable pure function: the
/// authorised-account diff is spread over async methods that also delete
/// accounts, and the SMB-signing and firewall-profile lists are locals inside
/// `execute()`. Those are pinned at the task row.
const PRIVATE_DECISION: &[(&str, &str)] = &[
    ("3", "account_permissions.rs: Guest check inside execute()"),
    (
        "4-8",
        "user_management.rs: the authorised-set diff inside async methods",
    ),
    (
        "9",
        "account_permissions.rs: password-expiry loop inside execute()",
    ),
    ("13", "group_policy.rs: SMB signing list inside execute()"),
    ("16", "firewall.rs: profile list inside execute()"),
];

#[test]
fn the_scoring_table_matches_the_key() {
    assert_eq!(SCORING.len(), 25);
    let manual: Vec<u32> = SCORING
        .iter()
        .filter(|(.., automated)| !automated)
        .map(|(n, ..)| *n)
        .collect();
    let listed: Vec<u32> = NOT_AUTOMATED.iter().map(|(n, _)| *n).collect();
    assert_eq!(manual, listed);
    assert_eq!(PENALTIES.len(), 5);
    assert!(
        PRIVATE_DECISION
            .iter()
            .all(|(_, reason)| !reason.is_empty()),
        "every private decision names what decides it"
    );
}

/// Every automatable item has an `item_NN_*` test, and the penalties have
/// `penalty_NN_*` tests (02-05 share one, and 05 has a second).
#[test]
fn every_automatable_item_has_a_test() {
    let source = include_str!("answer_key_windows11_training2.rs");
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
    for prefix in ["fn penalty_01_", "fn penalty_02_to_05_", "fn penalty_05_"] {
        assert!(source.contains(prefix), "missing {prefix}*");
    }
}
