// =============================================================================
// PinnacleCyPat - The Ubuntu 22.04 Exhibition Round answer key, as tests
// Author: Maxwell McCormick
// Copyright 2026 Maxwell McCormick
// SPDX-License-Identifier: Apache-2.0
// =============================================================================

//! Every scored item and penalty from a real CyberPatriot answer key, encoded
//! as an executable expectation.
//!
//! CyberPatriot publishes an answer key for its Exhibition Round: sixteen
//! scored items worth 100 points, and four penalties worth -20. That document
//! is the closest thing this project has to a specification, and until now
//! nothing connected it to the code.
//!
//! Each test below is named after its item and carries the point value, so a
//! failure says exactly what it would have cost. They are written against the
//! *decisions* the tool makes from the parsed README - which accounts it counts
//! as unauthorised, which services it refuses to mask, which packages it
//! purges - because that is the layer where the bugs are. Whether `gpasswd`
//! then does what it is told is not in doubt; whether the tool asks it to is.
//!
//! **Two items are not automatable and are marked so**: the forensics questions
//! are worth 16 of the 100 points and need a human to read a file and answer a
//! question. Every other item is either covered here or explicitly ignored with
//! the reason.
//!
//! ## Using this as a specification
//!
//! Add an answer key, write the tests, watch them fail, then fix the code. The
//! first run of this file failed on two items worth 13 points between them, both
//! parser gaps that reading the code had not found:
//!
//! - **Perl was not extracted as required software** (-5 penalty risk). The
//!   README names it in a sentence listing three programs; the parser handled
//!   two of them.
//! - **The `firesidegirls` group requirement was empty** (8 points). The
//!   README's phrasing - *add the user "candace" to the "firesidegirls" group* -
//!   put the user before the group, which no existing pattern matched.

use pinnacle_core::models::ReadmeData;
use pinnacle_core::readme_parser;
use pinnacle_linux::knowledge::{ALWAYS_PROHIBITED, HARDENING_SETTINGS, PROHIBITED_SERVICES};
use pinnacle_linux::tasks::{
    firewall, prohibited_media, service_management, software_management, software_update,
    user_management,
};

/// The README this key belongs to, kept as a corpus fixture so the parser's
/// output for it is also snapshotted.
const README: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../core/tests/corpus/06-ubuntu-22-exhibition-round.html"
);

async fn readme() -> ReadmeData {
    let data = readme_parser::parse_html_readme_async(README).await;
    assert!(
        !data.administrators.is_empty(),
        "the fixture did not parse - is {README} still there?"
    );
    data
}

// =============================================================================
// Scored items
// =============================================================================

/// **3) Removed unauthorized user jimmy: 6 pts.**
///
/// `jimmy` appears nowhere in the README. The authorised set is the
/// administrators plus the users plus anyone named in a group requirement, and
/// any human account outside it is surplus.
#[tokio::test]
async fn item_03_unauthorised_user_jimmy_is_removed() {
    let plan = user_management::authorised_from(&readme().await);
    assert!(
        !plan.everyone.contains("jimmy"),
        "jimmy is not in the README and must not be authorised"
    );

    let present = vec![account("jimmy", 1005), account("perry", 1000)];
    let surplus = user_management::unauthorised(&present, &plan.everyone);
    assert_eq!(
        surplus,
        ["jimmy"],
        "jimmy should be the only account removed"
    );
}

/// **4) User doofenshmirtz is not an administrator: 6 pts.**
///
/// The trap: `doofenshmirtz` *is* an authorised user, so he must keep his
/// account while losing his administrative rights. A tool that reads only the
/// administrators table would delete him.
#[tokio::test]
async fn item_04_doofenshmirtz_keeps_his_account_but_loses_admin() {
    let plan = user_management::authorised_from(&readme().await);
    assert!(
        plan.everyone.contains("doofenshmirtz"),
        "doofenshmirtz is an authorised user and must not be removed"
    );
    assert!(
        !plan.admins.contains("doofenshmirtz"),
        "doofenshmirtz is not an authorised administrator"
    );
}

/// **5) User vanessa is not an administrator: 6 pts.**
#[tokio::test]
async fn item_05_vanessa_keeps_her_account_but_loses_admin() {
    let plan = user_management::authorised_from(&readme().await);
    assert!(plan.everyone.contains("vanessa"));
    assert!(!plan.admins.contains("vanessa"));
}

/// **6) Changed insecure password for user pinky: 6 pts.**
///
/// The README publishes the administrators' passwords, and one of them -
/// `grilledcheese` - is a dictionary word with no digit, no symbol and no
/// upper-case letter. The tool has to notice that a password the README itself
/// supplied is not acceptable.
#[tokio::test]
async fn item_06_pinky_password_is_recognised_as_insecure() {
    let data = readme().await;
    let pinky = data
        .administrators
        .iter()
        .find(|a| a.username == "pinky")
        .expect("pinky is in the README");
    assert_eq!(pinky.password.as_deref(), Some("grilledcheese"));

    assert!(
        !user_management::is_secure_password("grilledcheese"),
        "grilledcheese must be treated as insecure"
    );
    // The other four are strong and must be left alone - resetting a password
    // the README published breaks the competitor's own login.
    for strong in [
        "M4mm@lOfAct!0n",
        "No#1UnP@!dInt3rn",
        "Go0glyMo0gly!",
        "Adm!r@l4cr0nym",
    ] {
        assert!(
            user_management::is_secure_password(strong),
            "{strong} is strong and must not be reset"
        );
    }
}

/// **7) Added candace to group firesidegirls: 8 pts.**
///
/// The highest-value automatable item, and the one the parser missed. The
/// README's phrasing puts the user before the group:
///
/// > Please add the user "candace" to the "firesidegirls" group.
#[tokio::test]
async fn item_07_candace_is_added_to_firesidegirls() {
    let data = readme().await;
    let group = data
        .group_requirements
        .iter()
        .find(|g| g.group_name.eq_ignore_ascii_case("firesidegirls"))
        .expect("the README asks for a firesidegirls group");
    assert!(
        group.members.iter().any(|m| m == "candace"),
        "candace should be a member; got {:?}",
        group.members
    );
}

/// **8) Uncomplicated Firewall (UFW) protection has been enabled: 6 pts.**
///
/// The README names UFW as *the only company approved firewall*, and separately
/// requires SSH to keep working. Both halves matter: enabling a default-deny
/// firewall without opening 22 would satisfy this item and immediately incur
/// penalty 1.
#[tokio::test]
async fn item_08_ufw_is_enabled_with_ssh_still_reachable() {
    let mut task = firewall::FirewallTask::new();
    task.set_readme_data(readme().await);
    let ports = task.ports_to_open();
    assert!(
        ports.contains(&"22/tcp"),
        "SSH must stay reachable through the firewall; got {ports:?}"
    );
}

/// **10) The system automatically checks for updates daily: 6 pts.**
///
/// Ubuntu decides this from `APT::Periodic::Update-Package-Lists` in
/// `/etc/apt/apt.conf.d/`. The Software & Updates dialog the answer key
/// describes is a front end for that one value.
#[tokio::test]
async fn item_10_updates_are_checked_daily() {
    let settings = software_update::PERIODIC_SETTINGS;
    let daily = settings
        .iter()
        .find(|(key, _, _)| *key == "APT::Periodic::Update-Package-Lists")
        .expect("the daily update check must be configured");
    assert_eq!(daily.1, "1", "1 means every day");
}

/// **11) Firefox has been updated: 5 pts** and **12) Thunderbird: 5 pts.**
///
/// Both are covered by the same upgrade, so the decision worth testing is that
/// the tool knows they are packages it manages rather than names it will shrug
/// at - an unresolved name is an upgrade that never happens.
#[tokio::test]
async fn items_11_and_12_firefox_and_thunderbird_are_upgradable_packages() {
    let (resolved, unresolved) = software_management::required_packages(&readme().await);
    assert!(
        unresolved.is_empty(),
        "unresolved requirements: {unresolved:?}"
    );
    for package in ["firefox", "thunderbird"] {
        assert!(
            resolved.iter().any(|p| p == package),
            "{package} must resolve so an upgrade can reach it; got {resolved:?}"
        );
    }
}

/// **9) Nginx service has been disabled or removed: 6 pts.**
#[tokio::test]
async fn item_09_nginx_is_masked() {
    let mut task = service_management::ServiceManagementTask::new();
    task.set_readme_data(readme().await);
    assert!(
        task.units_to_mask()
            .iter()
            .any(|(unit, _)| *unit == "nginx.service"),
        "nginx must be masked"
    );
}

/// **13) Prohibited MP3 files are removed: 6 pts.**
///
/// The scenario says *the presence of any non-work related media files ... is
/// strictly prohibited*, which is what authorises deletion. Without a sentence
/// like that the task reports and does not delete.
#[tokio::test]
async fn item_13_the_scenario_authorises_deleting_media() {
    let mut task = prohibited_media::ProhibitedMediaTask::new();
    task.set_readme_data(readme().await);
    assert!(
        task.media_is_prohibited(),
        "the scenario prohibits media files, so deletion is authorised"
    );
    // And the extension the key names is one the scanner recognises.
    assert!(prohibited_media::is_media(std::path::Path::new(
        "/home/linda/Music/song.mp3"
    )));
}

/// **14) Prohibited software ophcrack removed: 6 pts.**
///
/// The README never names ophcrack - a README lists what is *required*, and the
/// planted tools are exactly what it will not mention. This is what the
/// always-prohibited table is for.
#[tokio::test]
async fn item_14_ophcrack_is_purged() {
    let prohibited = software_management::prohibited_packages(Some(&readme().await));
    assert!(
        prohibited.iter().any(|(name, _)| name == "ophcrack"),
        "ophcrack must be purged"
    );
}

/// **15) Prohibited software Wireshark removed: 6 pts.**
///
/// Wireshark is on the always-prohibited list *and* is the one entry a README
/// may legitimately override. This README does not, so it goes.
#[tokio::test]
async fn item_15_wireshark_is_purged() {
    let prohibited = software_management::prohibited_packages(Some(&readme().await));
    assert!(
        prohibited.iter().any(|(name, _)| name == "wireshark"),
        "this README does not require Wireshark, so it must be purged"
    );
}

/// **16) SSH does not permit empty passwords: 6 pts.**
#[tokio::test]
async fn item_16_ssh_refuses_empty_passwords() {
    let setting = HARDENING_SETTINGS
        .iter()
        .find(|s| s.key == "PermitEmptyPasswords")
        .expect("PermitEmptyPasswords must be a hardening setting");
    assert_eq!(setting.value, "no");
}

// =============================================================================
// Penalties - things the tool must NOT do
// =============================================================================

/// **Penalty 1) OpenSSH service has been stopped or removed: -5 pts.**
///
/// The README says *sshd is a critical service and needs to remain enabled*.
/// This is the Remote Desktop bug in its Linux form: a default posture that
/// masks remote access, against a README that requires it.
#[tokio::test]
async fn penalty_01_sshd_is_never_masked() {
    let data = readme().await;
    assert!(
        data.critical_services.iter().any(|s| s == "sshd"),
        "the README lists sshd as critical; got {:?}",
        data.critical_services
    );

    let mut task = service_management::ServiceManagementTask::new();
    task.set_readme_data(data.clone());
    assert!(
        task.required_units().contains(&"ssh.service".to_string()),
        "sshd should resolve to ssh.service and be protected"
    );
    assert!(
        !task
            .units_to_mask()
            .iter()
            .any(|(unit, _)| unit.starts_with("ssh")),
        "no ssh unit may be masked when the README calls it critical"
    );

    // ...and the package must survive too. Purging openssh-server is the same
    // penalty by another route.
    let prohibited = software_management::prohibited_packages(Some(&data));
    assert!(
        !prohibited.iter().any(|(name, _)| name == "openssh-server"),
        "openssh-server must not be purged"
    );
}

/// **Penalty 2) Firefox has been removed: -5 pts.**
#[tokio::test]
async fn penalty_02_firefox_is_required_software() {
    assert_required(&readme().await, "Firefox", "firefox").await;
}

/// **Penalty 3) Thunderbird has been removed: -5 pts.**
#[tokio::test]
async fn penalty_03_thunderbird_is_required_software() {
    assert_required(&readme().await, "Thunderbird", "thunderbird").await;
}

/// **Penalty 4) Perl has been removed: -5 pts.**
///
/// Named in the same sentence as Thunderbird:
///
/// > Employees must also have access to the latest stable version of
/// > Thunderbird and Perl to securely support top secret activities.
///
/// The parser handled the first program in that sentence and dropped the
/// second, which is the whole reason this file exists.
#[tokio::test]
async fn penalty_04_perl_is_required_software() {
    assert_required(&readme().await, "Perl", "perl").await;
}

/// A required program must be extracted from the README, must resolve to a
/// package, and must never appear on the purge list.
async fn assert_required(data: &ReadmeData, display: &str, package: &str) {
    assert!(
        data.required_software
            .iter()
            .any(|s| s.name.to_lowercase().contains(&display.to_lowercase())),
        "{display} should be required software; got {:?}",
        data.required_software
            .iter()
            .map(|s| s.name.as_str())
            .collect::<Vec<_>>()
    );

    let (resolved, unresolved) = software_management::required_packages(data);
    assert!(
        resolved.iter().any(|p| p == package),
        "{display} should resolve to the package {package}; resolved {resolved:?}, unresolved {unresolved:?}"
    );

    let prohibited = software_management::prohibited_packages(Some(data));
    assert!(
        !prohibited.iter().any(|(name, _)| name == package),
        "{package} is required and must never be purged"
    );
}

// =============================================================================
// Not automatable
// =============================================================================

/// **1) Forensics Question 1: 8 pts** and **2) Forensics Question 2: 8 pts.**
///
/// Sixteen of the hundred points need a person to read a file on the Desktop
/// and type an answer. The tool deliberately does not touch forensics
/// questions, and the media scan is careful not to delete the files one of them
/// asks about - which is why deletion needs the README's own authorisation.
#[test]
fn items_01_and_02_forensics_questions_are_for_a_human() {
    // Recorded rather than skipped silently: 16 points of this key are outside
    // what any automation should attempt.
}

// =============================================================================
// Coverage - what this key says about the tables
// =============================================================================

/// Everything this key names that the tool finds through a table rather than
/// through the README.
///
/// A README lists what is *required*; the planted services and tools are
/// exactly what it will not mention, so the only thing standing between the
/// tool and those six-point items is an entry in `knowledge.rs`. As more answer
/// keys are added, this list grows and each new row is a claim about coverage.
#[test]
fn the_tables_cover_everything_this_key_scores_by_name() {
    let unit = "nginx.service";
    assert!(
        PROHIBITED_SERVICES.iter().any(|(u, _)| *u == unit),
        "{unit} is scored by the key but is not in PROHIBITED_SERVICES"
    );
    for package in ["ophcrack", "wireshark"] {
        assert!(
            ALWAYS_PROHIBITED.iter().any(|(p, _)| *p == package),
            "{package} is scored by the key but is not in ALWAYS_PROHIBITED"
        );
    }
}

/// What this key is worth, and how much of it the tool can reach.
///
/// Kept as a test rather than a comment so it cannot quietly stop being true.
/// Each row is `(item, points, automated)`; adding an item without deciding
/// which column it belongs in is not possible.
const SCORING: &[(&str, i32, bool)] = &[
    ("1. Forensics Question 1", 8, false),
    ("2. Forensics Question 2", 8, false),
    ("3. Removed unauthorised user jimmy", 6, true),
    ("4. doofenshmirtz is not an administrator", 6, true),
    ("5. vanessa is not an administrator", 6, true),
    ("6. Changed insecure password for pinky", 6, true),
    ("7. Added candace to firesidegirls", 8, true),
    ("8. UFW enabled", 6, true),
    ("9. nginx disabled or removed", 6, true),
    ("10. Updates checked daily", 6, true),
    ("11. Firefox updated", 5, true),
    ("12. Thunderbird updated", 5, true),
    ("13. Prohibited MP3 files removed", 6, true),
    ("14. ophcrack removed", 6, true),
    ("15. Wireshark removed", 6, true),
    ("16. SSH does not permit empty passwords", 6, true),
];

/// Penalties, all of which the tool must avoid incurring.
const PENALTIES: &[(&str, i32)] = &[
    ("OpenSSH stopped or removed", -5),
    ("Firefox removed", -5),
    ("Thunderbird removed", -5),
    ("Perl removed", -5),
];

/// The key totals 100 points, and everything except the two forensics
/// questions is reachable by automation.
///
/// If a future answer key drags this figure down, that is the number worth
/// knowing - it says how much of a round the tool can actually do.
#[test]
fn the_tool_can_reach_every_point_that_is_not_a_forensics_question() {
    let total: i32 = SCORING.iter().map(|(_, points, _)| points).sum();
    assert_eq!(total, 100, "the Exhibition Round key is worth 100 points");

    let automated: i32 = SCORING
        .iter()
        .filter(|(_, _, automated)| *automated)
        .map(|(_, points, _)| points)
        .sum();
    assert_eq!(
        automated, 84,
        "84 of the 100 points are automatable; the rest are the two forensics questions"
    );

    let manual: Vec<&str> = SCORING
        .iter()
        .filter(|(_, _, automated)| !automated)
        .map(|(name, _, _)| *name)
        .collect();
    assert_eq!(
        manual,
        ["1. Forensics Question 1", "2. Forensics Question 2"],
        "only the forensics questions should need a person"
    );

    assert_eq!(
        PENALTIES.iter().map(|(_, points)| points).sum::<i32>(),
        -20,
        "four penalties at -5 each"
    );
}

/// Every automatable item has a test named after it.
///
/// The check is on this file's own source, which is crude but catches the thing
/// that actually goes wrong: an item added to `SCORING` and then forgotten.
#[test]
fn every_automatable_item_has_a_test() {
    let source = include_str!("answer_key.rs");
    for (name, _points, automated) in SCORING {
        if !automated {
            continue;
        }
        // "3. Removed unauthorised user jimmy" -> "item_03"
        let number: u32 = name
            .split('.')
            .next()
            .and_then(|n| n.parse().ok())
            .unwrap_or_else(|| panic!("{name} does not start with its item number"));
        let prefix = format!("item_{number:02}");
        // 11 and 12 share one test - both are satisfied by the same upgrade.
        let covered = source.contains(&format!("fn {prefix}"))
            || (matches!(number, 11 | 12) && source.contains("items_11_and_12"));
        assert!(
            covered,
            "{name} is marked automatable but has no {prefix}_* test"
        );
    }
}

fn account(name: &str, uid: u32) -> pinnacle_linux::user_ops::Account {
    pinnacle_linux::user_ops::Account {
        name: name.to_string(),
        uid,
        gid: uid,
        comment: String::new(),
        home: format!("/home/{name}"),
        shell: "/bin/bash".to_string(),
    }
}
