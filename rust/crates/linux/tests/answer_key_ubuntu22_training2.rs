// =============================================================================
// PinnacleCyPat - The CP18 Ubuntu 22 Training Round 2 answer key, as tests
// Copyright 2026 Maxwell McCormick
// SPDX-License-Identifier: Apache-2.0
// =============================================================================

//! Every scored item and penalty from `CP18_Ubuntu22_Training2_Answer_Key.pdf`
//! (24 items worth 100 points, four penalties worth -20), one test each.
//!
//! **The README is synthetic.** No README was supplied for this round, so
//! [`readme`] builds the `ReadmeData` the key says the README contained:
//! authorised administrators and users (one administrator with a weak published
//! password), a request to add `mariya` to the `pioneers` group, X2Go, Firefox,
//! Thunderbird and Perl as required software, OpenSSH as a critical service, and
//! a scenario that prohibits non-work media. The names are the ones the key uses
//! where it names them (`eli`, `cornelius`, `alice`, `mariya`, `linda`) and
//! invented otherwise (`heinz`, `rodney`). If a real README for the round turns
//! up, add it to the parser corpus and replace the builder.
//!
//! Like `answer_key.rs`, these test the tool's *decisions* - tables, pure
//! functions, classifications - never `execute()`, and never touch the host. The
//! config-file items are tested by feeding the pure rewriters the stock Ubuntu
//! 22.04 text the key describes and checking that the result is what the scorer
//! reads.

use pinnacle_core::models::{AuthorizedUser, GroupRequirement, ReadmeData, SoftwareRequirement};
use pinnacle_linux::file_ops::{self, Style};
use pinnacle_linux::knowledge::{
    ALWAYS_PROHIBITED, CRITICAL_FILE_MODES, HARDENING_SETTINGS, PACKAGE_IDS, PROHIBITED_SERVICES,
    SSHD_DROPIN, SYSCTL_DROPIN,
};
use pinnacle_linux::tasks::backdoor_listeners::{self, Kind, Ownership, ProcessFacts};
use pinnacle_linux::tasks::software_update::PERIODIC_SETTINGS;
use pinnacle_linux::tasks::user_management::{self, GroupAction};
use pinnacle_linux::tasks::{
    firewall, prohibited_media, security_hardening, service_management, software_management,
};
use pinnacle_linux::user_ops::Account;
use pinnacle_linux::{pam_ops, readme_services};
use std::collections::HashSet;
use std::path::Path;

// =============================================================================
// The synthetic README
// =============================================================================

fn user(name: &str, password: Option<&str>, is_admin: bool, primary: bool) -> AuthorizedUser {
    AuthorizedUser {
        username: name.to_string(),
        password: password.map(str::to_string),
        is_admin,
        is_primary_user: primary,
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

/// What the key says the README contained.
fn readme() -> ReadmeData {
    ReadmeData {
        title: "CyberPatriot Ubuntu 22 Training Round 2 README (synthetic)".to_string(),
        operating_system: "Ubuntu 22.04".to_string(),
        scenario: "Non-work related media files are strictly prohibited on company computers. \
                   Employees need X2Go to work remotely."
            .to_string(),
        administrators: vec![
            user("heinz", Some("Ev!lInc0rp#2023"), true, true),
            // The key: "Changed insecure password for user alice". The README
            // publishes the administrators' passwords, and this one is weak.
            user("alice", Some("password1"), true, false),
        ],
        users: vec![
            // The trap in item 4: authorised user, not authorised administrator.
            user("cornelius", None, false, false),
            user("linda", None, false, false),
            user("mariya", None, false, false),
            user("rodney", None, false, false),
        ],
        required_software: vec![
            required("Firefox"),
            required("Thunderbird"),
            required("Perl"),
            required("X2Go"),
        ],
        critical_services: vec!["OpenSSH".to_string()],
        group_requirements: vec![GroupRequirement {
            group_name: "pioneers".to_string(),
            members: vec!["mariya".to_string()],
        }],
        ..Default::default()
    }
}

fn account(name: &str, uid: u32) -> Account {
    Account {
        name: name.to_string(),
        uid,
        gid: uid,
        comment: String::new(),
        home: format!("/home/{name}"),
        shell: "/bin/bash".to_string(),
    }
}

fn prohibited_names(readme: &ReadmeData) -> Vec<String> {
    software_management::prohibited_packages(Some(readme))
        .into_iter()
        .map(|(name, _)| name)
        .collect()
}

/// The sysctl `(key, value)` pairs the Security Hardening task writes.
fn sysctl_wanted() -> Vec<(&'static str, &'static str)> {
    HARDENING_SETTINGS
        .iter()
        .filter(|s| s.path == SYSCTL_DROPIN)
        .map(|s| (s.key, s.value))
        .collect()
}

fn sshd_wanted() -> Vec<(&'static str, &'static str)> {
    HARDENING_SETTINGS
        .iter()
        .filter(|s| s.path == SSHD_DROPIN)
        .map(|s| (s.key, s.value))
        .collect()
}

fn setting(key: &str) -> &'static str {
    HARDENING_SETTINGS
        .iter()
        .find(|s| s.key == key)
        .unwrap_or_else(|| panic!("{key} is not a hardening setting"))
        .value
}

/// Ubuntu 22.04's stock `common-password`.
const COMMON_PASSWORD: &str = "\
# here are the per-package modules (the \"Primary\" block)
password\trequisite\t\t\tpam_pwquality.so retry=3
password\t[success=1 default=ignore]\tpam_unix.so obscure use_authtok try_first_pass yescrypt
# here's the fallback if no module succeeds
password\trequisite\t\t\tpam_deny.so
password\trequired\t\t\tpam_permit.so
";

/// Ubuntu 22.04's stock `common-auth`, with the planted `nullok`.
const COMMON_AUTH_STOCK: &str = "\
auth\t[success=1 default=ignore]\tpam_unix.so nullok
auth\trequisite\t\t\tpam_deny.so
auth\trequired\t\t\tpam_permit.so
";

/// `common-auth` after `pam-auth-update` has applied the tool's two faillock
/// profiles.
const COMMON_AUTH_WITH_FAILLOCK: &str = "\
auth\trequisite\t\t\tpam_faillock.so preauth
auth\t[success=2 default=ignore]\tpam_unix.so try_first_pass
auth\t[default=die]\t\t\tpam_faillock.so authfail
auth\trequisite\t\t\tpam_deny.so
auth\trequired\t\t\tpam_permit.so
";

/// The value of `key=` on the first active `module` line of `text`.
fn module_arg(text: &str, module: &str, key: &str) -> Option<String> {
    let prefix = format!("{key}=");
    text.lines()
        .filter(|l| file_ops::is_active(l))
        .filter(|l| l.split_whitespace().any(|w| w == module))
        .find_map(|l| {
            l.split_whitespace()
                .find_map(|w| w.strip_prefix(&prefix))
                .map(str::to_string)
        })
}

// =============================================================================
// Scored items
// =============================================================================

/// **3) Removed unauthorized user eli: 2 pts.**
///
/// `eli` is in no README list, so he is the one surplus human account. The
/// authorised accounts stay.
#[test]
fn item_03_unauthorised_user_eli_is_removed() {
    let plan = user_management::authorised_from(&readme());
    assert!(!plan.everyone.contains("eli"));

    let present = vec![
        account("heinz", 1000),
        account("alice", 1001),
        account("cornelius", 1002),
        account("linda", 1003),
        account("mariya", 1004),
        account("rodney", 1005),
        account("eli", 1006),
    ];
    assert_eq!(
        user_management::unauthorised(&present, &plan.everyone),
        ["eli"]
    );
}

/// **4) User cornelius is not an administrator: 2 pts.**
///
/// He is an authorised *user*, so he keeps his account and loses `sudo`. The
/// task removes anyone in the admin group who is not in `plan.admins`.
#[test]
fn item_04_cornelius_keeps_his_account_but_loses_admin() {
    let plan = user_management::authorised_from(&readme());
    assert!(plan.everyone.contains("cornelius"));
    assert!(!plan.admins.contains("cornelius"));
    assert!(plan.admins.contains("heinz") && plan.admins.contains("alice"));
}

/// **5) Changed insecure password for user alice: 2 pts.**
///
/// The README publishes alice's password and it is weak; heinz's is strong and
/// is the primary user's, which must never be reset.
#[test]
fn item_05_alice_password_is_recognised_as_insecure() {
    assert!(!user_management::is_secure_password("password1"));
    assert!(user_management::is_secure_password("Ev!lInc0rp#2023"));
    assert_eq!(
        user_management::accounts_with_weak_passwords(&readme()),
        ["alice"]
    );
}

/// **6) Added mariya to group pioneers: 5 pts.**
///
/// The key runs `gpasswd -a mariya pioneers`, so the group already exists: the
/// plan is one additive `AddMember` and no `Create`. If the group were missing
/// the tool creates it first.
#[test]
fn item_06_mariya_is_added_to_pioneers() {
    let users: HashSet<String> = ["heinz", "alice", "cornelius", "linda", "mariya", "rodney"]
        .iter()
        .map(|s| s.to_string())
        .collect();

    let existing = vec!["sudo".to_string(), "pioneers".to_string()];
    assert_eq!(
        user_management::group_actions(&readme(), &existing, &users),
        [GroupAction::AddMember {
            group: "pioneers".to_string(),
            user: "mariya".to_string()
        }]
    );

    let missing = user_management::group_actions(&readme(), &["sudo".to_string()], &users);
    assert_eq!(missing[0], GroupAction::Create("pioneers".to_string()));
    assert_eq!(missing.len(), 2);
}

/// **7) A default minimum password age is set: 3 pts.**
///
/// "Guidelines recommend setting a minimum password age of 1-3 days
/// inclusive." The tool writes `PASS_MIN_DAYS 2` to `login.defs`.
#[test]
fn item_07_minimum_password_age_is_one_to_three_days() {
    let days: u32 = setting("PASS_MIN_DAYS").parse().expect("a number");
    assert!((1..=3).contains(&days), "PASS_MIN_DAYS is {days}");
}

/// **8) A minimum password length is required: 4 pts.**
///
/// The key appends `minlen=10` to the `pam_pwquality` line of
/// `common-password`; "10 or higher is recommended". The scorer reads the PAM
/// line, not `pwquality.conf`.
#[test]
fn item_08_minlen_is_on_the_pam_pwquality_line() {
    let fixed = pam_ops::with_password_args(COMMON_PASSWORD, 14, 5);
    let minlen: u32 = module_arg(&fixed, "pam_pwquality.so", "minlen")
        .expect("minlen on the pam_pwquality line")
        .parse()
        .expect("a number");
    assert!(minlen >= 10, "minlen={minlen}");
    assert!(pam_ops::password_args_present(&fixed, 14, 5));
    // Existing arguments survive, and the stack is still in a safe order.
    assert!(fixed.contains("retry=3"));
    assert!(fixed.contains("yescrypt"));
    // A second pass changes nothing.
    assert_eq!(pam_ops::with_password_args(&fixed, 14, 5), fixed);
}

/// **9) An account lockout policy is configured: 3 pts.**
///
/// The key builds two `pam-auth-update` profiles around `pam_faillock.so`
/// (`authfail` after `pam_unix`, `preauth` before it). The tool ships the same
/// pair; the file `pam-auth-update` then generates must carry both and still
/// let a correct password through.
#[test]
fn item_09_account_lockout_is_configured() {
    let bodies: String = pam_ops::FAILLOCK_PROFILES
        .iter()
        .map(|p| p.body)
        .collect::<Vec<_>>()
        .join("\n");
    assert!(bodies.contains("pam_faillock.so authfail"));
    assert!(bodies.contains("pam_faillock.so preauth"));
    assert!(bodies.contains("Default: yes"), "enabled without a prompt");

    assert!(
        !pinnacle_linux::tasks::password_policy::faillock_configured(COMMON_AUTH_STOCK),
        "the stock file has no lockout"
    );
    assert!(pinnacle_linux::tasks::password_policy::faillock_configured(
        COMMON_AUTH_WITH_FAILLOCK
    ));
    assert!(pam_ops::auth_order_is_safe(COMMON_AUTH_WITH_FAILLOCK));
}

/// **10) Null passwords do not authenticate: 3 pts.**
///
/// "Remove the option nullok" from the `pam_unix` line of `common-auth`.
#[test]
fn item_10_nullok_is_removed_from_common_auth() {
    assert!(pam_ops::has_nullok(COMMON_AUTH_STOCK));
    let fixed = pam_ops::strip_nullok(COMMON_AUTH_STOCK);
    assert!(!pam_ops::has_nullok(&fixed));
    assert!(fixed.contains("pam_unix.so"), "the module stays");
    assert!(
        fixed.contains("[success=1 default=ignore]"),
        "the control is untouched"
    );
    // `nullok_secure` is the same hole, spelled differently.
    assert!(!pam_ops::has_nullok(&pam_ops::strip_nullok(
        "auth\t[success=1 default=ignore]\tpam_unix.so nullok_secure try_first_pass\n"
    )));
}

/// **11) IPv4 TCP SYN cookies have been enabled: 4 pts.**
///
/// The image plants `net.ipv4.tcp_syncookies=0` in `/etc/sysctl.conf`, which is
/// read after our drop-in at `sysctl --system`, so writing the drop-in is not
/// enough: the contrary line has to be found and fixed.
#[test]
fn item_11_tcp_syncookies_are_enabled_despite_sysctl_conf() {
    assert_eq!(setting("net.ipv4.tcp_syncookies"), "1");
    let planted = vec![(
        "/etc/sysctl.conf".to_string(),
        "#net.ipv4.tcp_syncookies=1\nnet.ipv4.tcp_syncookies=0\n".to_string(),
    )];
    assert_eq!(
        security_hardening::sysctl_conflicts(&planted, &sysctl_wanted()),
        [(
            "/etc/sysctl.conf".to_string(),
            "net.ipv4.tcp_syncookies".to_string()
        )]
    );
}

/// **12) IPv4 forwarding has been disabled: 4 pts.**
///
/// `net.ipv4.ip_forward=1` is planted in `/etc/sysctl.conf`.
#[test]
fn item_12_ip_forwarding_is_disabled_despite_sysctl_conf() {
    assert_eq!(setting("net.ipv4.ip_forward"), "0");
    let planted = vec![(
        "/etc/sysctl.conf".to_string(),
        "net.ipv4.ip_forward=1\n".to_string(),
    )];
    assert_eq!(
        security_hardening::sysctl_conflicts(&planted, &sysctl_wanted()),
        [(
            "/etc/sysctl.conf".to_string(),
            "net.ipv4.ip_forward".to_string()
        )]
    );
    // A file that agrees, or does not mention the key, is left alone.
    let fine = vec![
        (
            "/etc/sysctl.conf".to_string(),
            "net.ipv4.ip_forward=0\n".to_string(),
        ),
        (
            "/etc/sysctl.d/10-x.conf".to_string(),
            "vm.swappiness=10\n".to_string(),
        ),
    ];
    assert!(security_hardening::sysctl_conflicts(&fine, &sysctl_wanted()).is_empty());
}

/// **13) Uncomplicated Firewall (UFW) protection has been enabled: 5 pts.**
///
/// Enabling must leave SSH open, because the README lists OpenSSH as critical
/// (penalty 1).
#[test]
fn item_13_ufw_is_enabled_with_ssh_reachable() {
    assert!(firewall::is_active("Status: active\n"));
    assert!(!firewall::is_active("Status: inactive\n"));
    let mut task = firewall::FirewallTask::new();
    task.set_readme_data(readme());
    assert!(task.ports_to_open().contains(&"22/tcp"));
}

/// **14) Insecure permissions on shadow file fixed: 5 pts.**
///
/// The key runs `chmod 640 /etc/shadow`.
#[test]
fn item_14_shadow_is_mode_640() {
    let (_, mode, owner, _) = CRITICAL_FILE_MODES
        .iter()
        .find(|(path, ..)| *path == "/etc/shadow")
        .expect("/etc/shadow is audited");
    assert_eq!(*mode, 0o640);
    assert_eq!(*owner, "root:shadow");
    assert_eq!(mode & 0o007, 0, "no world permissions");
}

/// **15) X2Go has been installed: 5 pts.**
///
/// "The ReadMe states that X2GO is required software." The README name has to
/// resolve to `x2goserver` or the install is silently skipped.
#[test]
fn item_15_x2go_resolves_to_x2goserver_and_is_installed() {
    let (resolved, unresolved) = software_management::required_packages(&readme());
    assert!(
        resolved.iter().any(|p| p == "x2goserver"),
        "resolved {resolved:?}, unresolved {unresolved:?}"
    );
    assert!(unresolved.is_empty(), "unresolved: {unresolved:?}");
    assert!(!prohibited_names(&readme()).contains(&"x2goserver".to_string()));
    for spelling in ["x2go", "X2GO SERVER", "X2Go Server"] {
        assert_eq!(
            pinnacle_core::software_matching::resolve_package_id(spelling, PACKAGE_IDS).as_deref(),
            Some("x2goserver"),
            "{spelling}"
        );
    }
}

/// **16) Nginx service has been disabled or removed: 4 pts.**
#[test]
fn item_16_nginx_is_masked() {
    let mut task = service_management::ServiceManagementTask::new();
    task.set_readme_data(readme());
    assert!(
        task.units_to_mask()
            .iter()
            .any(|(unit, _)| *unit == "nginx.service")
    );
}

/// **17) FTP service has been disabled or removed: 4 pts.**
///
/// The README does not call FTP critical, so vsftpd is masked.
#[test]
fn item_17_vsftpd_is_masked() {
    let mut task = service_management::ServiceManagementTask::new();
    task.set_readme_data(readme());
    assert!(
        task.units_to_mask()
            .iter()
            .any(|(unit, _)| *unit == "vsftpd.service"),
        "vsftpd must be masked when the README does not protect it"
    );
}

/// **18) The system automatically checks for updates daily: 5 pts.**
#[test]
fn item_18_updates_are_checked_daily() {
    let daily = PERIODIC_SETTINGS
        .iter()
        .find(|(key, ..)| *key == "APT::Periodic::Update-Package-Lists")
        .expect("the daily check is configured");
    assert_eq!(daily.1, "1", "1 means every day");
}

/// **19) Firefox has been updated: 4 pts.**
///
/// The upgrade is `apt upgrade`; the decision worth testing is that Firefox is
/// a package the tool knows (an unresolved name is an upgrade that never
/// reaches it) and never one it purges.
#[test]
fn item_19_firefox_is_an_upgradable_package() {
    assert_resolves_and_survives("firefox");
}

/// **20) Thunderbird has been updated: 4 pts.**
#[test]
fn item_20_thunderbird_is_an_upgradable_package() {
    assert_resolves_and_survives("thunderbird");
}

fn assert_resolves_and_survives(package: &str) {
    let data = readme();
    let (resolved, _) = software_management::required_packages(&data);
    assert!(resolved.iter().any(|p| p == package), "{resolved:?}");
    assert!(!prohibited_names(&data).contains(&package.to_string()));
}

/// **21) Prohibited MP3 files are removed: 4 pts.**
///
/// The scenario prohibits media, which authorises deletion; the scan recognises
/// the extension and a file in a user's `Music` directory is a delete, not a
/// report.
#[test]
fn item_21_mp3_files_in_lindas_music_are_deleted() {
    let mut task = prohibited_media::ProhibitedMediaTask::new();
    task.set_readme_data(readme());
    assert!(task.media_is_prohibited());

    let path = Path::new("/home/linda/Music/song.mp3");
    assert!(prohibited_media::is_media(path));
    assert!(!prohibited_media::is_exempt("/home/linda/Music/song.mp3"));
    let found = prohibited_media::Found {
        path: path.to_path_buf(),
        kind: prohibited_media::Kind::Media,
    };
    assert_eq!(
        prohibited_media::disposition(&found, &[], task.media_is_prohibited()),
        prohibited_media::Disposition::Delete
    );
}

/// **22) Prohibited software AisleRiot removed: 4 pts.**
///
/// "sudo apt purge aisleriot". The README never names it.
#[test]
fn item_22_aisleriot_is_purged() {
    assert!(prohibited_names(&readme()).contains(&"aisleriot".to_string()));
    assert!(ALWAYS_PROHIBITED.iter().any(|(p, _)| *p == "aisleriot"));
}

/// **23) Removed netcat backdoor: 5 pts.**
///
/// `nc.traditional` listening on 1337, started from `/etc/crontab`. The key
/// kills it, removes the crontab line and removes `/usr/bin/nc.traditional`.
/// The tool: detects the listener from `ss`, classifies it as a raw listener
/// whatever its port, disables the cron line, and leaves the package-owned
/// binary to the purge of `netcat-traditional`.
#[test]
fn item_23_netcat_backdoor_is_found_and_removed() {
    let ss = "tcp LISTEN 0 1 0.0.0.0:1337 0.0.0.0:* users:((\"nc.traditional\",pid=812,fd=3))\n\
              tcp LISTEN 0 128 0.0.0.0:22 0.0.0.0:* users:((\"sshd\",pid=700,fd=3))\n";
    let listeners = backdoor_listeners::parse_ss(ss);
    let nc = listeners
        .iter()
        .find(|l| l.process == "nc.traditional")
        .expect("the listener is parsed");
    assert_eq!((nc.port, nc.pid), (1337, 812));

    let facts = ProcessFacts {
        pid: 812,
        comm: "nc.traditional".to_string(),
        exe: "/usr/bin/nc.traditional".to_string(),
        args: vec![
            "/usr/bin/nc.traditional".to_string(),
            "-l".to_string(),
            "-p".to_string(),
            "1337".to_string(),
        ],
        ..Default::default()
    };
    // dpkg owns the binary (netcat-traditional).
    let verdict = backdoor_listeners::classify(&facts, Some(&readme()), |_| Ownership::Owned)
        .expect("a raw listener is a backdoor");
    assert_eq!(verdict.kind, Kind::RawListener);
    assert_eq!(
        verdict.left_for_purge.as_deref(),
        Some("/usr/bin/nc.traditional")
    );
    assert!(verdict.delete.is_empty(), "never delete a package's file");
    assert!(prohibited_names(&readme()).contains(&"netcat-traditional".to_string()));

    // The crontab line that launches it is disabled; its neighbours are not.
    let line = "*/5 * * * * root /usr/bin/nc.traditional -l -p 1337 -e /bin/bash";
    assert!(backdoor_listeners::cron_line_matches(line, &verdict));
    assert!(backdoor_listeners::disable_cron_line(line).starts_with('#'));
    assert!(!backdoor_listeners::cron_line_matches(
        "17 * * * * root cd / && run-parts --report /etc/cron.hourly",
        &verdict
    ));

    // sshd is never a backdoor, even though it listens.
    let sshd = ProcessFacts {
        pid: 700,
        comm: "sshd".to_string(),
        exe: "/usr/sbin/sshd".to_string(),
        ..Default::default()
    };
    assert!(
        backdoor_listeners::classify(&sshd, Some(&readme()), |_| Ownership::NotOwned).is_none()
    );
}

/// **24) SSH root login has been disabled: 5 pts.**
///
/// The image plants `PermitRootLogin yes` in the main `sshd_config`, which
/// Ubuntu's `Include` reads *before* any later drop-in - and the scorer greps.
#[test]
fn item_24_ssh_root_login_is_disabled_in_the_main_file() {
    assert_eq!(setting("PermitRootLogin"), "no");
    assert!(SSHD_DROPIN.contains("/00-"), "the drop-in sorts first");

    let main = "Include /etc/ssh/sshd_config.d/*.conf\n\
                #PermitRootLogin prohibit-password\n\
                PermitRootLogin yes\n\
                PasswordAuthentication yes\n";
    let files = vec![("/etc/ssh/sshd_config".to_string(), main.to_string())];
    let conflicts = security_hardening::sshd_conflicts(&files, &sshd_wanted());
    assert!(conflicts.contains(&(
        "/etc/ssh/sshd_config".to_string(),
        "PermitRootLogin".to_string()
    )));

    let fixed = security_hardening::rewrite_sshd_conflicts(main, &sshd_wanted());
    assert_eq!(
        file_ops::active_values(&fixed, Style::Space, "PermitRootLogin"),
        ["no"],
        "the file the scorer greps says no:\n{fixed}"
    );
    assert!(fixed.contains("Include /etc/ssh/sshd_config.d/*.conf"));
}

// =============================================================================
// Penalties - things the tool must NOT do
// =============================================================================

/// **Penalty 1) OpenSSH service has been stopped, disabled, or removed: -5 pts.**
#[test]
fn penalty_01_openssh_is_never_masked_or_purged() {
    let data = readme();
    assert!(readme_services::is_critical(Some(&data), "ssh.service"));

    let mut task = service_management::ServiceManagementTask::new();
    task.set_readme_data(data.clone());
    assert!(task.required_units().contains(&"ssh.service".to_string()));
    assert!(
        !task
            .units_to_mask()
            .iter()
            .any(|(unit, _)| unit.starts_with("ssh")),
        "no ssh unit may be masked"
    );
    assert!(!prohibited_names(&data).contains(&"openssh-server".to_string()));
    // Whatever the README says, the backdoor sweep spares sshd.
    assert!(
        !PROHIBITED_SERVICES
            .iter()
            .any(|(unit, _)| unit.starts_with("ssh")),
        "ssh is not a prohibited service"
    );
}

/// **Penalty 2) Firefox has been removed: -5 pts.**
#[test]
fn penalty_02_firefox_is_required_software() {
    assert_required("Firefox", "firefox");
}

/// **Penalty 3) Thunderbird has been removed: -5 pts.**
#[test]
fn penalty_03_thunderbird_is_required_software() {
    assert_required("Thunderbird", "thunderbird");
}

/// **Penalty 4) Perl has been removed: -5 pts.**
#[test]
fn penalty_04_perl_is_required_software() {
    assert_required("Perl", "perl");
}

fn assert_required(display: &str, package: &str) {
    let data = readme();
    assert!(
        data.required_software
            .iter()
            .any(|s| s.name.eq_ignore_ascii_case(display))
    );
    let (resolved, unresolved) = software_management::required_packages(&data);
    assert!(
        resolved.iter().any(|p| p == package),
        "{display}: resolved {resolved:?}, unresolved {unresolved:?}"
    );
    assert!(
        !prohibited_names(&data).contains(&package.to_string()),
        "{package} is required and must never be purged"
    );
}

// =============================================================================
// Not automatable
// =============================================================================

/// **1) Forensics Question 1: 7 pts** and **2) Forensics Question 2: 7 pts.**
///
/// Question 1 is a base64 file on the Desktop that sends you to the Trash;
/// question 2 asks for the directory holding the prohibited MP3s. Both need a
/// person, and the second is answered *before* the media is deleted - the
/// tool's media task prints what it removes for exactly that reason.
#[test]
fn items_01_and_02_forensics_questions_are_for_a_human() {
    // Recorded rather than skipped silently: 14 points are outside automation.
}

// =============================================================================
// Coverage
// =============================================================================

/// Every item: (number, title, points, automated).
const SCORING: &[(u32, &str, i32, bool)] = &[
    (1, "Forensics Question 1", 7, false),
    (2, "Forensics Question 2", 7, false),
    (3, "Removed unauthorized user eli", 2, true),
    (4, "cornelius is not an administrator", 2, true),
    (5, "Changed insecure password for alice", 2, true),
    (6, "Added mariya to group pioneers", 5, true),
    (7, "Minimum password age", 3, true),
    (8, "Minimum password length", 4, true),
    (9, "Account lockout policy", 3, true),
    (10, "Null passwords do not authenticate", 3, true),
    (11, "TCP SYN cookies", 4, true),
    (12, "IPv4 forwarding disabled", 4, true),
    (13, "UFW enabled", 5, true),
    (14, "Shadow file permissions", 5, true),
    (15, "X2Go installed", 5, true),
    (16, "Nginx disabled or removed", 4, true),
    (17, "FTP disabled or removed", 4, true),
    (18, "Daily update check", 5, true),
    (19, "Firefox updated", 4, true),
    (20, "Thunderbird updated", 4, true),
    (21, "Prohibited MP3 files removed", 4, true),
    (22, "AisleRiot removed", 4, true),
    (23, "Removed netcat backdoor", 5, true),
    (24, "SSH root login disabled", 5, true),
];

/// Penalties the tool must avoid incurring.
const PENALTIES: &[(&str, i32)] = &[
    ("OpenSSH stopped, disabled or removed", -5),
    ("Firefox removed", -5),
    ("Thunderbird removed", -5),
    ("Perl removed", -5),
];

/// Items the tool deliberately does not attempt, beyond the forensics
/// questions: none. Kept as a list so adding one forces a written reason.
const NOT_AUTOMATED: &[(u32, &str)] = &[
    (
        1,
        "forensics: decode a base64 file and open a file in the Trash",
    ),
    (
        2,
        "forensics: report the directory holding the prohibited MP3 files",
    ),
];

/// The key's arithmetic: 100 points, 86 of them reachable by automation.
#[test]
fn the_tool_can_reach_every_point_that_is_not_a_forensics_question() {
    let total: i32 = SCORING.iter().map(|(_, _, points, _)| points).sum();
    assert_eq!(total, 100);
    let automated: i32 = SCORING
        .iter()
        .filter(|(.., automated)| *automated)
        .map(|(_, _, points, _)| points)
        .sum();
    assert_eq!(automated, 86);
    assert_eq!(PENALTIES.iter().map(|(_, p)| p).sum::<i32>(), -20);

    // NOT_AUTOMATED and SCORING agree.
    let manual: Vec<u32> = SCORING
        .iter()
        .filter(|(.., automated)| !automated)
        .map(|(n, ..)| *n)
        .collect();
    let listed: Vec<u32> = NOT_AUTOMATED.iter().map(|(n, _)| *n).collect();
    assert_eq!(manual, listed);
}

/// Every automatable item has an `item_NN_*` test, and every penalty a
/// `penalty_NN_*` test.
#[test]
fn every_automatable_item_has_a_test() {
    let source = include_str!("answer_key_ubuntu22_training2.rs");
    for (number, title, _points, automated) in SCORING {
        if !automated {
            continue;
        }
        let prefix = format!("fn item_{number:02}_");
        assert!(
            source.contains(&prefix),
            "item {number} ({title}) is automatable but has no {prefix}* test"
        );
    }
    for (index, (title, _)) in PENALTIES.iter().enumerate() {
        let prefix = format!("fn penalty_{:02}_", index + 1);
        assert!(
            source.contains(&prefix),
            "penalty {title} has no {prefix}* test"
        );
    }
}
