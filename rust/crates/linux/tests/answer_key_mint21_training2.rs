// =============================================================================
// PinnacleCyPat - The CP18 Mint 21 Training Round 2 answer key, as tests
// Copyright 2026 Maxwell McCormick
// SPDX-License-Identifier: Apache-2.0
// =============================================================================

//! Every scored item and penalty from `CP18_Mint21_Training2_Answer_Key.pdf`,
//! one test each: three forensics questions (for a human) and twenty-three
//! automatable items, plus two penalties.
//!
//! **The README is synthetic.** No README was supplied for this round, so
//! [`readme`] builds the `ReadmeData` the key says it contained: authorised
//! administrators and users (`may`, `peni`, `stan` and `miguel` among them),
//! a request to create a group called `spider` holding those four, vsftpd as a
//! critical service, and a scenario that prohibits non-work media. The accounts
//! the key plants are `penguru` and `liv` (unauthorised; `liv` hides at uid 999
//! with a home under `/home`), `ham` (authorised user in the `sudo` group) and
//! `noir` (no maximum password age). Anything the key does not say - the
//! administrators' names, the primary user, the required software - is invented.
//!
//! **Two things the extracted key text does not give.** Item 5's header is
//! missing from the extraction and item 25's is merged into item 24's ("doona
//! and xproble, 3 pts. each"). Item 5 is read as the removal of the hidden user
//! `liv` (the item 4 text says "The user liv is a hidden user"); items 4 and 5
//! therefore carry no point value here.
//!
//! Like `answer_key.rs`, these test the tool's *decisions*, never `execute()`,
//! and never touch the host.

use pinnacle_core::models::{AuthorizedUser, GroupRequirement, ReadmeData, SoftwareRequirement};
use pinnacle_linux::file_ops;
use pinnacle_linux::knowledge::{
    ALWAYS_PROHIBITED, HARDENING_SETTINGS, PACKAGE_IDS, SYSCTL_DROPIN,
};
use pinnacle_linux::tasks::account_permissions::root_needs_lock;
use pinnacle_linux::tasks::backdoor_listeners::{self, Kind, Ownership, ProcessFacts};
use pinnacle_linux::tasks::prohibited_media::{self, Disposition, Found};
use pinnacle_linux::tasks::software_update::{
    MINT_AUTOMATION_FLAG, MINT_AUTOMATION_TIMER, is_linux_mint,
};
use pinnacle_linux::tasks::user_management::{self, GroupAction};
use pinnacle_linux::tasks::{
    firewall, security_hardening, service_management, software_management,
};
use pinnacle_linux::user_ops::{self, Account};
use pinnacle_linux::{apt, pam_ops, readme_services};
use std::collections::HashSet;
use std::path::{Path, PathBuf};

// =============================================================================
// The synthetic README and its helpers
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

fn readme() -> ReadmeData {
    ReadmeData {
        title: "CyberPatriot Mint 21 Training Round 2 README (synthetic)".to_string(),
        operating_system: "Linux Mint 21".to_string(),
        scenario: "Non-work related media files are strictly prohibited on company computers. \
                   The company runs a public FTP server."
            .to_string(),
        administrators: vec![
            user("kirk", Some("Enterpr!se#1701"), true, true),
            user("spock", Some("L1ve-Long&Pr0sper"), true, false),
        ],
        users: vec![
            // `ham` is authorised as a user but is not an administrator.
            user("ham", None, false, false),
            user("noir", None, false, false),
            user("may", None, false, false),
            user("peni", None, false, false),
            user("stan", None, false, false),
            user("miguel", None, false, false),
            user("steve", None, false, false),
        ],
        required_software: vec![SoftwareRequirement {
            name: "Firefox".to_string(),
            should_be_latest: true,
            ..Default::default()
        }],
        critical_services: vec!["vsftpd".to_string()],
        group_requirements: vec![GroupRequirement {
            group_name: "spider".to_string(),
            members: ["may", "peni", "stan", "miguel"]
                .iter()
                .map(|s| s.to_string())
                .collect(),
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

/// The hidden user the key plants: `liv:x:999:999::/home/liv:/bin/bash`.
fn liv() -> Account {
    user_ops::parse_passwd("liv:x:999:999::/home/liv:/bin/bash\n")
        .pop()
        .expect("the line parses")
}

fn prohibited_names(readme: &ReadmeData) -> Vec<String> {
    software_management::prohibited_packages(Some(readme))
        .into_iter()
        .map(|(name, _)| name)
        .collect()
}

fn sysctl_wanted() -> Vec<(&'static str, &'static str)> {
    HARDENING_SETTINGS
        .iter()
        .filter(|s| s.path == SYSCTL_DROPIN)
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

/// Mint 21's stock `common-password`: the key appends to the `pam_unix` line,
/// and there is no `pam_pwquality` line to append to.
const COMMON_PASSWORD: &str = "\
password\t[success=1 default=ignore]\tpam_unix.so obscure yescrypt
password\trequisite\t\t\tpam_deny.so
password\trequired\t\t\tpam_permit.so
";

const COMMON_AUTH_STOCK: &str = "\
auth\t[success=1 default=ignore]\tpam_unix.so try_first_pass nullok
auth\trequisite\t\t\tpam_deny.so
auth\trequired\t\t\tpam_permit.so
";

const COMMON_AUTH_WITH_FAILLOCK: &str = "\
auth\trequisite\t\t\tpam_faillock.so preauth
auth\t[success=2 default=ignore]\tpam_unix.so try_first_pass
auth\t[default=die]\t\t\tpam_faillock.so authfail
auth\trequisite\t\t\tpam_deny.so
auth\trequired\t\t\tpam_permit.so
";

const MINT_OS_RELEASE: &str = "NAME=\"Linux Mint\"\nVERSION=\"21.3 (Virginia)\"\nID=linuxmint\n\
                               ID_LIKE=\"ubuntu debian\"\n";
const UBUNTU_OS_RELEASE: &str = "NAME=\"Ubuntu\"\nVERSION=\"22.04.3 LTS (Jammy Jellyfish)\"\n\
                                 ID=ubuntu\nID_LIKE=debian\n";

fn vsftpd_conf() -> &'static str {
    "listen=YES\nanonymous_enable=YES\nanon_root=/srv/ftp/public\n# local_root=/nope\n"
}

// =============================================================================
// Scored items
// =============================================================================

/// **4) Removed unauthorized users penguru: pts not in the extracted text.**
///
/// `penguru` is in no README list; every authorised account stays.
#[test]
fn item_04_unauthorised_user_penguru_is_removed() {
    let plan = user_management::authorised_from(&readme());
    let present = vec![
        account("kirk", 1000),
        account("spock", 1001),
        account("ham", 1002),
        account("noir", 1003),
        account("may", 1004),
        account("penguru", 1010),
    ];
    assert_eq!(
        user_management::unauthorised(&present, &plan.everyone),
        ["penguru"]
    );
}

/// **5) Removed unauthorized user liv (hidden, uid 999): pts not in the text.**
///
/// "The user liv is a hidden user since her uid is less than 1000." The old
/// uid test called her a package account and never considered her. She is
/// selected because she has a login shell and a home under `/home`; package
/// accounts are not.
#[test]
fn item_05_hidden_user_liv_is_removed() {
    let liv = liv();
    assert_eq!((liv.uid, liv.home.as_str()), (999, "/home/liv"));
    assert!(!liv.is_human(), "uid 999 is below the human range");
    assert!(liv.is_hidden_human());

    let plan = user_management::authorised_from(&readme());
    let present = vec![
        account("kirk", 1000),
        liv.clone(),
        user_ops::parse_passwd("daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\n")
            .pop()
            .unwrap(),
        user_ops::parse_passwd("www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin\n")
            .pop()
            .unwrap(),
        user_ops::parse_passwd("syslog:x:104:110::/home/syslog:/usr/sbin/nologin\n")
            .pop()
            .unwrap(),
        user_ops::parse_passwd("nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin\n")
            .pop()
            .unwrap(),
    ];
    assert_eq!(
        user_management::unauthorised(&present, &plan.everyone),
        ["liv"],
        "only the hidden human is surplus; package accounts are never selected"
    );
}

/// **6) User ham is not an administrator: 3 pts.**
///
/// The key runs `gpasswd -d ham sudo`; `ham` is an authorised user and keeps
/// his account.
#[test]
fn item_06_ham_keeps_his_account_but_loses_admin() {
    let plan = user_management::authorised_from(&readme());
    assert!(plan.everyone.contains("ham"));
    assert!(!plan.admins.contains("ham"));
}

/// **7) User noir has a maximum password age: 4 pts.**
///
/// The key runs `chage -M 90 noir`. Account Permissions ages every human
/// account with the `login.defs` figure; `noir` is one, and the default is 90.
#[test]
fn item_07_noir_gets_a_maximum_password_age() {
    assert!(account("noir", 1003).is_human());
    let days: u32 = setting("PASS_MAX_DAYS").parse().expect("a number");
    assert!((1..=90).contains(&days), "PASS_MAX_DAYS is {days}");
}

/// **8) Created the group spider: 3 pts.**
///
/// The group is not in `/etc/group`, so the plan starts with a `Create`.
#[test]
fn item_08_group_spider_is_created() {
    let plan = group_plan(&["sudo", "adm"]);
    assert_eq!(plan[0], GroupAction::Create("spider".to_string()));
}

/// **9) Added users to group spider: 4 pts.**
///
/// may, peni, stan and miguel, additively, after the group exists. Nobody else
/// is touched.
#[test]
fn item_09_users_are_added_to_spider() {
    let plan = group_plan(&["sudo", "adm"]);
    let added: Vec<&str> = plan
        .iter()
        .filter_map(|a| match a {
            GroupAction::AddMember { group, user } if group == "spider" => Some(user.as_str()),
            _ => None,
        })
        .collect();
    assert_eq!(added, ["may", "peni", "stan", "miguel"]);
    assert_eq!(plan.len(), 5, "one Create and four AddMember, nothing else");

    // And once the group exists there is no Create.
    let again = group_plan(&["sudo", "spider"]);
    assert!(!again.iter().any(|a| matches!(a, GroupAction::Create(_))));
}

fn group_plan(existing: &[&str]) -> Vec<GroupAction> {
    let users: HashSet<String> = [
        "kirk", "spock", "ham", "noir", "may", "peni", "stan", "miguel",
    ]
    .iter()
    .map(|s| s.to_string())
    .collect();
    let existing: Vec<String> = existing.iter().map(|s| s.to_string()).collect();
    user_management::group_actions(&readme(), &existing, &users)
}

/// **10) Root password is no longer blank: 4 pts.**
///
/// The key runs `passwd -l root`. An empty shadow hash is the only state that
/// gets locked; a root that has a password, or is already locked, is left alone.
#[test]
fn item_10_blank_root_password_is_locked() {
    assert_eq!(user_ops::classify_hash(""), "no password");
    assert!(root_needs_lock(Some(&user_ops::classify_hash(""))));
    assert!(!root_needs_lock(Some(&user_ops::classify_hash("!"))));
    assert!(!root_needs_lock(Some(&user_ops::classify_hash(
        "!$y$j9T$abc"
    ))));
    assert!(!root_needs_lock(Some(&user_ops::classify_hash(
        "$y$j9T$abc"
    ))));
    assert!(!root_needs_lock(None), "unreadable shadow is not a finding");
}

/// **11) A minimum password length is required: 3 pts.**
///
/// The key appends `minlen=10` to the `pam_unix` line (Mint's stock file has no
/// `pam_pwquality` line); "10 or higher is recommended".
#[test]
fn item_11_minlen_is_on_the_pam_unix_line() {
    let fixed = pam_ops::with_password_args(COMMON_PASSWORD, 14, 5);
    let minlen: u32 = module_arg(&fixed, "pam_unix.so", "minlen")
        .expect("minlen on the pam_unix line")
        .parse()
        .expect("a number");
    assert!(minlen >= 10, "minlen={minlen}");
    assert!(
        fixed.contains("obscure yescrypt"),
        "existing options survive"
    );
    assert!(
        !fixed.contains("pam_pwquality.so"),
        "a module that is not in the stack is not added"
    );
}

/// **12) Previous passwords are remembered: 3 pts.**
///
/// The key appends `remember=3` to the `pam_unix` line. The tool writes its own
/// depth (5), which is at least as strict; the key's text does not say whether
/// the scorer wants exactly 3 or at least 3, so this pins "at least 3".
#[test]
fn item_12_remember_is_on_the_pam_unix_line() {
    let fixed = pam_ops::with_password_args(COMMON_PASSWORD, 14, 5);
    let remember: u32 = module_arg(&fixed, "pam_unix.so", "remember")
        .expect("remember on the pam_unix line")
        .parse()
        .expect("a number");
    assert!(remember >= 3, "remember={remember}");
    assert_eq!(pam_ops::history_depth(&fixed), Some(remember));
}

/// **13) An account lockout policy is configured: 4 pts.**
///
/// The key adds `faillock` profiles (authfail, authsucc reset, preauth notify)
/// and runs `pam-auth-update`; the scorer reads `pam_faillock.so` out of
/// `common-auth`. The tool's profiles produce the same lines, in an order that
/// still lets a correct password in.
#[test]
fn item_13_account_lockout_is_configured() {
    let bodies: String = pam_ops::FAILLOCK_PROFILES
        .iter()
        .map(|p| p.body)
        .collect::<Vec<_>>()
        .join("\n");
    for needle in ["pam_faillock.so authfail", "pam_faillock.so preauth"] {
        assert!(bodies.contains(needle), "{needle}");
    }
    assert!(bodies.contains("Account:"), "the reset-on-success half");
    assert!(!pinnacle_linux::tasks::password_policy::faillock_configured(COMMON_AUTH_STOCK));
    assert!(pinnacle_linux::tasks::password_policy::faillock_configured(
        COMMON_AUTH_WITH_FAILLOCK
    ));
    assert!(pam_ops::auth_order_is_safe(COMMON_AUTH_WITH_FAILLOCK));
}

/// **14) Null passwords do not authenticate: 4 pts.**
///
/// "Find auth [success=2 default=ignore] pam_unix.so try_first_pass nullok ...
/// remove the option nullok."
#[test]
fn item_14_nullok_is_removed_from_common_auth() {
    assert!(pam_ops::has_nullok(COMMON_AUTH_STOCK));
    let fixed = pam_ops::strip_nullok(COMMON_AUTH_STOCK);
    assert!(!pam_ops::has_nullok(&fixed));
    assert!(fixed.contains("pam_unix.so try_first_pass"), "{fixed}");
}

/// **15) Address space layout randomization enabled: 4 pts.**
///
/// `kernel.randomize_va_space=0` is planted in `/etc/sysctl.conf`.
#[test]
fn item_15_aslr_is_enabled_despite_sysctl_conf() {
    assert_eq!(setting("kernel.randomize_va_space"), "2");
    let planted = vec![(
        "/etc/sysctl.conf".to_string(),
        "kernel.randomize_va_space=0\n".to_string(),
    )];
    assert_eq!(
        security_hardening::sysctl_conflicts(&planted, &sysctl_wanted()),
        [(
            "/etc/sysctl.conf".to_string(),
            "kernel.randomize_va_space".to_string()
        )]
    );
}

/// **16) IPv4 TCP SYN cookies have been enabled: 4 pts.**
#[test]
fn item_16_tcp_syncookies_are_enabled_despite_sysctl_conf() {
    assert_eq!(setting("net.ipv4.tcp_syncookies"), "1");
    let planted = vec![(
        "/etc/sysctl.conf".to_string(),
        "net.ipv4.tcp_syncookies=0\n".to_string(),
    )];
    assert_eq!(
        security_hardening::sysctl_conflicts(&planted, &sysctl_wanted()),
        [(
            "/etc/sysctl.conf".to_string(),
            "net.ipv4.tcp_syncookies".to_string()
        )]
    );
}

/// **17) Uncomplicated Firewall (UFW) protection has been enabled: 3 pts.**
///
/// vsftpd is critical, so port 21 is opened as well as SSH before the default
/// deny goes on - or enabling the firewall would itself cost penalty 1.
#[test]
fn item_17_ufw_is_enabled_with_ftp_and_ssh_open() {
    assert!(firewall::is_active("Status: active\n"));
    let mut task = firewall::FirewallTask::new();
    task.set_readme_data(readme());
    let ports = task.ports_to_open();
    assert!(ports.contains(&"22/tcp"), "{ports:?}");
    assert!(ports.contains(&"21/tcp"), "{ports:?}");
}

/// **18) Nginx service has been disabled or removed: 4 pts.**
#[test]
fn item_18_nginx_is_masked() {
    assert!(masked_units().contains(&"nginx.service"));
}

/// **19) Squid proxy service has been disabled or removed: 4 pts.**
#[test]
fn item_19_squid_is_masked() {
    assert!(masked_units().contains(&"squid.service"));
}

fn masked_units() -> Vec<&'static str> {
    let mut task = service_management::ServiceManagementTask::new();
    task.set_readme_data(readme());
    task.units_to_mask().into_iter().map(|(u, _)| u).collect()
}

/// **20) The update manager installs updates automatically: 3 pts.**
///
/// Edit > Preferences > Automation > "Apply updates automatically" is a flag
/// file plus the `mintupdate-automation-upgrade.timer` unit. The tool does it
/// only on Linux Mint (`ID=linuxmint`), never on Ubuntu.
#[test]
fn item_20_mint_update_manager_applies_updates_automatically() {
    assert!(is_linux_mint(MINT_OS_RELEASE));
    assert!(!is_linux_mint(UBUNTU_OS_RELEASE));
    assert!(MINT_AUTOMATION_FLAG.starts_with("/var/lib/linuxmint/"));
    assert_eq!(MINT_AUTOMATION_TIMER, "mintupdate-automation-upgrade.timer");
}

/// **21) Vsftpd updated: 3 pts.**
///
/// The key runs `apt update && apt full-upgrade`. The decisions worth pinning:
/// vsftpd is a package the tool knows, is never one it purges (it is critical),
/// and an `Inst vsftpd` line in a simulated upgrade is read as an upgrade.
#[test]
fn item_21_vsftpd_is_an_upgradable_package_and_is_not_purged() {
    assert_eq!(
        pinnacle_core::software_matching::resolve_package_id("vsftpd", PACKAGE_IDS).as_deref(),
        Some("vsftpd")
    );
    assert!(!prohibited_names(&readme()).contains(&"vsftpd".to_string()));

    let simulated =
        "Inst vsftpd [3.0.3-13ubuntu1] (3.0.5-0ubuntu1 Ubuntu:22.04/jammy-updates [amd64])\n";
    let upgrades = apt::parse_simulated_upgrade(simulated);
    assert_eq!(upgrades.len(), 1);
    assert_eq!(upgrades[0].0, "vsftpd");
}

/// **22) Prohibited OGG files are removed: 4 pts.**
///
/// `rm /home/steve/Music/*/*/*.ogg`: three directories deep, in a home that is
/// not exempt, with the scenario authorising media deletion.
#[test]
fn item_22_ogg_files_in_steves_music_are_deleted() {
    let path = Path::new("/home/steve/Music/Album/Disc1/track.ogg");
    assert!(prohibited_media::is_media(path));
    assert!(!prohibited_media::is_exempt(
        "/home/steve/Music/Album/Disc1/track.ogg"
    ));
    let mut task = prohibited_media::ProhibitedMediaTask::new();
    task.set_readme_data(readme());
    assert!(task.media_is_prohibited());
    let found = Found {
        path: path.to_path_buf(),
        kind: prohibited_media::Kind::Media,
    };
    assert_eq!(
        prohibited_media::disposition(&found, &protected_roots(), true),
        Disposition::Delete
    );
}

fn protected_roots() -> Vec<String> {
    prohibited_media::protected_roots(Some(&readme()), Some(vsftpd_conf()), None)
}

/// **23) Removed prohibited software archive pyrdp: 4 pts.**
///
/// `/usr/games/pyrdp-master.zip`: an archive named for a tool, outside `/home`.
/// The README never names it. A tool-named archive is deleted without the
/// README having to authorise it, but a look-alike is not.
#[test]
fn item_23_pyrdp_archive_in_usr_games_is_deleted() {
    let path = Path::new("/usr/games/pyrdp-master.zip");
    assert!(prohibited_media::is_hacking_tool_name("pyrdp-master.zip"));
    assert!(prohibited_media::is_hacking_tool(path, false));
    assert!(!prohibited_media::is_exempt("/usr/games/pyrdp-master.zip"));
    assert!(!prohibited_media::is_required_software(
        Some(&readme()),
        "pyrdp-master.zip"
    ));
    let found = Found {
        path: path.to_path_buf(),
        kind: prohibited_media::Kind::HackingTool,
    };
    // Deleted even though no README prohibited anything.
    assert_eq!(
        prohibited_media::disposition(&found, &protected_roots(), false),
        Disposition::Delete
    );
    // Look-alikes are not hacking tools.
    for innocent in ["patchnotes.zip", "hydrate.sh", "Mabel.sh", "notes.txt"] {
        assert!(
            !prohibited_media::is_hacking_tool(Path::new(&format!("/usr/games/{innocent}")), false),
            "{innocent}"
        );
    }
}

/// **24) Prohibited software doona removed: 3 pts.**
#[test]
fn item_24_doona_is_purged() {
    assert!(prohibited_names(&readme()).contains(&"doona".to_string()));
    assert!(ALWAYS_PROHIBITED.iter().any(|(p, _)| *p == "doona"));
}

/// **25) Prohibited software xprobe removed: 3 pts.** The key writes "doona and
/// xproble ... 3 pts. each"; the package is `xprobe`.
#[test]
fn item_25_xprobe_is_purged() {
    assert!(prohibited_names(&readme()).contains(&"xprobe".to_string()));
    assert!(ALWAYS_PROHIBITED.iter().any(|(p, _)| *p == "xprobe"));
}

/// **26) Removed zod backdoor: 6 pts.**
///
/// `python3 /usr/share/zod/kneelB4zod.py` listening on 1337. The key deletes
/// the script and kills the process. The interpreter is package-owned and the
/// script is not, so the tool judges the *script*: it is deleted, nothing else
/// is. A vsftpd listener on 21 and sshd are never selected.
#[test]
fn item_26_zod_backdoor_is_found_and_removed() {
    let ss = "tcp LISTEN 0 5 0.0.0.0:1337 0.0.0.0:* users:((\"python3\",pid=977,fd=3))\n\
              tcp LISTEN 0 32 0.0.0.0:21 0.0.0.0:* users:((\"vsftpd\",pid=640,fd=3))\n";
    let listeners = backdoor_listeners::parse_ss(ss);
    assert!(
        listeners
            .iter()
            .any(|l| l.process == "python3" && l.port == 1337 && l.pid == 977)
    );

    let facts = ProcessFacts {
        pid: 977,
        comm: "python3".to_string(),
        exe: "/usr/bin/python3.10".to_string(),
        args: vec![
            "python3".to_string(),
            "/usr/share/zod/kneelB4zod.py".to_string(),
        ],
        cwd: Some("/".to_string()),
        ..Default::default()
    };
    let owned = |path: &str| {
        if path.starts_with("/usr/bin/") {
            Ownership::Owned
        } else {
            Ownership::NotOwned
        }
    };
    let verdict = backdoor_listeners::classify(&facts, Some(&readme()), owned)
        .expect("an unowned script under an interpreter is a backdoor");
    assert_eq!(verdict.kind, Kind::UnownedScript);
    assert_eq!(verdict.delete, ["/usr/share/zod/kneelB4zod.py"]);

    // The same python running a package's own script is left alone.
    let packaged = ProcessFacts {
        args: vec![
            "python3".to_string(),
            "/usr/bin/unattended-upgrade".to_string(),
        ],
        ..facts.clone()
    };
    assert!(
        backdoor_listeners::classify(&packaged, Some(&readme()), |_| Ownership::Owned).is_none()
    );

    // vsftpd is critical in this README, so even an unowned vsftpd is exempt.
    let ftp = ProcessFacts {
        pid: 640,
        comm: "vsftpd".to_string(),
        exe: "/usr/sbin/vsftpd".to_string(),
        ..Default::default()
    };
    assert!(backdoor_listeners::classify(&ftp, Some(&readme()), |_| Ownership::NotOwned).is_none());
}

// =============================================================================
// Penalties - things the tool must NOT do
// =============================================================================

/// **Penalty 1) VSFTP service has been stopped or removed: -5 pts.**
///
/// The README lists vsftpd as critical, so it is protected from the mask list,
/// its port stays open and its package is never purged. (The key says "VSFTP";
/// whichever spelling the README used has to resolve to `vsftpd.service`.)
#[test]
fn penalty_01_vsftpd_is_never_masked_or_purged() {
    let data = readme();
    assert!(readme_services::is_critical(Some(&data), "vsftpd.service"));
    assert!(
        !masked_units().contains(&"vsftpd.service"),
        "a critical service must not be masked"
    );
    assert!(!prohibited_names(&data).contains(&"vsftpd".to_string()));
    let mut task = service_management::ServiceManagementTask::new();
    task.set_readme_data(data);
    assert!(
        task.required_units()
            .contains(&"vsftpd.service".to_string())
    );
}

/// **Penalty 1, other spellings.** The key's own word is "VSFTP"; a README that
/// says "VSFTP" or "FTP" must protect the service as well.
#[test]
fn penalty_01_every_readme_spelling_of_vsftpd_protects_it() {
    for spelling in ["vsftpd", "FTP", "VSFTP", "VSFTPD"] {
        let data = ReadmeData {
            critical_services: vec![spelling.to_string()],
            ..Default::default()
        };
        assert!(
            readme_services::is_critical(Some(&data), "vsftpd.service"),
            "a README calling {spelling} critical must protect vsftpd.service"
        );
    }
}

/// **Penalty 2) Important files removed from public FTP directories: -5 pts.**
///
/// `/srv` is a search root, so media or a tool-named file under the FTP root
/// would be deleted - unless vsftpd is critical, in which case everything under
/// `/srv/ftp` and the configured `anon_root` is report-only. (The key's
/// forensics question 3 is about `override.txt` in the FTP tree.)
#[test]
fn penalty_02_files_under_the_ftp_roots_are_never_deleted() {
    let roots = protected_roots();
    assert!(roots.contains(&"/srv/ftp".to_string()), "{roots:?}");
    assert!(roots.contains(&"/srv/ftp/public".to_string()), "{roots:?}");

    for (path, kind) in [
        ("/srv/ftp/Sales/override.txt", prohibited_media::Kind::Media),
        ("/srv/ftp/public/song.mp3", prohibited_media::Kind::Media),
        (
            "/srv/ftp/public/pyrdp-master.zip",
            prohibited_media::Kind::HackingTool,
        ),
    ] {
        let found = Found {
            path: PathBuf::from(path),
            kind,
        };
        assert!(
            matches!(
                prohibited_media::disposition(&found, &roots, true),
                Disposition::ReportOnly(_)
            ),
            "{path} must be reported, not deleted"
        );
    }

    // The same file with no README protecting FTP is a normal delete, so the
    // protection is what stops it.
    let found = Found {
        path: PathBuf::from("/srv/ftp/public/song.mp3"),
        kind: prohibited_media::Kind::Media,
    };
    let none = prohibited_media::protected_roots(None, Some(vsftpd_conf()), None);
    assert_eq!(
        prohibited_media::disposition(&found, &none, true),
        Disposition::Delete
    );
}

// =============================================================================
// Not automatable
// =============================================================================

/// **1), 2), 3) Forensics Questions 1-3: 6 pts each.**
///
/// Question 1 finds the Python backdoor (and a base64 file); question 2 reads
/// TCP streams in a capture; question 3 decodes `override.txt` and runs steghide
/// on `stanlee.jpg`. All need a person. Question 1 sends you to the backdoor the
/// tool then removes (item 26), so the key says to answer it first - the
/// backdoor task prints that reminder.
#[test]
fn items_01_to_03_forensics_questions_are_for_a_human() {
    // Recorded rather than skipped silently: 18 points are outside automation.
}

// =============================================================================
// Coverage
// =============================================================================

/// (number, title, points if the extracted text gives them, automated)
const SCORING: &[(u32, &str, Option<i32>, bool)] = &[
    (1, "Forensics Question 1", Some(6), false),
    (2, "Forensics Question 2", Some(6), false),
    (3, "Forensics Question 3", Some(6), false),
    (4, "Removed unauthorized user penguru", None, true),
    (5, "Removed unauthorized user liv (hidden)", None, true),
    (6, "ham is not an administrator", Some(3), true),
    (7, "noir has a maximum password age", Some(4), true),
    (8, "Created the group spider", Some(3), true),
    (9, "Added users to group spider", Some(4), true),
    (10, "Root password is no longer blank", Some(4), true),
    (11, "Minimum password length", Some(3), true),
    (12, "Previous passwords remembered", Some(3), true),
    (13, "Account lockout policy", Some(4), true),
    (14, "Null passwords do not authenticate", Some(4), true),
    (15, "ASLR enabled", Some(4), true),
    (16, "TCP SYN cookies", Some(4), true),
    (17, "UFW enabled", Some(3), true),
    (18, "Nginx disabled or removed", Some(4), true),
    (19, "Squid disabled or removed", Some(4), true),
    (
        20,
        "Update manager installs updates automatically",
        Some(3),
        true,
    ),
    (21, "Vsftpd updated", Some(3), true),
    (22, "Prohibited OGG files removed", Some(4), true),
    (23, "Removed prohibited archive pyrdp", Some(4), true),
    (24, "Prohibited software doona removed", Some(3), true),
    (25, "Prohibited software xprobe removed", Some(3), true),
    (26, "Removed zod backdoor", Some(6), true),
];

const PENALTIES: &[(&str, i32)] = &[
    ("VSFTP service stopped or removed", -5),
    ("Important files removed from public FTP directories", -5),
];

/// Items the tool does not attempt, with the reason.
const NOT_AUTOMATED: &[(u32, &str)] = &[
    (1, "forensics: finds the python backdoor and a base64 file"),
    (
        2,
        "forensics: read TCP streams in a capture with tshark or Wireshark",
    ),
    (
        3,
        "forensics: decode override.txt, steghide extract from stanlee.jpg",
    ),
];

#[test]
fn the_scoring_table_matches_the_key() {
    let known: i32 = SCORING.iter().filter_map(|(_, _, p, _)| *p).sum();
    assert_eq!(
        known, 95,
        "every item whose points are in the extracted text; items 4 and 5 are not"
    );
    let manual: Vec<u32> = SCORING
        .iter()
        .filter(|(.., automated)| !automated)
        .map(|(n, ..)| *n)
        .collect();
    let listed: Vec<u32> = NOT_AUTOMATED.iter().map(|(n, _)| *n).collect();
    assert_eq!(manual, listed);
    assert_eq!(PENALTIES.iter().map(|(_, p)| p).sum::<i32>(), -10);
}

/// Every automatable item has an `item_NN_*` test, and every penalty a
/// `penalty_NN_*` test.
#[test]
fn every_automatable_item_has_a_test() {
    let source = include_str!("answer_key_mint21_training2.rs");
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
