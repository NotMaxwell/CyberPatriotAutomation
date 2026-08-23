// =============================================================================
// PinnacleCyPat - The Linux tables
// Author: Maxwell McCormick
// Copyright 2026 Maxwell McCormick
// SPDX-License-Identifier: Apache-2.0
// =============================================================================

//! Every Linux setting, service name and package this tool knows about, in one
//! place - the counterpart of `pinnacle_windows::knowledge`.
//!
//! A table is the one kind of code where a typo compiles perfectly, so the
//! tests at the bottom check the tables themselves: duplicate keys,
//! contradictory mappings, settings pointed at a file whose style does not
//! match. Those tests have already caught real mistakes in the Windows tables.
//!
//! Sources for the hardening values are the CIS Ubuntu Linux Benchmark and the
//! settings CyberPatriot has historically scored. Where the two differ, the
//! comment says which was followed and why.

use crate::file_ops::Style;

/// One hardening setting: where it lives, what it should be, and why.
pub struct Setting {
    /// The file to write it to.
    pub path: &'static str,
    pub style: Style,
    pub key: &'static str,
    pub value: &'static str,
    /// What the setting is for, in words. Lands in the run log next to the
    /// path, so a reader does not have to know what `fs.protected_hardlinks`
    /// means.
    pub why: &'static str,
}

/// The SSH daemon configuration.
///
/// Written to a drop-in rather than to `sshd_config` itself. Ubuntu 22.04 and
/// later ship `Include /etc/ssh/sshd_config.d/*.conf` as the *first* line of
/// `sshd_config`, and sshd obeys the first definition of a keyword it sees - so
/// a drop-in overrides the main file, while editing the main file would be
/// overridden by any drop-in already present. Editing the main file is the
/// mistake that makes a hardening run look applied and change nothing.
pub const SSHD_DROPIN: &str = "/etc/ssh/sshd_config.d/99-pinnacle.conf";

/// Kernel parameters, written to a `sysctl.d` drop-in.
///
/// `sysctl.d` files are read in lexical order and later values win, so `99-`
/// puts this last and makes it the effective setting whatever else is present.
pub const SYSCTL_DROPIN: &str = "/etc/sysctl.d/99-pinnacle.conf";

/// `login.defs` - shadow-suite defaults for new and existing accounts.
pub const LOGIN_DEFS: &str = "/etc/login.defs";

/// Settings applied by the Security Hardening task.
pub const HARDENING_SETTINGS: &[Setting] = &[
    // --- SSH -----------------------------------------------------------------
    Setting {
        path: SSHD_DROPIN,
        style: Style::Space,
        key: "PermitRootLogin",
        value: "no",
        why: "root must log in as a user and escalate, so the audit log names a person",
    },
    Setting {
        path: SSHD_DROPIN,
        style: Style::Space,
        key: "PermitEmptyPasswords",
        value: "no",
        why: "an empty password is not a credential",
    },
    Setting {
        path: SSHD_DROPIN,
        style: Style::Space,
        key: "X11Forwarding",
        value: "no",
        why: "forwarded X11 lets the server read the client's keystrokes",
    },
    Setting {
        path: SSHD_DROPIN,
        style: Style::Space,
        key: "MaxAuthTries",
        value: "4",
        why: "limits password guessing per connection",
    },
    Setting {
        path: SSHD_DROPIN,
        style: Style::Space,
        key: "IgnoreRhosts",
        value: "yes",
        why: "host-based trust files bypass authentication entirely",
    },
    Setting {
        path: SSHD_DROPIN,
        style: Style::Space,
        key: "HostbasedAuthentication",
        value: "no",
        why: "trusts the client's claim about who it is",
    },
    Setting {
        path: SSHD_DROPIN,
        style: Style::Space,
        key: "PermitUserEnvironment",
        value: "no",
        why: "a user-writable environment file can inject LD_PRELOAD at login",
    },
    Setting {
        path: SSHD_DROPIN,
        style: Style::Space,
        key: "LoginGraceTime",
        value: "60",
        why: "unauthenticated connections should not hold a slot for two minutes",
    },
    Setting {
        path: SSHD_DROPIN,
        style: Style::Space,
        key: "ClientAliveInterval",
        value: "300",
        why: "idle sessions are closed rather than left open at an unlocked desk",
    },
    Setting {
        path: SSHD_DROPIN,
        style: Style::Space,
        key: "ClientAliveCountMax",
        value: "0",
        why: "with the interval above, closes the session at five minutes idle",
    },
    Setting {
        path: SSHD_DROPIN,
        style: Style::Space,
        key: "Protocol",
        value: "2",
        why: "SSHv1 is broken; harmless on builds that no longer read this",
    },
    // --- Kernel networking ---------------------------------------------------
    Setting {
        path: SYSCTL_DROPIN,
        style: Style::Equals,
        key: "net.ipv4.ip_forward",
        value: "0",
        why: "a workstation is not a router",
    },
    Setting {
        path: SYSCTL_DROPIN,
        style: Style::Equals,
        key: "net.ipv4.conf.all.accept_redirects",
        value: "0",
        why: "an ICMP redirect can silently reroute traffic through an attacker",
    },
    Setting {
        path: SYSCTL_DROPIN,
        style: Style::Equals,
        key: "net.ipv4.conf.default.accept_redirects",
        value: "0",
        why: "as above, for interfaces added later",
    },
    Setting {
        path: SYSCTL_DROPIN,
        style: Style::Equals,
        key: "net.ipv4.conf.all.secure_redirects",
        value: "0",
        why: "accepting redirects only from the gateway is still accepting them",
    },
    Setting {
        path: SYSCTL_DROPIN,
        style: Style::Equals,
        key: "net.ipv4.conf.all.send_redirects",
        value: "0",
        why: "only a router should be issuing redirects",
    },
    Setting {
        path: SYSCTL_DROPIN,
        style: Style::Equals,
        key: "net.ipv4.conf.default.send_redirects",
        value: "0",
        why: "as above, for interfaces added later",
    },
    Setting {
        path: SYSCTL_DROPIN,
        style: Style::Equals,
        key: "net.ipv4.conf.all.accept_source_route",
        value: "0",
        why: "source routing lets the sender choose the return path and spoof its address",
    },
    Setting {
        path: SYSCTL_DROPIN,
        style: Style::Equals,
        key: "net.ipv4.conf.default.accept_source_route",
        value: "0",
        why: "as above, for interfaces added later",
    },
    Setting {
        path: SYSCTL_DROPIN,
        style: Style::Equals,
        key: "net.ipv4.conf.all.rp_filter",
        value: "1",
        why: "drops packets whose source address could not have arrived on that interface",
    },
    Setting {
        path: SYSCTL_DROPIN,
        style: Style::Equals,
        key: "net.ipv4.conf.all.log_martians",
        value: "1",
        why: "records the spoofed packets rp_filter drops",
    },
    Setting {
        path: SYSCTL_DROPIN,
        style: Style::Equals,
        key: "net.ipv4.icmp_echo_ignore_broadcasts",
        value: "1",
        why: "stops the machine amplifying a smurf attack",
    },
    Setting {
        path: SYSCTL_DROPIN,
        style: Style::Equals,
        key: "net.ipv4.icmp_ignore_bogus_error_responses",
        value: "1",
        why: "keeps malformed ICMP errors out of the log",
    },
    Setting {
        path: SYSCTL_DROPIN,
        style: Style::Equals,
        key: "net.ipv4.tcp_syncookies",
        value: "1",
        why: "survives a SYN flood without dropping legitimate connections",
    },
    Setting {
        path: SYSCTL_DROPIN,
        style: Style::Equals,
        key: "net.ipv6.conf.all.accept_redirects",
        value: "0",
        why: "as for IPv4; an image with IPv6 up is redirectable over it",
    },
    Setting {
        path: SYSCTL_DROPIN,
        style: Style::Equals,
        key: "net.ipv6.conf.all.accept_source_route",
        value: "0",
        why: "as for IPv4",
    },
    // --- Kernel hardening ----------------------------------------------------
    Setting {
        path: SYSCTL_DROPIN,
        style: Style::Equals,
        key: "kernel.randomize_va_space",
        value: "2",
        why: "full address-space layout randomisation",
    },
    Setting {
        path: SYSCTL_DROPIN,
        style: Style::Equals,
        key: "kernel.dmesg_restrict",
        value: "1",
        why: "the kernel ring buffer leaks addresses useful for building an exploit",
    },
    Setting {
        path: SYSCTL_DROPIN,
        style: Style::Equals,
        key: "kernel.sysrq",
        value: "0",
        why: "the magic SysRq key can dump memory or kill init from the console",
    },
    Setting {
        path: SYSCTL_DROPIN,
        style: Style::Equals,
        key: "fs.protected_hardlinks",
        value: "1",
        why: "stops a hardlink to a file the user cannot read being used to read it",
    },
    Setting {
        path: SYSCTL_DROPIN,
        style: Style::Equals,
        key: "fs.protected_symlinks",
        value: "1",
        why: "closes the classic /tmp symlink race",
    },
    Setting {
        path: SYSCTL_DROPIN,
        style: Style::Equals,
        key: "fs.suid_dumpable",
        value: "0",
        why: "a core dump from a setuid program can contain credentials",
    },
    // --- Account ageing defaults --------------------------------------------
    Setting {
        path: LOGIN_DEFS,
        style: Style::Space,
        key: "PASS_MAX_DAYS",
        value: "90",
        why: "passwords expire; the stock value is 99999, which is never",
    },
    Setting {
        path: LOGIN_DEFS,
        style: Style::Space,
        key: "PASS_MIN_DAYS",
        value: "7",
        why: "stops a user cycling straight back to the old password",
    },
    Setting {
        path: LOGIN_DEFS,
        style: Style::Space,
        key: "PASS_WARN_AGE",
        value: "14",
        why: "warns before the account locks rather than after",
    },
    Setting {
        path: LOGIN_DEFS,
        style: Style::Space,
        key: "UMASK",
        value: "027",
        why: "new files are not world-readable by default",
    },
    Setting {
        path: LOGIN_DEFS,
        style: Style::Space,
        key: "ENCRYPT_METHOD",
        value: "SHA512",
        why: "the hash new passwords are stored with",
    },
];

/// Services that should not be running on a competition image.
///
/// Each is a unit name and the reason, which lands in the run log. Every one of
/// these either sends credentials in clear text, accepts unauthenticated
/// connections, or exists only to serve files off a machine that is not
/// supposed to be a server.
pub const PROHIBITED_SERVICES: &[(&str, &str)] = &[
    ("telnet.socket", "sends the password in clear text"),
    ("telnetd.service", "sends the password in clear text"),
    (
        "inetutils-telnetd.service",
        "sends the password in clear text",
    ),
    ("rsh.socket", "sends the password in clear text"),
    ("rlogin.socket", "sends the password in clear text"),
    ("rexec.socket", "sends the password in clear text"),
    ("vsftpd.service", "FTP sends the password in clear text"),
    ("proftpd.service", "FTP sends the password in clear text"),
    ("pure-ftpd.service", "FTP sends the password in clear text"),
    ("tftpd-hpa.service", "TFTP has no authentication at all"),
    ("nfs-server.service", "exports a filesystem to the network"),
    (
        "rpcbind.service",
        "reachable RPC surface with no authentication",
    ),
    (
        "ypserv.service",
        "NIS distributes the password database over the network",
    ),
    (
        "snmpd.service",
        "the default community string is a password everyone knows",
    ),
    (
        "avahi-daemon.service",
        "advertises the machine and its services on the LAN",
    ),
    (
        "cups.service",
        "a network print server on a machine that is not one",
    ),
    (
        "cups-browsed.service",
        "discovers and trusts printers advertised on the LAN",
    ),
    (
        "bind9.service",
        "an open resolver is an amplification vector",
    ),
    ("nginx.service", "a web server on a machine that is not one"),
    (
        "apache2.service",
        "a web server on a machine that is not one",
    ),
    (
        "smbd.service",
        "SMB file sharing on a machine that is not a file server",
    ),
    (
        "nmbd.service",
        "NetBIOS name service, the SMB discovery half",
    ),
    ("dovecot.service", "an IMAP/POP server"),
    ("postfix.service", "an MTA that will relay if misconfigured"),
    ("exim4.service", "an MTA that will relay if misconfigured"),
    ("squid.service", "an open proxy"),
    (
        "nis.service",
        "NIS distributes the password database over the network",
    ),
    (
        "xinetd.service",
        "starts whichever of the above are configured under it",
    ),
];

/// Services that must keep running whatever else is disabled.
///
/// Masking any of these ends the round: `ssh` is often how the image is
/// administered, and the rest carry the run itself.
pub const NEVER_DISABLE: &[&str] = &[
    // The CyberPatriot scoring engine. Disabling it is the single worst thing
    // this tool could do - the round stops being scored.
    "ccsclient",
    "cyberpatriot",
    // Core system units. Masking any of these makes the image unbootable.
    "systemd-journald",
    "systemd-logind",
    "systemd-udevd",
    "dbus",
    "polkit",
    "systemd-resolved",
    "systemd-networkd",
    "NetworkManager",
    "networking",
    "cron",
    "rsyslog",
    "auditd",
    "ufw",
    "apparmor",
    "sudo",
];

/// Display names a README might use, mapped to the systemd unit.
///
/// A README writes "SSH" or "Secure Shell", not "ssh.service", and is
/// inconsistent about which. Resolving through this table is what keeps two
/// tasks from disagreeing about whether the README protected something.
pub const SERVICE_NAME_MAP: &[(&str, &str)] = &[
    ("SSH", "ssh.service"),
    ("SSHD", "ssh.service"),
    ("Secure Shell", "ssh.service"),
    ("OpenSSH", "ssh.service"),
    ("OpenSSH Server", "ssh.service"),
    ("Remote Desktop", "xrdp.service"),
    ("RDP", "xrdp.service"),
    ("XRDP", "xrdp.service"),
    ("VNC", "vncserver.service"),
    ("Apache", "apache2.service"),
    ("Apache2", "apache2.service"),
    ("HTTP Server", "apache2.service"),
    ("Web Server", "apache2.service"),
    ("Nginx", "nginx.service"),
    ("MySQL", "mysql.service"),
    ("MariaDB", "mariadb.service"),
    ("PostgreSQL", "postgresql.service"),
    ("Samba", "smbd.service"),
    ("SMB", "smbd.service"),
    ("CUPS", "cups.service"),
    ("Printing", "cups.service"),
    ("FTP", "vsftpd.service"),
    ("vsftpd", "vsftpd.service"),
    ("Telnet", "telnet.socket"),
    ("NFS", "nfs-server.service"),
    ("DNS", "bind9.service"),
    ("BIND", "bind9.service"),
    ("Postfix", "postfix.service"),
    ("Mail Server", "postfix.service"),
    ("Cron", "cron.service"),
    ("Auditd", "auditd.service"),
    ("Firewall", "ufw.service"),
    ("UFW", "ufw.service"),
    ("CCS Client", "ccsclient.service"),
];

/// Software a README may name, mapped to the apt package that provides it.
///
/// The README writes what a person calls the program; `apt` wants the package.
/// Without this table "Firefox" resolves to nothing and a required install is
/// silently skipped.
pub const PACKAGE_IDS: &[(&str, &str)] = &[
    ("Firefox", "firefox"),
    ("Mozilla Firefox", "firefox"),
    ("Chromium", "chromium-browser"),
    ("Google Chrome", "google-chrome-stable"),
    ("Thunderbird", "thunderbird"),
    ("LibreOffice", "libreoffice"),
    ("VLC", "vlc"),
    ("VLC Media Player", "vlc"),
    ("GIMP", "gimp"),
    ("Audacity", "audacity"),
    ("Wireshark", "wireshark"),
    ("Nmap", "nmap"),
    ("ClamAV", "clamav"),
    ("OpenSSH Server", "openssh-server"),
    ("Apache", "apache2"),
    ("Apache2", "apache2"),
    ("Nginx", "nginx"),
    ("MySQL", "mysql-server"),
    ("MariaDB", "mariadb-server"),
    ("PostgreSQL", "postgresql"),
    ("Samba", "samba"),
    ("vsftpd", "vsftpd"),
    ("Python", "python3"),
    ("Python3", "python3"),
    ("Git", "git"),
    ("Vim", "vim"),
    ("Emacs", "emacs"),
    ("curl", "curl"),
    ("Wget", "wget"),
    ("Auditd", "auditd"),
    ("UFW", "ufw"),
    ("Fail2ban", "fail2ban"),
    ("AIDE", "aide"),
    ("rkhunter", "rkhunter"),
    ("chkrootkit", "chkrootkit"),
];

/// Packages that are never legitimate on a competition image.
///
/// Removed whether or not the README names them - which is the point: a README
/// lists what is *required*, and the planted tools are exactly the ones it will
/// not mention. Each is either a remote-access backdoor, a password cracker, or
/// a clear-text network service.
pub const ALWAYS_PROHIBITED: &[(&str, &str)] = &[
    ("john", "password cracker"),
    ("john-data", "password cracker data files"),
    ("hydra", "network login brute-forcer"),
    ("hydra-gtk", "network login brute-forcer"),
    ("medusa", "network login brute-forcer"),
    ("hashcat", "password cracker"),
    ("ophcrack", "password cracker"),
    ("aircrack-ng", "wireless key cracker"),
    ("ettercap-text-only", "man-in-the-middle tool"),
    ("ettercap-graphical", "man-in-the-middle tool"),
    ("nikto", "web vulnerability scanner"),
    (
        "netcat-traditional",
        "raw network listener, the classic backdoor",
    ),
    ("telnetd", "clear-text remote shell"),
    ("inetutils-telnetd", "clear-text remote shell"),
    ("rsh-server", "clear-text remote shell"),
    ("rsh-client", "clear-text remote shell client"),
    ("talk", "clear-text chat service"),
    ("talkd", "clear-text chat service"),
    ("finger", "leaks who is logged in and when"),
    ("tftpd-hpa", "file transfer with no authentication"),
    ("nis", "distributes the password database over the network"),
    (
        "ypserv",
        "distributes the password database over the network",
    ),
    (
        "zeitgeist",
        "activity logger frequently repurposed as a keylogger",
    ),
    ("logkeys", "keylogger"),
    ("crack", "password cracker"),
    (
        "wireshark",
        "packet capture; a monitoring tool, not a workstation tool",
    ),
    ("kismet", "wireless sniffer"),
    ("nmap", "network scanner"),
    ("zenmap", "network scanner"),
];

/// Accounts that must never be removed or locked, whatever the README says.
///
/// A README lists the *human* users. Acting on the difference without this
/// exclusion would delete every system account on the image - which is how a
/// tool bricks a machine in one step.
pub const SYSTEM_ACCOUNTS: &[&str] = &[
    "root",
    "daemon",
    "bin",
    "sys",
    "sync",
    "games",
    "man",
    "lp",
    "mail",
    "news",
    "uucp",
    "proxy",
    "www-data",
    "backup",
    "list",
    "irc",
    "gnats",
    "nobody",
    "systemd-network",
    "systemd-resolve",
    "systemd-timesync",
    "messagebus",
    "syslog",
    "_apt",
    "tss",
    "uuidd",
    "tcpdump",
    "avahi-autoipd",
    "usbmux",
    "dnsmasq",
    "kernoops",
    "avahi",
    "cups-pk-helper",
    "rtkit",
    "whoopsie",
    "sssd",
    "speech-dispatcher",
    "nm-openvpn",
    "saned",
    "colord",
    "geoclue",
    "pulse",
    "gnome-initial-setup",
    "hplip",
    "gdm",
    "sshd",
    "lightdm",
    "polkitd",
    "nvidia-persistenced",
];

/// The lowest uid the shadow suite gives to a human account.
///
/// Ubuntu and Debian start regular accounts at 1000; everything below is a
/// system account created by a package. `nobody` is the exception at 65534,
/// which is why it is also listed above by name.
pub const FIRST_HUMAN_UID: u32 = 1000;

/// The group that grants administrative rights.
///
/// Debian and Ubuntu use `sudo`; Red Hat and its derivatives use `wheel`. Both
/// are checked, because a README says "administrator" and means whichever the
/// image uses.
pub const ADMIN_GROUPS: &[&str] = &["sudo", "wheel", "admin"];

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;

    /// A duplicate key means one of the two is dead code, and which one wins
    /// depends on iteration order. The Windows table had exactly this bug.
    #[test]
    fn no_setting_is_defined_twice() {
        let mut seen = HashSet::new();
        for s in HARDENING_SETTINGS {
            assert!(
                seen.insert((s.path, s.key)),
                "{} is set twice in {}",
                s.key,
                s.path
            );
        }
    }

    /// A sysctl key written with `Style::Space` produces `net.ipv4.ip_forward 0`,
    /// which sysctl ignores silently - the setting reads as applied and does
    /// nothing.
    #[test]
    fn every_setting_uses_the_style_its_file_expects() {
        for s in HARDENING_SETTINGS {
            let expected = if s.path == SYSCTL_DROPIN {
                Style::Equals
            } else {
                Style::Space
            };
            assert_eq!(
                s.style, expected,
                "{} in {} has the wrong style",
                s.key, s.path
            );
        }
    }

    /// A sysctl setting whose key is not dotted is almost certainly a typo, and
    /// sysctl accepts unknown keys in a file without complaint.
    #[test]
    fn sysctl_keys_look_like_sysctl_keys() {
        for s in HARDENING_SETTINGS
            .iter()
            .filter(|s| s.path == SYSCTL_DROPIN)
        {
            assert!(
                s.key.contains('.') && !s.key.contains(' '),
                "{} does not look like a sysctl key",
                s.key
            );
        }
    }

    #[test]
    fn every_setting_says_why_it_exists() {
        for s in HARDENING_SETTINGS {
            assert!(!s.why.is_empty(), "{} has no reason recorded", s.key);
            assert!(!s.value.is_empty(), "{} has no value", s.key);
        }
    }

    /// The catastrophic case. `ccsclient` is the scoring engine; a prohibited
    /// entry that also appears on the protected list would come down to which
    /// check ran first.
    #[test]
    fn nothing_is_both_prohibited_and_protected() {
        for (unit, _) in PROHIBITED_SERVICES {
            let stem = unit.split('.').next().unwrap();
            assert!(
                !NEVER_DISABLE.iter().any(|p| p.eq_ignore_ascii_case(stem)),
                "{unit} is on both the prohibited and the never-disable list"
            );
        }
    }

    #[test]
    fn prohibited_services_are_named_as_units() {
        let mut seen = HashSet::new();
        for (unit, why) in PROHIBITED_SERVICES {
            assert!(
                unit.contains('.'),
                "{unit} is missing its unit type; systemctl would guess .service"
            );
            assert!(!why.is_empty(), "{unit} has no reason recorded");
            assert!(seen.insert(*unit), "{unit} is listed twice");
        }
    }

    /// The README says "SSH"; the task asks systemd about "ssh.service". A
    /// mapping to a bare name would silently never match.
    #[test]
    fn service_aliases_resolve_to_unit_names() {
        for (display, unit) in SERVICE_NAME_MAP {
            assert!(
                unit.contains('.'),
                "{display} maps to {unit}, which is not a unit name"
            );
        }
    }

    /// Two spellings of one service must agree about which unit they mean, or
    /// a README using one spelling protects a different unit from the one the
    /// task disables.
    #[test]
    fn no_display_name_maps_to_two_different_units() {
        let mut seen: Vec<(String, &str)> = Vec::new();
        for (display, unit) in SERVICE_NAME_MAP {
            let key = display.to_lowercase();
            if let Some((_, existing)) = seen.iter().find(|(d, _)| *d == key) {
                assert_eq!(existing, unit, "{display} maps to two different units");
            }
            seen.push((key, unit));
        }
    }

    /// A prohibited package that is also a required one would be installed and
    /// removed in the same run, and the outcome would depend on task order.
    #[test]
    fn no_package_is_both_required_and_always_prohibited() {
        for (name, _) in ALWAYS_PROHIBITED {
            // Wireshark and nmap are deliberately on both sides: a README that
            // explicitly requires them wins, which is the point of the table
            // being consulted rather than applied blindly. Anything else
            // appearing twice is a mistake.
            if matches!(*name, "wireshark" | "nmap") {
                continue;
            }
            assert!(
                !PACKAGE_IDS.iter().any(|(_, pkg)| pkg == name),
                "{name} is both a resolvable requirement and always prohibited"
            );
        }
    }

    #[test]
    fn always_prohibited_has_no_duplicates_and_says_why() {
        let mut seen = HashSet::new();
        for (name, why) in ALWAYS_PROHIBITED {
            assert!(seen.insert(*name), "{name} is listed twice");
            assert!(!why.is_empty(), "{name} has no reason recorded");
        }
    }

    /// Deleting `root` or `www-data` because the README did not mention them
    /// breaks the image in a way no competitor recovers from mid-round.
    #[test]
    fn root_is_protected_from_the_readme() {
        assert!(SYSTEM_ACCOUNTS.contains(&"root"));
        assert!(SYSTEM_ACCOUNTS.contains(&"nobody"));
        let mut seen = HashSet::new();
        for account in SYSTEM_ACCOUNTS {
            assert!(seen.insert(*account), "{account} is listed twice");
        }
    }

    #[test]
    fn the_admin_group_list_covers_both_families() {
        assert!(ADMIN_GROUPS.contains(&"sudo"), "Debian and Ubuntu use sudo");
        assert!(ADMIN_GROUPS.contains(&"wheel"), "Red Hat uses wheel");
    }
}
