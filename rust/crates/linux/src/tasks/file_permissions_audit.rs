// =============================================================================
// PinnacleCyPat - File permissions audit (Linux)
// Author: Maxwell McCormick
// Copyright 2026 Maxwell McCormick
// SPDX-License-Identifier: Apache-2.0
// =============================================================================

//! The permission findings a Linux image is scored on, and Windows has no real
//! equivalent of.
//!
//! Windows hides its access control behind ACLs that nothing prints by default.
//! Linux puts it in twelve bits per file, which makes it both easy to get wrong
//! and easy to check - and a competition image ships with several of them wrong
//! on purpose.
//!
//! The one that matters most is `/etc/shadow`. At `0644` every user on the
//! machine can read the password hashes and take them away to crack offline,
//! and *nothing about the system behaves differently* - no error, no warning,
//! no failed login. It is invisible until somebody looks.
//!
//! **Modes on known files are fixed; everything else is reported.** A world-
//! writable file somewhere under `/opt` may be a vendor's install doing
//! something ugly but necessary, and a setuid binary may be the one the round
//! requires. Changing those unasked breaks working software to score nothing.
//! The known files in
//! [`CRITICAL_FILE_MODES`](crate::knowledge::CRITICAL_FILE_MODES) are different:
//! there is one right answer and it is documented.

use pinnacle_core::models::{SystemInfo, TaskResult};
use pinnacle_core::task::Task;
use pinnacle_core::{command, impl_task_meta, remediation, ui};

use crate::knowledge::{CRITICAL_FILE_MODES, DANGEROUS_DOTFILES};
use crate::user_ops;
use async_trait::async_trait;
use std::path::Path;

/// setuid and setgid programs a distribution legitimately ships, **by file
/// name**.
///
/// Matched on the name and not the full path, because the directory is a
/// distribution detail: `unix_chkpwd` is in `/usr/sbin` on Debian and `/usr/bin`
/// on Arch, `ssh-keysign` is under `/usr/lib/openssh` on one and `/usr/lib/ssh`
/// on the other. A full-path list reported twenty-one legitimate binaries on
/// the first machine it met - the same mistake as matching `nologin` by path,
/// found the same way, by running it.
///
/// The name alone is not enough, though: a planted `/home/alice/sudo` would
/// then be excused by being called `sudo`. So [`is_expected_setuid`] also
/// requires the path to be under a system directory. A setuid binary in a home
/// directory or `/tmp` is a finding whatever it is named.
const EXPECTED_SETUID_NAMES: &[&str] = &[
    // shadow-suite and login
    "chfn",
    "chsh",
    "passwd",
    "newgrp",
    "gpasswd",
    "expiry",
    "chage",
    "su",
    "sudo",
    "sudoedit",
    "unix_chkpwd",
    "pam_extrausers_chkpwd",
    "utempter",
    "sg",
    // mounting
    "mount",
    "umount",
    "fusermount",
    "fusermount3",
    "mount.cifs",
    "mount.nfs",
    "ntfs-3g",
    "dmcrypt-get-device",
    // scheduling
    "at",
    "crontab",
    // messaging between terminals
    "wall",
    "write",
    "bsd-write",
    // ssh, dbus, polkit, X
    "ssh-agent",
    "ssh-keysign",
    "pkexec",
    "polkit-agent-helper-1",
    "dbus-daemon-launch-helper",
    "Xorg.wrap",
    "Xorg",
    "ksu",
    // locate databases, which are setgid so they can read the index
    "mlocate",
    "locate",
    "plocate",
    "plocate-build",
    // networking helpers
    "pppd",
    "ping",
    "ping6",
    "arping",
    // packaging and containers
    "snap-confine",
    "newuidmap",
    "newgidmap",
    // browser and Electron sandboxes, which need setuid to build their jail
    "chrome-sandbox",
];

/// Directories a legitimately packaged setuid program lives in.
///
/// Everything here is written by the package manager and not by a user. A
/// setuid binary anywhere else - a home directory, `/tmp`, `/var/tmp`, a
/// mounted share - is a finding whatever it is called.
const SYSTEM_PREFIXES: &[&str] = &["/usr/", "/bin/", "/sbin/", "/opt/", "/snap/"];

/// Where to look for files that should not be world-writable.
///
/// `/tmp` and `/var/tmp` are excluded: they are world-writable *by design*, and
/// what matters there is the sticky bit, which is checked separately. `/proc`
/// and `/sys` are kernel interfaces, not files.
const SEARCH_ROOTS: &[&str] = &["/etc", "/usr", "/opt", "/srv", "/var", "/home", "/root"];

pub struct FilePermissionsAuditTask {
    name: String,
    description: String,
    dry_run: bool,
}

impl FilePermissionsAuditTask {
    pub fn new() -> Self {
        Self {
            name: "File Permissions Audit".to_string(),
            description: "Fix the modes on scored files; report the rest".to_string(),
            dry_run: false,
        }
    }
}

impl Default for FilePermissionsAuditTask {
    fn default() -> Self {
        Self::new()
    }
}

/// Format a mode as the four-digit octal `stat` prints.
pub fn octal(mode: u32) -> String {
    format!("{:04o}", mode & 0o7777)
}

/// Is this setuid binary one a distribution legitimately ships?
///
/// Both halves are required - see [`EXPECTED_SETUID_NAMES`]. The name says it
/// is a program a package manager installs; the location says a package manager
/// is what installed it.
pub fn is_expected_setuid(path: &str) -> bool {
    if !SYSTEM_PREFIXES.iter().any(|p| path.starts_with(p)) {
        return false;
    }
    let name = path.rsplit('/').next().unwrap_or(path);
    EXPECTED_SETUID_NAMES.contains(&name)
}

/// A file's mode and owner, as `"0640 root:shadow"`.
async fn describe(path: &str) -> Option<String> {
    // `stat` rather than a metadata call plus two lookups: it resolves the uid
    // and gid to names in one go, and its `-c` format is not localised.
    let (ok, out, _e) = command::execute("stat", Some(&format!("-c %a:%U:%G {path}"))).await;
    if !ok {
        return None;
    }
    let mut parts = out.trim().split(':');
    let mode: u32 = u32::from_str_radix(parts.next()?, 8).ok()?;
    let user = parts.next()?;
    let group = parts.next()?;
    Some(format!("{} {user}:{group}", octal(mode)))
}

/// Is the observed state at least as strict as the wanted one?
///
/// Stricter is accepted deliberately. An image whose `/etc/shadow` is `0600`
/// rather than `0640` is *more* locked down than the benchmark asks, and
/// loosening it to match would be a downgrade dressed up as a fix.
pub fn is_at_least_as_strict(observed: &str, wanted_mode: u32, wanted_owner: &str) -> bool {
    let Some((mode_text, owner)) = observed.split_once(' ') else {
        return false;
    };
    let Ok(mode) = u32::from_str_radix(mode_text, 8) else {
        return false;
    };
    // Every bit set must also be set in the wanted mode: no extra permission.
    mode & !wanted_mode == 0 && owner == wanted_owner
}

/// What a single filesystem scan found, tagged by which check matched.
#[derive(Debug, Default)]
pub struct Scan {
    pub world_writable: Vec<String>,
    pub unowned: Vec<String>,
    pub setuid: Vec<String>,
}

/// A generous ceiling for the scan.
///
/// One traversal of a competition image takes seconds. A minute means something
/// pathological - a symlink loop, or a network mount that `-xdev` did not stop -
/// and the run must not be held up by it.
const SCAN_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(60);

/// Walk the filesystem once, checking everything at the same time.
///
/// Three separate `find` invocations meant three full traversals of `/usr`,
/// which on a real image took long enough to look like a hang - and the run
/// still had four more tasks to go. One pass with tagged output costs what a
/// single check used to.
///
/// `-xdev` keeps the scan on one filesystem, so a mounted share or a container
/// overlay does not turn a permissions audit into a network operation.
pub async fn scan_filesystem() -> Scan {
    let roots: Vec<&str> = SEARCH_ROOTS
        .iter()
        .copied()
        .filter(|r| Path::new(r).is_dir())
        .collect();
    if roots.is_empty() {
        return Scan::default();
    }

    // No shell is involved, so the parentheses are passed to `find` as
    // arguments and must not be backslash-escaped the way they would be at a
    // prompt. Escaping them makes every one of these expressions fail.
    let expression = concat!(
        r#"( -type f -perm -0002 -printf "WW %p
" ) -o "#,
        r#"( -nouser -printf "UNOWNED %p
" ) -o "#,
        r#"( -nogroup -printf "UNOWNED %p
" ) -o "#,
        r#"( -type f ( -perm -4000 -o -perm -2000 ) -printf "SUID %p
" )"#
    );

    let (_ok, out, _e) = command::execute_with_timeout(
        "find",
        Some(&format!("{} -xdev {expression}", roots.join(" "))),
        SCAN_TIMEOUT,
    )
    .await;
    parse_scan(&out)
}

/// Sort the tagged output into its three lists.
///
/// Separated from the command so the parsing can be tested without waiting for
/// a filesystem walk - which is also what stopped the unit tests taking two
/// minutes each.
pub fn parse_scan(output: &str) -> Scan {
    let mut scan = Scan::default();
    for line in output.lines() {
        let Some((tag, path)) = line.split_once(' ') else {
            continue;
        };
        let path = path.trim();
        if path.is_empty() {
            continue;
        }
        match tag {
            "WW" => scan.world_writable.push(path.to_string()),
            "UNOWNED" => scan.unowned.push(path.to_string()),
            "SUID" if !is_expected_setuid(path) => scan.setuid.push(path.to_string()),
            _ => {}
        }
    }
    // A file with no user *and* no group matches twice in one pass.
    scan.unowned.sort();
    scan.unowned.dedup();
    scan
}

/// Home directories containing a file that grants access without a password.
async fn dangerous_dotfiles() -> Vec<(String, &'static str)> {
    let mut found = Vec::new();
    for account in user_ops::human_accounts().await {
        for (name, why) in DANGEROUS_DOTFILES {
            let path = format!("{}/{name}", account.home);
            if tokio::fs::metadata(&path).await.is_ok() {
                found.push((path, *why));
            }
        }
    }
    found
}

#[async_trait]
impl Task for FilePermissionsAuditTask {
    impl_task_meta!();

    async fn read_system_state(&mut self) -> SystemInfo {
        let mut lines = Vec::new();
        for (path, _mode, _owner, _why) in CRITICAL_FILE_MODES {
            if let Some(state) = describe(path).await {
                lines.push(format!("{path}: {state}"));
            }
        }
        SystemInfo {
            raw_output: Some(lines.join("\n")),
            ..Default::default()
        }
    }

    async fn execute(&mut self) -> TaskResult {
        let mut result = TaskResult {
            task_name: self.name.clone(),
            success: true,
            ..Default::default()
        };

        // --- the part that is fixed -----------------------------------------
        let mut present: Vec<&(&str, u32, &str, &str)> = Vec::new();
        for entry in CRITICAL_FILE_MODES {
            if tokio::fs::metadata(entry.0).await.is_ok() {
                present.push(entry);
            }
        }
        result.items_attempted = present.len() as i32;

        if self.dry_run {
            for (path, mode, owner, _why) in &present {
                ui::markup_line(&format!(
                    "[cyan]Would set {} to {} {}[/]",
                    ui::escape(path),
                    octal(*mode),
                    ui::escape(owner)
                ));
            }
            result.message = format!(
                "DRY RUN: would correct up to {} file modes; findings below are read-only.",
                present.len()
            );
        } else {
            let mut failures: Vec<String> = Vec::new();
            for (path, mode, owner, why) in &present {
                match set_mode(path, *mode, owner, why).await {
                    Ok(()) => result.items_succeeded += 1,
                    Err(e) => failures.push(format!("{path}: {e}")),
                }
            }
            if !failures.is_empty() {
                result.success = false;
                result.error_details = Some(failures.join("; "));
            }
            result.message = format!("Corrected {} file modes.", result.items_succeeded);
        }

        // --- the part that is only reported ---------------------------------
        //
        // Everything below changes nothing. A world-writable file under /opt
        // may be a vendor's installer doing something ugly but necessary, and a
        // setuid binary may be the one the round requires - breaking working
        // software to score nothing is the worse trade.
        let scan = scan_filesystem().await;
        finding(
            "world-writable files",
            "no file is writable by every user on the machine",
            &scan.world_writable,
            "any user can replace the contents; if it is a script something runs, that is root",
        );
        finding(
            "unowned files",
            "every file belongs to an account that exists",
            &scan.unowned,
            "a deleted user's uid is reused by the next account created, which then inherits these",
        );
        finding(
            "unexpected setuid binaries",
            "only the distribution's own setuid programs are present",
            &scan.setuid,
            "a setuid binary runs as its owner whoever starts it, which is how a foothold becomes permanent",
        );
        report_dangerous_dotfiles().await;
        report_sticky_bit().await;

        result
    }

    async fn verify(&mut self) -> bool {
        for (path, mode, owner, _why) in CRITICAL_FILE_MODES {
            if tokio::fs::metadata(path).await.is_err() {
                continue;
            }
            let Some(state) = describe(path).await else {
                return false;
            };
            if !is_at_least_as_strict(&state, *mode, owner) {
                return false;
            }
        }
        true
    }
}

/// Correct one file's mode and owner, and prove it.
async fn set_mode(path: &str, mode: u32, owner: &str, why: &str) -> Result<(), String> {
    remediation::apply(
        path,
        &format!("{} {owner} ({why})", octal(mode)),
        || async { describe(path).await },
        |state| is_at_least_as_strict(state, mode, owner),
        &format!("chmod {} and chown {owner}", octal(mode)),
        || async {
            let (chown_ok, _o, chown_err) =
                command::execute("chown", Some(&format!("{owner} {path}"))).await;
            let (chmod_ok, _o, chmod_err) =
                command::execute("chmod", Some(&format!("{} {path}", octal(mode)))).await;
            match (chown_ok, chmod_ok) {
                (true, true) => Ok(()),
                (false, _) => Err(chown_err.unwrap_or_else(|| "chown failed".into())),
                (_, false) => Err(chmod_err.unwrap_or_else(|| "chmod failed".into())),
            }
        },
    )
    .await
}

async fn report_dangerous_dotfiles() {
    let found = dangerous_dotfiles().await;
    let paths: Vec<String> = found
        .iter()
        .map(|(path, why)| format!("{path} ({why})"))
        .collect();
    finding(
        "host-trust and credential files",
        "no home directory grants access without a password",
        &paths,
        "these are read before any password is asked for",
    );
}

async fn report_sticky_bit() {
    // A world-writable directory without the sticky bit lets any user delete
    // any other user's files in it, which is how /tmp attacks start.
    let (_ok, out, _e) = command::execute(
        "find",
        Some("/tmp /var/tmp /dev/shm -xdev -maxdepth 0 -type d -perm -0002 ! -perm -1000"),
    )
    .await;
    let found: Vec<String> = out
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty())
        .map(str::to_string)
        .collect();
    finding(
        "the sticky bit on shared directories",
        "a world-writable directory does not let one user delete another's files",
        &found,
        "without it, any user can remove any file in /tmp",
    );
}

/// Print and record one read-only finding.
fn finding(subject: &str, intent: &str, found: &[String], why_it_matters: &str) {
    if found.is_empty() {
        remediation::record_finding(subject, intent, true, "nothing found");
        return;
    }

    ui::markup_line(&format!(
        "[yellow]⚠ {} {}[/] [dim]- {}[/]",
        found.len(),
        ui::escape(subject),
        ui::escape(why_it_matters)
    ));
    // Cap the listing. A misconfigured image can have thousands of
    // world-writable files, and a wall of paths is not a report.
    for path in found.iter().take(20) {
        ui::markup_line(&format!("    [dim]{}[/]", ui::escape(path)));
    }
    if found.len() > 20 {
        ui::markup_line(&format!(
            "    [dim]...and {} more; the run log has them all[/]",
            found.len() - 20
        ));
    }

    remediation::record_finding(
        subject,
        intent,
        false,
        &format!("{} found: {}", found.len(), found.join(", ")),
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn modes_are_formatted_as_four_octal_digits() {
        assert_eq!(octal(0o640), "0640");
        assert_eq!(octal(0o600), "0600");
        assert_eq!(octal(0o4755), "4755");
        // stat reports the file type in the high bits; only the low twelve are
        // permissions.
        assert_eq!(octal(0o100644), "0644");
    }

    /// The whole point of the comparison. An image already stricter than the
    /// benchmark must not be loosened to match it.
    #[test]
    fn a_stricter_mode_is_accepted() {
        assert!(is_at_least_as_strict(
            "0640 root:shadow",
            0o640,
            "root:shadow"
        ));
        assert!(
            is_at_least_as_strict("0600 root:shadow", 0o640, "root:shadow"),
            "0600 is stricter than 0640 and must be left alone"
        );
        assert!(is_at_least_as_strict(
            "0000 root:shadow",
            0o640,
            "root:shadow"
        ));
    }

    /// The finding that matters most: at 0644 every user can read the password
    /// hashes, and nothing about the system behaves differently.
    #[test]
    fn a_world_readable_shadow_file_is_not_compliant() {
        assert!(!is_at_least_as_strict(
            "0644 root:shadow",
            0o640,
            "root:shadow"
        ));
        assert!(!is_at_least_as_strict(
            "0666 root:shadow",
            0o640,
            "root:shadow"
        ));
    }

    /// The right mode on the wrong owner is still wrong - a file owned by a
    /// user is a file that user can chmod back.
    #[test]
    fn the_owner_has_to_match_too() {
        assert!(!is_at_least_as_strict(
            "0640 alice:shadow",
            0o640,
            "root:shadow"
        ));
        assert!(!is_at_least_as_strict(
            "0640 root:root",
            0o640,
            "root:shadow"
        ));
    }

    #[test]
    fn unreadable_state_is_never_compliant() {
        assert!(!is_at_least_as_strict("", 0o644, "root:root"));
        assert!(!is_at_least_as_strict(
            "notoctal root:root",
            0o644,
            "root:root"
        ));
    }

    /// The distribution's own setuid binaries are not findings. Flagging
    /// `/usr/bin/sudo` every run would train the reader to skim the list that
    /// also contains the planted one.
    #[test]
    fn the_distributions_own_setuid_binaries_are_expected() {
        for path in [
            "/usr/bin/sudo",
            "/usr/bin/passwd",
            "/usr/bin/su",
            "/usr/bin/mount",
        ] {
            assert!(is_expected_setuid(path), "{path} should be expected");
        }
    }

    /// The same programs live in different directories on different
    /// distributions. Matching full paths reported twenty-one legitimate
    /// binaries the first time this ran on a machine that was not Ubuntu.
    #[test]
    fn the_same_program_is_recognised_wherever_the_distribution_puts_it() {
        for path in [
            "/usr/sbin/unix_chkpwd",        // Debian, Ubuntu
            "/usr/bin/unix_chkpwd",         // Arch
            "/usr/lib/openssh/ssh-keysign", // Debian, Ubuntu
            "/usr/lib/ssh/ssh-keysign",     // Arch
            "/usr/lib/dbus-1.0/dbus-daemon-launch-helper",
            "/usr/lib/dbus-daemon-launch-helper",
            "/usr/lib/xorg/Xorg.wrap",
            "/usr/lib/Xorg.wrap",
        ] {
            assert!(is_expected_setuid(path), "{path} should be expected");
        }
    }

    /// The name alone must not be enough. A planted binary called `sudo` in a
    /// home directory is exactly what this task exists to find.
    #[test]
    fn a_familiar_name_outside_a_system_directory_is_still_a_finding() {
        for path in [
            "/home/alice/sudo",
            "/tmp/passwd",
            "/var/tmp/mount",
            "/home/mallory/.cache/su",
        ] {
            assert!(
                !is_expected_setuid(path),
                "{path} is setuid outside a system directory and must be reported"
            );
        }
    }

    #[test]
    fn an_unfamiliar_name_in_a_system_directory_is_a_finding() {
        for path in [
            "/usr/local/bin/rootshell",
            "/opt/evil/backdoor",
            "/usr/bin/nc",
        ] {
            assert!(!is_expected_setuid(path), "{path} should be a finding");
        }
    }

    /// /tmp is world-writable by design; scanning it for world-writable files
    /// would report every file in it.
    #[test]
    fn the_scan_skips_directories_that_are_world_writable_by_design() {
        assert!(!SEARCH_ROOTS.contains(&"/tmp"));
        assert!(!SEARCH_ROOTS.contains(&"/var/tmp"));
        assert!(!SEARCH_ROOTS.contains(&"/proc"));
        assert!(SEARCH_ROOTS.contains(&"/etc"));
        assert!(SEARCH_ROOTS.contains(&"/home"));
    }

    /// Real tagged output from the single-pass scan.
    #[test]
    fn the_scan_output_is_sorted_into_its_three_lists() {
        let output = "\
WW /etc/shadow
UNOWNED /home/deleted/file
SUID /usr/bin/sudo
SUID /usr/local/bin/rootshell
UNOWNED /home/deleted/file
";
        let scan = parse_scan(output);
        assert_eq!(scan.world_writable, ["/etc/shadow"]);
        // Matched once for -nouser and once for -nogroup; reported once.
        assert_eq!(scan.unowned, ["/home/deleted/file"]);
        // sudo is expected and filtered out; the planted one is not.
        assert_eq!(scan.setuid, ["/usr/local/bin/rootshell"]);
    }

    #[test]
    fn malformed_scan_output_is_skipped_rather_than_guessed_at() {
        let scan = parse_scan("no-tag-here\nWW \n\n");
        assert!(scan.world_writable.is_empty());
        assert!(scan.unowned.is_empty());
        assert!(scan.setuid.is_empty());
    }
}
