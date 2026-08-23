// =============================================================================
// PinnacleCyPat - Proved account operations
// Author: Maxwell McCormick
// Copyright 2026 Maxwell McCormick
// SPDX-License-Identifier: Apache-2.0
// =============================================================================

//! What `account_ops` is on Windows, for the shadow suite.
//!
//! One thing is markedly better here than on Windows. `net user` prints a
//! localised table, so a parser written against English output returns nothing
//! on a non-English image - and "nothing" reads as *already compliant* rather
//! than as a failure. That is why the Windows port went to netapi32. On Linux
//! the account database *is* the file: `/etc/passwd` and `/etc/group` are
//! colon-separated records with a format fixed by POSIX and no locale anywhere
//! near them. Reading them directly is both simpler and more reliable than
//! anything that shells out.
//!
//! Writing still goes through `useradd`, `usermod`, `chage` and `gpasswd`, and
//! deliberately so: those tools take the lock on `/etc/passwd`, keep
//! `/etc/shadow` in step, and create or move the home directory. Editing the
//! files directly would race with anything else on the machine and silently
//! desynchronise the shadow file.

use pinnacle_core::command;
use pinnacle_core::remediation;

use crate::knowledge::{ADMIN_GROUPS, FIRST_HUMAN_UID, SYSTEM_ACCOUNTS};

/// One account, as `/etc/passwd` records it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Account {
    pub name: String,
    pub uid: u32,
    pub gid: u32,
    /// The GECOS field - a full name, when the image bothered to set one.
    pub comment: String,
    pub home: String,
    pub shell: String,
}

impl Account {
    /// Is this a human account rather than one a package created?
    ///
    /// Both halves are needed. The uid rule alone would classify `nobody`
    /// (65534) as a person; the name list alone would miss an account an
    /// attacker added with a plausible system-sounding name.
    pub fn is_human(&self) -> bool {
        self.uid >= FIRST_HUMAN_UID
            && self.uid != 65534
            && !SYSTEM_ACCOUNTS
                .iter()
                .any(|s| s.eq_ignore_ascii_case(&self.name))
    }

    /// Can this account log in at all?
    ///
    /// A shell of `nologin` or `false` is how a service account is kept out. An
    /// account with a real shell that should not have one is a finding.
    ///
    /// Matched on the *basename*, not the full path. The directory differs by
    /// distribution - Debian and Ubuntu ship `/usr/sbin/nologin`, Arch and
    /// Fedora `/usr/bin/nologin` - and a list of full paths reported every
    /// system account on the wrong distribution as able to log in. That was
    /// found by running the audit, not by reading it.
    pub fn can_log_in(&self) -> bool {
        !is_nologin_shell(&self.shell)
    }
}

/// Is this shell one that refuses the login?
///
/// Compared by file name so it holds on every distribution - see
/// [`Account::can_log_in`].
pub fn is_nologin_shell(shell: &str) -> bool {
    let name = shell.rsplit('/').next().unwrap_or(shell);
    shell.trim().is_empty()
        || matches!(
            name,
            "nologin" | "false" | "true" | "sync" | "halt" | "shutdown"
        )
}

/// Parse `/etc/passwd` content into accounts.
///
/// Separated from the read so it can be tested against real fixtures without a
/// Linux host - which is also what lets the Windows CI check this crate.
pub fn parse_passwd(text: &str) -> Vec<Account> {
    text.lines()
        .filter(|l| !l.trim().is_empty() && !l.starts_with('#'))
        .filter_map(|line| {
            let f: Vec<&str> = line.split(':').collect();
            // name:password:uid:gid:gecos:home:shell - a short record is
            // corrupt, and guessing at which fields are missing would be worse
            // than skipping it.
            if f.len() < 7 {
                return None;
            }
            Some(Account {
                name: f[0].to_string(),
                uid: f[2].parse().ok()?,
                gid: f[3].parse().ok()?,
                comment: f[4].to_string(),
                home: f[5].to_string(),
                shell: f[6].to_string(),
            })
        })
        .collect()
}

/// Every account on the machine.
pub async fn accounts() -> Vec<Account> {
    match tokio::fs::read_to_string("/etc/passwd").await {
        Ok(text) => parse_passwd(&text),
        Err(_) => Vec::new(),
    }
}

/// The human accounts - the ones a README is talking about.
pub async fn human_accounts() -> Vec<Account> {
    accounts()
        .await
        .into_iter()
        .filter(|a| a.is_human())
        .collect()
}

/// Does this account exist?
pub async fn exists(name: &str) -> bool {
    accounts().await.iter().any(|a| a.name == name)
}

/// Parse `/etc/group` into `(group, members)` pairs.
///
/// The member list here is the *supplementary* membership only. An account
/// whose primary gid is the group does not appear in it, which is why
/// [`group_members`] also consults `/etc/passwd`.
pub fn parse_group(text: &str) -> Vec<(String, u32, Vec<String>)> {
    text.lines()
        .filter(|l| !l.trim().is_empty() && !l.starts_with('#'))
        .filter_map(|line| {
            let f: Vec<&str> = line.split(':').collect();
            if f.len() < 4 {
                return None;
            }
            let members = f[3]
                .split(',')
                .map(str::trim)
                .filter(|m| !m.is_empty())
                .map(str::to_string)
                .collect();
            Some((f[0].to_string(), f[2].parse().ok()?, members))
        })
        .collect()
}

/// Everyone in `group`, counting primary membership as well as supplementary.
///
/// Missing the primary-gid case is a real bug, not a corner: `usermod -g sudo`
/// grants administrative rights without adding a name to `/etc/group`, so an
/// audit that reads only the group file reports the account as unprivileged.
pub async fn group_members(group: &str) -> Vec<String> {
    let group_text = tokio::fs::read_to_string("/etc/group")
        .await
        .unwrap_or_default();
    let groups = parse_group(&group_text);
    let Some((_, gid, mut members)) = groups.into_iter().find(|(g, _, _)| g == group) else {
        return Vec::new();
    };
    for account in accounts().await {
        if account.gid == gid && !members.contains(&account.name) {
            members.push(account.name);
        }
    }
    members.sort();
    members
}

/// Everyone with administrative rights, from whichever admin group the image
/// uses.
pub async fn administrators() -> Vec<String> {
    let mut all: Vec<String> = Vec::new();
    for group in ADMIN_GROUPS {
        for member in group_members(group).await {
            if !all.contains(&member) {
                all.push(member);
            }
        }
    }
    all.sort();
    all
}

/// Is the account locked?
///
/// A locked account's hash in `/etc/shadow` is prefixed with `!`; `*` means no
/// password was ever set, which also prevents password login. An empty hash
/// field means the account logs in with *no password at all*, which is the
/// single worst finding on an image and is reported as its own state.
///
/// `None` means `/etc/shadow` could not be read - which, run as root, means
/// something is genuinely wrong rather than that the account is fine.
pub async fn password_state(name: &str) -> Option<String> {
    let text = tokio::fs::read_to_string("/etc/shadow").await.ok()?;
    let hash = text
        .lines()
        .find_map(|l| l.split_once(':').filter(|(n, _)| *n == name))
        .map(|(_, rest)| rest.split(':').next().unwrap_or("").to_string())?;
    Some(classify_hash(&hash))
}

/// Turn a shadow hash field into the state it represents.
pub fn classify_hash(hash: &str) -> String {
    match hash {
        "" => "no password".to_string(),
        "!" | "!!" | "*" => "locked".to_string(),
        h if h.starts_with('!') => "locked".to_string(),
        _ => "set".to_string(),
    }
}

/// Lock an account, and prove it.
pub async fn lock(name: &str, why: &str) -> Result<(), String> {
    remediation::apply(
        &format!("account {name}"),
        &format!("locked ({why})"),
        || async { password_state(name).await },
        |state| state == "locked",
        &format!("usermod --lock {name}"),
        || async {
            // `--lock` alone leaves the shell intact, so an account with an SSH
            // key still logs in. Expiring it as well is what actually closes
            // the account.
            let (ok, _o, e) = command::execute("usermod", Some(&format!("--lock {name}"))).await;
            let _ = command::execute("usermod", Some(&format!("--expiredate 1 {name}"))).await;
            if ok {
                Ok(())
            } else {
                Err(e.unwrap_or_else(|| format!("usermod --lock {name} failed")))
            }
        },
    )
    .await
}

/// Set an account's password, without a proof.
///
/// Uses [`remediation::apply_unprovable`] deliberately. The shadow file stores
/// a salted hash, so reading it back can confirm that *a* password is set but
/// never that it is *this* password - and claiming a proof that was not taken
/// is worse than saying plainly that none was.
///
/// The password is passed on `chpasswd`'s stdin rather than in the command
/// line, so it never reaches the process table or the run log's record of the
/// command.
pub async fn set_password(name: &str, password: &str) -> Result<(), String> {
    remediation::apply_unprovable(
        &format!("account {name}"),
        "password set to a generated value",
        "set the password via chpasswd",
        "the shadow file stores a salted hash, so a read-back cannot confirm which password was set",
        || async { chpasswd(name, password).await },
    )
    .await
}

/// Feed one `user:password` line to `chpasswd` on stdin.
async fn chpasswd(name: &str, password: &str) -> Result<(), String> {
    use tokio::io::AsyncWriteExt;

    let mut child = tokio::process::Command::new("chpasswd")
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .map_err(|e| format!("could not run chpasswd: {e}"))?;

    if let Some(mut stdin) = child.stdin.take() {
        stdin
            .write_all(format!("{name}:{password}\n").as_bytes())
            .await
            .map_err(|e| format!("could not write to chpasswd: {e}"))?;
        // Dropping the handle closes the pipe; chpasswd waits for EOF.
        drop(stdin);
    }

    let out = child
        .wait_with_output()
        .await
        .map_err(|e| format!("chpasswd did not complete: {e}"))?;
    if out.status.success() {
        Ok(())
    } else {
        Err(String::from_utf8_lossy(&out.stderr).trim().to_string())
    }
}

/// Add an account to a group, and prove it.
pub async fn add_to_group(name: &str, group: &str, why: &str) -> Result<(), String> {
    remediation::apply(
        &format!("group {group}"),
        &format!("{name} is a member ({why})"),
        || async { Some(group_members(group).await.join(", ")) },
        |state| state.split(", ").any(|m| m == name),
        &format!("gpasswd --add {name} {group}"),
        || async {
            let (ok, _o, e) =
                command::execute("gpasswd", Some(&format!("--add {name} {group}"))).await;
            if ok {
                Ok(())
            } else {
                Err(e.unwrap_or_else(|| format!("could not add {name} to {group}")))
            }
        },
    )
    .await
}

/// Remove an account from a group, and prove it.
pub async fn remove_from_group(name: &str, group: &str, why: &str) -> Result<(), String> {
    remediation::apply(
        &format!("group {group}"),
        &format!("{name} is not a member ({why})"),
        || async { Some(group_members(group).await.join(", ")) },
        |state| !state.split(", ").any(|m| m == name),
        &format!("gpasswd --delete {name} {group}"),
        || async {
            let (ok, _o, e) =
                command::execute("gpasswd", Some(&format!("--delete {name} {group}"))).await;
            if ok {
                Ok(())
            } else {
                Err(e.unwrap_or_else(|| format!("could not remove {name} from {group}")))
            }
        },
    )
    .await
}

/// Create an account, and prove it.
pub async fn create(name: &str, why: &str) -> Result<(), String> {
    remediation::apply(
        &format!("account {name}"),
        &format!("exists ({why})"),
        || async {
            Some(
                if exists(name).await {
                    "present"
                } else {
                    "absent"
                }
                .to_string(),
            )
        },
        |state| state == "present",
        &format!("useradd --create-home {name}"),
        || async {
            // `--create-home` explicitly: whether useradd does it by default is
            // a distribution setting, and an account with no home directory
            // fails to log in with an error that names neither.
            let (ok, _o, e) = command::execute(
                "useradd",
                Some(&format!("--create-home --shell /bin/bash {name}")),
            )
            .await;
            if ok {
                Ok(())
            } else {
                Err(e.unwrap_or_else(|| format!("useradd {name} failed")))
            }
        },
    )
    .await
}

/// Remove an account, and prove it.
///
/// The home directory is **kept**. Deleting it would destroy the forensics
/// questions' evidence along with the account, and an unauthorised account's
/// home directory is often where the answer is.
pub async fn delete(name: &str, why: &str) -> Result<(), String> {
    if SYSTEM_ACCOUNTS.iter().any(|s| s.eq_ignore_ascii_case(name)) {
        return Err(format!("{name} is a system account and is never removed"));
    }
    remediation::apply(
        &format!("account {name}"),
        &format!("removed ({why})"),
        || async {
            Some(
                if exists(name).await {
                    "present"
                } else {
                    "absent"
                }
                .to_string(),
            )
        },
        |state| state == "absent",
        &format!("userdel {name}, keeping the home directory as evidence"),
        || async {
            let (ok, _o, e) = command::execute("userdel", Some(name)).await;
            if ok {
                Ok(())
            } else {
                Err(e.unwrap_or_else(|| format!("userdel {name} failed")))
            }
        },
    )
    .await
}

/// Apply password ageing to an account, and prove it.
pub async fn set_ageing(
    name: &str,
    max_days: u32,
    min_days: u32,
    warn_days: u32,
) -> Result<(), String> {
    remediation::apply(
        &format!("account {name}"),
        &format!("password ages out after {max_days} days"),
        || async { ageing(name).await },
        |state| state == format!("{max_days}/{min_days}/{warn_days}"),
        &format!("chage -M {max_days} -m {min_days} -W {warn_days} {name}"),
        || async {
            let (ok, _o, e) = command::execute(
                "chage",
                Some(&format!(
                    "-M {max_days} -m {min_days} -W {warn_days} {name}"
                )),
            )
            .await;
            if ok {
                Ok(())
            } else {
                Err(e.unwrap_or_else(|| format!("chage failed for {name}")))
            }
        },
    )
    .await
}

/// An account's `max/min/warn` ageing values, read from `/etc/shadow`.
///
/// Read from the file rather than from `chage -l`, whose output is a localised
/// sentence - the exact problem that pushed the Windows port off `net user`.
async fn ageing(name: &str) -> Option<String> {
    let text = tokio::fs::read_to_string("/etc/shadow").await.ok()?;
    let line = text.lines().find(|l| l.starts_with(&format!("{name}:")))?;
    let f: Vec<&str> = line.split(':').collect();
    // name:hash:lastchange:min:max:warn:inactive:expire:reserved
    if f.len() < 6 {
        return None;
    }
    let get = |i: usize| if f[i].is_empty() { "-1" } else { f[i] };
    Some(format!("{}/{}/{}", get(4), get(3), get(5)))
}

#[cfg(test)]
mod tests {
    use super::*;

    const PASSWD: &str = "\
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
alice:x:1000:1000:Alice Example,,,:/home/alice:/bin/bash
bob:x:1001:1001::/home/bob:/bin/bash
mallory:x:1002:1002::/home/mallory:/bin/bash
";

    #[test]
    fn passwd_records_are_parsed_into_accounts() {
        let accounts = parse_passwd(PASSWD);
        assert_eq!(accounts.len(), 7);
        let alice = accounts.iter().find(|a| a.name == "alice").unwrap();
        assert_eq!(alice.uid, 1000);
        assert_eq!(alice.home, "/home/alice");
        assert_eq!(alice.shell, "/bin/bash");
        assert_eq!(alice.comment, "Alice Example,,,");
    }

    /// The rule that decides who a README is talking about. Getting it wrong in
    /// the permissive direction means deleting `www-data`.
    #[test]
    fn only_real_people_are_human_accounts() {
        let accounts = parse_passwd(PASSWD);
        let humans: Vec<&str> = accounts
            .iter()
            .filter(|a| a.is_human())
            .map(|a| a.name.as_str())
            .collect();
        assert_eq!(humans, ["alice", "bob", "mallory"]);
    }

    /// `nobody` has uid 65534, well above the 1000 threshold. A uid rule on its
    /// own would classify it as a person and offer it for deletion.
    #[test]
    fn nobody_is_not_a_person_despite_its_uid() {
        let nobody = parse_passwd(PASSWD)
            .into_iter()
            .find(|a| a.name == "nobody")
            .unwrap();
        assert!(nobody.uid > FIRST_HUMAN_UID);
        assert!(!nobody.is_human());
    }

    /// A corrupt or truncated line is skipped rather than guessed at. Guessing
    /// which fields are missing could shift the shell into the home column and
    /// make a service account look like a person.
    #[test]
    fn a_short_record_is_skipped_rather_than_misread() {
        let accounts = parse_passwd("alice:x:1000:1000\nbob:x:1001:1001::/home/bob:/bin/bash\n");
        assert_eq!(accounts.len(), 1);
        assert_eq!(accounts[0].name, "bob");
    }

    #[test]
    fn a_service_shell_means_the_account_cannot_log_in() {
        let accounts = parse_passwd(PASSWD);
        let www = accounts.iter().find(|a| a.name == "www-data").unwrap();
        assert!(!www.can_log_in());
        let alice = accounts.iter().find(|a| a.name == "alice").unwrap();
        assert!(alice.can_log_in());
    }

    /// Found by running the audit on Arch, which puts `nologin` in `/usr/bin`
    /// rather than `/usr/sbin`. Matching full paths reported every system
    /// account on that image as able to log in - fourteen false positives in
    /// one run, which is exactly how a reader learns to ignore a finding.
    #[test]
    fn nologin_is_recognised_wherever_the_distribution_puts_it() {
        for shell in [
            "/usr/sbin/nologin",
            "/sbin/nologin",
            "/usr/bin/nologin",
            "/bin/false",
            "/usr/bin/false",
            "",
        ] {
            assert!(is_nologin_shell(shell), "{shell:?} should refuse a login");
        }
        for shell in ["/bin/bash", "/usr/bin/zsh", "/bin/sh", "/usr/bin/fish"] {
            assert!(!is_nologin_shell(shell), "{shell:?} is a real shell");
        }
    }

    #[test]
    fn group_records_are_parsed_with_their_members() {
        let groups = parse_group("sudo:x:27:alice,bob\nempty:x:100:\n");
        assert_eq!(groups[0].0, "sudo");
        assert_eq!(groups[0].1, 27);
        assert_eq!(groups[0].2, ["alice", "bob"]);
        // An empty member list is empty, not a list containing "".
        assert!(groups[1].2.is_empty());
    }

    /// Every state the shadow hash field can hold, and what each means. The
    /// empty case is the one that matters: it is a passwordless account, not a
    /// locked one, and reporting it as locked would hide the worst finding on
    /// the image.
    #[test]
    fn a_shadow_hash_is_classified_by_its_prefix() {
        assert_eq!(classify_hash(""), "no password");
        assert_eq!(classify_hash("!"), "locked");
        assert_eq!(classify_hash("!!"), "locked");
        assert_eq!(classify_hash("*"), "locked");
        assert_eq!(classify_hash("!$6$salt$hash"), "locked");
        assert_eq!(classify_hash("$6$salt$hash"), "set");
        assert_eq!(classify_hash("$y$j9T$salt$hash"), "set");
    }

    #[tokio::test]
    async fn a_system_account_is_refused_before_any_command_runs() {
        // No process is spawned: the guard returns first. This is the check
        // that stands between a malformed README and an unbootable image.
        let err = delete("root", "not in the README").await.unwrap_err();
        assert!(err.contains("system account"), "{err}");
    }
}
