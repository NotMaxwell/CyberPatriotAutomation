// =============================================================================
// PinnacleCyPat - Proved changes to the PAM stack
// Copyright 2026 Maxwell McCormick
// SPDX-License-Identifier: Apache-2.0
// =============================================================================

//! Lockout and password history, added to PAM the way Ubuntu expects: as
//! `pam-auth-update` profiles, never as hand-inserted lines.
//!
//! `/etc/pam.d/common-*` are ordered stacks in which a line's position decides
//! what it does. `pam_unix` jumps over the lines after it on success
//! (`[success=N]`), so a `pam_faillock` line inserted in the wrong place either
//! never runs or sits where a correct password lands on it - and then every
//! login fails, root's included. That is unrecoverable inside a round, which is
//! why this was reported rather than fixed until now.
//!
//! `pam-auth-update` removes the guesswork: each profile states a priority, and
//! the tool computes the order and rewrites the `success=N` jumps itself. It is
//! also what Ubuntu regenerates these files with whenever a package touches
//! authentication, so a profile survives that and a hand edit does not. The
//! profiles below are the CIS Ubuntu 22.04 ones.
//!
//! Three safeguards sit around the call:
//!
//! - **No `--force`.** If an image's `common-*` files carry local edits,
//!   `pam-auth-update` refuses to touch them. Forcing it would discard those
//!   edits, which may be the round's own configuration. A refusal reads back as
//!   unchanged and is recorded as a failure, with the reason.
//! - **The result is checked structurally** ([`auth_order_is_safe`],
//!   [`password_order_is_safe`]): a correct password must still reach
//!   `pam_permit`, not `pam_deny` or the lockout check.
//! - **Anything unexpected is rolled back**: the profiles are disabled and
//!   removed, and the original files are written back if they still differ.

use pinnacle_core::{command, remediation};
use std::time::Duration;

use crate::file_ops;

pub const COMMON_AUTH: &str = "/etc/pam.d/common-auth";
pub const COMMON_ACCOUNT: &str = "/etc/pam.d/common-account";
pub const COMMON_PASSWORD: &str = "/etc/pam.d/common-password";
const PAM_CONFIGS: &str = "/usr/share/pam-configs";

/// One `pam-auth-update` profile: its file name and contents.
pub struct Profile {
    pub name: &'static str,
    pub body: &'static str,
}

/// Lockout. Two profiles because the module is called twice: `preauth` before
/// the password is checked (refuse a locked account) and `authfail` after it
/// fails (count the failure). Priority 0 places `authfail` after `pam_unix`,
/// where only a failed password reaches it.
pub const FAILLOCK_PROFILES: &[Profile] = &[
    Profile {
        name: "pinnacle-faillock",
        body: "Name: Lock accounts after repeated failed logins (PinnacleCyPat)
Default: yes
Priority: 0
Auth-Type: Primary
Auth:
\t[default=die]\tpam_faillock.so authfail
",
    },
    Profile {
        name: "pinnacle-faillock-notify",
        body: "Name: Check and reset the failed-login count (PinnacleCyPat)
Default: yes
Priority: 1024
Auth-Type: Primary
Auth:
\trequisite\tpam_faillock.so preauth
Account-Type: Primary
Account:
\trequired\tpam_faillock.so
",
    },
];

/// Password history. Priority 1000 puts it after `pam_pwquality` (1024), which
/// prompts for the new password, and before `pam_unix` (256), which stores it.
/// `use_authtok` makes it check the password `pam_pwquality` collected rather
/// than prompt a second time - and is why it needs `pam_pwquality` before it.
/// `remember=5` matches Password Policy's `REMEMBER`; a test there pins it.
pub const PWHISTORY_PROFILE: Profile = Profile {
    name: "pinnacle-pwhistory",
    body: "Name: Refuse recently used passwords (PinnacleCyPat)
Default: yes
Priority: 1000
Password-Type: Primary
Password:
\trequisite\tpam_pwhistory.so remember=5 enforce_for_root try_first_pass use_authtok
",
};

/// The active lines of a PAM file for one management group (`auth`,
/// `password`, ...), in order.
fn stack<'a>(text: &'a str, group: &str) -> Vec<&'a str> {
    text.lines()
        .filter(|l| file_ops::is_active(l))
        .filter(|l| l.split_whitespace().next() == Some(group))
        .collect()
}

fn module_index(lines: &[&str], module: &str, argument: Option<&str>) -> Option<usize> {
    lines.iter().position(|l| {
        let mut words = l.split_whitespace();
        words.any(|w| w == module) && argument.is_none_or(|a| l.split_whitespace().any(|w| w == a))
    })
}

/// The `N` in `[success=N ...]`, if the line has one.
fn success_jump(line: &str) -> Option<usize> {
    let start = line.find("success=")? + "success=".len();
    let digits: String = line[start..]
        .chars()
        .take_while(char::is_ascii_digit)
        .collect();
    digits.parse().ok()
}

/// Where a successful `pam_unix` sends the stack, or `None` if the file is not
/// in the shape `pam-auth-update` writes.
fn success_target<'a>(lines: &[&'a str], unix: usize) -> Option<&'a str> {
    let jump = success_jump(lines[unix])?;
    lines.get(unix + jump + 1).copied()
}

/// Would a correct password still log in, with lockout in effect?
///
/// - `preauth` runs before `pam_unix`, so a locked account is refused first;
/// - `authfail` runs after `pam_unix`, so only a failed password reaches it;
/// - a successful `pam_unix` jumps past both `authfail` and `pam_deny`.
///
/// The last one is the property that matters: if it fails, every login fails.
pub fn auth_order_is_safe(common_auth: &str) -> bool {
    let lines = stack(common_auth, "auth");
    let (Some(pre), Some(unix), Some(fail)) = (
        module_index(&lines, "pam_faillock.so", Some("preauth")),
        module_index(&lines, "pam_unix.so", None),
        module_index(&lines, "pam_faillock.so", Some("authfail")),
    ) else {
        return false;
    };
    if !(pre < unix && unix < fail) {
        return false;
    }
    match success_target(&lines, unix) {
        Some(target) => !target.contains("pam_deny.so") && !target.contains("pam_faillock.so"),
        None => false,
    }
}

/// Would a password change still work, with history in effect?
///
/// `pam_pwhistory` must come after `pam_pwquality` (which collects the new
/// password it checks) and before `pam_unix` (which stores it), and a
/// successful `pam_unix` must not land on `pam_deny`.
pub fn password_order_is_safe(common_password: &str) -> bool {
    let lines = stack(common_password, "password");
    let (Some(quality), Some(history), Some(unix)) = (
        module_index(&lines, "pam_pwquality.so", None),
        module_index(&lines, "pam_pwhistory.so", None),
        module_index(&lines, "pam_unix.so", None),
    ) else {
        return false;
    };
    if !(quality < history && history < unix) {
        return false;
    }
    success_target(&lines, unix).is_some_and(|t| !t.contains("pam_deny.so"))
}

/// The password history depth in effect: the larger of `pam_pwhistory`'s and
/// `pam_unix`'s `remember=`, since either one enforces it.
pub fn history_depth(common_password: &str) -> Option<u32> {
    stack(common_password, "password")
        .iter()
        .filter(|l| l.contains("pam_pwhistory.so") || l.contains("pam_unix.so"))
        .filter_map(|l| {
            l.split_whitespace()
                .find_map(|t| t.strip_prefix("remember="))
                .and_then(|v| v.parse().ok())
        })
        .max()
}

/// Is `pam_pwquality` in the password stack? `pam_pwhistory`'s `use_authtok`
/// depends on it; without it every password change would fail.
pub fn pwquality_in_stack(common_password: &str) -> bool {
    module_index(
        &stack(common_password, "password"),
        "pam_pwquality.so",
        None,
    )
    .is_some()
}

/// `auth` lines that let a login through without checking a password.
///
/// `auth sufficient pam_permit.so` succeeds unconditionally, and as
/// `sufficient` it ends the stack there: any password, or none, logs in. It is a
/// classic planted backdoor, and nothing in the file looks broken. A
/// `pam_permit.so` ahead of `pam_unix` is suspect for the same reason. The
/// stock `auth required pam_permit.so` at the end of `common-auth` is neither.
pub fn permissive_auth_lines(text: &str) -> Vec<String> {
    let lines = stack(text, "auth");
    let unix = module_index(&lines, "pam_unix.so", None);
    lines
        .iter()
        .enumerate()
        .filter(|(i, l)| {
            let mut words = l.split_whitespace();
            let control = words.nth(1).unwrap_or_default();
            l.split_whitespace().any(|w| w == "pam_permit.so")
                && (control == "sufficient" || unix.is_some_and(|u| *i < u))
        })
        .map(|(_, l)| l.trim().to_string())
        .collect()
}

/// Install `profiles`, enable them with `pam-auth-update`, and prove the result
/// with `is_safe` over `file` - rolling everything back if it is not safe.
///
/// Recorded through [`remediation::apply`], so a dry run changes nothing and the
/// ledger shows the state before and after.
pub async fn enable(
    profiles: &[Profile],
    file: &'static str,
    target: &str,
    intent: &str,
    is_safe: fn(&str) -> bool,
) -> Result<(), String> {
    remediation::apply(
        target,
        intent,
        || async move {
            let text = tokio::fs::read_to_string(file).await.ok()?;
            Some(if is_safe(&text) {
                "in effect, correctly ordered".to_string()
            } else {
                "not in effect".to_string()
            })
        },
        |state| state == "in effect, correctly ordered",
        &format!(
            "pam-auth-update --enable {}",
            profiles
                .iter()
                .map(|p| p.name)
                .collect::<Vec<_>>()
                .join(" ")
        ),
        || install(profiles, file, is_safe),
    )
    .await
}

/// Put `pam_pwquality` into `common-password` through its own profile, for an
/// image where `libpam-pwquality` is installed but was taken out of the stack.
pub async fn enable_pwquality() -> Result<(), String> {
    remediation::apply(
        COMMON_PASSWORD,
        "pam_pwquality is in the password stack, so minlen is enforced",
        || async {
            let text = tokio::fs::read_to_string(COMMON_PASSWORD).await.ok()?;
            Some(if pwquality_in_stack(&text) {
                "in effect".to_string()
            } else {
                "not in effect".to_string()
            })
        },
        |state| state == "in effect",
        "pam-auth-update --enable pwquality",
        || async {
            // No --force, for the reason given in the module notes.
            let (code, out, err) = command::execute_for_exit_code_with_env(
                "pam-auth-update",
                Some("--enable pwquality"),
                &[("DEBIAN_FRONTEND", "noninteractive")],
                Duration::from_secs(60),
            )
            .await;
            if code == Some(0) {
                Ok(())
            } else {
                Err(format!(
                    "pam-auth-update --enable pwquality failed: {} {}",
                    out,
                    err.unwrap_or_default()
                ))
            }
        },
    )
    .await
}

// --- argument edits ----------------------------------------------------------
//
// `pam-auth-update` regenerates `common-*` from the profiles, and the stock
// `unix` profile carries `nullok`, so these edits must run after every call to
// it. They change arguments on a line and never move one, so the ordering that
// [`auth_order_is_safe`] checks cannot be disturbed by them.

/// Apply `edit` to every active line that names `module`, leaving comments,
/// other lines, whitespace and the file's trailing newline exactly as they were.
fn map_module_lines(text: &str, module: &str, edit: impl Fn(&str) -> String) -> String {
    text.split_inclusive('\n')
        .map(|raw| {
            let (line, end) = match raw.strip_suffix('\n') {
                Some(l) => (l, "\n"),
                None => (raw, ""),
            };
            if file_ops::is_active(line) && line.split_whitespace().any(|w| w == module) {
                format!("{}{end}", edit(line))
            } else {
                raw.to_string()
            }
        })
        .collect()
}

/// Split a line into alternating whitespace and non-whitespace pieces.
fn pieces(line: &str) -> Vec<(bool, &str)> {
    let mut out = Vec::new();
    let mut rest = line;
    while !rest.is_empty() {
        let is_space = rest.starts_with(char::is_whitespace);
        let len = rest
            .find(|c: char| c.is_whitespace() != is_space)
            .unwrap_or(rest.len());
        let (piece, tail) = rest.split_at(len);
        out.push((is_space, piece));
        rest = tail;
    }
    out
}

/// Rebuild a line, calling `keep` on each word: `Some(w)` keeps (or replaces)
/// it with the whitespace before it, `None` drops it and that whitespace.
fn rebuild(line: &str, mut word: impl FnMut(&str) -> Option<String>) -> String {
    let mut out = String::new();
    let mut space = "";
    for (is_space, piece) in pieces(line) {
        if is_space {
            space = piece;
        } else if let Some(w) = word(piece) {
            out.push_str(space);
            out.push_str(&w);
            space = "";
        } else {
            space = "";
        }
    }
    out
}

/// Remove `nullok` and `nullok_secure` from every active `pam_unix` line.
///
/// `nullok` lets an account with an empty password log in; the stock `unix`
/// profile puts it back on every `pam-auth-update`.
pub fn strip_nullok(text: &str) -> String {
    map_module_lines(text, "pam_unix.so", |line| {
        rebuild(line, |w| {
            (w != "nullok" && w != "nullok_secure").then(|| w.to_string())
        })
    })
}

/// Does an active `pam_unix` line still carry `nullok` or `nullok_secure`?
pub fn has_nullok(text: &str) -> bool {
    text.lines()
        .filter(|l| file_ops::is_active(l))
        .filter(|l| l.split_whitespace().any(|w| w == "pam_unix.so"))
        .any(|l| {
            l.split_whitespace()
                .any(|w| w == "nullok" || w == "nullok_secure")
        })
}

/// Make every active line for `module` (e.g. `pam_unix.so`) carry
/// `key=value`: an existing `key=` is replaced (a repeat is dropped), otherwise
/// it is appended. Lines for other modules and comments are untouched, and a
/// module that is not in the file is not added.
pub fn set_module_arg(text: &str, module: &str, key: &str, value: &str) -> String {
    let prefix = format!("{key}=");
    let wanted = format!("{key}={value}");
    map_module_lines(text, module, |line| {
        let mut placed = false;
        let mut out = rebuild(line, |w| {
            if w.starts_with(&prefix) {
                if placed {
                    None
                } else {
                    placed = true;
                    Some(wanted.clone())
                }
            } else {
                Some(w.to_string())
            }
        });
        if !placed {
            out.push(' ');
            out.push_str(&wanted);
        }
        out
    })
}

/// The value of `key=` on each active line for `module` (`None` where absent).
fn module_arg(text: &str, module: &str, key: &str) -> Vec<Option<String>> {
    let prefix = format!("{key}=");
    text.lines()
        .filter(|l| file_ops::is_active(l))
        .filter(|l| l.split_whitespace().any(|w| w == module))
        .map(|l| {
            l.split_whitespace()
                .find_map(|w| w.strip_prefix(&prefix))
                .map(str::to_string)
        })
        .collect()
}

/// `common-password` with the length and history arguments the scored checks
/// read: `minlen` on `pam_pwquality` and `pam_unix`, `remember` on `pam_unix`.
pub fn with_password_args(text: &str, minlen: u32, remember: u32) -> String {
    let text = set_module_arg(text, "pam_pwquality.so", "minlen", &minlen.to_string());
    let text = set_module_arg(&text, "pam_unix.so", "minlen", &minlen.to_string());
    set_module_arg(&text, "pam_unix.so", "remember", &remember.to_string())
}

/// Does every `pam_pwquality`/`pam_unix` line in `common-password` carry the
/// arguments [`with_password_args`] sets? A module that is absent is not
/// required to be there.
pub fn password_args_present(text: &str, minlen: u32, remember: u32) -> bool {
    let (m, r) = (Some(minlen.to_string()), Some(remember.to_string()));
    module_arg(text, "pam_pwquality.so", "minlen")
        .iter()
        .all(|v| *v == m)
        && module_arg(text, "pam_unix.so", "minlen")
            .iter()
            .all(|v| *v == m)
        && module_arg(text, "pam_unix.so", "remember")
            .iter()
            .all(|v| *v == r)
}

/// Rewrite `file` through `transform`, proving it with `compliant` over a
/// re-read. Backed up first and written atomically, like `file_ops::set`.
async fn edit_file(
    file: &'static str,
    intent: &str,
    action: &str,
    transform: impl Fn(&str) -> String,
    compliant: impl Fn(&str) -> bool + Copy,
) -> Result<(), String> {
    remediation::apply(
        file,
        intent,
        || async move {
            let text = tokio::fs::read_to_string(file).await.ok()?;
            Some(if compliant(&text) {
                "compliant".to_string()
            } else {
                "not compliant".to_string()
            })
        },
        |state| state == "compliant",
        action,
        || async {
            let original = tokio::fs::read_to_string(file)
                .await
                .map_err(|e| format!("could not read {file}: {e}"))?;
            let updated = transform(&original);
            if updated == original {
                return Ok(());
            }
            file_ops::back_up(file, &original).await?;
            file_ops::write_atomically(file, &updated).await
        },
    )
    .await
}

/// Remove `nullok` from `common-auth` and `common-password`. Run it after the
/// last `pam-auth-update`, which restores it.
pub async fn remove_nullok() -> Result<(), String> {
    let mut failures = Vec::new();
    for file in [COMMON_AUTH, COMMON_PASSWORD] {
        if !tokio::fs::try_exists(file).await.unwrap_or(false) {
            continue;
        }
        if let Err(e) = edit_file(
            file,
            "no pam_unix line allows an empty password (nullok removed)",
            "strip nullok and nullok_secure from the pam_unix lines",
            strip_nullok,
            |t| !has_nullok(t),
        )
        .await
        {
            failures.push(e);
        }
    }
    if failures.is_empty() {
        Ok(())
    } else {
        Err(failures.join("; "))
    }
}

/// Put `minlen` and `remember` on the `common-password` lines. Run it after the
/// last `pam-auth-update`, which regenerates the file without them.
pub async fn ensure_password_args(minlen: u32, remember: u32) -> Result<(), String> {
    edit_file(
        COMMON_PASSWORD,
        &format!("minlen={minlen} on pam_pwquality and pam_unix, remember={remember} on pam_unix"),
        "add minlen/remember to the password lines",
        move |t| with_password_args(t, minlen, remember),
        move |t| password_args_present(t, minlen, remember),
    )
    .await
}

async fn install(
    profiles: &[Profile],
    file: &str,
    is_safe: fn(&str) -> bool,
) -> Result<(), String> {
    // Snapshot every file pam-auth-update may rewrite, so a rollback restores
    // exactly what was there rather than what pam-auth-update regenerates.
    let mut originals = Vec::new();
    for path in [COMMON_AUTH, COMMON_ACCOUNT, COMMON_PASSWORD] {
        originals.push((path, tokio::fs::read_to_string(path).await.ok()));
    }

    for profile in profiles {
        let path = format!("{PAM_CONFIGS}/{}", profile.name);
        tokio::fs::write(&path, profile.body)
            .await
            .map_err(|e| format!("could not write {path}: {e}"))?;
    }

    let names: Vec<&str> = profiles.iter().map(|p| p.name).collect();
    let (code, stdout, stderr) = command::execute_for_exit_code_with_env(
        "pam-auth-update",
        Some(&format!("--enable {}", names.join(" "))),
        // Otherwise a local-modification prompt waits for a console nobody is at.
        &[("DEBIAN_FRONTEND", "noninteractive")],
        Duration::from_secs(60),
    )
    .await;

    let after = tokio::fs::read_to_string(file).await.unwrap_or_default();
    if code == Some(0) && is_safe(&after) {
        return Ok(());
    }

    // Not in effect, or in effect in an order that could lock people out.
    let _ = command::execute_for_exit_code_with_env(
        "pam-auth-update",
        Some(&format!("--disable {}", names.join(" "))),
        &[("DEBIAN_FRONTEND", "noninteractive")],
        Duration::from_secs(60),
    )
    .await;
    for name in &names {
        let _ = tokio::fs::remove_file(format!("{PAM_CONFIGS}/{name}")).await;
    }
    for (path, original) in originals {
        if let Some(original) = original
            && tokio::fs::read_to_string(path).await.ok().as_deref() != Some(&original)
        {
            let _ = tokio::fs::write(path, original).await;
        }
    }

    let said = format!("{stdout} {}", stderr.unwrap_or_default());
    let said = said.trim();
    Err(if said.to_lowercase().contains("local modifications") {
        format!(
            "pam-auth-update refused: {file} has local edits, and forcing it would discard \
             them. Rolled back. ({said})"
        )
    } else if code != Some(0) {
        format!("pam-auth-update failed ({said}); rolled back")
    } else {
        format!("the resulting order in {file} was not safe; rolled back")
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// What pam-auth-update wrote on Ubuntu 24.04 with these profiles enabled,
    /// captured verbatim - a correct password logged in, five wrong ones
    /// locked the account, and a reset unlocked it.
    const AUTH_ENABLED: &str = "\
auth\trequisite\tpam_faillock.so preauth
auth\t[success=2 default=ignore]\tpam_unix.so nullok try_first_pass
auth\t[default=die]\tpam_faillock.so authfail
auth\trequisite\t\t\tpam_deny.so
auth\trequired\t\t\tpam_permit.so
";

    const PASSWORD_ENABLED: &str = "\
password\trequisite\t\t\tpam_pwquality.so retry=3
password\trequisite\tpam_pwhistory.so remember=5 enforce_for_root try_first_pass use_authtok
password\t[success=1 default=ignore]\tpam_unix.so obscure use_authtok try_first_pass yescrypt
password\trequisite\t\t\tpam_deny.so
password\trequired\t\t\tpam_permit.so
";

    #[test]
    fn the_order_pam_auth_update_writes_is_safe() {
        assert!(auth_order_is_safe(AUTH_ENABLED));
        assert!(password_order_is_safe(PASSWORD_ENABLED));
    }

    /// The failure this module exists to prevent: the jump not updated for the
    /// inserted line, so a correct password lands on the lockout check.
    #[test]
    fn a_correct_password_landing_on_authfail_is_unsafe() {
        let text = AUTH_ENABLED.replace("success=2", "success=0");
        assert!(!auth_order_is_safe(&text));
    }

    #[test]
    fn a_correct_password_landing_on_deny_is_unsafe() {
        let text = AUTH_ENABLED.replace("success=2", "success=1");
        assert!(!auth_order_is_safe(&text));
    }

    #[test]
    fn authfail_before_pam_unix_is_unsafe() {
        let text = "\
auth\trequisite\tpam_faillock.so preauth
auth\t[default=die]\tpam_faillock.so authfail
auth\t[success=1 default=ignore]\tpam_unix.so nullok
auth\trequisite\tpam_deny.so
auth\trequired\tpam_permit.so
";
        assert!(!auth_order_is_safe(text));
    }

    #[test]
    fn the_stock_files_are_not_in_effect() {
        let stock_auth = "\
auth\t[success=1 default=ignore]\tpam_unix.so nullok
auth\trequisite\t\t\tpam_deny.so
auth\trequired\t\t\tpam_permit.so
";
        assert!(!auth_order_is_safe(stock_auth));
        let stock_password = "\
password\trequisite\t\t\tpam_pwquality.so retry=3
password\t[success=1 default=ignore]\tpam_unix.so obscure use_authtok try_first_pass yescrypt
";
        assert!(!password_order_is_safe(stock_password));
        assert!(pwquality_in_stack(stock_password));
    }

    #[test]
    fn history_after_pam_unix_is_unsafe() {
        let text = "\
password\trequisite\tpam_pwquality.so retry=3
password\t[success=1 default=ignore]\tpam_unix.so obscure use_authtok
password\trequisite\tpam_pwhistory.so remember=5 use_authtok
password\trequired\tpam_permit.so
";
        assert!(!password_order_is_safe(text));
    }

    #[test]
    fn a_commented_line_is_not_part_of_the_stack() {
        let text = format!("# {}", AUTH_ENABLED.lines().next().unwrap());
        assert!(stack(&text, "auth").is_empty());
    }

    #[test]
    fn a_planted_sufficient_pam_permit_is_found() {
        let text = format!("auth\tsufficient\t\t\tpam_permit.so\n{AUTH_ENABLED}");
        assert_eq!(
            permissive_auth_lines(&text),
            vec!["auth\tsufficient\t\t\tpam_permit.so".to_string()]
        );
    }

    /// The stock trailing `required pam_permit.so` only runs after `pam_unix`
    /// has already jumped past `pam_deny`; flagging it would be noise.
    #[test]
    fn the_stock_trailing_pam_permit_is_not_flagged() {
        assert!(permissive_auth_lines(AUTH_ENABLED).is_empty());
    }

    #[test]
    fn pam_permit_ahead_of_pam_unix_is_flagged() {
        let text = "auth\trequired\tpam_permit.so\nauth\t[success=1 default=ignore]\tpam_unix.so\n";
        assert_eq!(permissive_auth_lines(text).len(), 1);
    }

    #[test]
    fn history_depth_reads_either_module() {
        assert_eq!(history_depth(PASSWORD_ENABLED), Some(5));
        assert_eq!(
            history_depth("password [success=1 default=ignore] pam_unix.so sha512 remember=12\n"),
            Some(12)
        );
        assert_eq!(history_depth("password requisite pam_deny.so\n"), None);
    }

    const STOCK_PASSWORD: &str = "\
# here are the per-package modules
password\trequisite\t\t\tpam_pwquality.so retry=3
password\t[success=1 default=ignore]\tpam_unix.so obscure use_authtok try_first_pass yescrypt
password\trequisite\t\t\tpam_deny.so
";

    #[test]
    fn nullok_is_stripped_from_pam_unix_only() {
        let text = "auth\t[success=1 default=ignore]\tpam_unix.so nullok try_first_pass\nauth\toptional\tpam_foo.so nullok\n# auth pam_unix.so nullok\n";
        let out = strip_nullok(text);
        assert_eq!(
            out,
            "auth\t[success=1 default=ignore]\tpam_unix.so try_first_pass\nauth\toptional\tpam_foo.so nullok\n# auth pam_unix.so nullok\n"
        );
        assert!(has_nullok(text));
        assert!(!has_nullok(&out));
    }

    #[test]
    fn nullok_secure_and_a_trailing_nullok_are_stripped() {
        let out = strip_nullok(
            "auth sufficient pam_unix.so nullok_secure\nauth required pam_unix.so try_first_pass nullok",
        );
        assert_eq!(
            out,
            "auth sufficient pam_unix.so\nauth required pam_unix.so try_first_pass"
        );
    }

    #[test]
    fn stripping_nullok_keeps_the_order_safe() {
        assert!(has_nullok(AUTH_ENABLED));
        let out = strip_nullok(AUTH_ENABLED);
        assert!(auth_order_is_safe(&out));
        assert!(!has_nullok(&out));
    }

    #[test]
    fn set_module_arg_replaces_or_appends() {
        let out = set_module_arg(STOCK_PASSWORD, "pam_pwquality.so", "minlen", "14");
        assert!(out.contains("pam_pwquality.so retry=3 minlen=14\n"));
        let again = set_module_arg(&out, "pam_pwquality.so", "minlen", "16");
        assert!(again.contains("retry=3 minlen=16\n"));
        assert!(!again.contains("minlen=14"));
    }

    #[test]
    fn set_module_arg_touches_only_active_lines_for_that_module() {
        let out = set_module_arg(STOCK_PASSWORD, "pam_unix.so", "remember", "5");
        assert!(out.contains("yescrypt remember=5\n"));
        assert!(out.contains("# here are the per-package modules\n"));
        assert!(out.contains("pam_deny.so\n"));
        let commented = "# password requisite pam_unix.so\n";
        assert_eq!(
            set_module_arg(commented, "pam_unix.so", "remember", "5"),
            commented
        );
        // A module that is not there is not invented.
        let deny = "password requisite pam_deny.so\n";
        assert_eq!(set_module_arg(deny, "pam_unix.so", "minlen", "14"), deny);
    }

    #[test]
    fn set_module_arg_drops_a_repeated_key() {
        let out = set_module_arg(
            "password required pam_unix.so minlen=8 minlen=9 sha512\n",
            "pam_unix.so",
            "minlen",
            "14",
        );
        assert_eq!(out, "password required pam_unix.so minlen=14 sha512\n");
    }

    #[test]
    fn password_args_land_on_both_modules_and_keep_the_order_safe() {
        let out = with_password_args(PASSWORD_ENABLED, 14, 5);
        assert!(!password_args_present(PASSWORD_ENABLED, 14, 5));
        assert!(password_args_present(&out, 14, 5));
        assert!(out.contains("pam_pwquality.so retry=3 minlen=14"));
        assert!(out.contains(
            "pam_unix.so obscure use_authtok try_first_pass yescrypt minlen=14 remember=5"
        ));
        assert!(password_order_is_safe(&out));
        assert_eq!(history_depth(&out), Some(5));
        assert_eq!(with_password_args(&out, 14, 5), out, "not idempotent");
    }

    #[test]
    fn password_args_without_pwquality_still_cover_pam_unix() {
        let text = "password [success=1 default=ignore] pam_unix.so obscure yescrypt\n";
        let out = with_password_args(text, 14, 5);
        assert!(password_args_present(&out, 14, 5));
        assert!(!out.contains("pam_pwquality"));
    }

    #[test]
    fn the_profiles_carry_the_fields_pam_auth_update_requires() {
        for profile in FAILLOCK_PROFILES.iter().chain([&PWHISTORY_PROFILE]) {
            for field in ["Name:", "Default: yes", "Priority:"] {
                assert!(
                    profile.body.contains(field),
                    "{} lacks {field}",
                    profile.name
                );
            }
            assert!(profile.name.starts_with("pinnacle-"));
        }
    }
}
