// =============================================================================
// PinnacleCyPat - Proved changes to sudoers
// Copyright 2026 Maxwell McCormick
// SPDX-License-Identifier: Apache-2.0
// =============================================================================

//! Makes sudo ask for a password: removes `NOPASSWD:` tags and comments out
//! `Defaults !authenticate`, in `/etc/sudoers` and `/etc/sudoers.d/*`.
//!
//! **The tag is removed, not the rule.** The usual plant is the stock line
//! edited to `%sudo ALL=(ALL:ALL) NOPASSWD: ALL`. Commenting that out would take
//! sudo away from every administrator - and with root's password locked, as it
//! is on Ubuntu, nobody could get it back. Dropping the tag leaves
//! `%sudo ALL=(ALL:ALL) ALL`: the same access, behind a password.
//!
//! **A sudoers syntax error disables sudo entirely**, so every write is checked
//! with `visudo -c` over the whole configuration and reverted if it fails, and a
//! configuration that already fails the check is not touched at all - the
//! error is someone else's and a second edit only obscures it.

use pinnacle_core::{command, remediation};

use crate::file_ops;

pub const SUDOERS: &str = "/etc/sudoers";
pub const SUDOERS_D: &str = "/etc/sudoers.d";

/// Is this sudoers line one that lets sudo run without a password?
fn is_passwordless(line: &str) -> bool {
    if !file_ops::is_active(line) {
        return false;
    }
    let t = line.trim_start();
    (t.starts_with("Defaults") && t.contains("!authenticate")) || t.contains("NOPASSWD:")
}

/// Every line that lets sudo run without a password.
pub fn passwordless_entries(text: &str) -> Vec<String> {
    text.lines()
        .filter(|l| is_passwordless(l))
        .map(|l| l.trim().to_string())
        .collect()
}

/// The file with sudo asking for a password everywhere. Pure, so the rules can
/// be tested without a filesystem.
pub fn rewrite(original: &str) -> String {
    let mut out: Vec<String> = Vec::new();
    for line in original.lines() {
        if !is_passwordless(line) {
            out.push(line.to_string());
            continue;
        }
        if line.trim_start().starts_with("Defaults") {
            out.push(format!(
                "# {line}    # disabled by PinnacleCyPat: it let sudo run without a password"
            ));
        } else {
            out.push("# PinnacleCyPat removed NOPASSWD from the next line".to_string());
            out.push(strip_nopasswd(line));
        }
    }
    let mut text = out.join("\n");
    text.push('\n');
    text
}

/// `NOPASSWD:` and the whitespace after it, removed wherever it appears - a
/// rule can carry it once per command list.
fn strip_nopasswd(line: &str) -> String {
    let mut rest = line;
    let mut out = String::new();
    while let Some(at) = rest.find("NOPASSWD:") {
        out.push_str(&rest[..at]);
        rest = rest[at + "NOPASSWD:".len()..].trim_start();
    }
    out.push_str(rest);
    out
}

/// The files sudo actually reads: `/etc/sudoers` and every file in
/// `/etc/sudoers.d` it does not skip. sudo ignores names containing `.` or
/// ending in `~`, so editing those would change nothing.
pub async fn files() -> Vec<String> {
    let mut found = vec![SUDOERS.to_string()];
    let Ok(mut entries) = tokio::fs::read_dir(SUDOERS_D).await else {
        return found;
    };
    let mut extra = Vec::new();
    while let Ok(Some(entry)) = entries.next_entry().await {
        let name = entry.file_name().to_string_lossy().to_string();
        if name.contains('.') || name.ends_with('~') {
            continue;
        }
        if entry.file_type().await.is_ok_and(|t| t.is_file()) {
            extra.push(format!("{SUDOERS_D}/{name}"));
        }
    }
    extra.sort();
    found.extend(extra);
    found
}

async fn sudoers_valid() -> Result<(), String> {
    let (ok, out, err) = command::execute("visudo", Some("-c")).await;
    if ok {
        Ok(())
    } else {
        Err(format!("{out} {}", err.unwrap_or_default())
            .trim()
            .to_string())
    }
}

/// Make sudo ask for a password in `path`, proved by reading the file back.
pub async fn require_password(path: &str) -> Result<usize, String> {
    let Ok(original) = tokio::fs::read_to_string(path).await else {
        return Err(format!("could not read {path}"));
    };
    let count = passwordless_entries(&original).len();
    if count == 0 {
        return Ok(0);
    }

    remediation::apply(
        path,
        "sudo asks for the user's password",
        || async {
            let text = tokio::fs::read_to_string(path).await.ok()?;
            Some(match passwordless_entries(&text).len() {
                0 => "no passwordless entries".to_string(),
                n => format!(
                    "{n} passwordless entries: {}",
                    passwordless_entries(&text).join(" | ")
                ),
            })
        },
        |state| state == "no passwordless entries",
        &format!("removed NOPASSWD / !authenticate from {count} entries"),
        || async {
            if let Err(e) = sudoers_valid().await {
                return Err(format!(
                    "sudoers already fails visudo -c, so it was not touched: {e}"
                ));
            }
            file_ops::back_up(path, &original).await?;
            file_ops::write_atomically(path, &rewrite(&original)).await?;
            if let Err(e) = sudoers_valid().await {
                // Put it back before anything else runs sudo.
                let restored = file_ops::write_atomically(path, &original).await;
                return Err(format!(
                    "the edited file failed visudo -c ({e}); {}",
                    match restored {
                        Ok(()) => "the original was restored".to_string(),
                        Err(r) =>
                            format!("RESTORING THE ORIGINAL FAILED ({r}) - fix {path} by hand"),
                    }
                ));
            }
            Ok(())
        },
    )
    .await?;
    Ok(count)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_tag_is_removed_and_the_rule_kept() {
        let out = rewrite("%sudo\tALL=(ALL:ALL) NOPASSWD: ALL\n");
        assert!(out.contains("%sudo\tALL=(ALL:ALL) ALL\n"), "{out}");
        assert!(passwordless_entries(&out).is_empty());
    }

    #[test]
    fn every_tag_on_a_line_is_removed() {
        let line = "bob ALL = NOPASSWD: /bin/ls, PASSWD: /bin/cat, NOPASSWD:NOEXEC: /bin/vi";
        assert_eq!(
            strip_nopasswd(line),
            "bob ALL = /bin/ls, PASSWD: /bin/cat, NOEXEC: /bin/vi"
        );
    }

    #[test]
    fn defaults_not_authenticate_is_commented_out() {
        let out = rewrite("Defaults:bob !authenticate\nDefaults env_reset\n");
        assert!(out.starts_with("# Defaults:bob !authenticate"), "{out}");
        assert!(out.contains("\nDefaults env_reset\n"));
        assert!(passwordless_entries(&out).is_empty());
    }

    /// The stock file: `#includedir` is a directive that looks like a comment,
    /// and must come through untouched.
    #[test]
    fn the_stock_file_is_left_alone() {
        let stock = "\
Defaults\tenv_reset
Defaults\tuse_pty
root\tALL=(ALL:ALL) ALL
%admin ALL=(ALL) ALL
%sudo\tALL=(ALL:ALL) ALL
@includedir /etc/sudoers.d
#includedir /etc/sudoers.d
";
        assert!(passwordless_entries(stock).is_empty());
        assert_eq!(rewrite(stock), stock);
    }

    #[test]
    fn a_commented_nopasswd_is_not_an_entry() {
        assert!(passwordless_entries("# %sudo ALL=(ALL) NOPASSWD: ALL\n").is_empty());
    }
}
