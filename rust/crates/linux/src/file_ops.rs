// =============================================================================
// PinnacleCyPat - Proved edits to Linux configuration files
// Author: Maxwell McCormick
// Copyright 2026 Maxwell McCormick
// SPDX-License-Identifier: Apache-2.0
// =============================================================================

//! What `registry_ops` is on Windows, this is on Linux: the one place a setting
//! is written, and the only place that knows how the file is shaped.
//!
//! Almost every Linux hardening setting is a keyword and a value in a text file
//! under `/etc`, in one of two spellings:
//!
//! ```text
//! PermitRootLogin no                 # sshd_config, login.defs - separated by space
//! net.ipv4.ip_forward = 0            # sysctl.conf - separated by '='
//! ```
//!
//! Two details make writing them by hand unreliable, and both are handled here.
//!
//! **Duplicates change the meaning, and the rule differs per file.** `sshd`
//! takes the *first* value for a keyword and ignores the rest; `sysctl` applies
//! them in order so the *last* one wins. A tool that appends its setting to the
//! end of the file is therefore correct for one and silently wrong for the
//! other. So a write here replaces the first active definition and comments out
//! every later one, leaving exactly one - after which both rules agree, and the
//! file says what it looks like it says.
//!
//! **A file with two active definitions is already broken**, whichever way the
//! parser resolves it. [`read`] reports every active value rather than picking
//! one, so a duplicate reads as non-compliant and gets cleaned up instead of
//! being silently tolerated.

use pinnacle_core::remediation;
use std::path::Path;

/// How a file separates a keyword from its value.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Style {
    /// `PermitRootLogin no` - sshd_config, login.defs, common-*.
    Space,
    /// `net.ipv4.ip_forward = 0` - sysctl.conf, limits.conf.
    Equals,
    /// `APT::Periodic::Update-Package-Lists "1";` - the apt configuration
    /// directory.
    ///
    /// Its own style because the value is quoted and the line ends in a
    /// semicolon, and apt rejects the file outright if either is missing -
    /// which disables *all* automatic updating rather than just the setting
    /// being written.
    AptConf,
}

impl Style {
    /// How this style writes a new definition.
    fn format(self, key: &str, value: &str) -> String {
        match self {
            Style::Space => format!("{key} {value}"),
            Style::Equals => format!("{key} = {value}"),
            Style::AptConf => format!("{key} \"{value}\";"),
        }
    }

    /// Split a line into its keyword and value, or `None` if it is a comment,
    /// blank, or not a definition at all.
    fn split(self, line: &str) -> Option<(&str, &str)> {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') || line.starts_with(';') {
            return None;
        }
        match self {
            Style::Space => {
                let mut parts = line.splitn(2, char::is_whitespace);
                let key = parts.next()?;
                Some((key, parts.next().unwrap_or("").trim()))
            }
            Style::Equals => {
                let (key, value) = line.split_once('=')?;
                Some((key.trim(), value.trim()))
            }
            Style::AptConf => {
                let mut parts = line.splitn(2, char::is_whitespace);
                let key = parts.next()?;
                // Compared against the bare value, so the quoting and the
                // trailing semicolon are stripped here rather than at every
                // call site.
                let value = parts
                    .next()
                    .unwrap_or("")
                    .trim()
                    .trim_end_matches(';')
                    .trim()
                    .trim_matches('"');
                Some((key, value))
            }
        }
    }
}

/// The active values of `key` in `text`, in the order they appear.
///
/// "Active" means not commented out. More than one is a misconfiguration
/// whichever parser reads the file, which is why they are all returned.
pub fn active_values(text: &str, style: Style, key: &str) -> Vec<String> {
    text.lines()
        .filter_map(|line| style.split(line))
        .filter(|(k, _)| k.eq_ignore_ascii_case(key))
        .map(|(_, v)| v.to_string())
        .collect()
}

/// The state of `key` in `path`, as text, for the remediation ledger.
///
/// - `Some("no")` - one active definition.
/// - `Some("absent")` - the file exists and does not define it. Absence is a
///   readable state and must be spelled as one: returning `None` here would
///   make a failed read indistinguishable from a setting that is genuinely not
///   there, and a later removal would be recorded as having worked.
/// - `Some("no, yes (2 active definitions)")` - a duplicate, reported rather
///   than resolved.
/// - `None` - the file could not be read at all.
pub async fn read(path: &str, style: Style, key: &str) -> Option<String> {
    let text = tokio::fs::read_to_string(path).await.ok()?;
    let values = active_values(&text, style, key);
    Some(match values.len() {
        0 => "absent".to_string(),
        1 => values[0].clone(),
        n => format!("{} ({n} active definitions)", values.join(", ")),
    })
}

/// Set `key` to `value` in `path`, and prove it.
///
/// `why` is what the setting is for, in words - it lands in the run log next to
/// the path, so a reader does not have to know what `fs.protected_hardlinks`
/// means.
pub async fn set(
    path: &str,
    style: Style,
    key: &str,
    value: &str,
    why: &str,
) -> Result<(), String> {
    remediation::apply(
        &format!("{path}:{key}"),
        &format!("{key} = {value} ({why})"),
        || async { read(path, style, key).await },
        |state| state == value,
        &format!("set {}", style.format(key, value)),
        || write(path, style, key, value),
    )
    .await
}

async fn write(path: &str, style: Style, key: &str, value: &str) -> Result<(), String> {
    let original = match tokio::fs::read_to_string(path).await {
        Ok(text) => text,
        // A missing file is not a failure: sysctl and sshd both read whole
        // drop-in directories, and creating the drop-in is the normal way to
        // add a setting.
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => String::new(),
        Err(e) => return Err(format!("could not read {path}: {e}")),
    };

    let updated = rewrite(&original, style, key, value);
    if updated == original {
        return Ok(());
    }

    back_up(path, &original).await?;
    write_atomically(path, &updated).await
}

/// Produce the new file contents. Separated from the I/O so the rules about
/// duplicates and comments can be tested without touching a filesystem.
pub fn rewrite(original: &str, style: Style, key: &str, value: &str) -> String {
    let wanted = style.format(key, value);
    let mut out: Vec<String> = Vec::with_capacity(original.lines().count() + 1);
    let mut written = false;

    for line in original.lines() {
        match style.split(line) {
            Some((k, _)) if k.eq_ignore_ascii_case(key) => {
                if written {
                    // A later definition of a key we have already set. Commented
                    // out rather than deleted: the original value stays visible
                    // to whoever reads the file afterwards, and the note says
                    // who changed it and why it is inactive.
                    out.push(format!("# {line}    # superseded by PinnacleCyPat"));
                } else {
                    // Preserve the original indentation, which some files use
                    // for continuation blocks.
                    let indent: String = line.chars().take_while(|c| c.is_whitespace()).collect();
                    out.push(format!("{indent}{wanted}"));
                    written = true;
                }
            }
            _ => out.push(line.to_string()),
        }
    }

    if !written {
        if !out.is_empty() && !out.last().is_some_and(|l| l.trim().is_empty()) {
            out.push(String::new());
        }
        out.push("# set by PinnacleCyPat".to_string());
        out.push(wanted);
    }

    let mut text = out.join("\n");
    // Keep the trailing newline. Its absence breaks `cat`-style includes and
    // makes the next appended line join onto the last one.
    text.push('\n');
    text
}

/// Comment out every line matching `should_remove`, and prove it.
///
/// Used by the audits that take entries *out* of a file - unauthorised hosts
/// entries, a share definition - where there is no key to set. Commenting
/// rather than deleting keeps what was there visible, which matters when the
/// removal turns out to have been wrong.
pub async fn comment_out(
    path: &str,
    target: &str,
    intent: &str,
    should_remove: impl Fn(&str) -> bool + Copy,
) -> Result<usize, String> {
    let Ok(original) = tokio::fs::read_to_string(path).await else {
        return Err(format!("could not read {path}"));
    };
    let doomed: Vec<&str> = original
        .lines()
        .filter(|l| is_active(l) && should_remove(l))
        .collect();
    if doomed.is_empty() {
        return Ok(0);
    }
    let count = doomed.len();

    remediation::apply(
        target,
        intent,
        || async {
            let text = tokio::fs::read_to_string(path).await.ok()?;
            let live = text
                .lines()
                .filter(|l| is_active(l) && should_remove(l))
                .count();
            Some(match live {
                0 => "no matching entries".to_string(),
                n => format!("{n} matching entries"),
            })
        },
        |state| state == "no matching entries",
        &format!("commented out {count} entries"),
        || async {
            let updated: Vec<String> = original
                .lines()
                .map(|line| {
                    if is_active(line) && should_remove(line) {
                        format!("# {line}    # removed by PinnacleCyPat")
                    } else {
                        line.to_string()
                    }
                })
                .collect();
            back_up(path, &original).await?;
            write_atomically(path, &(updated.join("\n") + "\n")).await
        },
    )
    .await?;

    Ok(count)
}

/// Is this line something the parser will act on, rather than a comment or a
/// blank?
pub fn is_active(line: &str) -> bool {
    let t = line.trim();
    !t.is_empty() && !t.starts_with('#') && !t.starts_with(';')
}

/// Keep a copy of the file as it was before the first change of this run.
///
/// Written once - if a backup is already there, an earlier task in the same run
/// made it, and overwriting it would replace the pristine copy with a
/// half-modified one.
async fn back_up(path: &str, original: &str) -> Result<(), String> {
    let backup = format!("{path}.pinnacle.bak");
    if Path::new(&backup).exists() {
        return Ok(());
    }
    tokio::fs::write(&backup, original)
        .await
        .map_err(|e| format!("could not write the backup {backup}: {e}"))
}

/// Replace a file's contents without ever leaving it truncated.
///
/// Written to a temporary file in the same directory and renamed over the
/// original, so a crash or a full disk part-way through leaves the old file
/// intact. The naive `write` leaves a zero-length `/etc/shadow` or
/// `sshd_config`, which locks the machine out of the thing being hardened -
/// exactly the failure a competitor cannot recover from mid-round.
async fn write_atomically(path: &str, contents: &str) -> Result<(), String> {
    let temp = format!("{path}.pinnacle.tmp");

    // Take the original's mode before replacing it: a fresh file would be
    // created 0644, and `/etc/shadow` at 0644 is a far worse problem than the
    // one being fixed.
    let mode = file_mode(path).await;

    tokio::fs::write(&temp, contents)
        .await
        .map_err(|e| format!("could not write {temp}: {e}"))?;

    if let Some(mode) = mode
        && let Err(e) = set_file_mode(&temp, mode).await
    {
        let _ = tokio::fs::remove_file(&temp).await;
        return Err(format!("could not preserve the mode of {path}: {e}"));
    }

    tokio::fs::rename(&temp, path)
        .await
        .map_err(|e| format!("could not replace {path}: {e}"))
}

#[cfg(unix)]
async fn file_mode(path: &str) -> Option<u32> {
    use std::os::unix::fs::PermissionsExt;
    let meta = tokio::fs::metadata(path).await.ok()?;
    Some(meta.permissions().mode())
}

#[cfg(unix)]
async fn set_file_mode(path: &str, mode: u32) -> std::io::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    tokio::fs::set_permissions(path, std::fs::Permissions::from_mode(mode)).await
}

#[cfg(not(unix))]
async fn file_mode(_path: &str) -> Option<u32> {
    None
}

#[cfg(not(unix))]
async fn set_file_mode(_path: &str, _mode: u32) -> std::io::Result<()> {
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_space_separated_setting_is_replaced_in_place() {
        let out = rewrite(
            "PermitRootLogin yes\nPort 22\n",
            Style::Space,
            "PermitRootLogin",
            "no",
        );
        assert_eq!(out, "PermitRootLogin no\nPort 22\n");
    }

    #[test]
    fn an_equals_separated_setting_keeps_its_spelling() {
        let out = rewrite(
            "net.ipv4.ip_forward = 1\n",
            Style::Equals,
            "net.ipv4.ip_forward",
            "0",
        );
        assert_eq!(out, "net.ipv4.ip_forward = 0\n");
    }

    /// The case that makes appending wrong: `sshd` obeys the first definition,
    /// so a second one added at the end would have no effect at all, while
    /// `sysctl` obeys the last, so replacing only the first would have no
    /// effect there. Leaving exactly one active definition is correct for both.
    #[test]
    fn later_definitions_are_commented_out_so_only_one_remains() {
        let out = rewrite(
            "PermitRootLogin yes\nPort 22\nPermitRootLogin prohibit-password\n",
            Style::Space,
            "PermitRootLogin",
            "no",
        );
        assert_eq!(active_values(&out, Style::Space, "PermitRootLogin"), ["no"]);
        assert!(
            out.contains("# PermitRootLogin prohibit-password"),
            "the superseded value should stay visible: {out}"
        );
    }

    #[test]
    fn a_missing_setting_is_appended_with_a_note() {
        let out = rewrite("Port 22\n", Style::Space, "PermitRootLogin", "no");
        assert!(out.starts_with("Port 22\n"));
        assert!(out.contains("# set by PinnacleCyPat"));
        assert_eq!(active_values(&out, Style::Space, "PermitRootLogin"), ["no"]);
    }

    #[test]
    fn an_empty_file_gains_the_setting() {
        let out = rewrite("", Style::Equals, "kernel.dmesg_restrict", "1");
        assert_eq!(
            active_values(&out, Style::Equals, "kernel.dmesg_restrict"),
            ["1"]
        );
        assert!(out.ends_with('\n'));
    }

    /// A commented-out setting is not a setting. Treating `#PermitRootLogin yes`
    /// as active would report the stock Debian sshd_config - which comments out
    /// every default - as already compliant, and change nothing.
    #[test]
    fn commented_lines_are_not_definitions() {
        let text = "#PermitRootLogin yes\n#  PermitRootLogin yes\n";
        assert!(active_values(text, Style::Space, "PermitRootLogin").is_empty());
        let out = rewrite(text, Style::Space, "PermitRootLogin", "no");
        assert_eq!(active_values(&out, Style::Space, "PermitRootLogin"), ["no"]);
        assert!(
            out.contains("#PermitRootLogin yes"),
            "the original stays: {out}"
        );
    }

    #[test]
    fn keywords_are_matched_without_regard_to_case() {
        // sshd_config keywords are case-insensitive, and real files are
        // inconsistent about it.
        assert_eq!(
            active_values("permitrootlogin yes\n", Style::Space, "PermitRootLogin"),
            ["yes"]
        );
    }

    #[test]
    fn a_login_defs_style_tab_separated_value_is_read() {
        assert_eq!(
            active_values("PASS_MAX_DAYS\t99999\n", Style::Space, "PASS_MAX_DAYS"),
            ["99999"]
        );
    }

    #[test]
    fn rewriting_always_ends_with_a_newline() {
        for original in ["", "Port 22", "Port 22\n"] {
            let out = rewrite(original, Style::Space, "X", "1");
            assert!(out.ends_with('\n'), "no trailing newline for {original:?}");
            assert!(
                !out.ends_with("\n\n\n"),
                "runaway blank lines for {original:?}"
            );
        }
    }

    /// apt rejects a configuration file whose value is unquoted or whose line
    /// has no semicolon, and a rejected file disables *all* automatic updating
    /// rather than just the setting being written.
    #[test]
    fn apt_conf_values_keep_their_quotes_and_semicolon() {
        let out = rewrite(
            "",
            Style::AptConf,
            "APT::Periodic::Update-Package-Lists",
            "1",
        );
        assert!(
            out.contains(r#"APT::Periodic::Update-Package-Lists "1";"#),
            "{out}"
        );
    }

    /// Reading strips them again, so the comparison is against the bare value.
    #[test]
    fn an_apt_conf_value_reads_back_without_its_punctuation() {
        let text = "APT::Periodic::Update-Package-Lists \"1\";\nAPT::Periodic::Unattended-Upgrade \"0\";\n";
        assert_eq!(
            active_values(text, Style::AptConf, "APT::Periodic::Update-Package-Lists"),
            ["1"]
        );
        assert_eq!(
            active_values(text, Style::AptConf, "APT::Periodic::Unattended-Upgrade"),
            ["0"]
        );
    }

    #[test]
    fn an_existing_apt_conf_value_is_replaced_not_appended() {
        let out = rewrite(
            "APT::Periodic::Update-Package-Lists \"0\";\n",
            Style::AptConf,
            "APT::Periodic::Update-Package-Lists",
            "1",
        );
        assert_eq!(
            active_values(&out, Style::AptConf, "APT::Periodic::Update-Package-Lists"),
            ["1"]
        );
    }

    #[test]
    fn an_active_line_is_anything_that_is_not_a_comment_or_blank() {
        assert!(is_active("127.0.0.1 localhost"));
        assert!(!is_active("# 127.0.0.1 localhost"));
        assert!(!is_active("   "));
        assert!(!is_active("; windows-style comment"));
    }
}
