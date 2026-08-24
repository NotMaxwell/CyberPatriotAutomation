// =============================================================================
// PinnacleCyPat - Shared folders audit (Linux)
// Author: Maxwell McCormick
// Copyright 2026 Maxwell McCormick
// SPDX-License-Identifier: Apache-2.0
// =============================================================================

//! Reports Samba shares and NFS exports.
//!
//! The Linux counterpart of the Windows share audit, and a harder problem: on
//! Windows the default shares are a fixed list of three and anything else is a
//! finding. On Linux there is no default at all - a stock image exports
//! nothing - so *every* share is something somebody configured, and the
//! question is whether they meant to.
//!
//! Two files, because the two protocols share nothing:
//!
//! - `/etc/samba/smb.conf` - `[section]` blocks, one per share, with `[global]`
//!   being configuration rather than a share.
//! - `/etc/exports` - one line per exported path, with the options in
//!   parentheses after each client.
//!
//! **Everything is reported; nothing is removed.** A share may be exactly what
//! the round requires - a README naming Samba as a critical service means the
//! machine is a file server - and deleting the export would lose more than the
//! finding is worth. What the task is for is making sure both files get read,
//! which is the step that gets skipped.
//!
//! The options are graded, because they are where the real finding usually is.
//! An export with `no_root_squash` lets a client's root write as root on this
//! machine, and a Samba share with `guest ok = yes` needs no credential at all.

use pinnacle_core::models::{SystemInfo, TaskResult};
use pinnacle_core::task::Task;
use pinnacle_core::{impl_task_meta, remediation, ui};

use crate::{file_ops, systemd_ops};
use async_trait::async_trait;

const SMB_CONF: &str = "/etc/samba/smb.conf";
const EXPORTS: &str = "/etc/exports";

/// Samba settings that remove authentication, and what each means.
const UNSAFE_SMB: &[(&str, &str)] = &[
    (
        "guest ok = yes",
        "anyone on the network can read it with no credential",
    ),
    ("public = yes", "the older spelling of guest ok"),
    (
        "writable = yes",
        "and writable, so anyone can also change it",
    ),
    (
        "writeable = yes",
        "and writable, so anyone can also change it",
    ),
    ("read only = no", "the other spelling of writable"),
    (
        "guest only = yes",
        "forces every connection to be anonymous",
    ),
    (
        "map to guest = bad user",
        "a wrong username silently becomes the guest account",
    ),
    (
        "null passwords = yes",
        "an account with no password can connect",
    ),
    (
        "security = share",
        "share-level security has no user authentication at all",
    ),
];

/// NFS export options that remove protection, and what each means.
const UNSAFE_NFS: &[(&str, &str)] = &[
    ("no_root_squash", "a client's root writes as root here"),
    (
        "insecure",
        "accepts connections from unprivileged client ports",
    ),
    ("rw", "exported writable"),
    ("no_all_squash", "client uids are trusted as they arrive"),
    (
        "no_subtree_check",
        "not a hole on its own, but it is paired with the ones that are",
    ),
];

pub struct SharedFoldersAuditTask {
    name: String,
    description: String,
    dry_run: bool,
}

impl SharedFoldersAuditTask {
    pub fn new() -> Self {
        Self {
            name: "Shared Folders Audit".to_string(),
            description: "Report Samba shares and NFS exports".to_string(),
            dry_run: false,
        }
    }
}

impl Default for SharedFoldersAuditTask {
    fn default() -> Self {
        Self::new()
    }
}

/// One share, and what is wrong with it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Share {
    /// The share name, or the exported path for NFS.
    pub name: String,
    /// The path it serves, when the file says.
    pub path: Option<String>,
    /// The reasons this share is worth looking at, in the file's own words.
    pub concerns: Vec<String>,
}

/// Read the share definitions out of `smb.conf`.
///
/// `[global]` is configuration, not a share, and reporting it as one would put
/// a finding on every Samba installation that exists. Its *settings* still
/// count, though: `map to guest = bad user` in `[global]` applies to every
/// share below it, so global concerns are carried down.
pub fn parse_smb_conf(text: &str) -> Vec<Share> {
    let mut shares: Vec<Share> = Vec::new();
    let mut global_concerns: Vec<String> = Vec::new();
    let mut current: Option<Share> = None;

    for line in text.lines() {
        let trimmed = line.trim();
        if !file_ops::is_active(trimmed) {
            continue;
        }

        if let Some(name) = trimmed
            .strip_prefix('[')
            .and_then(|rest| rest.strip_suffix(']'))
        {
            if let Some(share) = current.take() {
                shares.push(share);
            }
            if name.eq_ignore_ascii_case("global") {
                current = None;
            } else {
                current = Some(Share {
                    name: name.to_string(),
                    path: None,
                    concerns: Vec::new(),
                });
            }
            continue;
        }

        // Settings are `key = value` with arbitrary spacing around the equals
        // sign, and Samba ignores case and internal spaces in the key.
        let normalised = normalise_smb_setting(trimmed);
        let concerns: Vec<String> = UNSAFE_SMB
            .iter()
            .filter(|(setting, _)| normalised == *setting)
            .map(|(setting, why)| format!("{setting} - {why}"))
            .collect();

        match &mut current {
            Some(share) => {
                if let Some(path) = normalised.strip_prefix("path = ") {
                    share.path = Some(path.to_string());
                }
                share.concerns.extend(concerns);
            }
            None => global_concerns.extend(concerns),
        }
    }
    if let Some(share) = current.take() {
        shares.push(share);
    }

    // A global setting applies to every share, so it is a concern about each.
    for share in &mut shares {
        for concern in &global_concerns {
            share.concerns.push(format!("[global] {concern}"));
        }
    }
    shares
}

/// Normalise a Samba setting for comparison.
///
/// Samba treats `guest ok=yes`, `Guest OK = Yes` and `guest   ok  =  yes` as
/// the same thing, so a literal string comparison would miss most real files.
fn normalise_smb_setting(line: &str) -> String {
    let Some((key, value)) = line.split_once('=') else {
        return line.to_lowercase();
    };
    format!(
        "{} = {}",
        key.split_whitespace()
            .collect::<Vec<_>>()
            .join(" ")
            .to_lowercase(),
        value.trim().to_lowercase()
    )
}

/// Read the exports out of `/etc/exports`.
///
/// The format is `path client(options) client(options)`, where the path may be
/// quoted if it contains spaces.
pub fn parse_exports(text: &str) -> Vec<Share> {
    text.lines()
        .filter(|l| file_ops::is_active(l))
        .filter_map(|line| {
            let line = line.trim();
            let (path, rest) = if let Some(quoted) = line.strip_prefix('"') {
                quoted.split_once('"')?
            } else {
                line.split_once(char::is_whitespace)?
            };

            let lower = rest.to_lowercase();
            let mut concerns: Vec<String> = UNSAFE_NFS
                .iter()
                // Matched as a whole option between delimiters, so `rw` does
                // not also match inside `no_root_squash`... and, more to the
                // point, so `ro` does not match inside `no_root_squash`.
                .filter(|(option, _)| {
                    lower
                        .split(|c: char| !c.is_alphanumeric() && c != '_')
                        .any(|token| token == *option)
                })
                .map(|(option, why)| format!("{option} - {why}"))
                .collect();

            // An export with no client restriction reaches the whole network.
            if rest.trim_start().starts_with('*') || rest.contains(" *(") {
                concerns.push("* - exported to every host that can reach this machine".to_string());
            }

            Some(Share {
                name: path.to_string(),
                path: Some(path.to_string()),
                concerns,
            })
        })
        .collect()
}

async fn read(path: &str) -> Option<String> {
    tokio::fs::read_to_string(path).await.ok()
}

#[async_trait]
impl Task for SharedFoldersAuditTask {
    impl_task_meta!();

    async fn read_system_state(&mut self) -> SystemInfo {
        let smb = read(SMB_CONF)
            .await
            .map(|t| parse_smb_conf(&t).len())
            .unwrap_or(0);
        let nfs = read(EXPORTS)
            .await
            .map(|t| parse_exports(&t).len())
            .unwrap_or(0);
        SystemInfo {
            raw_output: Some(format!("{smb} Samba shares, {nfs} NFS exports")),
            ..Default::default()
        }
    }

    async fn execute(&mut self) -> TaskResult {
        let mut result = TaskResult {
            task_name: self.name.clone(),
            success: true,
            ..Default::default()
        };

        let smb = read(SMB_CONF)
            .await
            .map(|t| parse_smb_conf(&t))
            .unwrap_or_default();
        let nfs = read(EXPORTS)
            .await
            .map(|t| parse_exports(&t))
            .unwrap_or_default();
        result.items_attempted = (smb.len() + nfs.len()) as i32;

        report("Samba share", SMB_CONF, &smb);
        report("NFS export", EXPORTS, &nfs);

        // A share definition nothing serves is inert. Saying so keeps a stale
        // smb.conf on a machine with Samba masked from reading as a live
        // finding - and the reverse, a running daemon with no shares, is worth
        // knowing too.
        for (unit, file) in [("smbd.service", SMB_CONF), ("nfs-server.service", EXPORTS)] {
            if systemd_ops::is_active(unit).await {
                ui::markup_line(&format!(
                    "[yellow]⚠ {} is running, so {} is live.[/]",
                    ui::escape(unit),
                    ui::escape(file)
                ));
            }
        }

        let total = smb.len() + nfs.len();
        let risky = smb
            .iter()
            .chain(nfs.iter())
            .filter(|s| !s.concerns.is_empty())
            .count();
        result.message = if total == 0 {
            "No Samba shares or NFS exports.".to_string()
        } else {
            format!(
                "{total} shares found, {risky} with options worth reviewing. \
                 Nothing was removed - a share may be what the round requires."
            )
        };
        result
    }

    async fn verify(&mut self) -> bool {
        // An audit that changes nothing has nothing to verify. Returning false
        // because findings exist would report the task as failed for having
        // done its job.
        true
    }
}

/// Print and record the shares from one file.
fn report(kind: &str, file: &str, shares: &[Share]) {
    if shares.is_empty() {
        remediation::record_finding(
            file,
            &format!("no {kind}s beyond what the round requires"),
            true,
            "the file is absent or defines nothing",
        );
        return;
    }

    for share in shares {
        let where_to = share.path.as_deref().unwrap_or("(no path given)");
        if share.concerns.is_empty() {
            ui::markup_line(&format!(
                "[cyan]{}: {} [dim]-> {}[/][/]",
                ui::escape(kind),
                ui::escape(&share.name),
                ui::escape(where_to)
            ));
        } else {
            ui::markup_line(&format!(
                "[yellow]⚠ {}: {} [dim]-> {}[/][/]",
                ui::escape(kind),
                ui::escape(&share.name),
                ui::escape(where_to)
            ));
            for concern in &share.concerns {
                ui::markup_line(&format!("    [yellow]{}[/]", ui::escape(concern)));
            }
        }

        remediation::record_finding(
            &format!("{kind} {}", share.name),
            "serves only what the round requires, to only who needs it",
            share.concerns.is_empty(),
            &if share.concerns.is_empty() {
                format!("serves {where_to}; no unsafe options")
            } else {
                format!("serves {where_to}; {}", share.concerns.join("; "))
            },
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A real `smb.conf`, including the `[global]` block a stock installation
    /// always has.
    const SMB: &str = "\
[global]
   workgroup = WORKGROUP
   server string = %h server
   map to guest = bad user

[printers]
   comment = All Printers
   path = /var/spool/samba
   guest ok = no
   browseable = no

[public]
   comment = Public Stuff
   path = /home/samba/public
   guest ok = yes
   writable = yes
";

    #[test]
    fn global_is_configuration_rather_than_a_share() {
        let shares = parse_smb_conf(SMB);
        assert_eq!(
            shares.iter().map(|s| s.name.as_str()).collect::<Vec<_>>(),
            ["printers", "public"],
            "[global] should not be reported as a share"
        );
    }

    #[test]
    fn a_guest_writable_share_is_flagged_and_a_locked_one_is_not() {
        let shares = parse_smb_conf(SMB);
        let public = shares.iter().find(|s| s.name == "public").unwrap();
        assert_eq!(public.path.as_deref(), Some("/home/samba/public"));
        assert!(
            public
                .concerns
                .iter()
                .any(|c| c.starts_with("guest ok = yes")),
            "{:?}",
            public.concerns
        );
        assert!(
            public
                .concerns
                .iter()
                .any(|c| c.starts_with("writable = yes"))
        );
    }

    /// A setting in `[global]` applies to every share below it, so it has to be
    /// carried down or it is invisible on the share it actually affects.
    #[test]
    fn a_global_setting_is_reported_against_every_share() {
        let shares = parse_smb_conf(SMB);
        for share in &shares {
            assert!(
                share
                    .concerns
                    .iter()
                    .any(|c| c.contains("[global] map to guest")),
                "{} did not inherit the global concern: {:?}",
                share.name,
                share.concerns
            );
        }
    }

    /// Samba ignores case and internal spacing in a setting name, so a literal
    /// comparison would miss most real files.
    #[test]
    fn settings_are_matched_however_they_are_spaced_and_cased() {
        for spelling in ["guest ok = yes", "Guest OK=Yes", "guest   ok   =   YES"] {
            let shares = parse_smb_conf(&format!("[s]\n  path = /x\n  {spelling}\n"));
            assert!(
                !shares[0].concerns.is_empty(),
                "{spelling:?} was not recognised"
            );
        }
    }

    #[test]
    fn commented_settings_are_not_in_effect() {
        let shares = parse_smb_conf("[s]\n  path = /x\n; guest ok = yes\n# writable = yes\n");
        assert!(shares[0].concerns.is_empty(), "{:?}", shares[0].concerns);
    }

    /// The worst NFS option there is: a client's root becomes root here.
    #[test]
    fn no_root_squash_is_flagged() {
        let exports = parse_exports("/srv/nfs 192.168.1.0/24(rw,sync,no_root_squash)\n");
        assert_eq!(exports.len(), 1);
        assert_eq!(exports[0].name, "/srv/nfs");
        assert!(
            exports[0]
                .concerns
                .iter()
                .any(|c| c.starts_with("no_root_squash")),
            "{:?}",
            exports[0].concerns
        );
    }

    /// The reason options are matched between delimiters: `ro` appears inside
    /// `no_root_squash`, and a substring match would report a read-only export
    /// as writable.
    #[test]
    fn an_option_is_not_matched_inside_another_one() {
        let exports = parse_exports("/srv 10.0.0.0/8(ro,sync,root_squash)\n");
        assert!(
            !exports[0].concerns.iter().any(|c| c.starts_with("rw ")),
            "a read-only export was reported as writable: {:?}",
            exports[0].concerns
        );
    }

    #[test]
    fn an_export_to_every_host_is_flagged() {
        let exports = parse_exports("/srv *(ro,sync)\n");
        assert!(
            exports[0].concerns.iter().any(|c| c.contains("every host")),
            "{:?}",
            exports[0].concerns
        );
    }

    #[test]
    fn a_quoted_path_with_spaces_is_read() {
        let exports = parse_exports("\"/srv/my share\" 10.0.0.1(ro)\n");
        assert_eq!(exports[0].name, "/srv/my share");
    }

    #[test]
    fn absent_files_yield_nothing_rather_than_an_error() {
        assert!(parse_smb_conf("").is_empty());
        assert!(parse_exports("").is_empty());
        assert!(parse_exports("# only a comment\n").is_empty());
    }
}
