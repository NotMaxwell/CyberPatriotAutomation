// =============================================================================
// PinnacleCyPat - Hosts file audit (Linux)
// Author: Maxwell McCormick
// Copyright 2026 Maxwell McCormick
// SPDX-License-Identifier: Apache-2.0
// =============================================================================

//! Removes hosts-file entries that were not there on a clean image.
//!
//! A planted `/etc/hosts` entry is a favourite on competition images because it
//! is invisible from every tool that looks at the network: pointing
//! `security.ubuntu.com` or an antivirus vendor at `127.0.0.1` stops updates
//! reaching the machine while `ping`, `ip` and `resolvectl` all still look
//! healthy.
//!
//! The Windows version of this task reads the same shape of file from
//! `C:\Windows\System32\drivers\etc\hosts`, and the rules are identical - which
//! is why this was among the first tasks ported. The differences are the path
//! and the set of entries a stock image ships with: Debian and Ubuntu add the
//! machine's own hostname and a block of IPv6 multicast aliases that must not
//! be touched.

use pinnacle_core::models::{SystemInfo, TaskResult};
use pinnacle_core::task::Task;
use pinnacle_core::{impl_task_meta, remediation, ui};

use crate::file_ops;
use async_trait::async_trait;

const HOSTS_FILE_PATH: &str = "/etc/hosts";

/// Entries a clean Debian or Ubuntu image ships with.
///
/// The IPv6 block is written verbatim by the installer and means nothing to a
/// competitor, so it is easy to mistake for something planted. Removing
/// `ff02::1 ip6-allnodes` breaks IPv6 neighbour discovery on the image.
const ALLOWED_HOSTS: &[&str] = &[
    "localhost",
    "localhost.localdomain",
    "ip6-localhost",
    "ip6-loopback",
    "ip6-localnet",
    "ip6-mcastprefix",
    "ip6-allnodes",
    "ip6-allrouters",
    "ip6-allhosts",
];

/// Addresses a stock entry may point at.
///
/// Loopback and the unspecified address, plus the IPv6 link-local and multicast
/// prefixes the Debian installer uses for its `ip6-*` block. Anything else in
/// `/etc/hosts` on a single-machine competition image is a static override of
/// DNS, which is what this task is looking for.
///
/// Checking the address as well as the name matters: a rule written only around
/// the names would accept `1.2.3.4 localhost`, which is a redirect wearing a
/// stock name.
fn is_local_address(address: &str) -> bool {
    let address = address.to_ascii_lowercase();
    address.starts_with("127.")
        || address == "0.0.0.0"
        || address == "::1"
        || address == "::"
        // ff00::/8 multicast and fe00::/9 link-local - the installer's block.
        || address.starts_with("ff0")
        || address.starts_with("fe00:")
}

pub struct HostsFileAuditTask {
    name: String,
    description: String,
    dry_run: bool,
}

impl HostsFileAuditTask {
    pub fn new() -> Self {
        Self {
            name: "Hosts File Audit".to_string(),
            description: "Remove unauthorised /etc/hosts entries".to_string(),
            dry_run: false,
        }
    }
}

impl Default for HostsFileAuditTask {
    fn default() -> Self {
        Self::new()
    }
}

/// Collapse runs of whitespace so entries compare on content, not formatting.
///
/// A hosts file may separate the address from the names with a tab or any
/// number of spaces, and all of them are equivalent. The Windows task compared
/// raw strings and so classified a tab-separated localhost line as
/// unauthorised - and deleted it.
fn fields(line: &str) -> Vec<&str> {
    line.split_whitespace().collect()
}

/// Is this entry one a clean image would have?
///
/// An entry is left alone when it points at a local address *and* every name on
/// it is one the installer writes - the stock aliases, or the machine's own
/// hostname, which the installer maps to `127.0.1.1` and whose removal makes
/// `sudo` stall for a minute on every invocation.
///
/// Both halves are required. Names alone would accept `1.2.3.4 localhost`;
/// addresses alone would accept `127.0.0.1 security.ubuntu.com`, which is the
/// exact entry this task exists to find.
pub fn is_allowed(line: &str, hostname: &str) -> bool {
    let fields = fields(line);
    let Some((address, names)) = fields.split_first() else {
        return true;
    };
    if !is_local_address(address) {
        return false;
    }
    names.iter().all(|name| {
        ALLOWED_HOSTS.iter().any(|a| a.eq_ignore_ascii_case(name))
            || (!hostname.is_empty() && name.eq_ignore_ascii_case(hostname))
    })
}

/// Every active entry that is not one a clean image would have.
pub fn unauthorised_entries(text: &str, hostname: &str) -> Vec<String> {
    text.lines()
        .filter(|l| file_ops::is_active(l))
        .filter(|l| !is_allowed(l, hostname))
        .map(|l| l.trim().to_string())
        .collect()
}

/// The machine's hostname, or an empty string if it cannot be read.
///
/// Read from `/etc/hostname` rather than by calling `hostname`: the file is
/// what the installer wrote into `/etc/hosts`, so it is the value that has to
/// match for the self-reference entry to be recognised.
async fn hostname() -> String {
    tokio::fs::read_to_string("/etc/hostname")
        .await
        .map(|s| s.trim().to_string())
        .unwrap_or_default()
}

#[async_trait]
impl Task for HostsFileAuditTask {
    impl_task_meta!();

    async fn read_system_state(&mut self) -> SystemInfo {
        match tokio::fs::read_to_string(HOSTS_FILE_PATH).await {
            Ok(text) => SystemInfo {
                raw_output: Some(text),
                error_output: None,
                ..Default::default()
            },
            Err(e) => SystemInfo {
                raw_output: Some(String::new()),
                error_output: Some(e.to_string()),
                ..Default::default()
            },
        }
    }

    async fn execute(&mut self) -> TaskResult {
        let mut result = TaskResult {
            task_name: self.name.clone(),
            success: true,
            ..Default::default()
        };

        let hostname = hostname().await;
        let Ok(text) = tokio::fs::read_to_string(HOSTS_FILE_PATH).await else {
            result.success = false;
            result.message = format!("Could not read {HOSTS_FILE_PATH}");
            result.error_details = Some(result.message.clone());
            return result;
        };

        let found = unauthorised_entries(&text, &hostname);
        if found.is_empty() {
            result.items_skipped = 0;
            remediation::record_finding(
                HOSTS_FILE_PATH,
                "no static DNS overrides beyond the installer's own entries",
                true,
                "every active entry maps a local address to a stock name",
            );
            result.message = "No unauthorised hosts entries.".to_string();
            return result;
        }

        for entry in &found {
            ui::markup_line(&format!(
                "[yellow]⚠ Unauthorised hosts entry: {}[/]",
                ui::escape(entry)
            ));
        }

        if self.dry_run {
            result.message = format!(
                "DRY RUN: would comment out {} unauthorised entries.",
                found.len()
            );
            return result;
        }

        match file_ops::comment_out(
            HOSTS_FILE_PATH,
            HOSTS_FILE_PATH,
            "no static DNS overrides beyond the installer's own entries",
            |line| !is_allowed(line, &hostname),
        )
        .await
        {
            Ok(count) => {
                result.items_attempted = found.len() as i32;
                result.items_succeeded = count as i32;
                result.message = format!("Commented out {count} unauthorised entries.");
            }
            Err(e) => {
                result.success = false;
                result.items_attempted = found.len() as i32;
                result.message = format!("Could not update {HOSTS_FILE_PATH}: {e}");
                result.error_details = Some(e);
            }
        }
        result
    }

    async fn verify(&mut self) -> bool {
        // Read the file back rather than trusting the write. This is the whole
        // point of the verify step: `comment_out` returning Ok says the rewrite
        // was accepted, not that the entries are gone.
        let hostname = hostname().await;
        match tokio::fs::read_to_string(HOSTS_FILE_PATH).await {
            Ok(text) => unauthorised_entries(&text, &hostname).is_empty(),
            Err(_) => false,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const STOCK_UBUNTU: &str = "\
127.0.0.1\tlocalhost
127.0.1.1\tcyberpatriot-vm

# The following lines are desirable for IPv6 capable hosts
::1     ip6-localhost ip6-loopback
fe00::0 ip6-localnet
ff00::0 ip6-mcastprefix
ff02::1 ip6-allnodes
ff02::2 ip6-allrouters
";

    /// The failure that matters most: a false positive here deletes the
    /// machine's own hostname mapping, and `sudo` then stalls for a minute on
    /// every invocation while it tries to resolve it.
    #[test]
    fn a_stock_ubuntu_hosts_file_is_left_alone() {
        let found = unauthorised_entries(STOCK_UBUNTU, "cyberpatriot-vm");
        assert!(found.is_empty(), "flagged stock entries: {found:?}");
    }

    #[test]
    fn a_planted_redirect_is_found() {
        let text = format!("{STOCK_UBUNTU}127.0.0.1 security.ubuntu.com\n0.0.0.0 clamav.net\n");
        let found = unauthorised_entries(&text, "cyberpatriot-vm");
        assert_eq!(
            found,
            [
                "127.0.0.1 security.ubuntu.com".to_string(),
                "0.0.0.0 clamav.net".to_string()
            ]
        );
    }

    /// An entry pointing somewhere real is a redirect to an attacker's host,
    /// not a block - and is just as much an override.
    #[test]
    fn an_entry_pointing_off_the_machine_is_unauthorised() {
        let found = unauthorised_entries("10.0.0.5 www.google.com\n", "vm");
        assert_eq!(found, ["10.0.0.5 www.google.com".to_string()]);
    }

    #[test]
    fn commented_and_blank_lines_are_not_entries() {
        let found = unauthorised_entries("\n# 1.2.3.4 evil.example\n   \n", "vm");
        assert!(found.is_empty(), "{found:?}");
    }

    /// Whitespace between the address and the names is arbitrary. Comparing
    /// formatted strings is what made the Windows version delete a legitimate
    /// tab-separated localhost line.
    #[test]
    fn spacing_does_not_decide_whether_an_entry_is_allowed() {
        for line in [
            "127.0.0.1 localhost",
            "127.0.0.1\tlocalhost",
            "127.0.0.1      localhost",
            "  127.0.0.1   localhost  ",
        ] {
            assert!(is_allowed(line, "vm"), "rejected: {line:?}");
        }
    }

    /// The IPv6 aliases point at multicast addresses, not loopback, so a rule
    /// written only around 127.0.0.1 would strip them and break neighbour
    /// discovery. They are recognised by name instead.
    #[test]
    fn the_installers_ipv6_block_survives() {
        for line in [
            "ff02::1 ip6-allnodes",
            "ff02::2 ip6-allrouters",
            "fe00::0 ip6-localnet",
        ] {
            let found = unauthorised_entries(line, "vm");
            assert!(
                found.is_empty(),
                "would have removed the installer's own entry: {line}"
            );
        }
    }
}
