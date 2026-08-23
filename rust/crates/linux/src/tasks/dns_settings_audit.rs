// =============================================================================
// PinnacleCyPat - DNS settings audit (Linux)
// Copyright 2026 Maxwell McCormick
// SPDX-License-Identifier: Apache-2.0
// =============================================================================

//! Reports the resolvers the machine is using.
//!
//! A resolver pointed at a host an attacker controls redirects every name
//! lookup without touching a single file the competitor thinks to check - and
//! unlike a planted `/etc/hosts` entry, it leaves no list of the domains it
//! affects.
//!
//! Reported rather than changed. What the *correct* resolver is depends
//! entirely on the network the image is on: rewriting it to a public resolver
//! would break an image whose scenario is a corporate network with an internal
//! DNS server, and the round scores that machine resolving internal names.
//!
//! Both mechanisms are read. `/etc/resolv.conf` is what libc uses, but on a
//! systemd-resolved image it is a symlink to a stub that always says
//! `127.0.0.53` - so reading only that file reports the stub on every modern
//! Ubuntu and never sees the real upstream.

use pinnacle_core::models::{SystemInfo, TaskResult};
use pinnacle_core::task::Task;
use pinnacle_core::{command, impl_task_meta, remediation, ui};

use crate::file_ops;
use async_trait::async_trait;

/// Public resolvers. Not wrong in themselves - but on an image whose scenario
/// describes a corporate network, one of these means someone changed it.
const PUBLIC_RESOLVERS: &[(&str, &str)] = &[
    ("8.8.8.8", "Google"),
    ("8.8.4.4", "Google"),
    ("1.1.1.1", "Cloudflare"),
    ("1.0.0.1", "Cloudflare"),
    ("9.9.9.9", "Quad9"),
    ("208.67.222.222", "OpenDNS"),
    ("208.67.220.220", "OpenDNS"),
    ("4.2.2.1", "Level3"),
    ("4.2.2.2", "Level3"),
];

/// The systemd-resolved stub. Seeing this in `resolv.conf` means the real
/// resolvers are behind `resolvectl`, not in the file.
const STUB_RESOLVER: &str = "127.0.0.53";

pub struct DnsSettingsAuditTask {
    name: String,
    description: String,
    dry_run: bool,
}

impl DnsSettingsAuditTask {
    pub fn new() -> Self {
        Self {
            name: "DNS Settings Audit".to_string(),
            description: "Report the resolvers in use".to_string(),
            dry_run: false,
        }
    }
}

impl Default for DnsSettingsAuditTask {
    fn default() -> Self {
        Self::new()
    }
}

/// The `nameserver` entries in `resolv.conf` content.
pub fn nameservers(resolv_conf: &str) -> Vec<String> {
    resolv_conf
        .lines()
        .filter(|l| file_ops::is_active(l))
        .filter_map(|l| {
            l.split_whitespace()
                .collect::<Vec<_>>()
                .split_first()
                .map(|(k, rest)| (k.to_string(), rest.first().map(|s| s.to_string())))
        })
        .filter(|(key, _)| key == "nameserver")
        .filter_map(|(_, value)| value)
        .collect()
}

/// The addresses `resolvectl status` reports as current DNS servers.
///
/// Parsed from the `DNS Servers:` and `Current DNS Server:` lines, which may
/// list several addresses on one line and repeat per interface.
pub fn resolvectl_servers(output: &str) -> Vec<String> {
    let mut servers = Vec::new();
    for line in output.lines() {
        let trimmed = line.trim();
        let Some(rest) = trimmed
            .strip_prefix("DNS Servers:")
            .or_else(|| trimmed.strip_prefix("Current DNS Server:"))
        else {
            continue;
        };
        for address in rest.split_whitespace() {
            if !servers.contains(&address.to_string()) {
                servers.push(address.to_string());
            }
        }
    }
    servers
}

/// Which of these are well-known public resolvers?
pub fn public_among(servers: &[String]) -> Vec<(String, &'static str)> {
    servers
        .iter()
        .filter_map(|s| {
            PUBLIC_RESOLVERS
                .iter()
                .find(|(address, _)| address == s)
                .map(|(_, owner)| (s.clone(), *owner))
        })
        .collect()
}

#[async_trait]
impl Task for DnsSettingsAuditTask {
    impl_task_meta!();

    async fn read_system_state(&mut self) -> SystemInfo {
        let text = tokio::fs::read_to_string("/etc/resolv.conf")
            .await
            .unwrap_or_default();
        SystemInfo {
            raw_output: Some(text),
            ..Default::default()
        }
    }

    async fn execute(&mut self) -> TaskResult {
        let mut result = TaskResult {
            task_name: self.name.clone(),
            success: true,
            ..Default::default()
        };

        let resolv = tokio::fs::read_to_string("/etc/resolv.conf")
            .await
            .unwrap_or_default();
        let mut servers = nameservers(&resolv);

        // On a systemd-resolved image resolv.conf is a stub and the real
        // upstreams are only visible through resolvectl. Reading one and not
        // the other reports 127.0.0.53 on every modern Ubuntu.
        if servers.iter().any(|s| s == STUB_RESOLVER) || servers.is_empty() {
            let (_ok, out, _e) = command::execute("resolvectl", Some("status")).await;
            for address in resolvectl_servers(&out) {
                if !servers.contains(&address) && address != STUB_RESOLVER {
                    servers.push(address);
                }
            }
        }

        result.items_attempted = servers.len() as i32;

        if servers.is_empty() {
            ui::markup_line("[yellow]⚠ No DNS resolver could be determined.[/]");
            remediation::record_finding(
                "DNS resolvers",
                "the machine's resolvers are known and expected",
                false,
                "neither /etc/resolv.conf nor resolvectl reported a resolver",
            );
            result.message = "No resolver could be determined.".to_string();
            return result;
        }

        for server in &servers {
            ui::markup_line(&format!("[cyan]Resolver: {}[/]", ui::escape(server)));
        }

        let public = public_among(&servers);
        for (address, owner) in &public {
            ui::markup_line(&format!(
                "[yellow]⚠ {address} is {owner}'s public resolver. On a corporate-network \
                 scenario this is a change someone made.[/]"
            ));
        }

        remediation::record_finding(
            "DNS resolvers",
            "the machine's resolvers are known and expected",
            public.is_empty(),
            &format!(
                "resolvers in use: {}{}",
                servers.join(", "),
                if public.is_empty() {
                    String::new()
                } else {
                    format!(
                        "; {} of them public ({})",
                        public.len(),
                        public
                            .iter()
                            .map(|(a, o)| format!("{a} = {o}"))
                            .collect::<Vec<_>>()
                            .join(", ")
                    )
                }
            ),
        );

        result.message = format!(
            "{} resolvers in use, {} of them public. Nothing was changed - the correct \
             resolver depends on the network the image is on.",
            servers.len(),
            public.len()
        );
        result
    }

    async fn verify(&mut self) -> bool {
        // An audit that changes nothing has nothing to verify.
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn nameserver_entries_are_read_from_resolv_conf() {
        let text = "\
# Generated by NetworkManager
nameserver 192.168.1.1
nameserver 8.8.8.8
search example.com
options edns0
";
        assert_eq!(nameservers(text), ["192.168.1.1", "8.8.8.8"]);
    }

    #[test]
    fn commented_nameservers_are_not_in_use() {
        assert!(nameservers("# nameserver 8.8.8.8\n").is_empty());
        assert!(nameservers("").is_empty());
    }

    /// Real `resolvectl status` output. Reading only resolv.conf on this image
    /// would report the 127.0.0.53 stub and miss the actual upstream.
    #[test]
    fn resolvectl_output_yields_the_real_upstreams() {
        let output = "\
Global
       Protocols: -LLMNR -mDNS

Link 2 (enp0s3)
    Current Scopes: DNS
         Protocols: +DefaultRoute
Current DNS Server: 192.168.1.1
       DNS Servers: 192.168.1.1 8.8.8.8
";
        assert_eq!(resolvectl_servers(output), ["192.168.1.1", "8.8.8.8"]);
    }

    #[test]
    fn public_resolvers_are_named_with_their_owner() {
        let servers = vec![
            "192.168.1.1".to_string(),
            "8.8.8.8".to_string(),
            "1.1.1.1".to_string(),
        ];
        let public = public_among(&servers);
        assert_eq!(public.len(), 2);
        assert_eq!(public[0], ("8.8.8.8".to_string(), "Google"));
        assert_eq!(public[1], ("1.1.1.1".to_string(), "Cloudflare"));
    }

    /// An internal resolver is the expected case on a corporate scenario, and
    /// flagging it would invert the finding.
    #[test]
    fn a_private_resolver_is_not_a_finding() {
        assert!(public_among(&["10.0.0.1".to_string()]).is_empty());
    }
}
