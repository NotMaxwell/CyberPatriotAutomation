// =============================================================================
// PinnacleCyPat - README service-name resolution
// Author: Maxwell McCormick
// Copyright 2026 Maxwell McCormick
// SPDX-License-Identifier: Apache-2.0
// =============================================================================

//! Resolving the service names a README uses to the names the machine uses, and
//! answering "does the README say this service is critical?".
//!
//! This lives in one place because more than one task needs the answer and they
//! must not disagree. Service management protected `TermService` when the README
//! called Remote Desktop critical, while security hardening set
//! `fDenyTSConnections=1` regardless and never looked at the README at all - so
//! the service kept running and every connection to it was refused. That is the
//! worst of both outcomes, and it silently loses a scored item.
//!
//! A README writes display names ("Remote Desktop"), not service names
//! ("TermService" on Windows, "ssh" on Linux), and is inconsistent about which -
//! the same document may say "Remote Desktop Services" in one line and "RDP" in
//! another.
//!
//! The *matching* is the same on every platform; only the table of names
//! differs. So the table is a parameter, and each platform crate wraps these
//! functions with its own - see `pinnacle_windows::readme_services` and
//! `pinnacle_linux::readme_services`.

use crate::models::ReadmeData;

/// Display names a README might use, paired with the real service name.
pub type ServiceAliases = &'static [(&'static str, &'static str)];

/// The real service name for a README's display name, or the name unchanged
/// when it is not one the table knows.
pub fn resolve(aliases: ServiceAliases, display_name: &str) -> String {
    let trimmed = display_name.trim();
    aliases
        .iter()
        .find(|(name, _)| name.eq_ignore_ascii_case(trimmed))
        .map(|(_, service)| service.to_string())
        .unwrap_or_else(|| trimmed.to_string())
}

/// Does the README mark `service_name` as critical?
///
/// Every critical entry is resolved before comparing, so "Remote Desktop", "RDP"
/// and "TermService" all answer the same question. A `None` README means no -
/// nothing has been said either way, so the hardening default applies.
pub fn is_critical(
    aliases: ServiceAliases,
    readme: Option<&ReadmeData>,
    service_name: &str,
) -> bool {
    let Some(readme) = readme else {
        return false;
    };
    let wanted = resolve(aliases, service_name);
    readme
        .critical_services
        .iter()
        .any(|entry| resolve(aliases, entry).eq_ignore_ascii_case(&wanted))
}

#[cfg(test)]
mod tests {
    use super::*;

    const ALIASES: ServiceAliases = &[
        ("Remote Desktop", "TermService"),
        ("RDP", "TermService"),
        ("CCS Client", "CCSClient"),
    ];

    fn readme_with(critical: &[&str]) -> ReadmeData {
        ReadmeData {
            critical_services: critical.iter().map(|s| s.to_string()).collect(),
            ..Default::default()
        }
    }

    #[test]
    fn display_names_resolve_to_service_names() {
        assert_eq!(resolve(ALIASES, "Remote Desktop"), "TermService");
        assert_eq!(resolve(ALIASES, "RDP"), "TermService");
        assert_eq!(resolve(ALIASES, "  remote desktop  "), "TermService");
    }

    #[test]
    fn an_unknown_name_is_left_alone() {
        assert_eq!(resolve(ALIASES, "SomeVendorSvc"), "SomeVendorSvc");
    }

    /// The point of resolving before comparing: the README and the task are
    /// free to spell the same service differently.
    #[test]
    fn a_critical_entry_matches_however_it_is_spelled() {
        let readme = readme_with(&["RDP"]);
        assert!(is_critical(ALIASES, Some(&readme), "TermService"));
        assert!(is_critical(ALIASES, Some(&readme), "Remote Desktop"));
    }

    #[test]
    fn nothing_is_critical_without_a_readme() {
        assert!(!is_critical(ALIASES, None, "TermService"));
    }
}
