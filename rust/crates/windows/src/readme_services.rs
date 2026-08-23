// =============================================================================
// PinnacleCyPat - README service names, Windows
// Copyright 2026 Maxwell McCormick
// SPDX-License-Identifier: Apache-2.0
// =============================================================================

//! [`pinnacle_core::readme_services`] bound to the Windows service-name table.
//!
//! Ask the README questions through here, never by matching strings. Two tasks
//! that parse the same README differently is a bug class this codebase has
//! already had twice.

use crate::knowledge::SERVICE_NAME_MAP;
use pinnacle_core::models::ReadmeData;
use pinnacle_core::readme_services as core;

/// The Windows service name for a README's display name.
pub fn resolve(display_name: &str) -> String {
    core::resolve(SERVICE_NAME_MAP, display_name)
}

/// Does the README mark `service_name` as critical?
pub fn is_critical(readme: Option<&ReadmeData>, service_name: &str) -> bool {
    core::is_critical(SERVICE_NAME_MAP, readme, service_name)
}

/// Does the README require Remote Desktop to keep working?
///
/// Separate from [`is_critical`] because RDP is asked about by two tasks and is
/// the one hardening default a README routinely overrides: an image whose
/// scenario is "this machine is administered remotely" scores RDP being
/// *available*, and denying it loses that point while every other hardening step
/// still applies.
pub fn is_remote_desktop_required(readme: Option<&ReadmeData>) -> bool {
    is_critical(readme, "TermService")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn readme_with(critical: &[&str]) -> ReadmeData {
        ReadmeData {
            critical_services: critical.iter().map(|s| s.to_string()).collect(),
            ..Default::default()
        }
    }

    #[test]
    fn display_names_resolve_to_service_names() {
        assert_eq!(resolve("Remote Desktop"), "TermService");
        assert_eq!(resolve("RDP"), "TermService");
        assert_eq!(resolve("  remote desktop  "), "TermService");
        assert_eq!(resolve("CCS Client"), "CCSClient");
    }

    #[test]
    fn an_unknown_name_is_left_alone() {
        assert_eq!(resolve("SomeVendorSvc"), "SomeVendorSvc");
    }

    #[test]
    fn remote_desktop_is_recognised_however_the_readme_spells_it() {
        for entry in [
            "Remote Desktop",
            "Remote Desktop Services",
            "RDP",
            "TermService",
        ] {
            assert!(
                is_remote_desktop_required(Some(&readme_with(&[entry]))),
                "{entry} was not recognised"
            );
        }
    }

    #[test]
    fn remote_desktop_is_not_required_by_default() {
        assert!(!is_remote_desktop_required(Some(&readme_with(&[
            "CCS Client"
        ]))));
        assert!(!is_remote_desktop_required(None));
    }
}
