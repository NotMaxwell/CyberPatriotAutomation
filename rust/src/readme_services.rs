// =============================================================================
// PinnacleCyPat - README service-name resolution
// Author: Maxwell McCormick
// Copyright 2026 Maxwell McCormick
// SPDX-License-Identifier: Apache-2.0
// =============================================================================

//! Resolving the service names a README uses to the names Windows uses, and
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
//! ("TermService"), and is inconsistent about which - the same document may say
//! "Remote Desktop Services" in one line and "RDP" in another.

use crate::knowledge::SERVICE_NAME_MAP;
use crate::models::ReadmeData;

/// Display names a README might use, mapped to the Windows service name.
/// The Windows service name for a README's display name, or the name unchanged
/// when it is not one this table knows.
pub fn resolve(display_name: &str) -> String {
    let trimmed = display_name.trim();
    SERVICE_NAME_MAP
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
pub fn is_critical(readme: Option<&ReadmeData>, service_name: &str) -> bool {
    let Some(readme) = readme else {
        return false;
    };
    let wanted = resolve(service_name);
    readme
        .critical_services
        .iter()
        .any(|entry| resolve(entry).eq_ignore_ascii_case(&wanted))
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
