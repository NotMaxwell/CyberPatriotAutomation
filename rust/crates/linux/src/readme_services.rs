// =============================================================================
// PinnacleCyPat - README service names, Linux
// Copyright 2026 Maxwell McCormick
// SPDX-License-Identifier: Apache-2.0
// =============================================================================

//! [`pinnacle_core::readme_services`] bound to the systemd unit-name table.
//!
//! Ask the README questions through here, never by matching strings. Two tasks
//! that read the same README differently is a bug class this codebase has
//! already had twice on Windows - service management protected a service the
//! README called critical while hardening disabled it anyway, so the service
//! ran and every connection to it was refused.

use crate::knowledge::SERVICE_NAME_MAP;
use pinnacle_core::models::ReadmeData;
use pinnacle_core::readme_services as core;

/// The systemd unit for a README's display name.
pub fn resolve(display_name: &str) -> String {
    core::resolve(SERVICE_NAME_MAP, display_name)
}

/// Does the README mark this unit as critical?
pub fn is_critical(readme: Option<&ReadmeData>, unit: &str) -> bool {
    core::is_critical(SERVICE_NAME_MAP, readme, unit)
}

/// Is this unit one the run must not touch, whatever else it disables?
///
/// True when the README says so, or when it is on the never-disable list -
/// which covers the scoring engine and the units the image needs to boot.
pub fn is_protected(readme: Option<&ReadmeData>, unit: &str) -> bool {
    if is_critical(readme, unit) {
        return true;
    }
    let stem = unit.split('.').next().unwrap_or(unit);
    crate::knowledge::NEVER_DISABLE
        .iter()
        .any(|p| p.eq_ignore_ascii_case(stem))
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
    fn display_names_resolve_to_units() {
        assert_eq!(resolve("SSH"), "ssh.service");
        assert_eq!(resolve("  secure shell  "), "ssh.service");
        assert_eq!(resolve("Apache"), "apache2.service");
    }

    #[test]
    fn an_unknown_name_is_left_alone() {
        assert_eq!(resolve("some-vendor.service"), "some-vendor.service");
    }

    /// However the README spells it, the same unit is protected. A README
    /// saying "Apache" must protect the unit a task asks about as
    /// "apache2.service", or the web server the round requires gets masked.
    #[test]
    fn a_critical_service_is_recognised_however_it_is_spelled() {
        for spelling in ["Apache", "Apache2", "Web Server", "apache2.service"] {
            assert!(
                is_critical(Some(&readme_with(&[spelling])), "apache2.service"),
                "{spelling} was not recognised"
            );
        }
    }

    /// The catastrophic case, and the reason the never-disable list exists
    /// independently of the README: the scoring engine must survive a README
    /// that does not mention it, which is every README.
    #[test]
    fn the_scoring_engine_is_protected_without_the_readme_saying_so() {
        assert!(is_protected(None, "ccsclient.service"));
        assert!(is_protected(None, "systemd-journald.service"));
        assert!(is_protected(None, "cron.service"));
    }

    #[test]
    fn an_ordinary_service_is_not_protected_by_default() {
        assert!(!is_protected(None, "telnet.socket"));
        assert!(!is_protected(None, "apache2.service"));
        // ...until the README says it is.
        assert!(is_protected(
            Some(&readme_with(&["Apache"])),
            "apache2.service"
        ));
    }
}
