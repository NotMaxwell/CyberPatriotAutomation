// =============================================================================
// PinnacleCyPat - AppConfig Tests
// =============================================================================

use pinnacle_cypat::app_config;

#[test]
fn version_should_be_defined() {
    assert!(!app_config::VERSION.is_empty());
}

#[test]
fn ccs_client_service_name_should_be_defined() {
    assert!(!app_config::CCS_CLIENT_SERVICE_NAME.is_empty());
    assert!(app_config::CCS_CLIENT_SERVICE_NAME.contains("CCS"));
}

#[test]
fn scoring_report_shortcut_should_be_defined() {
    assert!(!app_config::SCORING_REPORT_SHORTCUT.is_empty());
}

#[test]
fn default_readme_paths_should_not_be_empty() {
    assert!(!app_config::default_readme_paths().is_empty());
}

#[test]
fn default_readme_paths_should_contain_common_locations() {
    let paths = app_config::default_readme_paths();
    assert!(paths.iter().any(|p| p.contains("Desktop")));
}

// CyberPatriot images conventionally place a `.lnk` shortcut to the README on
// the desktop of the user running the tool, rather than the file itself, so
// `find_readme_file` must resolve shortcuts (via WScript.Shell on Windows)
// before falling back to the literal default paths. This just exercises the
// async entry point end-to-end without asserting a specific outcome, since
// what (if anything) is found depends on the machine running the test.
#[tokio::test]
async fn find_readme_file_does_not_panic() {
    let _ = app_config::find_readme_file().await;
}

#[test]
fn secure_passwords_should_have_enough_passwords() {
    assert!(app_config::SECURE_PASSWORDS.len() >= 10);
}

#[test]
fn secure_passwords_should_be_unique() {
    let mut seen = std::collections::HashSet::new();
    for pw in app_config::SECURE_PASSWORDS {
        assert!(seen.insert(*pw), "duplicate password: {pw}");
    }
}

#[test]
fn secure_passwords_should_meet_complexity_requirements() {
    for password in app_config::SECURE_PASSWORDS {
        assert!(password.chars().count() >= 12, "password too short: {password}");
        assert!(password.chars().any(|c| c.is_ascii_uppercase()), "no uppercase: {password}");
        assert!(password.chars().any(|c| c.is_ascii_lowercase()), "no lowercase: {password}");
        assert!(password.chars().any(|c| c.is_ascii_digit()), "no digit: {password}");
        assert!(password.chars().any(|c| !c.is_ascii_alphanumeric()), "no special: {password}");
    }
}
