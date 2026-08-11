// =============================================================================
// CyberPatriot Automation Tool - ReadmeParser Tests
// =============================================================================

use cyberpatriot_automation::readme_parser;

const SAMPLE_README_PATH: &str = "../SampleData/sampleReadme.html";

#[tokio::test]
async fn parse_html_readme_nonexistent_file_returns_empty_data() {
    let result = readme_parser::parse_html_readme_async("nonexistent.html").await;
    assert_eq!(result.title, "");
    assert!(result.administrators.is_empty());
}

// The following mirror the original suite: they only assert when the (untracked)
// sample README is present, matching the C# `if (!File.Exists(...)) return;` guard.

#[tokio::test]
async fn parse_html_readme_should_extract_title() {
    if !std::path::Path::new(SAMPLE_README_PATH).exists() {
        return;
    }
    let result = readme_parser::parse_html_readme_async(SAMPLE_README_PATH).await;
    assert!(!result.title.is_empty());
}

#[tokio::test]
async fn parse_html_readme_should_extract_administrators() {
    if !std::path::Path::new(SAMPLE_README_PATH).exists() {
        return;
    }
    let result = readme_parser::parse_html_readme_async(SAMPLE_README_PATH).await;
    assert!(!result.administrators.is_empty());
}

// --- Inline coverage that always runs, exercising the parser end-to-end. ---

const INLINE_README: &str = r#"<html><head><title>Round 1</title></head><body>
<h1>CyberPatriot Practice Image</h1>
<h2>Operating System</h2><p>This image is Windows 10 Enterprise.</p>
<h2>Authorized Administrators</h2>
<pre>
Authorized Administrators
alice (you)
password: Alice#Pass1
bob
password: Bob#Pass2
Authorized Users
carol
dave
</pre>
<h2>Critical Services</h2><ul><li>DNS Client</li><li>DHCP Client</li></ul>
<h2>Competition Scenario</h2><p>Secure the workstation.</p>
<h2>Competition Guidelines</h2><ul><li>Do not disable the CCS Client service.</li><li>Do not stop the CCS Client service.</li><li>Read the README carefully.</li></ul>
</body></html>"#;

async fn parse_inline() -> cyberpatriot_automation::models::ReadmeData {
    let dir = std::env::temp_dir();
    let path = dir.join(format!("cpa_inline_{}.html", uuid_like()));
    std::fs::write(&path, INLINE_README).unwrap();
    let data = readme_parser::parse_html_readme_async(&path.to_string_lossy()).await;
    let _ = std::fs::remove_file(&path);
    data
}

fn uuid_like() -> u128 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos()
}

#[tokio::test]
async fn parse_inline_extracts_title_and_os() {
    let data = parse_inline().await;
    assert_eq!(data.title, "CyberPatriot Practice Image");
    assert_eq!(data.operating_system, "Windows 10");
}

#[tokio::test]
async fn parse_inline_extracts_admins_with_passwords() {
    let data = parse_inline().await;
    assert_eq!(data.administrators.len(), 2);

    let alice = data
        .administrators
        .iter()
        .find(|a| a.username == "alice")
        .expect("alice present");
    assert_eq!(alice.password.as_deref(), Some("Alice#Pass1"));
    assert!(alice.is_primary_user);

    let bob = data
        .administrators
        .iter()
        .find(|a| a.username == "bob")
        .expect("bob present");
    assert_eq!(bob.password.as_deref(), Some("Bob#Pass2"));
}

#[tokio::test]
async fn parse_inline_extracts_users() {
    let data = parse_inline().await;
    let names: Vec<&str> = data.users.iter().map(|u| u.username.as_str()).collect();
    assert!(names.contains(&"carol"));
    assert!(names.contains(&"dave"));
}

#[tokio::test]
async fn parse_inline_extracts_critical_services_including_ccs() {
    let data = parse_inline().await;
    assert!(data.critical_services.iter().any(|s| s == "DNS Client"));
    assert!(data.critical_services.iter().any(|s| s == "DHCP Client"));
    assert!(data.critical_services.iter().any(|s| s == "CCS Client"));
}

#[tokio::test]
async fn parse_inline_extracts_scenario_and_guidelines() {
    let data = parse_inline().await;
    assert_eq!(data.scenario, "Secure the workstation.");
    assert!(data.guidelines.iter().any(|g| g.contains("Read the README carefully")));
}

#[tokio::test]
async fn parse_inline_does_not_flag_do_not_disable_as_prohibited() {
    let data = parse_inline().await;
    // "Do not disable the CCS Client service" must NOT add CCS to prohibited services.
    assert!(!data
        .prohibited_services
        .iter()
        .any(|s| s.to_lowercase().contains("ccs")));
}
