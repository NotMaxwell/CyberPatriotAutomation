// =============================================================================
// PinnacleCyPat - ReadmeParser Tests
// =============================================================================

use pinnacle_cypat::readme_parser;

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

async fn parse_inline() -> pinnacle_cypat::models::ReadmeData {
    let dir = std::env::temp_dir();
    let path = dir.join(format!("cpa_inline_{}.html", uuid_like()));
    std::fs::write(&path, INLINE_README).unwrap();
    let data = readme_parser::parse_html_readme_async(&path.to_string_lossy()).await;
    let _ = std::fs::remove_file(&path);
    data
}

fn uuid_like() -> u128 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos()
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
    assert!(data
        .guidelines
        .iter()
        .any(|g| g.contains("Read the README carefully")));
}

// OS detection has to survive however the author typed the name: markup in the
// middle of it, a non-breaking space, or prose elsewhere naming a different
// version. All of these previously reported "Unknown" or the wrong OS.

#[tokio::test]
async fn os_detected_through_markup_and_nbsp() {
    let split_by_tag = r#"<html><head><title>Round 1</title></head><body>
<h1>Training Round <b>Windows 10</b> README</h1></body></html>"#;
    assert_eq!(
        parse_str(split_by_tag, "os1").await.operating_system,
        "Windows 10"
    );

    let nbsp = "<html><body><h1>Windows&nbsp;11 Image</h1></body></html>";
    assert_eq!(parse_str(nbsp, "os2").await.operating_system, "Windows 11");
}

#[tokio::test]
async fn headline_wins_over_prose_naming_another_version() {
    // A Windows 11 image whose body warns against rolling back to Windows 10.
    let html = r#"<html><head><title>Windows 11 Enterprise README</title></head><body>
<p>Do not attempt to go back to Windows 10 using recovery options.</p>
</body></html>"#;
    assert_eq!(parse_str(html, "os3").await.operating_system, "Windows 11");
}

#[tokio::test]
async fn server_editions_are_not_reported_as_desktop() {
    let html = "<html><body><h1>Windows Server 2022 Standard</h1></body></html>";
    assert_eq!(
        parse_str(html, "os4").await.operating_system,
        "Windows Server 2022"
    );
}

#[tokio::test]
async fn unrecognised_os_still_reports_unknown() {
    let html = "<html><body><h1>Some Appliance README</h1></body></html>";
    assert_eq!(parse_str(html, "os5").await.operating_system, "Unknown");
}

// "Do not stop or disable the X service" is standard CyberPatriot phrasing. The
// original negative-lookbehind only covered a literal "do not " immediately
// before "disable", so the intervening "stop or " let a critical service be
// queued for disabling.
const NEGATED_DISABLE_README: &str = r#"<html><body>
<h1>Windows 10 Image</h1>
<h2>Competition Guidelines</h2>
<ul>
<li>Do not stop or disable the CCS Client service.</li>
<li>Do not stop or disable the Windows Update service.</li>
<li>Never disable the Windows Defender service.</li>
<li>Disable the Telnet service.</li>
</ul>
</body></html>"#;

async fn parse_str(html: &str, tag: &str) -> pinnacle_cypat::models::ReadmeData {
    let path = std::env::temp_dir().join(format!("cpa_{tag}_{}.html", uuid_like()));
    std::fs::write(&path, html).unwrap();
    let data = readme_parser::parse_html_readme_async(&path.to_string_lossy()).await;
    let _ = std::fs::remove_file(&path);
    data
}

#[tokio::test]
async fn do_not_stop_or_disable_does_not_queue_service_for_disabling() {
    let data = parse_str(NEGATED_DISABLE_README, "neg").await;
    for protected in ["CCS Client", "Windows Update", "Windows Defender"] {
        assert!(
            !data
                .prohibited_services
                .iter()
                .any(|s| s.eq_ignore_ascii_case(protected)),
            "{protected} must not be queued for disabling, got {:?}",
            data.prohibited_services
        );
        assert!(
            data.critical_services
                .iter()
                .any(|s| s.eq_ignore_ascii_case(protected)),
            "{protected} should be recorded as critical, got {:?}",
            data.critical_services
        );
    }
    // A genuine, non-negated instruction must still be picked up.
    assert!(
        data.prohibited_services
            .iter()
            .any(|s| s.eq_ignore_ascii_case("Telnet")),
        "Telnet should still be queued, got {:?}",
        data.prohibited_services
    );
}

#[tokio::test]
async fn a_critical_service_is_never_also_prohibited() {
    let data = parse_str(NEGATED_DISABLE_README, "conflict").await;
    for critical in &data.critical_services {
        assert!(
            !data
                .prohibited_services
                .iter()
                .any(|p| p.eq_ignore_ascii_case(critical)),
            "{critical} appears in both critical and prohibited lists"
        );
    }
}

// Prose must not be mistaken for a software requirement, and "latest" applying
// to one package must not mark every other package as latest-required.
const SOFTWARE_README: &str = r#"<html><body>
<h1>Windows 10 Image</h1>
<h2>Software</h2>
<p>Employees must have access to the latest stable version of Firefox for company use.</p>
<p>Standard users should not have access to administrative tools.</p>
<p>This machine should be using Thunderbird.</p>
</body></html>"#;

#[tokio::test]
async fn software_parsing_rejects_prose_and_scopes_latest() {
    let data = parse_str(SOFTWARE_README, "sw").await;
    let names: Vec<&str> = data
        .required_software
        .iter()
        .map(|s| s.name.as_str())
        .collect();

    assert!(names.contains(&"Firefox"), "expected Firefox in {names:?}");
    assert!(
        !names
            .iter()
            .any(|n| n.eq_ignore_ascii_case("administrative tools")),
        "prose became a software requirement: {names:?}"
    );

    let firefox = data
        .required_software
        .iter()
        .find(|s| s.name == "Firefox")
        .unwrap();
    assert!(
        firefox.should_be_latest,
        "Firefox is described as latest stable"
    );

    // "Thunderbird" is not described as latest; the document merely contains the
    // word elsewhere, which used to be enough to flag it.
    if let Some(tb) = data
        .required_software
        .iter()
        .find(|s| s.name == "Thunderbird")
    {
        assert!(
            !tb.should_be_latest,
            "'latest' must not leak across requirements"
        );
    }
}

// Not every CyberPatriot README puts the user list in a <pre> block; many use
// <br>-separated lines. Stripping tags to "" would collapse those into one long
// line and yield zero users, which downstream reads as "no authorized users".
const BR_SEPARATED_README: &str = r#"<html><body>
<h1>Windows 10 Image</h1>
<h2>Authorized Administrators</h2>
<p>Authorized Administrators<br>alice (you)<br>password: Alice#Pass1<br>bob<br>password: Bob#Pass2<br>Authorized Users<br>carol<br>dave</p>
</body></html>"#;

#[tokio::test]
async fn parse_br_separated_user_list_extracts_users() {
    let dir = std::env::temp_dir();
    let path = dir.join(format!("cpa_br_{}.html", uuid_like()));
    std::fs::write(&path, BR_SEPARATED_README).unwrap();
    let data = readme_parser::parse_html_readme_async(&path.to_string_lossy()).await;
    let _ = std::fs::remove_file(&path);

    let admins: Vec<&str> = data
        .administrators
        .iter()
        .map(|a| a.username.as_str())
        .collect();
    assert!(admins.contains(&"alice"), "expected alice in {admins:?}");
    assert!(admins.contains(&"bob"), "expected bob in {admins:?}");

    let alice = data
        .administrators
        .iter()
        .find(|a| a.username == "alice")
        .unwrap();
    assert_eq!(alice.password.as_deref(), Some("Alice#Pass1"));
    assert!(alice.is_primary_user);

    let users: Vec<&str> = data.users.iter().map(|u| u.username.as_str()).collect();
    assert!(users.contains(&"carol"), "expected carol in {users:?}");
    assert!(users.contains(&"dave"), "expected dave in {users:?}");
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

/// Parse an arbitrary HTML fragment through the real file-based entry point.
async fn parse_html(html: &str) -> pinnacle_cypat::models::ReadmeData {
    let path = std::env::temp_dir().join(format!("cpa_group_{}.html", uuid_like()));
    std::fs::write(&path, html).unwrap();
    let data = readme_parser::parse_html_readme_async(&path.to_string_lossy()).await;
    let _ = std::fs::remove_file(&path);
    data
}

/// The sentence is verbatim from a competition README, and the run it produced
/// recorded `Members: users, ggoddard, ealderson, amoss, lchong, group` - so
/// `net localgroup allsafe "group" /add` was issued and failed.
///
/// The member capture is prose, and the regex only knew the phrasing "add the
/// following users to the X group:". Against "add the users ... into the group"
/// the optional prefix did not match, so the connectives were captured with the
/// names. "the", "and" and "into" were filtered as common words; "users" and
/// "group" were not.
#[tokio::test]
async fn group_members_exclude_the_connective_prose() {
    let data = parse_html(
        "<html><body><h1>Windows 11</h1><p>Please make a group called allsafe \
         and add the users ggoddard, ealderson, amoss, and lchong into the group.</p></body></html>",
    )
    .await;

    let group = data
        .group_requirements
        .iter()
        .find(|g| g.group_name == "allsafe")
        .expect("allsafe group");
    assert_eq!(group.members, ["ggoddard", "ealderson", "amoss", "lchong"]);
}

/// The phrasing the regex already handled must keep working.
#[tokio::test]
async fn group_members_still_parse_the_following_users_phrasing() {
    let data = parse_html(
        "<html><body><h1>Windows 11</h1><p>Create a new group called auditors and add \
         the following users to the auditors group: lchong, pprice.</p></body></html>",
    )
    .await;

    let group = data
        .group_requirements
        .iter()
        .find(|g| g.group_name == "auditors")
        .expect("auditors group");
    assert_eq!(group.members, ["lchong", "pprice"]);
}

#[test]
fn extract_group_members_keeps_only_the_names() {
    let cases: &[(&str, &[&str])] = &[
        // The two that reached a live command line.
        (
            "the users ggoddard, ealderson into the group",
            &["ggoddard", "ealderson"],
        ),
        // Other shapes of the same prose.
        ("the following users: amoss and lchong", &["amoss", "lchong"]),
        (
            "these accounts amoss, lchong to the group",
            &["amoss", "lchong"],
        ),
        (
            "users amoss and lchong as members of the group",
            &["amoss", "lchong"],
        ),
        // No connectives at all - the shape the original tests covered.
        (
            "ggoddard, ealderson, amoss",
            &["ggoddard", "ealderson", "amoss"],
        ),
    ];

    for (prose, expected) in cases {
        assert_eq!(
            readme_parser::extract_group_members(prose),
            *expected,
            "prose: {prose}"
        );
    }
}
