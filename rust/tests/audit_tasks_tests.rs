// =============================================================================
// PinnacleCyPat - Audit / misc task tests
// =============================================================================

use pinnacle_cypat::tasks::*;

// --- Group membership parsing -------------------------------------------------
//
// `is_user_admin` used to substring-search the whole `net localgroup` blob, so
// names appearing in the surrounding prose counted as membership.

const NET_LOCALGROUP_OUTPUT: &str = "Alias name     Administrators\r
Comment        Administrators have complete and unrestricted access to the computer/domain\r
\r
Members\r
\r
-------------------------------------------------------------------------------\r
Administrator\r
CYBERPC\\alice\r
bob\r
The command completed successfully.\r
";

#[test]
fn parse_local_group_members_reads_only_the_member_rows() {
    let members = parse_local_group_members(NET_LOCALGROUP_OUTPUT);
    assert_eq!(members, vec!["Administrator", "CYBERPC\\alice", "bob"]);
}

#[test]
fn is_group_member_matches_exact_names_only() {
    let members = parse_local_group_members(NET_LOCALGROUP_OUTPUT);

    assert!(is_group_member(&members, "bob"));
    assert!(
        is_group_member(&members, "BOB"),
        "match is case-insensitive"
    );
    assert!(is_group_member(&members, "Administrator"));
    // DOMAIN\user entries match on the bare account name too.
    assert!(is_group_member(&members, "alice"));

    // These all appear in the surrounding prose and used to yield false
    // positives under the old substring search.
    for impostor in ["admin", "command", "access", "the", "comp"] {
        assert!(
            !is_group_member(&members, impostor),
            "'{impostor}' must not be treated as an administrator"
        );
    }
}

#[tokio::test]
async fn dns_settings_audit_name_and_description() {
    let task = DnsSettingsAuditTask::new();
    assert_eq!(task.name(), "DNS Settings Audit");
    assert!(task.description().contains("DNS settings"));
}

#[tokio::test]
async fn dns_settings_audit_read_system_state() {
    let mut task = DnsSettingsAuditTask::new();
    let _ = task.read_system_state().await;
}

#[tokio::test]
async fn hosts_file_audit_name_and_description() {
    let task = HostsFileAuditTask::new();
    assert_eq!(task.name(), "Hosts File Audit");
    assert!(task.description().contains("hosts file"));
}

#[tokio::test]
async fn hosts_file_audit_read_system_state() {
    let mut task = HostsFileAuditTask::new();
    let _ = task.read_system_state().await;
}

#[tokio::test]
async fn shared_folders_audit_name_and_description() {
    let task = SharedFoldersAuditTask::new();
    assert_eq!(task.name(), "Shared Folders Audit");
    assert!(task.description().contains("shared folders"));
}

#[tokio::test]
async fn shared_folders_audit_read_system_state() {
    let mut task = SharedFoldersAuditTask::new();
    let _ = task.read_system_state().await;
}

#[tokio::test]
async fn software_management_name_and_description() {
    let task = SoftwareManagementTask::new();
    assert_eq!(task.name(), "Software Management");
    assert!(task.description().contains("Removes prohibited software"));
}

#[tokio::test]
async fn software_management_read_system_state() {
    let mut task = SoftwareManagementTask::new();
    let _ = task.read_system_state().await;
}

#[tokio::test]
async fn suspicious_scheduled_tasks_name_and_description() {
    let task = SuspiciousScheduledTasksAuditTask::new();
    assert_eq!(task.name(), "Suspicious Scheduled Tasks Audit");
    assert!(task.description().contains("scheduled tasks"));
}

#[tokio::test]
async fn suspicious_scheduled_tasks_read_system_state() {
    let mut task = SuspiciousScheduledTasksAuditTask::new();
    let _ = task.read_system_state().await;
}

#[tokio::test]
async fn group_policy_execute_should_succeed_when_dry_run() {
    let mut task = GroupPolicyTask::new();
    task.set_dry_run(true);
    let result = task.execute().await;
    assert!(result.success);
    assert!(result.message.contains("Don't display last user name"));
    assert!(result.message.contains("Require Ctrl+Alt+Del"));
    assert!(
        result
            .message
            .contains("ICS (Internet Connection Sharing) disabled")
    );
    assert!(result.message.contains("Restrict anonymous access"));
}

#[tokio::test]
async fn group_policy_verify_should_return_bool() {
    let mut task = GroupPolicyTask::new();
    task.set_dry_run(true);
    let _ = task.verify().await; // Must not panic; returns a valid bool.
}
