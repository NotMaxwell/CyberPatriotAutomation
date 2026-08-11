// =============================================================================
// CyberPatriot Automation Tool - Audit / misc task tests
// =============================================================================

use cyberpatriot_automation::tasks::*;

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
    assert!(result.message.contains("ICS (Internet Connection Sharing) disabled"));
    assert!(result.message.contains("Restrict anonymous access"));
}

#[tokio::test]
async fn group_policy_verify_should_return_bool() {
    let mut task = GroupPolicyTask::new();
    task.set_dry_run(true);
    let _ = task.verify().await; // Must not panic; returns a valid bool.
}
