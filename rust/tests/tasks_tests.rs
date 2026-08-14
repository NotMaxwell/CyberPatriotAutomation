// =============================================================================
// CyberPatriot Automation Tool - Task Tests
// =============================================================================

use cyberpatriot_automation::models::ReadmeData;
use cyberpatriot_automation::tasks::*;

#[tokio::test]
async fn software_update_task_should_have_correct_name_and_description() {
    let task = SoftwareUpdateTask::new();
    assert_eq!(task.name(), "Software Updates");
    assert!(task.description().contains("latest"));
}

#[tokio::test]
async fn software_update_task_set_readme_data_should_accept_data() {
    let mut task = SoftwareUpdateTask::new();
    task.set_readme_data(ReadmeData::default());
    assert_eq!(task.name(), "Software Updates");
}

#[tokio::test]
async fn software_update_task_read_system_state_should_not_panic() {
    // On a host without winget (including any non-Windows CI machine) this must
    // degrade to an empty inventory rather than failing.
    let mut task = SoftwareUpdateTask::new();
    let _ = task.read_system_state().await;
}

#[tokio::test]
async fn software_update_task_reports_failure_when_winget_is_unavailable() {
    // The task cannot determine a "latest version" without a package catalogue,
    // so it must say so rather than reporting a vacuous success.
    let mut task = SoftwareUpdateTask::new();
    let result = task.execute().await;
    if !result.success {
        assert!(
            result.message.to_lowercase().contains("winget"),
            "expected the message to explain the winget dependency, got: {}",
            result.message
        );
        assert!(result.error_details.is_some());
    }
}

#[tokio::test]
async fn software_update_task_dry_run_never_reports_applied_updates() {
    let mut task = SoftwareUpdateTask::new();
    task.set_dry_run(true);
    let result = task.execute().await;
    assert_eq!(
        result.items_succeeded, 0,
        "a dry run must not record any update as applied"
    );
}

#[tokio::test]
async fn password_policy_task_should_have_correct_name_and_description() {
    let task = PasswordPolicyTask::new();
    assert!(!task.name().is_empty());
    assert!(!task.description().is_empty());
    assert!(task.name().contains("Password"));
}

#[tokio::test]
async fn password_policy_task_read_system_state_should_return_system_info() {
    let mut task = PasswordPolicyTask::new();
    let result = task.read_system_state().await;
    // registry_settings is always populated with the seven captured keys.
    assert!(result.registry_settings.contains_key("MinPasswordLength"));
}

#[tokio::test]
async fn account_permissions_task_should_have_correct_name_and_description() {
    let task = AccountPermissionsTask::new();
    assert!(!task.name().is_empty());
    assert!(!task.description().is_empty());
    assert!(task.name().contains("Account"));
}

#[tokio::test]
async fn account_permissions_task_read_system_state_should_return_system_info() {
    let mut task = AccountPermissionsTask::new();
    let _ = task.read_system_state().await; // Must not panic.
}

#[tokio::test]
async fn user_management_task_should_have_correct_name_and_description() {
    let task = UserManagementTask::new();
    assert!(!task.name().is_empty());
    assert!(!task.description().is_empty());
    assert!(task.name().contains("User"));
}

#[tokio::test]
async fn user_management_task_set_readme_data_should_accept_data() {
    let mut task = UserManagementTask::new();
    let readme = ReadmeData {
        title: "Test README".to_string(),
        ..Default::default()
    };
    task.set_readme_data(readme); // Must not panic.
}

#[tokio::test]
async fn user_management_task_execute_without_readme_data_should_return_failure() {
    let mut task = UserManagementTask::new();
    let result = task.execute().await;
    assert!(!result.success);
    assert!(result.message.contains("README"));
}

#[tokio::test]
async fn service_management_task_should_have_correct_name_and_description() {
    let task = ServiceManagementTask::new();
    assert!(!task.name().is_empty());
    assert!(!task.description().is_empty());
    assert!(task.name().contains("Service"));
}

#[tokio::test]
async fn service_management_task_set_readme_data_should_accept_data() {
    let mut task = ServiceManagementTask::new();
    task.set_readme_data(ReadmeData {
        title: "Test README".to_string(),
        ..Default::default()
    });
}

#[tokio::test]
async fn service_management_task_read_system_state_should_return_system_info() {
    let mut task = ServiceManagementTask::new();
    let _ = task.read_system_state().await;
}

#[tokio::test]
async fn audit_policy_task_should_have_correct_name_and_description() {
    let task = AuditPolicyTask::new();
    assert!(!task.name().is_empty());
    assert!(!task.description().is_empty());
    assert!(task.name().contains("Audit"));
}

#[tokio::test]
async fn audit_policy_task_read_system_state_should_return_system_info() {
    let mut task = AuditPolicyTask::new();
    let _ = task.read_system_state().await;
}

#[tokio::test]
async fn firewall_configuration_task_should_have_correct_name_and_description() {
    let task = FirewallConfigurationTask::new();
    assert_eq!(task.name(), "Firewall Configuration");
    assert!(task.description().contains("Firewall"));
}

#[tokio::test]
async fn firewall_configuration_task_read_system_state_should_not_panic() {
    let mut task = FirewallConfigurationTask::new();
    let _ = task.read_system_state().await;
}

#[tokio::test]
async fn firewall_configuration_task_execute_should_return_task_result() {
    let mut task = FirewallConfigurationTask::new();
    task.set_dry_run(true);
    let result = task.execute().await;
    assert_eq!(result.task_name, "Firewall Configuration");
}

#[tokio::test]
async fn security_hardening_task_should_have_correct_name_and_description() {
    let task = SecurityHardeningTask::new();
    assert_eq!(task.name(), "Security Hardening");
    assert!(task.description().contains("security"));
}

#[tokio::test]
async fn security_hardening_task_read_system_state_should_not_panic() {
    let mut task = SecurityHardeningTask::new();
    let _ = task.read_system_state().await;
}

#[tokio::test]
async fn security_hardening_task_execute_should_return_task_result() {
    let mut task = SecurityHardeningTask::new();
    task.set_dry_run(true);
    let result = task.execute().await;
    assert_eq!(result.task_name, "Security Hardening");
}

#[tokio::test]
async fn prohibited_media_task_should_have_correct_name_and_description() {
    let task = ProhibitedMediaTask::new();
    assert_eq!(task.name(), "Prohibited Media Scanner");
    assert!(task.description().contains("prohibited"));
}

#[tokio::test]
async fn prohibited_media_task_set_readme_data_should_not_panic() {
    let mut task = ProhibitedMediaTask::new();
    task.set_readme_data(ReadmeData {
        title: "Test README".to_string(),
        prohibited_software: vec!["game.exe".to_string()],
        ..Default::default()
    });
}

#[tokio::test]
async fn prohibited_media_task_read_system_state_should_not_panic() {
    let mut task = ProhibitedMediaTask::new();
    let _ = task.read_system_state().await;
}

#[tokio::test]
async fn prohibited_media_task_execute_should_return_task_result() {
    let mut task = ProhibitedMediaTask::new();
    let result = task.execute().await;
    assert_eq!(result.task_name, "Prohibited Media Scanner");
}
