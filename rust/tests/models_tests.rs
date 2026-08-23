// =============================================================================
// PinnacleCyPat - Model Tests
// =============================================================================

use chrono::Local;
use pinnacle_cypat::models::*;

#[test]
fn task_result_should_set_executed_at_on_creation() {
    let result = TaskResult::default();
    let delta = (Local::now() - result.executed_at).num_seconds().abs();
    assert!(delta < 5);
}

#[test]
fn task_result_should_store_execution_result() {
    let result = TaskResult {
        task_name: "Test Task".to_string(),
        success: true,
        message: "Completed".to_string(),
        error_details: None,
        ..Default::default()
    };
    assert_eq!(result.task_name, "Test Task");
    assert!(result.success);
    assert_eq!(result.message, "Completed");
}

#[test]
fn readme_data_should_initialize_with_empty_collections() {
    let data = ReadmeData::default();
    assert!(data.administrators.is_empty());
    assert!(data.users.is_empty());
    assert!(data.prohibited_software.is_empty());
    assert!(data.critical_services.is_empty());
}

#[test]
fn authorized_user_should_store_user_data() {
    let user = AuthorizedUser {
        username: "testuser".to_string(),
        is_admin: true,
        password: Some("SecurePass123!".to_string()),
        ..Default::default()
    };
    assert_eq!(user.username, "testuser");
    assert!(user.is_admin);
    assert_eq!(user.password.as_deref(), Some("SecurePass123!"));
}

#[test]
fn software_requirement_should_store_requirements() {
    let software = SoftwareRequirement {
        name: "Firefox".to_string(),
        version: Some("latest".to_string()),
        should_be_latest: true,
        ..Default::default()
    };
    assert_eq!(software.name, "Firefox");
    assert_eq!(software.version.as_deref(), Some("latest"));
    assert!(software.should_be_latest);
}

#[test]
fn group_requirement_should_store_members_list() {
    let group = GroupRequirement {
        group_name: "Administrators".to_string(),
        members: vec!["admin".to_string(), "user1".to_string()],
    };
    assert_eq!(group.group_name, "Administrators");
    assert_eq!(group.members.len(), 2);
    assert!(group.members.contains(&"admin".to_string()));
}

#[test]
fn actionable_item_should_store_action_details() {
    let item = ActionableItem {
        item_type: ActionableItemType::CreateGroup,
        description: "Create backup operators group".to_string(),
        raw_text: "Create a group called BackupOperators".to_string(),
        ..Default::default()
    };
    assert_eq!(item.item_type, ActionableItemType::CreateGroup);
    assert!(item.description.contains("backup"));
}

#[test]
fn actionable_item_type_should_have_all_expected_types() {
    // Referencing the variants confirms they exist and are distinct.
    assert_ne!(
        ActionableItemType::CreateGroup,
        ActionableItemType::CreateUser
    );
    assert_ne!(
        ActionableItemType::CreateUser,
        ActionableItemType::DisableService
    );
}
