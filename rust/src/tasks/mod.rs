// =============================================================================
// CyberPatriot Automation Tool - Security task implementations
// =============================================================================

mod base;

mod account_permissions;
mod audit_policy;
mod dns_settings_audit;
mod firewall;
mod group_policy;
mod hosts_file_audit;
mod password_policy;
mod prohibited_media;
mod security_hardening;
mod service_management;
mod shared_folders_audit;
mod software_management;
mod software_update;
mod suspicious_scheduled_tasks_audit;
mod user_management;

pub use base::{
    is_group_member, local_group_members, parse_csv_line, parse_local_group_members, Task,
};

pub use account_permissions::AccountPermissionsTask;
pub use audit_policy::AuditPolicyTask;
pub use dns_settings_audit::DnsSettingsAuditTask;
pub use firewall::FirewallConfigurationTask;
pub use group_policy::GroupPolicyTask;
pub use hosts_file_audit::HostsFileAuditTask;
pub use password_policy::PasswordPolicyTask;
pub use prohibited_media::ProhibitedMediaTask;
pub use security_hardening::SecurityHardeningTask;
pub use service_management::ServiceManagementTask;
pub use shared_folders_audit::SharedFoldersAuditTask;
pub use software_management::SoftwareManagementTask;
pub use software_update::{
    parse_installed_software, parse_winget_upgrades, AvailableUpdate, InstalledApp,
    SoftwareUpdateTask,
};
pub use suspicious_scheduled_tasks_audit::SuspiciousScheduledTasksAuditTask;
pub use user_management::UserManagementTask;
