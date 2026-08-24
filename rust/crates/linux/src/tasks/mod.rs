// =============================================================================
// PinnacleCyPat - Linux security task implementations
// Copyright 2026 Maxwell McCormick
// SPDX-License-Identifier: Apache-2.0
// =============================================================================

//! The modules are public so the answer-key suite in `tests/answer_key.rs` can
//! reach the functions that make the decisions - which accounts are
//! unauthorised, which services are protected, which packages get purged. Those
//! are what a CyberPatriot answer key actually scores, and testing them through
//! `execute()` would mean running against a real image.

pub mod account_permissions;
pub mod audit_policy;
pub mod dns_settings_audit;
pub mod file_permissions_audit;
pub mod firewall;
pub mod hosts_file_audit;
pub mod password_policy;
pub mod prohibited_media;
pub mod scheduled_tasks_audit;
pub mod security_hardening;
pub mod service_management;
pub mod shared_folders_audit;
pub mod software_management;
pub mod software_update;
pub mod user_management;

pub use account_permissions::AccountPermissionsTask;
pub use audit_policy::AuditPolicyTask;
pub use dns_settings_audit::DnsSettingsAuditTask;
pub use file_permissions_audit::FilePermissionsAuditTask;
pub use firewall::FirewallTask;
pub use hosts_file_audit::HostsFileAuditTask;
pub use password_policy::PasswordPolicyTask;
pub use prohibited_media::ProhibitedMediaTask;
pub use scheduled_tasks_audit::ScheduledTasksAuditTask;
pub use security_hardening::SecurityHardeningTask;
pub use service_management::ServiceManagementTask;
pub use shared_folders_audit::SharedFoldersAuditTask;
pub use software_management::SoftwareManagementTask;
pub use software_update::SoftwareUpdateTask;
pub use user_management::UserManagementTask;
