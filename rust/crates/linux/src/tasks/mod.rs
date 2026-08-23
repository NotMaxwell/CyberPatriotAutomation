// =============================================================================
// PinnacleCyPat - Linux security task implementations
// Copyright 2026 Maxwell McCormick
// SPDX-License-Identifier: Apache-2.0
// =============================================================================

mod account_permissions;
mod audit_policy;
mod dns_settings_audit;
mod firewall;
mod hosts_file_audit;
mod password_policy;
mod prohibited_media;
mod scheduled_tasks_audit;
mod security_hardening;
mod service_management;
mod software_management;
mod software_update;
mod user_management;

pub use account_permissions::AccountPermissionsTask;
pub use audit_policy::AuditPolicyTask;
pub use dns_settings_audit::DnsSettingsAuditTask;
pub use firewall::FirewallTask;
pub use hosts_file_audit::HostsFileAuditTask;
pub use password_policy::PasswordPolicyTask;
pub use prohibited_media::ProhibitedMediaTask;
pub use scheduled_tasks_audit::ScheduledTasksAuditTask;
pub use security_hardening::SecurityHardeningTask;
pub use service_management::ServiceManagementTask;
pub use software_management::SoftwareManagementTask;
pub use software_update::SoftwareUpdateTask;
pub use user_management::UserManagementTask;
