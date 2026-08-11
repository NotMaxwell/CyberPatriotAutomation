use chrono::{DateTime, Local};

/// Represents user account information and permissions.
#[derive(Debug, Default, Clone)]
pub struct AccountInfo {
    pub username: String,
    pub full_name: String,
    pub is_enabled: bool,
    pub is_admin: bool,
    pub password_required: bool,
    pub password_never_expires: bool,
    pub cannot_change_password: bool,
    pub last_logon: Option<DateTime<Local>>,
    pub password_last_set: Option<DateTime<Local>>,
    pub group_memberships: Vec<String>,
}

/// Security standards for account permissions.
pub struct AccountSecurityStandards;

impl AccountSecurityStandards {
    /// Guest account should be disabled.
    pub const GUEST_ACCOUNT_SHOULD_BE_DISABLED: bool = true;
    /// Administrator account should be renamed from default.
    pub const ADMIN_ACCOUNT_SHOULD_BE_RENAMED: bool = true;
    /// All users should have password required.
    pub const PASSWORD_SHOULD_BE_REQUIRED: bool = true;
    /// Passwords should expire (not set to never expire).
    pub const PASSWORD_SHOULD_EXPIRE: bool = true;
    /// Maximum days of inactivity before account should be reviewed.
    pub const MAX_INACTIVE_DAYS: i64 = 90;

    /// Known default/insecure usernames to check.
    pub const INSECURE_USERNAMES: &'static [&'static str] =
        &["Guest", "DefaultAccount", "WDAGUtilityAccount"];

    /// Built-in admin account name to check for rename.
    pub const DEFAULT_ADMIN_NAME: &'static str = "Administrator";
}
