/// Represents password policy settings.
#[derive(Debug, Default, Clone)]
pub struct PasswordPolicyInfo {
    pub min_password_length: i32,
    pub max_password_age: i32,
    pub min_password_age: i32,
    pub password_history_count: i32,
    pub complexity_enabled: bool,
    pub lockout_threshold: i32,
    pub lockout_duration: i32,
    pub lockout_observation_window: i32,
    pub reversible_encryption_disabled: bool,
}

/// Professional security standards for password policies.
/// Based on NIST SP 800-63B, CIS Benchmarks, and industry best practices.
pub struct PasswordPolicyStandards;

impl PasswordPolicyStandards {
    // Password Requirements
    pub const MIN_PASSWORD_LENGTH: i32 = 14;
    pub const MAX_PASSWORD_AGE: i32 = 60; // days
    pub const MIN_PASSWORD_AGE: i32 = 1; // days
    pub const PASSWORD_HISTORY_COUNT: i32 = 24;
    pub const COMPLEXITY_ENABLED: bool = true;
    pub const REVERSIBLE_ENCRYPTION_DISABLED: bool = true;

    // Account Lockout Policy
    pub const LOCKOUT_THRESHOLD: i32 = 5; // failed attempts
    pub const LOCKOUT_DURATION: i32 = 30; // minutes
    pub const LOCKOUT_OBSERVATION_WINDOW: i32 = 30; // minutes
}
