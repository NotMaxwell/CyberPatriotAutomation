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

impl PasswordPolicyInfo {
    /// Read the table `net accounts` prints.
    ///
    /// Matches an English-language console only, which is why it is the fallback
    /// for the netapi32 read rather than the primary path. It lives on the model
    /// so the task and the run log's evidence read the output the same way; two
    /// parsers that disagreed would make a change look unapplied when it was not.
    ///
    /// `complexity_enabled` is not set here: it is not in this output, and only
    /// `secedit` reports it.
    pub fn parse_net_accounts(output: &str) -> Self {
        let mut policy = Self::default();

        for line in output.split(['\r', '\n']).filter(|l| !l.is_empty()) {
            if line.contains("Minimum password length") {
                policy.min_password_length = extract_numeric_value(line);
            } else if line.contains("Maximum password age") {
                let v = extract_numeric_value(line);
                // -1 is "Never"; the rest of the tool spells that 0.
                policy.max_password_age = if v == -1 { 0 } else { v };
            } else if line.contains("Minimum password age") {
                policy.min_password_age = extract_numeric_value(line);
            } else if line.contains("Length of password history") {
                policy.password_history_count = extract_numeric_value(line);
            } else if line.contains("Lockout threshold") {
                let v = extract_numeric_value(line);
                policy.lockout_threshold = if v == -1 { 0 } else { v };
            } else if line.contains("Lockout duration") {
                policy.lockout_duration = extract_numeric_value(line);
            } else if line.contains("Lockout observation window") {
                policy.lockout_observation_window = extract_numeric_value(line);
            }
        }

        policy
    }
}

/// The number on the right of a `net accounts` row, with its words for "no
/// limit" mapped to numbers.
pub fn extract_numeric_value(line: &str) -> i32 {
    let Some((_, value)) = line.split_once(':') else {
        return 0;
    };
    let value = value.trim();

    let lowered = value.to_lowercase();
    if lowered.contains("never") || lowered.contains("unlimited") {
        return -1;
    }
    if lowered.contains("none") {
        return 0;
    }

    // The sign is kept: some locales print "-1" where English prints "Never".
    let digits: String = value
        .chars()
        .take_while(|c| c.is_ascii_digit() || *c == '-')
        .collect();
    digits.parse().unwrap_or(0)
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
