//! Password and lockout policy writes for the tasks: the Windows API where
//! available, otherwise `net accounts`.
//!
//! Deciding here rather than at every call site keeps the tasks readable and the
//! fallback in one place, mirroring `PolicyOps` in the C# port. `net accounts`
//! reports failure only through an exit code, so "the value is out of range"
//! and "you are not an administrator" looked alike; netapi32 returns a status.
//!
//! Every write is followed by a read of the policy, recorded in the run log as
//! the evidence for it. That matters more here than elsewhere: Windows
//! normalises several of these values silently - a lockout observation window
//! wider than the duration is narrowed to match - so a write that succeeds and a
//! policy that ends up as asked are genuinely different things.

use crate::command;
use crate::models::PasswordPolicyInfo;
use crate::remediation;

/// Set the minimum password length, in characters.
pub async fn set_min_password_length(characters: i32) -> Result<(), String> {
    apply(
        "Minimum password length",
        &format!("{characters} characters"),
        |p| p.min_password_length,
        characters,
        || set_min_password_length_core(characters),
    )
    .await
}

/// Set the maximum password age, in days. Zero means "never expires".
pub async fn set_max_password_age_days(days: i32) -> Result<(), String> {
    apply(
        "Maximum password age",
        &format!("{days} days"),
        |p| p.max_password_age,
        days,
        || set_max_password_age_days_core(days),
    )
    .await
}

/// Set the minimum password age, in days.
pub async fn set_min_password_age_days(days: i32) -> Result<(), String> {
    apply(
        "Minimum password age",
        &format!("{days} days"),
        |p| p.min_password_age,
        days,
        || set_min_password_age_days_core(days),
    )
    .await
}

/// Set how many previous passwords are remembered.
pub async fn set_password_history_length(count: i32) -> Result<(), String> {
    apply(
        "Password history",
        &format!("{count} remembered"),
        |p| p.password_history_count,
        count,
        || set_password_history_length_core(count),
    )
    .await
}

/// Set how many bad passwords lock an account out. Zero disables lockout.
pub async fn set_lockout_threshold(attempts: i32) -> Result<(), String> {
    apply(
        "Account lockout threshold",
        &format!("{attempts} bad attempts"),
        |p| p.lockout_threshold,
        attempts,
        || set_lockout_threshold_core(attempts),
    )
    .await
}

/// Set how long an account stays locked out, in minutes.
pub async fn set_lockout_duration_minutes(minutes: i32) -> Result<(), String> {
    apply(
        "Account lockout duration",
        &format!("{minutes} minutes"),
        |p| p.lockout_duration,
        minutes,
        || set_lockout_duration_minutes_core(minutes),
    )
    .await
}

/// Set how long bad attempts are counted for, in minutes.
pub async fn set_lockout_observation_minutes(minutes: i32) -> Result<(), String> {
    apply(
        "Lockout observation window",
        &format!("{minutes} minutes"),
        |p| p.lockout_observation_window,
        minutes,
        || set_lockout_observation_minutes_core(minutes),
    )
    .await
}

/// Apply one policy value and prove it, reading the whole policy back and
/// picking the one field out of it.
async fn apply<Field, Apply, ApplyFut>(
    target: &str,
    intent: &str,
    field: Field,
    wanted: i32,
    apply_write: Apply,
) -> Result<(), String>
where
    Field: Fn(&PasswordPolicyInfo) -> i32,
    Apply: FnOnce() -> ApplyFut,
    ApplyFut: std::future::Future<Output = Result<(), String>>,
{
    remediation::apply(
        &format!("Password policy: {target}"),
        intent,
        || async { read_policy().await.map(|p| field(&p).to_string()) },
        |state| state == wanted.to_string(),
        &format!("set it to {wanted}"),
        apply_write,
    )
    .await
}

/// The current policy, or `None` when it could not be read.
///
/// The fallback re-parses `net accounts` through the model's own parser, so
/// evidence on a machine without the API path is read exactly the way the task
/// reads it, rather than by a second parser that could disagree.
async fn read_policy() -> Option<PasswordPolicyInfo> {
    #[cfg(windows)]
    if let Some(values) = crate::native::accounts::password_policy() {
        return Some(PasswordPolicyInfo {
            min_password_length: values.min_password_length as i32,
            max_password_age: values.max_password_age_days as i32,
            min_password_age: values.min_password_age_days as i32,
            password_history_count: values.password_history_length as i32,
            lockout_threshold: values.lockout_threshold as i32,
            lockout_duration: values.lockout_duration_minutes as i32,
            lockout_observation_window: values.lockout_observation_minutes as i32,
            ..Default::default()
        });
    }

    let (success, output, _e) = command::execute("net", Some("accounts")).await;
    if !success {
        return None;
    }
    Some(PasswordPolicyInfo::parse_net_accounts(&output))
}

async fn set_min_password_length_core(characters: i32) -> Result<(), String> {
    #[cfg(windows)]
    {
        crate::native::accounts::set_min_password_length(clamp(characters))
    }

    #[cfg(not(windows))]
    {
        net_accounts(&format!("minpwlen:{characters}")).await
    }
}

async fn set_max_password_age_days_core(days: i32) -> Result<(), String> {
    #[cfg(windows)]
    {
        crate::native::accounts::set_max_password_age_days(clamp(days))
    }

    #[cfg(not(windows))]
    {
        net_accounts(&format!("maxpwage:{days}")).await
    }
}

async fn set_min_password_age_days_core(days: i32) -> Result<(), String> {
    #[cfg(windows)]
    {
        crate::native::accounts::set_min_password_age_days(clamp(days))
    }

    #[cfg(not(windows))]
    {
        net_accounts(&format!("minpwage:{days}")).await
    }
}

async fn set_password_history_length_core(count: i32) -> Result<(), String> {
    #[cfg(windows)]
    {
        crate::native::accounts::set_password_history_length(clamp(count))
    }

    #[cfg(not(windows))]
    {
        net_accounts(&format!("uniquepw:{count}")).await
    }
}

async fn set_lockout_threshold_core(attempts: i32) -> Result<(), String> {
    #[cfg(windows)]
    {
        crate::native::accounts::set_lockout_threshold(clamp(attempts))
    }

    #[cfg(not(windows))]
    {
        net_accounts(&format!("lockoutthreshold:{attempts}")).await
    }
}

async fn set_lockout_duration_minutes_core(minutes: i32) -> Result<(), String> {
    #[cfg(windows)]
    {
        crate::native::accounts::set_lockout_duration_minutes(clamp(minutes))
    }

    #[cfg(not(windows))]
    {
        net_accounts(&format!("lockoutduration:{minutes}")).await
    }
}

async fn set_lockout_observation_minutes_core(minutes: i32) -> Result<(), String> {
    #[cfg(windows)]
    {
        crate::native::accounts::set_lockout_observation_minutes(clamp(minutes))
    }

    #[cfg(not(windows))]
    {
        net_accounts(&format!("lockoutwindow:{minutes}")).await
    }
}

#[cfg(not(windows))]
async fn net_accounts(argument: &str) -> Result<(), String> {
    let (success, _o, error) =
        command::execute("net", Some(&format!("accounts /{argument}"))).await;
    if success {
        Ok(())
    } else {
        Err(error.unwrap_or_else(|| format!("net accounts /{argument} failed")))
    }
}

/// The policy standards are `i32` so a task can compare them against a parsed
/// value; the API takes unsigned counts, and a negative one is meaningless.
#[cfg(windows)]
fn clamp(value: i32) -> u32 {
    value.max(0) as u32
}
