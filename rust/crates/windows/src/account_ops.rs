//! Local account and group operations for the tasks: the Windows API where
//! available, otherwise `net` and the `*-LocalUser` cmdlets.
//!
//! Deciding here rather than at every call site keeps the tasks readable and the
//! fallback in one place, mirroring `LocalAccounts` in the C# port. Every
//! function returns the reason on failure rather than a bare boolean, because
//! `net`'s exit code cannot tell "no such account" from "access denied" and the
//! caller needs to.

use pinnacle_core::command;
use pinnacle_core::models::AccountInfo;
use pinnacle_core::remediation;

/// Every ordinary local account, without its group memberships.
///
/// Returns `None` when the list could not be read at all, so "no accounts" and
/// "could not look" stay distinguishable. Callers fill in `is_admin` and
/// `group_memberships` themselves, because those come from the group side.
pub async fn enumerate_users() -> Option<Vec<AccountInfo>> {
    #[cfg(windows)]
    if let Some(users) = crate::native::users::enumerate() {
        return Some(
            users
                .into_iter()
                .map(|u| AccountInfo {
                    is_enabled: u.is_enabled(),
                    password_required: u.password_required(),
                    password_never_expires: u.password_never_expires(),
                    // netapi32 reports the stamp in seconds since the Unix
                    // epoch, and 0 for "has never logged on".
                    last_logon: (u.last_logon != 0)
                        .then(|| chrono::DateTime::from_timestamp(u.last_logon as i64, 0))
                        .flatten()
                        .map(|t| t.with_timezone(&chrono::Local)),
                    username: u.name,
                    full_name: u.full_name,
                    ..Default::default()
                })
                .collect(),
        );
    }

    let (success, output, _e) = command::powershell_query(
        "Get-LocalUser | Select-Object Name, FullName, Enabled, PasswordRequired, \
         PasswordNeverExpires, LastLogon | ConvertTo-Csv -NoTypeInformation",
    )
    .await;
    if !success || output.is_empty() {
        return None;
    }

    Some(
        output
            .split(['\r', '\n'])
            .filter(|l| !l.is_empty())
            .skip(1)
            .filter_map(parse_account_from_csv)
            .collect(),
    )
}

/// Turn one `Get-LocalUser | ConvertTo-Csv` row into an [`AccountInfo`].
///
/// Only reached when the Windows API is unavailable.
fn parse_account_from_csv(line: &str) -> Option<AccountInfo> {
    let values = crate::tasks::parse_csv_line(line);
    if values.len() < 3 {
        return None;
    }
    let field = |index: usize| {
        values
            .get(index)
            .map(|v| v.trim().trim_matches('"').to_string())
            .unwrap_or_default()
    };
    let flag = |index: usize| field(index).eq_ignore_ascii_case("True");

    let username = field(0);
    if username.is_empty() {
        return None;
    }
    Some(AccountInfo {
        username,
        full_name: field(1),
        is_enabled: flag(2),
        password_required: flag(3),
        password_never_expires: flag(4),
        last_logon: parse_datetime(&field(5)),
        ..Default::default()
    })
}

/// Read the timestamp PowerShell printed for `LastLogon`.
///
/// Only reached on the fallback path; the API reports the stamp as a number.
fn parse_datetime(value: &str) -> Option<chrono::DateTime<chrono::Local>> {
    use chrono::{DateTime, Local, NaiveDateTime};

    if value.trim().is_empty() {
        return None;
    }
    if let Ok(dt) = DateTime::parse_from_rfc3339(value) {
        return Some(dt.with_timezone(&Local));
    }
    for fmt in [
        "%m/%d/%Y %I:%M:%S %p",
        "%m/%d/%Y %H:%M:%S",
        "%Y-%m-%d %H:%M:%S",
    ] {
        if let Ok(ndt) = NaiveDateTime::parse_from_str(value, fmt) {
            return ndt.and_local_timezone(Local).single();
        }
    }
    None
}

/// One account as the machine currently reports it, or `None` when it does not
/// exist or could not be read.
///
/// The evidence for every account change comes from here, so it goes through
/// [`enumerate_users`] rather than the API directly - that way the proof is read
/// the same way on the fallback path as on the native one.
async fn read_account(username: &str) -> Option<AccountInfo> {
    enumerate_users()
        .await?
        .into_iter()
        .find(|a| a.username.eq_ignore_ascii_case(username))
}

/// Whether an account exists, as evidence text.
async fn read_presence(username: &str) -> Option<String> {
    let users = enumerate_users().await?;
    Some(
        if users
            .iter()
            .any(|a| a.username.eq_ignore_ascii_case(username))
        {
            "present".to_string()
        } else {
            "absent".to_string()
        },
    )
}

/// Set a local account's password.
///
/// The fallback uses PowerShell rather than `net user`: `net` interactively
/// confirms any password longer than 14 characters ("Do you want to continue
/// this operation? (Y/N)"), and these commands run with stdin closed, so the
/// prompt reaches EOF and `net` aborts. Every generated password is longer than
/// that, so every password change failed.
pub async fn set_password(username: &str, password: &str) -> Result<(), String> {
    remediation::apply_unprovable(
        &format!("Account {username}"),
        "a strong password that is not the competition default",
        "wrote a new password into the account database",
        "Windows will not hand a password back. The account database accepted it.",
        || set_password_core(username, password),
    )
    .await
}

async fn set_password_core(username: &str, password: &str) -> Result<(), String> {
    #[cfg(windows)]
    {
        crate::native::users::set_password(username, password)
    }

    #[cfg(not(windows))]
    {
        let script = format!(
            "Set-LocalUser -Name {} -Password (ConvertTo-SecureString {} -AsPlainText -Force)",
            command::ps_quote(username),
            command::ps_quote(password)
        );
        match command::powershell(&script).await {
            (true, _, _) => Ok(()),
            (false, _, error) => Err(describe(error)),
        }
    }
}

/// Create a local account with the given password, and prove it is there.
///
/// There is no API path here: `NetUserAdd` takes a `USER_INFO_1` with a
/// privilege level and account flags to fill in, and `New-LocalUser` already
/// picks sane defaults for both.
pub async fn create_user(username: &str, password: &str) -> Result<(), String> {
    remediation::apply(
        &format!("Account {username}"),
        "present, with a strong password",
        || read_presence(username),
        |s| s == "present",
        "created the account with New-LocalUser",
        || create_user_core(username, password),
    )
    .await
}

async fn create_user_core(username: &str, password: &str) -> Result<(), String> {
    let script = format!(
        "New-LocalUser -Name {} -Password (ConvertTo-SecureString {} -AsPlainText -Force) \
         -AccountNeverExpires -ErrorAction Stop | Out-Null",
        command::ps_quote(username),
        command::ps_quote(password)
    );
    match command::powershell(&script).await {
        (true, _, _) => Ok(()),
        (false, _, error) => Err(describe(error)),
    }
}

/// Delete a local account, and prove it is gone. An account that is already gone
/// is the desired end state, not a failure.
pub async fn delete_user(username: &str) -> Result<(), String> {
    remediation::apply(
        &format!("Account {username}"),
        "deleted",
        || read_presence(username),
        |s| s == "absent",
        "deleted the account",
        || delete_user_core(username),
    )
    .await
}

async fn delete_user_core(username: &str) -> Result<(), String> {
    #[cfg(windows)]
    {
        crate::native::users::delete(username)
    }

    #[cfg(not(windows))]
    {
        match command::execute("net", Some(&format!("user \"{username}\" /delete"))).await {
            (true, _, _) => Ok(()),
            (false, _, error) => Err(describe(error)),
        }
    }
}

/// Enable or disable a local account, and prove the flag took.
pub async fn set_enabled(username: &str, enabled: bool) -> Result<(), String> {
    let wanted = if enabled { "enabled" } else { "disabled" };
    remediation::apply(
        &format!("Account {username}"),
        wanted,
        || async {
            read_account(username)
                .await
                .map(|a| if a.is_enabled { "enabled" } else { "disabled" }.to_string())
        },
        |s| s == wanted,
        if enabled {
            "cleared the account-disabled flag"
        } else {
            "set the account-disabled flag"
        },
        || set_enabled_core(username, enabled),
    )
    .await
}

async fn set_enabled_core(username: &str, enabled: bool) -> Result<(), String> {
    #[cfg(windows)]
    {
        crate::native::users::set_enabled(username, enabled)
    }

    #[cfg(not(windows))]
    {
        let state = if enabled { "yes" } else { "no" };
        match command::execute("net", Some(&format!("user \"{username}\" /active:{state}"))).await {
            (true, _, _) => Ok(()),
            (false, _, error) => Err(describe(error)),
        }
    }
}

/// Subject an account's password to the maximum-age policy, or exempt it, and
/// prove the flag took.
pub async fn set_password_never_expires(username: &str, never_expires: bool) -> Result<(), String> {
    let wanted = if never_expires {
        "exempt from expiry"
    } else {
        "subject to the maximum-age policy"
    };
    remediation::apply(
        &format!("Account {username}"),
        &format!("password {wanted}"),
        || async {
            read_account(username).await.map(|a| {
                if a.password_never_expires {
                    "exempt from expiry"
                } else {
                    "subject to the maximum-age policy"
                }
                .to_string()
            })
        },
        |s| s == wanted,
        if never_expires {
            "set the password-never-expires flag"
        } else {
            "cleared the password-never-expires flag"
        },
        || set_password_never_expires_core(username, never_expires),
    )
    .await
}

async fn set_password_never_expires_core(
    username: &str,
    never_expires: bool,
) -> Result<(), String> {
    #[cfg(windows)]
    {
        crate::native::users::set_password_never_expires(username, never_expires)
    }

    #[cfg(not(windows))]
    {
        let script = format!(
            "Set-LocalUser -Name {} -PasswordNeverExpires ${never_expires}",
            command::ps_quote(username)
        );
        match command::powershell(&script).await {
            (true, _, _) => Ok(()),
            (false, _, error) => Err(describe(error)),
        }
    }
}

/// Clear an account's "no password required" flag, and prove it took.
///
/// There is no `net user` or `*-LocalUser` equivalent - the flag is only
/// reachable through the account database - so the fallback can do nothing but
/// say so.
pub async fn require_password(username: &str) -> Result<(), String> {
    remediation::apply(
        &format!("Account {username}"),
        "a password required to log in",
        || async {
            read_account(username).await.map(|a| {
                if a.password_required {
                    "password required"
                } else {
                    "no password required"
                }
                .to_string()
            })
        },
        |s| s == "password required",
        "cleared the password-not-required flag",
        || require_password_core(username),
    )
    .await
}

async fn require_password_core(username: &str) -> Result<(), String> {
    #[cfg(windows)]
    {
        crate::native::users::require_password(username)
    }

    #[cfg(not(windows))]
    {
        Err(format!(
            "the password-required flag on {username} cannot be set without the Windows API"
        ))
    }
}

/// The local groups an account belongs to, by name.
pub async fn groups_of(username: &str) -> Vec<String> {
    #[cfg(windows)]
    if let Some(groups) = crate::native::accounts::groups_of(username) {
        return groups;
    }

    let (success, output, _e) = command::powershell_query(&format!(
        "(Get-LocalUser {} | Get-LocalGroup).Name",
        command::ps_quote(username)
    ))
    .await;
    if !success || output.is_empty() {
        return Vec::new();
    }
    output
        .split(['\r', '\n'])
        .filter(|l| !l.trim().is_empty())
        .map(|l| l.trim().to_string())
        .collect()
}

/// Does a local group by this name exist? `None` when the question could not be
/// answered, which is not the same as "no".
pub async fn group_exists(group: &str) -> Option<bool> {
    #[cfg(windows)]
    if let Some(answer) = crate::native::accounts::group_exists(group) {
        return Some(answer);
    }

    let (success, output, _e) =
        command::execute("net", Some(&format!("localgroup \"{group}\""))).await;
    if success {
        return Some(true);
    }
    // `net` says so in the console language, so this only holds on an English
    // image - which is the whole reason the API path exists.
    if output.to_lowercase().contains("does not exist") {
        Some(false)
    } else {
        None
    }
}

/// Create a local group, and prove it is there. A group that already exists is
/// the desired end state, not a failure.
pub async fn create_group(group: &str) -> Result<(), String> {
    remediation::apply(
        &format!("Group {group}"),
        "present",
        || async {
            match group_exists(group).await {
                Some(true) => Some("present".to_string()),
                Some(false) => Some("absent".to_string()),
                None => None,
            }
        },
        |s| s == "present",
        "created the local group",
        || create_group_core(group),
    )
    .await
}

async fn create_group_core(group: &str) -> Result<(), String> {
    #[cfg(windows)]
    {
        crate::native::accounts::create_group(group)
    }

    #[cfg(not(windows))]
    {
        match command::execute("net", Some(&format!("localgroup \"{group}\" /add"))).await {
            (true, _, _) => Ok(()),
            (false, _, error) => Err(describe(error)),
        }
    }
}

/// Membership as evidence text, or `None` when it could not be read.
async fn read_membership(username: &str, group: &str) -> Option<String> {
    if groups_of(username)
        .await
        .iter()
        .any(|g| g.eq_ignore_ascii_case(group))
    {
        return Some("a member".to_string());
    }
    // An empty group list from an account that is not there at all is not an
    // answer, and a failed read looks exactly like one - so a negative is only
    // reported for an account that was actually found.
    match read_presence(username).await.as_deref() {
        Some("present") => Some("not a member".to_string()),
        _ => None,
    }
}

/// Add an account to a local group, and prove the membership. Already a member
/// is the desired end state.
pub async fn add_to_group(username: &str, group: &str) -> Result<(), String> {
    remediation::apply(
        &format!("{username} in {group}"),
        "a member",
        || read_membership(username, group),
        |s| s == "a member",
        &format!("added {username} to {group}"),
        || add_to_group_core(username, group),
    )
    .await
}

async fn add_to_group_core(username: &str, group: &str) -> Result<(), String> {
    #[cfg(windows)]
    {
        crate::native::accounts::add_to_group(username, group)
    }

    #[cfg(not(windows))]
    {
        let script = format!(
            "Add-LocalGroupMember -Group {} -Member {}",
            command::ps_quote(group),
            command::ps_quote(username)
        );
        match command::powershell(&script).await {
            (true, _, _) => Ok(()),
            (false, _, error) => {
                let reason = describe(error);
                // Already a member is the desired end state, not a failure.
                if reason.to_lowercase().contains("already a member") {
                    Ok(())
                } else {
                    Err(reason)
                }
            }
        }
    }
}

/// Remove an account from a local group, and prove it is gone. Not a member is
/// the desired end state.
pub async fn remove_from_group(username: &str, group: &str) -> Result<(), String> {
    remediation::apply(
        &format!("{username} in {group}"),
        "not a member",
        || read_membership(username, group),
        |s| s == "not a member",
        &format!("removed {username} from {group}"),
        || remove_from_group_core(username, group),
    )
    .await
}

async fn remove_from_group_core(username: &str, group: &str) -> Result<(), String> {
    #[cfg(windows)]
    {
        crate::native::accounts::remove_from_group(username, group)
    }

    #[cfg(not(windows))]
    {
        let script = format!(
            "Remove-LocalGroupMember -Group {} -Member {}",
            command::ps_quote(group),
            command::ps_quote(username)
        );
        match command::powershell(&script).await {
            (true, _, _) => Ok(()),
            (false, _, error) => Err(describe(error)),
        }
    }
}

/// The reason a shell-out reported, or a stand-in when it reported none.
pub fn describe(error: Option<String>) -> String {
    error
        .map(|e| e.trim().to_string())
        .filter(|e| !e.is_empty())
        .unwrap_or_else(|| "no reason reported".to_string())
}
