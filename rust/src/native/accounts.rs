//! Local group membership and password policy, read from netapi32.
//!
//! Replaces parsing `net localgroup` and `net accounts`. Besides the language
//! problem described in the module docs, `net localgroup` wraps its member list
//! in a header, a dashed rule and a trailing status sentence, and a caller that
//! substring-searched the whole blob matched the surrounding prose - an account
//! named `admin` matched the word "Administrators" in the header and was treated
//! as an administrator.

use super::{from_wide, to_wide};
use windows::Win32::NetworkManagement::NetManagement::{
    LOCALGROUP_INFO_0, LOCALGROUP_MEMBERS_INFO_3, LOCALGROUP_USERS_INFO_0, MAX_PREFERRED_LENGTH,
    NetApiBufferFree, NetLocalGroupAdd, NetLocalGroupAddMembers, NetLocalGroupDelMembers,
    NetLocalGroupGetInfo, NetLocalGroupGetMembers, NetUserGetLocalGroups, NetUserModalsGet,
    NetUserModalsSet, USER_MODALS_INFO_0, USER_MODALS_INFO_3,
};
use windows::core::{PCWSTR, PWSTR};

const NERR_SUCCESS: u32 = 0;

/// netapi32 reports "never expires" as this age.
const TIMEQ_FOREVER: u32 = u32::MAX;

// Local groups are aliases at the LSA level, so a membership change reports
// "already there" and "not there" with the alias spellings rather than the NERR
// ones. Both are accepted: either way the wanted state already holds.
const ERROR_NO_SUCH_ALIAS: u32 = 1376;
const ERROR_MEMBER_NOT_IN_ALIAS: u32 = 1377;
const ERROR_MEMBER_IN_ALIAS: u32 = 1378;
const ERROR_ALIAS_EXISTS: u32 = 1379;
const NERR_GROUP_NOT_FOUND: u32 = 2220;
const NERR_GROUP_EXISTS: u32 = 2223;
const NERR_USER_IN_GROUP: u32 = 2236;
const NERR_USER_NOT_IN_GROUP: u32 = 2237;

/// The machine password policy, normalised to the units `net accounts` printed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct PasswordPolicyValues {
    pub min_password_length: u32,
    pub max_password_age_days: u32,
    pub min_password_age_days: u32,
    pub password_history_length: u32,
    pub lockout_threshold: u32,
    pub lockout_duration_minutes: u32,
    pub lockout_observation_minutes: u32,
}

/// Members of a local group, by name.
///
/// Returns `None` when the lookup fails, so callers can tell "no members" apart
/// from "could not read the group".
pub fn group_members(group: &str) -> Option<Vec<String>> {
    let wide = to_wide(group);
    let mut buffer: *mut u8 = std::ptr::null_mut();
    let mut read = 0u32;
    let mut total = 0u32;

    unsafe {
        // Level 3 yields LOCALGROUP_MEMBERS_INFO_3, whose one field is the
        // account already rendered as DOMAIN\user - no SID translation needed.
        let status = NetLocalGroupGetMembers(
            PCWSTR::null(),
            PCWSTR(wide.as_ptr()),
            3,
            &mut buffer,
            MAX_PREFERRED_LENGTH,
            &mut read,
            &mut total,
            None,
        );

        if status != NERR_SUCCESS || buffer.is_null() {
            if !buffer.is_null() {
                let _ = NetApiBufferFree(Some(buffer as *mut _));
            }
            return None;
        }

        let entries = buffer as *const LOCALGROUP_MEMBERS_INFO_3;
        let mut members = Vec::with_capacity(read as usize);
        for index in 0..read as usize {
            if let Some(name) = from_wide((*entries.add(index)).lgrmi3_domainandname.0)
                && !name.trim().is_empty()
            {
                members.push(name);
            }
        }

        let _ = NetApiBufferFree(Some(buffer as *mut _));
        Some(members)
    }
}

/// The local groups an account belongs to, by name.
///
/// Returns `None` when the lookup fails. Replaces one `(Get-LocalUser X |
/// Get-LocalGroup).Name` per account - a PowerShell start-up each - with a
/// single call.
pub fn groups_of(username: &str) -> Option<Vec<String>> {
    let wide = to_wide(username);
    let mut buffer: *mut u8 = std::ptr::null_mut();
    let mut read = 0u32;
    let mut total = 0u32;

    unsafe {
        // Level 0 is just the group name. LG_INCLUDE_INDIRECT (1) would add the
        // groups reached through other groups; the tasks ask about direct
        // membership, which is what the cmdlet reported too.
        let status = NetUserGetLocalGroups(
            PCWSTR::null(),
            PCWSTR(wide.as_ptr()),
            0,
            0,
            &mut buffer,
            MAX_PREFERRED_LENGTH,
            &mut read,
            &mut total,
        );

        if status != NERR_SUCCESS || buffer.is_null() {
            if !buffer.is_null() {
                let _ = NetApiBufferFree(Some(buffer as *mut _));
            }
            return None;
        }

        let entries = buffer as *const LOCALGROUP_USERS_INFO_0;
        let groups = (0..read as usize)
            .filter_map(|index| from_wide((*entries.add(index)).lgrui0_name.0))
            .filter(|name| !name.trim().is_empty())
            .collect();

        let _ = NetApiBufferFree(Some(buffer as *mut _));
        Some(groups)
    }
}

/// Does a local group by this name exist?
///
/// Returns `None` when the question could not be answered, which is not the
/// same as "no". The caller used to look for "does not exist" in `net
/// localgroup` output; that string is localised, so on a non-English image the
/// check read every group as already present and the tool created none of them.
pub fn group_exists(group: &str) -> Option<bool> {
    let wide = to_wide(group);
    let mut buffer: *mut u8 = std::ptr::null_mut();

    unsafe {
        // Level 0 is just the name; the status is the whole answer.
        let status = NetLocalGroupGetInfo(PCWSTR::null(), PCWSTR(wide.as_ptr()), 0, &mut buffer);
        if !buffer.is_null() {
            let _ = NetApiBufferFree(Some(buffer as *mut _));
        }
        match status {
            NERR_SUCCESS => Some(true),
            NERR_GROUP_NOT_FOUND | ERROR_NO_SUCH_ALIAS => Some(false),
            _ => None,
        }
    }
}

/// Create a local group.
///
/// A group that already exists is the desired end state, not a failure.
pub fn create_group(group: &str) -> Result<(), String> {
    let mut wide = to_wide(group);
    let info = LOCALGROUP_INFO_0 {
        lgrpi0_name: PWSTR(wide.as_mut_ptr()),
    };

    let status =
        unsafe { NetLocalGroupAdd(PCWSTR::null(), 0, &info as *const _ as *const u8, None) };

    if matches!(
        status,
        NERR_SUCCESS | NERR_GROUP_EXISTS | ERROR_ALIAS_EXISTS
    ) {
        Ok(())
    } else {
        Err(format!("could not create group {group} (Win32 {status})"))
    }
}

/// Add an account to a local group.
///
/// An account that is already a member is the desired end state, not a failure.
pub fn add_to_group(username: &str, group: &str) -> Result<(), String> {
    match change_membership(username, group, true) {
        NERR_SUCCESS | ERROR_MEMBER_IN_ALIAS | NERR_USER_IN_GROUP => Ok(()),
        status => Err(format!(
            "could not add {username} to {group} (Win32 {status})"
        )),
    }
}

/// Remove an account from a local group.
///
/// An account that is not a member is the desired end state, not a failure.
pub fn remove_from_group(username: &str, group: &str) -> Result<(), String> {
    match change_membership(username, group, false) {
        NERR_SUCCESS | ERROR_MEMBER_NOT_IN_ALIAS | NERR_USER_NOT_IN_GROUP => Ok(()),
        status => Err(format!(
            "could not remove {username} from {group} (Win32 {status})"
        )),
    }
}

fn change_membership(username: &str, group: &str, add: bool) -> u32 {
    let group_wide = to_wide(group);
    let mut user_wide = to_wide(username);

    // Level 3 takes the account as DOMAIN\user or a bare local name, so the
    // caller never has to look a SID up.
    let member = LOCALGROUP_MEMBERS_INFO_3 {
        lgrmi3_domainandname: PWSTR(user_wide.as_mut_ptr()),
    };
    let buffer = &member as *const _ as *const u8;

    unsafe {
        if add {
            NetLocalGroupAddMembers(PCWSTR::null(), PCWSTR(group_wide.as_ptr()), 3, buffer, 1)
        } else {
            NetLocalGroupDelMembers(PCWSTR::null(), PCWSTR(group_wide.as_ptr()), 3, buffer, 1)
        }
    }
}

/// The machine's password and lockout policy.
///
/// Returns `None` when the lookup fails.
pub fn password_policy() -> Option<PasswordPolicyValues> {
    let mut buffer: *mut u8 = std::ptr::null_mut();

    let mut policy = unsafe {
        // Level 0 is the password half of the user modals.
        let status = NetUserModalsGet(PCWSTR::null(), 0, &mut buffer);
        if status != NERR_SUCCESS || buffer.is_null() {
            if !buffer.is_null() {
                let _ = NetApiBufferFree(Some(buffer as *mut _));
            }
            return None;
        }

        let info = buffer as *const USER_MODALS_INFO_0;
        let values = PasswordPolicyValues {
            min_password_length: (*info).usrmod0_min_passwd_len,
            max_password_age_days: to_days((*info).usrmod0_max_passwd_age),
            min_password_age_days: to_days((*info).usrmod0_min_passwd_age),
            password_history_length: (*info).usrmod0_password_hist_len,
            ..Default::default()
        };
        let _ = NetApiBufferFree(Some(buffer as *mut _));
        values
    };

    // Lockout lives at a different modals level, so it needs a second call. A
    // failure there leaves the password half usable rather than losing both.
    if let Some((threshold, duration, observation)) = lockout_policy() {
        policy.lockout_threshold = threshold;
        policy.lockout_duration_minutes = duration;
        policy.lockout_observation_minutes = observation;
    }

    Some(policy)
}

fn lockout_policy() -> Option<(u32, u32, u32)> {
    let mut buffer: *mut u8 = std::ptr::null_mut();
    unsafe {
        // Level 3 is the lockout half of the user modals.
        let status = NetUserModalsGet(PCWSTR::null(), 3, &mut buffer);
        if status != NERR_SUCCESS || buffer.is_null() {
            if !buffer.is_null() {
                let _ = NetApiBufferFree(Some(buffer as *mut _));
            }
            return None;
        }

        let info = buffer as *const USER_MODALS_INFO_3;
        let values = (
            (*info).usrmod3_lockout_threshold,
            to_minutes((*info).usrmod3_lockout_duration),
            to_minutes((*info).usrmod3_lockout_observation_window),
        );
        let _ = NetApiBufferFree(Some(buffer as *mut _));
        Some(values)
    }
}

/// Write a single-field user-modals level.
///
/// Levels 1001 to 1005 each take a struct whose only field is a `u32`, so the
/// address of a local `u32` is the whole structure. Setting one of those leaves
/// the rest of the policy untouched, which writing level 0 would not.
fn set_modals_u32(level: u32, value: u32) -> Result<(), String> {
    let mut value = value;
    let status = unsafe {
        NetUserModalsSet(
            PCWSTR::null(),
            level,
            &mut value as *mut u32 as *const u8,
            None,
        )
    };

    if status == NERR_SUCCESS {
        Ok(())
    } else {
        Err(format!(
            "could not write the password policy (Win32 {status})"
        ))
    }
}

/// Set the minimum password length, in characters.
pub fn set_min_password_length(characters: u32) -> Result<(), String> {
    set_modals_u32(1001, characters)
}

/// Set the maximum password age. Zero means "never expires".
pub fn set_max_password_age_days(days: u32) -> Result<(), String> {
    set_modals_u32(
        1002,
        if days == 0 {
            TIMEQ_FOREVER
        } else {
            days * 86_400
        },
    )
}

/// Set the minimum password age, in days.
pub fn set_min_password_age_days(days: u32) -> Result<(), String> {
    set_modals_u32(1003, days * 86_400)
}

/// Set how many previous passwords are remembered.
pub fn set_password_history_length(count: u32) -> Result<(), String> {
    set_modals_u32(1005, count)
}

/// Change one part of the lockout policy, leaving the other two as they are.
///
/// Lockout has no single-field level: it is written as a whole at level 3, so
/// the current values are read back first.
fn update_lockout(change: impl FnOnce(&mut USER_MODALS_INFO_3)) -> Result<(), String> {
    let mut buffer: *mut u8 = std::ptr::null_mut();

    unsafe {
        let status = NetUserModalsGet(PCWSTR::null(), 3, &mut buffer);
        if status != NERR_SUCCESS || buffer.is_null() {
            if !buffer.is_null() {
                let _ = NetApiBufferFree(Some(buffer as *mut _));
            }
            return Err(format!(
                "could not read the lockout policy (Win32 {status})"
            ));
        }

        let mut info = *(buffer as *const USER_MODALS_INFO_3);
        let _ = NetApiBufferFree(Some(buffer as *mut _));

        change(&mut info);

        let status = NetUserModalsSet(
            PCWSTR::null(),
            3,
            &info as *const USER_MODALS_INFO_3 as *const u8,
            None,
        );
        if status == NERR_SUCCESS {
            Ok(())
        } else {
            Err(format!(
                "could not write the lockout policy (Win32 {status})"
            ))
        }
    }
}

/// Set how many bad passwords lock an account out. Zero disables lockout.
pub fn set_lockout_threshold(attempts: u32) -> Result<(), String> {
    update_lockout(|info| info.usrmod3_lockout_threshold = attempts)
}

/// Set how long an account stays locked out, in minutes.
pub fn set_lockout_duration_minutes(minutes: u32) -> Result<(), String> {
    update_lockout(|info| {
        info.usrmod3_lockout_duration = minutes * 60;
        // Windows rejects a window longer than the duration, and `net accounts`
        // silently widened one to match the other. Do the same rather than fail.
        if info.usrmod3_lockout_observation_window > info.usrmod3_lockout_duration {
            info.usrmod3_lockout_observation_window = info.usrmod3_lockout_duration;
        }
    })
}

/// Set how long bad attempts are counted for, in minutes.
pub fn set_lockout_observation_minutes(minutes: u32) -> Result<(), String> {
    update_lockout(|info| {
        info.usrmod3_lockout_observation_window = minutes * 60;
        if info.usrmod3_lockout_duration < info.usrmod3_lockout_observation_window {
            info.usrmod3_lockout_duration = info.usrmod3_lockout_observation_window;
        }
    })
}

fn to_days(seconds: u32) -> u32 {
    if seconds == TIMEQ_FOREVER {
        0
    } else {
        seconds / 86_400
    }
}

// `net accounts` reported both lockout spans in minutes, so callers comparing
// against a README figure still see the units they expect.
fn to_minutes(seconds: u32) -> u32 {
    if seconds == TIMEQ_FOREVER {
        0
    } else {
        seconds / 60
    }
}
