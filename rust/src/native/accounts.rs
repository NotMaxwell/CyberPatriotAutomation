//! Local group membership and password policy, read from netapi32.
//!
//! Replaces parsing `net localgroup` and `net accounts`. Besides the language
//! problem described in the module docs, `net localgroup` wraps its member list
//! in a header, a dashed rule and a trailing status sentence, and a caller that
//! substring-searched the whole blob matched the surrounding prose - an account
//! named `admin` matched the word "Administrators" in the header and was treated
//! as an administrator.

use super::{from_wide, to_wide};
use windows::core::PCWSTR;
use windows::Win32::NetworkManagement::NetManagement::{
    NetApiBufferFree, NetLocalGroupGetMembers, NetUserModalsGet, LOCALGROUP_MEMBERS_INFO_3,
    MAX_PREFERRED_LENGTH, USER_MODALS_INFO_0, USER_MODALS_INFO_3,
};

const NERR_SUCCESS: u32 = 0;

/// netapi32 reports "never expires" as this age.
const TIMEQ_FOREVER: u32 = u32::MAX;

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
            if let Some(name) = from_wide((*entries.add(index)).lgrmi3_domainandname.0) {
                if !name.trim().is_empty() {
                    members.push(name);
                }
            }
        }

        let _ = NetApiBufferFree(Some(buffer as *mut _));
        Some(members)
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
