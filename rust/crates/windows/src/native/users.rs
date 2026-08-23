//! Local account changes, written through netapi32.
//!
//! Replaces `net user` and the `*-LocalUser` cmdlets. Both shell paths failed in
//! their own way: `net user` interactively confirms any password longer than 14
//! characters ("Do you want to continue this operation? (Y/N)") and these
//! commands run with stdin closed, so the prompt reaches EOF and `net` aborts -
//! every generated password is longer than that, so every password change
//! failed. The cmdlets have no prompt but cost a PowerShell start-up per
//! account and report failure as a formatted English error record rather than a
//! status code.

use super::{from_wide, to_wide};
use windows::Win32::NetworkManagement::NetManagement::{
    FILTER_NORMAL_ACCOUNT, MAX_PREFERRED_LENGTH, NetApiBufferFree, NetUserDel, NetUserEnum,
    NetUserGetInfo, NetUserSetInfo, USER_INFO_1, USER_INFO_3,
};
use windows::core::PCWSTR;

const NERR_SUCCESS: u32 = 0;

/// netapi32's "that account does not exist" status.
const NERR_USER_NOT_FOUND: u32 = 2221;

/// The account is disabled and cannot be logged into.
pub const UF_ACCOUNTDISABLE: u32 = 0x0002;

/// No password is required to log into the account.
pub const UF_PASSWD_NOTREQD: u32 = 0x0020;

/// The account's password is exempt from the maximum-age policy.
pub const UF_DONT_EXPIRE_PASSWD: u32 = 0x1_0000;

/// One local account, as the account database holds it.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct LocalUser {
    pub name: String,
    pub full_name: String,
    pub comment: String,
    /// The `UF_*` bits; see the constants above.
    pub flags: u32,
    /// Seconds since the Unix epoch, or 0 for "never logged on".
    pub last_logon: u32,
}

impl LocalUser {
    pub fn is_enabled(&self) -> bool {
        self.flags & UF_ACCOUNTDISABLE == 0
    }

    pub fn password_required(&self) -> bool {
        self.flags & UF_PASSWD_NOTREQD == 0
    }

    pub fn password_never_expires(&self) -> bool {
        self.flags & UF_DONT_EXPIRE_PASSWD != 0
    }
}

/// Every ordinary local account on this machine.
///
/// Returns `None` when the enumeration fails, so callers can tell "no accounts"
/// apart from "could not read the account list". Replaces `Get-LocalUser |
/// ConvertTo-Csv` and the CSV parser over its output, which cost a PowerShell
/// start-up and reported `Enabled` as an English word.
pub fn enumerate() -> Option<Vec<LocalUser>> {
    let mut buffer: *mut u8 = std::ptr::null_mut();
    let mut read = 0u32;
    let mut total = 0u32;

    unsafe {
        // Level 3 carries the flags and the last-logon stamp alongside the
        // names. FILTER_NORMAL_ACCOUNT leaves out the machine and trust
        // accounts, which are not accounts a competitor can act on.
        let status = NetUserEnum(
            PCWSTR::null(),
            3,
            FILTER_NORMAL_ACCOUNT,
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

        let entries = buffer as *const USER_INFO_3;
        let mut users = Vec::with_capacity(read as usize);
        for index in 0..read as usize {
            let entry = &*entries.add(index);
            let Some(name) = from_wide(entry.usri3_name.0) else {
                continue;
            };
            if name.is_empty() {
                continue;
            }
            users.push(LocalUser {
                name,
                full_name: from_wide(entry.usri3_full_name.0).unwrap_or_default(),
                comment: from_wide(entry.usri3_comment.0).unwrap_or_default(),
                flags: entry.usri3_flags.0,
                last_logon: entry.usri3_last_logon,
            });
        }

        let _ = NetApiBufferFree(Some(buffer as *mut _));
        Some(users)
    }
}

/// An account's `UF_*` flags, or `None` when the account does not exist or
/// could not be read.
pub fn flags(username: &str) -> Option<u32> {
    let wide = to_wide(username);
    let mut buffer: *mut u8 = std::ptr::null_mut();

    unsafe {
        // Level 1 is the general account view; its flags field carries every
        // UF_* bit the tasks care about.
        let status = NetUserGetInfo(PCWSTR::null(), PCWSTR(wide.as_ptr()), 1, &mut buffer);
        if status != NERR_SUCCESS || buffer.is_null() {
            if !buffer.is_null() {
                let _ = NetApiBufferFree(Some(buffer as *mut _));
            }
            return None;
        }

        // The field is a newtype over the u32 the UF_* constants live in.
        let value = (*(buffer as *const USER_INFO_1)).usri1_flags.0;
        let _ = NetApiBufferFree(Some(buffer as *mut _));
        Some(value)
    }
}

/// Does a local account by this name exist?
pub fn exists(username: &str) -> bool {
    flags(username).is_some()
}

/// Replace an account's `UF_*` flags wholesale.
fn set_flags(username: &str, value: u32) -> Result<(), String> {
    let wide = to_wide(username);
    // Level 1008 takes USER_INFO_1008, whose only field is the flags word, so
    // the address of a local u32 is the whole structure. Setting only this level
    // leaves the rest of the account untouched - level 1 would rewrite the home
    // directory, comment and script path as well.
    let mut value = value;
    let status = unsafe {
        NetUserSetInfo(
            PCWSTR::null(),
            PCWSTR(wide.as_ptr()),
            1008,
            &mut value as *mut u32 as *const u8,
            None,
        )
    };

    if status == NERR_SUCCESS {
        Ok(())
    } else {
        Err(format!("could not update {username} (Win32 {status})"))
    }
}

/// Turn one `UF_*` bit on or off, leaving the rest as they were.
fn set_flag(username: &str, flag: u32, on: bool) -> Result<(), String> {
    let Some(current) = flags(username) else {
        return Err(format!("could not read the account flags of {username}"));
    };

    let updated = if on { current | flag } else { current & !flag };

    // Already in the wanted state: nothing to write, and writing anyway would
    // fail on accounts the caller has no permission to change.
    if updated == current {
        Ok(())
    } else {
        set_flags(username, updated)
    }
}

/// Subject an account's password to the maximum-age policy, or exempt it.
pub fn set_password_never_expires(username: &str, never_expires: bool) -> Result<(), String> {
    set_flag(username, UF_DONT_EXPIRE_PASSWD, never_expires)
}

/// Enable or disable an account.
pub fn set_enabled(username: &str, enabled: bool) -> Result<(), String> {
    // The flag is stored the other way round: it marks the account disabled.
    set_flag(username, UF_ACCOUNTDISABLE, !enabled)
}

/// Require a password on an account that was set up without one.
pub fn require_password(username: &str) -> Result<(), String> {
    set_flag(username, UF_PASSWD_NOTREQD, false)
}

/// Set an account's password.
///
/// This is the call `net user USER PASSWORD` could not make, because it refuses
/// a password over 14 characters without an answer to an interactive prompt.
pub fn set_password(username: &str, password: &str) -> Result<(), String> {
    let user_wide = to_wide(username);
    let mut password_wide = to_wide(password);

    // Level 1003 takes USER_INFO_1003, whose only field is the password
    // pointer, so the address of a local PWSTR is the whole structure.
    let mut info = windows::core::PWSTR(password_wide.as_mut_ptr());
    let status = unsafe {
        NetUserSetInfo(
            PCWSTR::null(),
            PCWSTR(user_wide.as_ptr()),
            1003,
            &mut info as *mut _ as *const u8,
            None,
        )
    };

    if status == NERR_SUCCESS {
        Ok(())
    } else {
        Err(format!(
            "could not set the password for {username} (Win32 {status})"
        ))
    }
}

/// Delete a local account.
///
/// An account that is already gone is the desired end state, not a failure.
pub fn delete(username: &str) -> Result<(), String> {
    let wide = to_wide(username);
    let status = unsafe { NetUserDel(PCWSTR::null(), PCWSTR(wide.as_ptr())) };

    if status == NERR_SUCCESS || status == NERR_USER_NOT_FOUND {
        Ok(())
    } else {
        Err(format!("could not delete {username} (Win32 {status})"))
    }
}
