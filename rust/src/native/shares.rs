//! Shared-folder enumeration and removal, read from netapi32.
//!
//! Replaces `net share` and `net share NAME /delete`. Besides the language
//! problem described in the module docs, the delete path had one of its own:
//! `net share NAME /delete` asks "There are open files ... force them closed?
//! (Y/N)" when the share is in use, and with stdout captured that question is
//! never shown, so the tool appears to hang on a keypress that is not coming.
//! `NetShareDel` takes no interest in open handles and returns a status.

use super::{from_wide, to_wide};
use windows::core::PCWSTR;
use windows::Win32::NetworkManagement::NetManagement::{NetApiBufferFree, MAX_PREFERRED_LENGTH};
// The share APIs sit under Storage::FileSystem rather than with the rest of
// netapi32, which is where the Win32 metadata puts them.
use windows::Win32::Storage::FileSystem::{NetShareDel, NetShareEnum, SHARE_INFO_502};

const NERR_SUCCESS: u32 = 0;

/// netapi32's "that share does not exist" status.
const NERR_NET_NAME_NOT_FOUND: u32 = 2310;

/// The names of every share on this machine, including the administrative ones.
///
/// Returns `None` when the enumeration fails, so callers can tell "no shares"
/// apart from "could not read the share list".
pub fn enumerate() -> Option<Vec<String>> {
    let mut buffer: *mut u8 = std::ptr::null_mut();
    let mut read = 0u32;
    let mut total = 0u32;

    unsafe {
        // Level 502 is the full view and needs administrator rights, which the
        // tool already requires for every remediation it performs. A
        // non-elevated run fails here and falls back to `net share`.
        let status = NetShareEnum(
            PCWSTR::null(),
            502,
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

        let entries = buffer as *const SHARE_INFO_502;
        let mut shares = Vec::with_capacity(read as usize);
        for index in 0..read as usize {
            if let Some(name) = from_wide((*entries.add(index)).shi502_netname.0) {
                if !name.trim().is_empty() {
                    shares.push(name);
                }
            }
        }

        let _ = NetApiBufferFree(Some(buffer as *mut _));
        Some(shares)
    }
}

/// Remove a share.
///
/// A share that is already gone is the desired end state, not a failure.
pub fn delete(share: &str) -> Result<(), String> {
    let wide = to_wide(share);
    let status = unsafe { NetShareDel(PCWSTR::null(), PCWSTR(wide.as_ptr()), None) };

    if status == NERR_SUCCESS || status == NERR_NET_NAME_NOT_FOUND {
        Ok(())
    } else {
        Err(format!("could not remove share {share} (Win32 {status})"))
    }
}
