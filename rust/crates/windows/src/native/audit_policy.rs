//! Audit policy through advapi32, instead of `auditpol.exe`.
//!
//! `auditpol /set /category:"Account Logon"` addresses categories by display
//! name, and both the names it accepts and the "No Auditing" text it prints are
//! localised. On a non-English image the set matches nothing and the verify step
//! reads the absence of the English string as "audited", so the tool reports
//! success having configured nothing.
//!
//! The category GUIDs below are fixed in `ntsecapi.h` and identical on every
//! Windows install in every language, and the API reports state as flags, so
//! nothing here depends on the console language.

use super::from_wide;
use windows::Win32::Foundation::{ERROR_NOT_ALL_ASSIGNED, HANDLE};
use windows::Win32::Security::Authentication::Identity::{
    AUDIT_POLICY_INFORMATION, AuditEnumerateSubCategories, AuditFree, AuditLookupSubCategoryNameW,
    AuditQuerySystemPolicy, AuditSetSystemPolicy,
};
use windows::Win32::Security::{
    AdjustTokenPrivileges, LUID_AND_ATTRIBUTES, LookupPrivilegeValueW, SE_PRIVILEGE_ENABLED,
    TOKEN_ADJUST_PRIVILEGES, TOKEN_PRIVILEGES, TOKEN_QUERY,
};
use windows::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};
use windows::core::{GUID, PCWSTR, PWSTR};

const POLICY_AUDIT_EVENT_SUCCESS: u32 = 0x1;
const POLICY_AUDIT_EVENT_FAILURE: u32 = 0x2;

/// How one subcategory is currently audited.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SubcategoryState {
    pub name: String,
    pub success: bool,
    pub failure: bool,
}

impl SubcategoryState {
    /// Neither success nor failure events are being recorded.
    pub fn is_unaudited(&self) -> bool {
        !self.success && !self.failure
    }
}

/// The nine top-level audit categories, keyed by the names the task already
/// uses. These names are only keys in our own source; they are never compared
/// against anything Windows prints.
pub const CATEGORIES: [(&str, u128); 9] = [
    ("System", 0x69979848_797a_11d9_bed3_505054503030),
    ("Logon/Logoff", 0x69979849_797a_11d9_bed3_505054503030),
    ("Object Access", 0x6997984a_797a_11d9_bed3_505054503030),
    ("Privilege Use", 0x6997984b_797a_11d9_bed3_505054503030),
    ("Detailed Tracking", 0x6997984c_797a_11d9_bed3_505054503030),
    ("Policy Change", 0x6997984d_797a_11d9_bed3_505054503030),
    ("Account Management", 0x6997984e_797a_11d9_bed3_505054503030),
    ("DS Access", 0x6997984f_797a_11d9_bed3_505054503030),
    ("Account Logon", 0x69979850_797a_11d9_bed3_505054503030),
];

/// The GUID for a category name, if it is one of the nine.
pub fn category_guid(name: &str) -> Option<GUID> {
    CATEGORIES
        .iter()
        .find(|(known, _)| known.eq_ignore_ascii_case(name))
        .map(|(_, bits)| GUID::from_u128(*bits))
}

/// Every subcategory GUID under a category.
fn subcategories(category: &GUID) -> Option<Vec<GUID>> {
    let mut array: *mut GUID = std::ptr::null_mut();
    let mut count = 0u32;

    unsafe {
        if !AuditEnumerateSubCategories(Some(category), false, &mut array, &mut count)
            || array.is_null()
        {
            return None;
        }
        let found = std::slice::from_raw_parts(array, count as usize).to_vec();
        AuditFree(array as *mut _);
        (!found.is_empty()).then_some(found)
    }
}

/// The display name of a subcategory, falling back to its GUID.
fn subcategory_name(subcategory: &GUID) -> String {
    let mut name = PWSTR::null();
    unsafe {
        if AuditLookupSubCategoryNameW(subcategory, &mut name) && !name.is_null() {
            let text = from_wide(name.0).unwrap_or_else(|| format!("{subcategory:?}"));
            AuditFree(name.0 as *mut _);
            text
        } else {
            format!("{subcategory:?}")
        }
    }
}

/// Current auditing state for every subcategory of a category.
///
/// Returns `None` when the category is unknown or the query fails, so "could not
/// read" stays distinguishable from "nothing is audited".
pub fn query(category: &GUID) -> Option<Vec<SubcategoryState>> {
    let subs = subcategories(category)?;
    let mut policies: *mut AUDIT_POLICY_INFORMATION = std::ptr::null_mut();

    unsafe {
        if !AuditQuerySystemPolicy(&subs, &mut policies) || policies.is_null() {
            return None;
        }

        let mut states = Vec::with_capacity(subs.len());
        for index in 0..subs.len() {
            let entry = &*policies.add(index);
            states.push(SubcategoryState {
                name: subcategory_name(&entry.AuditSubCategoryGuid),
                success: entry.AuditingInformation & POLICY_AUDIT_EVENT_SUCCESS != 0,
                failure: entry.AuditingInformation & POLICY_AUDIT_EVENT_FAILURE != 0,
            });
        }

        AuditFree(policies as *mut _);
        Some(states)
    }
}

/// Turn on success and failure auditing for every subcategory of a category.
///
/// Returns the number of subcategories set, or the reason it could not be done.
pub fn enable_success_and_failure(category: &GUID) -> Result<usize, String> {
    enable_security_privilege()?;

    let subs = subcategories(category)
        .ok_or_else(|| "no subcategories reported for this category".to_string())?;

    let policies: Vec<AUDIT_POLICY_INFORMATION> = subs
        .iter()
        .map(|sub| AUDIT_POLICY_INFORMATION {
            AuditSubCategoryGuid: *sub,
            AuditCategoryGuid: *category,
            AuditingInformation: POLICY_AUDIT_EVENT_SUCCESS | POLICY_AUDIT_EVENT_FAILURE,
        })
        .collect();

    unsafe {
        if AuditSetSystemPolicy(&policies) {
            Ok(policies.len())
        } else {
            Err(format!(
                "AuditSetSystemPolicy failed ({})",
                std::io::Error::last_os_error()
            ))
        }
    }
}

/// `AuditSetSystemPolicy` needs `SeSecurityPrivilege` present *and* enabled.
///
/// An elevated token carries it disabled by default, so it has to be switched on
/// explicitly - which is what `auditpol.exe` does internally.
fn enable_security_privilege() -> Result<(), String> {
    unsafe {
        let mut token = HANDLE::default();
        OpenProcessToken(
            GetCurrentProcess(),
            TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY,
            &mut token,
        )
        .map_err(|_| "could not open the process token".to_string())?;

        let name: Vec<u16> = super::to_wide("SeSecurityPrivilege");
        let mut luid = Default::default();
        LookupPrivilegeValueW(PCWSTR::null(), PCWSTR(name.as_ptr()), &mut luid)
            .map_err(|_| "SeSecurityPrivilege is not available to this account".to_string())?;

        let privileges = TOKEN_PRIVILEGES {
            PrivilegeCount: 1,
            Privileges: [LUID_AND_ATTRIBUTES {
                Luid: luid,
                Attributes: SE_PRIVILEGE_ENABLED,
            }],
        };

        AdjustTokenPrivileges(token, false, Some(&privileges), 0, None, None)
            .map_err(|_| "could not enable SeSecurityPrivilege".to_string())?;

        // AdjustTokenPrivileges reports success even when it enabled nothing, so
        // the real answer is in the last error.
        if std::io::Error::last_os_error().raw_os_error() == Some(ERROR_NOT_ALL_ASSIGNED.0 as i32) {
            return Err("SeSecurityPrivilege was not granted (run as Administrator)".to_string());
        }
        Ok(())
    }
}
