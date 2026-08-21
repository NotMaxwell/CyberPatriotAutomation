//! Installed-software inventory read from the Windows uninstall registry keys.
//!
//! This replaces `wmic product get name`, which was wrong on three counts. It is
//! deprecated and already disabled by default on current Windows 11 images, so
//! it is on a countdown. It only ever saw MSI-installed products, missing
//! everything installed by an EXE bundle. And, worst for a timed run,
//! enumerating `Win32_Product` makes the installer service reconfigure every
//! installed product, which takes minutes and has been known to re-trigger
//! repairs.
//!
//! The uninstall keys are what Add/Remove Programs itself lists, so this sees
//! strictly more software and returns immediately.

use super::{from_wide, to_wide};
use std::collections::BTreeMap;
use windows::core::PCWSTR;
use windows::Win32::Foundation::ERROR_SUCCESS;
use windows::Win32::System::Registry::{
    RegCloseKey, RegEnumKeyExW, RegOpenKeyExW, RegQueryValueExW, HKEY, HKEY_CURRENT_USER,
    HKEY_LOCAL_MACHINE, KEY_READ, REG_VALUE_TYPE,
};

const UNINSTALL: &str = r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall";
const UNINSTALL_WOW: &str = r"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall";

/// One entry from the uninstall registry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InstalledProgram {
    pub name: String,
    pub version: Option<String>,
    pub publisher: Option<String>,
}

/// Every visible installed program.
///
/// Returns `None` only when no hive could be read at all, so an empty machine
/// stays distinguishable from a failure.
pub fn enumerate() -> Option<Vec<InstalledProgram>> {
    // 64-bit and 32-bit views plus the per-user hive: software installed for a
    // single user never appears under HKLM at all.
    let roots = [
        (HKEY_LOCAL_MACHINE, UNINSTALL),
        (HKEY_LOCAL_MACHINE, UNINSTALL_WOW),
        (HKEY_CURRENT_USER, UNINSTALL),
        (HKEY_CURRENT_USER, UNINSTALL_WOW),
    ];

    // Keyed by name so the same product seen in two views appears once, and
    // sorted for a stable report.
    let mut found: BTreeMap<String, InstalledProgram> = BTreeMap::new();
    let mut read_any = false;

    for (root, path) in roots {
        let Some(key) = open(root, path) else {
            continue;
        };
        read_any = true;

        for subkey_name in subkeys(key) {
            let full = format!("{path}\\{subkey_name}");
            if let Some(subkey) = open(root, &full) {
                if let Some(program) = read_entry(subkey) {
                    found.insert(program.name.clone(), program);
                }
                unsafe {
                    let _ = RegCloseKey(subkey);
                }
            }
        }

        unsafe {
            let _ = RegCloseKey(key);
        }
    }

    read_any.then(|| found.into_values().collect())
}

/// Just the display names, for callers that only match on name.
pub fn enumerate_names() -> Option<Vec<String>> {
    Some(enumerate()?.into_iter().map(|p| p.name).collect())
}

fn open(root: HKEY, path: &str) -> Option<HKEY> {
    let wide = to_wide(path);
    let mut key = HKEY::default();
    unsafe {
        RegOpenKeyExW(root, PCWSTR(wide.as_ptr()), Some(0), KEY_READ, &mut key)
            .is_ok()
            .then_some(key)
    }
}

fn subkeys(key: HKEY) -> Vec<String> {
    let mut names = Vec::new();
    // Registry key names are capped at 255 characters.
    let mut buffer = [0u16; 256];
    let mut index = 0u32;

    loop {
        let mut len = buffer.len() as u32;
        let status = unsafe {
            RegEnumKeyExW(
                key,
                index,
                Some(windows::core::PWSTR(buffer.as_mut_ptr())),
                &mut len,
                None,
                None,
                None,
                None,
            )
        };

        if status != ERROR_SUCCESS {
            break;
        }
        names.push(String::from_utf16_lossy(&buffer[..len as usize]));
        index += 1;
    }

    names
}

fn read_entry(key: HKEY) -> Option<InstalledProgram> {
    let name = string_value(key, "DisplayName")?;
    if name.trim().is_empty() {
        return None;
    }

    // Updates and driver payloads set SystemComponent=1 to stay out of
    // Add/Remove Programs; listing them would bury the real software. Patches
    // point at a parent product rather than being installs in their own right.
    if dword_value(key, "SystemComponent") == Some(1) {
        return None;
    }
    if string_value(key, "ParentKeyName").is_some_and(|p| !p.is_empty()) {
        return None;
    }

    Some(InstalledProgram {
        name: name.trim().to_string(),
        version: string_value(key, "DisplayVersion"),
        publisher: string_value(key, "Publisher"),
    })
}

fn string_value(key: HKEY, value: &str) -> Option<String> {
    let wide = to_wide(value);
    let mut kind = REG_VALUE_TYPE::default();
    let mut size = 0u32;

    unsafe {
        // First call sizes the buffer; the second fills it.
        if RegQueryValueExW(
            key,
            PCWSTR(wide.as_ptr()),
            None,
            Some(&mut kind),
            None,
            Some(&mut size),
        ) != ERROR_SUCCESS
            || size == 0
        {
            return None;
        }

        let mut data = vec![0u8; size as usize];
        if RegQueryValueExW(
            key,
            PCWSTR(wide.as_ptr()),
            None,
            Some(&mut kind),
            Some(data.as_mut_ptr()),
            Some(&mut size),
        ) != ERROR_SUCCESS
        {
            return None;
        }

        from_wide(data.as_ptr() as *const u16)
    }
}

fn dword_value(key: HKEY, value: &str) -> Option<u32> {
    let wide = to_wide(value);
    let mut kind = REG_VALUE_TYPE::default();
    let mut data = 0u32;
    let mut size = std::mem::size_of::<u32>() as u32;

    unsafe {
        (RegQueryValueExW(
            key,
            PCWSTR(wide.as_ptr()),
            None,
            Some(&mut kind),
            Some(&mut data as *mut u32 as *mut u8),
            Some(&mut size),
        ) == ERROR_SUCCESS)
            .then_some(data)
    }
}
