//! Registry reads and writes, replacing `reg.exe` and `Set-ItemProperty`.
//!
//! `reg add` costs a process launch per value and reports failure only through
//! an exit code, so the reason a policy did not apply was never available to the
//! caller. It also silently writes to the wrong place under WOW64: a 32-bit
//! process is redirected to `Wow6432Node`, so a hardening value written there
//! has no effect on the 64-bit system it was meant to configure. These calls ask
//! for the 64-bit view explicitly and return the Win32 status.

use super::{from_wide, to_wide};
use windows::core::PCWSTR;
use windows::Win32::Foundation::ERROR_SUCCESS;
use windows::Win32::System::Registry::{
    RegCloseKey, RegCreateKeyExW, RegDeleteValueW, RegOpenKeyExW, RegQueryValueExW, RegSetValueExW,
    HKEY, HKEY_CLASSES_ROOT, HKEY_CURRENT_USER, HKEY_LOCAL_MACHINE, HKEY_USERS, KEY_READ,
    KEY_WOW64_64KEY, KEY_WRITE, REG_DWORD, REG_OPTION_NON_VOLATILE, REG_SZ, REG_VALUE_TYPE,
};

/// Split `HKLM\Path\To\Key` into its hive and remainder, accepting the long and
/// short spellings `reg.exe` accepts.
fn split(full_path: &str) -> Option<(HKEY, String)> {
    let trimmed = full_path.trim().replace('/', "\\");
    let (hive_name, rest) = trimmed.split_once('\\')?;
    let hive = match hive_name.to_ascii_uppercase().as_str() {
        "HKLM" | "HKEY_LOCAL_MACHINE" => HKEY_LOCAL_MACHINE,
        "HKCU" | "HKEY_CURRENT_USER" => HKEY_CURRENT_USER,
        "HKCR" | "HKEY_CLASSES_ROOT" => HKEY_CLASSES_ROOT,
        "HKU" | "HKEY_USERS" => HKEY_USERS,
        _ => return None,
    };
    Some((hive, rest.to_string()))
}

/// Open an existing key for reading, in the 64-bit view.
fn open_read(path: &str) -> Option<(HKEY, HKEY)> {
    let (hive, rest) = split(path)?;
    let wide = to_wide(&rest);
    let mut key = HKEY::default();
    unsafe {
        RegOpenKeyExW(
            hive,
            PCWSTR(wide.as_ptr()),
            Some(0),
            KEY_READ | KEY_WOW64_64KEY,
            &mut key,
        )
        .is_ok()
        .then_some((hive, key))
    }
}

/// Open a key for writing, creating it and any missing parents.
fn open_write(path: &str) -> Result<HKEY, String> {
    let (hive, rest) =
        split(path).ok_or_else(|| format!("unrecognised registry hive in '{path}'"))?;
    let wide = to_wide(&rest);
    let mut key = HKEY::default();

    let status = unsafe {
        RegCreateKeyExW(
            hive,
            PCWSTR(wide.as_ptr()),
            None,
            PCWSTR::null(),
            REG_OPTION_NON_VOLATILE,
            KEY_WRITE | KEY_WOW64_64KEY,
            None,
            &mut key,
            None,
        )
    };

    if status == ERROR_SUCCESS {
        Ok(key)
    } else if status.0 == 5 {
        Err(format!(
            "access denied writing {path} (run as Administrator)"
        ))
    } else {
        Err(format!(
            "could not open or create {path} (Win32 {})",
            status.0
        ))
    }
}

/// Can this process write machine-wide policy?
///
/// Used as the elevation check. It asks the question that actually matters -
/// "can this process change the machine" - rather than inspecting the token for
/// Administrators membership, which is true for an unelevated member of the
/// group whose every write will still be refused.
///
/// The key is opened, never written, and closed immediately, so the probe leaves
/// nothing behind. `Policies\System` is chosen because it is a key the hardening
/// tasks really do write and it always exists.
pub fn can_write_machine_policy() -> bool {
    let path = r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System";
    let wide = to_wide(path);
    let mut key = HKEY::default();

    unsafe {
        let opened = RegOpenKeyExW(
            HKEY_LOCAL_MACHINE,
            PCWSTR(wide.as_ptr()),
            Some(0),
            KEY_WRITE | KEY_WOW64_64KEY,
            &mut key,
        )
        .is_ok();
        if opened {
            let _ = RegCloseKey(key);
        }
        opened
    }
}

/// Open an existing key for writing, in the 64-bit view.
///
/// Unlike [`open_write`] this never creates anything, so a delete against a key
/// that is not there cannot bring the key into existence as a side effect.
fn open_write_existing(path: &str) -> Option<HKEY> {
    let (hive, rest) = split(path)?;
    let wide = to_wide(&rest);
    let mut key = HKEY::default();
    unsafe {
        RegOpenKeyExW(
            hive,
            PCWSTR(wide.as_ptr()),
            Some(0),
            KEY_WRITE | KEY_WOW64_64KEY,
            &mut key,
        )
        .is_ok()
        .then_some(key)
    }
}

/// Does a key exist?
pub fn key_exists(path: &str) -> bool {
    match open_read(path) {
        Some((_hive, key)) => {
            unsafe {
                let _ = RegCloseKey(key);
            }
            true
        }
        None => false,
    }
}

/// Create a key, with no values under it.
pub fn create_key(path: &str) -> Result<(), String> {
    let key = open_write(path)?;
    unsafe {
        let _ = RegCloseKey(key);
    }
    Ok(())
}

fn set_raw(path: &str, name: &str, kind: REG_VALUE_TYPE, data: &[u8]) -> Result<(), String> {
    let key = open_write(path)?;
    let name_wide = to_wide(name);

    let status = unsafe { RegSetValueExW(key, PCWSTR(name_wide.as_ptr()), None, kind, Some(data)) };
    unsafe {
        let _ = RegCloseKey(key);
    }

    if status == ERROR_SUCCESS {
        Ok(())
    } else {
        Err(format!(
            "could not write {path}\\{name} (Win32 {})",
            status.0
        ))
    }
}

/// Write a REG_DWORD, creating the key if needed.
pub fn set_dword(path: &str, name: &str, value: u32) -> Result<(), String> {
    set_raw(path, name, REG_DWORD, &value.to_ne_bytes())
}

/// Write a REG_SZ, creating the key if needed.
pub fn set_string(path: &str, name: &str, value: &str) -> Result<(), String> {
    let wide = to_wide(value);
    let bytes: Vec<u8> = wide.iter().flat_map(|c| c.to_ne_bytes()).collect();
    set_raw(path, name, REG_SZ, &bytes)
}

/// Read a REG_DWORD, or `None` when the key or value is absent.
pub fn get_dword(path: &str, name: &str) -> Option<u32> {
    let (_hive, key) = open_read(path)?;
    let name_wide = to_wide(name);
    let mut kind = REG_VALUE_TYPE::default();
    let mut data = 0u32;
    let mut size = std::mem::size_of::<u32>() as u32;

    let status = unsafe {
        RegQueryValueExW(
            key,
            PCWSTR(name_wide.as_ptr()),
            None,
            Some(&mut kind),
            Some(&mut data as *mut u32 as *mut u8),
            Some(&mut size),
        )
    };
    unsafe {
        let _ = RegCloseKey(key);
    }

    (status == ERROR_SUCCESS && kind == REG_DWORD).then_some(data)
}

/// Read a REG_SZ, or `None` when the key or value is absent.
pub fn get_string(path: &str, name: &str) -> Option<String> {
    let (_hive, key) = open_read(path)?;
    let name_wide = to_wide(name);
    let mut kind = REG_VALUE_TYPE::default();
    let mut size = 0u32;

    unsafe {
        // Size the buffer first, then fill it.
        if RegQueryValueExW(
            key,
            PCWSTR(name_wide.as_ptr()),
            None,
            Some(&mut kind),
            None,
            Some(&mut size),
        ) != ERROR_SUCCESS
            || size == 0
        {
            let _ = RegCloseKey(key);
            return None;
        }

        let mut data = vec![0u8; size as usize];
        let status = RegQueryValueExW(
            key,
            PCWSTR(name_wide.as_ptr()),
            None,
            Some(&mut kind),
            Some(data.as_mut_ptr()),
            Some(&mut size),
        );
        let _ = RegCloseKey(key);

        (status == ERROR_SUCCESS)
            .then(|| from_wide(data.as_ptr() as *const u16))
            .flatten()
    }
}

/// Delete a value. A value that is already absent is the desired end state, not
/// a failure.
pub fn delete_value(path: &str, name: &str) -> Result<(), String> {
    // A key that does not exist holds no value to delete. Opening rather than
    // creating matters here: `open_write` would create the key on the way to
    // deleting nothing out of it.
    let Some(key) = open_write_existing(path) else {
        return Ok(());
    };
    let name_wide = to_wide(name);
    let status = unsafe { RegDeleteValueW(key, PCWSTR(name_wide.as_ptr())) };
    unsafe {
        let _ = RegCloseKey(key);
    }

    // 2 is ERROR_FILE_NOT_FOUND: already gone.
    if status == ERROR_SUCCESS || status.0 == 2 {
        Ok(())
    } else {
        Err(format!(
            "could not delete {path}\\{name} (Win32 {})",
            status.0
        ))
    }
}
