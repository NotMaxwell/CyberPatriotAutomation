//! Registry access for the tasks: the Windows API where available, otherwise
//! `reg.exe`.
//!
//! Deciding here rather than at every call site keeps the tasks readable and the
//! fallback in one place, mirroring `RegistryOps` in the C# port.
//!
//! Every write goes through [`crate::remediation`], so the run log holds what
//! the value was meant to be, what was written, and what reading it back
//! afterwards returned.

#[cfg(not(windows))]
use crate::command;
use crate::remediation;

/// Write a REG_DWORD, creating the key if needed, and prove the result.
///
/// `why` is what the value is for, in words - it lands in the run log next to
/// the path, so a reader does not have to know what `fDenyTSConnections` means.
pub async fn set_dword_because(
    key: &str,
    name: &str,
    value: u32,
    why: Option<&str>,
) -> Result<(), String> {
    let intent = match why {
        Some(why) => format!("REG_DWORD = {value} ({why})"),
        None => format!("REG_DWORD = {value}"),
    };
    remediation::apply(
        &format!("{key}\\{name}"),
        &intent,
        || async { get_dword(key, name).await.map(|v| v.to_string()) },
        |state| state == value.to_string(),
        &format!("wrote REG_DWORD {value}"),
        || write_dword(key, name, value),
    )
    .await
}

/// Write a REG_DWORD, creating the key if needed.
pub async fn set_dword(key: &str, name: &str, value: u32) -> Result<(), String> {
    set_dword_because(key, name, value, None).await
}

async fn write_dword(key: &str, name: &str, value: u32) -> Result<(), String> {
    #[cfg(windows)]
    {
        crate::native::registry::set_dword(key, name, value)
    }

    #[cfg(not(windows))]
    {
        let (success, _o, error) = command::execute(
            "reg",
            Some(&format!(
                "add \"{key}\" /v {name} /t REG_DWORD /d {value} /f"
            )),
        )
        .await;
        if success {
            Ok(())
        } else {
            Err(error.unwrap_or_else(|| "reg add failed".to_string()))
        }
    }
}

/// Write a REG_SZ, creating the key if needed, and prove the result.
pub async fn set_string(key: &str, name: &str, value: &str) -> Result<(), String> {
    remediation::apply(
        &format!("{key}\\{name}"),
        &format!("REG_SZ = \"{value}\""),
        || async { get_string(key, name).await },
        |state| state == value,
        &format!("wrote REG_SZ \"{value}\""),
        || write_string(key, name, value),
    )
    .await
}

async fn write_string(key: &str, name: &str, value: &str) -> Result<(), String> {
    #[cfg(windows)]
    {
        crate::native::registry::set_string(key, name, value)
    }

    #[cfg(not(windows))]
    {
        let (success, _o, error) = command::execute(
            "reg",
            Some(&format!(
                "add \"{key}\" /v {name} /t REG_SZ /d \"{value}\" /f"
            )),
        )
        .await;
        if success {
            Ok(())
        } else {
            Err(error.unwrap_or_else(|| "reg add failed".to_string()))
        }
    }
}

/// Create a key, with no values under it.
pub async fn create_key(key: &str) -> Result<(), String> {
    #[cfg(windows)]
    {
        crate::native::registry::create_key(key)
    }

    #[cfg(not(windows))]
    {
        let (success, _o, error) =
            command::execute("reg", Some(&format!("add \"{key}\" /f"))).await;
        if success {
            Ok(())
        } else {
            Err(error.unwrap_or_else(|| "reg add failed".to_string()))
        }
    }
}

/// Delete a value, and prove it is gone. A value that is already absent is the
/// desired end state, not a failure.
pub async fn delete_value(key: &str, name: &str) -> Result<(), String> {
    remediation::apply(
        &format!("{key}\\{name}"),
        "value removed",
        // "absent" is the wanted state, so it has to be a readable one rather
        // than the `None` that means "could not look".
        || async {
            match get_dword(key, name).await {
                Some(value) => Some(value.to_string()),
                None => Some(
                    get_string(key, name)
                        .await
                        .unwrap_or_else(|| "absent".to_string()),
                ),
            }
        },
        |state| state == "absent",
        "deleted the value",
        || remove_value(key, name),
    )
    .await
}

async fn remove_value(key: &str, name: &str) -> Result<(), String> {
    #[cfg(windows)]
    {
        crate::native::registry::delete_value(key, name)
    }

    #[cfg(not(windows))]
    {
        let (success, _o, error) =
            command::execute("reg", Some(&format!("delete \"{key}\" /v {name} /f"))).await;
        if success {
            Ok(())
        } else {
            Err(error.unwrap_or_else(|| "reg delete failed".to_string()))
        }
    }
}

/// Does a key exist? `None` when the question could not be answered.
pub async fn key_exists(key: &str) -> Option<bool> {
    #[cfg(windows)]
    {
        Some(crate::native::registry::key_exists(key))
    }

    #[cfg(not(windows))]
    {
        let (success, _o, _e) = command::execute("reg", Some(&format!("query \"{key}\""))).await;
        Some(success)
    }
}

/// Read a REG_DWORD, or `None` when the key or value is absent.
pub async fn get_dword(key: &str, name: &str) -> Option<u32> {
    #[cfg(windows)]
    {
        crate::native::registry::get_dword(key, name)
    }

    #[cfg(not(windows))]
    {
        let (success, output, _e) =
            command::execute("reg", Some(&format!("query \"{key}\" /v {name}"))).await;
        if !success {
            return None;
        }
        // Parsed by the same helper the tests cover, so the fallback cannot
        // drift away from the tested behaviour.
        parse_reg_dword(&output, name)
    }
}

/// Read a REG_SZ, or `None` when the key or value is absent.
pub async fn get_string(key: &str, name: &str) -> Option<String> {
    #[cfg(windows)]
    {
        crate::native::registry::get_string(key, name)
    }

    #[cfg(not(windows))]
    {
        let (success, output, _e) =
            command::execute("reg", Some(&format!("query \"{key}\" /v {name}"))).await;
        if !success {
            return None;
        }
        parse_reg_string(&output, name)
    }
}

/// Does a REG_DWORD hold an expected value?
pub async fn dword_equals(key: &str, name: &str, expected: u32) -> bool {
    get_dword(key, name).await == Some(expected)
}

/// Read the REG_DWORD value named `name` out of `reg query` output.
///
/// `reg query <key> /v <name>` prints the value on its own indented line:
///
/// ```text
/// HKEY_LOCAL_MACHINE\SOFTWARE\...\System
///     dontdisplaylastusername    REG_DWORD    0x1
/// ```
pub fn parse_reg_dword(output: &str, name: &str) -> Option<u32> {
    for line in output.lines() {
        let fields: Vec<&str> = line.split_whitespace().collect();
        if fields.len() >= 3
            && fields[0].eq_ignore_ascii_case(name)
            && fields[1].eq_ignore_ascii_case("REG_DWORD")
        {
            let raw = fields[2];
            let hex = raw.trim_start_matches("0x").trim_start_matches("0X");
            return u32::from_str_radix(hex, 16)
                .ok()
                .or_else(|| raw.parse().ok());
        }
    }
    None
}

/// Read the REG_SZ value named `name` out of `reg query` output.
///
/// Same shape as [`parse_reg_dword`], except the value may contain spaces, so
/// everything after the type column is the value.
pub fn parse_reg_string(output: &str, name: &str) -> Option<String> {
    for line in output.lines() {
        let fields: Vec<&str> = line.split_whitespace().collect();
        if fields.len() >= 3
            && fields[0].eq_ignore_ascii_case(name)
            && fields[1].eq_ignore_ascii_case("REG_SZ")
        {
            return Some(fields[2..].join(" "));
        }
    }
    None
}
