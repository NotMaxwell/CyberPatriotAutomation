//! Registry access for the tasks: the Windows API where available, otherwise
//! `reg.exe`.
//!
//! Deciding here rather than at every call site keeps the tasks readable and the
//! fallback in one place, mirroring `RegistryOps` in the C# port.

#[cfg(not(windows))]
use crate::command;

/// Write a REG_DWORD, creating the key if needed.
pub async fn set_dword(key: &str, name: &str, value: u32) -> Result<(), String> {
    #[cfg(windows)]
    {
        crate::native::registry::set_dword(key, name, value)
    }

    #[cfg(not(windows))]
    {
        let (success, _o, error) = command::execute(
            "reg",
            Some(&format!("add \"{key}\" /v {name} /t REG_DWORD /d {value} /f")),
        )
        .await;
        if success {
            Ok(())
        } else {
            Err(error.unwrap_or_else(|| "reg add failed".to_string()))
        }
    }
}

/// Write a REG_SZ, creating the key if needed.
pub async fn set_string(key: &str, name: &str, value: &str) -> Result<(), String> {
    #[cfg(windows)]
    {
        crate::native::registry::set_string(key, name, value)
    }

    #[cfg(not(windows))]
    {
        let (success, _o, error) = command::execute(
            "reg",
            Some(&format!("add \"{key}\" /v {name} /t REG_SZ /d \"{value}\" /f")),
        )
        .await;
        if success {
            Ok(())
        } else {
            Err(error.unwrap_or_else(|| "reg add failed".to_string()))
        }
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
            return u32::from_str_radix(hex, 16).ok().or_else(|| raw.parse().ok());
        }
    }
    None
}
