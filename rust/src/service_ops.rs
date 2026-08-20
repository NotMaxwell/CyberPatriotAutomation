//! Service control for the tasks: the service control manager where available,
//! otherwise `sc.exe` and PowerShell.
//!
//! Deciding here rather than at every call site keeps the tasks readable and the
//! fallback in one place, mirroring `ServiceOps` in the C# port. Every function
//! returns the reason on failure rather than a bare bool, because `sc.exe`'s
//! exit code cannot distinguish "no such service" from "access denied".

#[cfg(not(windows))]
use crate::command;

/// What a service is currently doing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ServiceState {
    /// Not installed on this machine.
    Absent,
    Stopped,
    Running,
    /// Installed, but mid-transition or paused.
    Other,
}

/// The current state of a service.
pub async fn state(name: &str) -> ServiceState {
    #[cfg(windows)]
    {
        match crate::native::services::state(name) {
            crate::native::services::ServiceState::Absent => ServiceState::Absent,
            crate::native::services::ServiceState::Stopped => ServiceState::Stopped,
            crate::native::services::ServiceState::Running => ServiceState::Running,
            crate::native::services::ServiceState::Other => ServiceState::Other,
        }
    }

    #[cfg(not(windows))]
    {
        let (success, output, _e) = command::powershell_query(&format!(
            "Get-Service -Name {} | Select-Object -ExpandProperty Status",
            command::ps_quote(name)
        ))
        .await;
        if !success || output.trim().is_empty() {
            return ServiceState::Absent;
        }
        match output.trim() {
            s if s.eq_ignore_ascii_case("Running") => ServiceState::Running,
            s if s.eq_ignore_ascii_case("Stopped") => ServiceState::Stopped,
            _ => ServiceState::Other,
        }
    }
}

/// Stop a service and anything depending on it. Already stopped, or not
/// installed, is success.
pub async fn stop(name: &str) -> Result<(), String> {
    #[cfg(windows)]
    {
        crate::native::services::stop(name)
    }

    #[cfg(not(windows))]
    {
        // -Force stops dependents too; plain `net stop` would ask about them.
        let (success, _o, error) = command::powershell(&format!(
            "Stop-Service -Name {} -Force",
            command::ps_quote(name)
        ))
        .await;
        if success {
            Ok(())
        } else {
            Err(error.unwrap_or_else(|| "Stop-Service failed".to_string()))
        }
    }
}

/// Start a service. Already running is success.
pub async fn start(name: &str) -> Result<(), String> {
    #[cfg(windows)]
    {
        crate::native::services::start(name)
    }

    #[cfg(not(windows))]
    {
        let (success, _o, error) = command::execute("net", Some(&format!("start \"{name}\""))).await;
        if success {
            Ok(())
        } else {
            Err(error.unwrap_or_else(|| "net start failed".to_string()))
        }
    }
}

/// Disable a service so it does not come back after a reboot. A service that is
/// not installed is not an error - that is already the wanted state.
pub async fn disable(name: &str) -> Result<(), String> {
    #[cfg(windows)]
    {
        crate::native::services::disable(name)
    }

    #[cfg(not(windows))]
    {
        let (success, _o, error) =
            command::execute("sc", Some(&format!("config \"{name}\" start= disabled"))).await;
        if success {
            Ok(())
        } else {
            Err(error.unwrap_or_else(|| "sc config failed".to_string()))
        }
    }
}

/// Set a service to start automatically at boot.
pub async fn set_automatic(name: &str) -> Result<(), String> {
    #[cfg(windows)]
    {
        crate::native::services::set_automatic(name)
    }

    #[cfg(not(windows))]
    {
        let (success, _o, error) =
            command::execute("sc", Some(&format!("config \"{name}\" start= auto"))).await;
        if success {
            Ok(())
        } else {
            Err(error.unwrap_or_else(|| "sc config failed".to_string()))
        }
    }
}
