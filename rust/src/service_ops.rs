//! Service control for the tasks: the service control manager where available,
//! otherwise `sc.exe` and PowerShell.
//!
//! Deciding here rather than at every call site keeps the tasks readable and the
//! fallback in one place, mirroring `ServiceOps` in the C# port. Every function
//! returns the reason on failure rather than a bare bool, because `sc.exe`'s
//! exit code cannot distinguish "no such service" from "access denied".
//!
//! Every change goes through [`crate::remediation`], so the run log holds what
//! the service was meant to end up as, what was done to it, and what querying it
//! again afterwards returned.

#[cfg(not(windows))]
use crate::command;
use crate::remediation;

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

/// Is a service configured as disabled? `None` when the question could not be
/// answered, which is not the same as "no".
pub async fn is_disabled(name: &str) -> Option<bool> {
    #[cfg(windows)]
    {
        crate::native::services::is_disabled(name)
    }

    #[cfg(not(windows))]
    {
        // `sc qc` prints e.g. "START_TYPE : 4   DISABLED": a number the API
        // returns directly, next to a localised word.
        let (success, output, _e) = command::execute("sc", Some(&format!("qc \"{name}\""))).await;
        if !success {
            return None;
        }
        output
            .lines()
            .find(|l| l.to_uppercase().contains("START_TYPE"))
            .map(|l| l.split_whitespace().any(|f| f == "4"))
    }
}

/// Every installed service, as (name, state) pairs.
///
/// Returns `None` when the list could not be read at all, so "no services" and
/// "could not look" stay distinguishable.
pub async fn enumerate_states() -> Option<Vec<(String, ServiceState)>> {
    #[cfg(windows)]
    {
        crate::native::services::enumerate_states().map(|services| {
            services
                .into_iter()
                .map(|(name, state)| {
                    let state = match state {
                        crate::native::services::ServiceState::Absent => ServiceState::Absent,
                        crate::native::services::ServiceState::Stopped => ServiceState::Stopped,
                        crate::native::services::ServiceState::Running => ServiceState::Running,
                        crate::native::services::ServiceState::Other => ServiceState::Other,
                    };
                    (name, state)
                })
                .collect()
        })
    }

    #[cfg(not(windows))]
    {
        let (success, output, _e) = command::powershell_query(
            "Get-Service | Select-Object Name, Status | ConvertTo-Csv -NoTypeInformation",
        )
        .await;
        if !success {
            return None;
        }
        Some(
            output
                .split(['\r', '\n'])
                .filter(|l| !l.is_empty())
                .skip(1)
                .filter_map(|line| {
                    let fields: Vec<&str> = line.split("\",\"").collect();
                    if fields.len() < 2 {
                        return None;
                    }
                    let name = fields[0].trim().trim_matches('"').trim().to_string();
                    let state = match fields[1].trim().trim_matches('"').trim() {
                        s if s.eq_ignore_ascii_case("Running") => ServiceState::Running,
                        s if s.eq_ignore_ascii_case("Stopped") => ServiceState::Stopped,
                        _ => ServiceState::Other,
                    };
                    (!name.is_empty()).then_some((name, state))
                })
                .collect(),
        )
    }
}

/// Stop a service and anything depending on it, and prove it stopped.
///
/// Already stopped, or not installed, is success.
pub async fn stop(name: &str) -> Result<(), String> {
    remediation::apply(
        &format!("Service {name}"),
        "stopped",
        || async { Some(format!("{:?}", state(name).await)) },
        // Absent is the wanted end state too: a service that is not installed
        // cannot be running.
        |s| s == "Stopped" || s == "Absent",
        "asked the service control manager to stop it, and its dependents first",
        || stop_core(name),
    )
    .await
}

async fn stop_core(name: &str) -> Result<(), String> {
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

/// Start a service, and prove it is running. Already running is success.
pub async fn start(name: &str) -> Result<(), String> {
    remediation::apply(
        &format!("Service {name}"),
        "running",
        || async { Some(format!("{:?}", state(name).await)) },
        |s| s == "Running",
        "asked the service control manager to start it",
        || start_core(name),
    )
    .await
}

async fn start_core(name: &str) -> Result<(), String> {
    #[cfg(windows)]
    {
        crate::native::services::start(name)
    }

    #[cfg(not(windows))]
    {
        let (success, _o, error) =
            command::execute("net", Some(&format!("start \"{name}\""))).await;
        if success {
            Ok(())
        } else {
            Err(error.unwrap_or_else(|| "net start failed".to_string()))
        }
    }
}

/// Disable a service so it does not come back after a reboot, and prove the
/// start type took.
///
/// A service that is not installed is not an error - that is already the wanted
/// state.
pub async fn disable(name: &str) -> Result<(), String> {
    remediation::apply(
        &format!("Service {name}"),
        "start type disabled, so it cannot return after a reboot",
        || read_start_type(name),
        |s| s == "disabled" || s == "not installed",
        "set the start type to disabled",
        || set_start_type(name, true),
    )
    .await
}

/// Set a service to start automatically at boot, and prove the start type took.
pub async fn set_automatic(name: &str) -> Result<(), String> {
    remediation::apply(
        &format!("Service {name}"),
        "start type automatic",
        || read_start_type(name),
        |s| s == "not disabled",
        "set the start type to automatic",
        || set_start_type(name, false),
    )
    .await
}

/// The start type as evidence: "disabled", "not disabled", "not installed", or
/// `None` when it could not be read.
///
/// The service control manager distinguishes automatic from manual, but nothing
/// here acts on that difference, and reporting it would make "already compliant"
/// depend on a distinction the caller did not ask about.
async fn read_start_type(name: &str) -> Option<String> {
    if state(name).await == ServiceState::Absent {
        return Some("not installed".to_string());
    }
    match is_disabled(name).await {
        Some(true) => Some("disabled".to_string()),
        Some(false) => Some("not disabled".to_string()),
        None => None,
    }
}

async fn set_start_type(name: &str, disabled: bool) -> Result<(), String> {
    #[cfg(windows)]
    {
        if disabled {
            crate::native::services::disable(name)
        } else {
            crate::native::services::set_automatic(name)
        }
    }

    #[cfg(not(windows))]
    {
        let start = if disabled { "disabled" } else { "auto" };
        let (success, _o, error) =
            command::execute("sc", Some(&format!("config \"{name}\" start= {start}"))).await;
        if success {
            Ok(())
        } else {
            Err(error.unwrap_or_else(|| "sc config failed".to_string()))
        }
    }
}
