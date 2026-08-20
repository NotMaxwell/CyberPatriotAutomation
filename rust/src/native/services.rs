//! Service control through the service control manager, replacing `sc.exe`,
//! `net start`/`net stop` and `Stop-Service`.
//!
//! `net stop` asks "Do you want to continue this operation? (Y/N)" when a
//! service has dependents; stdin is `/dev/null` here so it reaches EOF and
//! aborts, having stopped nothing, silently. `sc config` reports failure only
//! through an exit code, so "no such service" and "access denied" look alike.
//! Here the dependents are enumerated and stopped explicitly, so nothing
//! prompts, and every failure carries its Win32 error.

use super::to_wide;
use windows::core::PCWSTR;
use windows::Win32::System::Services::{
    ChangeServiceConfigW, CloseServiceHandle, ControlService, EnumDependentServicesW,
    OpenSCManagerW, OpenServiceW, QueryServiceStatusEx, StartServiceW, ENUM_SERVICE_STATE,
    ENUM_SERVICE_STATUSW, ENUM_SERVICE_TYPE, SC_HANDLE, SC_STATUS_PROCESS_INFO, SERVICE_ERROR,
    SERVICE_AUTO_START, SERVICE_DISABLED, SERVICE_START_TYPE, SERVICE_STATUS,
    SERVICE_STATUS_PROCESS, SERVICE_RUNNING, SERVICE_STOPPED,
};

const SC_MANAGER_CONNECT: u32 = 0x0001;
const SERVICE_QUERY_STATUS: u32 = 0x0004;
const SERVICE_ENUMERATE_DEPENDENTS: u32 = 0x0008;
const SERVICE_START_ACCESS: u32 = 0x0010;
const SERVICE_STOP_ACCESS: u32 = 0x0020;
const SERVICE_CHANGE_CONFIG: u32 = 0x0002;
const SERVICE_CONTROL_STOP: u32 = 0x0001;

const ERROR_SERVICE_DOES_NOT_EXIST: u32 = 1060;

/// Leave a ChangeServiceConfig field at its existing value.
const SERVICE_NO_CHANGE: u32 = 0xFFFF_FFFF;

/// How long to wait for a service to reach the stopped state.
const STOP_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(30);

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

/// An open SCM or service handle that closes itself.
struct Handle(SC_HANDLE);

impl Drop for Handle {
    fn drop(&mut self) {
        if !self.0.is_invalid() {
            unsafe {
                let _ = CloseServiceHandle(self.0);
            }
        }
    }
}

fn last_error() -> String {
    std::io::Error::last_os_error().to_string()
}

fn manager() -> Result<Handle, String> {
    unsafe {
        OpenSCManagerW(PCWSTR::null(), PCWSTR::null(), SC_MANAGER_CONNECT)
            .map(Handle)
            .map_err(|_| format!("could not open the service control manager ({})", last_error()))
    }
}

/// Open a service, distinguishing "not installed" from a real failure.
fn open(manager: &Handle, name: &str, access: u32) -> Result<Option<Handle>, String> {
    let wide = to_wide(name);
    unsafe {
        match OpenServiceW(manager.0, PCWSTR(wide.as_ptr()), access) {
            Ok(handle) => Ok(Some(Handle(handle))),
            Err(e) if e.code().0 as u32 & 0xFFFF == ERROR_SERVICE_DOES_NOT_EXIST => Ok(None),
            Err(_) => {
                let os = std::io::Error::last_os_error();
                if os.raw_os_error() == Some(ERROR_SERVICE_DOES_NOT_EXIST as i32) {
                    Ok(None)
                } else {
                    Err(format!("could not open service {name} ({os})"))
                }
            }
        }
    }
}

fn query_state(service: &Handle) -> ServiceState {
    let mut buffer = [0u8; std::mem::size_of::<SERVICE_STATUS_PROCESS>()];
    let mut needed = 0u32;

    unsafe {
        if QueryServiceStatusEx(
            service.0,
            SC_STATUS_PROCESS_INFO,
            Some(&mut buffer),
            &mut needed,
        )
        .is_err()
        {
            return ServiceState::Other;
        }

        let status = &*(buffer.as_ptr() as *const SERVICE_STATUS_PROCESS);
        match status.dwCurrentState {
            SERVICE_STOPPED => ServiceState::Stopped,
            SERVICE_RUNNING => ServiceState::Running,
            _ => ServiceState::Other,
        }
    }
}

/// The current state of a service.
pub fn state(name: &str) -> ServiceState {
    let Ok(scm) = manager() else {
        return ServiceState::Absent;
    };
    match open(&scm, name, SERVICE_QUERY_STATUS) {
        Ok(Some(service)) => query_state(&service),
        _ => ServiceState::Absent,
    }
}

/// Names of the services depending on this one.
fn dependents(service: &Handle) -> Vec<String> {
    let mut needed = 0u32;
    let mut returned = 0u32;

    unsafe {
        // Sizing call: expected to fail with the required buffer size.
        let _ = EnumDependentServicesW(
            service.0,
            ENUM_SERVICE_STATE(1), // SERVICE_ACTIVE
            None,
            0,
            &mut needed,
            &mut returned,
        );
        if needed == 0 {
            return Vec::new();
        }

        let mut buffer = vec![0u8; needed as usize];
        if EnumDependentServicesW(
            service.0,
            ENUM_SERVICE_STATE(1),
            Some(buffer.as_mut_ptr() as *mut ENUM_SERVICE_STATUSW),
            needed,
            &mut needed,
            &mut returned,
        )
        .is_err()
        {
            return Vec::new();
        }

        let entries = buffer.as_ptr() as *const ENUM_SERVICE_STATUSW;
        (0..returned as usize)
            .filter_map(|i| super::from_wide((*entries.add(i)).lpServiceName.0))
            .filter(|n| !n.is_empty())
            .collect()
    }
}

/// Stop a service and anything depending on it.
///
/// Already stopped, or not installed, is success.
pub fn stop(name: &str) -> Result<(), String> {
    let scm = manager()?;
    let Some(service) = open(
        &scm,
        name,
        SERVICE_STOP_ACCESS | SERVICE_QUERY_STATUS | SERVICE_ENUMERATE_DEPENDENTS,
    )?
    else {
        return Ok(());
    };

    // Dependents first: this is what `net stop` would have asked permission for.
    for dependent in dependents(&service) {
        stop(&dependent)
            .map_err(|e| format!("could not stop {dependent}, which depends on {name}: {e}"))?;
    }

    if query_state(&service) == ServiceState::Stopped {
        return Ok(());
    }

    let mut status = SERVICE_STATUS::default();
    unsafe {
        ControlService(service.0, SERVICE_CONTROL_STOP, &mut status)
            .map_err(|_| format!("could not stop {name} ({})", last_error()))?;
    }

    let deadline = std::time::Instant::now() + STOP_TIMEOUT;
    while std::time::Instant::now() < deadline {
        if query_state(&service) == ServiceState::Stopped {
            return Ok(());
        }
        std::thread::sleep(std::time::Duration::from_millis(250));
    }
    Err(format!(
        "{name} did not reach the stopped state within {}s",
        STOP_TIMEOUT.as_secs()
    ))
}

/// Start a service. Already running is success.
pub fn start(name: &str) -> Result<(), String> {
    let scm = manager()?;
    let Some(service) = open(&scm, name, SERVICE_START_ACCESS | SERVICE_QUERY_STATUS)? else {
        return Err(format!("service {name} is not installed"));
    };

    if query_state(&service) == ServiceState::Running {
        return Ok(());
    }

    unsafe {
        StartServiceW(service.0, None)
            .map_err(|_| format!("could not start {name} ({})", last_error()))
    }
}

fn set_start_type(name: &str, start_type: SERVICE_START_TYPE) -> Result<(), String> {
    let scm = manager()?;
    // Not installed is not an error: there is nothing to configure, which is
    // already the state the caller wanted.
    let Some(service) = open(&scm, name, SERVICE_CHANGE_CONFIG)? else {
        return Ok(());
    };

    unsafe {
        ChangeServiceConfigW(
            service.0,
            ENUM_SERVICE_TYPE(SERVICE_NO_CHANGE),
            start_type,
            SERVICE_ERROR(SERVICE_NO_CHANGE),
            PCWSTR::null(),
            PCWSTR::null(),
            None,
            PCWSTR::null(),
            PCWSTR::null(),
            PCWSTR::null(),
            PCWSTR::null(),
        )
        .map_err(|_| format!("could not set the start type of {name} ({})", last_error()))
    }
}

/// Disable a service so it does not come back after a reboot.
pub fn disable(name: &str) -> Result<(), String> {
    set_start_type(name, SERVICE_DISABLED)
}

/// Set a service to start automatically at boot.
pub fn set_automatic(name: &str) -> Result<(), String> {
    set_start_type(name, SERVICE_AUTO_START)
}
