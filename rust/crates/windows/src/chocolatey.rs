//! Package installs and upgrades through Chocolatey.
//!
//! Chocolatey is the default package source for this tool: it is scriptable
//! without a console prompt, it is present on or installable onto every
//! supported image, and its package names are stable across Windows editions.
//! If it is missing it is bootstrapped from the official install script rather
//! than leaving required software uninstalled.
//!
//! The one sharp edge is PATH. The bootstrap adds Chocolatey to the machine
//! PATH, but an already-running process keeps the environment block it started
//! with, so `choco` stays unresolvable in this process until it restarts. Every
//! call therefore resolves the executable by absolute path as well as by name.

use pinnacle_core::command;
use pinnacle_core::ui;
use std::path::PathBuf;
use std::sync::Mutex;
use std::time::Duration;

/// Installs and upgrades routinely outrun the default ceiling.
const PACKAGE_TIMEOUT: Duration = Duration::from_secs(20 * 60);

/// Upgrading everything on a stale image can take far longer.
const UPGRADE_ALL_TIMEOUT: Duration = Duration::from_secs(60 * 60);

const BOOTSTRAP_TIMEOUT: Duration = Duration::from_secs(15 * 60);

const VERSION_TIMEOUT: Duration = Duration::from_secs(60);

/// Exit codes Chocolatey uses for "succeeded, but a reboot is pending".
/// Treating these as failure would report completed installs as failed.
const SUCCESS_EXIT_CODES: [i32; 5] = [0, 1605, 1614, 1641, 3010];

/// Cached resolved path, so detection runs once per run.
///
/// Only ever held across a plain read or write - never across an await - so a
/// blocking mutex is the right primitive here.
static RESOLVED: Mutex<Option<String>> = Mutex::new(None);

fn cached() -> Option<String> {
    RESOLVED.lock().unwrap().clone()
}

fn cache(path: &str) -> String {
    *RESOLVED.lock().unwrap() = Some(path.to_string());
    path.to_string()
}

fn forget() {
    *RESOLVED.lock().unwrap() = None;
}

/// The standard install location, used when PATH is stale.
fn default_path() -> PathBuf {
    let program_data =
        std::env::var("ProgramData").unwrap_or_else(|_| r"C:\ProgramData".to_string());
    PathBuf::from(program_data)
        .join("chocolatey")
        .join("bin")
        .join("choco.exe")
}

/// Locate a usable `choco`, or `None` when it is not installed.
pub async fn resolve() -> Option<String> {
    if let Some(path) = cached() {
        return Some(path);
    }

    // PATH first, so a non-standard install location still works.
    let (on_path, _o, _e) =
        command::execute_with_timeout("choco", Some("--version"), VERSION_TIMEOUT).await;
    if on_path {
        return Some(cache("choco"));
    }

    let absolute = default_path();
    if absolute.is_file() {
        let absolute = absolute.to_string_lossy().into_owned();
        let (works, _o, _e) =
            command::execute_with_timeout(&absolute, Some("--version"), VERSION_TIMEOUT).await;
        if works {
            return Some(cache(&absolute));
        }
    }

    None
}

/// Is Chocolatey already usable?
pub async fn is_available() -> bool {
    resolve().await.is_some()
}

/// Ensure Chocolatey is usable, installing it if absent. Returns `None` on
/// success, or the reason it could not be made available.
pub async fn ensure_available() -> Option<String> {
    if is_available().await {
        return None;
    }

    ui::markup_line("[yellow]Chocolatey not found - installing...[/]");

    // The documented bootstrap. TLS 1.2 is forced because Windows PowerShell
    // 5.1 still offers older protocols that community.chocolatey.org refuses.
    let script = "Set-ExecutionPolicy Bypass -Scope Process -Force; \
         [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12; \
         Invoke-Expression ((New-Object System.Net.WebClient).DownloadString(\
         'https://community.chocolatey.org/install.ps1'))";

    let (ok, _o, error) = command::powershell_with_timeout(script, BOOTSTRAP_TIMEOUT).await;

    // Re-resolve either way: the bootstrap can report a non-zero exit while
    // still having produced a working install, and the fresh binary is only
    // reachable by absolute path in this process.
    forget();
    if is_available().await {
        ui::markup_line("[green]✓ Chocolatey installed[/]");
        return None;
    }

    Some(if ok {
        "the Chocolatey installer completed but choco.exe is still not usable".to_string()
    } else {
        format!(
            "could not install Chocolatey: {}",
            error.unwrap_or_else(|| "no reason reported".to_string())
        )
    })
}

/// Install one package. Returns `None` on success, else the reason.
pub async fn install(package: &str) -> Option<String> {
    run(
        &format!("install {} -y --no-progress --limit-output", quote(package)),
        PACKAGE_TIMEOUT,
    )
    .await
}

/// Upgrade one package. Returns `None` on success, else the reason.
pub async fn upgrade(package: &str) -> Option<String> {
    run(
        &format!("upgrade {} -y --no-progress --limit-output", quote(package)),
        PACKAGE_TIMEOUT,
    )
    .await
}

/// Upgrade every managed package. Returns `None` on success.
pub async fn upgrade_all() -> Option<String> {
    run(
        "upgrade all -y --no-progress --limit-output",
        UPGRADE_ALL_TIMEOUT,
    )
    .await
}

/// Uninstall one package. Returns `None` on success, else the reason.
pub async fn uninstall(package: &str) -> Option<String> {
    run(
        &format!(
            "uninstall {} -y --remove-dependencies --limit-output",
            quote(package)
        ),
        PACKAGE_TIMEOUT,
    )
    .await
}

/// The packages Chocolatey currently manages, or `None` when it cannot be read.
pub async fn list_installed() -> Option<Vec<String>> {
    let choco = resolve().await?;

    let (exit_code, output, _e) = command::execute_for_exit_code(
        &choco,
        Some("list --local-only --limit-output"),
        PACKAGE_TIMEOUT,
    )
    .await;
    if !exit_code.is_some_and(|c| SUCCESS_EXIT_CODES.contains(&c)) {
        return None;
    }

    // --limit-output prints "name|version" per line and nothing else, so there
    // is no banner or summary to skip and no localised text to match.
    Some(
        output
            .lines()
            .filter_map(|line| line.split('|').next())
            .map(str::trim)
            .filter(|name| !name.is_empty())
            .map(str::to_string)
            .collect(),
    )
}

async fn run(arguments: &str, timeout: Duration) -> Option<String> {
    let Some(choco) = resolve().await else {
        return Some("Chocolatey is not installed".to_string());
    };

    let (exit_code, output, error) =
        command::execute_for_exit_code(&choco, Some(arguments), timeout).await;

    let Some(code) = exit_code else {
        return Some(
            error.unwrap_or_else(|| "the Chocolatey command did not complete".to_string()),
        );
    };

    if SUCCESS_EXIT_CODES.contains(&code) {
        return None;
    }

    // Chocolatey reports the useful detail on stdout, not stderr.
    Some(
        error
            .filter(|e| !e.trim().is_empty())
            .map(|e| e.trim().to_string())
            .or_else(|| last_meaningful_line(&output))
            .unwrap_or_else(|| format!("exit code {code}")),
    )
}

fn last_meaningful_line(output: &str) -> Option<String> {
    output
        .lines()
        .map(str::trim)
        .rfind(|l| !l.is_empty())
        .map(str::to_string)
}

/// Quote a package id so a name with a space stays one argument.
fn quote(value: &str) -> String {
    format!("\"{}\"", value.replace('"', "\\\""))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_package_id_with_a_space_stays_one_argument() {
        assert_eq!(quote("Some Package"), "\"Some Package\"");
    }

    #[test]
    fn an_embedded_quote_is_escaped_rather_than_ending_the_argument() {
        assert_eq!(quote(r#"od"d"#), r#""od\"d""#);
    }

    /// Chocolatey writes the reason on stdout, so the fallback has to read it.
    #[test]
    fn the_last_non_empty_line_is_the_reason() {
        let output = "Installing...\nThe install of googlechrome was NOT successful.\n\n";
        assert_eq!(
            last_meaningful_line(output).as_deref(),
            Some("The install of googlechrome was NOT successful.")
        );
        assert_eq!(last_meaningful_line("  \n\n"), None);
    }

    /// 1641 and 3010 mean "done, reboot pending" - not a failure.
    #[test]
    fn reboot_pending_codes_count_as_success() {
        for code in [0, 1605, 1614, 1641, 3010] {
            assert!(SUCCESS_EXIT_CODES.contains(&code), "code {code}");
        }
        assert!(!SUCCESS_EXIT_CODES.contains(&1));
    }
}
