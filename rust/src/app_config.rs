// =============================================================================
// CyberPatriot Automation Tool
// Author: Maxwell McCormick
// Copyright (c) 2026 Maxwell McCormick. All Rights Reserved.
// =============================================================================

//! Application configuration and default paths.

use std::path::{Path, PathBuf};

/// CCS Client service name - must never be disabled.
pub const CCS_CLIENT_SERVICE_NAME: &str = "CCSClient";

/// CyberPatriot scoring report desktop shortcut name.
pub const SCORING_REPORT_SHORTCUT: &str = "CyberPatriot Scoring Report";

/// Application version.
pub const VERSION: &str = "1.0.0";

/// Secure passwords for user account management.
/// These meet complexity requirements: 14+ chars, upper, lower, digit, special.
pub const SECURE_PASSWORDS: &[&str] = &[
    "CyberP@tr10t2026!",
    "Secur3P@ssw0rd#1",
    "Str0ng!P@ssKey99",
    "C0mpl3x#Pass2026",
    "H@rdT0Gu3ss!123",
    "S@fetyF1rst#2026",
    "Pr0t3ct3d!Acc0unt",
    "N0H@ck1ng#All0wed",
    "D3f3nd3r$#Strong1",
    "W1nd0ws!S3cur3#99",
];

/// The current user's desktop directory.
pub fn desktop_dir() -> PathBuf {
    #[cfg(windows)]
    {
        if let Ok(profile) = std::env::var("USERPROFILE") {
            return Path::new(&profile).join("Desktop");
        }
    }
    if let Ok(home) = std::env::var("HOME") {
        return Path::new(&home).join("Desktop");
    }
    PathBuf::from("Desktop")
}

/// The machine-wide (common) desktop directory.
pub fn common_desktop_dir() -> PathBuf {
    PathBuf::from(r"C:\Users\Public\Desktop")
}

/// Default CyberPatriot competition README paths on Windows images.
pub fn default_readme_paths() -> Vec<String> {
    vec![
        r"C:\Users\Public\Desktop\README.html".to_string(),
        r"C:\CyberPatriot\README.html".to_string(),
        r"C:\Users\Public\Documents\README.html".to_string(),
        common_desktop_dir()
            .join("README.html")
            .to_string_lossy()
            .into_owned(),
        desktop_dir()
            .join("README.html")
            .to_string_lossy()
            .into_owned(),
        // Fallback: look for any README on desktop
        r"C:\Users\*\Desktop\README.html".to_string(),
    ]
}

/// Try to find the README file automatically.
///
/// On real CyberPatriot images the README is not dropped on the desktop as a
/// literal file — the competitor's desktop instead has a `.lnk` shortcut
/// (commonly named "README") that points at the actual HTML file, which may
/// live somewhere else entirely (e.g. `C:\CyberPatriot\`). That shortcut is
/// always present on the desktop of the user running the tool, so shortcut
/// resolution is tried first; the hard-coded literal paths below remain as a
/// fallback for images that do place the file directly.
pub async fn find_readme_file() -> Option<String> {
    if let Some(found) = find_readme_shortcut(&desktop_dir()).await {
        return Some(found);
    }
    if let Some(found) = find_readme_shortcut(&common_desktop_dir()).await {
        return Some(found);
    }

    for path in default_readme_paths() {
        if path.contains('*') {
            // Handle wildcard paths: search recursively for the file name.
            let dir = Path::new(&path.replace('*', ""))
                .parent()
                .map(|p| p.to_path_buf());
            let file_name = Path::new(&path)
                .file_name()
                .map(|f| f.to_string_lossy().into_owned());
            if let (Some(dir), Some(file_name)) = (dir, file_name) {
                if dir.exists() {
                    if let Some(found) = find_file_recursive(&dir, &file_name) {
                        return Some(found.to_string_lossy().into_owned());
                    }
                }
            }
        } else if Path::new(&path).is_file() {
            return Some(path);
        }
    }
    None
}

/// Look in `dir` for a `.lnk` shortcut whose name suggests it points at the
/// README, and resolve it to the target file it links to.
async fn find_readme_shortcut(dir: &Path) -> Option<String> {
    let entries = std::fs::read_dir(dir).ok()?;
    for entry in entries.flatten() {
        let path = entry.path();
        let is_lnk = path
            .extension()
            .map(|e| e.eq_ignore_ascii_case("lnk"))
            .unwrap_or(false);
        if !is_lnk {
            continue;
        }
        if !shortcut_name_looks_like_readme(&path) {
            continue;
        }
        if let Some(target) = resolve_shortcut_target(&path).await {
            if Path::new(&target).is_file() {
                return Some(target);
            }
        }
    }
    None
}

/// Does this shortcut's file name suggest it points at the README?
/// (e.g. "README.lnk", "Read Me.lnk", "CyberPatriot README.lnk")
fn shortcut_name_looks_like_readme(path: &Path) -> bool {
    path.file_stem()
        .map(|s| s.to_string_lossy().to_lowercase().replace(' ', "").contains("readme"))
        .unwrap_or(false)
}

/// Resolve a Windows `.lnk` shortcut to its target path using the
/// `WScript.Shell` COM object (the standard way to read shortcut targets
/// without a native shell-link parser).
async fn resolve_shortcut_target(lnk_path: &Path) -> Option<String> {
    let script = format!(
        "(New-Object -ComObject WScript.Shell).CreateShortcut({}).TargetPath",
        crate::command::ps_quote(&lnk_path.to_string_lossy())
    );
    let (success, output, _error) = crate::command::powershell_query(&script).await;
    if !success {
        return None;
    }
    let target = output.trim();
    if target.is_empty() {
        None
    } else {
        Some(target.to_string())
    }
}

fn find_file_recursive(dir: &Path, file_name: &str) -> Option<PathBuf> {
    let entries = std::fs::read_dir(dir).ok()?;
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            if let Some(found) = find_file_recursive(&path, file_name) {
                return Some(found);
            }
        } else if path
            .file_name()
            .map(|f| f.to_string_lossy() == file_name)
            .unwrap_or(false)
        {
            return Some(path);
        }
    }
    None
}
