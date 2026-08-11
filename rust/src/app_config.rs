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
pub fn find_readme_file() -> Option<String> {
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
