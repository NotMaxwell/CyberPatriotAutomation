// =============================================================================
// PinnacleCyPat - Directory listing for the file browsers
// Copyright 2026 Maxwell McCormick
// SPDX-License-Identifier: Apache-2.0
// =============================================================================

//! What the GUI's and the web UI's file browsers show: one directory at a
//! time, folders first, README-like files marked.
//!
//! One listing for both front ends, so "which files look like a README" is
//! decided once. Hidden entries are left out; a README is never hidden, and a
//! home directory full of dotfiles buries the one file being looked for.

use std::path::{Path, PathBuf};

/// The extensions a README arrives as: the document itself, or a shortcut to
/// it (Windows `.url`/`.lnk`, freedesktop `.desktop`).
pub const README_EXTENSIONS: &[&str] = &["html", "htm", "url", "lnk", "desktop"];

#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
pub struct Entry {
    pub name: String,
    pub path: String,
    pub is_dir: bool,
    /// A file whose extension a README arrives as.
    pub readme_like: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
pub struct Listing {
    /// The directory listed, as an absolute path.
    pub path: String,
    /// One level up, if there is one.
    pub parent: Option<String>,
    pub entries: Vec<Entry>,
}

/// Is this file name one a README could arrive as?
pub fn readme_like(name: &str) -> bool {
    Path::new(name)
        .extension()
        .and_then(|e| e.to_str())
        .is_some_and(|e| README_EXTENSIONS.iter().any(|r| e.eq_ignore_ascii_case(r)))
}

/// List `dir`: folders first, then files, each alphabetically, hidden entries
/// left out. With `readme_only`, files that are not README-like are left out
/// too (folders always stay, or the browser could not navigate).
pub fn list_dir(dir: &Path, readme_only: bool) -> std::io::Result<Listing> {
    let dir = std::fs::canonicalize(dir)?;
    let mut entries: Vec<Entry> = std::fs::read_dir(&dir)?
        .flatten()
        .filter_map(|entry| {
            let name = entry.file_name().to_string_lossy().into_owned();
            if name.starts_with('.') {
                return None;
            }
            // Follow symlinks: a Desktop shortcut folder is often a link.
            let is_dir = entry.path().is_dir();
            let readme = !is_dir && readme_like(&name);
            if readme_only && !is_dir && !readme {
                return None;
            }
            Some(Entry {
                path: entry.path().to_string_lossy().into_owned(),
                name,
                is_dir,
                readme_like: readme,
            })
        })
        .collect();
    entries.sort_by(|a, b| {
        b.is_dir
            .cmp(&a.is_dir)
            .then_with(|| a.name.to_lowercase().cmp(&b.name.to_lowercase()))
    });
    Ok(Listing {
        path: dir.to_string_lossy().into_owned(),
        parent: dir.parent().map(|p| p.to_string_lossy().into_owned()),
        entries,
    })
}

/// Where a browser should open: the first of these that exists.
///
/// The competition folder first, because that is where the README is; then the
/// invoking user's Desktop (under sudo, `HOME` is root's, not theirs).
pub fn start_dir() -> PathBuf {
    let mut candidates: Vec<PathBuf> = vec![
        PathBuf::from(r"C:\CyberPatriot"),
        PathBuf::from("/opt/CyberPatriot"),
    ];
    if let Ok(user) = std::env::var("SUDO_USER") {
        candidates.push(PathBuf::from(format!("/home/{user}/Desktop")));
    }
    candidates.push(crate::app_config::desktop_dir());
    candidates
        .into_iter()
        .find(|p| p.is_dir())
        .unwrap_or_else(|| PathBuf::from(if cfg!(windows) { r"C:\" } else { "/" }))
}

/// Top-level places to jump to: drive letters on Windows, `/` elsewhere.
pub fn roots() -> Vec<String> {
    if cfg!(windows) {
        (b'A'..=b'Z')
            .map(|d| format!("{}:\\", d as char))
            .filter(|d| Path::new(d).is_dir())
            .collect()
    } else {
        vec!["/".to_string()]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn readme_shapes_are_recognised_case_insensitively() {
        for name in [
            "README.html",
            "readme.HTM",
            "README.url",
            "Round.desktop",
            "x.LNK",
        ] {
            assert!(readme_like(name), "{name}");
        }
        for name in ["notes.txt", "README", "song.mp3", ".html"] {
            assert!(!readme_like(name), "{name}");
        }
    }

    #[test]
    fn folders_come_first_hidden_entries_never_and_the_filter_keeps_folders() {
        let root = std::env::temp_dir().join(format!("pinnacle-files-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(root.join("b-folder")).unwrap();
        std::fs::create_dir_all(root.join(".hidden-folder")).unwrap();
        for f in [
            "README.html",
            "a-notes.txt",
            ".secret.html",
            "Round.desktop",
        ] {
            std::fs::write(root.join(f), "x").unwrap();
        }

        let all = list_dir(&root, false).unwrap();
        let names: Vec<&str> = all.entries.iter().map(|e| e.name.as_str()).collect();
        assert_eq!(
            names,
            ["b-folder", "a-notes.txt", "README.html", "Round.desktop"]
        );
        assert!(all.parent.is_some());

        let readme = list_dir(&root, true).unwrap();
        let names: Vec<&str> = readme.entries.iter().map(|e| e.name.as_str()).collect();
        assert_eq!(names, ["b-folder", "README.html", "Round.desktop"]);

        std::fs::remove_dir_all(&root).unwrap();
    }

    #[test]
    fn a_missing_directory_is_an_error_not_an_empty_listing() {
        assert!(list_dir(Path::new("/definitely/not/here"), false).is_err());
    }
}
