// =============================================================================
// PinnacleCyPat - Prohibited media (Linux)
// Copyright 2026 Maxwell McCormick
// SPDX-License-Identifier: Apache-2.0
// =============================================================================

//! Finds media files in user home directories, which nearly every round
//! prohibits.
//!
//! This is one of the tasks that ported almost verbatim: the decision is "is
//! this extension a media file, and is it somewhere a person put it", and
//! neither half is Windows-specific. Only the roots differ - `/home` and
//! `/root` instead of `C:\Users`.
//!
//! **Found files are reported, not deleted, unless `--all` asked for a change
//! and the README prohibits them.** A competitor who deletes the wrong file has
//! no undo, and a media file is sometimes the answer to a forensics question.
//! Where deletion does happen the path is recorded in the ledger first, so the
//! log names every file that went.

use pinnacle_core::models::{ReadmeData, SystemInfo, TaskResult};
use pinnacle_core::task::Task;
use pinnacle_core::{impl_task_meta, remediation, ui};

use async_trait::async_trait;
use std::path::{Path, PathBuf};

/// Extensions a round prohibits. Audio, video and disc images.
const MEDIA_EXTENSIONS: &[&str] = &[
    "mp3", "mp4", "m4a", "m4v", "wav", "wma", "wmv", "avi", "mov", "mkv", "flac", "aac", "ogg",
    "oga", "ogv", "webm", "flv", "mpg", "mpeg", "3gp", "aiff", "alac", "opus", "mid", "midi",
    "iso", "img", "vob",
];

/// Where a person's files live.
const SEARCH_ROOTS: &[&str] = &["/home", "/root", "/srv", "/opt", "/tmp", "/var/tmp"];

/// Directories that hold media legitimately, as part of an installed program.
///
/// Deleting the sample sounds a desktop environment ships with is a change that
/// scores nothing and can break the login chime, which then reads as a broken
/// image.
const EXEMPT_PATH_FRAGMENTS: &[&str] = &[
    "/.cache/",
    "/.local/share/Trash/",
    "/usr/share/",
    "/snap/",
    "/.config/",
    "/site-packages/",
    "/node_modules/",
];

pub struct ProhibitedMediaTask {
    name: String,
    description: String,
    dry_run: bool,
    readme_data: Option<ReadmeData>,
}

impl ProhibitedMediaTask {
    pub fn new() -> Self {
        Self {
            name: "Prohibited Media".to_string(),
            description: "Find media files in user directories".to_string(),
            dry_run: false,
            readme_data: None,
        }
    }

    pub fn set_readme_data(&mut self, data: ReadmeData) {
        self.readme_data = Some(data);
    }

    /// Does the README actually prohibit media?
    ///
    /// Almost every round does, but not all - a round whose scenario is a media
    /// production company does not, and deleting the company's files there
    /// loses points rather than winning them. Absent a README the task reports
    /// and does not delete.
    fn media_is_prohibited(&self) -> bool {
        let Some(readme) = &self.readme_data else {
            return false;
        };
        let haystack = format!(
            "{} {} {}",
            readme.scenario.to_lowercase(),
            readme.guidelines.join(" ").to_lowercase(),
            readme.prohibited_software.join(" ").to_lowercase()
        );
        [
            "media file",
            "media files",
            "music",
            "video",
            "mp3",
            "non-work related",
        ]
        .iter()
        .any(|needle| haystack.contains(needle))
    }
}

impl Default for ProhibitedMediaTask {
    fn default() -> Self {
        Self::new()
    }
}

/// Is this a media file by extension?
pub fn is_media(path: &Path) -> bool {
    path.extension()
        .and_then(|e| e.to_str())
        .is_some_and(|e| MEDIA_EXTENSIONS.iter().any(|m| e.eq_ignore_ascii_case(m)))
}

/// Is this path one a program owns rather than a person?
pub fn is_exempt(path: &str) -> bool {
    EXEMPT_PATH_FRAGMENTS.iter().any(|f| path.contains(f))
}

/// Walk `root` and collect the media files under it.
///
/// Depth-limited and iterative rather than recursive: a symlink loop under
/// `/home` would otherwise recurse until the stack runs out, and a competition
/// image is exactly where a deliberately planted one would be.
async fn scan(root: &Path, found: &mut Vec<PathBuf>) {
    const MAX_DEPTH: usize = 12;
    let mut queue: Vec<(PathBuf, usize)> = vec![(root.to_path_buf(), 0)];

    while let Some((dir, depth)) = queue.pop() {
        if depth > MAX_DEPTH {
            continue;
        }
        let Ok(mut entries) = tokio::fs::read_dir(&dir).await else {
            continue;
        };
        while let Ok(Some(entry)) = entries.next_entry().await {
            let path = entry.path();
            let display = path.to_string_lossy();
            if is_exempt(&display) {
                continue;
            }
            // `symlink_metadata` does not follow the link, so a symlink to `/`
            // is seen as a link and skipped rather than walked.
            let Ok(meta) = tokio::fs::symlink_metadata(&path).await else {
                continue;
            };
            if meta.is_symlink() {
                continue;
            }
            if meta.is_dir() {
                queue.push((path, depth + 1));
            } else if is_media(&path) {
                found.push(path);
            }
        }
    }
}

#[async_trait]
impl Task for ProhibitedMediaTask {
    impl_task_meta!();

    async fn read_system_state(&mut self) -> SystemInfo {
        SystemInfo {
            raw_output: Some(format!("searching {}", SEARCH_ROOTS.join(", "))),
            ..Default::default()
        }
    }

    async fn execute(&mut self) -> TaskResult {
        let mut result = TaskResult {
            task_name: self.name.clone(),
            success: true,
            ..Default::default()
        };

        let mut found: Vec<PathBuf> = Vec::new();
        for root in SEARCH_ROOTS {
            let path = Path::new(root);
            if path.is_dir() {
                scan(path, &mut found).await;
            }
        }
        found.sort();
        result.items_attempted = found.len() as i32;

        if found.is_empty() {
            remediation::record_finding(
                "user directories",
                "no prohibited media files",
                true,
                &format!("searched {}", SEARCH_ROOTS.join(", ")),
            );
            result.message = "No media files found.".to_string();
            return result;
        }

        for path in &found {
            ui::markup_line(&format!(
                "[yellow]⚠ Media file: {}[/]",
                ui::escape(&path.to_string_lossy())
            ));
        }

        if !self.media_is_prohibited() {
            // Reported, not deleted. Without a README saying so, this tool has
            // no basis for destroying a user's files.
            remediation::record_finding(
                "user directories",
                "media files are reviewed by the competitor",
                false,
                &format!(
                    "{} media files found; not deleted, because no README prohibited them",
                    found.len()
                ),
            );
            result.message = format!(
                "{} media files found. Review them; no README prohibited media, so \
                 nothing was deleted.",
                found.len()
            );
            return result;
        }

        if self.dry_run {
            result.message = format!("DRY RUN: would delete {} media files.", found.len());
            return result;
        }

        let mut failures = Vec::new();
        for path in &found {
            let display = path.to_string_lossy().into_owned();
            match remediation::apply(
                &display,
                "prohibited media file removed",
                || {
                    let path = path.clone();
                    async move {
                        Some(if path.exists() { "present" } else { "absent" }.to_string())
                    }
                },
                |state| state == "absent",
                "deleted the file",
                || async {
                    tokio::fs::remove_file(path)
                        .await
                        .map_err(|e| format!("could not delete: {e}"))
                },
            )
            .await
            {
                Ok(()) => result.items_succeeded += 1,
                Err(e) => failures.push(format!("{display}: {e}")),
            }
        }

        result.success = failures.is_empty();
        result.message = format!("Deleted {} media files.", result.items_succeeded);
        if !failures.is_empty() {
            result.error_details = Some(failures.join("; "));
        }
        result
    }

    async fn verify(&mut self) -> bool {
        if !self.media_is_prohibited() {
            // Nothing was claimed, so there is nothing to disprove.
            return true;
        }
        let mut found = Vec::new();
        for root in SEARCH_ROOTS {
            let path = Path::new(root);
            if path.is_dir() {
                scan(path, &mut found).await;
            }
        }
        found.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn media_is_recognised_by_extension_in_any_case() {
        for name in ["song.mp3", "clip.MP4", "album.FLAC", "disc.iso"] {
            assert!(is_media(Path::new(name)), "{name} was not recognised");
        }
        for name in ["notes.txt", "report.pdf", "script.sh", "noextension"] {
            assert!(!is_media(Path::new(name)), "{name} was wrongly flagged");
        }
    }

    /// A desktop environment's own sample sounds are not a competitor's media
    /// files, and deleting them breaks the login chime for no points.
    #[test]
    fn program_owned_directories_are_exempt() {
        assert!(is_exempt("/usr/share/sounds/freedesktop/stereo/bell.oga"));
        assert!(is_exempt("/home/alice/.cache/thumbnails/x.mp4"));
        assert!(is_exempt("/home/alice/.local/share/Trash/files/old.mp3"));
        assert!(!is_exempt("/home/alice/Music/song.mp3"));
        assert!(!is_exempt("/home/alice/Desktop/movie.mp4"));
    }

    /// Without a README this task must not delete anything. The scenario text
    /// is what authorises destruction.
    #[test]
    fn media_is_only_prohibited_when_the_readme_says_so() {
        let mut task = ProhibitedMediaTask::new();
        assert!(!task.media_is_prohibited(), "no README means no deletion");

        task.set_readme_data(ReadmeData {
            scenario: "The presence of any non-work related media files is strictly prohibited."
                .to_string(),
            ..Default::default()
        });
        assert!(task.media_is_prohibited());
    }

    /// The round whose scenario is a media production company. Deleting the
    /// company's own files there loses points rather than winning them.
    #[test]
    fn a_readme_that_says_nothing_about_media_does_not_authorise_deletion() {
        let mut task = ProhibitedMediaTask::new();
        task.set_readme_data(ReadmeData {
            scenario: "You are the administrator for a small accounting firm.".to_string(),
            ..Default::default()
        });
        assert!(!task.media_is_prohibited());
    }
}
