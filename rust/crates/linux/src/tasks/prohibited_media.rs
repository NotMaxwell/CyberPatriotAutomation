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

use crate::readme_services;
use pinnacle_core::models::{ReadmeData, SystemInfo, TaskResult};
use pinnacle_core::task::Task;
use pinnacle_core::{command, impl_task_meta, remediation, ui};

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

/// Roots searched for hacking tools only. Games and local installs are where a
/// planted tool lands, and they hold no media a person put there.
const TOOL_ONLY_ROOTS: &[&str] = &[
    "/usr/games",
    "/usr/local/games",
    "/usr/local/bin",
    "/usr/local/share",
];

/// Hacking tools, by specific name.
///
/// Deliberately narrow: a broad substring such as "patch", "crack" or "abel"
/// flags `patchnotes.zip` and `Mabel.sh`, and a wrong deletion costs points.
/// Names are matched on word boundaries (see [`is_hacking_tool_name`]).
const HACKING_TOOL_NAMES: &[&str] = &[
    "pyrdp",
    "brutus",
    "mimikatz",
    "metasploit",
    "msfconsole",
    "sqlmap",
    "hydra",
    "john-the-ripper",
    "johnny",
    "hashcat",
    "aircrack",
    "ettercap",
    "nikto",
    "responder",
    "crackmapexec",
    "impacket",
    "ophcrack",
    "wifite",
    "beef-xss",
    "routersploit",
    "sherlock",
    "doona",
    "xprobe",
    "zenmap",
];

/// Archive extensions a downloaded tool arrives in.
const ARCHIVE_EXTENSIONS: &[&str] = &["zip", "tar", "gz", "tgz", "bz2", "xz", "7z", "rar"];

/// Script extensions a tool is commonly written in.
const SCRIPT_EXTENSIONS: &[&str] = &["py", "pl", "rb", "sh"];

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
    // The scoring engine's own directory - the counterpart of C:\CyberPatriot,
    // which the Windows scan never reaches because it searches only C:\Users.
    // `/opt` is searched here, so without this a README that prohibits media
    // would have the run delete whatever audio the scoring client ships with.
    // Both spellings, as README discovery tries both.
    "/opt/CyberPatriot/",
    "/opt/cyberpatriot/",
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
    pub fn media_is_prohibited(&self) -> bool {
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

/// What kind of prohibited file this is. The kind decides whether the README
/// has to authorise deleting it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    Media,
    HackingTool,
}

/// One file the scan found.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Found {
    pub path: PathBuf,
    pub kind: Kind,
}

/// What to do with a found file. Pure, so the decision is tested rather than
/// `execute()`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Disposition {
    Delete,
    /// Reported only; the string is the reason recorded in the ledger.
    ReportOnly(String),
}

/// Is this file name a hacking tool?
///
/// A tool name must stand on word boundaries: not preceded by a letter or digit
/// and not followed by a letter, so `pyrdp-master.zip` and `hydra.sh` match while
/// `hydrate.sh` and `patchnotes.zip` do not. A digit after the name is allowed
/// for versioned downloads (`sqlmap1.7.tar.gz`).
pub fn is_hacking_tool_name(file_name: &str) -> bool {
    let lower = file_name.to_ascii_lowercase();
    HACKING_TOOL_NAMES.iter().any(|tool| {
        lower.match_indices(tool).any(|(at, _)| {
            let before_ok = lower[..at]
                .chars()
                .next_back()
                .is_none_or(|c| !c.is_ascii_alphanumeric());
            let after_ok = lower[at + tool.len()..]
                .chars()
                .next()
                .is_none_or(|c| !c.is_ascii_alphabetic());
            before_ok && after_ok
        })
    })
}

/// Is this a hacking-tool *file*: a tool name on an archive, a script, or an
/// extensionless executable? A tool name on a `.txt` or `.png` is a note or a
/// screenshot about the tool, not the tool.
pub fn is_hacking_tool(path: &Path, executable: bool) -> bool {
    let Some(name) = path.file_name().and_then(|n| n.to_str()) else {
        return false;
    };
    let shape_ok = match path.extension().and_then(|e| e.to_str()) {
        Some(ext) => ARCHIVE_EXTENSIONS
            .iter()
            .chain(SCRIPT_EXTENSIONS)
            .any(|k| ext.eq_ignore_ascii_case(k)),
        None => executable,
    };
    shape_ok && is_hacking_tool_name(name)
}

/// Does the README list software this file name belongs to? A round that
/// requires `John the Ripper` or `Nikto` must not have it deleted.
pub fn is_required_software(readme: Option<&ReadmeData>, file_name: &str) -> bool {
    let Some(readme) = readme else {
        return false;
    };
    let squash = |s: &str| -> String {
        s.chars()
            .filter(|c| c.is_ascii_alphanumeric())
            .collect::<String>()
            .to_ascii_lowercase()
    };
    let file = squash(file_name);
    readme
        .required_software
        .iter()
        .filter(|s| s.is_required)
        .map(|s| squash(&s.name))
        .filter(|n| n.len() >= 3)
        .any(|n| file.contains(&n))
}

/// `key = value` lines of a config text, skipping `#` and `;` comments.
fn config_values<'a>(text: &'a str, key: &'a str) -> impl Iterator<Item = String> + 'a {
    text.lines().filter_map(move |line| {
        let line = line.trim();
        if line.starts_with('#') || line.starts_with(';') {
            return None;
        }
        let (k, v) = line.split_once('=')?;
        if !k.trim().eq_ignore_ascii_case(key) {
            return None;
        }
        let v = v.trim().trim_matches('"');
        (!v.is_empty()).then(|| v.to_string())
    })
}

/// The directories vsftpd serves: `anon_root` and `local_root`.
pub fn vsftpd_roots(conf: &str) -> Vec<String> {
    config_values(conf, "anon_root")
        .chain(config_values(conf, "local_root"))
        .collect()
}

/// Every `path =` in `smb.conf`: the shares Samba serves.
pub fn samba_paths(conf: &str) -> Vec<String> {
    config_values(conf, "path").collect()
}

/// Directories whose contents belong to a service the README says must keep
/// running, so a file there is data, not clutter. Mint 21 Training 2 penalises
/// "Important files removed from public FTP directories".
///
/// Pure over the README and the two config texts; `None` means the file is
/// absent.
pub fn protected_roots(
    readme: Option<&ReadmeData>,
    vsftpd_conf: Option<&str>,
    smb_conf: Option<&str>,
) -> Vec<String> {
    let mut roots = Vec::new();
    if readme_services::is_critical(readme, "vsftpd.service") {
        roots.push("/srv/ftp".to_string());
        if let Some(conf) = vsftpd_conf {
            roots.extend(vsftpd_roots(conf));
        }
    }
    if readme_services::is_critical(readme, "smbd.service")
        && let Some(conf) = smb_conf
    {
        roots.extend(samba_paths(conf));
    }
    if readme_services::is_critical(readme, "apache2.service")
        || readme_services::is_critical(readme, "nginx.service")
    {
        roots.push("/var/www".to_string());
    }
    // A relative root would match nothing; an empty one is a parse accident.
    roots.retain(|r| r.starts_with('/'));
    roots.sort();
    roots.dedup();
    roots
}

/// The protected root containing `path`, if any. Compared by path component,
/// so `/srv/ftpx` is not under `/srv/ftp`.
pub fn protecting_root<'a>(path: &Path, roots: &'a [String]) -> Option<&'a str> {
    roots
        .iter()
        .find(|r| path.starts_with(r.as_str()))
        .map(String::as_str)
}

/// Decide what happens to one file.
pub fn disposition(found: &Found, roots: &[String], media_prohibited: bool) -> Disposition {
    if let Some(root) = protecting_root(&found.path, roots) {
        return Disposition::ReportOnly(format!(
            "under {root}, a data directory of a service the README says is critical"
        ));
    }
    match found.kind {
        Kind::HackingTool => Disposition::Delete,
        Kind::Media if media_prohibited => Disposition::Delete,
        Kind::Media => Disposition::ReportOnly("no README prohibited media".to_string()),
    }
}

#[cfg(unix)]
fn is_executable(meta: &std::fs::Metadata) -> bool {
    use std::os::unix::fs::PermissionsExt;
    meta.permissions().mode() & 0o111 != 0
}

#[cfg(not(unix))]
fn is_executable(_meta: &std::fs::Metadata) -> bool {
    false
}

/// Walk `root` and collect the prohibited files under it. `media` is false for
/// the tool-only roots.
///
/// Depth-limited and iterative rather than recursive: a symlink loop under
/// `/home` would otherwise recurse until the stack runs out, and a competition
/// image is exactly where a deliberately planted one would be.
async fn scan(root: &Path, media: bool, found: &mut Vec<Found>) {
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
            } else if media && is_media(&path) {
                found.push(Found {
                    path,
                    kind: Kind::Media,
                });
            } else if is_hacking_tool(&path, is_executable(&meta)) {
                found.push(Found {
                    path,
                    kind: Kind::HackingTool,
                });
            }
        }
    }
}

/// Is a file owned by an installed package? `dpkg -S` exits 0 for an owned
/// path. Such a file is the distribution's, and removing it breaks the package.
async fn dpkg_owned(path: &Path) -> bool {
    let text = path.to_string_lossy();
    if text.contains('"') {
        return false;
    }
    let (owned, _o, _e) = command::execute("dpkg", Some(&format!("-S \"{text}\""))).await;
    owned
}

async fn read_optional(path: &str) -> Option<String> {
    tokio::fs::read_to_string(path).await.ok()
}

#[async_trait]
impl Task for ProhibitedMediaTask {
    impl_task_meta!();

    async fn read_system_state(&mut self) -> SystemInfo {
        SystemInfo {
            raw_output: Some(format!(
                "searching {}; hacking tools also in {}",
                SEARCH_ROOTS.join(", "),
                TOOL_ONLY_ROOTS.join(", ")
            )),
            ..Default::default()
        }
    }

    async fn execute(&mut self) -> TaskResult {
        let mut result = TaskResult {
            task_name: self.name.clone(),
            success: true,
            ..Default::default()
        };

        let found = self.gather().await;
        result.items_attempted = found.len() as i32;

        if found.is_empty() {
            remediation::record_finding(
                "user directories",
                "no prohibited media files or hacking tools",
                true,
                &format!(
                    "searched {}, {}",
                    SEARCH_ROOTS.join(", "),
                    TOOL_ONLY_ROOTS.join(", ")
                ),
            );
            result.message = "No media files or hacking tools found.".to_string();
            return result;
        }

        let roots = self.protected_roots().await;
        let media_ok = self.media_is_prohibited();
        let mut to_delete: Vec<&Found> = Vec::new();
        let mut kept = 0usize;
        for f in &found {
            let label = match f.kind {
                Kind::Media => "Media file",
                Kind::HackingTool => "Hacking tool",
            };
            ui::markup_line(&format!(
                "[yellow]⚠ {label}: {}[/]",
                ui::escape(&f.path.to_string_lossy())
            ));
            match disposition(f, &roots, media_ok) {
                Disposition::Delete => to_delete.push(f),
                Disposition::ReportOnly(why) => {
                    kept += 1;
                    let target = f.path.to_string_lossy();
                    if protecting_root(&f.path, &roots).is_some() {
                        remediation::record_skipped(&target, "prohibited file left in place", &why);
                    } else {
                        // Without a README saying so, this tool has no basis
                        // for destroying a user's files.
                        remediation::record_finding(
                            &target,
                            "media files are reviewed by the competitor",
                            false,
                            &format!("not deleted: {why}"),
                        );
                    }
                }
            }
        }

        if to_delete.is_empty() {
            result.message = format!(
                "{kept} prohibited files found; none deleted (service data or no README \
                 prohibition). Review them."
            );
            return result;
        }

        if self.dry_run {
            result.message = format!(
                "DRY RUN: would delete {} files ({kept} reported only).",
                to_delete.len()
            );
            return result;
        }

        let mut failures = Vec::new();
        for f in &to_delete {
            let path = &f.path;
            let display = path.to_string_lossy().into_owned();
            let intent = match f.kind {
                Kind::Media => "prohibited media file removed",
                Kind::HackingTool => "hacking tool removed",
            };
            match remediation::apply(
                &display,
                intent,
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
        result.message = format!(
            "Deleted {} files ({kept} reported only).",
            result.items_succeeded
        );
        if !failures.is_empty() {
            result.error_details = Some(failures.join("; "));
        }
        result
    }

    async fn verify(&mut self) -> bool {
        let found = self.gather().await;
        let roots = self.protected_roots().await;
        let media_ok = self.media_is_prohibited();
        // Nothing is claimed for files left in place on purpose.
        !found
            .iter()
            .any(|f| disposition(f, &roots, media_ok) == Disposition::Delete)
    }
}

impl ProhibitedMediaTask {
    /// Every prohibited file on the host, minus dpkg-owned and README-required
    /// hacking tools.
    async fn gather(&self) -> Vec<Found> {
        let mut raw = Vec::new();
        for root in SEARCH_ROOTS {
            let path = Path::new(root);
            if path.is_dir() {
                scan(path, true, &mut raw).await;
            }
        }
        for root in TOOL_ONLY_ROOTS {
            let path = Path::new(root);
            if path.is_dir() {
                scan(path, false, &mut raw).await;
            }
        }
        let mut found = Vec::new();
        for f in raw {
            if f.kind == Kind::HackingTool {
                let name = f.path.file_name().and_then(|n| n.to_str()).unwrap_or("");
                if is_required_software(self.readme_data.as_ref(), name)
                    || dpkg_owned(&f.path).await
                {
                    continue;
                }
            }
            found.push(f);
        }
        found.sort_by(|a, b| a.path.cmp(&b.path));
        found.dedup_by(|a, b| a.path == b.path);
        found
    }

    async fn protected_roots(&self) -> Vec<String> {
        let vsftpd = read_optional("/etc/vsftpd.conf").await;
        let smb = read_optional("/etc/samba/smb.conf").await;
        protected_roots(self.readme_data.as_ref(), vsftpd.as_deref(), smb.as_deref())
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
        assert!(is_exempt("/opt/CyberPatriot/sounds/gain.wav"));
        assert!(is_exempt("/opt/cyberpatriot/sounds/gain.wav"));
        assert!(!is_exempt("/opt/hidden/song.mp3"));
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

    fn found(path: &str, kind: Kind) -> Found {
        Found {
            path: PathBuf::from(path),
            kind,
        }
    }

    fn readme_critical(names: &[&str]) -> ReadmeData {
        ReadmeData {
            critical_services: names.iter().map(|s| s.to_string()).collect(),
            ..Default::default()
        }
    }

    #[test]
    fn specific_tool_names_are_flagged_on_archives_scripts_and_executables() {
        for p in [
            "/home/a/Downloads/pyrdp-master.zip",
            "/usr/games/Hydra.sh",
            "/home/a/sqlmap1.7.tar.gz",
            "/home/a/john-the-ripper.7z",
            "/usr/local/share/mimikatz.py",
        ] {
            assert!(is_hacking_tool(Path::new(p), false), "{p} was not flagged");
        }
        assert!(is_hacking_tool(Path::new("/usr/local/bin/nikto"), true));
    }

    #[test]
    fn broad_lookalikes_and_non_tool_shapes_are_not_flagged() {
        for p in [
            "/home/a/patchnotes.zip",
            "/home/a/hydrate.sh",
            "/home/a/Mabel.sh",
            "/home/a/crackers.tar.gz",
            "/home/a/hydra-notes.txt",
            "/home/a/hydra.png",
        ] {
            assert!(!is_hacking_tool(Path::new(p), false), "{p} was flagged");
        }
        // Extensionless but not executable: a data file, not a tool.
        assert!(!is_hacking_tool(Path::new("/home/a/sherlock"), false));
    }

    #[test]
    fn program_owned_tool_paths_are_exempt() {
        assert!(is_exempt("/usr/share/doc/hydra/hydra.sh"));
        assert!(!is_exempt("/usr/local/share/hydra.sh"));
    }

    #[test]
    fn readme_required_software_is_not_a_hacking_tool_to_delete() {
        let readme = ReadmeData {
            required_software: vec![pinnacle_core::models::SoftwareRequirement {
                name: "John the Ripper".to_string(),
                ..Default::default()
            }],
            ..Default::default()
        };
        assert!(is_required_software(Some(&readme), "john-the-ripper.zip"));
        assert!(!is_required_software(Some(&readme), "pyrdp.zip"));
        assert!(!is_required_software(None, "john-the-ripper.zip"));
    }

    #[test]
    fn vsftpd_roots_come_from_anon_and_local_root_ignoring_comments() {
        let conf = "# anon_root=/nope\nanon_enable=YES\nanon_root = /srv/ftp/public\nlocal_root=/home/ftp\n";
        assert_eq!(vsftpd_roots(conf), ["/srv/ftp/public", "/home/ftp"]);
    }

    #[test]
    fn samba_paths_come_from_every_path_line() {
        let conf = "[global]\n; path = /nope\n[Sales]\n   path = /srv/samba/sales\n[print$]\npath=/var/lib/samba/printers\n";
        assert_eq!(
            samba_paths(conf),
            ["/srv/samba/sales", "/var/lib/samba/printers"]
        );
    }

    #[test]
    fn protected_roots_follow_the_critical_services() {
        let vsftpd = "anon_root=/data/ftp\n";
        let smb = "[s]\npath=/srv/share\n";
        let none = protected_roots(Some(&readme_critical(&[])), Some(vsftpd), Some(smb));
        assert!(none.is_empty());

        let ftp = protected_roots(Some(&readme_critical(&["vsftpd"])), Some(vsftpd), Some(smb));
        assert_eq!(ftp, ["/data/ftp", "/srv/ftp"]);

        let all = protected_roots(
            Some(&readme_critical(&["FTP", "Samba", "Apache"])),
            Some(vsftpd),
            Some(smb),
        );
        for r in ["/srv/ftp", "/data/ftp", "/srv/share", "/var/www"] {
            assert!(all.iter().any(|x| x == r), "{r} missing from {all:?}");
        }
        let nginx = protected_roots(Some(&readme_critical(&["Nginx"])), None, None);
        assert_eq!(nginx, ["/var/www"]);
    }

    #[test]
    fn a_protected_root_matches_by_path_component() {
        let roots = vec!["/srv/ftp".to_string()];
        assert!(protecting_root(Path::new("/srv/ftp/Sales/a.txt"), &roots).is_some());
        assert!(protecting_root(Path::new("/srv/ftpx/a.txt"), &roots).is_none());
    }

    /// Mint 21 Training 2 penalty: important files removed from public FTP
    /// directories. Media and tools under a critical service's data root stay.
    #[test]
    fn files_under_a_critical_ftp_root_are_never_deleted() {
        let roots = protected_roots(Some(&readme_critical(&["vsftpd"])), None, None);
        for (path, kind) in [
            ("/srv/ftp/Sales/override.txt", Kind::Media),
            ("/srv/ftp/Sales/song.mp3", Kind::Media),
            ("/srv/ftp/pub/hydra.zip", Kind::HackingTool),
        ] {
            assert!(
                matches!(
                    disposition(&found(path, kind), &roots, true),
                    Disposition::ReportOnly(_)
                ),
                "{path} would be deleted"
            );
        }
    }

    #[test]
    fn hacking_tools_are_deleted_without_a_readme_but_media_is_not() {
        let roots: Vec<String> = Vec::new();
        assert_eq!(
            disposition(
                &found("/home/a/pyrdp.zip", Kind::HackingTool),
                &roots,
                false
            ),
            Disposition::Delete
        );
        assert!(matches!(
            disposition(&found("/home/a/song.ogg", Kind::Media), &roots, false),
            Disposition::ReportOnly(_)
        ));
        assert_eq!(
            disposition(&found("/home/a/song.ogg", Kind::Media), &roots, true),
            Disposition::Delete
        );
    }
}
