// =============================================================================
// PinnacleCyPat
// Author: Maxwell McCormick
// Copyright 2026 Maxwell McCormick
// SPDX-License-Identifier: Apache-2.0
// =============================================================================

//! Application configuration and default paths.

use std::path::{Path, PathBuf};

/// CCS Client service name - must never be disabled.
pub const CCS_CLIENT_SERVICE_NAME: &str = "CCSClient";

/// CyberPatriot scoring report desktop shortcut name.
pub const SCORING_REPORT_SHORTCUT: &str = "CyberPatriot Scoring Report";

/// Application version, taken from `Cargo.toml` so the two cannot drift apart.
///
/// Bump `version` in `Cargo.toml` with every behavioural change; the run log
/// stamps this value in its header and in its file name, so a log can always be
/// tied back to the build that produced it. See `CHANGELOG.md` for what each
/// version changed.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// Short build stamp shown alongside the version.
///
/// The date the binary was compiled disambiguates two builds of the same
/// version, which happens while iterating between releases.
pub const BUILD_DATE: &str = env!("PCP_BUILD_DATE");

/// Version and build stamp as one display string.
pub fn version_string() -> String {
    format!("v{VERSION} (build {BUILD_DATE})")
}

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

/// Where a competition image installs its own resources.
///
/// The case matters: the directory on an Ubuntu image is `/opt/CyberPatriot`,
/// and Linux filesystems are case-sensitive, so the lower-case spelling that
/// looks natural in code finds nothing. Both are listed rather than picking
/// one, since a fixture or a hand-made image may use either.
#[cfg(not(windows))]
const CYBERPATRIOT_DIRS: &[&str] = &[
    "/opt/CyberPatriot",
    "/opt/cyberpatriot",
    "/usr/share/CyberPatriot",
    "/usr/share/cyberpatriot",
    "/etc/CyberPatriot",
];

#[cfg(windows)]
const CYBERPATRIOT_DIRS: &[&str] = &[r"C:\CyberPatriot"];

/// Every directory worth scanning for a README shortcut, in priority order.
///
/// On Linux this matters more than it looks. The tool has to run as root, and
/// `sudo` rewrites `HOME` to `/root` - so `desktop_dir()` points at
/// `/root/Desktop` while the launcher the competitor can see is on
/// `/home/perry/Desktop`. Looking only where `HOME` says finds nothing on the
/// one image this is written for.
///
/// `SUDO_USER` names the account that invoked sudo and is checked first,
/// because it is the person whose desktop the README is on. Every other home
/// directory is scanned after that, since an image may auto-login as one
/// account and store the README under another.
pub fn readme_search_dirs() -> Vec<PathBuf> {
    let mut dirs = Vec::new();
    let push = |dir: PathBuf, dirs: &mut Vec<PathBuf>| {
        if dir.is_dir() && !dirs.contains(&dir) {
            dirs.push(dir);
        }
    };

    // The canonical location first, on both platforms. `C:\CyberPatriot` on
    // Windows; `/opt/CyberPatriot` on Ubuntu, where the round's resources -
    // including the README launcher - are installed.
    //
    // Scanned as a directory rather than probed by file name, because the
    // launcher is not called `README.desktop`. It is called whatever the round
    // named it: "Exhibition Round Ubuntu 22.04 README". A fixed-name lookup
    // finds nothing.
    for dir in CYBERPATRIOT_DIRS {
        push(PathBuf::from(dir), &mut dirs);
    }

    #[cfg(not(windows))]
    if let Ok(user) = std::env::var("SUDO_USER") {
        push(PathBuf::from(format!("/home/{user}/Desktop")), &mut dirs);
    }

    push(desktop_dir(), &mut dirs);
    push(common_desktop_dir(), &mut dirs);

    #[cfg(not(windows))]
    {
        // Every other human's desktop, sorted so the answer does not depend on
        // the order the filesystem happens to return.
        let mut homes: Vec<PathBuf> = std::fs::read_dir("/home")
            .into_iter()
            .flatten()
            .flatten()
            .map(|entry| entry.path().join("Desktop"))
            .collect();
        homes.sort();
        for home in homes {
            push(home, &mut dirs);
        }
        push(PathBuf::from("/root/Desktop"), &mut dirs);
    }

    dirs
}

/// The machine-wide (common) desktop directory.
pub fn common_desktop_dir() -> PathBuf {
    PathBuf::from(r"C:\Users\Public\Desktop")
}

/// Default CyberPatriot competition README paths.
///
/// A standard image does not ship the README as a file. Windows puts an
/// *Internet Shortcut* at `C:\CyberPatriot\README.url`; Ubuntu puts a
/// freedesktop launcher on the Desktop. Both name an https:// address, and
/// [`resolve_readme_candidate`] follows either to the document. The literal
/// `.html` paths remain for images that place the document directly.
pub fn default_readme_paths() -> Vec<String> {
    #[cfg(windows)]
    {
        windows_readme_paths()
    }
    #[cfg(not(windows))]
    {
        linux_readme_paths()
    }
}

/// The Windows candidates, in the order they are worth trying.
#[cfg_attr(not(windows), allow(dead_code))]
fn windows_readme_paths() -> Vec<String> {
    vec![
        r"C:\CyberPatriot\README.url".to_string(),
        r"C:\CyberPatriot\README.html".to_string(),
        r"C:\Users\Public\Desktop\README.url".to_string(),
        r"C:\Users\Public\Desktop\README.html".to_string(),
        r"C:\Users\Public\Documents\README.html".to_string(),
        common_desktop_dir()
            .join("README.url")
            .to_string_lossy()
            .into_owned(),
        common_desktop_dir()
            .join("README.html")
            .to_string_lossy()
            .into_owned(),
        desktop_dir()
            .join("README.url")
            .to_string_lossy()
            .into_owned(),
        desktop_dir()
            .join("README.html")
            .to_string_lossy()
            .into_owned(),
        // Fallback: any user's desktop.
        r"C:\Users\*\Desktop\README.url".to_string(),
        r"C:\Users\*\Desktop\README.html".to_string(),
    ]
}

/// The Linux candidates.
///
/// The `.desktop` launcher is listed first because it is what an Ubuntu image
/// actually ships - and its file name is not `README.desktop`. It is whatever
/// the round called it, which on the Ubuntu 22.04 Exhibition Round is
/// "Exhibition Round Ubuntu 22.04 README". So the named paths below are a
/// convenience for images that do place a file, and the real discovery is the
/// wildcard scan of every Desktop directory, which
/// [`find_readme_shortcut`] does by matching the *name* rather than the path.
#[cfg_attr(windows, allow(dead_code))]
fn linux_readme_paths() -> Vec<String> {
    let mut paths = Vec::new();
    let mut dirs: Vec<&str> = CYBERPATRIOT_DIRS.to_vec();
    dirs.push("/root/Desktop");
    for dir in dirs {
        for name in ["README.desktop", "README.html", "README.htm", "readme.html"] {
            paths.push(format!("{dir}/{name}"));
        }
    }
    for name in ["README.desktop", "README.html", "README.htm", "readme.html"] {
        paths.push(desktop_dir().join(name).to_string_lossy().into_owned());
        paths.push(
            home_dir()
                .join("Documents")
                .join(name)
                .to_string_lossy()
                .into_owned(),
        );
    }
    // Fallback: any user's desktop, which is where the launcher actually is.
    paths.push("/home/*/Desktop/README.desktop".to_string());
    paths.push("/home/*/Desktop/README.html".to_string());
    paths
}

/// The current user's home directory.
fn home_dir() -> PathBuf {
    std::env::var("HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from("/root"))
}

/// Try to find the README file automatically.
///
/// On a real CyberPatriot image the README is rarely the HTML document itself:
/// the canonical entry point is `C:\CyberPatriot\README.url`, an Internet
/// Shortcut naming the actual file, and the competitor's desktop carries a
/// shortcut to it as well. Every candidate is therefore run through
/// [`resolve_readme_candidate`], which follows `.url` and `.lnk` shortcuts to
/// the document they point at.
pub async fn find_readme_file() -> Option<String> {
    find_readme_file_reporting(&mut Vec::new()).await
}

/// As [`find_readme_file`], but records every location examined.
///
/// When discovery fails there is otherwise nothing to go on: the run simply
/// reports no README and gives no indication of where it looked or which
/// candidate existed but could not be followed. `attempts` receives one
/// human-readable line per candidate.
pub async fn find_readme_file_reporting(attempts: &mut Vec<String>) -> Option<String> {
    // Desktop shortcuts first - that is what a competitor actually clicks.
    for dir in readme_search_dirs() {
        match find_readme_shortcut(&dir).await {
            Some(found) => {
                attempts.push(format!("{} -> {found}", dir.to_string_lossy()));
                return Some(found);
            }
            None => attempts.push(format!(
                "{} (no README shortcut resolved)",
                dir.to_string_lossy()
            )),
        }
    }

    for path in default_readme_paths() {
        let candidates = if path.contains('*') {
            expand_wildcard_path(&path).into_iter().collect::<Vec<_>>()
        } else {
            vec![path.clone()]
        };
        if candidates.is_empty() {
            attempts.push(format!("{path} (no match)"));
            continue;
        }
        for candidate in candidates {
            match resolve_readme_candidate(Path::new(&candidate)).await {
                Some(found) => {
                    attempts.push(format!("{candidate} -> {found}"));
                    return Some(found);
                }
                None => {
                    // Distinguish "not there" from "there but unusable", and in
                    // the latter case say what the shortcut actually points at.
                    // A shortcut naming a web address or a missing file is
                    // otherwise indistinguishable from one that is absent.
                    let note = if Path::new(&candidate).exists() {
                        describe_unresolvable(Path::new(&candidate))
                    } else {
                        "not found".to_string()
                    };
                    attempts.push(format!("{candidate} ({note})"));
                }
            }
        }
    }
    None
}

/// Resolve one candidate path to a readable README document.
///
/// `.url` and `.lnk` files are shortcuts and must be followed; anything else is
/// taken at face value. Returns `None` unless the end result is a file that
/// exists, so a shortcut left behind pointing at a deleted document does not
/// masquerade as a README.
///
/// Shortcuts are followed **repeatedly**, because on a real image they chain:
/// the desktop icon is a `.lnk` whose target is `C:\CyberPatriot\README.url`,
/// which in turn names the HTML document. Stopping after one hop returns the
/// `.url` itself, and parsing that INI file as HTML yields a README with no
/// title and no detectable operating system - the "Unknown / Unknown" symptom.
pub async fn resolve_readme_candidate(path: &Path) -> Option<String> {
    // Enough for lnk -> url -> html with room to spare; also bounds a shortcut
    // that points at itself.
    const MAX_HOPS: usize = 5;

    // Accept a URL given directly, so `--readme <https url>` works - the natural
    // fallback when a competitor has the address but the shortcut cannot be read.
    let as_text = path.to_string_lossy();
    if is_remote_target(&as_text) {
        return download_readme(as_text.trim()).await;
    }

    let mut current = path.to_path_buf();
    for _ in 0..MAX_HOPS {
        let extension = current
            .extension()
            .map(|e| e.to_string_lossy().to_lowercase())
            .unwrap_or_default();

        let next = match extension.as_str() {
            "url" => {
                let contents = read_text_lenient(&current)?;
                let target = parse_internet_shortcut(&contents)?;
                // A competition image hosts the README remotely - the shortcut
                // names an https:// document, not a file on disk - so following
                // it means fetching it.
                if is_remote_target(&target) {
                    return download_readme(&target).await;
                }
                to_local_path(&target)?
            }
            "lnk" => resolve_shortcut_target(&current).await?,
            // The Linux equivalent of a `.url`, and the form an Ubuntu
            // competition image ships: a freedesktop launcher on the Desktop
            // whose target is the README's address.
            "desktop" => {
                let contents = read_text_lenient(&current)?;
                let target = parse_desktop_entry(&contents)?;
                if is_remote_target(&target) {
                    return download_readme(&target).await;
                }
                to_local_path(&target)?
            }
            // Not a shortcut: this is the document itself.
            _ => {
                return current
                    .is_file()
                    .then(|| current.to_string_lossy().into_owned());
            }
        };
        current = PathBuf::from(next);
    }
    None
}

/// Is this shortcut target a remote address rather than a path?
///
/// Nothing about the address is assumed or stored: the README URL is unique per
/// image and changes every competition, so it is always read from the shortcut
/// at run time. Only the scheme is inspected here.
pub fn is_remote_target(target: &str) -> bool {
    let lower = target.trim().to_lowercase();
    lower.starts_with("http://") || lower.starts_with("https://")
}

/// Where a downloaded README is cached.
fn downloaded_readme_path() -> PathBuf {
    std::env::temp_dir().join("pinnaclecypat_readme.html")
}

/// Fetch a remotely hosted README and return the local path it was saved to.
///
/// A standard competition image does not ship the README as a file:
/// `C:\CyberPatriot\README.url` points at an https:// document (an S3 object),
/// which is what the competitor's browser opens. Reading it therefore requires
/// an HTTP request.
///
/// This shells out rather than linking an HTTP client: it keeps TLS, the
/// certificate store and any configured proxy in the hands of the OS, adds no
/// dependency to a cross-compiled binary, and matches how the rest of the tool
/// talks to the system. `Invoke-WebRequest` is present on every supported
/// Windows; `curl.exe` (shipped since Windows 10 1803) is the fallback.
async fn download_readme(url: &str) -> Option<String> {
    let dest = downloaded_readme_path();
    let dest_str = dest.to_string_lossy().into_owned();

    crate::ui::markup_line(&format!(
        "[cyan]Downloading README from {}[/]",
        crate::ui::escape(url)
    ));

    match crate::command::download_file(url, &dest).await {
        Ok(()) => Some(dest_str),
        Err(reason) => {
            crate::ui::markup_line(&format!(
                "[red]✗ Could not download the README: {}[/]",
                crate::ui::escape(&reason)
            ));
            None
        }
    }
}

/// Explain why an existing candidate could not be turned into a README path.
///
/// The distinction that matters is *why* a shortcut failed: pointing at a web
/// address is a different problem from pointing at a file that is not there,
/// and neither is visible from a bare "could not be resolved".
fn describe_unresolvable(path: &Path) -> String {
    let extension = path
        .extension()
        .map(|e| e.to_string_lossy().to_lowercase())
        .unwrap_or_default();

    if !matches!(extension.as_str(), "url" | "desktop") {
        return "exists but could not be resolved to a readable file".to_string();
    }

    let Some(contents) = read_text_lenient(path) else {
        return "shortcut could not be read".to_string();
    };
    let parsed = if extension == "desktop" {
        parse_desktop_entry(&contents)
    } else {
        parse_internet_shortcut(&contents)
    };
    let Some(target) = parsed else {
        return if extension == "desktop" {
            "launcher has no URL= entry and no address in its Exec= line".to_string()
        } else {
            "shortcut has no URL= entry".to_string()
        };
    };

    if is_remote_target(&target) {
        // Reaching here means the download was attempted and failed.
        return format!("shortcut points to '{target}', which could not be downloaded");
    }

    match to_local_path(&target) {
        Some(local) => format!("shortcut points to '{local}', which does not exist"),
        None => format!("shortcut target '{target}' is not a usable location"),
    }
}

/// Read a text file without assuming it is valid UTF-8.
///
/// `std::fs::read_to_string` fails outright on anything that is not UTF-8, and
/// Windows tools routinely write UTF-16 (with a BOM) or single-byte extended
/// ASCII. A `.url` written that way made shortcut resolution return `None`,
/// which surfaced as "no README found" with nothing to explain it. Decode by
/// BOM, and fall back to a lossy read rather than discarding the file.
fn read_text_lenient(path: &Path) -> Option<String> {
    let bytes = std::fs::read(path).ok()?;

    match bytes.as_slice() {
        [0xFF, 0xFE, rest @ ..] => Some(decode_utf16(rest, u16::from_le_bytes)),
        [0xFE, 0xFF, rest @ ..] => Some(decode_utf16(rest, u16::from_be_bytes)),
        // Strip a UTF-8 BOM so the first key is not prefixed with it.
        [0xEF, 0xBB, 0xBF, rest @ ..] => Some(String::from_utf8_lossy(rest).into_owned()),
        _ => Some(String::from_utf8_lossy(&bytes).into_owned()),
    }
}

fn decode_utf16(bytes: &[u8], to_u16: fn([u8; 2]) -> u16) -> String {
    let units: Vec<u16> = bytes
        .as_chunks::<2>()
        .0
        .iter()
        .copied()
        .map(to_u16)
        .collect();
    String::from_utf16_lossy(&units)
}

/// Extract the `URL=` value from an Internet Shortcut.
///
/// The format is INI-like:
///
/// ```text
/// [InternetShortcut]
/// URL=file:///C:/CyberPatriot/README.html
/// IconIndex=0
/// ```
pub fn parse_internet_shortcut(contents: &str) -> Option<String> {
    contents.lines().find_map(|line| {
        let (key, value) = line.split_once('=')?;
        key.trim()
            .eq_ignore_ascii_case("URL")
            .then(|| value.trim().to_string())
    })
}

/// Read the target out of a freedesktop `.desktop` launcher.
///
/// This is how an Ubuntu competition image ships its README: not as a file, and
/// not as a `.url`, but as a launcher on the Desktop. Two shapes appear, and
/// both are handled because which one an image uses is not predictable:
///
/// ```text
/// [Desktop Entry]          [Desktop Entry]
/// Type=Link                Type=Application
/// URL=https://...          Exec=firefox https://...
/// ```
///
/// The `Exec=` form needs more care than it looks. The value is a command line,
/// so the address is one token among several and may be quoted; and it can
/// carry freedesktop *field codes* - `%u`, `%U`, `%f`, `%F` - which are
/// placeholders the desktop environment substitutes, not part of the address.
/// Passing `https://example.com/x.html %u` to a downloader fetches nothing.
pub fn parse_desktop_entry(contents: &str) -> Option<String> {
    let mut exec_line: Option<&str> = None;

    for line in contents.lines() {
        let line = line.trim();
        // Comments, and the `[Desktop Entry]` group header.
        if line.starts_with('#') || line.starts_with('[') {
            continue;
        }
        let Some((key, value)) = line.split_once('=') else {
            continue;
        };
        let key = key.trim();
        let value = value.trim();

        // `URL=` is unambiguous, so it wins outright when present.
        if key.eq_ignore_ascii_case("URL") && !value.is_empty() {
            return Some(value.to_string());
        }
        if key.eq_ignore_ascii_case("Exec") && exec_line.is_none() {
            exec_line = Some(value);
        }
    }

    exec_line.and_then(url_in_command_line)
}

/// Pull the first http(s) address out of a command line.
///
/// Strips the quoting a launcher uses around an argument, and the trailing
/// punctuation a hand-edited file picks up.
fn url_in_command_line(command: &str) -> Option<String> {
    command
        .split_whitespace()
        // A field code is a placeholder, not an argument - see
        // [`parse_desktop_entry`].
        .filter(|token| !matches!(*token, "%u" | "%U" | "%f" | "%F" | "%i" | "%c" | "%k"))
        .map(|token| token.trim_matches(|c| matches!(c, '"' | '\'' | ',' | ';')))
        .find(|token| is_remote_target(token))
        .map(str::to_string)
}

/// Convert a shortcut target into a local Windows path, if it names one.
///
/// Targets appear either as a `file:` URI or as a bare path. A remote
/// `http(s)` target cannot be read from disk, so it yields `None` rather than a
/// path that would fail to open later.
pub fn to_local_path(target: &str) -> Option<String> {
    let target = target.trim();
    if target.is_empty() {
        return None;
    }

    let lower = target.to_lowercase();
    if lower.starts_with("http://") || lower.starts_with("https://") {
        return None;
    }

    if lower.starts_with("file:") {
        // `file:///C:/x`, `file://C:/x` and `file://localhost/C:/x` all occur.
        let rest = &target["file:".len()..];
        let rest = rest.strip_prefix("//").unwrap_or(rest);
        let rest = rest.strip_prefix("localhost").unwrap_or(rest);
        let decoded = percent_decode(rest);

        // Only a drive-letter target is a Windows path. Blindly stripping every
        // leading slash and swapping separators would turn the absolute POSIX
        // path `/tmp/README.html` into the relative `tmp\README.html`.
        let without_root = decoded.trim_start_matches('/');
        if is_windows_drive_path(without_root) {
            return Some(without_root.replace('/', "\\"));
        }
        return Some(if decoded.starts_with('/') {
            decoded
        } else {
            format!("/{decoded}")
        });
    }

    // A bare target: normalise separators only when it names a Windows drive.
    if is_windows_drive_path(target) {
        return Some(target.replace('/', "\\"));
    }
    Some(target.to_string())
}

/// Does this path begin with a `X:` drive specifier?
fn is_windows_drive_path(path: &str) -> bool {
    let mut chars = path.chars();
    matches!(
        (chars.next(), chars.next()),
        (Some(letter), Some(':')) if letter.is_ascii_alphabetic()
    )
}

/// Decode `%XX` escapes; a URI may encode spaces and other characters.
fn percent_decode(input: &str) -> String {
    let bytes = input.as_bytes();
    let mut out: Vec<u8> = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' && i + 2 < bytes.len() {
            let hex = std::str::from_utf8(&bytes[i + 1..i + 3]).ok();
            if let Some(byte) = hex.and_then(|h| u8::from_str_radix(h, 16).ok()) {
                out.push(byte);
                i += 3;
                continue;
            }
        }
        out.push(bytes[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// Resolve a single-`*` pattern such as `C:\Users\*\Desktop\README.html` by
/// enumerating the directory in the `*` position.
///
/// The C# original (and the first port of it) stripped the `*` and searched the
/// remaining directory *recursively* for the file name. Stripping turned
/// `C:\Users\*\Desktop\README.html` into a parent of `C:\Users\Desktop`, which
/// does not exist - so this fallback silently never matched anything. Had the
/// directory existed, recursing the whole of `C:\Users` would have been worse:
/// it would return the first `README.html` found anywhere in any user's
/// profile, documents and downloads included, rather than a competition README.
fn expand_wildcard_path(pattern: &str) -> Option<String> {
    let (prefix, suffix) = pattern.split_once('*')?;
    let parent = Path::new(prefix.trim_end_matches(['\\', '/']));
    let suffix = suffix.trim_start_matches(['\\', '/']);

    let mut matches: Vec<PathBuf> = std::fs::read_dir(parent)
        .ok()?
        .flatten()
        .map(|entry| entry.path().join(suffix))
        .filter(|candidate| candidate.is_file())
        .collect();

    // Directory order is arbitrary; sort so repeated runs pick the same file.
    matches.sort();
    matches
        .into_iter()
        .next()
        .map(|p| p.to_string_lossy().into_owned())
}

/// Look in `dir` for a README shortcut and resolve it to its target.
///
/// Both shortcut kinds are considered: competition images use `.url` Internet
/// Shortcuts for the README, while a hand-made desktop link is usually a `.lnk`.
/// Entries are sorted so a directory containing both resolves the same way on
/// every run, and `.url` is preferred because it is the form the image ships.
async fn find_readme_shortcut(dir: &Path) -> Option<String> {
    let mut candidates: Vec<PathBuf> = std::fs::read_dir(dir)
        .ok()?
        .flatten()
        .map(|entry| entry.path())
        .filter(|path| is_shortcut(path) && shortcut_name_looks_like_readme(path))
        .collect();

    candidates.sort_by_key(|path| {
        let ext = path
            .extension()
            .map(|e| e.to_string_lossy().to_lowercase())
            .unwrap_or_default();
        // `.url` first, then `.desktop`, then `.lnk`, then by name for
        // determinism. Each platform's own form is tried before the others.
        let rank = match ext.as_str() {
            "url" => 0,
            "desktop" => 1,
            _ => 2,
        };
        (rank, path.to_string_lossy().to_lowercase())
    });

    for path in candidates {
        if let Some(target) = resolve_readme_candidate(&path).await {
            return Some(target);
        }
    }
    None
}

/// Is this path a shortcut rather than a document?
pub fn is_shortcut(path: &Path) -> bool {
    path.extension()
        .map(|e| {
            e.eq_ignore_ascii_case("url")
                || e.eq_ignore_ascii_case("lnk")
                || e.eq_ignore_ascii_case("desktop")
        })
        .unwrap_or(false)
}

/// Does this shortcut's file name suggest it points at the README?
/// (e.g. "README.url", "Read Me.lnk", "CyberPatriot README.lnk")
fn shortcut_name_looks_like_readme(path: &Path) -> bool {
    path.file_stem()
        .map(|s| {
            s.to_string_lossy()
                .to_lowercase()
                .replace(' ', "")
                .contains("readme")
        })
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

#[cfg(test)]
mod tests {
    use super::*;

    /// The form an Ubuntu competition image actually ships: a launcher on the
    /// Desktop whose target is the README's address.
    #[test]
    fn a_link_launcher_yields_its_url() {
        let entry = "\
[Desktop Entry]
Encoding=UTF-8
Name=Exhibition Round Ubuntu 22.04 README
Type=Link
URL=https://cp19.s3.us-east-1.amazonaws.com/cp19_exrd/private/readme.html
Icon=text-html
";
        assert_eq!(
            parse_desktop_entry(entry).as_deref(),
            Some("https://cp19.s3.us-east-1.amazonaws.com/cp19_exrd/private/readme.html")
        );
    }

    /// The other shape: a launcher that opens the address in a browser. The
    /// address is one token of a command line rather than the whole value.
    #[test]
    fn an_exec_launcher_yields_the_address_from_its_command_line() {
        for exec in [
            "Exec=firefox https://example.com/readme.html",
            "Exec=xdg-open https://example.com/readme.html",
            "Exec=/usr/bin/firefox --new-tab https://example.com/readme.html",
            "Exec=firefox \"https://example.com/readme.html\"",
        ] {
            let entry = format!("[Desktop Entry]\nType=Application\n{exec}\n");
            assert_eq!(
                parse_desktop_entry(&entry).as_deref(),
                Some("https://example.com/readme.html"),
                "{exec}"
            );
        }
    }

    /// Field codes are placeholders the desktop environment substitutes, not
    /// part of the address. Passing `%u` to a downloader fetches nothing.
    #[test]
    fn freedesktop_field_codes_are_not_mistaken_for_the_address() {
        let entry =
            "[Desktop Entry]\nType=Application\nExec=firefox %u https://example.com/r.html\n";
        assert_eq!(
            parse_desktop_entry(entry).as_deref(),
            Some("https://example.com/r.html")
        );
    }

    /// `URL=` is unambiguous, so it wins over an `Exec=` line that names
    /// something else - a launcher can carry both.
    #[test]
    fn an_explicit_url_wins_over_the_exec_line() {
        let entry = "\
[Desktop Entry]
Type=Link
Exec=firefox https://wrong.example/other.html
URL=https://right.example/readme.html
";
        assert_eq!(
            parse_desktop_entry(entry).as_deref(),
            Some("https://right.example/readme.html")
        );
    }

    #[test]
    fn a_launcher_with_no_address_yields_nothing() {
        assert!(
            parse_desktop_entry("[Desktop Entry]\nType=Application\nExec=gnome-terminal\n")
                .is_none()
        );
        assert!(parse_desktop_entry("").is_none());
        // The group header is not a key=value line.
        assert!(parse_desktop_entry("[Desktop Entry]\n").is_none());
    }

    /// The competition resources live in `/opt/CyberPatriot` - capital C,
    /// capital P. Linux filesystems are case-sensitive, so the lower-case
    /// spelling that looks natural in code finds nothing on a real image.
    #[test]
    fn the_canonical_resource_directory_is_spelled_the_way_the_image_spells_it() {
        if cfg!(windows) {
            assert!(CYBERPATRIOT_DIRS.contains(&r"C:\CyberPatriot"));
            return;
        }
        assert_eq!(
            CYBERPATRIOT_DIRS.first(),
            Some(&"/opt/CyberPatriot"),
            "the canonical directory must be tried first, and with its real case"
        );
        assert!(
            CYBERPATRIOT_DIRS.contains(&"/opt/cyberpatriot"),
            "a hand-made image may use the lower-case spelling"
        );
    }

    /// The launcher is not called `README.desktop` - it is called whatever the
    /// round named it. So the resource directory has to be *scanned*, which is
    /// what putting it in the search-dirs list does; probing fixed file names
    /// there would find nothing.
    #[tokio::test]
    async fn the_resource_directory_is_scanned_by_name_not_probed_by_filename() {
        let root = std::env::temp_dir().join(format!("cpa_optcp_{}", std::process::id()));
        std::fs::create_dir_all(&root).unwrap();
        let launcher = root.join("Exhibition Round Ubuntu 22.04 README.desktop");
        std::fs::write(
            &launcher,
            "[Desktop Entry]\nType=Link\nURL=file:///nonexistent/readme.html\n",
        )
        .unwrap();

        // The name is what identifies it, and the extension is what makes it a
        // shortcut. Both hold for a launcher named after the round.
        assert!(is_shortcut(&launcher));
        assert!(shortcut_name_looks_like_readme(&launcher));

        let _ = std::fs::remove_dir_all(&root);
    }

    /// A commented-out entry is not in effect.
    #[test]
    fn commented_entries_are_ignored() {
        let entry = "[Desktop Entry]\n#URL=https://commented.example/x.html\nType=Link\n";
        assert!(parse_desktop_entry(entry).is_none());
    }

    /// The launcher on the Ubuntu image is not called `README.desktop` - it is
    /// called whatever the round named it. Discovery matches on the name
    /// containing "readme", so this has to hold.
    #[test]
    fn the_rounds_own_launcher_name_is_recognised() {
        for name in [
            "Exhibition Round Ubuntu 22.04 README.desktop",
            "README.desktop",
            "CyberPatriot README.desktop",
            "Read Me.desktop",
        ] {
            let path = Path::new(name);
            assert!(is_shortcut(path), "{name} should be treated as a shortcut");
        }
    }

    #[test]
    fn a_desktop_launcher_is_a_shortcut_and_a_html_file_is_not() {
        assert!(is_shortcut(Path::new("/home/perry/Desktop/README.desktop")));
        assert!(is_shortcut(Path::new("C:/CyberPatriot/README.url")));
        assert!(!is_shortcut(Path::new("/home/perry/Desktop/README.html")));
    }

    #[test]
    fn wildcard_expands_to_a_real_file_in_the_starred_position() {
        let root = std::env::temp_dir().join(format!("cpa_wild_{}", std::process::id()));
        let alice = root.join("alice").join("Desktop");
        let bob = root.join("bob").join("Desktop");
        std::fs::create_dir_all(&alice).unwrap();
        std::fs::create_dir_all(&bob).unwrap();
        std::fs::write(bob.join("README.html"), "<html></html>").unwrap();

        let pattern = format!("{}/*/Desktop/README.html", root.to_string_lossy());
        let found = expand_wildcard_path(&pattern).expect("should find bob's README");
        assert!(found.contains("bob"), "got {found}");

        let _ = std::fs::remove_dir_all(&root);
    }

    // A standard competition image ships C:\CyberPatriot\README.url - an
    // Internet Shortcut, not the document. Following it is the whole point.

    #[test]
    fn internet_shortcut_url_value_is_extracted() {
        let contents =
            "[InternetShortcut]\r\nURL=file:///C:/CyberPatriot/README.html\r\nIconIndex=0\r\n";
        assert_eq!(
            parse_internet_shortcut(contents).as_deref(),
            Some("file:///C:/CyberPatriot/README.html")
        );
    }

    #[test]
    fn internet_shortcut_key_is_case_insensitive_and_tolerates_other_keys() {
        let contents = "[InternetShortcut]\r\nIDList=\r\nurl=C:\\CyberPatriot\\README.html\r\n";
        assert_eq!(
            parse_internet_shortcut(contents).as_deref(),
            Some("C:\\CyberPatriot\\README.html")
        );
    }

    #[test]
    fn file_uri_forms_all_convert_to_a_windows_path() {
        for uri in [
            "file:///C:/CyberPatriot/README.html",
            "file://C:/CyberPatriot/README.html",
            "file://localhost/C:/CyberPatriot/README.html",
        ] {
            assert_eq!(
                to_local_path(uri).as_deref(),
                Some("C:\\CyberPatriot\\README.html"),
                "failed for {uri}"
            );
        }
    }

    #[test]
    fn percent_escapes_in_a_file_uri_are_decoded() {
        assert_eq!(
            to_local_path("file:///C:/Cyber%20Patriot/READ%20ME.html").as_deref(),
            Some("C:\\Cyber Patriot\\READ ME.html")
        );
    }

    #[test]
    fn a_bare_path_target_is_used_as_is() {
        assert_eq!(
            to_local_path("C:\\CyberPatriot\\README.html").as_deref(),
            Some("C:\\CyberPatriot\\README.html")
        );
    }

    #[test]
    fn a_remote_target_is_not_treated_as_a_local_file() {
        // Nothing on disk to open, so it must not be returned as a path.
        assert_eq!(to_local_path("https://example.org/readme.html"), None);
        assert_eq!(to_local_path(""), None);
    }

    #[test]
    fn an_absolute_posix_target_keeps_its_root() {
        // Stripping every leading slash and swapping separators would turn this
        // absolute path into a relative one.
        assert_eq!(
            to_local_path("file:///tmp/CyberPatriot/README.html").as_deref(),
            Some("/tmp/CyberPatriot/README.html")
        );
    }

    #[tokio::test]
    async fn a_url_shortcut_resolves_to_the_document_it_names() {
        let root = std::env::temp_dir().join(format!("cpa_url_{}", std::process::id()));
        std::fs::create_dir_all(&root).unwrap();
        let doc = root.join("README.html");
        std::fs::write(&doc, "<html><h1>Windows 10</h1></html>").unwrap();

        let shortcut = root.join("README.url");
        let uri = format!("file:///{}", doc.to_string_lossy().replace('\\', "/"));
        std::fs::write(&shortcut, format!("[InternetShortcut]\r\nURL={uri}\r\n")).unwrap();

        let resolved = resolve_readme_candidate(&shortcut)
            .await
            .expect("shortcut should resolve");
        assert!(resolved.ends_with("README.html"), "got {resolved}");
        assert!(Path::new(&resolved).is_file());

        let _ = std::fs::remove_dir_all(&root);
    }

    #[tokio::test]
    async fn a_utf16_encoded_url_shortcut_still_resolves() {
        // Windows tools often write UTF-16 with a BOM. `read_to_string` rejects
        // it outright, which made resolution return None and surfaced as
        // "no README found" with nothing to explain why.
        let root = std::env::temp_dir().join(format!("cpa_utf16_{}", std::process::id()));
        std::fs::create_dir_all(&root).unwrap();
        let doc = root.join("README.html");
        std::fs::write(&doc, "<html><h1>Windows 10</h1></html>").unwrap();

        let text = format!(
            "[InternetShortcut]\r\nURL=file://{}\r\n",
            doc.to_string_lossy().replace('\\', "/")
        );
        let mut bytes = vec![0xFF, 0xFE]; // UTF-16LE BOM
        for unit in text.encode_utf16() {
            bytes.extend_from_slice(&unit.to_le_bytes());
        }
        let shortcut = root.join("README.url");
        std::fs::write(&shortcut, bytes).unwrap();

        let resolved = resolve_readme_candidate(&shortcut)
            .await
            .expect("a UTF-16 shortcut should still resolve");
        assert!(resolved.ends_with("README.html"), "got {resolved}");

        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn remote_targets_are_recognised() {
        // Only the scheme is examined. The addresses below are sample data: the
        // real one is unique per image and read from the shortcut at run time,
        // so no host, bucket or path is baked into the tool.
        assert!(is_remote_target(
            "https://example-bucket.s3.us-east-1.amazonaws.com/round/private/readme.html"
        ));
        assert!(is_remote_target(
            "https://any-other-host.example/whatever.html"
        ));
        assert!(is_remote_target("http://example.org/readme.html"));
        assert!(is_remote_target("  HTTPS://EXAMPLE.ORG/x  "));

        assert!(!is_remote_target("C:\\CyberPatriot\\README.html"));
        assert!(!is_remote_target("file:///C:/CyberPatriot/README.html"));
        assert!(!is_remote_target(""));
    }

    #[test]
    fn a_remote_shortcut_reports_a_download_failure_not_a_bad_path() {
        let root = std::env::temp_dir().join(format!("cpa_remote_{}", std::process::id()));
        std::fs::create_dir_all(&root).unwrap();
        // Sample address; the real one differs per image and is read from the
        // shortcut, never assumed.
        let shortcut = root.join("README.url");
        std::fs::write(
            &shortcut,
            "[InternetShortcut]\r\nURL=https://example-bucket.s3.amazonaws.com/x/readme.html\r\n",
        )
        .unwrap();

        let reason = describe_unresolvable(&shortcut);
        assert!(reason.contains("could not be downloaded"), "got: {reason}");
        // The diagnostic must echo whatever address the shortcut carried.
        assert!(reason.contains("example-bucket.s3"), "got: {reason}");

        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn an_unresolvable_shortcut_says_what_it_points_at() {
        let root = std::env::temp_dir().join(format!("cpa_why_{}", std::process::id()));
        std::fs::create_dir_all(&root).unwrap();

        let web = root.join("web.url");
        std::fs::write(
            &web,
            "[InternetShortcut]\r\nURL=https://example.org/readme.html\r\n",
        )
        .unwrap();
        let reason = describe_unresolvable(&web);
        assert!(reason.contains("could not be downloaded"), "got: {reason}");
        assert!(reason.contains("https://example.org"), "got: {reason}");

        let missing = root.join("missing.url");
        std::fs::write(
            &missing,
            "[InternetShortcut]\r\nURL=file:///C:/nope/gone.html\r\n",
        )
        .unwrap();
        let reason = describe_unresolvable(&missing);
        assert!(reason.contains("does not exist"), "got: {reason}");
        assert!(reason.contains("gone.html"), "got: {reason}");

        let _ = std::fs::remove_dir_all(&root);
    }

    #[tokio::test]
    async fn discovery_reports_every_location_it_checked() {
        let mut attempts = Vec::new();
        let _ = find_readme_file_reporting(&mut attempts).await;
        assert!(
            !attempts.is_empty(),
            "failed discovery must explain where it looked"
        );
        // The canonical location differs by platform: `C:\CyberPatriot` on
        // Windows, somebody's Desktop on Linux.
        let canonical = if cfg!(windows) {
            "CyberPatriot"
        } else {
            "Desktop"
        };
        assert!(
            attempts.iter().any(|a| a.contains(canonical)),
            "the canonical image location should appear: {attempts:?}"
        );
    }

    #[tokio::test]
    async fn shortcut_chains_are_followed_to_the_document() {
        // A real image chains: desktop .lnk -> C:\CyberPatriot\README.url -> the
        // HTML. Stopping after one hop returns the .url, and parsing that INI
        // file as HTML produces a README with no title and no detectable OS -
        // the "Unknown / Unknown" output seen on a live competition VM.
        // `.lnk` needs Windows shell interop, so the chain is exercised here
        // with .url -> .url -> .html, which uses the same hop loop.
        let root = std::env::temp_dir().join(format!("cpa_chain_{}", std::process::id()));
        std::fs::create_dir_all(&root).unwrap();

        let doc = root.join("README.html");
        std::fs::write(&doc, "<html><h1>Windows 10</h1></html>").unwrap();

        let inner = root.join("inner.url");
        std::fs::write(
            &inner,
            format!(
                "[InternetShortcut]\r\nURL=file://{}\r\n",
                doc.to_string_lossy().replace('\\', "/")
            ),
        )
        .unwrap();

        let outer = root.join("README.url");
        std::fs::write(
            &outer,
            format!(
                "[InternetShortcut]\r\nURL=file://{}\r\n",
                inner.to_string_lossy().replace('\\', "/")
            ),
        )
        .unwrap();

        let resolved = resolve_readme_candidate(&outer)
            .await
            .expect("chain should resolve to the document");
        assert!(
            resolved.ends_with("README.html"),
            "expected the HTML document, got {resolved}"
        );

        let _ = std::fs::remove_dir_all(&root);
    }

    #[tokio::test]
    async fn a_shortcut_loop_terminates() {
        let root = std::env::temp_dir().join(format!("cpa_loop_{}", std::process::id()));
        std::fs::create_dir_all(&root).unwrap();

        let a = root.join("a.url");
        let b = root.join("b.url");
        let uri = |p: &Path| format!("file://{}", p.to_string_lossy().replace('\\', "/"));
        std::fs::write(&a, format!("[InternetShortcut]\r\nURL={}\r\n", uri(&b))).unwrap();
        std::fs::write(&b, format!("[InternetShortcut]\r\nURL={}\r\n", uri(&a))).unwrap();

        // Must give up rather than spin forever.
        assert_eq!(resolve_readme_candidate(&a).await, None);

        let _ = std::fs::remove_dir_all(&root);
    }

    #[tokio::test]
    async fn a_url_shortcut_pointing_at_a_missing_file_resolves_to_nothing() {
        let root = std::env::temp_dir().join(format!("cpa_url_dead_{}", std::process::id()));
        std::fs::create_dir_all(&root).unwrap();
        let shortcut = root.join("README.url");
        std::fs::write(
            &shortcut,
            "[InternetShortcut]\r\nURL=file:///C:/nope/does-not-exist.html\r\n",
        )
        .unwrap();

        // A stale shortcut must not masquerade as a README.
        assert_eq!(resolve_readme_candidate(&shortcut).await, None);

        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn default_paths_lead_with_the_standard_image_location() {
        let paths = default_readme_paths();
        assert!(!paths.is_empty());
        assert!(paths.iter().any(|p| p.ends_with("README.html")));

        // Each platform leads with the form its own image ships.
        if cfg!(windows) {
            assert_eq!(paths[0], r"C:\CyberPatriot\README.url");
        } else {
            assert!(
                paths.iter().any(|p| p.ends_with(".desktop")),
                "an Ubuntu image ships a launcher, not a file: {paths:?}"
            );
        }
    }

    /// Both platforms' path lists are built, not just the host's - a mistake in
    /// the one that is not compiled here would not surface until it shipped.
    #[test]
    fn both_platforms_have_a_usable_path_list() {
        for paths in [windows_readme_paths(), linux_readme_paths()] {
            assert!(!paths.is_empty());
            assert!(paths.iter().all(|p| !p.trim().is_empty()));
        }
        assert!(
            linux_readme_paths().iter().any(|p| p.starts_with("/home/")),
            "the launcher lives on somebody's desktop"
        );
    }

    #[test]
    fn wildcard_returns_none_when_nothing_matches() {
        let root = std::env::temp_dir().join(format!("cpa_wild_empty_{}", std::process::id()));
        std::fs::create_dir_all(root.join("alice").join("Desktop")).unwrap();

        let pattern = format!("{}/*/Desktop/README.html", root.to_string_lossy());
        assert_eq!(expand_wildcard_path(&pattern), None);

        let _ = std::fs::remove_dir_all(&root);
    }
}
