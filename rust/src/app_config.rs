// =============================================================================
// PinnacleCyPat
// Author: Maxwell McCormick
// Copyright (c) 2026 Maxwell McCormick. All Rights Reserved.
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

/// The machine-wide (common) desktop directory.
pub fn common_desktop_dir() -> PathBuf {
    PathBuf::from(r"C:\Users\Public\Desktop")
}

/// Default CyberPatriot competition README paths on Windows images.
///
/// A standard image ships `C:\CyberPatriot\README.url` - an *Internet
/// Shortcut*, not the document itself. It is listed first because it is the
/// canonical location; [`resolve_readme_candidate`] follows it to the HTML file
/// it names. The literal `.html` paths remain for images that place the
/// document directly.
pub fn default_readme_paths() -> Vec<String> {
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
    for dir in [desktop_dir(), common_desktop_dir()] {
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
    let is_url = path
        .extension()
        .map(|e| e.eq_ignore_ascii_case("url"))
        .unwrap_or(false);

    if !is_url {
        return "exists but could not be resolved to a readable file".to_string();
    }

    let Some(contents) = read_text_lenient(path) else {
        return "shortcut could not be read".to_string();
    };
    let Some(target) = parse_internet_shortcut(&contents) else {
        return "shortcut has no URL= entry".to_string();
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
    let units: Vec<u16> = bytes.as_chunks::<2>().0.iter().copied().map(to_u16).collect();
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
        // `.url` first, then `.lnk`, then by name for determinism.
        (ext != "url", path.to_string_lossy().to_lowercase())
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
        .map(|e| e.eq_ignore_ascii_case("url") || e.eq_ignore_ascii_case("lnk"))
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
        assert!(
            attempts.iter().any(|a| a.contains("CyberPatriot")),
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
        assert_eq!(paths[0], r"C:\CyberPatriot\README.url");
        assert!(paths.iter().any(|p| p.ends_with("README.html")));
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
