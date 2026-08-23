// =============================================================================
// PinnacleCyPat - Software matching and uninstall-command derivation
// Author: Maxwell McCormick
// Copyright (c) 2026 Maxwell McCormick. All Rights Reserved.
// =============================================================================

//! Bridging the names Windows records to the packages Chocolatey knows, and
//! turning a registered `UninstallString` into something runnable unattended.
//!
//! The two naming schemes never agree. Windows records `Notepad++ (64-bit x64)`,
//! `Mozilla Firefox (x64 en-US)`, `7-Zip 23.01 (x64)`; Chocolatey wants
//! `notepadplusplus.install`, `firefox`, `7zip.install`. Matching has to
//! tolerate the version, architecture and locale suffixes real display names
//! carry, or it matches only the handful of products registered with a bare
//! name.
//!
//! The uninstall half exists because `wmic product call uninstall` does not
//! work. It reads `Win32_Product`, which lists **only MSI-installed** software -
//! and CCleaner, Notepad++ and Jellyfin Media Player all ship NSIS installers,
//! so they are not in it at all. Worse, `wmic` exits **0** when its `where`
//! clause matches nothing, so the caller saw success and reported software as
//! removed while it sat untouched on disk.

/// One installed program, as Add/Remove Programs sees it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InstalledSoftware {
    pub name: String,
    pub version: Option<String>,
    /// The registered uninstall command, if any.
    pub uninstall_string: Option<String>,
    /// True when it came from `QuietUninstallString` and is already unattended.
    pub uninstall_is_quiet: bool,
}

impl InstalledSoftware {
    /// A name-only entry, for the `wmic` fallback inventory.
    pub fn named(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            version: None,
            uninstall_string: None,
            uninstall_is_quiet: false,
        }
    }
}

/// Reduce a display name to a comparable core: lower-cased, with version,
/// architecture and locale decoration removed.
///
/// Punctuation is kept. `Notepad++` and `7-Zip` would otherwise normalise to
/// `notepad` and `7zip`, and `notepad` is a suspiciously generic word to match
/// on.
pub fn normalize(display_name: &str) -> String {
    let mut text = display_name.trim().to_string();

    // Drop every parenthesised group: "(64-bit)", "(x64 en-US)".
    text = strip_parentheticals(&text);

    // Drop a trailing version number, with or without a leading "v".
    text = strip_trailing_version(&text);

    // Drop bare architecture and bitness words wherever they appear.
    const ARCH_WORDS: [&str; 7] = ["x64", "x86", "amd64", "32-bit", "64-bit", "win64", "win32"];
    let kept: Vec<&str> = text
        .split_whitespace()
        .filter(|word| !ARCH_WORDS.iter().any(|a| word.eq_ignore_ascii_case(a)))
        .collect();

    kept.join(" ").trim().to_lowercase()
}

fn strip_parentheticals(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    let mut depth = 0usize;
    for ch in text.chars() {
        match ch {
            '(' => depth += 1,
            ')' => depth = depth.saturating_sub(1),
            _ if depth == 0 => out.push(ch),
            _ => {}
        }
    }
    out
}

/// Remove a trailing `1.2.3` or `v1.2.3`, which is decoration rather than name.
fn strip_trailing_version(text: &str) -> String {
    let trimmed = text.trim_end();
    let Some(last) = trimmed.split_whitespace().next_back() else {
        return trimmed.to_string();
    };

    let candidate = last.strip_prefix('v').unwrap_or(last);
    let looks_like_version = !candidate.is_empty()
        && candidate.chars().all(|c| c.is_ascii_digit() || c == '.')
        && candidate.chars().any(|c| c.is_ascii_digit());

    if !looks_like_version {
        return trimmed.to_string();
    }

    trimmed[..trimmed.len() - last.len()].trim_end().to_string()
}

/// Does `display_name` name the software `term` refers to?
///
/// Used for the prohibited list, where the term is a bare product name
/// ("CCleaner") and the display name is whatever the publisher registered.
pub fn matches(display_name: &str, term: &str) -> bool {
    let name = normalize(display_name);
    let needle = normalize(term);
    !name.is_empty() && !needle.is_empty() && name.contains(&needle)
}

/// The Chocolatey package id for an installed program, or `None`.
///
/// The longest matching key wins, so "Mozilla Firefox" is preferred over
/// "Firefox" and a short key cannot shadow a more specific one.
pub fn resolve_package_id(display_name: &str, package_ids: &[(&str, &str)]) -> Option<String> {
    let name = normalize(display_name);
    if name.is_empty() {
        return None;
    }

    let mut best: Option<(&str, usize)> = None;
    for (key, id) in package_ids {
        let needle = normalize(key);
        if needle.is_empty() || !name.contains(&needle) {
            continue;
        }
        if best.is_none_or(|(_, len)| needle.len() > len) {
            best = Some((id, needle.len()));
        }
    }

    best.map(|(id, _)| id.to_string())
}

/// An uninstaller to run: the program, and the arguments to pass it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UninstallCommand {
    pub program: String,
    pub arguments: String,
}

/// Executable extensions an uninstall string can name.
const PROGRAM_EXTENSIONS: [&str; 5] = [".exe", ".com", ".bat", ".cmd", ".msi"];

/// Split a command line into its program and the rest.
///
/// A quoted program path is taken verbatim up to the closing quote. An unquoted
/// one cannot simply end at the first space: plenty of programs register an
/// unquoted `UninstallString` whose path contains one - `C:\Program
/// Files\CCleaner\uninst.exe` would split into the program `C:\Program` and
/// nonsense arguments, and starting that fails outright. `CreateProcess`
/// recovers by trying successive interpretations; spawning with a separate
/// program and argument list does not. So the split is made at the executable
/// extension, which is unambiguous.
pub fn split_command(command_line: &str) -> (String, String) {
    let line = command_line.trim();
    if line.is_empty() {
        return (String::new(), String::new());
    }

    if let Some(rest) = line.strip_prefix('"') {
        return match rest.find('"') {
            Some(end) => (rest[..end].to_string(), rest[end + 1..].trim().to_string()),
            None => (rest.to_string(), String::new()),
        };
    }

    // Earliest extension match wins, so an argument naming another executable
    // cannot capture the split.
    let lower = line.to_lowercase();
    let mut best: Option<usize> = None;
    for extension in PROGRAM_EXTENSIONS {
        if let Some(at) = lower.find(extension) {
            let end = at + extension.len();
            if best.is_none_or(|b| end < b) {
                best = Some(end);
            }
        }
    }

    if let Some(end) = best {
        return (line[..end].to_string(), line[end..].trim().to_string());
    }

    match line.find(' ') {
        Some(space) => (
            line[..space].to_string(),
            line[space + 1..].trim().to_string(),
        ),
        None => (line.to_string(), String::new()),
    }
}

/// Pull the `{GUID}` product code out of an msiexec argument list.
pub fn extract_product_code(arguments: &str) -> Option<String> {
    let open = arguments.find('{')?;
    let close = arguments[open..].find('}')? + open;
    let code = &arguments[open..=close];
    // A product code is {8-4-4-4-12}; anything else is not one, and a malformed
    // code makes msiexec pop an error dialog and wait.
    (code.len() == 38).then(|| code.to_string())
}

/// The last path segment, splitting on both Windows and POSIX separators.
///
/// Not the standard path API: that uses the *host's* separator, so on a
/// non-Windows host it does not treat a backslash as one and returns the whole
/// path. These are always Windows paths whatever the host, and the tests run on
/// Linux.
fn file_name_of(path: &str) -> &str {
    match path.rfind(['\\', '/']) {
        Some(cut) => &path[cut + 1..],
        None => path,
    }
}

/// Is this Inno Setup's uninstaller?
///
/// Inno names it `unins000.exe`, numbered. A plain `unins` prefix is too loose:
/// CCleaner's NSIS uninstaller is `uninst.exe`, which starts with the same five
/// letters, and handing NSIS Inno's switches leaves it with no silent switch at
/// all so it blocks on a dialog.
fn is_inno_uninstaller(file_name: &str) -> bool {
    let lower = file_name.to_lowercase();
    let Some(stem) = lower.strip_suffix(".exe") else {
        return false;
    };
    let Some(digits) = stem.strip_prefix("unins") else {
        return false;
    };
    !digits.is_empty() && digits.chars().all(|c| c.is_ascii_digit())
}

/// Build a runnable, unattended uninstall command.
///
/// `already_silent` is true when the value came from `QuietUninstallString`,
/// which the publisher has already made unattended - nothing should be added.
pub fn build_uninstall_command(
    uninstall_string: Option<&str>,
    already_silent: bool,
) -> Option<UninstallCommand> {
    let raw = uninstall_string?.trim();
    if raw.is_empty() {
        return None;
    }

    let (program, arguments) = split_command(raw);
    if program.is_empty() {
        return None;
    }

    if already_silent {
        return Some(UninstallCommand { program, arguments });
    }

    let file_name = file_name_of(&program);

    // MSI: rewrite rather than append. The registered string is usually
    // "MsiExec.exe /I{GUID}" - /I is *install*, and passing it to an installed
    // product opens the repair dialog instead of removing anything.
    if file_name.to_lowercase().contains("msiexec") {
        let code = extract_product_code(&arguments)?;
        return Some(UninstallCommand {
            program: "msiexec.exe".to_string(),
            arguments: format!("/x {code} /qn /norestart"),
        });
    }

    let switches: Vec<&str> = if is_inno_uninstaller(file_name) {
        vec!["/VERYSILENT", "/SUPPRESSMSGBOXES", "/NORESTART"]
    } else if arguments.to_lowercase().contains("/uninstall") {
        // A bundle re-invoked to uninstall itself, which is how Python
        // registers. Its own switch is already in `arguments`; add the quiet
        // half.
        vec!["/quiet", "/norestart"]
    } else {
        // NSIS. /S is case-sensitive - a lowercase /s is a different switch.
        vec!["/S"]
    };

    let lower_args = arguments.to_lowercase();
    let mut parts: Vec<String> = Vec::new();
    if !arguments.is_empty() {
        parts.push(arguments.clone());
    }
    for switch in switches {
        if !lower_args.contains(&switch.to_lowercase()) {
            parts.push(switch.to_string());
        }
    }

    Some(UninstallCommand {
        program,
        arguments: parts.join(" "),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    const PACKAGE_IDS: [(&str, &str); 5] = [
        ("Notepad++", "notepadplusplus.install"),
        ("Google Chrome", "googlechrome"),
        ("Mozilla Firefox", "firefox"),
        ("Firefox", "firefox"),
        ("7-Zip", "7zip.install"),
    ];

    #[test]
    fn prohibited_software_is_matched_through_its_registered_name() {
        assert!(matches("CCleaner", "CCleaner"));
        assert!(matches("Python 3.12.1 (64-bit)", "Python"));
        assert!(matches("Jellyfin Media Player", "Jellyfin"));
        assert!(matches("CCleaner Free 6.21", "CCleaner"));
    }

    #[test]
    fn unrelated_software_is_not_matched() {
        assert!(!matches("Google Chrome", "Firefox"));
        assert!(!matches("Notepad++ (64-bit x64)", "Python"));
    }

    #[test]
    fn installed_names_resolve_to_their_package() {
        assert_eq!(
            resolve_package_id("Notepad++ (64-bit x64)", &PACKAGE_IDS).as_deref(),
            Some("notepadplusplus.install")
        );
        assert_eq!(
            resolve_package_id("7-Zip 23.01 (x64)", &PACKAGE_IDS).as_deref(),
            Some("7zip.install")
        );
        assert_eq!(
            resolve_package_id("Mozilla Firefox (x64 en-US)", &PACKAGE_IDS).as_deref(),
            Some("firefox")
        );
        assert_eq!(
            resolve_package_id("Bespoke Internal Tool", &PACKAGE_IDS),
            None
        );
    }

    #[test]
    fn normalize_strips_decoration() {
        assert_eq!(normalize("Notepad++ (64-bit x64)"), "notepad++");
        assert_eq!(normalize("Python 3.12.1 (64-bit)"), "python");
        assert_eq!(normalize("7-Zip 23.01 (x64)"), "7-zip");
        assert_eq!(normalize("Mozilla Firefox (x64 en-US)"), "mozilla firefox");
    }

    #[test]
    fn nsis_uninstallers_get_the_silent_switch() {
        // An unquoted path with a space: the common real-world shape, and the
        // one a naive split at the first space gets wrong.
        let command =
            build_uninstall_command(Some(r"C:\Program Files\CCleaner\uninst.exe"), false).unwrap();
        assert_eq!(command.program, r"C:\Program Files\CCleaner\uninst.exe");
        assert_eq!(command.arguments, "/S");
    }

    #[test]
    fn inno_uninstallers_get_very_silent() {
        let command =
            build_uninstall_command(Some(r"C:\Program Files\App\unins000.exe"), false).unwrap();
        assert!(command.arguments.contains("/VERYSILENT"));
    }

    #[test]
    fn msi_uninstallers_are_rewritten_to_remove() {
        let command = build_uninstall_command(
            Some("MsiExec.exe /I{90160000-008C-0000-1000-0000000FF1CE}"),
            false,
        )
        .unwrap();
        assert_eq!(command.program, "msiexec.exe");
        assert_eq!(
            command.arguments,
            "/x {90160000-008C-0000-1000-0000000FF1CE} /qn /norestart"
        );
    }

    #[test]
    fn a_malformed_product_code_is_rejected() {
        assert!(build_uninstall_command(Some("MsiExec.exe /I{not-a-guid}"), false).is_none());
    }

    #[test]
    fn pythons_bundle_uninstaller_is_made_quiet() {
        let command = build_uninstall_command(
            Some(r#""C:\Package Cache\{abc}\python-3.12.1-amd64.exe" /uninstall"#),
            false,
        )
        .unwrap();
        assert!(command.arguments.contains("/uninstall"));
        assert!(command.arguments.contains("/quiet"));
    }

    #[test]
    fn a_quiet_uninstall_string_is_used_verbatim() {
        let command = build_uninstall_command(
            Some(r#""C:\Program Files\App\uninst.exe" /SILENT /NORESTART"#),
            true,
        )
        .unwrap();
        assert_eq!(command.arguments, "/SILENT /NORESTART");
    }

    #[test]
    fn a_switch_already_present_is_not_duplicated() {
        let command = build_uninstall_command(Some(r"C:\App\uninst.exe /S"), false).unwrap();
        assert_eq!(command.arguments, "/S");
    }

    #[test]
    fn a_missing_uninstall_string_yields_nothing() {
        assert!(build_uninstall_command(None, false).is_none());
        assert!(build_uninstall_command(Some("   "), false).is_none());
    }
}
