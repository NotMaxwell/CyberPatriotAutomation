//! The tool's fixed knowledge about Windows, in one place.
//!
//! These tables are *data*, not logic: which registry values harden a machine,
//! which Windows feature names are worth disabling, what a README means when it
//! says "RDP", and which Chocolatey package installs a given program. They live
//! here rather than next to the task that happens to use them because more than
//! one task uses most of them, and a second copy is a second thing to keep
//! right.
//!
//! That is not hypothetical. Before this module existed the service-name table
//! was written out twice — once here for the README readers and once inside
//! service management — and the two had already drifted: the service-management
//! copy was missing `"Remote Desktop Service"` and `"Terminal Services"`, so a
//! README using either spelling was understood by security hardening and group
//! policy but *not* by the task responsible for keeping the service running.
//! The feature list had drifted the same way, by two entries.
//!
//! The tests at the bottom check the tables themselves — duplicate keys,
//! contradictory mappings, malformed registry paths, values that do not parse.
//! A table is the one kind of code where a typo compiles perfectly.

/// Registry settings applied by security hardening: (path, name, type, value, description).
///
/// The description is not decoration - it rides along into the remediation
/// ledger so a reader does not have to know what `fDenyTSConnections` means.
pub const REGISTRY_SETTINGS: &[(&str, &str, &str, &str, &str)] = &[
    // UAC Settings
    (
        r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System",
        "EnableLUA",
        "REG_DWORD",
        "1",
        "Enable UAC",
    ),
    (
        r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System",
        "ConsentPromptBehaviorAdmin",
        "REG_DWORD",
        "5",
        "UAC prompt for admins",
    ),
    (
        r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System",
        "PromptOnSecureDesktop",
        "REG_DWORD",
        "1",
        "UAC on secure desktop",
    ),
    (
        r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System",
        "EnableInstallerDetection",
        "REG_DWORD",
        "1",
        "Enable installer detection",
    ),
    (
        r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System",
        "DisableCAD",
        "REG_DWORD",
        "0",
        "Require Ctrl+Alt+Del",
    ),
    (
        r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System",
        "dontdisplaylastusername",
        "REG_DWORD",
        "1",
        "Don't display last username",
    ),
    (
        r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System",
        "undockwithoutlogon",
        "REG_DWORD",
        "0",
        "Disable undocking without logon",
    ),
    // AutoRun/AutoPlay
    (
        r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer",
        "NoAutorun",
        "REG_DWORD",
        "1",
        "Disable AutoRun",
    ),
    (
        r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer",
        "NoDriveTypeAutoRun",
        "REG_DWORD",
        "255",
        "Disable AutoRun for all drives",
    ),
    // Remote Desktop Disable
    (
        r"HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server",
        "fDenyTSConnections",
        "REG_DWORD",
        "1",
        "Deny RDP connections",
    ),
    (
        r"HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server",
        "fAllowToGetHelp",
        "REG_DWORD",
        "0",
        "Disable Remote Assistance",
    ),
    (
        r"HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server",
        "AllowTSConnections",
        "REG_DWORD",
        "0",
        "Disable TS connections",
    ),
    // Auto Admin Logon Disable
    (
        r"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon",
        "AutoAdminLogon",
        "REG_DWORD",
        "0",
        "Disable auto admin logon",
    ),
    // Windows Defender
    (
        r"HKLM\SOFTWARE\Policies\Microsoft\Windows Defender",
        "DisableAntiSpyware",
        "REG_DWORD",
        "0",
        "Enable Windows Defender",
    ),
    (
        r"HKLM\SOFTWARE\Policies\Microsoft\Windows Defender",
        "ServiceKeepAlive",
        "REG_DWORD",
        "1",
        "Keep Defender alive",
    ),
    (
        r"HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection",
        "DisableRealtimeMonitoring",
        "REG_DWORD",
        "0",
        "Enable real-time monitoring",
    ),
    (
        r"HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection",
        "DisableIOAVProtection",
        "REG_DWORD",
        "0",
        "Enable IOAV protection",
    ),
    // Windows Update
    (
        r"HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU",
        "NoAutoUpdate",
        "REG_DWORD",
        "0",
        "Enable auto update",
    ),
    (
        r"HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU",
        "AUOptions",
        "REG_DWORD",
        "4",
        "Auto download and install",
    ),
    (
        r"HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU",
        "AutoInstallMinorUpdates",
        "REG_DWORD",
        "1",
        "Auto install minor updates",
    ),
    // LSA Protection
    (
        r"HKLM\SYSTEM\CurrentControlSet\Control\Lsa",
        "RunAsPPL",
        "REG_DWORD",
        "1",
        "Enable LSA protection",
    ),
    (
        r"HKLM\SYSTEM\CurrentControlSet\Control\Lsa",
        "LimitBlankPasswordUse",
        "REG_DWORD",
        "1",
        "Limit blank password use",
    ),
    (
        r"HKLM\SYSTEM\CurrentControlSet\Control\Lsa",
        "restrictanonymous",
        "REG_DWORD",
        "1",
        "Restrict anonymous enumeration",
    ),
    (
        r"HKLM\SYSTEM\CurrentControlSet\Control\Lsa",
        "restrictanonymoussam",
        "REG_DWORD",
        "1",
        "Restrict anonymous SAM",
    ),
    (
        r"HKLM\SYSTEM\CurrentControlSet\Control\Lsa",
        "everyoneincludesanonymous",
        "REG_DWORD",
        "0",
        "Anonymous not in Everyone",
    ),
    (
        r"HKLM\SYSTEM\CurrentControlSet\Control\Lsa",
        "disabledomaincreds",
        "REG_DWORD",
        "1",
        "Disable domain credential storage",
    ),
    (
        r"HKLM\SYSTEM\CurrentControlSet\Control\Lsa",
        "auditbaseobjects",
        "REG_DWORD",
        "1",
        "Audit global system objects",
    ),
    (
        r"HKLM\SYSTEM\CurrentControlSet\Control\Lsa",
        "fullprivilegeauditing",
        "REG_DWORD",
        "1",
        "Audit backup/restore",
    ),
    // LSASS Auditing
    (
        r"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\LSASS.exe",
        "AuditLevel",
        "REG_DWORD",
        "8",
        "LSASS audit level",
    ),
    // Memory Protection
    (
        r"HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management",
        "ClearPageFileAtShutdown",
        "REG_DWORD",
        "1",
        "Clear page file at shutdown",
    ),
    // Crash Dump Disable
    (
        r"HKLM\SYSTEM\CurrentControlSet\Control\CrashControl",
        "CrashDumpEnabled",
        "REG_DWORD",
        "0",
        "Disable crash dumps",
    ),
    // CD/Floppy Access
    (
        r"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon",
        "AllocateCDRoms",
        "REG_DWORD",
        "1",
        "Restrict CD-ROM access",
    ),
    (
        r"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon",
        "AllocateFloppies",
        "REG_DWORD",
        "1",
        "Restrict floppy access",
    ),
    // SMB Security
    (
        r"HKLM\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters",
        "EnablePlainTextPassword",
        "REG_DWORD",
        "0",
        "Disable plain text passwords",
    ),
    // Explorer Settings
    (
        r"HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced",
        "Hidden",
        "REG_DWORD",
        "1",
        "Show hidden files",
    ),
    (
        r"HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced",
        "ShowSuperHidden",
        "REG_DWORD",
        "1",
        "Show super hidden files",
    ),
    // IE/Edge Security
    (
        r"HKCU\Software\Microsoft\Internet Explorer\PhishingFilter",
        "EnabledV9",
        "REG_DWORD",
        "1",
        "Enable SmartScreen",
    ),
    (
        r"HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings",
        "DisablePasswordCaching",
        "REG_DWORD",
        "1",
        "Disable password caching",
    ),
    (
        r"HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings",
        "WarnonBadCertRecving",
        "REG_DWORD",
        "1",
        "Warn on bad certificates",
    ),
    (
        r"HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings",
        "WarnOnPostRedirect",
        "REG_DWORD",
        "1",
        "Warn on POST redirect",
    ),
    (
        r"HKCU\Software\Microsoft\Internet Explorer\Main",
        "DoNotTrack",
        "REG_DWORD",
        "1",
        "Enable Do Not Track",
    ),
    // Disable Remote Shell
    (
        r"HKLM\SOFTWARE\Policies\Microsoft\Windows\WinRM\Service\WinRS",
        "AllowRemoteShellAccess",
        "REG_DWORD",
        "0",
        "Disable remote shell",
    ),
];

/// Windows optional features worth removing from a competition image.
///
/// Used by both security hardening and service management. Disabling an
/// already-disabled feature is a no-op, so the overlap costs a process spawn
/// rather than correctness - but the two lists having drifted by two entries is
/// why they are no longer written out separately.
pub const FEATURES_TO_DISABLE: &[&str] = &[
    "TelnetClient",
    "TelnetServer",
    "TFTP",
    "SMB1Protocol",
    "SMB1Protocol-Client",
    "SMB1Protocol-Server",
    "MicrosoftWindowsPowerShellV2",
    "MicrosoftWindowsPowerShellV2Root",
];

/// Windows display names mapped to the Chocolatey package that installs them.
///
/// The `.install` packages run the vendor installer, which puts the program
/// under Program Files. The bare ids are portable packages that unpack under
/// ProgramData instead - and the CP19 answer key deducts points when 7-Zip,
/// Notepad++, Chrome or Wireshark are "not installed at the default location".
pub const PACKAGE_IDS: &[(&str, &str)] = &[
    ("Mozilla Firefox", "firefox"),
    ("Firefox", "firefox"),
    ("Google Chrome", "googlechrome"),
    ("Chrome", "googlechrome"),
    ("7-Zip", "7zip.install"),
    ("7Zip", "7zip.install"),
    ("Notepad++", "notepadplusplus.install"),
    ("VLC", "vlc"),
    ("VLC media player", "vlc"),
    ("Wireshark", "wireshark"),
    ("PuTTY", "putty"),
    ("Python", "python"),
    ("Adobe Acrobat Reader DC", "adobereader"),
    ("Adobe Reader", "adobereader"),
    ("Microsoft Edge", "microsoft-edge"),
    ("Thunderbird", "thunderbird"),
    ("Mozilla Thunderbird", "thunderbird"),
    ("LibreOffice", "libreoffice-fresh"),
    ("Git", "git"),
    ("Malwarebytes", "malwarebytes"),
    // Prohibited by default, and listed here so the update step can exclude
    // them by id. Without an entry they resolve to nothing, and software this
    // run just removed cannot be kept out of `choco upgrade`.
    ("CCleaner", "ccleaner"),
    ("Jellyfin", "jellyfin-media-player"),
    ("Jellyfin Media Player", "jellyfin-media-player"),
];

/// Display names a README might use, mapped to the Windows service name.
///
/// A README writes display names ("Remote Desktop"), not service names
/// ("TermService"), and is inconsistent about which - the same document may say
/// "Remote Desktop Services" in one line and "RDP" in another.
pub const SERVICE_NAME_MAP: &[(&str, &str)] = &[
    ("CCS Client", "CCSClient"),
    ("Remote Desktop", "TermService"),
    ("Remote Desktop Services", "TermService"),
    ("Remote Desktop Service", "TermService"),
    ("RDP", "TermService"),
    ("Terminal Services", "TermService"),
    ("FTP", "ftpsvc"),
    ("Telnet", "TlntSvr"),
    ("SSH", "sshd"),
    ("OpenSSH", "sshd"),
    ("OpenSSH SSH Server", "sshd"),
    ("Remote Registry", "RemoteRegistry"),
    ("Windows Update", "wuauserv"),
    ("Windows Defender", "WinDefend"),
    ("Windows Firewall", "MpsSvc"),
    ("Print Spooler", "Spooler"),
    ("ICS", "SharedAccess"),
    ("Internet Connection Sharing", "SharedAccess"),
];

/// The registry values that turn Remote Desktop off.
///
/// Named rather than filtered by path: the Terminal Server key also carries
/// `fAllowToGetHelp`, which disables Remote *Assistance* - a different feature,
/// never required by a README, and still worth turning off.
pub const REMOTE_DESKTOP_VALUES: &[&str] = &["fDenyTSConnections", "AllowTSConnections"];

/// Software treated as prohibited even when the README does not name it.
///
/// Scoring images routinely include software that is not a hacking tool but is
/// not authorised either - a media player, a scripting runtime, a registry
/// cleaner. The CP19 exhibition answer key scored removing Jellyfin Media
/// Player and Python 3 as separate items and the README named neither, so they
/// are prohibited by default and only spared when the README explicitly
/// requires them.
pub const ALWAYS_PROHIBITED: &[&str] = &["Python", "CCleaner", "Jellyfin"];

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    /// Two rows writing the same value are a merge artefact, and the loser is
    /// silently dead.
    #[test]
    fn no_registry_value_is_set_twice() {
        let mut seen: HashMap<(String, String), &str> = HashMap::new();
        for (path, name, _ty, value, _desc) in REGISTRY_SETTINGS {
            let key = (path.to_lowercase(), name.to_lowercase());
            if let Some(previous) = seen.insert(key, value) {
                assert_eq!(
                    previous, *value,
                    "{path}\\{name} is set twice, to {previous} and {value}"
                );
                panic!("{path}\\{name} appears twice");
            }
        }
    }

    /// The apply loop parses the value as a `u32` and fails the row loudly when
    /// it cannot. A row that can never apply should not be in the table.
    #[test]
    fn every_registry_row_can_actually_be_applied() {
        for (path, name, ty, value, description) in REGISTRY_SETTINGS {
            assert!(
                path.starts_with("HKLM\\") || path.starts_with("HKCU\\"),
                "{path}\\{name}: path must name a hive"
            );
            assert!(
                !description.trim().is_empty(),
                "{path}\\{name}: the ledger prints this, so it cannot be blank"
            );
            assert_eq!(
                *ty, "REG_DWORD",
                "{path}\\{name}: only REG_DWORD is handled; add REG_SZ support first"
            );
            assert!(
                value.parse::<u32>().is_ok(),
                "{path}\\{name}: {value} does not parse as a DWORD"
            );
        }
    }

    /// The skip list is matched against the table by value name, so a typo in
    /// either one silently stops skipping and Remote Desktop gets denied on an
    /// image that needs it.
    #[test]
    fn every_remote_desktop_value_exists_in_the_table() {
        for wanted in REMOTE_DESKTOP_VALUES {
            assert!(
                REGISTRY_SETTINGS.iter().any(|(_, name, ..)| name == wanted),
                "{wanted} is in the skip list but nothing in the table sets it"
            );
        }
    }

    /// Two spellings of one service must not resolve to different services.
    #[test]
    fn no_display_name_maps_to_two_services() {
        let mut seen: HashMap<String, &str> = HashMap::new();
        for (display, service) in SERVICE_NAME_MAP {
            if let Some(previous) = seen.insert(display.to_lowercase(), service) {
                assert_eq!(
                    previous, *service,
                    "\"{display}\" maps to both {previous} and {service}"
                );
            }
        }
    }

    /// The spellings a real README has used. This is the table that had already
    /// drifted once, and every entry here was in the copy that survived.
    #[test]
    fn the_readme_spellings_that_matter_are_all_present() {
        for spelling in [
            "Remote Desktop",
            "Remote Desktop Service",
            "Remote Desktop Services",
            "RDP",
            "Terminal Services",
        ] {
            let found = SERVICE_NAME_MAP
                .iter()
                .find(|(display, _)| display.eq_ignore_ascii_case(spelling));
            assert_eq!(
                found.map(|(_, service)| *service),
                Some("TermService"),
                "{spelling} does not resolve to TermService"
            );
        }
        assert!(
            SERVICE_NAME_MAP
                .iter()
                .any(|(d, s)| *d == "CCS Client" && *s == "CCSClient")
        );
    }

    #[test]
    fn no_package_name_maps_to_two_ids() {
        let mut seen: HashMap<String, &str> = HashMap::new();
        for (name, id) in PACKAGE_IDS {
            if let Some(previous) = seen.insert(name.to_lowercase(), id) {
                assert_eq!(previous, *id, "\"{name}\" maps to both {previous} and {id}");
            }
        }
    }

    /// A package id with a space would need quoting everywhere it is used.
    #[test]
    fn package_ids_are_shaped_like_chocolatey_ids() {
        for (name, id) in PACKAGE_IDS {
            assert!(!id.is_empty(), "{name} maps to an empty id");
            assert_eq!(*id, id.to_lowercase(), "{id} is not lower-case");
            assert!(
                id.chars()
                    .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '.'),
                "{id} has characters Chocolatey ids do not use"
            );
        }
    }

    /// Every default prohibition needs a package id, because that id is what
    /// the update step keys its exclusion on. Without one, a program can be
    /// removed and then reinstalled by `choco upgrade` in the same run.
    #[test]
    fn every_default_prohibition_resolves_to_a_package_id() {
        for name in ALWAYS_PROHIBITED {
            assert!(
                PACKAGE_IDS
                    .iter()
                    .any(|(key, _)| key.eq_ignore_ascii_case(name)),
                "{name} is prohibited by default but has no package id to exclude from updates"
            );
        }
    }

    #[test]
    fn feature_names_are_not_duplicated() {
        let mut seen = Vec::new();
        for feature in FEATURES_TO_DISABLE {
            let lower = feature.to_lowercase();
            assert!(!seen.contains(&lower), "{feature} is listed twice");
            seen.push(lower);
        }
    }
}
