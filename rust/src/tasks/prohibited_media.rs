//! Scan for and remove prohibited media files from user directories.

use crate::app_config;
use crate::impl_task_meta;
use crate::models::{ReadmeData, SystemInfo, TaskResult};
use crate::tasks::Task;
use crate::ui;
use async_trait::async_trait;
use chrono::{DateTime, Local};
use std::path::{Path, PathBuf};
use std::time::SystemTime;

const MEDIA_EXTENSIONS: &[&str] = &[
    ".mp3", ".wav", ".wma", ".aac", ".flac", ".ogg", ".m4a", ".m4p", ".aiff", ".ac3", ".midi",
    ".mid", ".vqf", ".mp4", ".avi", ".mkv", ".mov", ".wmv", ".flv", ".mpeg", ".mpg", ".mpeg4",
    ".m4v", ".webm", ".3gp", ".gif", ".m3u", ".m3u8", ".pls", ".wpl", ".torrent",
];

const HACKING_TOOL_PATTERNS: &[&str] = &[
    "cain", "abel", "wireshark", "nmap", "metasploit", "burp", "sqlmap", "hydra", "john", "hashcat",
    "aircrack", "ettercap", "nikto", "netcat", "nc.exe", "nc64.exe", "mimikatz", "pwdump", "fgdump",
    "wce", "gsecdump", "lsadump", "procdump", "keylogger", "keylog", "trojan", "backdoor", "rootkit",
    "exploit", "payload", "hack", "crack", "keygen", "patch", "loader", "injector", "cheat",
    "aimbot", "wallhack", "speedhack", "godmode", "trainer",
];

const GAME_PATTERNS: &[&str] = &[
    "steam", "origin", "epic games", "uplay", "gog", "battlenet", "riot", "minecraft", "fortnite",
    "valorant", "league of legends", "csgo", "dota", "overwatch", "pubg", "apex legends",
    "call of duty", "gta", "fifa", "game", "games",
];

const SKIP_DIRECTORIES: &[&str] = &[
    "Windows",
    "Program Files",
    "Program Files (x86)",
    "ProgramData",
    "$Recycle.Bin",
    "System Volume Information",
    "Recovery",
    r"AppData\Local\Microsoft",
    r"AppData\Local\Packages",
];

struct FoundFile {
    full_name: PathBuf,
    name: String,
    extension: String,
    length: u64,
    creation_time: Option<SystemTime>,
    last_write_time: Option<SystemTime>,
    directory_name: Option<String>,
}

pub struct ProhibitedMediaTask {
    name: String,
    description: String,
    dry_run: bool,
    readme_data: Option<ReadmeData>,
    backup_folder: PathBuf,
    found_files: Vec<FoundFile>,
}

impl ProhibitedMediaTask {
    pub fn new() -> Self {
        Self {
            name: "Prohibited Media Scanner".to_string(),
            description:
                "Scan for and remove prohibited media, games, and hacking tools from user directories"
                    .to_string(),
            dry_run: false,
            readme_data: None,
            backup_folder: PathBuf::new(),
            found_files: Vec::new(),
        }
    }

    pub fn set_readme_data(&mut self, data: ReadmeData) {
        self.readme_data = Some(data);
    }

    fn scan_directory(&mut self, path: &Path) {
        let path_str = path.to_string_lossy();
        for skip in SKIP_DIRECTORIES {
            if path_str.to_lowercase().contains(&skip.to_lowercase()) {
                return;
            }
        }

        let entries = match std::fs::read_dir(path) {
            Ok(e) => e,
            Err(_) => return,
        };

        for entry in entries.flatten() {
            let entry_path = entry.path();
            let metadata = match entry.metadata() {
                Ok(m) => m,
                Err(_) => continue,
            };

            if metadata.is_file() {
                if let Some(file) = to_found_file(&entry_path, &metadata) {
                    if self.is_prohibited_file(&file) {
                        self.found_files.push(file);
                    }
                }
            } else if metadata.is_dir() {
                if is_hidden_or_system(&entry_path, &metadata) {
                    continue;
                }
                self.scan_directory(&entry_path);
            }
        }
    }

    fn is_prohibited_file(&self, file: &FoundFile) -> bool {
        let file_name = file.name.to_lowercase();
        let extension = file.extension.to_lowercase();

        if MEDIA_EXTENSIONS.contains(&extension.as_str()) {
            if file.length < 10000 && extension == ".wav" {
                return false;
            }
            return true;
        }

        for pattern in HACKING_TOOL_PATTERNS {
            if file_name.contains(pattern) {
                return true;
            }
        }

        if file
            .directory_name
            .as_deref()
            .map(|d| d.to_lowercase().contains("users"))
            .unwrap_or(false)
        {
            for pattern in GAME_PATTERNS {
                if file_name.contains(pattern) && (extension == ".exe" || extension == ".msi") {
                    return true;
                }
            }
        }

        if let Some(readme) = &self.readme_data {
            for prohibited in &readme.prohibited_software {
                if file_name.contains(&prohibited.to_lowercase()) {
                    return true;
                }
            }
        }

        false
    }

    fn categorize_file(file: &FoundFile) -> &'static str {
        let extension = file.extension.to_lowercase();
        let file_name = file.name.to_lowercase();

        if MEDIA_EXTENSIONS.contains(&extension.as_str()) {
            return "Media";
        }
        for pattern in HACKING_TOOL_PATTERNS {
            if file_name.contains(pattern) {
                return "HackingTool";
            }
        }
        for pattern in GAME_PATTERNS {
            if file_name.contains(pattern) {
                return "Game";
            }
        }
        "Other"
    }

    fn display_found_files(&self) {
        if self.found_files.is_empty() {
            ui::markup_line("[green]? No prohibited files found[/]");
            return;
        }

        let by_cat = |cat: &str| -> Vec<&FoundFile> {
            self.found_files.iter().filter(|f| Self::categorize_file(f) == cat).collect()
        };
        let media = by_cat("Media");
        let hacking = by_cat("HackingTool");
        let games = by_cat("Game");
        let other = by_cat("Other");

        let sum = |v: &[&FoundFile]| -> u64 { v.iter().map(|f| f.length).sum() };

        let mut summary = ui::TableBuilder::new()
            .title("[bold red]Prohibited Files Found[/]")
            .columns(&["[bold]Category[/]", "[bold]Count[/]", "[bold]Total Size[/]"]);
        if !media.is_empty() {
            summary.add_row(["[yellow]Media Files[/]".to_string(), media.len().to_string(), format_size(sum(&media))]);
        }
        if !hacking.is_empty() {
            summary.add_row(["[red]Hacking Tools[/]".to_string(), hacking.len().to_string(), format_size(sum(&hacking))]);
        }
        if !games.is_empty() {
            summary.add_row(["[blue]Games[/]".to_string(), games.len().to_string(), format_size(sum(&games))]);
        }
        if !other.is_empty() {
            summary.add_row(["[dim]Other[/]".to_string(), other.len().to_string(), format_size(sum(&other))]);
        }
        summary.add_row([
            "[bold]TOTAL[/]".to_string(),
            self.found_files.len().to_string(),
            format_size(self.found_files.iter().map(|f| f.length).sum()),
        ]);
        summary.print();
        ui::write_line();

        let mut sample = ui::TableBuilder::new()
            .title("[bold]Sample Files (up to 20)[/]")
            .columns(&["[bold]File[/]", "[bold]Path[/]", "[bold]Size[/]", "[bold]Category[/]"]);
        for file in self.found_files.iter().take(20) {
            let category = Self::categorize_file(file);
            let category_color = match category {
                "Media" => "yellow",
                "HackingTool" => "red",
                "Game" => "blue",
                _ => "dim",
            };
            let dir = file.directory_name.clone().unwrap_or_default();
            let short_path = if dir.chars().count() > 50 {
                format!("...{}", &dir[dir.len().saturating_sub(47)..])
            } else {
                dir
            };
            sample.add_row([
                ui::escape(&file.name),
                ui::escape(&short_path),
                format_size(file.length),
                format!("[{category_color}]{category}[/]"),
            ]);
        }
        sample.print();

        if self.found_files.len() > 20 {
            ui::markup_line(&format!("[dim]...and {} more files[/]", self.found_files.len() - 20));
        }
    }

    fn display_summary(&self, fixes: &[String], issues: &[String]) {
        ui::markup_line("[bold]Removal Summary[/]");
        ui::markup_line(&format!("[green]Files Removed:[/] {}", fixes.len()));
        ui::markup_line(&format!("[red]Errors:[/] {}", issues.len()));
        ui::markup_line(&format!("[cyan]Backup Location:[/] {}", ui::escape(&self.backup_folder.to_string_lossy())));
        ui::write_line();
        ui::markup_line("[dim]A detailed log has been saved to the backup folder.[/]");
    }
}

impl Default for ProhibitedMediaTask {
    fn default() -> Self {
        Self::new()
    }
}

fn to_found_file(path: &Path, metadata: &std::fs::Metadata) -> Option<FoundFile> {
    let name = path.file_name()?.to_string_lossy().into_owned();
    let extension = path
        .extension()
        .map(|e| format!(".{}", e.to_string_lossy()))
        .unwrap_or_default();
    Some(FoundFile {
        full_name: path.to_path_buf(),
        name,
        extension,
        length: metadata.len(),
        creation_time: metadata.created().ok(),
        last_write_time: metadata.modified().ok(),
        directory_name: path.parent().map(|p| p.to_string_lossy().into_owned()),
    })
}

#[cfg(windows)]
fn is_hidden_or_system(_path: &Path, metadata: &std::fs::Metadata) -> bool {
    use std::os::windows::fs::MetadataExt;
    const FILE_ATTRIBUTE_HIDDEN: u32 = 0x2;
    const FILE_ATTRIBUTE_SYSTEM: u32 = 0x4;
    let attrs = metadata.file_attributes();
    (attrs & FILE_ATTRIBUTE_HIDDEN) != 0 || (attrs & FILE_ATTRIBUTE_SYSTEM) != 0
}

#[cfg(not(windows))]
fn is_hidden_or_system(path: &Path, _metadata: &std::fs::Metadata) -> bool {
    path.file_name()
        .map(|n| n.to_string_lossy().starts_with('.'))
        .unwrap_or(false)
}

fn format_size(bytes: u64) -> String {
    let sizes = ["B", "KB", "MB", "GB", "TB"];
    let mut order = 0;
    let mut size = bytes as f64;
    while size >= 1024.0 && order < sizes.len() - 1 {
        order += 1;
        size /= 1024.0;
    }
    // Mirror C#'s "{0:0.##}" formatting.
    let formatted = format!("{size:.2}");
    let trimmed = formatted.trim_end_matches('0').trim_end_matches('.');
    format!("{trimmed} {}", sizes[order])
}

fn format_time(t: Option<SystemTime>) -> String {
    match t {
        Some(st) => {
            let dt: DateTime<Local> = st.into();
            dt.format("%m/%d/%Y %H:%M:%S").to_string()
        }
        None => "Unknown".to_string(),
    }
}

#[async_trait]
impl Task for ProhibitedMediaTask {
    impl_task_meta!();

    async fn read_system_state(&mut self) -> SystemInfo {
        let system_info = SystemInfo::new();

        ui::markup_line("[cyan]Scanning for prohibited files...[/]");
        ui::markup_line("[dim]This may take a few minutes...[/]");
        ui::write_line();

        self.backup_folder = app_config::desktop_dir().join(format!(
            "CyberPatriot_RemovedFiles_{}",
            Local::now().format("%Y%m%d_%H%M%S")
        ));

        let users_path = Path::new(r"C:\Users");
        if users_path.exists() {
            self.scan_directory(users_path);
        }

        self.display_found_files();
        system_info
    }

    async fn execute(&mut self) -> TaskResult {
        let mut result = TaskResult {
            task_name: self.name.clone(),
            success: true,
            message: "Prohibited media scan completed".to_string(),
            ..Default::default()
        };

        let mut fixes: Vec<String> = Vec::new();
        let mut issues: Vec<String> = Vec::new();

        if self.found_files.is_empty() {
            ui::markup_line("[green]✓ No prohibited files found[/]");
            result.message = "No prohibited files found".to_string();
            return result;
        }

        if self.dry_run {
            ui::markup_line("[yellow]DRY RUN: Previewing prohibited media removal (no changes will be made)[/]");
            ui::markup_line(&format!("[cyan]Would remove {} prohibited files[/]", self.found_files.len()));
            ui::markup_line(&format!("[cyan]Would back up files to: {}[/]", ui::escape(&self.backup_folder.to_string_lossy())));
            result.message = format!("DRY RUN: Would remove {} prohibited files.", self.found_files.len());
            return result;
        }

        if let Err(e) = std::fs::create_dir_all(&self.backup_folder) {
            result.success = false;
            result.message = "Failed to complete prohibited media scan".to_string();
            result.error_details = Some(e.to_string());
            ui::write_exception(&e.to_string());
            return result;
        }

        let media_dir = self.backup_folder.join("Media");
        let hacking_dir = self.backup_folder.join("HackingTools");
        let games_dir = self.backup_folder.join("Games");
        let other_dir = self.backup_folder.join("Other");
        for d in [&media_dir, &hacking_dir, &games_dir, &other_dir] {
            let _ = std::fs::create_dir_all(d);
        }

        let log_path = self.backup_folder.join("removal_log.txt");
        let mut log_entries: Vec<String> = vec![
            "CyberPatriot Prohibited Files Removal Log".to_string(),
            format!("Date: {}", Local::now().format("%m/%d/%Y %H:%M:%S")),
            format!("Total files found: {}", self.found_files.len()),
            String::new(),
            "Files removed:".to_string(),
            format!("={}", "=".repeat(79)),
        ];

        ui::write_line();
        ui::rule("[bold yellow]Removing Prohibited Files[/]");
        ui::write_line();

        let total_count = self.found_files.len();
        let found = std::mem::take(&mut self.found_files);

        for (index, file) in found.iter().enumerate() {
            let category = Self::categorize_file(file);
            let backup_dir = match category {
                "Media" => &media_dir,
                "HackingTool" => &hacking_dir,
                "Game" => &games_dir,
                _ => &other_dir,
            };

            let stem = file
                .full_name
                .file_stem()
                .map(|s| s.to_string_lossy().into_owned())
                .unwrap_or_default();
            let backup_file_name = format!("{}_{}{}", stem, uuid::Uuid::new_v4().simple(), file.extension);
            let backup_path = backup_dir.join(&backup_file_name);

            let copy_result = std::fs::copy(&file.full_name, &backup_path);
            match copy_result.and_then(|_| std::fs::remove_file(&file.full_name)) {
                Ok(_) => {
                    log_entries.push(format!("[{category}] {}", file.full_name.to_string_lossy()));
                    log_entries.push(format!("  ✓ Backed up to: {}", backup_path.to_string_lossy()));
                    log_entries.push(format!("  ✓ Size: {} bytes", file.length));
                    log_entries.push(format!("  ✓ Created: {}", format_time(file.creation_time)));
                    log_entries.push(format!("  ✓ Modified: {}", format_time(file.last_write_time)));
                    log_entries.push(String::new());
                    fixes.push(format!("Removed {category}: {}", file.name));
                }
                Err(e) => {
                    issues.push(format!("Failed to remove {}: {}", file.full_name.to_string_lossy(), e));
                    log_entries.push(format!("[ERROR] Failed to remove: {}", file.full_name.to_string_lossy()));
                    log_entries.push(format!("  ✗ Error: {e}"));
                    log_entries.push(String::new());
                }
            }

            let processed = index + 1;
            if processed % 100 == 0 || processed == total_count {
                ui::markup_line(&format!("[cyan]Processed {processed}/{total_count} files...[/]"));
            }
        }

        log_entries.push(String::new());
        log_entries.push(format!("={}", "=".repeat(79)));
        log_entries.push(format!("Summary: {} files removed, {} errors", fixes.len(), issues.len()));
        let _ = std::fs::write(&log_path, log_entries.join("\n"));

        ui::write_line();
        self.display_summary(&fixes, &issues);

        result.message = format!(
            "Removed {} prohibited files. Backups saved to: {}",
            fixes.len(),
            self.backup_folder.to_string_lossy()
        );
        if !issues.is_empty() {
            result.error_details = Some(issues.iter().take(10).cloned().collect::<Vec<_>>().join("\n"));
        }

        result
    }

    async fn verify(&mut self) -> bool {
        self.found_files.clear();
        let users_path = Path::new(r"C:\Users");
        if users_path.exists() {
            self.scan_directory(users_path);
        }
        if self.found_files.is_empty() {
            ui::markup_line("[green]? No prohibited files found after cleanup[/]");
            true
        } else {
            ui::markup_line(&format!("[yellow]? {} prohibited files still remain[/]", self.found_files.len()));
            false
        }
    }
}
