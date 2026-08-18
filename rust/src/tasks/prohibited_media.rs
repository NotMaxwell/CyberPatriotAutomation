//! Scan for and remove prohibited media files from user directories.

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
    last_write_time: Option<SystemTime>,
    directory_name: Option<String>,
}

pub struct ProhibitedMediaTask {
    name: String,
    description: String,
    dry_run: bool,
    readme_data: Option<ReadmeData>,
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

        // Never delete this tool or anything alongside it. The game-pattern list
        // contains "riot", which is a substring of "cyberPATRIOTautomation.exe",
        // so the scanner classified its own binary as a game and queued it for
        // deletion whenever it was run from a folder under C:\Users - which is
        // where a competitor runs it from.
        if self.is_own_executable(file) {
            return false;
        }

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

    /// Is this the running tool, or a file sitting beside it?
    ///
    /// Windows locks a running executable, so deleting it would fail anyway and
    /// be reported as an error; the sibling check additionally protects the
    /// run log and any files shipped with the tool.
    fn is_own_executable(&self, file: &FoundFile) -> bool {
        let Ok(exe) = std::env::current_exe() else {
            return false;
        };

        if file.full_name == exe {
            return true;
        }

        match (exe.parent(), file.full_name.parent()) {
            (Some(exe_dir), Some(file_dir)) => exe_dir == file_dir,
            _ => false,
        }
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
        ui::markup_line(&format!("[green]Files Deleted:[/] {}", fixes.len()));
        ui::markup_line(&format!("[red]Errors:[/] {}", issues.len()));
        ui::write_line();
        ui::markup_line(
            "[dim]Files were deleted permanently. Every deletion is listed in the run log.[/]",
        );
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
            ui::markup_line("[cyan]Files would be deleted permanently, not backed up[/]");
            result.message = format!("DRY RUN: Would remove {} prohibited files.", self.found_files.len());
            return result;
        }

        ui::write_line();
        ui::rule("[bold yellow]Removing Prohibited Files[/]");
        ui::write_line();

        let total_count = self.found_files.len();
        let found = std::mem::take(&mut self.found_files);

        // Files are deleted outright rather than copied to a review folder. A
        // backup left the prohibited content on the machine - just relocated -
        // which does not clear the finding it was flagged for, and doubled the
        // disk written during the scan. Every deletion is recorded in the run
        // log, which is the record for review.
        for (index, file) in found.iter().enumerate() {
            let category = Self::categorize_file(file);

            match std::fs::remove_file(&file.full_name) {
                Ok(_) => {
                    ui::markup_line(&format!(
                        "[green]Deleted [{}] {}[/]",
                        category,
                        ui::escape(&file.full_name.to_string_lossy())
                    ));
                    fixes.push(format!(
                        "Deleted {category}: {} ({} bytes, modified {})",
                        file.full_name.to_string_lossy(),
                        file.length,
                        format_time(file.last_write_time)
                    ));
                }
                Err(e) => {
                    issues.push(format!(
                        "Failed to delete {}: {}",
                        file.full_name.to_string_lossy(),
                        e
                    ));
                    ui::markup_line(&format!(
                        "[red]Failed to delete {}: {}[/]",
                        ui::escape(&file.full_name.to_string_lossy()),
                        ui::escape(&e.to_string())
                    ));
                }
            }

            let processed = index + 1;
            if processed % 100 == 0 || processed == total_count {
                ui::markup_line(&format!("[cyan]Processed {processed}/{total_count} files...[/]"));
            }
        }

        ui::write_line();
        self.display_summary(&fixes, &issues);

        result.items_attempted = total_count as i32;
        result.items_succeeded = fixes.len() as i32;
        result.success = issues.is_empty();
        result.message = format!("Deleted {} prohibited file(s).", fixes.len());
        if !issues.is_empty() {
            result.message = format!(
                "Deleted {} of {} prohibited file(s); {} could not be deleted.",
                fixes.len(),
                total_count,
                issues.len()
            );
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
