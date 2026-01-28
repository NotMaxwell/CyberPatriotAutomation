using CyberPatriotAutomation.Core.Models;
using CyberPatriotAutomation.Core.Utilities;
using Spectre.Console;

namespace CyberPatriotAutomation.Core.Tasks;

/// <summary>
/// Task to scan for and remove prohibited media files from user directories
/// Backs up files to a desktop folder before deletion for review
/// </summary>
public class ProhibitedMediaTask : BaseTask
{
    private ReadmeData? _readmeData;
    private string _backupFolder = string.Empty;
    private readonly List<FileInfo> _foundFiles = new();

    /// <summary>
    /// Media file extensions that are typically prohibited in CyberPatriot
    /// </summary>
    private static readonly string[] MediaExtensions = new[]
    {
        // Audio files
        ".mp3",
        ".wav",
        ".wma",
        ".aac",
        ".flac",
        ".ogg",
        ".m4a",
        ".m4p",
        ".aiff",
        ".ac3",
        ".midi",
        ".mid",
        ".vqf",
        // Video files
        ".mp4",
        ".avi",
        ".mkv",
        ".mov",
        ".wmv",
        ".flv",
        ".mpeg",
        ".mpg",
        ".mpeg4",
        ".m4v",
        ".webm",
        ".3gp",
        // Image files (that might be non-work related)
        ".gif", // animated gifs often non-work
        // Playlist files
        ".m3u",
        ".m3u8",
        ".pls",
        ".wpl",
        // Torrent files
        ".torrent",
    };

    /// <summary>
    /// Hacking tools and suspicious file patterns
    /// </summary>
    private static readonly string[] HackingToolPatterns = new[]
    {
        "cain",
        "abel",
        "wireshark",
        "nmap",
        "metasploit",
        "burp",
        "sqlmap",
        "hydra",
        "john",
        "hashcat",
        "aircrack",
        "ettercap",
        "nikto",
        "netcat",
        "nc.exe",
        "nc64.exe",
        "mimikatz",
        "pwdump",
        "fgdump",
        "wce",
        "gsecdump",
        "lsadump",
        "procdump",
        "keylogger",
        "keylog",
        "trojan",
        "backdoor",
        "rootkit",
        "exploit",
        "payload",
        "hack",
        "crack",
        "keygen",
        "patch",
        "loader",
        "injector",
        "cheat",
        "aimbot",
        "wallhack",
        "speedhack",
        "godmode",
        "trainer",
    };

    /// <summary>
    /// Game-related patterns
    /// </summary>
    private static readonly string[] GamePatterns = new[]
    {
        "steam",
        "origin",
        "epic games",
        "uplay",
        "gog",
        "battlenet",
        "riot",
        "minecraft",
        "fortnite",
        "valorant",
        "league of legends",
        "csgo",
        "dota",
        "overwatch",
        "pubg",
        "apex legends",
        "call of duty",
        "gta",
        "fifa",
        "game",
        "games",
    };

    /// <summary>
    /// Directories to skip during scanning
    /// </summary>
    private static readonly string[] SkipDirectories = new[]
    {
        "Windows",
        "Program Files",
        "Program Files (x86)",
        "ProgramData",
        "$Recycle.Bin",
        "System Volume Information",
        "Recovery",
        "AppData\\Local\\Microsoft",
        "AppData\\Local\\Packages",
    };

    public ProhibitedMediaTask()
    {
        Name = "Prohibited Media Scanner";
        Description =
            "Scan for and remove prohibited media, games, and hacking tools from user directories";
    }

    /// <summary>
    /// Set the README data for this task
    /// </summary>
    public void SetReadmeData(ReadmeData data)
    {
        _readmeData = data;
    }

    public override async Task<SystemInfo> ReadSystemStateAsync()
    {
        var systemInfo = new SystemInfo();

        AnsiConsole.MarkupLine("[cyan]Scanning for prohibited files...[/]");
        AnsiConsole.MarkupLine("[dim]This may take a few minutes...[/]");
        AnsiConsole.WriteLine();

        // Create backup folder on desktop
        _backupFolder = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.Desktop),
            $"CyberPatriot_RemovedFiles_{DateTime.Now:yyyyMMdd_HHmmss}"
        );

        // Scan user directories
        var usersPath = @"C:\Users";
        if (Directory.Exists(usersPath))
        {
            await ScanDirectoryAsync(usersPath);
        }

        // Display found files
        DisplayFoundFiles();

        return systemInfo;
    }

    public override async Task<TaskResult> ExecuteAsync()
    {
        var result = new TaskResult
        {
            TaskName = Name,
            Success = true,
            Message = "Prohibited media scan completed",
        };

        var fixes = new List<string>();
        var issues = new List<string>();

        try
        {
            if (_foundFiles.Count == 0)
            {
                AnsiConsole.MarkupLine("[green]? No prohibited files found[/]");
                result.Message = "No prohibited files found";
                return result;
            }

            // Create backup directory
            Directory.CreateDirectory(_backupFolder);

            // Create subdirectories for organization
            var mediaDir = Path.Combine(_backupFolder, "Media");
            var hackingDir = Path.Combine(_backupFolder, "HackingTools");
            var gamesDir = Path.Combine(_backupFolder, "Games");
            var otherDir = Path.Combine(_backupFolder, "Other");

            Directory.CreateDirectory(mediaDir);
            Directory.CreateDirectory(hackingDir);
            Directory.CreateDirectory(gamesDir);
            Directory.CreateDirectory(otherDir);

            // Create a log file
            var logPath = Path.Combine(_backupFolder, "removal_log.txt");
            var logEntries = new List<string>
            {
                "CyberPatriot Prohibited Files Removal Log",
                $"Date: {DateTime.Now}",
                $"Total files found: {_foundFiles.Count}",
                "",
                "Files removed:",
                "=" + new string('=', 79),
            };

            AnsiConsole.WriteLine();
            AnsiConsole.Write(
                new Rule("[bold yellow]Removing Prohibited Files[/]").RuleStyle("yellow")
            );
            AnsiConsole.WriteLine();

            await AnsiConsole
                .Progress()
                .AutoClear(false)
                .HideCompleted(false)
                .Columns(
                    new ProgressColumn[]
                    {
                        new TaskDescriptionColumn(),
                        new ProgressBarColumn(),
                        new PercentageColumn(),
                        new SpinnerColumn(),
                    }
                )
                .StartAsync(async ctx =>
                {
                    var task = ctx.AddTask(
                        "[cyan]Processing files...[/]",
                        maxValue: _foundFiles.Count
                    );

                    foreach (var file in _foundFiles)
                    {
                        try
                        {
                            // Determine category and backup location
                            var category = CategorizeFile(file);
                            var backupDir = category switch
                            {
                                "Media" => mediaDir,
                                "HackingTool" => hackingDir,
                                "Game" => gamesDir,
                                _ => otherDir,
                            };

                            // Generate unique backup filename
                            var backupFileName =
                                $"{Path.GetFileNameWithoutExtension(file.Name)}_{Guid.NewGuid():N}{file.Extension}";
                            var backupPath = Path.Combine(backupDir, backupFileName);

                            // Copy file to backup
                            File.Copy(file.FullName, backupPath, true);

                            // Log the removal
                            logEntries.Add($"[{category}] {file.FullName}");
                            logEntries.Add($"  ? Backed up to: {backupPath}");
                            logEntries.Add($"  ? Size: {file.Length:N0} bytes");
                            logEntries.Add($"  ? Created: {file.CreationTime}");
                            logEntries.Add($"  ? Modified: {file.LastWriteTime}");
                            logEntries.Add("");

                            // Delete the original file
                            File.Delete(file.FullName);

                            fixes.Add($"Removed {category}: {file.Name}");
                        }
                        catch (Exception ex)
                        {
                            issues.Add($"Failed to remove {file.FullName}: {ex.Message}");
                            logEntries.Add($"[ERROR] Failed to remove: {file.FullName}");
                            logEntries.Add($"  ? Error: {ex.Message}");
                            logEntries.Add("");
                        }

                        task.Increment(1);
                        await Task.Delay(10); // Small delay for UI responsiveness
                    }
                });

            // Write log file
            logEntries.Add("");
            logEntries.Add("=" + new string('=', 79));
            logEntries.Add($"Summary: {fixes.Count} files removed, {issues.Count} errors");
            await File.WriteAllLinesAsync(logPath, logEntries);

            // Display summary
            AnsiConsole.WriteLine();
            DisplaySummary(fixes, issues);

            result.Message =
                $"Removed {fixes.Count} prohibited files. Backups saved to: {_backupFolder}";
            if (issues.Count > 0)
            {
                result.ErrorDetails = string.Join("\n", issues.Take(10));
            }
        }
        catch (Exception ex)
        {
            result.Success = false;
            result.Message = "Failed to complete prohibited media scan";
            result.ErrorDetails = ex.Message;
            AnsiConsole.WriteException(ex);
        }

        return result;
    }

    public override async Task<bool> VerifyAsync()
    {
        // Re-scan to verify files were removed
        _foundFiles.Clear();

        var usersPath = @"C:\Users";
        if (Directory.Exists(usersPath))
        {
            await ScanDirectoryAsync(usersPath, silent: true);
        }

        if (_foundFiles.Count == 0)
        {
            AnsiConsole.MarkupLine("[green]? No prohibited files found after cleanup[/]");
            return true;
        }
        else
        {
            AnsiConsole.MarkupLine(
                $"[yellow]? {_foundFiles.Count} prohibited files still remain[/]"
            );
            return false;
        }
    }

    #region Helper Methods

    private async Task ScanDirectoryAsync(string path, bool silent = false)
    {
        try
        {
            // Skip system directories
            foreach (var skipDir in SkipDirectories)
            {
                if (path.Contains(skipDir, StringComparison.OrdinalIgnoreCase))
                    return;
            }

            var dir = new DirectoryInfo(path);

            // Scan files in current directory
            foreach (var file in dir.GetFiles())
            {
                if (IsProhibitedFile(file))
                {
                    _foundFiles.Add(file);
                }
            }

            // Recursively scan subdirectories
            foreach (var subDir in dir.GetDirectories())
            {
                // Skip hidden and system directories
                if (
                    (subDir.Attributes & FileAttributes.Hidden) != 0
                    || (subDir.Attributes & FileAttributes.System) != 0
                )
                    continue;

                await ScanDirectoryAsync(subDir.FullName, silent);
            }
        }
        catch (UnauthorizedAccessException)
        {
            // Skip directories we don't have access to
        }
        catch (Exception)
        {
            // Skip any other errors
        }
    }

    private bool IsProhibitedFile(FileInfo file)
    {
        var fileName = file.Name.ToLowerInvariant();
        var extension = file.Extension.ToLowerInvariant();

        // Check for media files
        if (MediaExtensions.Contains(extension))
        {
            // Skip small files (likely system sounds)
            if (file.Length < 10000 && extension == ".wav")
                return false;
            return true;
        }

        // Check for hacking tools
        foreach (var pattern in HackingToolPatterns)
        {
            if (fileName.Contains(pattern, StringComparison.OrdinalIgnoreCase))
                return true;
        }

        // Check for games (only in certain locations)
        if (file.DirectoryName?.Contains("Users", StringComparison.OrdinalIgnoreCase) == true)
        {
            foreach (var pattern in GamePatterns)
            {
                if (
                    fileName.Contains(pattern, StringComparison.OrdinalIgnoreCase)
                    && (extension == ".exe" || extension == ".msi")
                )
                    return true;
            }
        }

        // Check README prohibited software
        if (_readmeData != null)
        {
            foreach (var prohibited in _readmeData.ProhibitedSoftware)
            {
                if (fileName.Contains(prohibited, StringComparison.OrdinalIgnoreCase))
                    return true;
            }
        }

        return false;
    }

    private string CategorizeFile(FileInfo file)
    {
        var extension = file.Extension.ToLowerInvariant();
        var fileName = file.Name.ToLowerInvariant();

        if (MediaExtensions.Contains(extension))
            return "Media";

        foreach (var pattern in HackingToolPatterns)
        {
            if (fileName.Contains(pattern, StringComparison.OrdinalIgnoreCase))
                return "HackingTool";
        }

        foreach (var pattern in GamePatterns)
        {
            if (fileName.Contains(pattern, StringComparison.OrdinalIgnoreCase))
                return "Game";
        }

        return "Other";
    }

    private void DisplayFoundFiles()
    {
        if (_foundFiles.Count == 0)
        {
            AnsiConsole.MarkupLine("[green]? No prohibited files found[/]");
            return;
        }

        // Group by category
        var mediaFiles = _foundFiles.Where(f => CategorizeFile(f) == "Media").ToList();
        var hackingFiles = _foundFiles.Where(f => CategorizeFile(f) == "HackingTool").ToList();
        var gameFiles = _foundFiles.Where(f => CategorizeFile(f) == "Game").ToList();
        var otherFiles = _foundFiles.Where(f => CategorizeFile(f) == "Other").ToList();

        var summaryTable = new Table()
            .Border(TableBorder.Rounded)
            .BorderColor(Color.Red)
            .Title("[bold red]Prohibited Files Found[/]")
            .AddColumn("[bold]Category[/]")
            .AddColumn("[bold]Count[/]")
            .AddColumn("[bold]Total Size[/]");

        if (mediaFiles.Count > 0)
            summaryTable.AddRow(
                "[yellow]Media Files[/]",
                mediaFiles.Count.ToString(),
                FormatSize(mediaFiles.Sum(f => f.Length))
            );
        if (hackingFiles.Count > 0)
            summaryTable.AddRow(
                "[red]Hacking Tools[/]",
                hackingFiles.Count.ToString(),
                FormatSize(hackingFiles.Sum(f => f.Length))
            );
        if (gameFiles.Count > 0)
            summaryTable.AddRow(
                "[blue]Games[/]",
                gameFiles.Count.ToString(),
                FormatSize(gameFiles.Sum(f => f.Length))
            );
        if (otherFiles.Count > 0)
            summaryTable.AddRow(
                "[dim]Other[/]",
                otherFiles.Count.ToString(),
                FormatSize(otherFiles.Sum(f => f.Length))
            );

        summaryTable.AddRow(
            "[bold]TOTAL[/]",
            _foundFiles.Count.ToString(),
            FormatSize(_foundFiles.Sum(f => f.Length))
        );

        AnsiConsole.Write(summaryTable);
        AnsiConsole.WriteLine();

        // Show sample files (first 20)
        if (_foundFiles.Count > 0)
        {
            var sampleTable = new Table()
                .Border(TableBorder.Rounded)
                .BorderColor(Color.Grey)
                .Title("[bold]Sample Files (up to 20)[/]")
                .AddColumn("[bold]File[/]")
                .AddColumn("[bold]Path[/]")
                .AddColumn("[bold]Size[/]")
                .AddColumn("[bold]Category[/]");

            foreach (var file in _foundFiles.Take(20))
            {
                var category = CategorizeFile(file);
                var categoryColor = category switch
                {
                    "Media" => "yellow",
                    "HackingTool" => "red",
                    "Game" => "blue",
                    _ => "dim",
                };

                var shortPath =
                    file.DirectoryName?.Length > 50
                        ? "..." + file.DirectoryName.Substring(file.DirectoryName.Length - 47)
                        : file.DirectoryName ?? "";

                sampleTable.AddRow(
                    file.Name,
                    shortPath,
                    FormatSize(file.Length),
                    $"[{categoryColor}]{category}[/]"
                );
            }

            AnsiConsole.Write(sampleTable);

            if (_foundFiles.Count > 20)
            {
                AnsiConsole.MarkupLine($"[dim]...and {_foundFiles.Count - 20} more files[/]");
            }
        }
    }

    private void DisplaySummary(List<string> fixes, List<string> issues)
    {
        var panel = new Panel(
            new Markup(
                $"""
                [green]Files Removed:[/] {fixes.Count}
                [red]Errors:[/] {issues.Count}
                [cyan]Backup Location:[/] {_backupFolder}

                [dim]A detailed log has been saved to the backup folder.[/]
                """
            )
        ).Header("[bold]Removal Summary[/]").Border(BoxBorder.Rounded).BorderColor(Color.Green);

        AnsiConsole.Write(panel);
    }

    private static string FormatSize(long bytes)
    {
        string[] sizes = { "B", "KB", "MB", "GB", "TB" };
        int order = 0;
        double size = bytes;
        while (size >= 1024 && order < sizes.Length - 1)
        {
            order++;
            size /= 1024;
        }
        return $"{size:0.##} {sizes[order]}";
    }

    #endregion
}
