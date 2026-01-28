// =============================================================================
// CyberPatriot Automation Tool
// Author: Maxwell McCormick
// Copyright (c) 2026 Maxwell McCormick. All Rights Reserved.
// =============================================================================

namespace CyberPatriotAutomation.Core;

/// <summary>
/// Application configuration and default paths
/// </summary>
public static class AppConfig
{
    /// <summary>
    /// Default CyberPatriot competition README path on Windows images
    /// The README is typically located on the desktop of the primary user
    /// </summary>
    public static readonly string[] DefaultReadmePaths = new[]
    {
        // Common CyberPatriot README locations
        @"C:\Users\Public\Desktop\README.html",
        @"C:\CyberPatriot\README.html",
        @"C:\Users\Public\Documents\README.html",
        Environment.GetFolderPath(Environment.SpecialFolder.CommonDesktopDirectory)
            + @"\README.html",
        Environment.GetFolderPath(Environment.SpecialFolder.Desktop) + @"\README.html",
        // Fallback: look for any README on desktop
        @"C:\Users\*\Desktop\README.html",
    };

    /// <summary>
    /// CCS Client service name - must never be disabled
    /// </summary>
    public const string CCSClientServiceName = "CCSClient";

    /// <summary>
    /// CyberPatriot scoring report desktop shortcut name
    /// </summary>
    public const string ScoringReportShortcut = "CyberPatriot Scoring Report";

    /// <summary>
    /// Application version
    /// </summary>
    public const string Version = "1.0.0";

    /// <summary>
    /// Try to find the README file automatically
    /// </summary>
    public static string? FindReadmeFile()
    {
        foreach (var path in DefaultReadmePaths)
        {
            if (path.Contains("*"))
            {
                // Handle wildcard paths
                try
                {
                    var directory = Path.GetDirectoryName(path.Replace("*", ""))!;
                    var fileName = Path.GetFileName(path);

                    if (Directory.Exists(directory))
                    {
                        var files = Directory.GetFiles(
                            directory,
                            fileName,
                            SearchOption.AllDirectories
                        );
                        if (files.Length > 0)
                        {
                            return files[0];
                        }
                    }
                }
                catch 
                {
                    // Ignore errors for wildcard paths
                }
            }
            else if (File.Exists(path))
            {
                return path;
            }
        }

        return null;
    }

    /// <summary>
    /// Secure passwords for user account management
    /// These meet complexity requirements: 14+ chars, upper, lower, digit, special
    /// </summary>
    public static readonly string[] SecurePasswords = new[]
    {
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
    };
}
