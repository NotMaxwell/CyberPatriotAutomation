// =============================================================================
// PinnacleCyPat - Interactive terminal UI
// Author: Maxwell McCormick
// Copyright (c) 2026 Maxwell McCormick. All Rights Reserved.
// =============================================================================
using Spectre.Console;

namespace PinnacleCyPat.Core;

/// <summary>
/// The interactive front end: a guided menu that asks which README to use, which
/// tasks to run and whether to preview or apply, then hands the answers back as
/// a command line.
/// </summary>
/// <remarks>
/// <para>
/// It deliberately produces <em>arguments</em> rather than running anything
/// itself. The command line is the single execution path, and every ordering
/// guarantee the run depends on - the README is parsed before user management,
/// service protection happens before service disabling - lives there. A TUI that
/// drove the tasks directly would be a second copy of that logic, free to drift
/// from the first.
/// </para>
/// <para>
/// It is also the answer to the double-click problem. Launching the executable
/// with no arguments used to begin a full destructive run; it now prints help
/// and stops. That is safe but unhelpful to the competitor who just wants to get
/// going, so a bare launch on a real console opens this menu instead - which
/// changes nothing until an explicit confirmation.
/// </para>
/// </remarks>
public static class Tui
{
    /// <summary>One selectable task, and the flag that runs it.</summary>
    private readonly record struct TaskChoice(string Flag, string Label, string Detail)
    {
        /// <summary>What the multi-select prompt shows for this entry.</summary>
        public string Display => $"{Label}  [dim]{Detail}[/]";
    }

    /// <summary>
    /// Every task the menu offers, in the order the run executes them.
    /// </summary>
    /// <remarks>
    /// Kept in run order rather than alphabetical so the confirmation summary
    /// reads as the sequence that is about to happen.
    /// </remarks>
    private static readonly TaskChoice[] Tasks =
    [
        new("--password-policy", "Password Policy", "length, age, history, lockout"),
        new("--account-permissions", "Account Permissions", "Guest, password expiry, admins"),
        new("--user-management", "User Management", "needs a README"),
        new("--service-management", "Service Management", "disable insecure, protect critical"),
        new("--audit-policy", "Audit Policy", "event logging and security settings"),
        new("--firewall", "Firewall", "profiles, blocked ports, risky rules"),
        new("--security-hardening", "Security Hardening", "registry hardening, features"),
        new("--media-scan", "Prohibited Media", "deletes matching files permanently"),
        new("--software-management", "Software Management", "remove, install, Defender scan"),
        new("--shared-folders", "Shared Folders Audit", "removes non-default shares"),
        new("--hosts-file", "Hosts File Audit", "removes unauthorised entries"),
        new("--dns-settings", "DNS Settings Audit", "reports public resolvers"),
        new("--scheduled-tasks", "Scheduled Tasks Audit", "disables suspicious tasks"),
    ];

    /// <summary>
    /// Every task flag the menu can emit, for the test that checks the parser
    /// accepts all of them.
    /// </summary>
    /// <remarks>
    /// A flag named here but missing from <c>Program.Flags</c> would exit 2 with
    /// "Unrecognised argument" the moment that task was picked - a failure only
    /// reachable by walking through the menu, which no test can do.
    /// </remarks>
    public static IEnumerable<string> OfferedFlags => Tasks.Select(t => t.Flag);

    /// <summary>Tasks that do nothing useful without a parsed README.</summary>
    private static readonly string[] NeedReadme = ["--user-management", "--software-management"];

    /// <summary>
    /// Should a bare invocation open the menu rather than print help?
    /// </summary>
    /// <remarks>
    /// Only when there is a human at a terminal. Redirected output means a
    /// script or a pipe, where a prompt would block forever waiting for an
    /// answer that is never coming.
    /// </remarks>
    public static bool IsInteractiveConsole()
    {
        try
        {
            return !Console.IsInputRedirected && !Console.IsOutputRedirected;
        }
        catch
        {
            return false;
        }
    }

    /// <summary>
    /// Run the menu. Returns the command line to execute, or null if the user
    /// chose to quit.
    /// </summary>
    public static string[]? BuildArguments()
    {
        ShowBanner();

        var mode = AnsiConsole.Prompt(
            new SelectionPrompt<string>()
                .Title("[bold]What would you like to do?[/]")
                .HighlightStyle(new Style(Color.Cyan1))
                .AddChoices(
                    "Inspect the README only  [dim](read-only, changes nothing)[/]",
                    "Preview every task  [dim](dry run, changes nothing)[/]",
                    "Run every task  [dim](applies changes)[/]",
                    "Choose individual tasks",
                    "Quit"
                )
        );

        if (mode.StartsWith("Quit", StringComparison.Ordinal))
            return null;

        var args = new List<string>();

        // Every path needs a README except the one that explicitly declines it,
        // so it is asked for first and the answer reused below.
        var readmeArgs = AskForReadme(
            parseOnly: mode.StartsWith("Inspect", StringComparison.Ordinal)
        );
        args.AddRange(readmeArgs);

        if (mode.StartsWith("Inspect", StringComparison.Ordinal))
        {
            args.Add("--parse-readme");
            return args.ToArray();
        }

        List<string> chosen;
        bool dryRun;

        if (mode.StartsWith("Choose", StringComparison.Ordinal))
        {
            chosen = AskForTasks();
            if (chosen.Count == 0)
            {
                AnsiConsole.MarkupLine("[yellow]No tasks selected - nothing to do.[/]");
                return null;
            }
            dryRun = AskForDryRun();
        }
        else
        {
            // "--all" rather than the thirteen flags: it is what the help
            // documents, and it is what appears in the run log's Command line.
            chosen = ["--all"];
            dryRun = mode.StartsWith("Preview", StringComparison.Ordinal);
        }

        args.AddRange(chosen);
        if (dryRun)
            args.Add("--dry-run");

        WarnAboutMissingReadme(readmeArgs, chosen);

        return Confirm(args, dryRun) ? args.ToArray() : null;
    }

    private static void ShowBanner()
    {
        AnsiConsole.Clear();
        AnsiConsole.Write(
            new Panel(
                new Markup(
                    $"[bold cyan]PinnacleCyPat[/]\n"
                        + $"[dim]{AppConfig.VersionString}[/]\n\n"
                        + "[dim]Windows security hardening for CyberPatriot images[/]"
                )
            )
                .Border(BoxBorder.Rounded)
                .BorderColor(Color.Cyan1)
                .Padding(2, 1)
        );
        AnsiConsole.WriteLine();

        // Almost everything the tool does needs elevation, and the failure mode
        // without it is a long run in which every change is denied - which reads
        // as the tool not working rather than as a missing privilege.
        if (OperatingSystem.IsWindows() && !IsAdministrator())
        {
            AnsiConsole.MarkupLine(
                "[yellow]! Not running as Administrator. Most changes will be refused.[/]"
            );
            AnsiConsole.MarkupLine(
                "[dim]  Close this, right-click the executable and choose 'Run as administrator'.[/]"
            );
            AnsiConsole.WriteLine();
        }
    }

    [System.Runtime.Versioning.SupportedOSPlatform("windows")]
    private static bool IsAdministrator()
    {
        try
        {
            using var identity = System.Security.Principal.WindowsIdentity.GetCurrent();
            return new System.Security.Principal.WindowsPrincipal(identity).IsInRole(
                System.Security.Principal.WindowsBuiltInRole.Administrator
            );
        }
        catch
        {
            return false;
        }
    }

    /// <summary>Ask where the README comes from, as command-line arguments.</summary>
    private static List<string> AskForReadme(bool parseOnly)
    {
        var choices = new List<string>
        {
            "Find it automatically  [dim](recommended)[/]",
            "Enter a path or URL",
        };
        if (!parseOnly)
            choices.Add("Continue without a README");

        var answer = AnsiConsole.Prompt(
            new SelectionPrompt<string>()
                .Title("\n[bold]Which competition README should drive the run?[/]")
                .HighlightStyle(new Style(Color.Cyan1))
                .AddChoices(choices)
        );

        if (answer.StartsWith("Find", StringComparison.Ordinal))
            return ["--auto-readme"];

        if (answer.StartsWith("Continue", StringComparison.Ordinal))
            return [];

        // Accepts what --readme accepts: a .url or .lnk shortcut, an .html file,
        // or an https:// address. Resolution happens in the run, not here.
        var path = AnsiConsole.Prompt(
            new TextPrompt<string>("[bold]Path or URL:[/]")
                .PromptStyle(new Style(Color.Cyan1))
                .Validate(value =>
                    string.IsNullOrWhiteSpace(value)
                        ? ValidationResult.Error("[red]Enter a path, or press Ctrl+C to go back[/]")
                        : ValidationResult.Success()
                )
        );

        return ["--readme", path.Trim().Trim('"')];
    }

    private static List<string> AskForTasks()
    {
        var prompt = new MultiSelectionPrompt<string>()
            .Title("\n[bold]Which tasks should run?[/]")
            .NotRequired()
            .PageSize(16)
            .HighlightStyle(new Style(Color.Cyan1))
            .InstructionsText(
                "[dim](space toggles, enter confirms - everything starts selected)[/]"
            );

        // Added one at a time so each can be pre-selected. Starting with nothing
        // ticked would make the common case - "everything except the media scan"
        // - twelve keystrokes of work rather than one.
        foreach (var task in Tasks)
            prompt.AddChoice(task.Display).Select();

        var selected = AnsiConsole.Prompt(prompt);
        return Tasks.Where(t => selected.Contains(t.Display)).Select(t => t.Flag).ToList();
    }

    private static bool AskForDryRun()
    {
        var answer = AnsiConsole.Prompt(
            new SelectionPrompt<string>()
                .Title("\n[bold]Preview or apply?[/]")
                .HighlightStyle(new Style(Color.Cyan1))
                .AddChoices(
                    "Preview  [dim](dry run - reports what would change)[/]",
                    "Apply  [dim](makes the changes)[/]"
                )
        );
        return answer.StartsWith("Preview", StringComparison.Ordinal);
    }

    /// <summary>
    /// Say so when a chosen task depends on a README that was declined.
    /// </summary>
    /// <remarks>
    /// Without the warning the run simply reports "No README data provided" part
    /// way through, by which point the other tasks have already made changes.
    /// </remarks>
    private static void WarnAboutMissingReadme(List<string> readmeArgs, List<string> chosen)
    {
        if (readmeArgs.Count > 0)
            return;

        var affected = chosen.Contains("--all")
            ? NeedReadme
            : NeedReadme.Where(chosen.Contains).ToArray();

        if (affected.Length == 0)
            return;

        AnsiConsole.WriteLine();
        AnsiConsole.MarkupLine(
            "[yellow]! Without a README these tasks cannot tell authorised accounts and "
                + "software from unauthorised ones, and will decline to act:[/]"
        );
        foreach (var flag in affected)
        {
            var label = Tasks.First(t => t.Flag == flag).Label;
            AnsiConsole.MarkupLine($"[yellow]    {label}[/]");
        }
    }

    /// <summary>
    /// Show what is about to happen and require an explicit yes.
    /// </summary>
    /// <remarks>
    /// The default answer is no for a run that applies changes and yes for a dry
    /// run, so pressing enter without reading can only ever be the harmless
    /// choice.
    /// </remarks>
    private static bool Confirm(List<string> args, bool dryRun)
    {
        var summary = new Table()
            .Border(TableBorder.Rounded)
            .BorderColor(dryRun ? Color.Cyan1 : Color.Yellow)
            .AddColumn("[bold]Setting[/]")
            .AddColumn("[bold]Value[/]");

        var readmeIndex = args.IndexOf("--readme");
        summary.AddRow(
            "README",
            readmeIndex >= 0 ? Markup.Escape(args[readmeIndex + 1])
                : args.Contains("--auto-readme") ? "found automatically"
                : "[yellow]none[/]"
        );

        var taskFlags = args.Where(a => Tasks.Any(t => t.Flag == a) || a == "--all").ToList();
        summary.AddRow(
            "Tasks",
            taskFlags.Contains("--all")
                ? "every task"
                : string.Join("\n", taskFlags.Select(f => Tasks.First(t => t.Flag == f).Label))
        );

        summary.AddRow(
            "Mode",
            dryRun
                ? "[cyan]preview - nothing is changed[/]"
                : "[yellow]apply - changes this machine[/]"
        );
        summary.AddRow(
            "Command",
            $"[dim]PinnacleCyPat.exe {Markup.Escape(string.Join(' ', args))}[/]"
        );

        AnsiConsole.WriteLine();
        AnsiConsole.Write(summary);

        if (!dryRun)
        {
            AnsiConsole.MarkupLine(
                "[yellow]This deletes files, removes accounts and disables services. "
                    + "Run a preview first if you have not.[/]"
            );
        }

        return AnsiConsole.Prompt(
            new ConfirmationPrompt(dryRun ? "Start the preview?" : "[bold]Apply these changes?[/]")
            {
                DefaultValue = dryRun,
            }
        );
    }
}
