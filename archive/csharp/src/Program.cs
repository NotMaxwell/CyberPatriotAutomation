using System.Text;
using PinnacleCyPat.Core;
using PinnacleCyPat.Core.Models;
using PinnacleCyPat.Core.Tasks;
using PinnacleCyPat.Core.Utilities;
using Spectre.Console;

public class Program
{
    public static async Task Main(string[] args)
    {
        await RunAutomationAsync();
    }

    private static async Task RunAutomationAsync()
    {
        // Parse command line arguments
        var cliArgs = Environment.GetCommandLineArgs().Skip(1).ToArray();

        // Help before anything else, and before the run log opens.
        if (
            cliArgs.Contains("--help")
            || cliArgs.Contains("-h")
            || cliArgs.Contains("-?")
            || cliArgs.Contains("/?")
        )
        {
            PrintHelp();
            return;
        }

        // The interactive menu, either asked for or offered.
        //
        // A bare launch - which is what double-clicking the executable does -
        // has nothing to act on, and printing help at someone who cannot see a
        // command line does not help them. The menu is offered instead, but only
        // with a human at a terminal: redirected streams mean a script or a pipe,
        // where a prompt would wait forever for an answer that never comes.
        // Whatever the menu returns is a command line, so everything below this
        // point is unchanged by its presence.
        if (
            cliArgs.Contains("--tui")
            || cliArgs.Contains("-i")
            || (cliArgs.Length == 0 && Tui.IsInteractiveConsole())
        )
        {
            var chosen = Tui.BuildArguments();
            if (chosen is null)
                return;
            cliArgs = chosen;
        }

        // Reject anything unrecognised rather than letting it fall through.
        //
        // Every flag used to be matched by name and anything else ignored, while
        // "no task flag given" meant "run everything" - so a typo, or --help
        // itself, silently began a full destructive run instead of doing nothing.
        var unknown = FirstUnknownArgument(cliArgs);
        if (unknown is not null)
        {
            AnsiConsole.MarkupLine($"[red]Unrecognised argument: {Markup.Escape(unknown)}[/]");
            AnsiConsole.MarkupLine("[dim]Run with --help to see the available options.[/]");
            Environment.ExitCode = 2;
            return;
        }

        var readmeFile = ExtractArgument(cliArgs, "--readme", "-r");
        var autoFindReadme = cliArgs.Contains("--auto-readme") || cliArgs.Contains("-R");
        var dryRun = cliArgs.Contains("--dry-run") || cliArgs.Contains("-d");
        var runPasswordPolicy = cliArgs.Contains("--password-policy") || cliArgs.Contains("-p");
        var runAccountPermissions =
            cliArgs.Contains("--account-permissions") || cliArgs.Contains("-a");
        var runUserManagement = cliArgs.Contains("--user-management") || cliArgs.Contains("-u");
        var runServiceManagement =
            cliArgs.Contains("--service-management") || cliArgs.Contains("-s");
        var runAuditPolicy = cliArgs.Contains("--audit-policy") || cliArgs.Contains("-t");
        var runFirewall = cliArgs.Contains("--firewall") || cliArgs.Contains("-f");
        var runSecurityHardening =
            cliArgs.Contains("--security-hardening") || cliArgs.Contains("-H");
        var runMediaScan = cliArgs.Contains("--media-scan") || cliArgs.Contains("-m");

        // These five used to run only under --all, so there was no way to run one
        // on its own - or to offer them individually in the menu, which is what
        // prompted giving them flags.
        var runSoftwareManagement = cliArgs.Contains("--software-management");
        var runSharedFolders = cliArgs.Contains("--shared-folders");
        var runHostsFile = cliArgs.Contains("--hosts-file");
        var runDnsSettings = cliArgs.Contains("--dns-settings");
        var runScheduledTasks = cliArgs.Contains("--scheduled-tasks");
        var runGroupPolicy = cliArgs.Contains("--group-policy") || cliArgs.Contains("-g");

        var parseReadmeOnly = cliArgs.Contains("--parse-readme");

        // Split out from anyTaskNamed because --parse-readme is a report rather
        // than a task: combining it with real task flags has to be called out,
        // and testing "any task named" there would have flagged --parse-readme
        // on its own.
        var anyRemediationNamed =
            runPasswordPolicy
            || runAccountPermissions
            || runUserManagement
            || runServiceManagement
            || runAuditPolicy
            || runFirewall
            || runSecurityHardening
            || runMediaScan
            || runSoftwareManagement
            || runSharedFolders
            || runHostsFile
            || runDnsSettings
            || runScheduledTasks
            || runGroupPolicy;

        var anyTaskNamed = anyRemediationNamed || parseReadmeOnly;

        // The version, before the no-task guard below.
        //
        // --version names no task, so the guard treated it as "nothing to do",
        // printed the help and returned - the version never appeared. The Rust
        // port has always answered it here.
        if (cliArgs.Contains("--version") || cliArgs.Contains("-V"))
        {
            Console.WriteLine($"PinnacleCyPat {AppConfig.VersionString}");
            return;
        }

        // Running everything has to be asked for.
        //
        // "No task flag given" used to mean "run every task", so simply
        // launching the executable - by double-clicking it, or to see what it
        // does - began a full destructive run against the machine. Nothing about
        // a bare invocation says "change this system", so it now prints the help
        // and stops.
        var runAll = cliArgs.Contains("--all");
        if (!runAll && !anyTaskNamed)
        {
            PrintHelp();
            AnsiConsole.MarkupLine(
                "\n[yellow]No task selected. Pass --all to run every task, or name individual tasks.[/]"
            );
            AnsiConsole.MarkupLine("[dim]Pass --dry-run first to preview the changes.[/]");
            return;
        }

        // Where to write the run log; --log <path> overrides the default.
        var logPath = ExtractArgument(cliArgs, "--log") ?? RunLog.DefaultLogPath();
        foreach (var line in RunLog.Header(string.Join(' ', cliArgs)))
            RunLog.RecordRaw(line);
        RunLog.AttachToConsole();

        // Auto-find the README if requested and none supplied. The flag was
        // previously parsed but never acted on, so --auto-readme did nothing.
        var discoveryAttempts = new List<string>();
        if (string.IsNullOrEmpty(readmeFile) && autoFindReadme)
        {
            readmeFile = await AppConfig.FindReadmeFileAsync(discoveryAttempts);
        }

        // Parse README if needed.
        //
        // An explicitly supplied path is resolved the same way an auto-discovered
        // one is: the documented location on a competition image is
        // C:\CyberPatriot\README.url, so --readme pointing at a .url (or .lnk, or
        // an https:// address) has to follow it rather than parse the shortcut
        // itself as HTML.
        ReadmeData? readmeData = null;
        if (!string.IsNullOrEmpty(readmeFile))
        {
            var indirect =
                AppConfig.IsRemoteTarget(readmeFile)
                || Path.GetExtension(readmeFile).Equals(".url", StringComparison.OrdinalIgnoreCase)
                || Path.GetExtension(readmeFile).Equals(".lnk", StringComparison.OrdinalIgnoreCase);

            var resolved = await AppConfig.ResolveReadmeCandidateAsync(readmeFile);

            if (resolved != null)
            {
                // Say which document was actually used. Without this a shortcut
                // resolving to the wrong target is invisible: the run reports an
                // empty README with nothing to point at.
                AnsiConsole.MarkupLine(
                    resolved == readmeFile
                        ? $"[dim]Using README: {Markup.Escape(resolved)}[/]"
                        : $"[dim]Using README: {Markup.Escape(resolved)} (resolved from {Markup.Escape(readmeFile)})[/]"
                );
                readmeData = await ReadmeParser.ParseHtmlReadmeAsync(resolved);
            }
            else if (indirect)
            {
                // A shortcut or URL that could not be followed must not be fed to
                // the HTML parser: an INI file yields a README with no title and
                // no detectable OS, reporting "Unknown" for everything and hiding
                // the real failure.
                AnsiConsole.MarkupLine(
                    $"[red]Could not obtain the README from {Markup.Escape(readmeFile)}[/]"
                );
                AnsiConsole.MarkupLine(
                    "[yellow]If the image has no network access, open the README in a browser, "
                        + "save it as HTML, and pass it with --readme <file>.[/]"
                );
            }
            else
            {
                // A plain path that does not exist: let the parser report "not
                // found" against exactly what was typed.
                readmeData = await ReadmeParser.ParseHtmlReadmeAsync(readmeFile);
            }
        }
        else if (autoFindReadme)
        {
            AnsiConsole.MarkupLine(
                "[yellow]No README found automatically. Pass --readme <file> to specify one.[/]"
            );
            // Show where it looked, so a candidate that exists but cannot be
            // followed is visible rather than silently skipped.
            AnsiConsole.MarkupLine("[dim]Locations checked:[/]");
            foreach (var attempt in discoveryAttempts)
            {
                AnsiConsole.MarkupLine($"[dim]  - {Markup.Escape(attempt)}[/]");
            }
        }

        // Parse-only mode: display the parsed data and stop. The flag previously
        // only suppressed runAll, so it printed nothing and ran no tasks - an
        // empty summary table with no indication why.
        if (parseReadmeOnly)
        {
            if (readmeData != null)
            {
                ReadmeParser.DisplayParsedData(readmeData);
            }
            else
            {
                AnsiConsole.MarkupLine(
                    "[yellow]No README file specified. Use --readme <file> to parse one.[/]"
                );
            }

            // --parse-readme is a report, not a run. Combining it with task flags
            // silently did nothing, which reads as the tasks having been skipped
            // for some other reason.
            if (runAll || anyRemediationNamed)
            {
                AnsiConsole.WriteLine();
                AnsiConsole.MarkupLine(
                    "[yellow]Note: --parse-readme only reports the README; no tasks were run.[/]"
                );
                AnsiConsole.MarkupLine(
                    "[yellow]Drop --parse-readme to apply them - the README is displayed either way.[/]"
                );
            }

            await FinishLogAsync(logPath);
            return;
        }

        // Show what was extracted before acting on it. The tasks are driven by
        // this data - which users are authorised, which services are critical -
        // so seeing it first is what makes the run reviewable.
        if (readmeData != null)
        {
            ReadmeParser.DisplayParsedData(readmeData);
            AnsiConsole.WriteLine();
        }

        // Build task list
        var tasks = new List<BaseTask>();
        if (runPasswordPolicy || runAll)
            tasks.Add(new PasswordPolicyTask());
        if (runAccountPermissions || runAll)
            tasks.Add(new AccountPermissionsTask());
        if (runUserManagement || runAll)
        {
            var userTask = new UserManagementTask();
            if (readmeData != null)
                userTask.SetReadmeData(readmeData);
            tasks.Add(userTask);
        }
        if (runServiceManagement || runAll)
        {
            var serviceTask = new ServiceManagementTask();
            if (readmeData != null)
                serviceTask.SetReadmeData(readmeData);
            tasks.Add(serviceTask);
        }
        if (runAuditPolicy || runAll)
            tasks.Add(new AuditPolicyTask());
        if (runFirewall || runAll)
            tasks.Add(new FirewallConfigurationTask());
        if (runSecurityHardening || runAll)
        {
            var hardeningTask = new SecurityHardeningTask();
            if (readmeData != null)
                hardeningTask.SetReadmeData(readmeData);
            tasks.Add(hardeningTask);
        }
        if (runGroupPolicy || runAll)
        {
            var groupPolicyTask = new GroupPolicyTask();
            if (readmeData != null)
                groupPolicyTask.SetReadmeData(readmeData);
            tasks.Add(groupPolicyTask);
        }
        if (runMediaScan || runAll)
        {
            var mediaTask = new ProhibitedMediaTask();
            if (readmeData != null)
                mediaTask.SetReadmeData(readmeData);
            tasks.Add(mediaTask);
        }
        if (runSharedFolders || runAll)
            tasks.Add(new SharedFoldersAuditTask());
        if (runHostsFile || runAll)
            tasks.Add(new HostsFileAuditTask());
        if (runDnsSettings || runAll)
            tasks.Add(new DnsSettingsAuditTask());
        if (runScheduledTasks || runAll)
            tasks.Add(new SuspiciousScheduledTasksAuditTask());
        if (runSoftwareManagement || runAll)
        {
            var softwareTask = new SoftwareManagementTask();
            if (readmeData != null)
                softwareTask.SetReadmeData(readmeData);
            tasks.Add(softwareTask);
        }

        // Set dry-run mode on all tasks
        foreach (var task in tasks)
        {
            task.DryRun = dryRun;
        }

        // The utilities record every change against whichever task is running,
        // and hold back from writing anything at all during a dry run.
        RunLog.DryRun = dryRun;

        // Run all tasks
        var results = new List<TaskResult>();
        foreach (var task in tasks)
        {
            RunLog.BeginTask(task.Name);
            AnsiConsole.WriteLine();
            AnsiConsole.Write(new Rule($"[bold blue]{task.Name}[/]").RuleStyle("blue"));
            AnsiConsole.WriteLine();

            // Step 1: Read system state
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
                    var scanTask = ctx.AddTask($"[cyan]📊 Reading system state...[/]");
                    AnsiConsole.MarkupLine("[cyan]📊 Reading current system state...[/]");
                    await task.ReadSystemStateAsync();
                    scanTask.Value = 100;
                    scanTask.StopTask();
                });
            AnsiConsole.MarkupLine("[green]✓ System state captured[/]");
            AnsiConsole.WriteLine();

            // Step 2: Execute remediation
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
                    var execTask = ctx.AddTask($"[yellow]🔧 Executing remediation...[/]");
                    AnsiConsole.MarkupLine("[yellow]🔧 Applying security fixes...[/]");
                    var result = await task.ExecuteAsync();
                    results.Add(result);
                    execTask.Value = 100;
                    execTask.StopTask();
                });
            var lastResult = results.Last();
            if (lastResult.Success)
            {
                AnsiConsole.MarkupLine($"[green]✓ {lastResult.Message}[/]");
            }
            else
            {
                AnsiConsole.MarkupLine($"[red]✗ {lastResult.Message}[/]");
            }
            AnsiConsole.WriteLine();

            // Step 3: Verify changes
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
                    var verifyTask = ctx.AddTask($"[magenta]🔍 Verifying changes...[/]");
                    AnsiConsole.MarkupLine("[magenta]🔍 Verifying applied changes...[/]");
                    var verified = await task.VerifyAsync();

                    // Update the task result with verification status
                    lastResult.Verified = verified;
                    if (!verified)
                    {
                        // Reduce confidence if verification fails
                        lastResult.ConfidencePercent = Math.Max(
                            50,
                            lastResult.ConfidencePercent - 30
                        );
                    }

                    verifyTask.Value = 100;
                    verifyTask.StopTask();
                    if (verified)
                    {
                        AnsiConsole.MarkupLine("[green]✓ All changes verified successfully[/]");
                    }
                    else
                    {
                        AnsiConsole.MarkupLine(
                            "[yellow]⚠ Some changes may need manual verification[/]"
                        );
                    }
                });
            AnsiConsole.WriteLine();
        }
        // Display summary
        RunLog.BeginTask("(summary)");
        DisplaySummary(results);
        DisplayLedgerSummary();
        AnsiConsole.WriteLine();
        AnsiConsole.Write(new Rule("[bold green]✓ Automation Complete[/]").RuleStyle("green"));
        AnsiConsole.WriteLine();

        RunLog.AppendLedger();
        RunLog.AppendResults(results);
        await FinishLogAsync(logPath);
    }

    /// <summary>
    /// Write the run log, reporting where it went or why it could not be written.
    /// </summary>
    static async Task FinishLogAsync(string path)
    {
        try
        {
            await RunLog.WriteToAsync(path);
            AnsiConsole.MarkupLine($"[dim]Run log written to: {Markup.Escape(path)}[/]");
        }
        catch (Exception ex)
        {
            AnsiConsole.MarkupLine(
                $"[yellow]Could not write run log to {Markup.Escape(path)}: "
                    + $"{Markup.Escape(ex.Message)}[/]"
            );
        }
    }

    /// <summary>
    /// Every accepted flag, with the description shown by <c>--help</c>.
    /// </summary>
    /// <remarks>
    /// The single source of truth for both the help text and the
    /// unrecognised-argument check, so a flag cannot be accepted without also
    /// being documented.
    /// </remarks>
    private static readonly (string Long, string Short, string Description)[] Flags =
    [
        ("--help", "-h", "Show this help and exit"),
        ("--tui", "-i", "Open the interactive menu"),
        ("--version", "-V", "Print the version and build date, then exit"),
        ("--readme <path>", "-r", "Read the competition README at <path>"),
        ("--auto-readme", "-R", "Find the README automatically"),
        ("--parse-readme", "", "Show what the parser extracted, then exit (read-only)"),
        ("--dry-run", "-d", "Report what would change without changing it"),
        ("--all", "", "Run every task"),
        ("--password-policy", "-p", "Password and lockout policy"),
        ("--account-permissions", "-a", "Account permissions and group membership"),
        ("--user-management", "-u", "Create, remove and correct user accounts"),
        ("--service-management", "-s", "Enable required and disable insecure services"),
        ("--audit-policy", "-t", "Audit policy and security event logging"),
        ("--firewall", "-f", "Windows Firewall profiles and rules"),
        ("--security-hardening", "-H", "General security hardening"),
        ("--media-scan", "-m", "Find and remove prohibited media"),
        ("--software-management", "", "Remove prohibited and install required software"),
        ("--shared-folders", "", "Remove shares beyond ADMIN$, C$ and IPC$"),
        ("--hosts-file", "", "Remove unauthorised hosts file entries"),
        ("--dns-settings", "", "Report public DNS resolvers"),
        ("--scheduled-tasks", "", "Disable suspicious scheduled tasks"),
        ("--group-policy", "-g", "Local Security Policy: SMB signing, logon, RDP"),
        ("--log <path>", "", "Write the run log to <path>"),
    ];

    /// <summary>Flags that consume the following argument as their value.</summary>
    private static readonly string[] ValueFlags = ["--readme", "-r", "--log"];

    /// <summary>The first argument that is not a flag this tool accepts, if any.</summary>
    public static string? FirstUnknownArgument(string[] args)
    {
        var known = new HashSet<string>(StringComparer.Ordinal);
        foreach (var (longName, shortName, _) in Flags)
        {
            // The table spells value-taking flags as "--readme <path>".
            known.Add(longName.Split(' ')[0]);
            if (shortName.Length > 0)
                known.Add(shortName);
        }
        // Accepted as help but deliberately absent from the table, which lists
        // one spelling per flag.
        known.Add("-?");
        known.Add("/?");

        var skipNext = false;
        foreach (var arg in args)
        {
            if (skipNext)
            {
                skipNext = false;
                continue;
            }
            if (ValueFlags.Contains(arg))
            {
                skipNext = true;
                continue;
            }
            if (!known.Contains(arg))
                return arg;
        }
        return null;
    }

    private static void PrintHelp()
    {
        Console.WriteLine($"PinnacleCyPat {AppConfig.VersionString}");
        Console.WriteLine();
        Console.WriteLine("USAGE:");
        Console.WriteLine("    PinnacleCyPat.exe [OPTIONS]");
        Console.WriteLine();
        Console.WriteLine("Run as Administrator. Name a task, or pass --all to run every task.");
        Console.WriteLine("Pass --dry-run first to see what would change.");
        Console.WriteLine("Not sure? Run --tui for a guided menu.");
        Console.WriteLine();
        Console.WriteLine("OPTIONS:");
        foreach (var (longName, shortName, description) in Flags)
        {
            var flag = shortName.Length > 0 ? $"    {shortName}, {longName}" : $"    {longName}";
            Console.WriteLine($"{flag, -34}{description}");
        }
        Console.WriteLine();
        Console.WriteLine("EXAMPLES:");
        Console.WriteLine("    PinnacleCyPat.exe --tui                          # guided menu");
        Console.WriteLine("    PinnacleCyPat.exe --auto-readme --parse-readme   # read-only");
        Console.WriteLine("    PinnacleCyPat.exe --auto-readme --all --dry-run  # preview");
        Console.WriteLine("    PinnacleCyPat.exe --auto-readme --all            # apply");
    }

    // Helper functions
    static string? ExtractArgument(string[] args, params string[] flags)
    {
        for (int i = 0; i < args.Length; i++)
        {
            if (flags.Contains(args[i]) && i + 1 < args.Length)
            {
                return args[i + 1];
            }
        }
        return null;
    }

    [System.Runtime.Versioning.SupportedOSPlatform("windows")]
    static bool IsRunningAsAdmin()
    {
        try
        {
            var identity = System.Security.Principal.WindowsIdentity.GetCurrent();
            var principal = new System.Security.Principal.WindowsPrincipal(identity);
            return principal.IsInRole(System.Security.Principal.WindowsBuiltInRole.Administrator);
        }
        catch
        {
            return false;
        }
    }

    static void DisplaySummary(List<TaskResult> results)
    {
        AnsiConsole.WriteLine();
        AnsiConsole.Write(new Rule("[bold blue]Summary[/]").RuleStyle("blue"));
        AnsiConsole.WriteLine();

        var table = new Table()
            .Border(TableBorder.Rounded)
            .BorderColor(Color.Grey)
            .AddColumn(new TableColumn("[bold]Task[/]").Centered())
            .AddColumn(new TableColumn("[bold]Status[/]").Centered())
            .AddColumn(new TableColumn("[bold]Completion[/]").Centered())
            .AddColumn(new TableColumn("[bold]Confidence[/]").Centered())
            .AddColumn(new TableColumn("[bold]Message[/]"))
            .AddColumn(new TableColumn("[bold]Time[/]").Centered());

        foreach (var result in results)
        {
            var status = result.Success ? "[green]✓ Success[/]" : "[red]✗ Failed[/]";
            var completionRate = result.CompletionRate;
            var completionColor =
                completionRate >= 90 ? "green"
                : completionRate >= 70 ? "yellow"
                : "red";
            var confidenceColor =
                result.ConfidencePercent >= 90 ? "green"
                : result.ConfidencePercent >= 70 ? "yellow"
                : "red";

            table.AddRow(
                new Markup($"[bold]{result.TaskName}[/]"),
                new Markup(status),
                new Markup($"[{completionColor}]{completionRate:F1}%[/]"),
                new Markup($"[{confidenceColor}]{result.ConfidencePercent}%[/]"),
                new Markup(result.Message),
                new Markup($"[dim]{result.ExecutedAt:HH:mm:ss}[/]")
            );

            if (!string.IsNullOrEmpty(result.ErrorDetails))
            {
                table.AddRow(
                    new Markup(""),
                    new Markup(""),
                    new Markup(""),
                    new Markup(""),
                    new Markup($"[dim italic]{result.ErrorDetails}[/]"),
                    new Markup("")
                );
            }
        }

        AnsiConsole.Write(table);
        AnsiConsole.WriteLine();

        // Calculate and display overall statistics
        DisplayOverallStatistics(results);
    }

    /// <summary>
    /// Show what the run actually changed, and how much of it was confirmed.
    /// </summary>
    /// <remarks>
    /// The task summary above answers "did each task run"; this answers "what is
    /// different about this machine now, and how do we know". The two disagree
    /// more often than is comfortable - a task that reports success while every
    /// change it made reads back unverified is exactly the case worth surfacing
    /// before the round ends, so anything not confirmed is listed by name.
    /// </remarks>
    static void DisplayLedgerSummary()
    {
        var fixes = RunLog.FixSnapshot();
        if (fixes.Count == 0)
            return;

        AnsiConsole.WriteLine();
        AnsiConsole.Write(new Rule("[bold blue]Changes and Proof[/]").RuleStyle("blue"));
        AnsiConsole.WriteLine();

        int Count(FixOutcome outcome) => fixes.Count(f => f.Outcome == outcome);

        var table = new Table()
            .Border(TableBorder.Rounded)
            .BorderColor(Color.Grey)
            .AddColumn(new TableColumn("[bold]Outcome[/]"))
            .AddColumn(new TableColumn("[bold]Count[/]").Centered())
            .AddColumn(new TableColumn("[bold]Meaning[/]"));

        table.AddRow(
            new Markup("[green]Fixed[/]"),
            new Markup($"{Count(FixOutcome.Fixed)}"),
            new Markup("[dim]changed, and reading it back confirms it[/]")
        );
        table.AddRow(
            new Markup("[green]Already OK[/]"),
            new Markup($"{Count(FixOutcome.AlreadyCompliant)}"),
            new Markup("[dim]nothing to do; the machine was already right[/]")
        );
        table.AddRow(
            new Markup("[red]Failed[/]"),
            new Markup($"{Count(FixOutcome.Failed)}"),
            new Markup("[dim]attempted and did not take[/]")
        );
        table.AddRow(
            new Markup("[yellow]Unverified[/]"),
            new Markup($"{Count(FixOutcome.Unverified)}"),
            new Markup("[dim]the write reported success but could not be confirmed[/]")
        );
        table.AddRow(
            new Markup("[dim]Skipped[/]"),
            new Markup($"{Count(FixOutcome.Skipped)}"),
            new Markup("[dim]not attempted[/]")
        );

        AnsiConsole.Write(table);

        var needsAttention = fixes
            .Where(f => f.Outcome is FixOutcome.Failed or FixOutcome.Unverified)
            .ToList();

        if (needsAttention.Count > 0)
        {
            AnsiConsole.WriteLine();
            AnsiConsole.MarkupLine("[yellow]Not confirmed - check these by hand:[/]");
            foreach (var fix in needsAttention)
            {
                AnsiConsole.MarkupLine(
                    $"  [dim]{fix.Tag, -10}[/] {Markup.Escape(fix.Target)} "
                        + $"[dim]- {Markup.Escape(fix.Evidence)}[/]"
                );
            }
        }

        AnsiConsole.WriteLine();
        AnsiConsole.MarkupLine(
            "[dim]Every change, with what it wanted and the read-back that proves it, "
                + "is in the run log.[/]"
        );
    }

    static void DisplayOverallStatistics(List<TaskResult> results)
    {
        if (results.Count == 0)
            return;

        var successCount = results.Count(r => r.Success);
        var failCount = results.Count(r => !r.Success);
        var verifiedCount = results.Count(r => r.Verified);

        var totalItemsAttempted = results.Sum(r => r.ItemsAttempted);
        var totalItemsSucceeded = results.Sum(r => r.ItemsSucceeded);
        var totalItemsSkipped = results.Sum(r => r.ItemsSkipped);

        // Overall completion rate
        var overallCompletionRate =
            totalItemsAttempted > 0
                ? (double)(totalItemsSucceeded + totalItemsSkipped) / totalItemsAttempted * 100
                : 100;

        // Overall confidence (weighted average based on items attempted)
        var overallConfidence =
            totalItemsAttempted > 0
                ? results.Sum(r => r.ConfidencePercent * r.ItemsAttempted)
                    / (double)totalItemsAttempted
                : results.Average(r => r.ConfidencePercent);

        // Adjust confidence based on verification status
        var verificationBonus = verifiedCount / (double)results.Count;
        overallConfidence = Math.Min(100, overallConfidence * (0.7 + 0.3 * verificationBonus));

        AnsiConsole.Write(new Rule("[bold cyan]Overall Statistics[/]").RuleStyle("cyan"));
        AnsiConsole.WriteLine();

        // Create a panel with statistics
        var grid = new Grid();
        grid.AddColumn();
        grid.AddColumn();
        grid.AddColumn();
        grid.AddColumn();

        grid.AddRow(
            new Markup($"[bold]Tasks:[/] {successCount}/{results.Count} passed"),
            new Markup($"[bold]Verified:[/] {verifiedCount}/{results.Count}"),
            new Markup(
                $"[bold]Items:[/] {totalItemsSucceeded + totalItemsSkipped}/{totalItemsAttempted}"
            ),
            new Markup($"[bold]Skipped:[/] {totalItemsSkipped}")
        );

        AnsiConsole.Write(grid);
        AnsiConsole.WriteLine();

        // Display completion rate bar chart
        var completionColor =
            overallCompletionRate >= 90 ? Color.Green
            : overallCompletionRate >= 70 ? Color.Yellow
            : Color.Red;
        AnsiConsole.Write(
            new BarChart()
                .Width(60)
                .Label("[bold]Completion Rate[/]")
                .AddItem("Completed", overallCompletionRate, completionColor)
                .AddItem("Remaining", 100 - overallCompletionRate, Color.Grey)
        );

        AnsiConsole.WriteLine();

        // Display confidence bar chart
        var confidenceColor =
            overallConfidence >= 90 ? Color.Green
            : overallConfidence >= 70 ? Color.Yellow
            : Color.Red;
        AnsiConsole.Write(
            new BarChart()
                .Width(60)
                .Label("[bold]Confidence Level[/]")
                .AddItem("Confident", overallConfidence, confidenceColor)
                .AddItem("Uncertain", 100 - overallConfidence, Color.Grey)
        );

        AnsiConsole.WriteLine();

        // Display final summary message
        var completionEmoji =
            overallCompletionRate >= 90 ? "🎉"
            : overallCompletionRate >= 70 ? "👍"
            : "⚠️";
        var confidenceEmoji =
            overallConfidence >= 90 ? "✅"
            : overallConfidence >= 70 ? "🔶"
            : "❌";

        AnsiConsole.MarkupLine(
            $"{completionEmoji} [bold]Overall Completion Rate:[/] [{(overallCompletionRate >= 90 ? "green" : overallCompletionRate >= 70 ? "yellow" : "red")}]{overallCompletionRate:F1}%[/]"
        );
        AnsiConsole.MarkupLine(
            $"{confidenceEmoji} [bold]Overall Confidence Level:[/] [{(overallConfidence >= 90 ? "green" : overallConfidence >= 70 ? "yellow" : "red")}]{overallConfidence:F1}%[/]"
        );

        if (overallConfidence < 90)
        {
            AnsiConsole.WriteLine();
            AnsiConsole.MarkupLine(
                "[dim italic]💡 Tip: Manual verification recommended for tasks with low confidence.[/]"
            );
        }
    }
}
