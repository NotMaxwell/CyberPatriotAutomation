// =============================================================================
// CyberPatriot Automation Tool
// Author: Maxwell McCormick
// Copyright (c) 2026 Maxwell McCormick. All Rights Reserved.
// =============================================================================

using System.Text;
using CyberPatriotAutomation.Core;
using CyberPatriotAutomation.Core.Models;
using CyberPatriotAutomation.Core.Tasks;
using CyberPatriotAutomation.Core.Utilities;
using Spectre.Console;

// Set console encoding to UTF-8 for proper character display
Console.OutputEncoding = Encoding.UTF8;
Console.InputEncoding = Encoding.UTF8;

// Display header with fancy styling
AnsiConsole.Write(new FigletText("CyberPatriot").LeftJustified().Color(Color.Blue));

AnsiConsole.Write(
    new Rule($"[bold blue]Automation Tool v{AppConfig.Version}[/]").RuleStyle("blue dim")
);
AnsiConsole.MarkupLine("[dim]By Maxwell McCormick[/]");
AnsiConsole.WriteLine();

// Parse command line arguments
var cliArgs = Environment.GetCommandLineArgs().Skip(1).ToArray();
var readmeFile = ExtractArgument(cliArgs, "--readme", "-r");
var autoFindReadme = cliArgs.Contains("--auto-readme") || cliArgs.Contains("-R");
var dryRun = cliArgs.Contains("--dry-run") || cliArgs.Contains("-d");
var interactive = !cliArgs.Contains("--no-interactive");
var runPasswordPolicy = cliArgs.Contains("--password-policy") || cliArgs.Contains("-p");
var runAccountPermissions = cliArgs.Contains("--account-permissions") || cliArgs.Contains("-a");
var runUserManagement = cliArgs.Contains("--user-management") || cliArgs.Contains("-u");
var runServiceManagement = cliArgs.Contains("--service-management") || cliArgs.Contains("-s");
var runAuditPolicy = cliArgs.Contains("--audit-policy") || cliArgs.Contains("-t");
var runFirewall = cliArgs.Contains("--firewall") || cliArgs.Contains("-f");
var runSecurityHardening = cliArgs.Contains("--security-hardening") || cliArgs.Contains("-h");
var runMediaScan = cliArgs.Contains("--media-scan") || cliArgs.Contains("-m");
var parseReadmeOnly = cliArgs.Contains("--parse-readme");
var runAll =
    cliArgs.Contains("--all")
    || (
        !runPasswordPolicy
        && !runAccountPermissions
        && !runUserManagement
        && !runServiceManagement
        && !runAuditPolicy
        && !runFirewall
        && !runSecurityHardening
        && !runMediaScan
        && !parseReadmeOnly
    );

// Auto-find README if requested and not explicitly provided
if (string.IsNullOrEmpty(readmeFile) && autoFindReadme)
{
    AnsiConsole.MarkupLine("[cyan]Auto-searching for README file...[/]");
    readmeFile = AppConfig.FindReadmeFile();

    if (!string.IsNullOrEmpty(readmeFile))
    {
        AnsiConsole.MarkupLine($"[green]✓ Found README: {readmeFile}[/]");
    }
    else
    {
        AnsiConsole.MarkupLine("[yellow]⚠ Could not auto-find README file[/]");
    }
    AnsiConsole.WriteLine();
}

// Display configuration panel
var configPanel = new Panel(
    new Markup(
        $"""
        [yellow]README File:[/] {(readmeFile ?? "[dim]Not specified (use -R to auto-find)[/]")}
        [yellow]Interactive Mode:[/] {(interactive ? "[green]ON[/]" : "[red]OFF[/]")}
        [yellow]Dry Run:[/] {(dryRun ? "[green]ON[/]" : "[dim]OFF[/]")}
        """
    )
).Header("[bold]Configuration[/]").Border(BoxBorder.Rounded).BorderColor(Color.Grey);

AnsiConsole.Write(configPanel);
AnsiConsole.WriteLine();

// Parse README file if provided
ReadmeData? readmeData = null;
if (!string.IsNullOrEmpty(readmeFile))
{
    AnsiConsole.Write(new Rule("[bold cyan]Parsing README File[/]").RuleStyle("cyan"));
    AnsiConsole.WriteLine();

    await AnsiConsole
        .Status()
        .Spinner(Spinner.Known.Dots)
        .SpinnerStyle(Style.Parse("cyan"))
        .StartAsync(
            "Parsing README file...",
            async ctx =>
            {
                readmeData = await ReadmeParser.ParseHtmlReadmeAsync(readmeFile);
            }
        );

    if (readmeData != null)
    {
        ReadmeParser.DisplayParsedData(readmeData);

        // If parse-readme-only flag is set, exit after displaying
        if (parseReadmeOnly)
        {
            AnsiConsole.WriteLine();
            AnsiConsole.Write(
                new Rule("[bold green]✓ README Parsing Complete[/]").RuleStyle("green")
            );
            return;
        }
    }

    AnsiConsole.WriteLine();
}

// Check for admin privileges
if (!IsRunningAsAdmin())
{
    AnsiConsole.Write(
        new Panel(
            new Markup(
                "[red]Not running with administrator privileges![/]\n[yellow]Some operations may fail. Please run as Administrator for full functionality.[/]"
            )
        )
            .Header("[bold red]⚠ Warning[/]")
            .Border(BoxBorder.Double)
            .BorderColor(Color.Red)
    );
    AnsiConsole.WriteLine();
}

// Build list of tasks to execute
var tasks = new List<BaseTask>();

if (runAll || runPasswordPolicy)
{
    tasks.Add(new PasswordPolicyTask());
}

if (runAll || runAccountPermissions)
{
    tasks.Add(new AccountPermissionsTask());
}

if (runAll || runUserManagement)
{
    var userTask = new UserManagementTask();
    if (readmeData != null)
    {
        userTask.SetReadmeData(readmeData);
    }
    tasks.Add(userTask);
}

if (runAll || runServiceManagement)
{
    var serviceTask = new ServiceManagementTask();
    if (readmeData != null)
    {
        serviceTask.SetReadmeData(readmeData);
    }
    tasks.Add(serviceTask);
}

if (runAll || runAuditPolicy)
{
    tasks.Add(new AuditPolicyTask());
}

if (runAll || runFirewall)
{
    tasks.Add(new FirewallConfigurationTask());
}

if (runAll || runSecurityHardening)
{
    tasks.Add(new SecurityHardeningTask());
}

if (runAll || runMediaScan)
{
    var mediaTask = new ProhibitedMediaTask();
    if (readmeData != null)
    {
        mediaTask.SetReadmeData(readmeData);
    }
    tasks.Add(mediaTask);
}

// Display tasks to execute
AnsiConsole.Write(new Rule("[bold]Tasks to Execute[/]").RuleStyle("grey"));
var taskTree = new Tree("[bold blue]Security Tasks[/]");
foreach (var task in tasks)
{
    taskTree.AddNode($"[yellow]{task.Name}[/]: {task.Description}");
}
AnsiConsole.Write(taskTree);
AnsiConsole.WriteLine();

if (dryRun)
{
    AnsiConsole.Write(
        new Panel("[yellow]DRY RUN MODE - No changes will be made[/]")
            .Border(BoxBorder.Rounded)
            .BorderColor(Color.Yellow)
    );
    AnsiConsole.WriteLine();

    // In dry run mode, show system state with progress
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
            foreach (var task in tasks)
            {
                var progressTask = ctx.AddTask($"[blue]Scanning: {task.Name}[/]");

                AnsiConsole.WriteLine();
                AnsiConsole.Write(new Rule($"[bold blue]{task.Name}[/]").RuleStyle("blue"));

                // Simulate progress while reading system state
                progressTask.MaxValue = 100;
                for (int i = 0; i < 100; i += 20)
                {
                    progressTask.Increment(20);
                    await Task.Delay(50);
                }

                await task.ReadSystemStateAsync();
                progressTask.Value = 100;
                progressTask.StopTask();

                AnsiConsole.MarkupLine("[green]✓ Scan complete[/]");
                AnsiConsole.WriteLine();
            }
        });
}
else
{
    // Execute tasks with progress tracking
    var results = new List<TaskResult>();

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
                new RemainingTimeColumn(),
                new SpinnerColumn(),
            }
        )
        .StartAsync(async ctx =>
        {
            var overallProgress = ctx.AddTask(
                "[bold]Overall Progress[/]",
                maxValue: tasks.Count * 3
            );

            foreach (var task in tasks)
            {
                AnsiConsole.WriteLine();
                AnsiConsole.Write(new Rule($"[bold blue]{task.Name}[/]").RuleStyle("blue"));
                AnsiConsole.WriteLine();

                if (interactive)
                {
                    var proceed = AnsiConsole.Confirm(
                        $"Execute [yellow]{task.Name}[/]?",
                        defaultValue: true
                    );
                    if (!proceed)
                    {
                        AnsiConsole.MarkupLine("[dim]⏭ Skipped[/]");
                        overallProgress.Increment(3);
                        continue;
                    }
                }

                // Step 1: Read system state
                var scanTask = ctx.AddTask($"[cyan]📊 Reading system state...[/]");
                AnsiConsole.MarkupLine("[cyan]📊 Reading current system state...[/]");

                await task.ReadSystemStateAsync();
                scanTask.Value = 100;
                scanTask.StopTask();
                overallProgress.Increment(1);

                AnsiConsole.MarkupLine("[green]✓ System state captured[/]");
                AnsiConsole.WriteLine();

                // Step 2: Execute remediation
                var execTask = ctx.AddTask($"[yellow]🔧 Executing remediation...[/]");
                AnsiConsole.MarkupLine("[yellow]🔧 Applying security fixes...[/]");

                var result = await task.ExecuteAsync();
                results.Add(result);
                execTask.Value = 100;
                execTask.StopTask();
                overallProgress.Increment(1);

                if (result.Success)
                {
                    AnsiConsole.MarkupLine($"[green]✓ {result.Message}[/]");
                }
                else
                {
                    AnsiConsole.MarkupLine($"[red]✗ {result.Message}[/]");
                }
                AnsiConsole.WriteLine();

                // Step 3: Verify changes
                var verifyTask = ctx.AddTask($"[magenta]🔍 Verifying changes...[/]");
                AnsiConsole.MarkupLine("[magenta]🔍 Verifying applied changes...[/]");

                var verified = await task.VerifyAsync();
                verifyTask.Value = 100;
                verifyTask.StopTask();
                overallProgress.Increment(1);

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
                AnsiConsole.WriteLine();
            }
        });

    // Display summary
    DisplaySummary(results);
}

AnsiConsole.WriteLine();
AnsiConsole.Write(new Rule("[bold green]✓ Automation Complete[/]").RuleStyle("green"));
AnsiConsole.WriteLine();

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
        .AddColumn(new TableColumn("[bold]Message[/]"))
        .AddColumn(new TableColumn("[bold]Time[/]").Centered());

    foreach (var result in results)
    {
        var status = result.Success ? "[green]✓ Success[/]" : "[red]✗ Failed[/]";
        var statusColor = result.Success ? Color.Green : Color.Red;

        table.AddRow(
            new Markup($"[bold]{result.TaskName}[/]"),
            new Markup(status),
            new Markup(result.Message),
            new Markup($"[dim]{result.ExecutedAt:HH:mm:ss}[/]")
        );

        if (!string.IsNullOrEmpty(result.ErrorDetails))
        {
            table.AddRow(
                new Markup(""),
                new Markup(""),
                new Markup($"[dim italic]{result.ErrorDetails}[/]"),
                new Markup("")
            );
        }
    }

    AnsiConsole.Write(table);
    AnsiConsole.WriteLine();

    var successCount = results.Count(r => r.Success);
    var failCount = results.Count(r => !r.Success);
    var totalCount = results.Count;

    // Create a summary bar chart
    var chart = new BreakdownChart()
        .Width(60)
        .AddItem("Successful", successCount, Color.Green)
        .AddItem("Failed", failCount, Color.Red);

    if (totalCount > 0)
    {
        AnsiConsole.Write(
            new Panel(chart)
                .Header("[bold]Results Breakdown[/]")
                .Border(BoxBorder.Rounded)
                .BorderColor(Color.Grey)
        );
    }

    AnsiConsole.WriteLine();
    AnsiConsole.MarkupLine(
        $"[bold]Total:[/] {totalCount} task(s) | [green]Successful: {successCount}[/] | [red]Failed: {failCount}[/]"
    );
}
