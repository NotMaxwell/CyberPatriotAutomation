using System.Text;
using CyberPatriotAutomation.Core;
using CyberPatriotAutomation.Core.Models;
using CyberPatriotAutomation.Core.Tasks;
using CyberPatriotAutomation.Core.Utilities;
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
            cliArgs.Contains("--security-hardening") || cliArgs.Contains("-h");
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

        // Parse README if needed
        ReadmeData? readmeData = null;
        if (!string.IsNullOrEmpty(readmeFile))
        {
            readmeData = await ReadmeParser.ParseHtmlReadmeAsync(readmeFile);
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
            tasks.Add(new SecurityHardeningTask());
        if (runMediaScan || runAll)
        {
            var mediaTask = new ProhibitedMediaTask();
            if (readmeData != null)
                mediaTask.SetReadmeData(readmeData);
            tasks.Add(mediaTask);
        }
        if (runAll)
        {
            tasks.Add(new SharedFoldersAuditTask());
            tasks.Add(new HostsFileAuditTask());
            tasks.Add(new DnsSettingsAuditTask());
            tasks.Add(new SuspiciousScheduledTasksAuditTask());
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

        // Run all tasks
        var results = new List<TaskResult>();
        foreach (var task in tasks)
        {
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
        DisplaySummary(results);
        AnsiConsole.WriteLine();
        AnsiConsole.Write(new Rule("[bold green]✓ Automation Complete[/]").RuleStyle("green"));
        AnsiConsole.WriteLine();
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
        if (results.Count > 0)
        {
            var lastResult = results.Last();
            if (lastResult.Success)
            {
                AnsiConsole.MarkupLine($"[green]\u2713 {lastResult.Message}[/]");
            }
            else
            {
                AnsiConsole.MarkupLine($"[red]\u2717 {lastResult.Message}[/]");
            }
            AnsiConsole.WriteLine();
        }
    }
}
