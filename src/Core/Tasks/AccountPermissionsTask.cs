using CyberPatriotAutomation.Core.Models;
using CyberPatriotAutomation.Core.Utilities;
using Spectre.Console;

namespace CyberPatriotAutomation.Core.Tasks;

/// <summary>
/// Task to check and fix account permissions and security settings
/// </summary>
public class AccountPermissionsTask : BaseTask
{
    private List<AccountInfo> _accounts = new();

    public AccountPermissionsTask()
    {
        Name = "Account Permissions Check";
        Description = "Check and fix user account permissions and security settings";
    }

    public override async Task<SystemInfo> ReadSystemStateAsync()
    {
        var systemInfo = new SystemInfo();
        _accounts = await GetUserAccountsAsync();

        foreach (var account in _accounts)
        {
            systemInfo.UserAccounts.Add(
                $"{account.Username} (Admin: {account.IsAdmin}, Enabled: {account.IsEnabled})"
            );
        }

        return systemInfo;
    }

    public override async Task<TaskResult> ExecuteAsync()
    {
        var result = new TaskResult
        {
            TaskName = Name,
            Success = true,
            Message = "Account permissions check completed",
        };

        var issues = new List<string>();
        var fixes = new List<string>();

        try
        {
            AnsiConsole.MarkupLine("[bold]Checking User Account Security...[/]");

            if (_accounts.Count == 0)
            {
                _accounts = await GetUserAccountsAsync();
            }

            // Display current accounts
            DisplayAccountsTable(_accounts);

            // Check and fix Guest account
            var guestFixes = await CheckGuestAccountAsync();
            fixes.AddRange(guestFixes.Fixes);
            issues.AddRange(guestFixes.Issues);

            // Check and fix accounts with no password required
            var passwordFixes = await EnforcePasswordRequiredAsync();
            fixes.AddRange(passwordFixes.Fixes);
            issues.AddRange(passwordFixes.Issues);

            // Check accounts with password never expires
            var expiryFixes = await CheckPasswordExpirationAsync();
            fixes.AddRange(expiryFixes.Fixes);
            issues.AddRange(expiryFixes.Issues);

            // Check for unauthorized admin accounts
            var adminFixes = await ReviewAdminAccountsAsync();
            fixes.AddRange(adminFixes.Fixes);
            issues.AddRange(adminFixes.Issues);

            // Check for inactive accounts
            var inactiveFixes = await CheckInactiveAccountsAsync();
            fixes.AddRange(inactiveFixes.Fixes);
            issues.AddRange(inactiveFixes.Issues);

            if (issues.Count > 0)
            {
                result.Message =
                    $"Applied {fixes.Count} fixes. {issues.Count} issues require manual review.";
                result.ErrorDetails = string.Join("\n", issues);
            }
            else
            {
                result.Message = $"Successfully applied {fixes.Count} account security fixes.";
            }
        }
        catch (Exception ex)
        {
            result.Success = false;
            result.Message = "Failed to check account permissions";
            result.ErrorDetails = ex.Message;
            AnsiConsole.WriteException(ex);
        }

        return result;
    }

    public override async Task<bool> VerifyAsync()
    {
        var accounts = await GetUserAccountsAsync();
        bool allGood = true;

        // Verify Guest is disabled
        var guest = accounts.FirstOrDefault(a =>
            a.Username.Equals("Guest", StringComparison.OrdinalIgnoreCase)
        );
        if (guest != null && guest.IsEnabled)
        {
            AnsiConsole.MarkupLine("[red]? Guest account is still enabled[/]");
            allGood = false;
        }

        // Verify all accounts require passwords
        var noPassword = accounts.Where(a => !a.PasswordRequired && a.IsEnabled).ToList();
        if (noPassword.Any())
        {
            AnsiConsole.MarkupLine(
                $"[red]? {noPassword.Count} account(s) still don't require passwords[/]"
            );
            allGood = false;
        }

        if (allGood)
        {
            AnsiConsole.MarkupLine("[green]? All account security settings verified[/]");
        }

        return allGood;
    }

    private async Task<List<AccountInfo>> GetUserAccountsAsync()
    {
        var accounts = new List<AccountInfo>();

        // Get all local users using PowerShell
        var (success, output, _) = await CommandExecutor.ExecuteAsync(
            "powershell",
            "-Command \"Get-LocalUser | Select-Object Name, FullName, Enabled, PasswordRequired, PasswordNeverExpires, LastLogon | ConvertTo-Csv -NoTypeInformation\""
        );

        if (success && !string.IsNullOrEmpty(output))
        {
            var lines = output.Split(new[] { '\r', '\n' }, StringSplitOptions.RemoveEmptyEntries);

            // Skip header
            foreach (var line in lines.Skip(1))
            {
                var account = ParseAccountFromCsv(line);
                if (account != null)
                {
                    // Check if user is admin
                    account.IsAdmin = await IsUserAdminAsync(account.Username);
                    account.GroupMemberships = await GetUserGroupsAsync(account.Username);
                    accounts.Add(account);
                }
            }
        }

        return accounts;
    }

    private AccountInfo? ParseAccountFromCsv(string csvLine)
    {
        try
        {
            // Parse CSV line - handle quoted values
            var values = ParseCsvLine(csvLine);
            if (values.Count < 5)
                return null;

            return new AccountInfo
            {
                Username = values[0].Trim('"'),
                FullName = values.Count > 1 ? values[1].Trim('"') : "",
                IsEnabled =
                    values.Count > 2
                    && values[2].Trim('"').Equals("True", StringComparison.OrdinalIgnoreCase),
                PasswordRequired =
                    values.Count > 3
                    && values[3].Trim('"').Equals("True", StringComparison.OrdinalIgnoreCase),
                PasswordNeverExpires =
                    values.Count > 4
                    && values[4].Trim('"').Equals("True", StringComparison.OrdinalIgnoreCase),
                LastLogon = values.Count > 5 ? ParseDateTime(values[5].Trim('"')) : null,
            };
        }
        catch
        {
            return null;
        }
    }

    private List<string> ParseCsvLine(string line)
    {
        var result = new List<string>();
        bool inQuotes = false;
        var currentValue = "";

        foreach (char c in line)
        {
            if (c == '"')
            {
                inQuotes = !inQuotes;
                currentValue += c;
            }
            else if (c == ',' && !inQuotes)
            {
                result.Add(currentValue);
                currentValue = "";
            }
            else
            {
                currentValue += c;
            }
        }
        result.Add(currentValue);
        return result;
    }

    private DateTime? ParseDateTime(string value)
    {
        if (string.IsNullOrWhiteSpace(value) || value == "")
            return null;

        if (DateTime.TryParse(value, out DateTime result))
            return result;

        return null;
    }

    private async Task<bool> IsUserAdminAsync(string username)
    {
        var (success, output, _) = await CommandExecutor.ExecuteAsync(
            "net",
            $"localgroup Administrators"
        );

        return success && output.Contains(username, StringComparison.OrdinalIgnoreCase);
    }

    private async Task<List<string>> GetUserGroupsAsync(string username)
    {
        var groups = new List<string>();
        var (success, output, _) = await CommandExecutor.ExecuteAsync(
            "powershell",
            $"-Command \"(Get-LocalUser '{username}' | Get-LocalGroup).Name\""
        );

        if (success && !string.IsNullOrEmpty(output))
        {
            groups = output
                .Split(new[] { '\r', '\n' }, StringSplitOptions.RemoveEmptyEntries)
                .ToList();
        }

        return groups;
    }

    private void DisplayAccountsTable(List<AccountInfo> accounts)
    {
        var table = new Table()
            .Border(TableBorder.Rounded)
            .AddColumn("Username")
            .AddColumn("Enabled")
            .AddColumn("Admin")
            .AddColumn("Password Required")
            .AddColumn("Password Expires")
            .AddColumn("Status");

        foreach (var account in accounts)
        {
            var status = GetAccountStatus(account);
            var statusColor = status == "OK" ? "green" : "red";

            table.AddRow(
                account.Username,
                account.IsEnabled ? "[green]Yes[/]" : "[dim]No[/]",
                account.IsAdmin ? "[yellow]Yes[/]" : "No",
                account.PasswordRequired ? "[green]Yes[/]" : "[red]No[/]",
                account.PasswordNeverExpires ? "[red]Never[/]" : "[green]Yes[/]",
                $"[{statusColor}]{status}[/]"
            );
        }

        AnsiConsole.Write(table);
    }

    private string GetAccountStatus(AccountInfo account)
    {
        var issues = new List<string>();

        // Check Guest account
        if (
            account.Username.Equals("Guest", StringComparison.OrdinalIgnoreCase)
            && account.IsEnabled
        )
            issues.Add("Guest enabled");

        // Check password required
        if (account.IsEnabled && !account.PasswordRequired)
            issues.Add("No password");

        // Check password never expires (exclude system accounts)
        if (
            account.IsEnabled
            && account.PasswordNeverExpires
            && !AccountSecurityStandards.InsecureUsernames.Contains(
                account.Username,
                StringComparer.OrdinalIgnoreCase
            )
        )
            issues.Add("Password never expires");

        return issues.Count > 0 ? string.Join(", ", issues) : "OK";
    }

    private async Task<(List<string> Fixes, List<string> Issues)> CheckGuestAccountAsync()
    {
        var fixes = new List<string>();
        var issues = new List<string>();

        var guest = _accounts.FirstOrDefault(a =>
            a.Username.Equals("Guest", StringComparison.OrdinalIgnoreCase)
        );

        if (guest != null && guest.IsEnabled)
        {
            AnsiConsole.MarkupLine("[yellow]Disabling Guest account...[/]");
            var (success, _, error) = await CommandExecutor.ExecuteAsync(
                "net",
                "user Guest /active:no"
            );

            if (success)
            {
                fixes.Add("Disabled Guest account");
                AnsiConsole.MarkupLine("[green]? Guest account disabled[/]");
            }
            else
            {
                issues.Add($"Failed to disable Guest account: {error}");
                AnsiConsole.MarkupLine($"[red]? Failed to disable Guest account: {error}[/]");
            }
        }
        else
        {
            AnsiConsole.MarkupLine("[green]? Guest account is already disabled[/]");
        }

        return (fixes, issues);
    }

    private Task<(List<string> Fixes, List<string> Issues)> EnforcePasswordRequiredAsync()
    {
        var fixes = new List<string>();
        var issues = new List<string>();

        var accountsWithoutPassword = _accounts
            .Where(a =>
                a.IsEnabled
                && !a.PasswordRequired
                && !AccountSecurityStandards.InsecureUsernames.Contains(
                    a.Username,
                    StringComparer.OrdinalIgnoreCase
                )
            )
            .ToList();

        foreach (var account in accountsWithoutPassword)
        {
            AnsiConsole.MarkupLine(
                $"[yellow]Enforcing password requirement for {account.Username}...[/]"
            );

            // Can't directly force password required, but we can flag it
            issues.Add(
                $"Account '{account.Username}' does not require a password - manual password set required"
            );
            AnsiConsole.MarkupLine(
                $"[yellow]? Account '{account.Username}' needs a password set manually[/]"
            );
        }

        if (accountsWithoutPassword.Count == 0)
        {
            AnsiConsole.MarkupLine("[green]? All enabled accounts require passwords[/]");
        }

        return Task.FromResult((fixes, issues));
    }

    private async Task<(List<string> Fixes, List<string> Issues)> CheckPasswordExpirationAsync()
    {
        var fixes = new List<string>();
        var issues = new List<string>();

        var neverExpires = _accounts
            .Where(a =>
                a.IsEnabled
                && a.PasswordNeverExpires
                && !AccountSecurityStandards.InsecureUsernames.Contains(
                    a.Username,
                    StringComparer.OrdinalIgnoreCase
                )
                && !a.Username.Equals("Administrator", StringComparison.OrdinalIgnoreCase)
            ) // Admin might need special handling
            .ToList();

        foreach (var account in neverExpires)
        {
            AnsiConsole.MarkupLine(
                $"[yellow]Enabling password expiration for {account.Username}...[/]"
            );

            var (success, _, error) = await CommandExecutor.ExecuteAsync(
                "powershell",
                $"-Command \"Set-LocalUser -Name '{account.Username}' -PasswordNeverExpires $false\""
            );

            if (success)
            {
                fixes.Add($"Enabled password expiration for {account.Username}");
                AnsiConsole.MarkupLine(
                    $"[green]? Password expiration enabled for {account.Username}[/]"
                );
            }
            else
            {
                issues.Add($"Failed to enable password expiration for {account.Username}: {error}");
                AnsiConsole.MarkupLine(
                    $"[red]? Failed to enable password expiration for {account.Username}[/]"
                );
            }
        }

        if (neverExpires.Count == 0)
        {
            AnsiConsole.MarkupLine(
                "[green]? All user accounts have password expiration enabled[/]"
            );
        }

        return (fixes, issues);
    }

    private Task<(List<string> Fixes, List<string> Issues)> ReviewAdminAccountsAsync()
    {
        var fixes = new List<string>();
        var issues = new List<string>();

        var adminAccounts = _accounts.Where(a => a.IsAdmin && a.IsEnabled).ToList();

        AnsiConsole.MarkupLine($"[bold]Found {adminAccounts.Count} administrator account(s):[/]");

        foreach (var admin in adminAccounts)
        {
            if (admin.Username.Equals("Administrator", StringComparison.OrdinalIgnoreCase))
            {
                // Recommend renaming the default Administrator account
                issues.Add("Default Administrator account should be renamed for security");
                AnsiConsole.MarkupLine(
                    $"[yellow]? Consider renaming default Administrator account[/]"
                );
            }
            else
            {
                AnsiConsole.MarkupLine($"  - {admin.Username}");
            }
        }

        // Log for review
        if (adminAccounts.Count > 2)
        {
            issues.Add(
                $"Review required: {adminAccounts.Count} admin accounts exist - ensure all are necessary"
            );
            AnsiConsole.MarkupLine(
                $"[yellow]? Consider reviewing admin accounts - {adminAccounts.Count} accounts have admin privileges[/]"
            );
        }

        return Task.FromResult((fixes, issues));
    }

    private Task<(List<string> Fixes, List<string> Issues)> CheckInactiveAccountsAsync()
    {
        var fixes = new List<string>();
        var issues = new List<string>();

        var cutoffDate = DateTime.Now.AddDays(-AccountSecurityStandards.MaxInactiveDays);

        var inactiveAccounts = _accounts
            .Where(a =>
                a.IsEnabled
                && a.LastLogon.HasValue
                && a.LastLogon.Value < cutoffDate
                && !AccountSecurityStandards.InsecureUsernames.Contains(
                    a.Username,
                    StringComparer.OrdinalIgnoreCase
                )
            )
            .ToList();

        foreach (var account in inactiveAccounts)
        {
            var daysSinceLogon = (DateTime.Now - account.LastLogon!.Value).Days;
            issues.Add(
                $"Account '{account.Username}' inactive for {daysSinceLogon} days - consider disabling"
            );
            AnsiConsole.MarkupLine(
                $"[yellow]? Account '{account.Username}' has been inactive for {daysSinceLogon} days[/]"
            );
        }

        if (inactiveAccounts.Count == 0)
        {
            AnsiConsole.MarkupLine("[green]? No inactive accounts detected[/]");
        }

        return Task.FromResult((fixes, issues));
    }
}
