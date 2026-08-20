using CyberPatriotAutomation.Core.Models;
using CyberPatriotAutomation.Core.Utilities;
using Spectre.Console;

namespace CyberPatriotAutomation.Core.Tasks;

/// <summary>
/// Task to manage user accounts based on README requirements
/// - Update insecure passwords
/// - Delete unauthorized users
/// - Fix admin/user permissions
/// - Create new required users
/// </summary>
public class UserManagementTask : BaseTask
{
    private ReadmeData? _readmeData;
    private List<AccountInfo> _currentAccounts = new();

    /// <summary>
    /// Secure passwords to use when resetting insecure passwords
    /// These meet strict complexity requirements: 24+ chars, upper, lower, digit, special, no dictionary words, no username, no repeats, no sequences
    /// </summary>
    private static readonly string[] SecurePasswords = new[]
    {
        "A9!vX2#rT7$wQ4@eLp6^zM8&bN0Yj5uH3sK1oF",
        "Zx7!Qw2@Er5#Ty8$Ui3%Op6^As9&Df0Gh4(Jk1)L",
        "P0!lK9@mJ8#hG7$fD6%sA5^qW4&eR3tT2(yU1)iO",
        "Vb6!Nn5@Mm4#Ll3$Kk2%Jj1^Hh0&Gg9Ff8(Dd7)S",
        "C3!vB2@nM1#bN0$mL9%kJ8^hG7&fD6sA5(qW4)E",
        "R4!tY3@uI2#oP1$pA0%sD9^fG8&hJ7kL6(lZ5)X",
        "W5!eR4@tT3#yU2$uI1%oP0^aS9&dF8gH7(jK6)L",
        "Q6!wE5@rT4#yU3$uI2%oP1^aS0&dF9gH8(jK7)L",
        "M7!nB6@vC5#xZ4$cV3%bN2^mL1&kJ0hG9(fD8)S",
        "S8!dF7@gH6#jK5$lZ4%xC3^vB2&nM1bN0(mL9)K",
    };

    public UserManagementTask()
    {
        Name = "User Account Management";
        Description = "Manage users, passwords, and permissions based on README requirements";
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

        AnsiConsole.MarkupLine("[cyan]Reading current user accounts...[/]");
        _currentAccounts = await GetAllUserAccountsAsync();

        foreach (var account in _currentAccounts)
        {
            var info =
                $"{account.Username} (Admin: {account.IsAdmin}, Enabled: {account.IsEnabled})";
            systemInfo.UserAccounts.Add(info);
        }

        // Display current state
        DisplayCurrentAccounts();

        return systemInfo;
    }

    public override async Task<TaskResult> ExecuteAsync()
    {
        var result = new TaskResult
        {
            TaskName = Name,
            Success = true,
            Message = "User management completed",
        };

        if (_readmeData == null)
        {
            result.Success = false;
            result.Message = "No README data provided. Please parse a README file first.";
            result.ErrorDetails = "Use --readme flag to specify a README file";
            return result;
        }

        if (DryRun)
        {
            AnsiConsole.MarkupLine(
                "[yellow]DRY RUN: Previewing user management changes (no changes will be made)[/]"
            );
            AnsiConsole.MarkupLine(
                $"[cyan]Authorized admins: {_readmeData.Administrators.Count}[/]"
            );
            AnsiConsole.MarkupLine($"[cyan]Authorized users: {_readmeData.Users.Count}[/]");
            AnsiConsole.MarkupLine($"[cyan]Users to create: {_readmeData.UsersToCreate.Count}[/]");
            result.Message = "DRY RUN: User management changes previewed.";
            return result;
        }

        var fixes = new List<string>();
        var issues = new List<string>();

        try
        {
            // Build lists of authorized users
            var authorizedAdmins = _readmeData
                .Administrators.Select(a => a.Username)
                .ToHashSet(StringComparer.OrdinalIgnoreCase);
            var authorizedUsers = _readmeData
                .Users.Select(u => u.Username)
                .ToHashSet(StringComparer.OrdinalIgnoreCase);
            var usersToCreate = _readmeData.UsersToCreate.ToHashSet(
                StringComparer.OrdinalIgnoreCase
            );

            // Combine all authorized usernames
            var allAuthorized = new HashSet<string>(
                authorizedAdmins,
                StringComparer.OrdinalIgnoreCase
            );
            foreach (var user in authorizedUsers)
                allAuthorized.Add(user);
            foreach (var user in usersToCreate)
                allAuthorized.Add(user);

            // System accounts that should never be modified
            var systemAccounts = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
            {
                "Administrator",
                "DefaultAccount",
                "WDAGUtilityAccount",
                "SYSTEM",
                "LocalService",
                "NetworkService",
                "Guest",
            };

            AnsiConsole.WriteLine();
            AnsiConsole.Write(
                new Rule("[bold yellow]Step 1: Delete Unauthorized Users[/]").RuleStyle("yellow")
            );
            var deleteResults = await DeleteUnauthorizedUsersAsync(allAuthorized, systemAccounts);
            fixes.AddRange(deleteResults.Fixes);
            issues.AddRange(deleteResults.Issues);

            AnsiConsole.WriteLine();
            AnsiConsole.Write(
                new Rule("[bold yellow]Step 2: Fix User Permissions[/]").RuleStyle("yellow")
            );
            var permResults = await FixUserPermissionsAsync(authorizedAdmins, systemAccounts);
            fixes.AddRange(permResults.Fixes);
            issues.AddRange(permResults.Issues);

            AnsiConsole.WriteLine();
            AnsiConsole.Write(
                new Rule("[bold yellow]Step 3: Update Insecure Passwords[/]").RuleStyle("yellow")
            );
            var passwordResults = await UpdateInsecurePasswordsAsync(authorizedUsers);
            fixes.AddRange(passwordResults.Fixes);
            issues.AddRange(passwordResults.Issues);

            AnsiConsole.WriteLine();
            AnsiConsole.Write(
                new Rule("[bold yellow]Step 4: Create New Users[/]").RuleStyle("yellow")
            );
            var createResults = await CreateNewUsersAsync(usersToCreate, authorizedAdmins);
            fixes.AddRange(createResults.Fixes);
            issues.AddRange(createResults.Issues);

            AnsiConsole.WriteLine();
            AnsiConsole.Write(
                new Rule("[bold yellow]Step 5: Configure Groups[/]").RuleStyle("yellow")
            );
            var groupResults = await ConfigureGroupsAsync();
            fixes.AddRange(groupResults.Fixes);
            issues.AddRange(groupResults.Issues);

            // Summary
            if (issues.Count > 0)
            {
                result.Message =
                    $"Applied {fixes.Count} changes. {issues.Count} issues require attention.";
                result.ErrorDetails = string.Join("\n", issues);
            }
            else
            {
                result.Message = $"Successfully applied {fixes.Count} user management changes.";
            }
        }
        catch (Exception ex)
        {
            result.Success = false;
            result.Message = "Failed to complete user management";
            result.ErrorDetails = ex.Message;
            AnsiConsole.WriteException(ex);
        }

        return result;
    }

    public override async Task<bool> VerifyAsync()
    {
        if (_readmeData == null)
            return false;

        var accounts = await GetAllUserAccountsAsync();
        var authorizedAdmins = _readmeData
            .Administrators.Select(a => a.Username)
            .ToHashSet(StringComparer.OrdinalIgnoreCase);
        var authorizedUsers = _readmeData
            .Users.Select(u => u.Username)
            .ToHashSet(StringComparer.OrdinalIgnoreCase);
        var usersToCreate = _readmeData.UsersToCreate.ToHashSet(StringComparer.OrdinalIgnoreCase);

        // Combine all authorized usernames for existence check
        var allAuthorized = new HashSet<string>(authorizedAdmins, StringComparer.OrdinalIgnoreCase);
        foreach (var user in authorizedUsers)
            allAuthorized.Add(user);

        bool allGood = true;

        // Check all required users exist
        foreach (var username in usersToCreate)
        {
            if (!accounts.Any(a => a.Username.Equals(username, StringComparison.OrdinalIgnoreCase)))
            {
                AnsiConsole.MarkupLine($"[red]? Required user '{username}' not found[/]");
                allGood = false;
            }
        }

        // Check admin permissions
        foreach (var account in accounts.Where(a => a.IsEnabled))
        {
            bool shouldBeAdmin = authorizedAdmins.Contains(account.Username);
            if (account.IsAdmin != shouldBeAdmin && !IsSystemAccount(account.Username))
            {
                var expected = shouldBeAdmin ? "admin" : "standard user";
                AnsiConsole.MarkupLine($"[red]? User '{account.Username}' should be {expected}[/]");
                allGood = false;
            }
        }

        if (allGood)
        {
            AnsiConsole.MarkupLine("[green]? All user accounts verified[/]");
        }

        return allGood;
    }

    #region Helper Methods

    private async Task<List<AccountInfo>> GetAllUserAccountsAsync()
    {
        var accounts = new List<AccountInfo>();

        var (success, output, _) = await CommandExecutor.PowerShellQueryAsync(
            "Get-LocalUser | Select-Object Name, FullName, Enabled, Description | ConvertTo-Csv -NoTypeInformation"
        );

        if (success && !string.IsNullOrEmpty(output))
        {
            var lines = output.Split(new[] { '\r', '\n' }, StringSplitOptions.RemoveEmptyEntries);

            // Read the Administrators membership once rather than shelling out
            // per account, and match names exactly.
            var admins = await LocalAccounts.GetGroupMembersAsync("Administrators");

            foreach (var line in lines.Skip(1))
            {
                var account = ParseAccountLine(line);
                if (account != null)
                {
                    account.IsAdmin = LocalAccounts.IsGroupMember(admins, account.Username);
                    accounts.Add(account);
                }
            }
        }

        return accounts;
    }

    private AccountInfo? ParseAccountLine(string csvLine)
    {
        try
        {
            var values = ParseCsvLine(csvLine);
            if (values.Count < 3)
                return null;

            return new AccountInfo
            {
                Username = values[0].Trim('"'),
                FullName = values.Count > 1 ? values[1].Trim('"') : "",
                IsEnabled =
                    values.Count > 2
                    && values[2].Trim('"').Equals("True", StringComparison.OrdinalIgnoreCase),
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

    private bool IsSystemAccount(string username)
    {
        var systemAccounts = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
        {
            "Administrator",
            "DefaultAccount",
            "WDAGUtilityAccount",
            "SYSTEM",
            "LocalService",
            "NetworkService",
            "Guest",
        };
        return systemAccounts.Contains(username);
    }

    private void DisplayCurrentAccounts()
    {
        var table = new Table()
            .Border(TableBorder.Rounded)
            .BorderColor(Color.Grey)
            .Title("[bold]Current User Accounts[/]")
            .AddColumn("[bold]Username[/]")
            .AddColumn("[bold]Enabled[/]")
            .AddColumn("[bold]Admin[/]");

        foreach (var account in _currentAccounts)
        {
            table.AddRow(
                account.Username,
                account.IsEnabled ? "[green]Yes[/]" : "[dim]No[/]",
                account.IsAdmin ? "[yellow]Yes[/]" : "[dim]No[/]"
            );
        }

        AnsiConsole.Write(table);
    }

    #endregion

    #region Step 1: Delete Unauthorized Users

    private async Task<(List<string> Fixes, List<string> Issues)> DeleteUnauthorizedUsersAsync(
        HashSet<string> allAuthorized,
        HashSet<string> systemAccounts
    )
    {
        var fixes = new List<string>();
        var issues = new List<string>();

        // An empty authorised set means the README did not parse, not that every
        // account on the machine is unauthorised. Without this guard a parsing
        // failure deletes every enabled non-system account - a real README always
        // names at least one administrator.
        if (allAuthorized.Count == 0)
        {
            var message =
                "Refusing to delete any users: the README produced no authorized accounts. "
                + "Check that the correct README was parsed before running user management.";
            issues.Add(message);
            AnsiConsole.MarkupLine($"[red]{Markup.Escape(message)}[/]");
            return (fixes, issues);
        }

        var unauthorizedUsers = _currentAccounts
            .Where(a =>
                a.IsEnabled
                && !allAuthorized.Contains(a.Username)
                && !systemAccounts.Contains(a.Username)
            )
            .ToList();

        if (unauthorizedUsers.Count == 0)
        {
            AnsiConsole.MarkupLine("[green]? No unauthorized users found[/]");
            return (fixes, issues);
        }

        AnsiConsole.MarkupLine($"[yellow]Found {unauthorizedUsers.Count} unauthorized user(s):[/]");

        var table = new Table()
            .Border(TableBorder.Rounded)
            .BorderColor(Color.Red)
            .AddColumn("[bold]Username[/]")
            .AddColumn("[bold]Action[/]");

        foreach (var user in unauthorizedUsers)
        {
            table.AddRow($"[red]{user.Username}[/]", "Will be deleted");
        }
        AnsiConsole.Write(table);
        AnsiConsole.WriteLine();

        foreach (var user in unauthorizedUsers)
        {
            AnsiConsole.MarkupLine($"[yellow]Deleting user: {user.Username}...[/]");

            var (success, _, error) = await CommandExecutor.ExecuteAsync(
                "net",
                $"user \"{user.Username}\" /delete"
            );

            if (success)
            {
                fixes.Add($"Deleted unauthorized user: {user.Username}");
                AnsiConsole.MarkupLine($"[green]? Deleted user: {user.Username}[/]");
            }
            else
            {
                issues.Add($"Failed to delete user {user.Username}: {error}");
                AnsiConsole.MarkupLine($"[red]? Failed to delete {user.Username}: {error}[/]");
            }
        }

        return (fixes, issues);
    }

    #endregion

    #region Step 2: Fix User Permissions

    private async Task<(List<string> Fixes, List<string> Issues)> FixUserPermissionsAsync(
        HashSet<string> authorizedAdmins,
        HashSet<string> systemAccounts
    )
    {
        var fixes = new List<string>();
        var issues = new List<string>();

        // Refresh account list
        _currentAccounts = await GetAllUserAccountsAsync();

        foreach (
            var account in _currentAccounts.Where(a =>
                a.IsEnabled && !systemAccounts.Contains(a.Username)
            )
        )
        {
            bool shouldBeAdmin = authorizedAdmins.Contains(account.Username);
            bool isCurrentlyAdmin = account.IsAdmin;

            if (shouldBeAdmin && !isCurrentlyAdmin)
            {
                // Should be admin but isn't - add to Administrators group
                AnsiConsole.MarkupLine(
                    $"[yellow]Adding {account.Username} to Administrators group...[/]"
                );

                var failure = await LocalAccounts.AddToGroupAsync(
                    account.Username,
                    "Administrators"
                );

                if (failure == null)
                {
                    fixes.Add($"Added {account.Username} to Administrators group");
                    AnsiConsole.MarkupLine(
                        $"[green]? {Markup.Escape(account.Username)} is now an administrator[/]"
                    );
                }
                else
                {
                    issues.Add($"Failed to add {account.Username} to Administrators: {failure}");
                    AnsiConsole.MarkupLine(
                        $"[red]? Failed to add {Markup.Escape(account.Username)} to Administrators[/]"
                    );
                }
            }
            else if (!shouldBeAdmin && isCurrentlyAdmin)
            {
                // Is admin but shouldn't be - remove from Administrators group
                AnsiConsole.MarkupLine(
                    $"[yellow]Removing {account.Username} from Administrators group...[/]"
                );

                var failure = await LocalAccounts.RemoveFromGroupAsync(
                    account.Username,
                    "Administrators"
                );

                if (failure == null)
                {
                    fixes.Add($"Removed {account.Username} from Administrators group");
                    AnsiConsole.MarkupLine(
                        $"[green]? {Markup.Escape(account.Username)} is no longer an administrator[/]"
                    );
                }
                else
                {
                    issues.Add(
                        $"Failed to remove {account.Username} from Administrators: {failure}"
                    );
                    AnsiConsole.MarkupLine(
                        $"[red]? Failed to remove {Markup.Escape(account.Username)} from Administrators[/]"
                    );
                }
            }
            else
            {
                var role = shouldBeAdmin ? "administrator" : "standard user";
                AnsiConsole.MarkupLine(
                    $"[dim]? {account.Username} has correct permissions ({role})[/]"
                );
            }
        }

        return (fixes, issues);
    }

    #endregion

    #region Step 3: Update Insecure Passwords

    private async Task<(List<string> Fixes, List<string> Issues)> UpdateInsecurePasswordsAsync(
        HashSet<string> authorizedUsers
    )
    {
        var fixes = new List<string>();
        var issues = new List<string>();

        // Accounts the README marks as the primary, auto-login user. READMEs
        // state plainly that changing this password may lock you out of the
        // machine, so it is left alone.
        var primaryUsers = LocalAccounts.PrimaryUsers(_readmeData);

        var readmeAdmins = new HashSet<string>(
            _readmeData?.Administrators.Select(a => a.Username) ?? Enumerable.Empty<string>(),
            StringComparer.OrdinalIgnoreCase
        );

        // Refresh account list
        _currentAccounts = await GetAllUserAccountsAsync();

        int passwordIndex = 0;

        // Every account gets a freshly generated strong password, administrators
        // included. The README lists the passwords an audit *found*, not
        // passwords that must be kept - several are trivial ("root", "data"), and
        // setting those would both weaken the machine and be rejected outright by
        // the complexity and length policy this run enforces moments earlier,
        // which is why every password change failed.
        foreach (
            var account in _currentAccounts.Where(a => a.IsEnabled && !IsSystemAccount(a.Username))
        )
        {
            var isAuthorized =
                authorizedUsers.Contains(account.Username)
                || account.IsAdmin
                || readmeAdmins.Contains(account.Username);
            if (!isAuthorized)
                continue;

            if (primaryUsers.Contains(account.Username))
            {
                AnsiConsole.MarkupLine(
                    $"[dim]? Skipping {Markup.Escape(account.Username)} - primary auto-login account "
                        + "(changing it risks lockout)[/]"
                );
                continue;
            }

            var password = LocalAccounts.GeneratePassword(passwordIndex);
            passwordIndex++;

            AnsiConsole.MarkupLine(
                $"[yellow]Setting secure password for {Markup.Escape(account.Username)}...[/]"
            );

            var failure = await LocalAccounts.SetPasswordAsync(account.Username, password);
            if (failure == null)
            {
                // Record the password: it is the only way back into the account,
                // and the log stays on the competitor's own machine.
                fixes.Add($"Set secure password for {account.Username}: {password}");
                AnsiConsole.MarkupLine(
                    $"[green]? {Markup.Escape(account.Username)} password set to: {Markup.Escape(password)}[/]"
                );
            }
            else
            {
                issues.Add($"Failed to set password for {account.Username}: {failure}");
                AnsiConsole.MarkupLine(
                    $"[red]? Failed to set password for {Markup.Escape(account.Username)}: "
                        + $"{Markup.Escape(failure)}[/]"
                );
            }
        }

        // Ensure all accounts require password
        AnsiConsole.WriteLine();
        AnsiConsole.MarkupLine("[cyan]Ensuring all accounts require passwords...[/]");

        foreach (
            var account in _currentAccounts.Where(a => a.IsEnabled && !IsSystemAccount(a.Username))
        )
        {
            // Set password to never expire = false, and password required
            var (success, _, error) = await CommandExecutor.PowerShellAsync(
                $"Set-LocalUser -Name {CommandExecutor.PsQuote(account.Username)} -PasswordNeverExpires $false"
            );

            if (success)
            {
                AnsiConsole.MarkupLine(
                    $"[dim]? Password expiration enabled for {Markup.Escape(account.Username)}[/]"
                );
            }
            else
            {
                issues.Add($"Failed to enable password expiration for {account.Username}: {error}");
            }
        }

        return (fixes, issues);
    }

    #endregion

    #region Step 4: Create New Users

    private async Task<(List<string> Fixes, List<string> Issues)> CreateNewUsersAsync(
        HashSet<string> usersToCreate,
        HashSet<string> authorizedAdmins
    )
    {
        var fixes = new List<string>();
        var issues = new List<string>();

        if (usersToCreate.Count == 0)
        {
            AnsiConsole.MarkupLine("[green]? No new users need to be created[/]");
            return (fixes, issues);
        }

        // Refresh account list
        _currentAccounts = await GetAllUserAccountsAsync();
        var existingUsers = _currentAccounts
            .Select(a => a.Username)
            .ToHashSet(StringComparer.OrdinalIgnoreCase);

        int passwordIndex = 0;

        foreach (var username in usersToCreate)
        {
            if (existingUsers.Contains(username))
            {
                AnsiConsole.MarkupLine($"[dim]? User {username} already exists[/]");
                continue;
            }

            // Generate a secure password
            var password = LocalAccounts.GeneratePassword(passwordIndex);
            passwordIndex++;

            AnsiConsole.MarkupLine($"[yellow]Creating new user: {Markup.Escape(username)}...[/]");

            var failure = await LocalAccounts.CreateUserAsync(username, password);

            if (failure == null)
            {
                fixes.Add($"Created new user {username} with password: {password}");
                AnsiConsole.MarkupLine(
                    $"[green]? Created user {Markup.Escape(username)} with password: "
                        + $"{Markup.Escape(password)}[/]"
                );

                // If this user should be an admin, add them to Administrators
                if (authorizedAdmins.Contains(username))
                {
                    var adminFailure = await LocalAccounts.AddToGroupAsync(
                        username,
                        "Administrators"
                    );

                    if (adminFailure == null)
                    {
                        fixes.Add($"Added {username} to Administrators");
                        AnsiConsole.MarkupLine(
                            $"[green]? Added {Markup.Escape(username)} to Administrators group[/]"
                        );
                    }
                    else
                    {
                        issues.Add($"Failed to add {username} to Administrators: {adminFailure}");
                        AnsiConsole.MarkupLine(
                            $"[red]? Failed to add {Markup.Escape(username)} to Administrators: "
                                + $"{Markup.Escape(adminFailure)}[/]"
                        );
                    }
                }
            }
            else
            {
                issues.Add($"Failed to create user {username}: {failure}");
                AnsiConsole.MarkupLine(
                    $"[red]? Failed to create user {Markup.Escape(username)}: "
                        + $"{Markup.Escape(failure)}[/]"
                );
            }
        }

        return (fixes, issues);
    }

    #endregion

    #region Step 5: Configure Groups

    private async Task<(List<string> Fixes, List<string> Issues)> ConfigureGroupsAsync()
    {
        var fixes = new List<string>();
        var issues = new List<string>();

        if (_readmeData?.GroupRequirements == null || _readmeData.GroupRequirements.Count == 0)
        {
            AnsiConsole.MarkupLine("[green]? No group requirements specified[/]");
            return (fixes, issues);
        }

        foreach (var groupReq in _readmeData.GroupRequirements)
        {
            AnsiConsole.MarkupLine($"[cyan]Configuring group: {groupReq.GroupName}[/]");

            // Check if group exists
            var (checkSuccess, checkOutput, _) = await CommandExecutor.ExecuteAsync(
                "net",
                $"localgroup \"{groupReq.GroupName}\""
            );

            if (!checkSuccess || checkOutput.Contains("does not exist"))
            {
                // Create the group
                AnsiConsole.MarkupLine($"[yellow]Creating group: {groupReq.GroupName}...[/]");
                var (createSuccess, _, createError) = await CommandExecutor.ExecuteAsync(
                    "net",
                    $"localgroup \"{groupReq.GroupName}\" /add"
                );

                if (createSuccess)
                {
                    fixes.Add($"Created group: {groupReq.GroupName}");
                    AnsiConsole.MarkupLine($"[green]? Created group: {groupReq.GroupName}[/]");
                }
                else
                {
                    issues.Add($"Failed to create group {groupReq.GroupName}: {createError}");
                    AnsiConsole.MarkupLine(
                        $"[red]? Failed to create group: {groupReq.GroupName}[/]"
                    );
                    continue;
                }
            }
            else
            {
                AnsiConsole.MarkupLine($"[dim]Group {groupReq.GroupName} already exists[/]");
            }

            // Add members to the group
            foreach (var member in groupReq.Members)
            {
                var (addSuccess, _, addError) = await CommandExecutor.ExecuteAsync(
                    "net",
                    $"localgroup \"{groupReq.GroupName}\" \"{member}\" /add"
                );

                if (addSuccess)
                {
                    fixes.Add($"Added {member} to group {groupReq.GroupName}");
                    AnsiConsole.MarkupLine($"[green]? Added {member} to {groupReq.GroupName}[/]");
                }
                else if (addError?.Contains("already a member") == true)
                {
                    AnsiConsole.MarkupLine($"[dim]{member} is already in {groupReq.GroupName}[/]");
                }
                else
                {
                    issues.Add($"Failed to add {member} to {groupReq.GroupName}: {addError}");
                    AnsiConsole.MarkupLine(
                        $"[red]? Failed to add {member} to {groupReq.GroupName}[/]"
                    );
                }
            }
        }

        return (fixes, issues);
    }

    #endregion
}
