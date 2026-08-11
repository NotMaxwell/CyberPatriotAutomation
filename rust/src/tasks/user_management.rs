//! Manage user accounts based on README requirements.

use crate::command;
use crate::impl_task_meta;
use crate::models::{AccountInfo, ReadmeData, SystemInfo, TaskResult};
use crate::tasks::Task;
use crate::ui;
use async_trait::async_trait;
use std::collections::HashSet;

/// Secure passwords to use when resetting insecure passwords.
const SECURE_PASSWORDS: &[&str] = &[
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
];

/// Case-insensitive set built from an iterator of strings.
fn ci_set<'a, I: IntoIterator<Item = &'a String>>(items: I) -> HashSet<String> {
    items.into_iter().map(|s| s.to_lowercase()).collect()
}

fn ci_contains(set: &HashSet<String>, value: &str) -> bool {
    set.contains(&value.to_lowercase())
}

pub struct UserManagementTask {
    name: String,
    description: String,
    dry_run: bool,
    readme_data: Option<ReadmeData>,
    current_accounts: Vec<AccountInfo>,
}

impl UserManagementTask {
    pub fn new() -> Self {
        Self {
            name: "User Account Management".to_string(),
            description: "Manage users, passwords, and permissions based on README requirements".to_string(),
            dry_run: false,
            readme_data: None,
            current_accounts: Vec::new(),
        }
    }

    pub fn set_readme_data(&mut self, data: ReadmeData) {
        self.readme_data = Some(data);
    }

    async fn get_all_user_accounts() -> Vec<AccountInfo> {
        let mut accounts = Vec::new();
        let (success, output, _e) = command::execute(
            "powershell",
            Some("-Command \"Get-LocalUser | Select-Object Name, FullName, Enabled, Description | ConvertTo-Csv -NoTypeInformation\""),
        )
        .await;

        if success && !output.is_empty() {
            for line in output.split(['\r', '\n']).filter(|l| !l.is_empty()).skip(1) {
                if let Some(mut account) = parse_account_line(line) {
                    account.is_admin = is_user_admin(&account.username).await;
                    accounts.push(account);
                }
            }
        }
        accounts
    }

    fn is_system_account(username: &str) -> bool {
        const SYSTEM: &[&str] = &[
            "Administrator",
            "DefaultAccount",
            "WDAGUtilityAccount",
            "SYSTEM",
            "LocalService",
            "NetworkService",
            "Guest",
        ];
        SYSTEM.iter().any(|s| s.eq_ignore_ascii_case(username))
    }

    fn display_current_accounts(&self) {
        let mut table = ui::TableBuilder::new()
            .title("[bold]Current User Accounts[/]")
            .columns(&["[bold]Username[/]", "[bold]Enabled[/]", "[bold]Admin[/]"]);
        for account in &self.current_accounts {
            table.add_row([
                account.username.clone(),
                if account.is_enabled { "[green]Yes[/]" } else { "[dim]No[/]" }.to_string(),
                if account.is_admin { "[yellow]Yes[/]" } else { "[dim]No[/]" }.to_string(),
            ]);
        }
        table.print();
    }

    async fn delete_unauthorized_users(
        &self,
        all_authorized: &HashSet<String>,
        system_accounts: &HashSet<String>,
    ) -> (Vec<String>, Vec<String>) {
        let mut fixes = Vec::new();
        let mut issues = Vec::new();

        let unauthorized: Vec<AccountInfo> = self
            .current_accounts
            .iter()
            .filter(|a| {
                a.is_enabled
                    && !ci_contains(all_authorized, &a.username)
                    && !ci_contains(system_accounts, &a.username)
            })
            .cloned()
            .collect();

        if unauthorized.is_empty() {
            ui::markup_line("[green]? No unauthorized users found[/]");
            return (fixes, issues);
        }

        ui::markup_line(&format!("[yellow]Found {} unauthorized user(s):[/]", unauthorized.len()));
        let mut table = ui::TableBuilder::new().columns(&["[bold]Username[/]", "[bold]Action[/]"]);
        for user in &unauthorized {
            table.add_row([format!("[red]{}[/]", ui::escape(&user.username)), "Will be deleted".to_string()]);
        }
        table.print();
        ui::write_line();

        for user in &unauthorized {
            ui::markup_line(&format!("[yellow]Deleting user: {}...[/]", ui::escape(&user.username)));
            let (success, _o, error) =
                command::execute("net", Some(&format!("user \"{}\" /delete", user.username))).await;
            if success {
                fixes.push(format!("Deleted unauthorized user: {}", user.username));
                ui::markup_line(&format!("[green]? Deleted user: {}[/]", ui::escape(&user.username)));
            } else {
                let e = error.unwrap_or_default();
                issues.push(format!("Failed to delete user {}: {}", user.username, e));
                ui::markup_line(&format!("[red]? Failed to delete {}: {}[/]", ui::escape(&user.username), ui::escape(&e)));
            }
        }

        (fixes, issues)
    }

    async fn fix_user_permissions(
        &mut self,
        authorized_admins: &HashSet<String>,
        system_accounts: &HashSet<String>,
    ) -> (Vec<String>, Vec<String>) {
        let mut fixes = Vec::new();
        let mut issues = Vec::new();

        self.current_accounts = Self::get_all_user_accounts().await;

        let accounts: Vec<AccountInfo> = self
            .current_accounts
            .iter()
            .filter(|a| a.is_enabled && !ci_contains(system_accounts, &a.username))
            .cloned()
            .collect();

        for account in &accounts {
            let should_be_admin = ci_contains(authorized_admins, &account.username);
            let is_currently_admin = account.is_admin;

            if should_be_admin && !is_currently_admin {
                ui::markup_line(&format!("[yellow]Adding {} to Administrators group...[/]", ui::escape(&account.username)));
                let (success, _o, error) = command::execute(
                    "net",
                    Some(&format!("localgroup Administrators \"{}\" /add", account.username)),
                )
                .await;
                if success {
                    fixes.push(format!("Added {} to Administrators group", account.username));
                    ui::markup_line(&format!("[green]? {} is now an administrator[/]", ui::escape(&account.username)));
                } else if error.as_deref().map(|e| e.contains("already a member")).unwrap_or(false) {
                    ui::markup_line(&format!("[dim]{} is already in Administrators group[/]", ui::escape(&account.username)));
                } else {
                    issues.push(format!("Failed to add {} to Administrators: {}", account.username, error.unwrap_or_default()));
                    ui::markup_line(&format!("[red]? Failed to add {} to Administrators[/]", ui::escape(&account.username)));
                }
            } else if !should_be_admin && is_currently_admin {
                ui::markup_line(&format!("[yellow]Removing {} from Administrators group...[/]", ui::escape(&account.username)));
                let (success, _o, error) = command::execute(
                    "net",
                    Some(&format!("localgroup Administrators \"{}\" /delete", account.username)),
                )
                .await;
                if success {
                    fixes.push(format!("Removed {} from Administrators group", account.username));
                    ui::markup_line(&format!("[green]? {} is no longer an administrator[/]", ui::escape(&account.username)));
                } else {
                    issues.push(format!("Failed to remove {} from Administrators: {}", account.username, error.unwrap_or_default()));
                    ui::markup_line(&format!("[red]? Failed to remove {} from Administrators[/]", ui::escape(&account.username)));
                }
            } else {
                let role = if should_be_admin { "administrator" } else { "standard user" };
                ui::markup_line(&format!("[dim]? {} has correct permissions ({})[/]", ui::escape(&account.username), role));
            }
        }

        (fixes, issues)
    }

    async fn update_insecure_passwords(&mut self, authorized_users: &HashSet<String>) -> (Vec<String>, Vec<String>) {
        let mut fixes = Vec::new();
        let mut issues = Vec::new();

        let admin_passwords: Vec<(String, String)> = self
            .readme_data
            .as_ref()
            .map(|r| {
                r.administrators
                    .iter()
                    .filter(|a| a.password.as_deref().map(|p| !p.is_empty()).unwrap_or(false))
                    .map(|a| (a.username.clone(), a.password.clone().unwrap()))
                    .collect()
            })
            .unwrap_or_default();

        let admin_password_for = |username: &str| -> Option<String> {
            admin_passwords
                .iter()
                .find(|(u, _)| u.eq_ignore_ascii_case(username))
                .map(|(_, p)| p.clone())
        };

        self.current_accounts = Self::get_all_user_accounts().await;

        let mut password_index = 0usize;
        let accounts: Vec<AccountInfo> = self
            .current_accounts
            .iter()
            .filter(|a| a.is_enabled && !Self::is_system_account(&a.username))
            .cloned()
            .collect();

        for account in &accounts {
            if let Some(readme_password) = admin_password_for(&account.username) {
                ui::markup_line(&format!("[yellow]Setting password for admin {} (from README)...[/]", ui::escape(&account.username)));
                let (success, _o, error) = command::execute(
                    "net",
                    Some(&format!("user \"{}\" \"{}\"", account.username, readme_password)),
                )
                .await;
                if success {
                    fixes.push(format!("Set password for admin: {}", account.username));
                    ui::markup_line(&format!("[green]? Password set for {}[/]", ui::escape(&account.username)));
                } else {
                    issues.push(format!("Failed to set password for {}: {}", account.username, error.unwrap_or_default()));
                    ui::markup_line(&format!("[red]? Failed to set password for {}[/]", ui::escape(&account.username)));
                }
            } else if ci_contains(authorized_users, &account.username) {
                let secure_password = SECURE_PASSWORDS[password_index % SECURE_PASSWORDS.len()];
                password_index += 1;
                ui::markup_line(&format!("[yellow]Setting secure password for user {}...[/]", ui::escape(&account.username)));
                let (success, _o, error) = command::execute(
                    "net",
                    Some(&format!("user \"{}\" \"{}\"", account.username, secure_password)),
                )
                .await;
                if success {
                    fixes.push(format!("Set secure password for user: {}", account.username));
                    ui::markup_line(&format!("[green]? Secure password set for {}[/]", ui::escape(&account.username)));
                } else {
                    issues.push(format!("Failed to set password for {}: {}", account.username, error.unwrap_or_default()));
                    ui::markup_line(&format!("[red]? Failed to set password for {}[/]", ui::escape(&account.username)));
                }
            }
        }

        ui::write_line();
        ui::markup_line("[cyan]Ensuring all accounts require passwords...[/]");
        for account in &accounts {
            let (success, _o, _e) = command::execute(
                "powershell",
                Some(&format!("-Command \"Set-LocalUser -Name '{}' -PasswordNeverExpires $false\"", account.username)),
            )
            .await;
            if success {
                ui::markup_line(&format!("[dim]? Password expiration enabled for {}[/]", ui::escape(&account.username)));
            }
        }

        (fixes, issues)
    }

    async fn create_new_users(
        &mut self,
        users_to_create: &HashSet<String>,
        authorized_admins: &HashSet<String>,
    ) -> (Vec<String>, Vec<String>) {
        let mut fixes = Vec::new();
        let mut issues = Vec::new();

        if users_to_create.is_empty() {
            ui::markup_line("[green]? No new users need to be created[/]");
            return (fixes, issues);
        }

        self.current_accounts = Self::get_all_user_accounts().await;
        let existing = ci_set(self.current_accounts.iter().map(|a| &a.username));

        let mut password_index = 0usize;
        for username in users_to_create {
            if ci_contains(&existing, username) {
                ui::markup_line(&format!("[dim]? User {} already exists[/]", ui::escape(username)));
                continue;
            }

            let password = SECURE_PASSWORDS[password_index % SECURE_PASSWORDS.len()];
            password_index += 1;

            ui::markup_line(&format!("[yellow]Creating new user: {}...[/]", ui::escape(username)));
            let (success, output, error) =
                command::execute("net", Some(&format!("user \"{username}\" \"{password}\" /add"))).await;

            if success {
                fixes.push(format!("Created new user: {username}"));
                ui::markup_line(&format!("[green]? Created user: {}[/]", ui::escape(username)));

                if ci_contains(authorized_admins, username) {
                    let (admin_success, admin_output, admin_error) = command::execute(
                        "net",
                        Some(&format!("localgroup Administrators \"{username}\" /add")),
                    )
                    .await;
                    if admin_success {
                        fixes.push(format!("Added {username} to Administrators"));
                        ui::markup_line(&format!("[green]? Added {} to Administrators group[/]", ui::escape(username)));
                    } else {
                        let e = admin_error.unwrap_or_default();
                        issues.push(format!("Failed to add {username} to Administrators: {e}"));
                        ui::markup_line(&format!("[red]? Failed to add {} to Administrators: {}[/]", ui::escape(username), ui::escape(&e)));
                        if !admin_output.trim().is_empty() {
                            ui::markup_line(&format!("[red]Command output: {}[/]", ui::escape(&admin_output)));
                        }
                    }
                }
            } else {
                let e = error.unwrap_or_default();
                issues.push(format!("Failed to create user {username}: {e}"));
                ui::markup_line(&format!("[red]? Failed to create user {}: {}[/]", ui::escape(username), ui::escape(&e)));
                if !output.trim().is_empty() {
                    ui::markup_line(&format!("[red]Command output: {}[/]", ui::escape(&output)));
                }
            }
        }

        (fixes, issues)
    }

    async fn configure_groups(&self) -> (Vec<String>, Vec<String>) {
        let mut fixes = Vec::new();
        let mut issues = Vec::new();

        let group_requirements = self.readme_data.as_ref().map(|r| &r.group_requirements);
        if group_requirements.map(|g| g.is_empty()).unwrap_or(true) {
            ui::markup_line("[green]? No group requirements specified[/]");
            return (fixes, issues);
        }

        for group_req in group_requirements.unwrap() {
            ui::markup_line(&format!("[cyan]Configuring group: {}[/]", ui::escape(&group_req.group_name)));

            let (check_success, check_output, _e) =
                command::execute("net", Some(&format!("localgroup \"{}\"", group_req.group_name))).await;

            if !check_success || check_output.contains("does not exist") {
                ui::markup_line(&format!("[yellow]Creating group: {}...[/]", ui::escape(&group_req.group_name)));
                let (create_success, _o, create_error) =
                    command::execute("net", Some(&format!("localgroup \"{}\" /add", group_req.group_name))).await;
                if create_success {
                    fixes.push(format!("Created group: {}", group_req.group_name));
                    ui::markup_line(&format!("[green]? Created group: {}[/]", ui::escape(&group_req.group_name)));
                } else {
                    issues.push(format!("Failed to create group {}: {}", group_req.group_name, create_error.unwrap_or_default()));
                    ui::markup_line(&format!("[red]? Failed to create group: {}[/]", ui::escape(&group_req.group_name)));
                    continue;
                }
            } else {
                ui::markup_line(&format!("[dim]Group {} already exists[/]", ui::escape(&group_req.group_name)));
            }

            for member in &group_req.members {
                let (add_success, _o, add_error) = command::execute(
                    "net",
                    Some(&format!("localgroup \"{}\" \"{}\" /add", group_req.group_name, member)),
                )
                .await;
                if add_success {
                    fixes.push(format!("Added {} to group {}", member, group_req.group_name));
                    ui::markup_line(&format!("[green]? Added {} to {}[/]", ui::escape(member), ui::escape(&group_req.group_name)));
                } else if add_error.as_deref().map(|e| e.contains("already a member")).unwrap_or(false) {
                    ui::markup_line(&format!("[dim]{} is already in {}[/]", ui::escape(member), ui::escape(&group_req.group_name)));
                } else {
                    issues.push(format!("Failed to add {} to {}: {}", member, group_req.group_name, add_error.unwrap_or_default()));
                    ui::markup_line(&format!("[red]? Failed to add {} to {}[/]", ui::escape(member), ui::escape(&group_req.group_name)));
                }
            }
        }

        (fixes, issues)
    }
}

impl Default for UserManagementTask {
    fn default() -> Self {
        Self::new()
    }
}

fn parse_account_line(csv_line: &str) -> Option<AccountInfo> {
    let values = parse_csv_line(csv_line);
    if values.len() < 3 {
        return None;
    }
    let trim = |s: &str| s.trim_matches('"').to_string();
    Some(AccountInfo {
        username: trim(&values[0]),
        full_name: values.get(1).map(|v| trim(v)).unwrap_or_default(),
        is_enabled: values.get(2).map(|v| trim(v).eq_ignore_ascii_case("True")).unwrap_or(false),
        ..Default::default()
    })
}

fn parse_csv_line(line: &str) -> Vec<String> {
    let mut result = Vec::new();
    let mut in_quotes = false;
    let mut current = String::new();
    for c in line.chars() {
        match c {
            '"' => {
                in_quotes = !in_quotes;
                current.push(c);
            }
            ',' if !in_quotes => result.push(std::mem::take(&mut current)),
            _ => current.push(c),
        }
    }
    result.push(current);
    result
}

async fn is_user_admin(username: &str) -> bool {
    let (success, output, _e) = command::execute("net", Some("localgroup Administrators")).await;
    success && output.to_lowercase().contains(&username.to_lowercase())
}

#[async_trait]
impl Task for UserManagementTask {
    impl_task_meta!();

    async fn read_system_state(&mut self) -> SystemInfo {
        let mut system_info = SystemInfo::new();
        ui::markup_line("[cyan]Reading current user accounts...[/]");
        self.current_accounts = Self::get_all_user_accounts().await;
        for account in &self.current_accounts {
            system_info.user_accounts.push(format!(
                "{} (Admin: {}, Enabled: {})",
                account.username, account.is_admin, account.is_enabled
            ));
        }
        self.display_current_accounts();
        system_info
    }

    async fn execute(&mut self) -> TaskResult {
        let mut result = TaskResult {
            task_name: self.name.clone(),
            success: true,
            message: "User management completed".to_string(),
            ..Default::default()
        };

        if self.readme_data.is_none() {
            result.success = false;
            result.message = "No README data provided. Please parse a README file first.".to_string();
            result.error_details = Some("Use --readme flag to specify a README file".to_string());
            return result;
        }

        if self.dry_run {
            let rd = self.readme_data.as_ref().unwrap();
            ui::markup_line("[yellow]DRY RUN: Previewing user management changes (no changes will be made)[/]");
            ui::markup_line(&format!("[cyan]Authorized admins: {}[/]", rd.administrators.len()));
            ui::markup_line(&format!("[cyan]Authorized users: {}[/]", rd.users.len()));
            ui::markup_line(&format!("[cyan]Users to create: {}[/]", rd.users_to_create.len()));
            result.message = "DRY RUN: User management changes previewed.".to_string();
            return result;
        }

        let rd = self.readme_data.clone().unwrap();
        let authorized_admins = ci_set(rd.administrators.iter().map(|a| &a.username));
        let authorized_users = ci_set(rd.users.iter().map(|u| &u.username));
        let users_to_create = ci_set(rd.users_to_create.iter());

        let mut all_authorized = authorized_admins.clone();
        all_authorized.extend(authorized_users.iter().cloned());
        all_authorized.extend(users_to_create.iter().cloned());

        let system_accounts: HashSet<String> = [
            "Administrator",
            "DefaultAccount",
            "WDAGUtilityAccount",
            "SYSTEM",
            "LocalService",
            "NetworkService",
            "Guest",
        ]
        .iter()
        .map(|s| s.to_lowercase())
        .collect();

        let mut fixes: Vec<String> = Vec::new();
        let mut issues: Vec<String> = Vec::new();

        ui::write_line();
        ui::rule("[bold yellow]Step 1: Delete Unauthorized Users[/]");
        let (f, i) = self.delete_unauthorized_users(&all_authorized, &system_accounts).await;
        fixes.extend(f);
        issues.extend(i);

        ui::write_line();
        ui::rule("[bold yellow]Step 2: Fix User Permissions[/]");
        let (f, i) = self.fix_user_permissions(&authorized_admins, &system_accounts).await;
        fixes.extend(f);
        issues.extend(i);

        ui::write_line();
        ui::rule("[bold yellow]Step 3: Update Insecure Passwords[/]");
        let (f, i) = self.update_insecure_passwords(&authorized_users).await;
        fixes.extend(f);
        issues.extend(i);

        ui::write_line();
        ui::rule("[bold yellow]Step 4: Create New Users[/]");
        let (f, i) = self.create_new_users(&users_to_create, &authorized_admins).await;
        fixes.extend(f);
        issues.extend(i);

        ui::write_line();
        ui::rule("[bold yellow]Step 5: Configure Groups[/]");
        let (f, i) = self.configure_groups().await;
        fixes.extend(f);
        issues.extend(i);

        if !issues.is_empty() {
            result.message = format!("Applied {} changes. {} issues require attention.", fixes.len(), issues.len());
            result.error_details = Some(issues.join("\n"));
        } else {
            result.message = format!("Successfully applied {} user management changes.", fixes.len());
        }

        result
    }

    async fn verify(&mut self) -> bool {
        let Some(rd) = self.readme_data.clone() else {
            return false;
        };

        let accounts = Self::get_all_user_accounts().await;
        let authorized_admins = ci_set(rd.administrators.iter().map(|a| &a.username));
        let users_to_create = ci_set(rd.users_to_create.iter());

        let mut all_good = true;

        for username in &users_to_create {
            if !accounts.iter().any(|a| a.username.eq_ignore_ascii_case(username)) {
                ui::markup_line(&format!("[red]? Required user '{}' not found[/]", ui::escape(username)));
                all_good = false;
            }
        }

        for account in accounts.iter().filter(|a| a.is_enabled) {
            let should_be_admin = ci_contains(&authorized_admins, &account.username);
            if account.is_admin != should_be_admin && !Self::is_system_account(&account.username) {
                let expected = if should_be_admin { "admin" } else { "standard user" };
                ui::markup_line(&format!("[red]? User '{}' should be {}[/]", ui::escape(&account.username), expected));
                all_good = false;
            }
        }

        if all_good {
            ui::markup_line("[green]? All user accounts verified[/]");
        }
        all_good
    }
}
