//! Manage user accounts based on README requirements.

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

// Account and group changes go through `account_ops`, which picks the Windows
// API where it is available and the shell otherwise. See that module for why
// neither `net user` nor the cmdlets are used directly.
use crate::account_ops::{
    self, add_to_group, create_group, create_user, delete_user, group_exists, remove_from_group,
    set_password, set_password_never_expires,
};

/// A strong password unique to each account.
///
/// Cycling the fixed list alone repeated passwords once there were more
/// accounts than entries; the index suffix keeps every account distinct while
/// preserving length and character-class coverage.
fn generate_password(index: usize) -> String {
    format!(
        "{}#{index:02}",
        SECURE_PASSWORDS[index % SECURE_PASSWORDS.len()]
    )
}

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
            description: "Manage users, passwords, and permissions based on README requirements"
                .to_string(),
            dry_run: false,
            readme_data: None,
            current_accounts: Vec::new(),
        }
    }

    pub fn set_readme_data(&mut self, data: ReadmeData) {
        self.readme_data = Some(data);
    }

    async fn get_all_user_accounts() -> Vec<AccountInfo> {
        let Some(mut accounts) = account_ops::enumerate_users().await else {
            return Vec::new();
        };

        // Read the Administrators membership once rather than shelling out per
        // account, and match names exactly.
        let admins = crate::tasks::local_group_members("Administrators").await;
        for account in &mut accounts {
            account.is_admin = crate::tasks::is_group_member(&admins, &account.username);
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
                if account.is_enabled {
                    "[green]Yes[/]"
                } else {
                    "[dim]No[/]"
                }
                .to_string(),
                if account.is_admin {
                    "[yellow]Yes[/]"
                } else {
                    "[dim]No[/]"
                }
                .to_string(),
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

        // A real CyberPatriot README always names at least one authorized
        // administrator. An empty authorized set therefore means README parsing
        // failed — not that every account on the image is unauthorized. Deleting
        // on that basis would wipe every legitimate user, so refuse instead.
        if all_authorized.is_empty() {
            ui::markup_line(
                "[red]⚠ No authorized users were parsed from the README - skipping deletion.[/]",
            );
            ui::markup_line(
                "[yellow]This usually means the README failed to parse. Deleting every account is never correct;[/]",
            );
            ui::markup_line(
                "[yellow]re-check the README with --parse-readme before running user management.[/]",
            );
            issues.push(
                "Skipped unauthorized-user deletion: README produced no authorized users"
                    .to_string(),
            );
            return (fixes, issues);
        }

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
            ui::markup_line("[green]✓ No unauthorized users found[/]");
            return (fixes, issues);
        }

        ui::markup_line(&format!(
            "[yellow]Found {} unauthorized user(s):[/]",
            unauthorized.len()
        ));
        let mut table = ui::TableBuilder::new().columns(&["[bold]Username[/]", "[bold]Action[/]"]);
        for user in &unauthorized {
            table.add_row([
                format!("[red]{}[/]", ui::escape(&user.username)),
                "Will be deleted".to_string(),
            ]);
        }
        table.print();
        ui::write_line();

        for user in &unauthorized {
            ui::markup_line(&format!(
                "[yellow]Deleting user: {}...[/]",
                ui::escape(&user.username)
            ));
            match delete_user(&user.username).await {
                Ok(()) => {
                    fixes.push(format!("Deleted unauthorized user: {}", user.username));
                    ui::markup_line(&format!(
                        "[green]✓ Deleted user: {}[/]",
                        ui::escape(&user.username)
                    ));
                }
                Err(e) => {
                    issues.push(format!("Failed to delete user {}: {}", user.username, e));
                    ui::markup_line(&format!(
                        "[red]✗ Failed to delete {}: {}[/]",
                        ui::escape(&user.username),
                        ui::escape(&e)
                    ));
                }
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
                ui::markup_line(&format!(
                    "[yellow]Adding {} to Administrators group...[/]",
                    ui::escape(&account.username)
                ));
                // Already a member reads as success from here, so there is no
                // longer a localised "already a member" string to match on.
                match add_to_group(&account.username, "Administrators").await {
                    Ok(()) => {
                        fixes.push(format!(
                            "Added {} to Administrators group",
                            account.username
                        ));
                        ui::markup_line(&format!(
                            "[green]✓ {} is now an administrator[/]",
                            ui::escape(&account.username)
                        ));
                    }
                    Err(e) => {
                        issues.push(format!(
                            "Failed to add {} to Administrators: {}",
                            account.username, e
                        ));
                        ui::markup_line(&format!(
                            "[red]✗ Failed to add {} to Administrators[/]",
                            ui::escape(&account.username)
                        ));
                    }
                }
            } else if !should_be_admin && is_currently_admin {
                ui::markup_line(&format!(
                    "[yellow]Removing {} from Administrators group...[/]",
                    ui::escape(&account.username)
                ));
                match remove_from_group(&account.username, "Administrators").await {
                    Ok(()) => {
                        fixes.push(format!(
                            "Removed {} from Administrators group",
                            account.username
                        ));
                        ui::markup_line(&format!(
                            "[green]✓ {} is no longer an administrator[/]",
                            ui::escape(&account.username)
                        ));
                    }
                    Err(e) => {
                        issues.push(format!(
                            "Failed to remove {} from Administrators: {}",
                            account.username, e
                        ));
                        ui::markup_line(&format!(
                            "[red]✗ Failed to remove {} from Administrators[/]",
                            ui::escape(&account.username)
                        ));
                    }
                }
            } else {
                let role = if should_be_admin {
                    "administrator"
                } else {
                    "standard user"
                };
                ui::markup_line(&format!(
                    "[dim]? {} has correct permissions ({})[/]",
                    ui::escape(&account.username),
                    role
                ));
            }
        }

        (fixes, issues)
    }

    async fn update_insecure_passwords(
        &mut self,
        authorized_users: &HashSet<String>,
    ) -> (Vec<String>, Vec<String>) {
        let mut fixes = Vec::new();
        let mut issues = Vec::new();

        // Accounts the README marks as the primary, auto-login user. READMEs
        // state plainly that changing this password may lock you out of the
        // machine, so it is left alone.
        let primary_users: HashSet<String> = self
            .readme_data
            .as_ref()
            .map(|r| {
                r.administrators
                    .iter()
                    .chain(r.users.iter())
                    .filter(|u| u.is_primary_user)
                    .map(|u| u.username.to_lowercase())
                    .collect()
            })
            .unwrap_or_default();

        self.current_accounts = Self::get_all_user_accounts().await;

        let accounts: Vec<AccountInfo> = self
            .current_accounts
            .iter()
            .filter(|a| a.is_enabled && !Self::is_system_account(&a.username))
            .cloned()
            .collect();

        // Every account gets a freshly generated strong password, administrators
        // included. The README lists the passwords it *found* during an audit,
        // not passwords that must be kept - several are trivial ("root",
        // "data"), and setting those would both weaken the machine and be
        // rejected outright by the complexity and length policy this run has
        // just enforced, which is why every password change failed.
        let mut password_index = 0usize;
        for account in &accounts {
            let is_authorized = ci_contains(authorized_users, &account.username)
                || account.is_admin
                || self
                    .readme_data
                    .as_ref()
                    .map(|r| {
                        r.administrators
                            .iter()
                            .any(|a| a.username.eq_ignore_ascii_case(&account.username))
                    })
                    .unwrap_or(false);
            if !is_authorized {
                continue;
            }

            if primary_users.contains(&account.username.to_lowercase()) {
                ui::markup_line(&format!(
                    "[dim]? Skipping {} - primary auto-login account (changing it risks lockout)[/]",
                    ui::escape(&account.username)
                ));
                continue;
            }

            let password = generate_password(password_index);
            password_index += 1;

            ui::markup_line(&format!(
                "[yellow]Setting secure password for {}...[/]",
                ui::escape(&account.username)
            ));
            match set_password(&account.username, &password).await {
                Ok(()) => {
                    // Record the password: it is the only way back into the
                    // account, and the log is the competitor's own machine.
                    fixes.push(format!(
                        "Set secure password for {}: {password}",
                        account.username
                    ));
                    ui::markup_line(&format!(
                        "[green]✓ {} password set to: {}[/]",
                        ui::escape(&account.username),
                        ui::escape(&password)
                    ));
                }
                Err(reason) => {
                    issues.push(format!(
                        "Failed to set password for {}: {reason}",
                        account.username
                    ));
                    ui::markup_line(&format!(
                        "[red]✗ Failed to set password for {}: {}[/]",
                        ui::escape(&account.username),
                        ui::escape(&reason)
                    ));
                }
            }
        }

        ui::write_line();
        ui::markup_line("[cyan]Ensuring all accounts require passwords...[/]");
        for account in &accounts {
            // Subject the password to the maximum-age policy the password task
            // just set; without this the account is exempt from it.
            match set_password_never_expires(&account.username, false).await {
                Ok(()) => {
                    ui::markup_line(&format!(
                        "[dim]? Password expiration enabled for {}[/]",
                        ui::escape(&account.username)
                    ));
                }
                Err(e) => {
                    issues.push(format!(
                        "Failed to enable password expiration for {}: {e}",
                        account.username
                    ));
                }
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
            ui::markup_line("[green]✓ No new users need to be created[/]");
            return (fixes, issues);
        }

        self.current_accounts = Self::get_all_user_accounts().await;
        let existing = ci_set(self.current_accounts.iter().map(|a| &a.username));

        let mut password_index = 0usize;
        for username in users_to_create {
            if ci_contains(&existing, username) {
                ui::markup_line(&format!(
                    "[dim]? User {} already exists[/]",
                    ui::escape(username)
                ));
                continue;
            }

            let password = generate_password(password_index);
            password_index += 1;

            ui::markup_line(&format!(
                "[yellow]Creating new user: {}...[/]",
                ui::escape(username)
            ));
            match create_user(username, &password).await {
                Ok(()) => {
                    fixes.push(format!(
                        "Created new user {username} with password: {password}"
                    ));
                    ui::markup_line(&format!(
                        "[green]✓ Created user {} with password: {}[/]",
                        ui::escape(username),
                        ui::escape(&password)
                    ));

                    if ci_contains(authorized_admins, username) {
                        match add_to_group(username, "Administrators").await {
                            Ok(()) => {
                                fixes.push(format!("Added {username} to Administrators"));
                                ui::markup_line(&format!(
                                    "[green]✓ Added {} to Administrators group[/]",
                                    ui::escape(username)
                                ));
                            }
                            Err(reason) => {
                                issues.push(format!(
                                    "Failed to add {username} to Administrators: {reason}"
                                ));
                                ui::markup_line(&format!(
                                    "[red]✗ Failed to add {} to Administrators: {}[/]",
                                    ui::escape(username),
                                    ui::escape(&reason)
                                ));
                            }
                        }
                    }
                }
                Err(reason) => {
                    issues.push(format!("Failed to create user {username}: {reason}"));
                    ui::markup_line(&format!(
                        "[red]✗ Failed to create user {}: {}[/]",
                        ui::escape(username),
                        ui::escape(&reason)
                    ));
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
            ui::markup_line("[green]✓ No group requirements specified[/]");
            return (fixes, issues);
        }

        for group_req in group_requirements.unwrap() {
            ui::markup_line(&format!(
                "[cyan]Configuring group: {}[/]",
                ui::escape(&group_req.group_name)
            ));

            // Unknown counts as absent: creating a group that is already there
            // is harmless, skipping one that is not is not.
            if group_exists(&group_req.group_name).await != Some(true) {
                ui::markup_line(&format!(
                    "[yellow]Creating group: {}...[/]",
                    ui::escape(&group_req.group_name)
                ));
                match create_group(&group_req.group_name).await {
                    Ok(()) => {
                        fixes.push(format!("Created group: {}", group_req.group_name));
                        ui::markup_line(&format!(
                            "[green]✓ Created group: {}[/]",
                            ui::escape(&group_req.group_name)
                        ));
                    }
                    Err(e) => {
                        issues.push(format!(
                            "Failed to create group {}: {e}",
                            group_req.group_name
                        ));
                        ui::markup_line(&format!(
                            "[red]✗ Failed to create group: {}[/]",
                            ui::escape(&group_req.group_name)
                        ));
                        continue;
                    }
                }
            } else {
                ui::markup_line(&format!(
                    "[dim]Group {} already exists[/]",
                    ui::escape(&group_req.group_name)
                ));
            }

            for member in &group_req.members {
                // Already a member reads as success from here, so there is no
                // longer a localised "already a member" string to match on.
                match add_to_group(member, &group_req.group_name).await {
                    Ok(()) => {
                        fixes.push(format!(
                            "Added {} to group {}",
                            member, group_req.group_name
                        ));
                        ui::markup_line(&format!(
                            "[green]✓ Added {} to {}[/]",
                            ui::escape(member),
                            ui::escape(&group_req.group_name)
                        ));
                    }
                    Err(e) => {
                        issues.push(format!(
                            "Failed to add {} to {}: {e}",
                            member, group_req.group_name
                        ));
                        ui::markup_line(&format!(
                            "[red]✗ Failed to add {} to {}[/]",
                            ui::escape(member),
                            ui::escape(&group_req.group_name)
                        ));
                    }
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
            result.message =
                "No README data provided. Please parse a README file first.".to_string();
            result.error_details = Some("Use --readme flag to specify a README file".to_string());
            return result;
        }

        if self.dry_run {
            let rd = self.readme_data.as_ref().unwrap();
            ui::markup_line(
                "[yellow]DRY RUN: Previewing user management changes (no changes will be made)[/]",
            );
            ui::markup_line(&format!(
                "[cyan]Authorized admins: {}[/]",
                rd.administrators.len()
            ));
            ui::markup_line(&format!("[cyan]Authorized users: {}[/]", rd.users.len()));
            ui::markup_line(&format!(
                "[cyan]Users to create: {}[/]",
                rd.users_to_create.len()
            ));
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
        let (f, i) = self
            .delete_unauthorized_users(&all_authorized, &system_accounts)
            .await;
        fixes.extend(f);
        issues.extend(i);

        ui::write_line();
        ui::rule("[bold yellow]Step 2: Fix User Permissions[/]");
        let (f, i) = self
            .fix_user_permissions(&authorized_admins, &system_accounts)
            .await;
        fixes.extend(f);
        issues.extend(i);

        ui::write_line();
        ui::rule("[bold yellow]Step 3: Update Insecure Passwords[/]");
        let (f, i) = self.update_insecure_passwords(&authorized_users).await;
        fixes.extend(f);
        issues.extend(i);

        ui::write_line();
        ui::rule("[bold yellow]Step 4: Create New Users[/]");
        let (f, i) = self
            .create_new_users(&users_to_create, &authorized_admins)
            .await;
        fixes.extend(f);
        issues.extend(i);

        ui::write_line();
        ui::rule("[bold yellow]Step 5: Configure Groups[/]");
        let (f, i) = self.configure_groups().await;
        fixes.extend(f);
        issues.extend(i);

        if !issues.is_empty() {
            result.message = format!(
                "Applied {} changes. {} issues require attention.",
                fixes.len(),
                issues.len()
            );
            result.error_details = Some(issues.join("\n"));
        } else {
            result.message = format!(
                "Successfully applied {} user management changes.",
                fixes.len()
            );
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
            if !accounts
                .iter()
                .any(|a| a.username.eq_ignore_ascii_case(username))
            {
                ui::markup_line(&format!(
                    "[red]✗ Required user '{}' not found[/]",
                    ui::escape(username)
                ));
                all_good = false;
            }
        }

        for account in accounts.iter().filter(|a| a.is_enabled) {
            let should_be_admin = ci_contains(&authorized_admins, &account.username);
            if account.is_admin != should_be_admin && !Self::is_system_account(&account.username) {
                let expected = if should_be_admin {
                    "admin"
                } else {
                    "standard user"
                };
                ui::markup_line(&format!(
                    "[red]✗ User '{}' should be {}[/]",
                    ui::escape(&account.username),
                    expected
                ));
                all_good = false;
            }
        }

        if all_good {
            ui::markup_line("[green]✓ All user accounts verified[/]");
        }
        all_good
    }
}
