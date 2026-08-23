//! Check and fix account permissions and security settings.

use crate::account_ops;
use async_trait::async_trait;
use chrono::{Duration, Local};
use pinnacle_core::Task;
use pinnacle_core::impl_task_meta;
use pinnacle_core::models::{AccountInfo, AccountSecurityStandards, SystemInfo, TaskResult};
use pinnacle_core::ui;

pub struct AccountPermissionsTask {
    name: String,
    description: String,
    dry_run: bool,
    accounts: Vec<AccountInfo>,
}

impl AccountPermissionsTask {
    pub fn new() -> Self {
        Self {
            name: "Account Permissions Check".to_string(),
            description: "Check and fix user account permissions and security settings".to_string(),
            dry_run: false,
            accounts: Vec::new(),
        }
    }

    async fn get_user_accounts() -> Vec<AccountInfo> {
        let Some(mut accounts) = account_ops::enumerate_users().await else {
            return Vec::new();
        };

        // Read the Administrators membership once rather than shelling out per
        // account, and match names exactly.
        let admins = crate::tasks::local_group_members("Administrators").await;
        for account in &mut accounts {
            account.is_admin = crate::tasks::is_group_member(&admins, &account.username);
            account.group_memberships = account_ops::groups_of(&account.username).await;
        }

        accounts
    }

    fn display_accounts_table(accounts: &[AccountInfo]) {
        let mut table = ui::TableBuilder::new().columns(&[
            "Username",
            "Enabled",
            "Admin",
            "Password Required",
            "Password Expires",
            "Status",
        ]);

        for account in accounts {
            let status = get_account_status(account);
            let status_color = if status == "OK" { "green" } else { "red" };
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
                    "No"
                }
                .to_string(),
                if account.password_required {
                    "[green]Yes[/]"
                } else {
                    "[red]No[/]"
                }
                .to_string(),
                if account.password_never_expires {
                    "[red]Never[/]"
                } else {
                    "[green]Yes[/]"
                }
                .to_string(),
                format!("[{status_color}]{}[/]", ui::escape(&status)),
            ]);
        }

        table.print();
    }

    async fn check_guest_account(&self) -> (Vec<String>, Vec<String>) {
        let mut fixes = Vec::new();
        let mut issues = Vec::new();

        let guest = self
            .accounts
            .iter()
            .find(|a| a.username.eq_ignore_ascii_case("Guest"));

        if let Some(guest) = guest
            && guest.is_enabled
        {
            ui::markup_line("[yellow]Disabling Guest account...[/]");
            match account_ops::set_enabled("Guest", false).await {
                Ok(()) => {
                    fixes.push("Disabled Guest account".to_string());
                    ui::markup_line("[green]✓ Guest account disabled[/]");
                }
                Err(e) => {
                    issues.push(format!("Failed to disable Guest account: {e}"));
                    ui::markup_line(&format!(
                        "[red]✗ Failed to disable Guest account: {}[/]",
                        ui::escape(&e)
                    ));
                }
            }
            return (fixes, issues);
        }
        ui::markup_line("[green]✓ Guest account is already disabled[/]");
        (fixes, issues)
    }

    async fn enforce_password_required(&self) -> (Vec<String>, Vec<String>) {
        let mut fixes = Vec::new();
        let mut issues = Vec::new();

        let accounts_without_password: Vec<&AccountInfo> = self
            .accounts
            .iter()
            .filter(|a| {
                a.is_enabled
                    && !a.password_required
                    && !AccountSecurityStandards::INSECURE_USERNAMES
                        .iter()
                        .any(|u| u.eq_ignore_ascii_case(&a.username))
            })
            .collect();

        for account in &accounts_without_password {
            if self.dry_run {
                ui::markup_line(&format!(
                    "[cyan]Would require a password on {}[/]",
                    ui::escape(&account.username)
                ));
                continue;
            }

            ui::markup_line(&format!(
                "[yellow]Enforcing password requirement for {}...[/]",
                ui::escape(&account.username)
            ));

            // UF_PASSWD_NOTREQD is only reachable through the account database:
            // neither `net user` nor Set-LocalUser exposes it, which is why this
            // step used to do nothing but tell the competitor to go and do it by
            // hand.
            match account_ops::require_password(&account.username).await {
                Ok(()) => {
                    fixes.push(format!("Required a password on {}", account.username));
                    ui::markup_line(&format!(
                        "[green]✓ Password now required for {}[/]",
                        ui::escape(&account.username)
                    ));
                }
                Err(e) => {
                    issues.push(format!(
                        "Account '{}' does not require a password and could not be changed \
                         ({e}) - set one manually",
                        account.username
                    ));
                    ui::markup_line(&format!(
                        "[yellow]⚠ Account '{}' needs a password set manually[/]",
                        ui::escape(&account.username)
                    ));
                }
            }
        }

        if accounts_without_password.is_empty() {
            ui::markup_line("[green]✓ All enabled accounts require passwords[/]");
        }

        (fixes, issues)
    }

    async fn check_password_expiration(&self) -> (Vec<String>, Vec<String>) {
        let mut fixes = Vec::new();
        let mut issues = Vec::new();

        let never_expires: Vec<AccountInfo> = self
            .accounts
            .iter()
            .filter(|a| {
                a.is_enabled
                    && a.password_never_expires
                    && !AccountSecurityStandards::INSECURE_USERNAMES
                        .iter()
                        .any(|u| u.eq_ignore_ascii_case(&a.username))
                    && !a.username.eq_ignore_ascii_case("Administrator")
            })
            .cloned()
            .collect();

        for account in &never_expires {
            ui::markup_line(&format!(
                "[yellow]Enabling password expiration for {}...[/]",
                ui::escape(&account.username)
            ));
            match account_ops::set_password_never_expires(&account.username, false).await {
                Ok(()) => {
                    fixes.push(format!(
                        "Enabled password expiration for {}",
                        account.username
                    ));
                    ui::markup_line(&format!(
                        "[green]✓ Password expiration enabled for {}[/]",
                        ui::escape(&account.username)
                    ));
                }
                Err(error) => {
                    issues.push(format!(
                        "Failed to enable password expiration for {}: {error}",
                        account.username
                    ));
                    ui::markup_line(&format!(
                        "[red]✗ Failed to enable password expiration for {}[/]",
                        ui::escape(&account.username)
                    ));
                }
            }
        }

        if never_expires.is_empty() {
            ui::markup_line("[green]✓ All user accounts have password expiration enabled[/]");
        }

        (fixes, issues)
    }

    fn review_admin_accounts(&self) -> (Vec<String>, Vec<String>) {
        let fixes = Vec::new();
        let mut issues = Vec::new();

        let admin_accounts: Vec<&AccountInfo> = self
            .accounts
            .iter()
            .filter(|a| a.is_admin && a.is_enabled)
            .collect();

        ui::markup_line(&format!(
            "[bold]Found {} administrator account(s):[/]",
            admin_accounts.len()
        ));

        for admin in &admin_accounts {
            if admin.username.eq_ignore_ascii_case("Administrator") {
                issues.push(
                    "Default Administrator account should be renamed for security".to_string(),
                );
                ui::markup_line("[yellow]⚠ Consider renaming default Administrator account[/]");
            } else {
                ui::markup_line(&format!("  - {}", ui::escape(&admin.username)));
            }
        }

        if admin_accounts.len() > 2 {
            issues.push(format!(
                "Review required: {} admin accounts exist - ensure all are necessary",
                admin_accounts.len()
            ));
            ui::markup_line(&format!(
                "[yellow]⚠ Consider reviewing admin accounts - {} accounts have admin privileges[/]",
                admin_accounts.len()
            ));
        }

        (fixes, issues)
    }

    fn check_inactive_accounts(&self) -> (Vec<String>, Vec<String>) {
        let fixes = Vec::new();
        let mut issues = Vec::new();

        let cutoff = Local::now() - Duration::days(AccountSecurityStandards::MAX_INACTIVE_DAYS);

        let inactive_accounts: Vec<&AccountInfo> = self
            .accounts
            .iter()
            .filter(|a| {
                a.is_enabled
                    && a.last_logon.map(|l| l < cutoff).unwrap_or(false)
                    && !AccountSecurityStandards::INSECURE_USERNAMES
                        .iter()
                        .any(|u| u.eq_ignore_ascii_case(&a.username))
            })
            .collect();

        for account in &inactive_accounts {
            let days = (Local::now() - account.last_logon.unwrap()).num_days();
            issues.push(format!(
                "Account '{}' inactive for {} days - consider disabling",
                account.username, days
            ));
            ui::markup_line(&format!(
                "[yellow]⚠ Account '{}' has been inactive for {} days[/]",
                ui::escape(&account.username),
                days
            ));
        }

        if inactive_accounts.is_empty() {
            ui::markup_line("[green]✓ No inactive accounts detected[/]");
        }

        (fixes, issues)
    }
}

impl Default for AccountPermissionsTask {
    fn default() -> Self {
        Self::new()
    }
}

fn get_account_status(account: &AccountInfo) -> String {
    let mut issues = Vec::new();
    if account.username.eq_ignore_ascii_case("Guest") && account.is_enabled {
        issues.push("Guest enabled");
    }
    if account.is_enabled && !account.password_required {
        issues.push("No password");
    }
    if account.is_enabled
        && account.password_never_expires
        && !AccountSecurityStandards::INSECURE_USERNAMES
            .iter()
            .any(|u| u.eq_ignore_ascii_case(&account.username))
    {
        issues.push("Password never expires");
    }
    if issues.is_empty() {
        "OK".to_string()
    } else {
        issues.join(", ")
    }
}

#[async_trait]
impl Task for AccountPermissionsTask {
    impl_task_meta!();

    async fn read_system_state(&mut self) -> SystemInfo {
        let mut system_info = SystemInfo::new();
        self.accounts = Self::get_user_accounts().await;
        for account in &self.accounts {
            system_info.user_accounts.push(format!(
                "{} (Admin: {}, Enabled: {})",
                account.username, account.is_admin, account.is_enabled
            ));
        }
        system_info
    }

    async fn execute(&mut self) -> TaskResult {
        let mut result = TaskResult {
            task_name: self.name.clone(),
            success: true,
            message: "Account permissions check completed".to_string(),
            ..Default::default()
        };

        let mut issues: Vec<String> = Vec::new();
        let mut fixes: Vec<String> = Vec::new();

        ui::markup_line("[bold]Checking User Account Security...[/]");

        if self.accounts.is_empty() {
            self.accounts = Self::get_user_accounts().await;
        }

        Self::display_accounts_table(&self.accounts);

        // This task had no dry-run guard at all, so `--dry-run` still disabled
        // the Guest account and rewrote password-expiry flags - the one mode in
        // which the tool promises to change nothing.
        if self.dry_run {
            ui::markup_line(
                "[yellow]DRY RUN: Previewing account permission changes (no changes will be made)[/]",
            );

            let guest_enabled = self
                .accounts
                .iter()
                .any(|a| a.username.eq_ignore_ascii_case("Guest") && a.is_enabled);
            if guest_enabled {
                ui::markup_line("[cyan]Would disable the Guest account[/]");
            }

            let would_expire: Vec<&str> = self
                .accounts
                .iter()
                .filter(|a| {
                    a.is_enabled
                        && a.password_never_expires
                        && !a.username.eq_ignore_ascii_case("Administrator")
                        && !AccountSecurityStandards::INSECURE_USERNAMES
                            .iter()
                            .any(|u| u.eq_ignore_ascii_case(&a.username))
                })
                .map(|a| a.username.as_str())
                .collect();
            if !would_expire.is_empty() {
                ui::markup_line(&format!(
                    "[cyan]Would enable password expiration for: {}[/]",
                    ui::escape(&would_expire.join(", "))
                ));
            }

            // The remaining steps honour dry_run themselves or only report; run
            // them so the preview is complete.
            let (_f, i) = self.enforce_password_required().await;
            issues.extend(i);
            let (_f, i) = self.review_admin_accounts();
            issues.extend(i);
            let (_f, i) = self.check_inactive_accounts();
            issues.extend(i);

            result.message = "DRY RUN: Account permission changes previewed.".to_string();
            if !issues.is_empty() {
                result.error_details = Some(issues.join("\n"));
            }
            return result;
        }

        let (f, i) = self.check_guest_account().await;
        fixes.extend(f);
        issues.extend(i);
        let (f, i) = self.enforce_password_required().await;
        fixes.extend(f);
        issues.extend(i);
        let (f, i) = self.check_password_expiration().await;
        fixes.extend(f);
        issues.extend(i);
        let (f, i) = self.review_admin_accounts();
        fixes.extend(f);
        issues.extend(i);
        let (f, i) = self.check_inactive_accounts();
        fixes.extend(f);
        issues.extend(i);

        if !issues.is_empty() {
            result.message = format!(
                "Applied {} fixes. {} issues require manual review.",
                fixes.len(),
                issues.len()
            );
            result.error_details = Some(issues.join("\n"));
        } else {
            result.message = format!(
                "Successfully applied {} account security fixes.",
                fixes.len()
            );
        }

        result
    }

    async fn verify(&mut self) -> bool {
        let accounts = Self::get_user_accounts().await;
        let mut all_good = true;

        if let Some(guest) = accounts
            .iter()
            .find(|a| a.username.eq_ignore_ascii_case("Guest"))
            && guest.is_enabled
        {
            ui::markup_line("[red]✗ Guest account is still enabled[/]");
            all_good = false;
        }

        // Apply the same exclusion `enforce_password_required` uses. Without it,
        // verification permanently fails over built-in accounts that execute
        // deliberately never touches.
        let no_password: Vec<&AccountInfo> = accounts
            .iter()
            .filter(|a| {
                !a.password_required
                    && a.is_enabled
                    && !AccountSecurityStandards::INSECURE_USERNAMES
                        .iter()
                        .any(|u| u.eq_ignore_ascii_case(&a.username))
            })
            .collect();
        if !no_password.is_empty() {
            ui::markup_line(&format!(
                "[red]✗ {} account(s) still don't require passwords[/]",
                no_password.len()
            ));
            all_good = false;
        }

        if all_good {
            ui::markup_line("[green]✓ All account security settings verified[/]");
        }
        all_good
    }
}
