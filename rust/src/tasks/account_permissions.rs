//! Check and fix account permissions and security settings.

use crate::command;
use crate::impl_task_meta;
use crate::models::{AccountInfo, AccountSecurityStandards, SystemInfo, TaskResult};
use crate::tasks::Task;
use crate::ui;
use async_trait::async_trait;
use chrono::{DateTime, Duration, Local};

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
        let mut accounts = Vec::new();

        let (success, output, _e) = command::powershell_query(
            "Get-LocalUser | Select-Object Name, FullName, Enabled, PasswordRequired, PasswordNeverExpires, LastLogon | ConvertTo-Csv -NoTypeInformation",
        )
        .await;

        if success && !output.is_empty() {
            // Read the Administrators membership once rather than shelling out
            // per account, and match names exactly.
            let admins = crate::tasks::local_group_members("Administrators").await;
            for line in output.split(['\r', '\n']).filter(|l| !l.is_empty()).skip(1) {
                if let Some(mut account) = parse_account_from_csv(line) {
                    account.is_admin = crate::tasks::is_group_member(&admins, &account.username);
                    account.group_memberships = get_user_groups(&account.username).await;
                    accounts.push(account);
                }
            }
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
                if account.is_enabled { "[green]Yes[/]" } else { "[dim]No[/]" }.to_string(),
                if account.is_admin { "[yellow]Yes[/]" } else { "No" }.to_string(),
                if account.password_required { "[green]Yes[/]" } else { "[red]No[/]" }.to_string(),
                if account.password_never_expires { "[red]Never[/]" } else { "[green]Yes[/]" }.to_string(),
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

        if let Some(guest) = guest {
            if guest.is_enabled {
                ui::markup_line("[yellow]Disabling Guest account...[/]");
                let (success, _o, error) =
                    command::execute("net", Some("user Guest /active:no")).await;
                if success {
                    fixes.push("Disabled Guest account".to_string());
                    ui::markup_line("[green]? Guest account disabled[/]");
                } else {
                    let e = error.unwrap_or_default();
                    issues.push(format!("Failed to disable Guest account: {e}"));
                    ui::markup_line(&format!("[red]? Failed to disable Guest account: {}[/]", ui::escape(&e)));
                }
                return (fixes, issues);
            }
        }
        ui::markup_line("[green]? Guest account is already disabled[/]");
        (fixes, issues)
    }

    fn enforce_password_required(&self) -> (Vec<String>, Vec<String>) {
        let fixes = Vec::new();
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
            ui::markup_line(&format!(
                "[yellow]Enforcing password requirement for {}...[/]",
                ui::escape(&account.username)
            ));
            issues.push(format!(
                "Account '{}' does not require a password - manual password set required",
                account.username
            ));
            ui::markup_line(&format!(
                "[yellow]? Account '{}' needs a password set manually[/]",
                ui::escape(&account.username)
            ));
        }

        if accounts_without_password.is_empty() {
            ui::markup_line("[green]? All enabled accounts require passwords[/]");
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
            let (success, _o, error) = command::powershell(&format!(
                "Set-LocalUser -Name {} -PasswordNeverExpires $false",
                command::ps_quote(&account.username)
            ))
            .await;
            if success {
                fixes.push(format!("Enabled password expiration for {}", account.username));
                ui::markup_line(&format!("[green]? Password expiration enabled for {}[/]", ui::escape(&account.username)));
            } else {
                issues.push(format!("Failed to enable password expiration for {}: {}", account.username, error.unwrap_or_default()));
                ui::markup_line(&format!("[red]? Failed to enable password expiration for {}[/]", ui::escape(&account.username)));
            }
        }

        if never_expires.is_empty() {
            ui::markup_line("[green]? All user accounts have password expiration enabled[/]");
        }

        (fixes, issues)
    }

    fn review_admin_accounts(&self) -> (Vec<String>, Vec<String>) {
        let fixes = Vec::new();
        let mut issues = Vec::new();

        let admin_accounts: Vec<&AccountInfo> =
            self.accounts.iter().filter(|a| a.is_admin && a.is_enabled).collect();

        ui::markup_line(&format!("[bold]Found {} administrator account(s):[/]", admin_accounts.len()));

        for admin in &admin_accounts {
            if admin.username.eq_ignore_ascii_case("Administrator") {
                issues.push("Default Administrator account should be renamed for security".to_string());
                ui::markup_line("[yellow]? Consider renaming default Administrator account[/]");
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
                "[yellow]? Consider reviewing admin accounts - {} accounts have admin privileges[/]",
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
            issues.push(format!("Account '{}' inactive for {} days - consider disabling", account.username, days));
            ui::markup_line(&format!(
                "[yellow]? Account '{}' has been inactive for {} days[/]",
                ui::escape(&account.username),
                days
            ));
        }

        if inactive_accounts.is_empty() {
            ui::markup_line("[green]? No inactive accounts detected[/]");
        }

        (fixes, issues)
    }
}

impl Default for AccountPermissionsTask {
    fn default() -> Self {
        Self::new()
    }
}

fn parse_account_from_csv(csv_line: &str) -> Option<AccountInfo> {
    let values = crate::tasks::parse_csv_line(csv_line);
    if values.len() < 5 {
        return None;
    }
    let trim = |s: &str| s.trim_matches('"').to_string();
    Some(AccountInfo {
        username: trim(&values[0]),
        full_name: values.get(1).map(|v| trim(v)).unwrap_or_default(),
        is_enabled: values.get(2).map(|v| trim(v).eq_ignore_ascii_case("True")).unwrap_or(false),
        password_required: values.get(3).map(|v| trim(v).eq_ignore_ascii_case("True")).unwrap_or(false),
        password_never_expires: values.get(4).map(|v| trim(v).eq_ignore_ascii_case("True")).unwrap_or(false),
        last_logon: values.get(5).and_then(|v| parse_datetime(&trim(v))),
        ..Default::default()
    })
}

fn parse_datetime(value: &str) -> Option<DateTime<Local>> {
    if value.trim().is_empty() {
        return None;
    }
    // Try RFC3339 first, then a couple of common formats.
    if let Ok(dt) = DateTime::parse_from_rfc3339(value) {
        return Some(dt.with_timezone(&Local));
    }
    use chrono::NaiveDateTime;
    for fmt in ["%m/%d/%Y %I:%M:%S %p", "%m/%d/%Y %H:%M:%S", "%Y-%m-%d %H:%M:%S"] {
        if let Ok(ndt) = NaiveDateTime::parse_from_str(value, fmt) {
            return ndt.and_local_timezone(Local).single();
        }
    }
    None
}

async fn get_user_groups(username: &str) -> Vec<String> {
    let (success, output, _e) = command::powershell_query(&format!(
        "(Get-LocalUser {} | Get-LocalGroup).Name",
        command::ps_quote(username)
    ))
    .await;
    if success && !output.is_empty() {
        output.split(['\r', '\n']).filter(|l| !l.is_empty()).map(|l| l.to_string()).collect()
    } else {
        Vec::new()
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
            ui::markup_line("[yellow]DRY RUN: Previewing account permission changes (no changes will be made)[/]");

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

            // The remaining steps only report; run them so the preview is complete.
            let (_f, i) = self.enforce_password_required();
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
        let (f, i) = self.enforce_password_required();
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
            result.message = format!("Applied {} fixes. {} issues require manual review.", fixes.len(), issues.len());
            result.error_details = Some(issues.join("\n"));
        } else {
            result.message = format!("Successfully applied {} account security fixes.", fixes.len());
        }

        result
    }

    async fn verify(&mut self) -> bool {
        let accounts = Self::get_user_accounts().await;
        let mut all_good = true;

        if let Some(guest) = accounts.iter().find(|a| a.username.eq_ignore_ascii_case("Guest")) {
            if guest.is_enabled {
                ui::markup_line("[red]? Guest account is still enabled[/]");
                all_good = false;
            }
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
                "[red]? {} account(s) still don't require passwords[/]",
                no_password.len()
            ));
            all_good = false;
        }

        if all_good {
            ui::markup_line("[green]? All account security settings verified[/]");
        }
        all_good
    }
}
