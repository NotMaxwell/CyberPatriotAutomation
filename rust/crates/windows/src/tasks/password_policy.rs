//! Check and enforce secure password policies (NIST SP 800-63B / CIS).

use crate::policy_ops;
use async_trait::async_trait;
use pinnacle_core::Task;
use pinnacle_core::command;
use pinnacle_core::impl_task_meta;
use pinnacle_core::models::{PasswordPolicyInfo, PasswordPolicyStandards, SystemInfo, TaskResult};
use pinnacle_core::ui;

pub struct PasswordPolicyTask {
    name: String,
    description: String,
    dry_run: bool,
    current_policy: Option<PasswordPolicyInfo>,
}

impl PasswordPolicyTask {
    pub fn new() -> Self {
        Self {
            name: "Password Policy Enforcement".to_string(),
            description:
                "Check and enforce secure password policies according to professional security standards"
                    .to_string(),
            dry_run: false,
            current_policy: None,
        }
    }

    async fn get_current_password_policy() -> PasswordPolicyInfo {
        let mut policy = PasswordPolicyInfo::default();

        // Read the policy as data first. `net accounts` prints a localised
        // table, and on a non-English image every line test below fails to
        // match, leaving the policy at its zero defaults - which reads as
        // "already compliant".
        #[cfg(windows)]
        if let Some(values) = crate::native::accounts::password_policy() {
            policy.min_password_length = values.min_password_length as i32;
            policy.max_password_age = values.max_password_age_days as i32;
            policy.min_password_age = values.min_password_age_days as i32;
            policy.password_history_count = values.password_history_length as i32;
            policy.lockout_threshold = values.lockout_threshold as i32;
            policy.lockout_duration = values.lockout_duration_minutes as i32;
            policy.lockout_observation_window = values.lockout_observation_minutes as i32;
            return policy;
        }

        // The parser lives on the model so `policy_ops` reads its evidence the
        // same way rather than through a second one that could disagree.
        let (success, output, _) = command::execute("net", Some("accounts")).await;
        if success && !output.is_empty() {
            policy = PasswordPolicyInfo::parse_net_accounts(&output);
        }

        // `secedit` is spawned directly rather than through a shell, so a
        // literal "%TEMP%" is never expanded and the export lands in a file
        // named "%TEMP%\secpol.cfg" relative to the working directory - while
        // the `cmd /c type` that read it back *did* expand the variable and so
        // looked somewhere else entirely. Complexity therefore always read as
        // disabled. Resolve the path ourselves and read the file directly.
        let cfg_path = std::env::temp_dir().join("cpa_secpol_export.cfg");
        let cfg_path_str = cfg_path.to_string_lossy().into_owned();
        let (sec_success, _o, _e) = command::execute(
            "secedit",
            Some(&format!("/export /cfg \"{cfg_path_str}\" /quiet")),
        )
        .await;
        if sec_success {
            if let Ok(cfg_output) = std::fs::read_to_string(&cfg_path)
                && cfg_output.contains("PasswordComplexity")
            {
                // The exported value is written as "PasswordComplexity = 1";
                // tolerate any surrounding whitespace.
                policy.complexity_enabled = cfg_output
                    .lines()
                    .filter_map(|l| l.split_once('='))
                    .any(|(k, v)| {
                        k.trim().eq_ignore_ascii_case("PasswordComplexity") && v.trim() == "1"
                    });
            }
            let _ = std::fs::remove_file(&cfg_path);
        }

        policy
    }

    fn display_policy_comparison(current: &PasswordPolicyInfo) {
        let mut table =
            ui::TableBuilder::new().columns(&["Setting", "Current", "Recommended", "Status"]);

        add_comparison_row(
            &mut table,
            "Min Password Length",
            &current.min_password_length.to_string(),
            &PasswordPolicyStandards::MIN_PASSWORD_LENGTH.to_string(),
            current.min_password_length >= PasswordPolicyStandards::MIN_PASSWORD_LENGTH,
        );
        add_comparison_row(
            &mut table,
            "Max Password Age (days)",
            &(if current.max_password_age == 0 {
                "Never".to_string()
            } else {
                current.max_password_age.to_string()
            }),
            &PasswordPolicyStandards::MAX_PASSWORD_AGE.to_string(),
            current.max_password_age > 0
                && current.max_password_age <= PasswordPolicyStandards::MAX_PASSWORD_AGE,
        );
        add_comparison_row(
            &mut table,
            "Min Password Age (days)",
            &current.min_password_age.to_string(),
            &PasswordPolicyStandards::MIN_PASSWORD_AGE.to_string(),
            current.min_password_age >= PasswordPolicyStandards::MIN_PASSWORD_AGE,
        );
        add_comparison_row(
            &mut table,
            "Password History",
            &current.password_history_count.to_string(),
            &PasswordPolicyStandards::PASSWORD_HISTORY_COUNT.to_string(),
            current.password_history_count >= PasswordPolicyStandards::PASSWORD_HISTORY_COUNT,
        );
        add_comparison_row(
            &mut table,
            "Complexity Enabled",
            if current.complexity_enabled {
                "Yes"
            } else {
                "No"
            },
            "Yes",
            current.complexity_enabled,
        );
        add_comparison_row(
            &mut table,
            "Lockout Threshold",
            &(if current.lockout_threshold == 0 {
                "Disabled".to_string()
            } else {
                current.lockout_threshold.to_string()
            }),
            &PasswordPolicyStandards::LOCKOUT_THRESHOLD.to_string(),
            current.lockout_threshold > 0
                && current.lockout_threshold <= PasswordPolicyStandards::LOCKOUT_THRESHOLD,
        );
        add_comparison_row(
            &mut table,
            "Lockout Duration (min)",
            &current.lockout_duration.to_string(),
            &PasswordPolicyStandards::LOCKOUT_DURATION.to_string(),
            current.lockout_duration >= PasswordPolicyStandards::LOCKOUT_DURATION,
        );

        table.print();
    }

    async fn apply_password_policy(
        &self,
        current: &PasswordPolicyInfo,
    ) -> (Vec<String>, Vec<String>) {
        let mut fixes = Vec::new();
        let mut issues = Vec::new();

        if self.dry_run {
            ui::markup_line("[yellow]DRY RUN: Skipping password policy changes[/]");
            if current.min_password_length < PasswordPolicyStandards::MIN_PASSWORD_LENGTH {
                issues.push(format!(
                    "Would set minimum password length to {}",
                    PasswordPolicyStandards::MIN_PASSWORD_LENGTH
                ));
            }
            if current.password_history_count < PasswordPolicyStandards::PASSWORD_HISTORY_COUNT {
                issues.push(format!(
                    "Would set password history to {}",
                    PasswordPolicyStandards::PASSWORD_HISTORY_COUNT
                ));
            }
            if !current.complexity_enabled {
                issues.push("Would enable password complexity".to_string());
            }
            return (fixes, issues);
        }

        if current.min_password_length < PasswordPolicyStandards::MIN_PASSWORD_LENGTH {
            ui::markup_line(&format!(
                "[yellow]Setting minimum password length to {}...[/]",
                PasswordPolicyStandards::MIN_PASSWORD_LENGTH
            ));
            match policy_ops::set_min_password_length(PasswordPolicyStandards::MIN_PASSWORD_LENGTH)
                .await
            {
                Ok(()) => fixes.push(format!(
                    "Set minimum password length to {}",
                    PasswordPolicyStandards::MIN_PASSWORD_LENGTH
                )),
                Err(e) => issues.push(format!("Failed to set minimum password length: {e}")),
            }
        }

        if current.max_password_age == 0
            || current.max_password_age > PasswordPolicyStandards::MAX_PASSWORD_AGE
        {
            ui::markup_line(&format!(
                "[yellow]Setting maximum password age to {} days...[/]",
                PasswordPolicyStandards::MAX_PASSWORD_AGE
            ));
            match policy_ops::set_max_password_age_days(PasswordPolicyStandards::MAX_PASSWORD_AGE)
                .await
            {
                Ok(()) => fixes.push(format!(
                    "Set maximum password age to {} days",
                    PasswordPolicyStandards::MAX_PASSWORD_AGE
                )),
                Err(e) => issues.push(format!("Failed to set maximum password age: {e}")),
            }
        }

        if current.min_password_age < PasswordPolicyStandards::MIN_PASSWORD_AGE {
            ui::markup_line(&format!(
                "[yellow]Setting minimum password age to {} day(s)...[/]",
                PasswordPolicyStandards::MIN_PASSWORD_AGE
            ));
            match policy_ops::set_min_password_age_days(PasswordPolicyStandards::MIN_PASSWORD_AGE)
                .await
            {
                Ok(()) => fixes.push(format!(
                    "Set minimum password age to {} day(s)",
                    PasswordPolicyStandards::MIN_PASSWORD_AGE
                )),
                Err(e) => issues.push(format!("Failed to set minimum password age: {e}")),
            }
        }

        if current.password_history_count < PasswordPolicyStandards::PASSWORD_HISTORY_COUNT {
            ui::markup_line(&format!(
                "[yellow]Setting password history to {}...[/]",
                PasswordPolicyStandards::PASSWORD_HISTORY_COUNT
            ));
            match policy_ops::set_password_history_length(
                PasswordPolicyStandards::PASSWORD_HISTORY_COUNT,
            )
            .await
            {
                Ok(()) => fixes.push(format!(
                    "Set password history to {}",
                    PasswordPolicyStandards::PASSWORD_HISTORY_COUNT
                )),
                Err(e) => issues.push(format!("Failed to set password history: {e}")),
            }
        }

        if !current.complexity_enabled {
            ui::markup_line("[yellow]Enabling password complexity...[/]");
            let (success, error) = enable_password_complexity().await;
            if success {
                fixes.push("Enabled password complexity requirement".to_string());
            } else {
                issues.push(format!(
                    "Failed to enable password complexity: {}",
                    error.unwrap_or_default()
                ));
            }
        }

        (fixes, issues)
    }

    async fn apply_lockout_policy(
        &self,
        current: &PasswordPolicyInfo,
    ) -> (Vec<String>, Vec<String>) {
        let mut fixes = Vec::new();
        let mut issues = Vec::new();

        if self.dry_run {
            ui::markup_line("[yellow]DRY RUN: Skipping lockout policy changes[/]");
            return (fixes, issues);
        }

        if current.lockout_threshold == 0
            || current.lockout_threshold > PasswordPolicyStandards::LOCKOUT_THRESHOLD
        {
            ui::markup_line(&format!(
                "[yellow]Setting account lockout threshold to {}...[/]",
                PasswordPolicyStandards::LOCKOUT_THRESHOLD
            ));
            match policy_ops::set_lockout_threshold(PasswordPolicyStandards::LOCKOUT_THRESHOLD)
                .await
            {
                Ok(()) => fixes.push(format!(
                    "Set account lockout threshold to {}",
                    PasswordPolicyStandards::LOCKOUT_THRESHOLD
                )),
                Err(e) => issues.push(format!("Failed to set lockout threshold: {e}")),
            }
        }

        if current.lockout_duration < PasswordPolicyStandards::LOCKOUT_DURATION {
            ui::markup_line(&format!(
                "[yellow]Setting lockout duration to {} minutes...[/]",
                PasswordPolicyStandards::LOCKOUT_DURATION
            ));
            match policy_ops::set_lockout_duration_minutes(
                PasswordPolicyStandards::LOCKOUT_DURATION,
            )
            .await
            {
                Ok(()) => fixes.push(format!(
                    "Set lockout duration to {} minutes",
                    PasswordPolicyStandards::LOCKOUT_DURATION
                )),
                Err(e) => issues.push(format!("Failed to set lockout duration: {e}")),
            }
        }

        if current.lockout_observation_window < PasswordPolicyStandards::LOCKOUT_OBSERVATION_WINDOW
        {
            ui::markup_line(&format!(
                "[yellow]Setting lockout observation window to {} minutes...[/]",
                PasswordPolicyStandards::LOCKOUT_OBSERVATION_WINDOW
            ));
            match policy_ops::set_lockout_observation_minutes(
                PasswordPolicyStandards::LOCKOUT_OBSERVATION_WINDOW,
            )
            .await
            {
                Ok(()) => fixes.push(format!(
                    "Set lockout observation window to {} minutes",
                    PasswordPolicyStandards::LOCKOUT_OBSERVATION_WINDOW
                )),
                Err(e) => issues.push(format!("Failed to set lockout observation window: {e}")),
            }
        }

        (fixes, issues)
    }
}

impl Default for PasswordPolicyTask {
    fn default() -> Self {
        Self::new()
    }
}

fn add_comparison_row(
    table: &mut ui::TableBuilder,
    setting: &str,
    current: &str,
    recommended: &str,
    is_compliant: bool,
) {
    let status = if is_compliant {
        "[green]✓ OK[/]"
    } else {
        "[red]✗ Fix[/]"
    };
    let current_formatted = if is_compliant {
        format!("[green]{current}[/]")
    } else {
        format!("[yellow]{current}[/]")
    };
    table.add_row([
        setting.to_string(),
        current_formatted,
        recommended.to_string(),
        status.to_string(),
    ]);
}

async fn enable_password_complexity() -> (bool, Option<String>) {
    let temp_dir = std::env::temp_dir();
    let temp_file = temp_dir.join("secpol_temp.inf");
    let db_file = temp_dir.join("secpol_temp.sdb");
    let temp_file_str = temp_file.to_string_lossy().into_owned();
    let db_file_str = db_file.to_string_lossy().into_owned();

    let (export_success, _o, export_error) = command::execute(
        "secedit",
        Some(&format!("/export /cfg \"{temp_file_str}\"")),
    )
    .await;
    if !export_success {
        return (false, export_error);
    }

    let content = match std::fs::read_to_string(&temp_file) {
        Ok(c) => c,
        Err(e) => return (false, Some(e.to_string())),
    };

    let mut content = if content.contains("PasswordComplexity = 0") {
        content.replace("PasswordComplexity = 0", "PasswordComplexity = 1")
    } else if !content.contains("PasswordComplexity") {
        content.replace("[System Access]", "[System Access]\nPasswordComplexity = 1")
    } else {
        content
    };
    if content.contains("ClearTextPassword = 1") {
        content = content.replace("ClearTextPassword = 1", "ClearTextPassword = 0");
    }

    if let Err(e) = std::fs::write(&temp_file, &content) {
        return (false, Some(e.to_string()));
    }

    let (import_success, _o, import_error) = command::execute(
        "secedit",
        Some(&format!(
            "/configure /db \"{db_file_str}\" /cfg \"{temp_file_str}\" /areas SECURITYPOLICY"
        )),
    )
    .await;

    let _ = std::fs::remove_file(&temp_file);
    let _ = std::fs::remove_file(&db_file);

    (import_success, import_error)
}

#[async_trait]
impl Task for PasswordPolicyTask {
    impl_task_meta!();

    async fn read_system_state(&mut self) -> SystemInfo {
        let mut system_info = SystemInfo::new();
        let policy = Self::get_current_password_policy().await;

        system_info.registry_settings.insert(
            "MinPasswordLength".to_string(),
            policy.min_password_length.to_string(),
        );
        system_info.registry_settings.insert(
            "MaxPasswordAge".to_string(),
            policy.max_password_age.to_string(),
        );
        system_info.registry_settings.insert(
            "MinPasswordAge".to_string(),
            policy.min_password_age.to_string(),
        );
        system_info.registry_settings.insert(
            "PasswordHistoryCount".to_string(),
            policy.password_history_count.to_string(),
        );
        system_info.registry_settings.insert(
            "ComplexityEnabled".to_string(),
            policy.complexity_enabled.to_string(),
        );
        system_info.registry_settings.insert(
            "LockoutThreshold".to_string(),
            policy.lockout_threshold.to_string(),
        );
        system_info.registry_settings.insert(
            "LockoutDuration".to_string(),
            policy.lockout_duration.to_string(),
        );

        self.current_policy = Some(policy);
        system_info
    }

    async fn execute(&mut self) -> TaskResult {
        let mut result = TaskResult {
            task_name: self.name.clone(),
            success: true,
            message: "Password policy enforcement completed".to_string(),
            ..Default::default()
        };

        let mut issues: Vec<String> = Vec::new();
        let mut fixes: Vec<String> = Vec::new();

        ui::markup_line("[bold]Checking Password Policy Settings...[/]");

        if self.current_policy.is_none() {
            self.current_policy = Some(Self::get_current_password_policy().await);
        }
        let policy = self.current_policy.clone().unwrap();

        Self::display_policy_comparison(&policy);

        let (pf, pi) = self.apply_password_policy(&policy).await;
        fixes.extend(pf);
        issues.extend(pi);

        let (lf, li) = self.apply_lockout_policy(&policy).await;
        fixes.extend(lf);
        issues.extend(li);

        if !issues.is_empty() {
            result.message = format!(
                "Applied {} fixes. {} issues remain.",
                fixes.len(),
                issues.len()
            );
            result.error_details = Some(issues.join("\n"));
        } else {
            result.message = format!(
                "Successfully applied {} password policy settings.",
                fixes.len()
            );
        }

        result
    }

    async fn verify(&mut self) -> bool {
        let verified = Self::get_current_password_policy().await;
        let mut all_good = true;

        if verified.min_password_length < PasswordPolicyStandards::MIN_PASSWORD_LENGTH {
            ui::markup_line("[red]✗ Minimum password length not set correctly[/]");
            all_good = false;
        }
        if verified.max_password_age > PasswordPolicyStandards::MAX_PASSWORD_AGE
            || verified.max_password_age == 0
        {
            ui::markup_line("[red]✗ Maximum password age not set correctly[/]");
            all_good = false;
        }
        if !verified.complexity_enabled {
            ui::markup_line("[red]✗ Password complexity not enabled[/]");
            all_good = false;
        }
        if verified.lockout_threshold == 0
            || verified.lockout_threshold > PasswordPolicyStandards::LOCKOUT_THRESHOLD
        {
            ui::markup_line("[red]✗ Account lockout threshold not set correctly[/]");
            all_good = false;
        }

        if all_good {
            ui::markup_line("[green]✓ All password policy settings verified[/]");
        }
        all_good
    }
}
