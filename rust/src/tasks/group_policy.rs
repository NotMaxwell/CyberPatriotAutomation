//! Configures key Group Policy (gpedit) settings for security hardening.

use crate::command;
use crate::impl_task_meta;
use crate::models::{SystemInfo, TaskResult};
use crate::tasks::Task;
use crate::ui;
use async_trait::async_trait;

pub struct GroupPolicyTask {
    name: String,
    description: String,
    dry_run: bool,
}

impl GroupPolicyTask {
    pub fn new() -> Self {
        Self {
            name: "Group Policy".to_string(),
            description:
                "Configures Group Policy settings: Hide last user, require Ctrl+Alt+Del, disable ICS, and more."
                    .to_string(),
            dry_run: false,
        }
    }
}

impl Default for GroupPolicyTask {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl Task for GroupPolicyTask {
    impl_task_meta!();

    async fn read_system_state(&mut self) -> SystemInfo {
        let (_success, output, error) = command::execute(
            "reg",
            Some(r"query HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"),
        )
        .await;
        SystemInfo {
            raw_output: Some(output),
            error_output: error,
            ..Default::default()
        }
    }

    async fn execute(&mut self) -> TaskResult {
        if self.dry_run {
            ui::markup_line("[yellow]DRY RUN: Previewing Group Policy changes (no changes will be made)[/]");
            return TaskResult {
                task_name: self.name.clone(),
                success: true,
                message: "DRY RUN: Would apply:\n✓ Don't display last user name set\n✓ Require Ctrl+Alt+Del set\n✓ ICS (Internet Connection Sharing) disabled\n✓ Restrict anonymous access set".to_string(),
                ..Default::default()
            };
        }

        let mut details: Vec<String> = Vec::new();
        let mut all_success = true;

        let (hide_user_success, _o, hide_user_error) = command::execute(
            "reg",
            Some(r"add HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /v dontdisplaylastusername /t REG_DWORD /d 1 /f"),
        )
        .await;
        details.push(if hide_user_success {
            "✓ Don't display last user name set".to_string()
        } else {
            format!("✗ Failed: {}", hide_user_error.unwrap_or_default())
        });
        all_success &= hide_user_success;

        let (cad_success, _o, cad_error) = command::execute(
            "reg",
            Some(r"add HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /v DisableCAD /t REG_DWORD /d 0 /f"),
        )
        .await;
        details.push(if cad_success {
            "✓ Require Ctrl+Alt+Del set".to_string()
        } else {
            format!("✗ Failed: {}", cad_error.unwrap_or_default())
        });
        all_success &= cad_success;

        let (ics_success, _o, ics_error) =
            command::execute("sc", Some("config SharedAccess start= disabled")).await;
        details.push(if ics_success {
            "✓ ICS (Internet Connection Sharing) disabled".to_string()
        } else {
            format!("✗ Failed: {}", ics_error.unwrap_or_default())
        });
        all_success &= ics_success;

        let (anon_success, _o, anon_error) = command::execute(
            "reg",
            Some(r"add HKLM\SYSTEM\CurrentControlSet\Control\Lsa /v restrictanonymous /t REG_DWORD /d 1 /f"),
        )
        .await;
        details.push(if anon_success {
            "✓ Restrict anonymous access set".to_string()
        } else {
            format!("✗ Failed: {}", anon_error.unwrap_or_default())
        });
        all_success &= anon_success;

        TaskResult {
            task_name: self.name.clone(),
            success: all_success,
            message: details.join("\n"),
            ..Default::default()
        }
    }

    async fn verify(&mut self) -> bool {
        let (hide_user_success, _o, _e) = command::execute(
            "reg",
            Some(r"query HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /v dontdisplaylastusername"),
        )
        .await;
        let (cad_success, _o, _e) = command::execute(
            "reg",
            Some(r"query HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /v DisableCAD"),
        )
        .await;
        let (ics_success, _o, _e) = command::execute("sc", Some("qc SharedAccess")).await;
        let (anon_success, _o, _e) = command::execute(
            "reg",
            Some(r"query HKLM\SYSTEM\CurrentControlSet\Control\Lsa /v restrictanonymous"),
        )
        .await;
        hide_user_success && cad_success && ics_success && anon_success
    }
}
