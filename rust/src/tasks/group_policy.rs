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

/// Read the REG_DWORD value named `name` out of `reg query` output.
///
/// `reg query <key> /v <name>` prints the value on its own indented line:
///
/// ```text
/// HKEY_LOCAL_MACHINE\SOFTWARE\...\System
///     dontdisplaylastusername    REG_DWORD    0x1
/// ```
fn parse_reg_dword(output: &str, name: &str) -> Option<u32> {
    for line in output.lines() {
        let fields: Vec<&str> = line.split_whitespace().collect();
        if fields.len() >= 3
            && fields[0].eq_ignore_ascii_case(name)
            && fields[1].eq_ignore_ascii_case("REG_DWORD")
        {
            let raw = fields[2];
            let hex = raw.trim_start_matches("0x").trim_start_matches("0X");
            return u32::from_str_radix(hex, 16).ok().or_else(|| raw.parse().ok());
        }
    }
    None
}

/// Confirm a registry value is present *and* set to `expected`.
async fn reg_dword_equals(key: &str, name: &str, expected: u32) -> bool {
    let (success, output, _e) =
        command::execute("reg", Some(&format!("query {key} /v {name}"))).await;
    success && parse_reg_dword(&output, name) == Some(expected)
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
        // These checks previously only asserted that `reg query` / `sc qc`
        // exited successfully, which is true whenever the value merely *exists*.
        // A setting left at the wrong value therefore verified as correct.
        const POLICIES: &str = r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System";
        const LSA: &str = r"HKLM\SYSTEM\CurrentControlSet\Control\Lsa";

        let hide_user_ok = reg_dword_equals(POLICIES, "dontdisplaylastusername", 1).await;
        // DisableCAD = 0 means Ctrl+Alt+Del *is* required.
        let cad_ok = reg_dword_equals(POLICIES, "DisableCAD", 0).await;
        let anon_ok = reg_dword_equals(LSA, "restrictanonymous", 1).await;

        let (sc_success, sc_output, _e) = command::execute("sc", Some("qc SharedAccess")).await;
        // `sc qc` prints e.g. "START_TYPE : 4   DISABLED".
        let ics_ok = sc_success
            && sc_output
                .lines()
                .find(|l| l.to_uppercase().contains("START_TYPE"))
                .map(|l| l.to_uppercase().contains("DISABLED"))
                .unwrap_or(false);

        if !hide_user_ok {
            ui::markup_line("[red]? 'Don't display last user name' is not set[/]");
        }
        if !cad_ok {
            ui::markup_line("[red]? Ctrl+Alt+Del is not required at logon[/]");
        }
        if !anon_ok {
            ui::markup_line("[red]? Anonymous access is not restricted[/]");
        }
        if !ics_ok {
            ui::markup_line("[red]? Internet Connection Sharing is not disabled[/]");
        }

        hide_user_ok && cad_ok && anon_ok && ics_ok
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const REG_QUERY_OUTPUT: &str = "\r
HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\r
    dontdisplaylastusername    REG_DWORD    0x1\r
    DisableCAD    REG_DWORD    0x0\r
";

    #[test]
    fn parse_reg_dword_reads_the_named_value() {
        assert_eq!(parse_reg_dword(REG_QUERY_OUTPUT, "dontdisplaylastusername"), Some(1));
        assert_eq!(parse_reg_dword(REG_QUERY_OUTPUT, "DisableCAD"), Some(0));
    }

    #[test]
    fn parse_reg_dword_is_case_insensitive_on_the_value_name() {
        assert_eq!(parse_reg_dword(REG_QUERY_OUTPUT, "DONTDISPLAYLASTUSERNAME"), Some(1));
    }

    #[test]
    fn parse_reg_dword_returns_none_when_absent() {
        assert_eq!(parse_reg_dword(REG_QUERY_OUTPUT, "restrictanonymous"), None);
    }

    #[test]
    fn a_present_but_wrong_value_is_distinguishable() {
        // The old verify only checked that `reg query` exited 0, so a value
        // present with the wrong contents passed verification.
        assert_ne!(parse_reg_dword(REG_QUERY_OUTPUT, "DisableCAD"), Some(1));
    }
}
