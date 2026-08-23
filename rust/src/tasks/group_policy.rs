//! Configures key Group Policy (gpedit) settings for security hardening.

use crate::impl_task_meta;
use crate::models::{SystemInfo, TaskResult};
use crate::readme_services;
use crate::registry_ops;
use crate::run_log;
use crate::service_ops;
use crate::tasks::Task;
use crate::ui;
use async_trait::async_trait;

pub struct GroupPolicyTask {
    name: String,
    description: String,
    dry_run: bool,
    readme_data: Option<crate::models::ReadmeData>,
}

impl GroupPolicyTask {
    /// Set the README data for this task.
    ///
    /// Only one setting consults it - Remote Desktop, which a README can declare
    /// critical. Everything else here is unconditional hardening.
    pub fn set_readme_data(&mut self, data: crate::models::ReadmeData) {
        self.readme_data = Some(data);
    }

    pub fn new() -> Self {
        Self {
            name: "Group Policy".to_string(),
            description:
                "Configures Group Policy settings: Hide last user, require Ctrl+Alt+Del, disable ICS, and more."
                    .to_string(),
            dry_run: false,
            readme_data: None,
        }
    }
}

impl Default for GroupPolicyTask {
    fn default() -> Self {
        Self::new()
    }
}

const POLICIES_SYSTEM: &str = r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System";
const LSA_KEY: &str = r"HKLM\SYSTEM\CurrentControlSet\Control\Lsa";

/// SMB client settings ("Microsoft network client" in gpedit).
const LANMAN_WORKSTATION: &str =
    r"HKLM\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters";

/// SMB server settings ("Microsoft network server" in gpedit).
const LANMAN_SERVER: &str = r"HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters";

/// Where Remote Desktop's listener is switched on and off.
const TERMINAL_SERVER: &str = r"HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server";

/// The policy form of the same setting, which takes precedence.
const TERMINAL_SERVICES_POLICY: &str =
    r"HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services";

/// Confirm a registry value is present *and* set to `expected`.
async fn reg_dword_equals(key: &str, name: &str, expected: u32) -> bool {
    registry_ops::dword_equals(key, name, expected).await
}

#[async_trait]
impl Task for GroupPolicyTask {
    impl_task_meta!();

    async fn read_system_state(&mut self) -> SystemInfo {
        let hide_last_user =
            registry_ops::get_dword(POLICIES_SYSTEM, "dontdisplaylastusername").await;
        let disable_cad = registry_ops::get_dword(POLICIES_SYSTEM, "DisableCAD").await;
        let restrict_anonymous = registry_ops::get_dword(LSA_KEY, "restrictanonymous").await;

        let describe = |v: Option<u32>| v.map_or("(not set)".to_string(), |n| n.to_string());
        let raw = format!(
            "dontdisplaylastusername = {}\nDisableCAD = {}\nrestrictanonymous = {}",
            describe(hide_last_user),
            describe(disable_cad),
            describe(restrict_anonymous)
        );
        SystemInfo {
            raw_output: Some(raw),
            error_output: None,
            ..Default::default()
        }
    }

    async fn execute(&mut self) -> TaskResult {
        if self.dry_run {
            ui::markup_line(
                "[yellow]DRY RUN: Previewing Group Policy changes (no changes will be made)[/]",
            );
            return TaskResult {
                task_name: self.name.clone(),
                success: true,
                message: "DRY RUN: Would apply:\n✓ Don't display last user name set\n✓ Require Ctrl+Alt+Del set\n✓ ICS (Internet Connection Sharing) disabled\n✓ Restrict anonymous access set".to_string(),
                ..Default::default()
            };
        }

        let mut details: Vec<String> = Vec::new();
        let mut all_success = true;

        let hide_user_error =
            registry_ops::set_dword(POLICIES_SYSTEM, "dontdisplaylastusername", 1)
                .await
                .err();
        details.push(match &hide_user_error {
            None => "✓ Don't display last user name set".to_string(),
            Some(e) => format!("✗ Failed: {e}"),
        });
        all_success &= hide_user_error.is_none();

        let cad_error = registry_ops::set_dword(POLICIES_SYSTEM, "DisableCAD", 0)
            .await
            .err();
        details.push(match &cad_error {
            None => "✓ Require Ctrl+Alt+Del set".to_string(),
            Some(e) => format!("✗ Failed: {e}"),
        });
        all_success &= cad_error.is_none();

        let ics_error = service_ops::disable("SharedAccess").await.err();
        details.push(match &ics_error {
            None => "✓ ICS (Internet Connection Sharing) disabled".to_string(),
            Some(e) => format!("✗ Failed: {e}"),
        });
        all_success &= ics_error.is_none();

        let anon_error = registry_ops::set_dword(LSA_KEY, "restrictanonymous", 1)
            .await
            .err();
        details.push(match &anon_error {
            None => "✓ Restrict anonymous access set".to_string(),
            Some(e) => format!("✗ Failed: {e}"),
        });
        all_success &= anon_error.is_none();

        // Microsoft network client: digitally sign communications (always).
        //
        // Without it an SMB session can be tampered with in transit, which is
        // what makes SMB relay attacks work. The server-side setting goes with
        // it: they are a pair in every hardening benchmark, and signing only one
        // side leaves the other able to negotiate an unsigned session.
        // Local Security Policy lists four SMB signing settings, not two, and
        // the benchmarks want all four. "Always" forces signing; "if the other
        // side agrees" makes this machine *offer* it to a peer that does not
        // require it. Setting only the "always" pair leaves the negotiated case
        // unsigned and two of the four scored items unset.
        for (key, label, value, qualifier) in [
            (
                LANMAN_WORKSTATION,
                "client",
                "RequireSecuritySignature",
                "always",
            ),
            (
                LANMAN_SERVER,
                "server",
                "RequireSecuritySignature",
                "always",
            ),
            (
                LANMAN_WORKSTATION,
                "client",
                "EnableSecuritySignature",
                "if server agrees",
            ),
            (
                LANMAN_SERVER,
                "server",
                "EnableSecuritySignature",
                "if client agrees",
            ),
        ] {
            let error = registry_ops::set_dword(key, value, 1).await.err();
            details.push(match &error {
                None => format!(
                    "✓ Microsoft network {label}: digitally sign communications ({qualifier})"
                ),
                Some(e) => format!("✗ Failed: {e}"),
            });
            all_success &= error.is_none();
        }

        // Remote desktop sharing off - unless the README says it must work.
        //
        // fDenyTSConnections is the switch the Settings UI toggles. The policy
        // key is set too: a policy value overrides the local one, so an image
        // with the policy set to "allow" would otherwise keep RDP listening no
        // matter what the local setting said.
        //
        // A README that lists Remote Desktop as critical is describing a machine
        // administered remotely, where RDP *working* is the scored condition.
        // Service management already protects TermService in that case; denying
        // connections here too would leave the service running with every
        // connection refused - the worst of both, and a lost point.
        if readme_services::is_remote_desktop_required(self.readme_data.as_ref()) {
            let note = "- Remote desktop left enabled: the README lists it as a critical service";
            details.push(note.to_string());
            run_log::diagnostic("grouppolicy", note.trim_start_matches(['-', ' ']));
            ui::markup_line(&format!("[yellow]{}[/]", ui::escape(note)));
        } else {
            for (key, label) in [
                (TERMINAL_SERVER, "Remote desktop sharing turned off"),
                (
                    TERMINAL_SERVICES_POLICY,
                    "Remote desktop sharing denied by policy",
                ),
            ] {
                let error = registry_ops::set_dword(key, "fDenyTSConnections", 1)
                    .await
                    .err();
                details.push(match &error {
                    None => format!("✓ {label}"),
                    Some(e) => format!("✗ Failed: {e}"),
                });
                all_success &= error.is_none();
            }
        }

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

        // This used to look for the word "DISABLED" in `sc qc` output, which is
        // localised; the service control manager returns the start type as a
        // number.
        let ics_ok = service_ops::is_disabled("SharedAccess").await == Some(true);

        if !hide_user_ok {
            ui::markup_line("[red]✗ 'Don't display last user name' is not set[/]");
        }
        if !cad_ok {
            ui::markup_line("[red]✗ Ctrl+Alt+Del is not required at logon[/]");
        }
        if !anon_ok {
            ui::markup_line("[red]✗ Anonymous access is not restricted[/]");
        }
        if !ics_ok {
            ui::markup_line("[red]✗ Internet Connection Sharing is not disabled[/]");
        }

        let client_signing_ok =
            reg_dword_equals(LANMAN_WORKSTATION, "RequireSecuritySignature", 1).await;
        let server_signing_ok =
            reg_dword_equals(LANMAN_SERVER, "RequireSecuritySignature", 1).await;
        // fDenyTSConnections = 1 means Remote Desktop is refused. When the README
        // requires RDP this step was deliberately skipped, so verifying it as
        // "must be denied" would report a failure for doing the right thing.
        let rdp_ok = readme_services::is_remote_desktop_required(self.readme_data.as_ref())
            || reg_dword_equals(TERMINAL_SERVER, "fDenyTSConnections", 1).await;

        if !client_signing_ok {
            ui::markup_line("[red]✗ Microsoft network client does not require SMB signing[/]");
        }
        if !server_signing_ok {
            ui::markup_line("[red]✗ Microsoft network server does not require SMB signing[/]");
        }
        if !rdp_ok {
            ui::markup_line("[red]✗ Remote desktop sharing is not turned off[/]");
        }

        hide_user_ok
            && cad_ok
            && anon_ok
            && ics_ok
            && client_signing_ok
            && server_signing_ok
            && rdp_ok
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
        assert_eq!(
            registry_ops::parse_reg_dword(REG_QUERY_OUTPUT, "dontdisplaylastusername"),
            Some(1)
        );
        assert_eq!(
            registry_ops::parse_reg_dword(REG_QUERY_OUTPUT, "DisableCAD"),
            Some(0)
        );
    }

    #[test]
    fn parse_reg_dword_is_case_insensitive_on_the_value_name() {
        assert_eq!(
            registry_ops::parse_reg_dword(REG_QUERY_OUTPUT, "DONTDISPLAYLASTUSERNAME"),
            Some(1)
        );
    }

    #[test]
    fn parse_reg_dword_returns_none_when_absent() {
        assert_eq!(
            registry_ops::parse_reg_dword(REG_QUERY_OUTPUT, "restrictanonymous"),
            None
        );
    }

    #[test]
    fn a_present_but_wrong_value_is_distinguishable() {
        // The old verify only checked that `reg query` exited 0, so a value
        // present with the wrong contents passed verification.
        assert_ne!(
            registry_ops::parse_reg_dword(REG_QUERY_OUTPUT, "DisableCAD"),
            Some(1)
        );
    }
}
