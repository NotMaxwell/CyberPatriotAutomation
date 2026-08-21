//! Base trait for remediation tasks.

use crate::command;
use crate::models::{SystemInfo, TaskResult};
use async_trait::async_trait;

/// Split one line of `ConvertTo-Csv` output into its fields.
///
/// Quotes are kept in the returned fields so callers can `trim_matches('"')`,
/// matching how PowerShell emits them; a comma inside quotes does not split.
pub fn parse_csv_line(line: &str) -> Vec<String> {
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

/// Read the members of a local group via `net localgroup <group>`.
///
/// The output wraps the member list in a header, a dashed separator and a
/// trailing "The command completed successfully." line:
///
/// ```text
/// Alias name     Administrators
/// Comment        Administrators have complete and unrestricted access ...
/// Members
/// -------------------------------------------------------------------------------
/// Administrator
/// Bob
/// The command completed successfully.
/// ```
///
/// Only the lines between the separator and the trailing status line are
/// members. Callers previously substring-searched the whole blob, which matched
/// the surrounding prose - a user called "admin" matched the word
/// "Administrators" in the header and was wrongly treated as an administrator.
pub async fn local_group_members(group: &str) -> Vec<String> {
    // netapi32 returns the members as data, so there is nothing to parse and
    // nothing that depends on the console language. The parser below stays as
    // the fallback for the rare case the call itself fails.
    #[cfg(windows)]
    if let Some(members) = crate::native::accounts::group_members(group) {
        return members;
    }

    let (success, output, _e) =
        command::execute("net", Some(&format!("localgroup \"{group}\""))).await;
    if !success {
        return Vec::new();
    }
    parse_local_group_members(&output)
}

/// Split `net localgroup` output into member names. Separated from the command
/// execution so it can be tested without a Windows host.
pub fn parse_local_group_members(output: &str) -> Vec<String> {
    let mut members = Vec::new();
    let mut past_separator = false;
    for line in output.lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        if line.starts_with("---") {
            past_separator = true;
            continue;
        }
        if !past_separator {
            continue;
        }
        // `net` ends the listing with a localised status sentence; it always
        // contains a space, which a bare account name never has to.
        if line.starts_with("The command completed") {
            break;
        }
        members.push(line.to_string());
    }
    members
}

/// Is `username` one of `members`? Handles the `DOMAIN\user` form that `net`
/// prints for non-local accounts.
pub fn is_group_member(members: &[String], username: &str) -> bool {
    members.iter().any(|m| {
        let bare = m.rsplit('\\').next().unwrap_or(m);
        m.eq_ignore_ascii_case(username) || bare.eq_ignore_ascii_case(username)
    })
}

/// Base trait for remediation tasks (mirrors the C# `BaseTask`).
#[async_trait]
pub trait Task: Send {
    fn name(&self) -> &str;
    fn description(&self) -> &str;

    /// When true, only preview changes without applying them.
    fn dry_run(&self) -> bool;
    fn set_dry_run(&mut self, value: bool);

    /// Read current system state for this task area.
    async fn read_system_state(&mut self) -> SystemInfo;

    /// Execute the remediation for this task.
    async fn execute(&mut self) -> TaskResult;

    /// Verify that the remediation was successful.
    async fn verify(&mut self) -> bool;
}

/// Implements the metadata accessors of [`Task`] for a struct that has
/// `name: String`, `description: String`, and `dry_run: bool` fields.
#[macro_export]
macro_rules! impl_task_meta {
    () => {
        fn name(&self) -> &str {
            &self.name
        }
        fn description(&self) -> &str {
            &self.description
        }
        fn dry_run(&self) -> bool {
            self.dry_run
        }
        fn set_dry_run(&mut self, value: bool) {
            self.dry_run = value;
        }
    };
}
