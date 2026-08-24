// =============================================================================
// PinnacleCyPat - User management (Linux)
// Author: Maxwell McCormick
// Copyright 2026 Maxwell McCormick
// SPDX-License-Identifier: Apache-2.0
// =============================================================================

//! Makes the machine's human accounts match the README's list.
//!
//! This is the task where the platform split earns its keep: the *decisions*
//! here - who is authorised, who is an administrator, who should not exist -
//! are read out of `ReadmeData` by exactly the same code that drives the
//! Windows version. Only the verbs differ (`useradd` for `net user`, `gpasswd`
//! for `net localgroup`), and those live in `user_ops`.
//!
//! **Without a README this task refuses to act.** An empty authorised list
//! would otherwise mean "nobody is authorised", and the difference it acts on
//! would be every account on the image. Reporting success having deleted the
//! machine's users is far worse than doing nothing.
//!
//! Removed accounts keep their home directories. An unauthorised account's home
//! is often where the answer to a forensics question is, and deleting it
//! destroys evidence for a point the tool cannot score anyway.

use std::collections::HashSet;

use pinnacle_core::models::{ReadmeData, SystemInfo, TaskResult};
use pinnacle_core::task::Task;
use pinnacle_core::{impl_task_meta, ui};

use crate::knowledge::{ADMIN_GROUPS, SYSTEM_ACCOUNTS};
use crate::user_ops;
use async_trait::async_trait;

/// Strong passwords, one per account.
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

/// Is this password strong enough to leave alone?
///
/// A README publishes its administrators' passwords, and CyberPatriot scores
/// noticing that one of them is weak - in the Ubuntu Exhibition Round it is
/// `grilledcheese`, worth six points.
///
/// **The README's own password set calibrates this, and it says the
/// discriminator is character classes rather than length.** From that round:
///
/// | Password | Length | Classes | Scored as weak? |
/// |---|---|---|---|
/// | `M4mm@lOfAct!0n` | 14 | 4 | no |
/// | `No#1UnP@!dInt3rn` | 16 | 4 | no |
/// | `Go0glyMo0gly!` | 13 | 4 | no |
/// | `Adm!r@l4cr0nym` | 14 | 4 | no |
/// | `grilledcheese` | 13 | 1 | **yes** |
///
/// `grilledcheese` and `Go0glyMo0gly!` are the same length. A length rule that
/// caught the first would have caught the second too, and resetting a password
/// the README published as valid locks the competitor out of an account they
/// were told they could use - a worse outcome than the six points.
///
/// So the length floor is deliberately below the round's shortest accepted
/// password, and all four character classes are required.
///
/// This is a *lower* bar than the `minlen = 14` the hardening task writes into
/// `pwquality.conf`, and deliberately so: that policy governs passwords chosen
/// from now on, while this answers the narrower question of whether an existing
/// password is bad enough to be worth replacing.
pub fn is_secure_password(password: &str) -> bool {
    // Counted in characters, not bytes: a password with an accented letter is
    // shorter than `len()` suggests, and rejecting it for being too short when
    // it is not is exactly the false positive described above.
    if password.chars().count() < MIN_PASSWORD_LENGTH {
        return false;
    }
    password.chars().any(|c| c.is_uppercase())
        && password.chars().any(|c| c.is_lowercase())
        && password.chars().any(|c| c.is_numeric())
        && password.chars().any(|c| !c.is_alphanumeric())
}

/// One below the shortest password the Exhibition Round answer key accepts, so
/// that a README-published password is judged on its character classes.
const MIN_PASSWORD_LENGTH: usize = 12;

/// The administrators whose README-published password is too weak to keep.
///
/// The primary user is deliberately excluded. The README says so in as many
/// words — *you are NOT required to change the password of the primary,
/// auto-login, user account* — and changing it can lock the competitor out of
/// the machine mid-round.
pub fn accounts_with_weak_passwords(readme: &ReadmeData) -> Vec<String> {
    readme
        .administrators
        .iter()
        .chain(readme.users.iter())
        .filter(|account| !account.is_primary_user)
        .filter(|account| {
            account
                .password
                .as_deref()
                .is_some_and(|password| !is_secure_password(password))
        })
        .map(|account| account.username.clone())
        .collect()
}

/// The group that grants administrative rights on *this* image.
///
/// Debian and Ubuntu use `sudo`, Red Hat uses `wheel`. Picking the one the
/// image actually has avoids creating a second, meaningless group - adding a
/// user to a `wheel` group that no `sudoers` rule references grants nothing,
/// while appearing to have worked.
async fn admin_group() -> &'static str {
    let text = tokio::fs::read_to_string("/etc/group")
        .await
        .unwrap_or_default();
    let existing = user_ops::parse_group(&text);
    for candidate in ADMIN_GROUPS {
        if existing.iter().any(|(g, _, _)| g == candidate) {
            return candidate;
        }
    }
    "sudo"
}

pub struct UserManagementTask {
    name: String,
    description: String,
    dry_run: bool,
    readme_data: Option<ReadmeData>,
}

impl UserManagementTask {
    pub fn new() -> Self {
        Self {
            name: "User Management".to_string(),
            description: "Create, remove and correct user accounts".to_string(),
            dry_run: false,
            readme_data: None,
        }
    }

    pub fn set_readme_data(&mut self, data: ReadmeData) {
        self.readme_data = Some(data);
    }
}

impl Default for UserManagementTask {
    fn default() -> Self {
        Self::new()
    }
}

/// What the README says the machine's accounts should look like.
pub struct Authorised {
    pub everyone: HashSet<String>,
    pub admins: HashSet<String>,
    pub to_create: Vec<String>,
}

/// Read the account plan out of a README.
///
/// Separated from the task so the decisions can be tested against real parsed
/// READMEs with no machine involved - which is where the Windows equivalent's
/// bugs were found.
pub fn authorised_from(readme: &ReadmeData) -> Authorised {
    let admins: HashSet<String> = readme
        .administrators
        .iter()
        .map(|u| u.username.to_lowercase())
        .collect();

    let mut everyone = admins.clone();
    everyone.extend(readme.users.iter().map(|u| u.username.to_lowercase()));
    everyone.extend(readme.users_to_create.iter().map(|u| u.to_lowercase()));

    // A group requirement naming a member is an authorisation too. Without
    // this, a user listed only under "add these people to the developers
    // group" is treated as unauthorised and deleted.
    //
    // A requirement naming an *admin* group is also a grant of administrative
    // rights, which is how several READMEs express it rather than by listing
    // the person under "Authorized Administrators".
    let mut admins = admins;
    for group in &readme.group_requirements {
        everyone.extend(group.members.iter().map(|m| m.to_lowercase()));
        if ADMIN_GROUPS
            .iter()
            .any(|a| a.eq_ignore_ascii_case(&group.group_name))
        {
            admins.extend(group.members.iter().map(|m| m.to_lowercase()));
        }
    }

    Authorised {
        everyone,
        admins,
        to_create: readme.users_to_create.clone(),
    }
}

/// Accounts on the machine that the README does not authorise.
///
/// System accounts are excluded twice over - by uid and by name - because
/// acting on the raw difference would delete every account a package created.
pub fn unauthorised(present: &[user_ops::Account], authorised: &HashSet<String>) -> Vec<String> {
    present
        .iter()
        .filter(|a| a.is_human())
        .filter(|a| !authorised.contains(&a.name.to_lowercase()))
        .filter(|a| {
            !SYSTEM_ACCOUNTS
                .iter()
                .any(|s| s.eq_ignore_ascii_case(&a.name))
        })
        .map(|a| a.name.clone())
        .collect()
}

#[async_trait]
impl Task for UserManagementTask {
    impl_task_meta!();

    async fn read_system_state(&mut self) -> SystemInfo {
        let accounts = user_ops::human_accounts().await;
        let admins = user_ops::administrators().await;
        SystemInfo {
            raw_output: Some(format!(
                "users: {}\nadministrators: {}",
                accounts
                    .iter()
                    .map(|a| a.name.as_str())
                    .collect::<Vec<_>>()
                    .join(", "),
                admins.join(", ")
            )),
            ..Default::default()
        }
    }

    async fn execute(&mut self) -> TaskResult {
        let mut result = TaskResult {
            task_name: self.name.clone(),
            success: true,
            ..Default::default()
        };

        let Some(readme) = self.readme_data.clone() else {
            // Not a failure: the task was asked to run and correctly declined.
            // Treating it as one would make `--all` report a failing run on
            // every image where no README was supplied.
            result.message = "No README data provided; no accounts were changed.".to_string();
            ui::markup_line(
                "[yellow]⚠ User Management needs a README to tell authorised accounts from \
                 unauthorised ones. Nothing was changed.[/]",
            );
            return result;
        };

        let plan = authorised_from(&readme);
        let present = user_ops::accounts().await;
        let surplus = unauthorised(&present, &plan.everyone);
        let group = admin_group().await;
        let current_admins = user_ops::administrators().await;

        let missing: Vec<&String> = plan
            .to_create
            .iter()
            .filter(|u| !present.iter().any(|a| a.name.eq_ignore_ascii_case(u)))
            .collect();

        // Accounts whose README-published password is too weak to keep, and
        // that actually exist on this machine.
        let weak: Vec<String> = accounts_with_weak_passwords(&readme)
            .into_iter()
            .filter(|name| present.iter().any(|a| a.name.eq_ignore_ascii_case(name)))
            .collect();

        result.items_attempted =
            (surplus.len() + missing.len() + plan.admins.len() + weak.len()) as i32;

        if self.dry_run {
            for user in &missing {
                ui::markup_line(&format!("[cyan]Would create: {}[/]", ui::escape(user)));
            }
            for user in &surplus {
                ui::markup_line(&format!(
                    "[cyan]Would remove: {} [dim](keeping the home directory)[/][/]",
                    ui::escape(user)
                ));
            }
            for user in &weak {
                ui::markup_line(&format!(
                    "[cyan]Would reset the password of: {} [dim](the README's own password \
                     is too weak)[/][/]",
                    ui::escape(user)
                ));
            }
            result.message = format!(
                "DRY RUN: would create {}, remove {} and reset {} passwords.",
                missing.len(),
                surplus.len(),
                weak.len()
            );
            return result;
        }

        let mut failures: Vec<String> = Vec::new();

        // Create first. An account named both as "to create" and as an
        // administrator has to exist before it can be put in the admin group.
        for (index, user) in missing.iter().enumerate() {
            match user_ops::create(user, "the README lists it as an authorised account").await {
                Ok(()) => {
                    result.items_succeeded += 1;
                    ui::markup_line(&format!("[green]✓ Created: {}[/]", ui::escape(user)));
                    // The generated password is written to the ledger as
                    // "set to a generated value" and never printed, so it does
                    // not end up in a run log that gets committed.
                    if let Err(e) = user_ops::set_password(user, &generate_password(index)).await {
                        failures.push(format!("{user}: could not set a password ({e})"));
                    }
                }
                Err(e) => failures.push(format!("{user}: {e}")),
            }
        }

        // Administrative rights, in both directions.
        for admin in &plan.admins {
            if !user_ops::exists(admin).await {
                continue;
            }
            if let Err(e) =
                user_ops::add_to_group(admin, group, "the README lists them as an administrator")
                    .await
            {
                failures.push(format!("{admin}: {e}"));
            } else {
                result.items_succeeded += 1;
            }
        }
        for admin in &current_admins {
            if plan.admins.contains(&admin.to_lowercase()) || admin == "root" {
                continue;
            }
            if let Err(e) = user_ops::remove_from_group(
                admin,
                group,
                "the README does not list them as an administrator",
            )
            .await
            {
                failures.push(format!("{admin}: {e}"));
            } else {
                ui::markup_line(&format!(
                    "[green]✓ Removed administrative rights: {}[/]",
                    ui::escape(admin)
                ));
            }
        }

        // Replace the weak published passwords. The README says in as many words
        // not to touch the primary user's, which `accounts_with_weak_passwords`
        // already excludes - changing an auto-login account's password can lock
        // the competitor out of the machine mid-round.
        for (index, user) in weak.iter().enumerate() {
            // Offset so a reset password never collides with one just issued to
            // a newly created account.
            let password = generate_password(missing.len() + index);
            match user_ops::set_password(user, &password).await {
                Ok(()) => {
                    result.items_succeeded += 1;
                    // The password itself is never printed. It reaches the
                    // ledger as "set to a generated value", so a run log that
                    // gets committed does not carry it.
                    ui::markup_line(&format!(
                        "[green]✓ Reset the password of: {} [dim](the README's own was too \
                         weak)[/][/]",
                        ui::escape(user)
                    ));
                }
                Err(e) => failures.push(format!("{user}: could not reset the password ({e})")),
            }
        }

        for user in &surplus {
            match user_ops::delete(user, "the README does not list this account").await {
                Ok(()) => {
                    result.items_succeeded += 1;
                    ui::markup_line(&format!(
                        "[green]✓ Removed: {} [dim](home directory kept as evidence)[/][/]",
                        ui::escape(user)
                    ));
                }
                Err(e) => failures.push(format!("{user}: {e}")),
            }
        }

        result.success = failures.is_empty();
        result.message = format!(
            "Created {}, removed {}, reset {} passwords, corrected administrative rights.",
            missing.len(),
            surplus.len(),
            weak.len()
        );
        if !failures.is_empty() {
            result.error_details = Some(failures.join("; "));
        }
        result
    }

    async fn verify(&mut self) -> bool {
        let Some(readme) = &self.readme_data else {
            // Nothing was claimed, so there is nothing to disprove.
            return true;
        };
        let plan = authorised_from(readme);
        let present = user_ops::accounts().await;
        if !unauthorised(&present, &plan.everyone).is_empty() {
            return false;
        }
        for user in &plan.to_create {
            if !present.iter().any(|a| a.name.eq_ignore_ascii_case(user)) {
                return false;
            }
        }
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use pinnacle_core::models::{AuthorizedUser, GroupRequirement};

    fn user(name: &str, admin: bool) -> AuthorizedUser {
        AuthorizedUser {
            username: name.to_string(),
            password: None,
            is_admin: admin,
            is_primary_user: false,
            notes: None,
        }
    }

    fn account(name: &str, uid: u32) -> user_ops::Account {
        user_ops::Account {
            name: name.to_string(),
            uid,
            gid: uid,
            comment: String::new(),
            home: format!("/home/{name}"),
            shell: "/bin/bash".to_string(),
        }
    }

    #[test]
    fn administrators_and_users_are_both_authorised() {
        let readme = ReadmeData {
            administrators: vec![user("alice", true)],
            users: vec![user("bob", false)],
            ..Default::default()
        };
        let plan = authorised_from(&readme);
        assert!(plan.everyone.contains("alice"));
        assert!(plan.everyone.contains("bob"));
        assert!(plan.admins.contains("alice"));
        assert!(!plan.admins.contains("bob"));
    }

    /// A user named only under a group requirement is still authorised.
    /// Missing this deletes someone the README explicitly mentioned - the same
    /// class of bug the group-member parser had.
    #[test]
    fn a_user_named_only_in_a_group_requirement_is_authorised() {
        let readme = ReadmeData {
            administrators: vec![user("alice", true)],
            group_requirements: vec![GroupRequirement {
                group_name: "developers".to_string(),
                members: vec!["carol".to_string(), "dave".to_string()],
            }],
            ..Default::default()
        };
        let plan = authorised_from(&readme);
        assert!(plan.everyone.contains("carol"));
        assert!(plan.everyone.contains("dave"));
    }

    /// Several READMEs grant administrative rights by naming the sudo group
    /// rather than by listing the person as an administrator. Reading only the
    /// administrators table would then strip the rights the README just gave.
    #[test]
    fn membership_of_an_admin_group_grants_administrative_rights() {
        let readme = ReadmeData {
            group_requirements: vec![GroupRequirement {
                group_name: "sudo".to_string(),
                members: vec!["erin".to_string()],
            }],
            ..Default::default()
        };
        let plan = authorised_from(&readme);
        assert!(plan.admins.contains("erin"));
        assert!(plan.everyone.contains("erin"));
    }

    /// ...but an ordinary group is not an admin group.
    #[test]
    fn membership_of_an_ordinary_group_grants_nothing_extra() {
        let readme = ReadmeData {
            group_requirements: vec![GroupRequirement {
                group_name: "developers".to_string(),
                members: vec!["carol".to_string()],
            }],
            ..Default::default()
        };
        let plan = authorised_from(&readme);
        assert!(plan.everyone.contains("carol"));
        assert!(!plan.admins.contains("carol"));
    }

    /// The rule that stands between a short README and an unbootable image.
    #[test]
    fn system_accounts_are_never_unauthorised() {
        let present = vec![
            account("root", 0),
            account("www-data", 33),
            account("nobody", 65534),
            account("syslog", 104),
            account("mallory", 1002),
        ];
        let authorised: HashSet<String> = ["alice".to_string()].into_iter().collect();
        assert_eq!(unauthorised(&present, &authorised), ["mallory"]);
    }

    #[test]
    fn authorisation_is_case_insensitive() {
        let present = vec![account("Alice", 1000)];
        let authorised: HashSet<String> = ["alice".to_string()].into_iter().collect();
        assert!(unauthorised(&present, &authorised).is_empty());
    }

    /// Calibrated against the Ubuntu Exhibition Round answer key, which scores
    /// exactly one of these five as weak. The pair that matters is
    /// `grilledcheese` and `Go0glyMo0gly!`: both thirteen characters, and only
    /// the first is a finding.
    #[test]
    fn readme_published_passwords_are_judged_on_character_classes() {
        assert!(
            !is_secure_password("grilledcheese"),
            "one class, scored weak"
        );
        for strong in [
            "M4mm@lOfAct!0n",
            "No#1UnP@!dInt3rn",
            "Go0glyMo0gly!",
            "Adm!r@l4cr0nym",
        ] {
            assert!(
                is_secure_password(strong),
                "{strong} is accepted by the key and must not be reset"
            );
        }
    }

    /// Each class missing on its own is enough to fail.
    #[test]
    fn a_password_missing_any_one_class_is_weak() {
        assert!(!is_secure_password("nouppercase1!"), "no upper case");
        assert!(!is_secure_password("NOLOWERCASE1!"), "no lower case");
        assert!(!is_secure_password("NoDigitsHere!"), "no digit");
        assert!(!is_secure_password("NoSymbolsHere1"), "no symbol");
        assert!(!is_secure_password("Sh0rt!"), "too short");
    }

    /// The README says in as many words not to change the primary user's
    /// password, because it auto-logs in and changing it can lock the
    /// competitor out of the machine mid-round.
    #[test]
    fn the_primary_users_password_is_never_reset() {
        let readme = ReadmeData {
            administrators: vec![
                AuthorizedUser {
                    username: "perry".to_string(),
                    password: Some("weak".to_string()),
                    is_admin: true,
                    is_primary_user: true,
                    notes: None,
                },
                AuthorizedUser {
                    username: "pinky".to_string(),
                    password: Some("grilledcheese".to_string()),
                    is_admin: true,
                    is_primary_user: false,
                    notes: None,
                },
            ],
            ..Default::default()
        };
        assert_eq!(accounts_with_weak_passwords(&readme), ["pinky"]);
    }

    /// An account the README lists without a password says nothing about its
    /// strength, and guessing would reset every user on the image.
    #[test]
    fn an_account_with_no_published_password_is_left_alone() {
        let readme = ReadmeData {
            users: vec![user("bob", false)],
            ..Default::default()
        };
        assert!(accounts_with_weak_passwords(&readme).is_empty());
    }

    /// Every account gets a distinct password. Cycling the fixed list alone
    /// repeated them once there were more accounts than entries.
    #[test]
    fn generated_passwords_are_distinct_and_strong() {
        let generated: HashSet<String> = (0..25).map(generate_password).collect();
        assert_eq!(generated.len(), 25);
        for password in &generated {
            assert!(password.len() >= 14, "too short: {password}");
            assert!(password.chars().any(|c| c.is_ascii_uppercase()));
            assert!(password.chars().any(|c| c.is_ascii_lowercase()));
            assert!(password.chars().any(|c| c.is_ascii_digit()));
            assert!(password.chars().any(|c| !c.is_alphanumeric()));
        }
    }

    /// Without a README the task must change nothing and must not report a
    /// failure - "nothing to do" and "could not do it" are different facts.
    #[tokio::test]
    async fn without_a_readme_nothing_is_touched() {
        let mut task = UserManagementTask::new();
        let (result, _lines) = pinnacle_core::ui::capture(task.execute()).await;
        assert!(result.success);
        assert_eq!(result.items_attempted, 0);
        assert!(result.message.contains("No README"), "{}", result.message);
    }

    #[test]
    fn a_readme_with_no_accounts_authorises_nobody_but_removes_no_system_account() {
        let plan = authorised_from(&ReadmeData::default());
        assert!(plan.everyone.is_empty());
        let present = vec![account("root", 0), account("www-data", 33)];
        assert!(unauthorised(&present, &plan.everyone).is_empty());
    }
}
