// =============================================================================
// PinnacleCyPat GUI - Readme screen
// Copyright 2026 Maxwell McCormick
// SPDX-License-Identifier: Apache-2.0
// =============================================================================

//! Step 1: pick the README, see what was parsed, correct the lists.
//!
//! The decisions (may the run continue, what an edit does to the data, how the
//! directives are ordered) are plain functions below the drawing code so they
//! are tested without egui.

use eframe::egui::{self, Color32, RichText};
use pinnacle_core::directives::{Directive, Handling};
use pinnacle_core::engine::ReadmeChoice;
use pinnacle_core::models::{AuthorizedUser, ReadmeData};

use crate::state::{Action, AppState, Screen};

const WARN: Color32 = Color32::from_rgb(240, 190, 80);
const BAD: Color32 = Color32::from_rgb(240, 110, 110);

/// The lists a person can correct by hand.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ListKind {
    Administrators,
    Users,
    CriticalServices,
    ProhibitedSoftware,
}

impl ListKind {
    fn title(self) -> &'static str {
        match self {
            ListKind::Administrators => "Administrators",
            ListKind::Users => "Users",
            ListKind::CriticalServices => "Critical services",
            ListKind::ProhibitedSoftware => "Prohibited software",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum ListEdit {
    Add(String),
    Remove(usize),
}

pub fn show(ui: &mut egui::Ui, state: &mut AppState) -> Option<Action> {
    let mut action = None;

    egui::Panel::bottom("readme_nav").show(ui, |ui| {
        ui.add_space(6.0);
        ui.horizontal(|ui| {
            let verdict = can_continue(state);
            let next = ui.add_enabled(verdict.is_ok(), egui::Button::new("Next: choose tasks"));
            if next.clicked() {
                action = Some(Action::Go(Screen::Tasks));
            }
            match &verdict {
                Err(reason) => {
                    ui.colored_label(BAD, reason);
                }
                Ok(()) if state.readme_data().is_none() && !state.inspecting => {
                    ui.colored_label(
                        WARN,
                        "No README loaded: tasks that need one will be unavailable.",
                    );
                }
                Ok(()) => {}
            }
        });
        ui.add_space(6.0);
    });

    egui::ScrollArea::vertical()
        .auto_shrink([false, false])
        .show(ui, |ui| {
            if let Some(a) = source_section(ui, state) {
                action = Some(a);
            }
            ui.add_space(8.0);
            if !state.inspecting && state.inspection.is_some() {
                parsed_section(ui, state);
            }
        });

    action
}

fn source_section(ui: &mut egui::Ui, state: &mut AppState) -> Option<Action> {
    let mut action = None;
    ui.heading("README source");
    ui.horizontal(|ui| {
        ui.add(
            egui::TextEdit::singleline(&mut state.readme_path)
                .hint_text("empty = find automatically")
                .desired_width((ui.available_width() - 260.0).max(120.0)),
        );
        let idle = !state.inspecting;
        if ui
            .add_enabled(idle, egui::Button::new("Find automatically"))
            .clicked()
        {
            action = Some(Action::Inspect(ReadmeChoice::Auto));
        }
        if ui.add_enabled(idle, egui::Button::new("Load")).clicked() {
            action = Some(Action::Inspect(state.readme_choice()));
        }
    });
    ui.weak("Type or paste the path to the README (.html or .url). There is no file browser here.");
    if state.inspecting {
        ui.horizontal(|ui| {
            ui.spinner();
            ui.label("Reading the README...");
        });
    }
    action
}

fn parsed_section(ui: &mut egui::Ui, state: &mut AppState) {
    let Some(inspection) = state.inspection.clone() else {
        return;
    };
    match &inspection.source {
        Some(source) => {
            ui.horizontal_wrapped(|ui| {
                ui.strong("Parsed:");
                ui.monospace(source);
            });
        }
        None => {
            ui.colored_label(WARN, "No README was found.");
            if !inspection.attempts.is_empty() {
                ui.label("Locations checked:");
                for attempt in &inspection.attempts {
                    ui.monospace(format!("  {attempt}"));
                }
            }
        }
    }
    if inspection.source.is_some() && inspection.data.is_none() {
        ui.colored_label(BAD, "The file could not be read as a README.");
    }

    if !inspection.directives.is_empty() {
        ui.add_space(10.0);
        directives_section(ui, &inspection.directives);
    }

    if state.readme_data().is_some() {
        ui.add_space(6.0);
        edited_banner(ui, state);
        ui.add_space(6.0);
        data_section(ui, state);
    }
}

fn edited_banner(ui: &mut egui::Ui, state: &mut AppState) {
    if state.edited.is_none() {
        return;
    }
    egui::Frame::group(ui.style())
        .stroke(egui::Stroke::new(1.0, WARN))
        .show(ui, |ui| {
            ui.horizontal(|ui| {
                ui.colored_label(
                    WARN,
                    "Edited by hand - the run log will record the difference.",
                );
                if ui.button("Revert to parsed").clicked() {
                    state.edited = None;
                }
            });
        });
}

fn data_section(ui: &mut egui::Ui, state: &mut AppState) {
    let Some(data) = state.readme_data().cloned() else {
        return;
    };
    ui.heading("What was parsed");
    egui::Grid::new("readme_facts")
        .num_columns(2)
        .spacing([12.0, 4.0])
        .show(ui, |ui| {
            ui.strong("Title");
            ui.label(or_dash(&data.title));
            ui.end_row();
            ui.strong("Operating system");
            ui.label(or_dash(&data.operating_system));
            ui.end_row();
        });
    ui.add_space(6.0);

    let mut edit = None;
    for kind in [
        ListKind::Administrators,
        ListKind::Users,
        ListKind::CriticalServices,
        ListKind::ProhibitedSoftware,
    ] {
        if let Some(e) = list_editor(ui, kind, &names(&data, kind)) {
            edit = Some((kind, e));
        }
    }
    if let Some((kind, e)) = edit {
        with_edit(state, kind, e);
    }

    ui.add_space(6.0);
    egui::CollapsingHeader::new(format!("Groups ({})", data.group_requirements.len()))
        .id_salt("groups")
        .default_open(true)
        .show(ui, |ui| {
            if data.group_requirements.is_empty() {
                ui.weak("none");
            }
            for g in &data.group_requirements {
                ui.label(format!("{}: {}", g.group_name, g.members.join(", ")));
            }
        });
    egui::CollapsingHeader::new(format!(
        "Required software ({})",
        data.required_software.len()
    ))
    .id_salt("required")
    .default_open(true)
    .show(ui, |ui| {
        if data.required_software.is_empty() {
            ui.weak("none");
        }
        for s in &data.required_software {
            match &s.version {
                Some(v) => ui.label(format!("{} {v}", s.name)),
                None => ui.label(&s.name),
            };
        }
    });
}

fn list_editor(ui: &mut egui::Ui, kind: ListKind, items: &[String]) -> Option<ListEdit> {
    let mut edit = None;
    let id = ui.make_persistent_id(("readme_list", kind.title()));
    egui::CollapsingHeader::new(format!("{} ({})", kind.title(), items.len()))
        .id_salt(id)
        // A long roster would push everything below it off screen.
        .default_open(items.len() <= 8)
        .show(ui, |ui| {
            if items.is_empty() {
                ui.weak("none");
            }
            for (i, item) in items.iter().enumerate() {
                ui.horizontal(|ui| {
                    if ui.small_button("Remove").clicked() {
                        edit = Some(ListEdit::Remove(i));
                    }
                    ui.label(item);
                });
            }
            let input_id = id.with("new");
            let mut text = ui.data_mut(|d| d.get_temp::<String>(input_id).unwrap_or_default());
            ui.horizontal(|ui| {
                let field = ui.add(
                    egui::TextEdit::singleline(&mut text)
                        .hint_text("add an entry")
                        .desired_width(200.0),
                );
                let enter = field.lost_focus() && ui.input(|i| i.key_pressed(egui::Key::Enter));
                if (ui.button("Add").clicked() || enter) && !text.trim().is_empty() {
                    edit = Some(ListEdit::Add(text.trim().to_string()));
                    text.clear();
                }
            });
            ui.data_mut(|d| d.insert_temp(input_id, text));
        });
    edit
}

fn directives_section(ui: &mut egui::Ui, directives: &[Directive]) {
    ui.heading("What this round asks for");
    let (manual, automated, untouched) = grouped_directives(directives);

    if !manual.is_empty() {
        egui::Frame::group(ui.style())
            .stroke(egui::Stroke::new(1.5, WARN))
            .show(ui, |ui| {
                ui.colored_label(
                    WARN,
                    RichText::new(format!("Do these by hand ({})", manual.len())).strong(),
                );
                ui.weak("The tool cannot do these for you.");
                for d in &manual {
                    directive_row(ui, d);
                }
            });
        ui.add_space(4.0);
    }
    directive_group(
        ui,
        "Handled by the tool",
        "Automated: the matching task does this.",
        &automated,
    );
    directive_group(
        ui,
        "Left alone on purpose",
        "Not touched: doing nothing is the safe choice.",
        &untouched,
    );
}

fn directive_group(ui: &mut egui::Ui, title: &str, note: &str, items: &[&Directive]) {
    if items.is_empty() {
        return;
    }
    egui::CollapsingHeader::new(format!("{title} ({})", items.len()))
        .id_salt(title)
        .default_open(false)
        .show(ui, |ui| {
            ui.weak(note);
            for d in items {
                directive_row(ui, d);
            }
        });
}

fn directive_row(ui: &mut egui::Ui, d: &Directive) {
    ui.add_space(2.0);
    ui.label(RichText::new(d.subject).strong());
    ui.label(&d.sentence);
    ui.weak(d.handling.detail());
}

fn or_dash(s: &str) -> &str {
    if s.trim().is_empty() { "-" } else { s }
}

// --- decisions -------------------------------------------------------------

/// May the user leave this screen?
///
/// Refuses only when a README is present but names no administrators and no
/// users: with an empty authorised list every account would look unauthorised.
/// No README at all is allowed; the next screen disables tasks that need one.
fn can_continue(state: &AppState) -> Result<(), String> {
    if state.inspecting {
        return Err("Still reading the README.".to_string());
    }
    match state.readme_data() {
        Some(d) if d.administrators.is_empty() && d.users.is_empty() => Err(
            "No administrators or users were found in the README; an empty list would make \
             every account look unauthorised."
                .to_string(),
        ),
        _ => Ok(()),
    }
}

fn names(data: &ReadmeData, kind: ListKind) -> Vec<String> {
    match kind {
        ListKind::Administrators => data
            .administrators
            .iter()
            .map(|u| u.username.clone())
            .collect(),
        ListKind::Users => data.users.iter().map(|u| u.username.clone()).collect(),
        ListKind::CriticalServices => data.critical_services.clone(),
        ListKind::ProhibitedSoftware => data.prohibited_software.clone(),
    }
}

fn apply_edit(data: &mut ReadmeData, kind: ListKind, edit: ListEdit) {
    fn on<T>(list: &mut Vec<T>, edit: ListEdit, make: impl FnOnce(String) -> T) {
        match edit {
            ListEdit::Add(name) => list.push(make(name)),
            ListEdit::Remove(i) if i < list.len() => {
                list.remove(i);
            }
            ListEdit::Remove(_) => {}
        }
    }
    let account = |is_admin| {
        move |username| AuthorizedUser {
            username,
            is_admin,
            ..Default::default()
        }
    };
    match kind {
        ListKind::Administrators => on(&mut data.administrators, edit, account(true)),
        ListKind::Users => on(&mut data.users, edit, account(false)),
        ListKind::CriticalServices => on(&mut data.critical_services, edit, |s| s),
        ListKind::ProhibitedSoftware => on(&mut data.prohibited_software, edit, |s| s),
    }
}

/// Record an edit as the run's README data, starting from what is in force
/// now so earlier edits and the untouched fields carry over.
fn with_edit(state: &mut AppState, kind: ListKind, edit: ListEdit) {
    let mut data = state.readme_data().cloned().unwrap_or_default();
    apply_edit(&mut data, kind, edit);
    state.edited = Some(data);
}

type Grouped<'a> = (Vec<&'a Directive>, Vec<&'a Directive>, Vec<&'a Directive>);

/// By-hand, automated, left-alone. Forensics questions lead the by-hand group:
/// they are worth the most points and are the easiest to forget.
fn grouped_directives(directives: &[Directive]) -> Grouped<'_> {
    let pick = |f: fn(&Handling) -> bool| -> Vec<&Directive> {
        directives.iter().filter(|d| f(&d.handling)).collect()
    };
    let mut manual = pick(|h| matches!(h, Handling::Manual(_)));
    manual.sort_by_key(|d| !d.subject.to_lowercase().contains("forensic"));
    (
        manual,
        pick(|h| matches!(h, Handling::Automated(_))),
        pick(|h| matches!(h, Handling::SafeByInaction(_))),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use pinnacle_core::engine::ReadmeInspection;

    fn user(name: &str) -> AuthorizedUser {
        AuthorizedUser {
            username: name.to_string(),
            ..Default::default()
        }
    }

    fn state_with(data: Option<ReadmeData>) -> AppState {
        let mut s = AppState::new(&[], true, "root", "use sudo");
        s.inspection = Some(ReadmeInspection {
            source: data.as_ref().map(|_| "README.html".to_string()),
            data,
            ..Default::default()
        });
        s
    }

    fn directive(subject: &'static str, handling: Handling) -> Directive {
        Directive {
            subject,
            sentence: String::new(),
            handling,
        }
    }

    #[test]
    fn a_readme_with_no_accounts_cannot_continue() {
        let s = state_with(Some(ReadmeData::default()));
        assert!(can_continue(&s).unwrap_err().contains("unauthorised"));
    }

    #[test]
    fn one_administrator_or_one_user_is_enough_to_continue() {
        let admins = ReadmeData {
            administrators: vec![user("alice")],
            ..Default::default()
        };
        assert!(can_continue(&state_with(Some(admins))).is_ok());
        let users = ReadmeData {
            users: vec![user("bob")],
            ..Default::default()
        };
        assert!(can_continue(&state_with(Some(users))).is_ok());
    }

    #[test]
    fn no_readme_at_all_may_continue() {
        assert!(can_continue(&state_with(None)).is_ok());
    }

    #[test]
    fn removing_the_last_account_by_hand_blocks_continuing() {
        let mut s = state_with(Some(ReadmeData {
            users: vec![user("bob")],
            ..Default::default()
        }));
        with_edit(&mut s, ListKind::Users, ListEdit::Remove(0));
        assert!(can_continue(&s).is_err());
    }

    #[test]
    fn adding_an_account_to_an_empty_readme_unblocks_it() {
        let mut s = state_with(Some(ReadmeData::default()));
        with_edit(
            &mut s,
            ListKind::Administrators,
            ListEdit::Add("root2".into()),
        );
        assert!(can_continue(&s).is_ok());
        assert!(s.edited.as_ref().unwrap().administrators[0].is_admin);
    }

    #[test]
    fn an_edit_becomes_the_override_and_leaves_the_parse_alone() {
        let mut s = state_with(Some(ReadmeData {
            title: "Round".into(),
            critical_services: vec!["ssh".into()],
            ..Default::default()
        }));
        with_edit(
            &mut s,
            ListKind::CriticalServices,
            ListEdit::Add("cups".into()),
        );
        let edited = s.edited.as_ref().unwrap();
        assert_eq!(edited.critical_services, ["ssh", "cups"]);
        assert_eq!(edited.title, "Round", "other fields carry over");
        let parsed = s.inspection.as_ref().unwrap().data.as_ref().unwrap();
        assert_eq!(parsed.critical_services, ["ssh"]);
        assert_eq!(s.readme_data().unwrap().critical_services, ["ssh", "cups"]);
    }

    #[test]
    fn successive_edits_accumulate() {
        let mut s = state_with(Some(ReadmeData::default()));
        for e in [
            ListEdit::Add("nmap".into()),
            ListEdit::Add("john".into()),
            ListEdit::Remove(0),
        ] {
            with_edit(&mut s, ListKind::ProhibitedSoftware, e);
        }
        assert_eq!(s.edited.unwrap().prohibited_software, ["john"]);
    }

    #[test]
    fn removing_past_the_end_changes_nothing() {
        let mut data = ReadmeData {
            critical_services: vec!["ssh".into()],
            ..Default::default()
        };
        apply_edit(&mut data, ListKind::CriticalServices, ListEdit::Remove(5));
        assert_eq!(data.critical_services, ["ssh"]);
    }

    #[test]
    fn forensics_leads_the_by_hand_group() {
        let ds = [
            directive("a service", Handling::Automated("x")),
            directive("something else", Handling::Manual("y")),
            directive("forensics questions", Handling::Manual("z")),
            directive("media", Handling::SafeByInaction("w")),
        ];
        let (manual, automated, untouched) = grouped_directives(&ds);
        assert_eq!(manual[0].subject, "forensics questions");
        assert_eq!(manual.len(), 2);
        assert_eq!(automated.len(), 1);
        assert_eq!(untouched.len(), 1);
    }
}
