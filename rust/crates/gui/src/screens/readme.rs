// =============================================================================
// PinnacleCyPat GUI - README tab and locations picker
// Copyright 2026 Maxwell McCormick
// SPDX-License-Identifier: Apache-2.0
// =============================================================================

//! The README tab (what was parsed, correct the lists) and the dialog that
//! chooses which README to parse.
//!
//! The decisions (may the run continue, what an edit does to the data, how the
//! directives are ordered, which candidates can be picked) are plain functions
//! below the drawing code so they are tested without egui.

use eframe::egui::{self, RichText, Stroke};
use pinnacle_core::app_config::ReadmeCandidate;
use pinnacle_core::directives::{Directive, Handling};
use pinnacle_core::models::{AuthorizedUser, ReadmeData};

use crate::state::{Action, AppState, Tab};
use crate::theme::{self, Tone};

/// The lists a person can correct by hand.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ListKind {
    Administrators,
    Users,
    CriticalServices,
    ProhibitedSoftware,
}

impl ListKind {
    const ALL: [ListKind; 4] = [
        ListKind::Administrators,
        ListKind::Users,
        ListKind::CriticalServices,
        ListKind::ProhibitedSoftware,
    ];

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

// --- the picker --------------------------------------------------------------

/// The README locations picker, drawn over every tab while
/// `state.locations_open`.
///
/// Closing it (Escape, a click outside) only hides it: the README tab already
/// explains what is lost without a README and offers "Choose README", so
/// closing never silently moves the person to another tab.
pub fn locations_dialog(ui: &mut egui::Ui, state: &mut AppState) -> Option<Action> {
    let mut action = None;
    let modal = egui::Modal::new(egui::Id::unique("readme-locations")).show(ui.ctx(), |ui| {
        ui.set_width(560.0);
        ui.label(
            RichText::new("Choose the README")
                .size(20.0)
                .family(theme::bold_family()),
        );
        ui.label(theme::muted(
            "The round's README says who may be on the machine and what must stay running.",
        ));
        ui.add_space(theme::GAP);

        if state.discovering {
            ui.horizontal(|ui| {
                ui.spinner();
                ui.label(theme::muted(
                    "Looking in C:\\CyberPatriot, /opt/CyberPatriot and every Desktop...",
                ));
            });
        } else {
            candidate_list(ui, state);
        }

        ui.add_space(theme::GAP);
        ui.label(RichText::new("Or enter a path by hand").family(theme::bold_family()));
        ui.add(
            egui::TextEdit::singleline(&mut state.readme_path)
                .hint_text("path to a .html, .url or .desktop file")
                .desired_width(f32::INFINITY),
        );
        ui.add_space(theme::GAP);

        ui.horizontal(|ui| {
            let ready = !state.readme_path.trim().is_empty();
            if ui
                .add_enabled(ready, theme::primary_button("Use this README"))
                .clicked()
            {
                action = Some(Action::UseReadme(state.readme_path.trim().to_string()));
            }
            if ui
                .add_enabled(!state.discovering, theme::secondary_button("Search again"))
                .clicked()
            {
                action = Some(Action::DiscoverReadme);
            }
            if ui
                .add(theme::secondary_button("Continue without README"))
                .clicked()
            {
                action = Some(Action::ContinueWithoutReadme);
            }
        });
    });
    if modal.should_close() && action.is_none() {
        action = Some(Action::ShowLocations(false));
    }
    action
}

fn candidate_list(ui: &mut egui::Ui, state: &mut AppState) {
    let candidates = state.candidates.clone().unwrap_or_default();
    if candidates.is_empty() {
        theme::callout(ui, Tone::Warning, |ui| {
            ui.label(
                RichText::new("No README was found")
                    .family(theme::bold_family())
                    .color(theme::WARNING),
            );
            ui.label(theme::muted(
                "Nothing at the usual places. Search again after copying it to the Desktop, \
                 or enter its path below.",
            ));
        });
        return;
    }
    ui.label(
        RichText::new(format!("Found {}", candidates.len()))
            .size(13.0)
            .color(theme::MUTED),
    );
    egui::ScrollArea::vertical()
        .max_height(230.0)
        .auto_shrink([true, true])
        .show(ui, |ui| {
            for (i, c) in candidates.iter().enumerate() {
                if candidate_card(ui, i, c, &state.readme_path)
                    && let Some(path) = &c.resolved
                {
                    state.readme_path = path.clone();
                }
                ui.add_space(6.0);
            }
        });
}

/// One selectable row; true when it was clicked and may be chosen.
fn candidate_card(ui: &mut egui::Ui, index: usize, c: &ReadmeCandidate, current: &str) -> bool {
    let selectable = candidate_selectable(c);
    let selected = selectable && c.resolved.as_deref() == Some(current);
    let (fill, stroke) = if selected {
        (theme::ACCENT_SOFT, Stroke::new(1.5, theme::ACCENT))
    } else {
        (theme::SURFACE, Stroke::new(1.0, theme::BORDER))
    };
    let name_colour = if selectable {
        theme::TEXT
    } else {
        theme::MUTED
    };
    let frame = egui::Frame::new()
        .fill(fill)
        .stroke(stroke)
        .corner_radius(egui::CornerRadius::same(8))
        .inner_margin(egui::Margin::symmetric(14, 10))
        .show(ui, |ui| {
            ui.set_width(ui.available_width());
            ui.label(
                RichText::new(file_name(&c.location))
                    .family(theme::bold_family())
                    .size(15.0)
                    .color(name_colour),
            );
            ui.label(RichText::new(&c.location).size(12.5).color(theme::MUTED));
            match (&c.resolved, &c.note) {
                (Some(r), _) if r != &c.location => {
                    ui.label(
                        RichText::new(format!("opens {r}"))
                            .size(12.5)
                            .color(theme::ACCENT),
                    );
                }
                (None, note) => {
                    let why = note.as_deref().unwrap_or("could not be followed");
                    ui.label(RichText::new(why).size(12.5).color(theme::WARNING));
                }
                _ => {}
            }
        });
    if !selectable {
        return false;
    }
    ui.interact(
        frame.response.rect,
        ui.make_persistent_id(("readme-candidate", index)),
        egui::Sense::click(),
    )
    .on_hover_cursor(egui::CursorIcon::PointingHand)
    .clicked()
}

// --- the tab -------------------------------------------------------------------

pub fn show(ui: &mut egui::Ui, state: &mut AppState) -> Option<Action> {
    let mut action = None;
    let subtitle = match state.readme_source() {
        Some(source) => format!("Read from {source}"),
        None => "No README loaded".to_string(),
    };
    theme::page_title(ui, "README", &subtitle);

    if state.inspecting {
        theme::card(ui, |ui| {
            ui.horizontal(|ui| {
                ui.spinner();
                ui.label("Reading the README...");
            });
        });
        return None;
    }
    if state.readme_data().is_none() {
        return no_readme(ui, state);
    }

    egui::ScrollArea::vertical()
        .auto_shrink([false, false])
        .show(ui, |ui| {
            egui::Frame::new()
                .inner_margin(egui::Margin {
                    right: 14,
                    ..Default::default()
                })
                .show(ui, |ui| {
                    if let Some(a) = summary_card(ui, state) {
                        action = Some(a);
                    }
                    ui.add_space(theme::GAP);
                    let directives = state
                        .inspection
                        .as_ref()
                        .map(|i| i.directives.clone())
                        .unwrap_or_default();
                    if !directives.is_empty() {
                        theme::card(ui, |ui| directives_section(ui, &directives));
                        ui.add_space(theme::GAP);
                    }
                    lists_section(ui, state);
                    if let Some(a) = footer(ui, state) {
                        action = Some(a);
                    }
                    ui.add_space(theme::GAP);
                });
        });
    action
}

fn no_readme(ui: &mut egui::Ui, state: &AppState) -> Option<Action> {
    let mut action = None;
    theme::card(ui, |ui| {
        theme::section(
            ui,
            "No README loaded",
            Some("The README is how the tool knows who belongs on this machine."),
        );
        let needing = state.tasks.iter().filter(|t| t.needs_readme).count();
        ui.label(format!(
            "Without it, the {needing} tasks that compare the machine against the README \
             (accounts, services, software) are switched off. Everything else still runs."
        ));
        ui.add_space(theme::GAP);
        if ui.add(theme::primary_button("Choose README")).clicked() {
            action = Some(Action::ShowLocations(true));
        }
    });
    action
}

fn summary_card(ui: &mut egui::Ui, state: &AppState) -> Option<Action> {
    let mut action = None;
    let data = state.readme_data()?;
    theme::card(ui, |ui| {
        ui.horizontal(|ui| {
            ui.vertical(|ui| {
                ui.label(
                    RichText::new(or_dash(&data.title))
                        .size(18.0)
                        .family(theme::bold_family()),
                );
                ui.label(theme::muted(format!(
                    "{}  |  {}",
                    or_dash(&data.operating_system),
                    state.readme_source().unwrap_or("-")
                )));
            });
            ui.with_layout(egui::Layout::right_to_left(egui::Align::TOP), |ui| {
                if ui.add(theme::secondary_button("Change README")).clicked() {
                    action = Some(Action::ShowLocations(true));
                }
            });
        });
        ui.add_space(theme::GAP);
        ui.horizontal_wrapped(|ui| {
            for (label, n) in [
                ("Administrators", data.administrators.len()),
                ("Users", data.users.len()),
                ("Groups", data.group_requirements.len()),
                ("Critical services", data.critical_services.len()),
                ("Prohibited software", data.prohibited_software.len()),
            ] {
                theme::stat(ui, label, n.to_string(), Tone::Neutral);
            }
        });
    });
    action
}

fn directives_section(ui: &mut egui::Ui, directives: &[Directive]) {
    theme::section(
        ui,
        "What this round asks for",
        Some("The README's own sentences, sorted by who does the work."),
    );
    let (manual, automated, untouched) = grouped_directives(directives);

    if !manual.is_empty() {
        theme::callout(ui, Tone::Warning, |ui| {
            ui.label(
                RichText::new(format!("Do these by hand ({})", manual.len()))
                    .family(theme::bold_family())
                    .color(theme::WARNING),
            );
            ui.label(theme::muted("The tool cannot do these for you."));
            for d in &manual {
                directive_row(ui, d);
            }
        });
        ui.add_space(6.0);
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
    egui::CollapsingHeader::new(
        RichText::new(format!("{title} ({})", items.len())).family(theme::bold_family()),
    )
    .id_salt(title)
    .default_open(false)
    .show(ui, |ui| {
        ui.label(theme::muted(note));
        for d in items {
            directive_row(ui, d);
        }
    });
}

fn directive_row(ui: &mut egui::Ui, d: &Directive) {
    ui.add_space(4.0);
    ui.label(RichText::new(d.subject).family(theme::bold_family()));
    ui.label(&d.sentence);
    ui.label(
        RichText::new(d.handling.detail())
            .size(12.5)
            .color(theme::MUTED),
    );
}

fn lists_section(ui: &mut egui::Ui, state: &mut AppState) {
    let Some(data) = state.readme_data().cloned() else {
        return;
    };
    let mut edit = None;
    for pair in ListKind::ALL.chunks(2) {
        ui.columns(2, |cols| {
            for (col, kind) in cols.iter_mut().zip(pair) {
                theme::card(col, |ui| {
                    if let Some(e) = list_editor(ui, *kind, &names(&data, *kind)) {
                        edit = Some((*kind, e));
                    }
                });
            }
        });
        ui.add_space(theme::GAP);
    }
    if let Some((kind, e)) = edit {
        with_edit(state, kind, e);
    }
}

fn list_editor(ui: &mut egui::Ui, kind: ListKind, items: &[String]) -> Option<ListEdit> {
    let mut edit = None;
    let id = ui.make_persistent_id(("readme_list", kind.title()));
    theme::section(ui, &format!("{} ({})", kind.title(), items.len()), None);
    egui::ScrollArea::vertical()
        .id_salt(id)
        .max_height(190.0)
        .min_scrolled_height(190.0_f32.min(items.len() as f32 * 38.0))
        .auto_shrink([false, true])
        .show(ui, |ui| {
            if items.is_empty() {
                ui.label(theme::muted("none"));
            }
            for (i, item) in items.iter().enumerate() {
                ui.horizontal(|ui| {
                    ui.label(item);
                    ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                        let remove = egui::Button::new(
                            RichText::new("Remove").size(12.5).color(theme::MUTED),
                        )
                        .frame(false);
                        if ui.add(remove).clicked() {
                            edit = Some(ListEdit::Remove(i));
                        }
                    });
                });
            }
        });
    ui.add_space(4.0);
    let input_id = id.with("new");
    let mut text = ui.data_mut(|d| d.get_temp::<String>(input_id).unwrap_or_default());
    ui.horizontal(|ui| {
        let field = ui.add(
            egui::TextEdit::singleline(&mut text)
                .hint_text("add an entry")
                .desired_width((ui.available_width() - 70.0).max(80.0)),
        );
        let enter = field.lost_focus() && ui.input(|i| i.key_pressed(egui::Key::Enter));
        if (ui.add(theme::secondary_button("Add")).clicked() || enter) && !text.trim().is_empty() {
            edit = Some(ListEdit::Add(text.trim().to_string()));
            text.clear();
        }
    });
    ui.data_mut(|d| d.insert_temp(input_id, text));
    edit
}

fn footer(ui: &mut egui::Ui, state: &mut AppState) -> Option<Action> {
    let mut action = None;
    if state.edited.is_some() {
        theme::callout(ui, Tone::Warning, |ui| {
            ui.horizontal(|ui| {
                ui.label(
                    RichText::new("Edited by hand - the run log records the difference")
                        .color(theme::WARNING)
                        .family(theme::bold_family()),
                );
                if ui
                    .add(theme::secondary_button("Revert to parsed"))
                    .clicked()
                {
                    state.edited = None;
                }
            });
        });
        ui.add_space(theme::GAP);
    }
    let verdict = can_continue(state);
    if let Err(reason) = &verdict {
        theme::callout(ui, Tone::Danger, |ui| {
            ui.label(
                RichText::new("The run cannot continue")
                    .family(theme::bold_family())
                    .color(theme::DANGER),
            );
            ui.label(reason);
        });
        ui.add_space(theme::GAP);
    }
    if ui
        .add_enabled(verdict.is_ok(), theme::primary_button("Continue to Run"))
        .clicked()
    {
        action = Some(Action::OpenTab(Tab::Run));
    }
    action
}

fn or_dash(s: &str) -> &str {
    if s.trim().is_empty() { "-" } else { s }
}

fn file_name(location: &str) -> &str {
    location
        .rsplit(['/', '\\'])
        .find(|s| !s.is_empty())
        .unwrap_or(location)
}

// --- decisions -------------------------------------------------------------

/// A candidate that could not be followed to a document has nothing to parse.
fn candidate_selectable(c: &ReadmeCandidate) -> bool {
    c.resolved.is_some()
}

/// May the user leave this tab for Run?
///
/// Refuses only when a README is present but names no administrators and no
/// users: with an empty authorised list every account would look unauthorised.
/// No README at all is allowed; Run disables tasks that need one.
fn can_continue(state: &AppState) -> Result<(), String> {
    if state.inspecting {
        return Err("Still reading the README.".to_string());
    }
    match state.readme_data() {
        Some(d) if d.administrators.is_empty() && d.users.is_empty() => Err(
            "No administrators or users were found in the README. An empty roster makes every \
             account look unauthorised, so the tool would flag all of them. Add the \
             authorised accounts above, or choose a different README."
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

    #[test]
    fn only_a_followable_candidate_can_be_picked() {
        let ok = ReadmeCandidate {
            location: "/opt/CyberPatriot/README.html".into(),
            resolved: Some("/opt/CyberPatriot/README.html".into()),
            note: None,
        };
        let broken = ReadmeCandidate {
            location: "/root/Desktop/x.desktop".into(),
            resolved: None,
            note: Some("no URL".into()),
        };
        assert!(candidate_selectable(&ok));
        assert!(!candidate_selectable(&broken));
    }

    #[test]
    fn file_names_come_from_either_separator() {
        assert_eq!(file_name("C:\\CyberPatriot\\README.url"), "README.url");
        assert_eq!(file_name("/opt/CyberPatriot/README.html"), "README.html");
    }
}
