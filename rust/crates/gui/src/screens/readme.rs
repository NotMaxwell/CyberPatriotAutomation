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
use pinnacle_core::models::{AuthorizedUser, GroupRequirement, ReadmeData, SoftwareRequirement};

use super::file_browser;
use crate::state::{Action, AppState, Tab};
use crate::theme::{self, Tone};

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
        ui.horizontal(|ui| {
            if ui.add(theme::secondary_button("Browse...")).clicked() {
                file_browser::open(ui.ctx());
            }
            ui.add(
                egui::TextEdit::singleline(&mut state.readme_path)
                    .hint_text("path to a .html, .url or .desktop file")
                    .desired_width(f32::INFINITY),
            );
        });
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
    // Drawn after the picker so it stacks on top; it owns Escape while open.
    let browser_was_open = file_browser::is_open(ui.ctx());
    let browsed = file_browser::show(ui, state);
    if browsed.is_some() {
        return browsed;
    }
    if modal.should_close() && action.is_none() && !browser_was_open {
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
    let action = tab(ui, state);
    // While the picker is open it draws the browser itself, so it is not
    // drawn twice.
    let browsed = if state.locations_open {
        None
    } else {
        file_browser::show(ui, state)
    };
    action.or(browsed)
}

fn tab(ui: &mut egui::Ui, state: &mut AppState) -> Option<Action> {
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
                    editors(ui, state);
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
        ui.horizontal(|ui| {
            if ui.add(theme::primary_button("Choose README")).clicked() {
                action = Some(Action::ShowLocations(true));
            }
            if ui.add(theme::secondary_button("Browse...")).clicked() {
                file_browser::open(ui.ctx());
            }
        });
    });
    action
}

fn summary_card(ui: &mut egui::Ui, state: &AppState) -> Option<Action> {
    let mut action = None;
    let data = state.readme_data()?;
    theme::card(ui, |ui| {
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
        ui.add_space(theme::GAP);
        ui.horizontal(|ui| {
            if ui.add(theme::secondary_button("Change README")).clicked() {
                action = Some(Action::ShowLocations(true));
            }
            if ui.add(theme::secondary_button("Browse...")).clicked() {
                file_browser::open(ui.ctx());
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

// --- the editors -------------------------------------------------------------

/// Whether a section starts open. `PINNACLE_GUI_README_OPEN=all` opens every
/// section, for screenshots; a person gets the short list.
fn starts_open(default: bool) -> bool {
    default || std::env::var("PINNACLE_GUI_README_OPEN").is_ok_and(|v| v == "all")
}

/// Every README field a person can correct. Edits go to a copy that becomes
/// `state.edited` only if something changed, so merely looking never marks the
/// run as hand-edited.
fn editors(ui: &mut egui::Ui, state: &mut AppState) {
    let Some(mut data) = state.readme_data().cloned() else {
        return;
    };
    let mut changed = false;

    section_card(
        ui,
        "overview",
        "Overview",
        "What the round is and which machine it describes.",
        true,
        |ui| changed |= overview(ui, &mut data),
    );
    section_card(
        ui,
        "people",
        "People",
        "Who may be on the machine. Anyone else is flagged as unauthorised.",
        true,
        |ui| changed |= people(ui, &mut data),
    );
    section_card(
        ui,
        "software",
        "Software",
        "What must be installed and what must go.",
        false,
        |ui| changed |= software(ui, &mut data),
    );
    section_card(
        ui,
        "services",
        "Services",
        "Critical services are never stopped; prohibited ones are disabled.",
        false,
        |ui| changed |= services(ui, &mut data),
    );
    section_card(
        ui,
        "groups",
        "Groups",
        "Groups the README asks for, with their members.",
        false,
        |ui| changed |= groups(ui, &mut data),
    );
    section_card(
        ui,
        "other",
        "Other",
        "Accounts to create and the README's general rules.",
        false,
        |ui| changed |= other(ui, &mut data),
    );
    derived_card(ui, &data);

    if changed {
        commit(state, data);
    }
}

fn section_card(
    ui: &mut egui::Ui,
    id: &str,
    title: &str,
    subtitle: &str,
    open: bool,
    body: impl FnOnce(&mut egui::Ui),
) {
    theme::card(ui, |ui| {
        egui::CollapsingHeader::new(
            RichText::new(title)
                .size(16.5)
                .family(theme::bold_family())
                .color(theme::TEXT),
        )
        .id_salt(("readme-section", id))
        .default_open(starts_open(open))
        .show(ui, |ui| {
            ui.label(RichText::new(subtitle).size(13.0).color(theme::MUTED));
            ui.add_space(8.0);
            body(ui);
        });
    });
    ui.add_space(theme::GAP);
}

fn field_label(ui: &mut egui::Ui, text: &str) {
    ui.label(RichText::new(text).size(13.0).color(theme::MUTED));
}

fn overview(ui: &mut egui::Ui, d: &mut ReadmeData) -> bool {
    let mut changed = false;
    egui::Grid::new("readme-overview")
        .num_columns(2)
        .spacing([12.0, 8.0])
        .show(ui, |ui| {
            field_label(ui, "Title");
            changed |= ui
                .add(egui::TextEdit::singleline(&mut d.title).desired_width(f32::INFINITY))
                .changed();
            ui.end_row();
            field_label(ui, "Operating system");
            changed |= ui
                .add(
                    egui::TextEdit::singleline(&mut d.operating_system)
                        .desired_width(f32::INFINITY),
                )
                .changed();
            ui.end_row();
            ui.label(RichText::new("Scenario").size(13.0).color(theme::MUTED));
            changed |= ui
                .add(
                    egui::TextEdit::multiline(&mut d.scenario)
                        .desired_rows(4)
                        .desired_width(f32::INFINITY),
                )
                .changed();
            ui.end_row();
        });
    changed
}

fn people(ui: &mut egui::Ui, d: &mut ReadmeData) -> bool {
    let a = accounts(ui, "admins", "Administrators", &mut d.administrators, true);
    ui.add_space(theme::GAP);
    let u = accounts(ui, "users", "Users", &mut d.users, false);
    a | u
}

fn accounts(
    ui: &mut egui::Ui,
    salt: &str,
    title: &str,
    list: &mut Vec<AuthorizedUser>,
    admins: bool,
) -> bool {
    let mut changed = false;
    let show_id = ui.make_persistent_id(("show-passwords", salt));
    let mut show = ui.data(|d| d.get_temp::<bool>(show_id).unwrap_or(false));
    ui.horizontal(|ui| {
        ui.label(
            RichText::new(format!("{title} ({})", list.len()))
                .family(theme::bold_family())
                .size(14.5),
        );
        ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
            ui.checkbox(&mut show, "Show passwords");
        });
    });
    ui.data_mut(|d| d.insert_temp(show_id, show));

    let notes_w = (ui.available_width() - 130.0 - 120.0 - 56.0 - 62.0 - 70.0 - 5.0 * 8.0).max(70.0);
    let mut remove = None;
    if !list.is_empty() {
        egui::ScrollArea::vertical()
            .id_salt(("readme-accounts-scroll", salt))
            .max_height(280.0)
            .min_scrolled_height((list.len() as f32 * 38.0 + 34.0).min(280.0))
            .auto_shrink([false, true])
            .show(ui, |ui| {
                egui::Grid::new(("readme-accounts", salt))
                    .num_columns(6)
                    .spacing([8.0, 6.0])
                    .show(ui, |ui| {
                        for h in ["Username", "Password", "Admin", "Primary", "Notes", ""] {
                            field_label(ui, h);
                        }
                        ui.end_row();
                        for (i, u) in list.iter_mut().enumerate() {
                            changed |= cell(ui, 130.0, &mut u.username).changed();
                            let mut pw = u.password.clone().unwrap_or_default();
                            if ui
                                .add_sized(
                                    [120.0, CELL_H],
                                    egui::TextEdit::singleline(&mut pw)
                                        .password(password_masked(show)),
                                )
                                .changed()
                            {
                                set_optional(&mut u.password, &pw);
                                changed = true;
                            }
                            changed |= ui.checkbox(&mut u.is_admin, "").changed();
                            changed |= ui.checkbox(&mut u.is_primary_user, "").changed();
                            let mut notes = u.notes.clone().unwrap_or_default();
                            if cell(ui, notes_w, &mut notes).changed() {
                                set_optional(&mut u.notes, &notes);
                                changed = true;
                            }
                            if remove_button(ui) {
                                remove = Some(i);
                            }
                            ui.end_row();
                        }
                    });
            });
    } else {
        ui.label(theme::muted("none"));
    }
    if let Some(i) = remove {
        remove_at(list, i);
        changed = true;
    }
    ui.add_space(4.0);
    if let Some(name) = add_row(
        ui,
        ui.make_persistent_id(("new-account", salt)),
        if admins {
            "add an administrator"
        } else {
            "add a user"
        },
    ) {
        list.push(new_account(&name, admins));
        changed = true;
    }
    changed
}

fn software(ui: &mut egui::Ui, d: &mut ReadmeData) -> bool {
    let mut changed = false;
    ui.label(
        RichText::new(format!("Required software ({})", d.required_software.len()))
            .family(theme::bold_family())
            .size(14.5),
    );
    let notes_w = (ui.available_width() - 150.0 - 90.0 - 56.0 - 70.0 - 70.0 - 5.0 * 8.0).max(70.0);
    let mut remove = None;
    if d.required_software.is_empty() {
        ui.label(theme::muted("none"));
    } else {
        egui::Grid::new("readme-software")
            .num_columns(6)
            .spacing([8.0, 6.0])
            .show(ui, |ui| {
                for h in ["Name", "Version", "Latest", "Required", "Notes", ""] {
                    field_label(ui, h);
                }
                ui.end_row();
                for (i, s) in d.required_software.iter_mut().enumerate() {
                    changed |= cell(ui, 150.0, &mut s.name).changed();
                    let mut v = s.version.clone().unwrap_or_default();
                    if cell(ui, 90.0, &mut v).changed() {
                        set_optional(&mut s.version, &v);
                        changed = true;
                    }
                    changed |= ui.checkbox(&mut s.should_be_latest, "").changed();
                    changed |= ui.checkbox(&mut s.is_required, "").changed();
                    let mut n = s.notes.clone().unwrap_or_default();
                    if cell(ui, notes_w, &mut n).changed() {
                        set_optional(&mut s.notes, &n);
                        changed = true;
                    }
                    if remove_button(ui) {
                        remove = Some(i);
                    }
                    ui.end_row();
                }
            });
    }
    if let Some(i) = remove {
        remove_at(&mut d.required_software, i);
        changed = true;
    }
    ui.add_space(4.0);
    if let Some(name) = add_row(
        ui,
        ui.make_persistent_id("new-software"),
        "add required software",
    ) {
        d.required_software.push(new_software(&name));
        changed = true;
    }
    ui.add_space(theme::GAP);
    changed
        | string_list(
            ui,
            "prohibited-software",
            "Prohibited software",
            "add prohibited software",
            &mut d.prohibited_software,
        )
}

fn services(ui: &mut egui::Ui, d: &mut ReadmeData) -> bool {
    let mut changed = false;
    ui.columns(2, |cols| {
        changed |= string_list(
            &mut cols[0],
            "critical-services",
            "Critical services",
            "add a service",
            &mut d.critical_services,
        );
        changed |= string_list(
            &mut cols[1],
            "prohibited-services",
            "Prohibited services",
            "add a service",
            &mut d.prohibited_services,
        );
    });
    changed
}

fn groups(ui: &mut egui::Ui, d: &mut ReadmeData) -> bool {
    let mut changed = false;
    let mut remove_group = None;
    for (gi, g) in d.group_requirements.iter_mut().enumerate() {
        egui::Frame::new()
            .fill(theme::BG)
            .stroke(Stroke::new(1.0, theme::BORDER))
            .corner_radius(egui::CornerRadius::same(8))
            .inner_margin(egui::Margin::same(10))
            .show(ui, |ui| {
                ui.set_width(ui.available_width());
                ui.horizontal(|ui| {
                    field_label(ui, "Group");
                    changed |= ui
                        .add(
                            egui::TextEdit::singleline(&mut g.group_name)
                                .desired_width((ui.available_width() - 150.0).max(100.0)),
                        )
                        .changed();
                    if remove_button_labeled(ui, "Remove group") {
                        remove_group = Some(gi);
                    }
                });
                ui.add_space(4.0);
                let mut remove_member = None;
                ui.horizontal_wrapped(|ui| {
                    field_label(ui, "Members");
                    if g.members.is_empty() {
                        ui.label(theme::muted("none"));
                    }
                    for (mi, m) in g.members.iter().enumerate() {
                        egui::Frame::new()
                            .fill(theme::ACCENT_SOFT)
                            .corner_radius(egui::CornerRadius::same(255))
                            .inner_margin(egui::Margin::symmetric(10, 2))
                            .show(ui, |ui| {
                                ui.label(RichText::new(m).color(theme::ACCENT));
                                let x = egui::Button::new(
                                    RichText::new("x").color(theme::MUTED).size(12.5),
                                )
                                .frame(false);
                                if ui.add(x).on_hover_text("Remove from group").clicked() {
                                    remove_member = Some(mi);
                                }
                            });
                    }
                });
                if let Some(mi) = remove_member {
                    remove_at(&mut g.members, mi);
                    changed = true;
                }
                ui.add_space(4.0);
                if let Some(name) = add_row(
                    ui,
                    ui.make_persistent_id(("new-member", gi)),
                    "add a member",
                ) && add_member(g, &name)
                {
                    changed = true;
                }
            });
        ui.add_space(8.0);
    }
    if d.group_requirements.is_empty() {
        ui.label(theme::muted("none"));
    }
    if let Some(i) = remove_group {
        remove_at(&mut d.group_requirements, i);
        changed = true;
    }
    if let Some(name) = add_row(ui, ui.make_persistent_id("new-group"), "add a group") {
        d.group_requirements.push(new_group(&name));
        changed = true;
    }
    changed
}

fn other(ui: &mut egui::Ui, d: &mut ReadmeData) -> bool {
    let a = string_list(
        ui,
        "users-to-create",
        "Users to create",
        "add a username",
        &mut d.users_to_create,
    );
    ui.add_space(theme::GAP);
    let b = string_list(
        ui,
        "guidelines",
        "Guidelines",
        "add a guideline",
        &mut d.guidelines,
    );
    a | b
}

/// What the parser derived from the prose. Shown for context; correcting the
/// fields above is what changes the run.
fn derived_card(ui: &mut egui::Ui, d: &ReadmeData) {
    theme::card(ui, |ui| {
        egui::CollapsingHeader::new(
            RichText::new(format!(
                "Derived from the README ({} actions, {} sections)",
                d.actionable_items.len(),
                d.sections.len()
            ))
            .size(16.5)
            .family(theme::bold_family()),
        )
        .id_salt(("readme-section", "derived"))
        .default_open(starts_open(false))
        .show(ui, |ui| {
            ui.label(theme::muted(
                "Read-only. These follow from the text, not from the fields above.",
            ));
            ui.add_space(6.0);
            egui::ScrollArea::vertical()
                .id_salt("derived-scroll")
                .max_height(200.0)
                .auto_shrink([false, true])
                .show(ui, |ui| {
                    for item in &d.actionable_items {
                        ui.label(format!("{:?}: {}", item.item_type, item.description));
                    }
                    let mut keys: Vec<&String> = d.sections.keys().collect();
                    keys.sort();
                    if !keys.is_empty() {
                        ui.add_space(6.0);
                        ui.label(theme::muted(format!(
                            "Sections: {}",
                            keys.iter()
                                .map(|k| k.as_str())
                                .collect::<Vec<_>>()
                                .join(", ")
                        )));
                    }
                });
        });
    });
    ui.add_space(theme::GAP);
}

/// An editable list of strings, each row correctable in place.
fn string_list(
    ui: &mut egui::Ui,
    salt: &str,
    title: &str,
    hint: &str,
    items: &mut Vec<String>,
) -> bool {
    let mut changed = false;
    ui.label(
        RichText::new(format!("{title} ({})", items.len()))
            .family(theme::bold_family())
            .size(14.5),
    );
    let mut remove = None;
    egui::ScrollArea::vertical()
        .id_salt(("readme-list", salt))
        .max_height(200.0)
        .min_scrolled_height((items.len() as f32 * 34.0).clamp(24.0, 200.0))
        .auto_shrink([false, true])
        .show(ui, |ui| {
            if items.is_empty() {
                ui.label(theme::muted("none"));
            }
            for (i, item) in items.iter_mut().enumerate() {
                ui.horizontal(|ui| {
                    changed |= ui
                        .add(
                            egui::TextEdit::singleline(item)
                                .desired_width((ui.available_width() - 76.0).max(60.0)),
                        )
                        .changed();
                    if remove_button(ui) {
                        remove = Some(i);
                    }
                });
            }
        });
    if let Some(i) = remove {
        remove_at(items, i);
        changed = true;
    }
    ui.add_space(4.0);
    if let Some(text) = add_row(ui, ui.make_persistent_id(("new-item", salt)), hint)
        && add_item(items, &text)
    {
        changed = true;
    }
    changed
}

const CELL_H: f32 = 30.0;

/// A fixed-width text cell: `desired_width` alone is shrunk by the grid.
fn cell(ui: &mut egui::Ui, width: f32, text: &mut String) -> egui::Response {
    ui.add_sized([width, CELL_H], egui::TextEdit::singleline(text))
}

fn remove_button(ui: &mut egui::Ui) -> bool {
    remove_button_labeled(ui, "Remove")
}

fn remove_button_labeled(ui: &mut egui::Ui, label: &str) -> bool {
    let b = egui::Button::new(RichText::new(label).size(12.5).color(theme::MUTED)).frame(false);
    ui.add(b).clicked()
}

/// A text box and Add button; returns the trimmed text when submitted. The
/// half-typed text lives in egui memory under `id`.
fn add_row(ui: &mut egui::Ui, id: egui::Id, hint: &str) -> Option<String> {
    let mut text = ui.data_mut(|d| d.get_temp::<String>(id).unwrap_or_default());
    let mut out = None;
    ui.horizontal(|ui| {
        let field = ui.add(
            egui::TextEdit::singleline(&mut text)
                .hint_text(hint)
                .desired_width((ui.available_width() - 70.0).max(80.0)),
        );
        let enter = field.lost_focus() && ui.input(|i| i.key_pressed(egui::Key::Enter));
        if (ui.add(theme::secondary_button("Add")).clicked() || enter) && !text.trim().is_empty() {
            out = Some(text.trim().to_string());
            text.clear();
        }
    });
    ui.data_mut(|d| d.insert_temp(id, text));
    out
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

/// Passwords are hidden until the person asks to see them.
fn password_masked(show: bool) -> bool {
    !show
}

/// An emptied optional field is "not given", not an empty string: the run log
/// and the matching code read `None` as absent.
fn set_optional(slot: &mut Option<String>, text: &str) {
    *slot = if text.trim().is_empty() {
        None
    } else {
        Some(text.to_string())
    };
}

fn new_account(name: &str, is_admin: bool) -> AuthorizedUser {
    AuthorizedUser {
        username: name.trim().to_string(),
        is_admin,
        ..Default::default()
    }
}

fn new_software(name: &str) -> SoftwareRequirement {
    SoftwareRequirement {
        name: name.trim().to_string(),
        ..Default::default()
    }
}

fn new_group(name: &str) -> GroupRequirement {
    GroupRequirement {
        group_name: name.trim().to_string(),
        members: Vec::new(),
    }
}

fn remove_at<T>(list: &mut Vec<T>, i: usize) {
    if i < list.len() {
        list.remove(i);
    }
}

/// Add a non-empty entry; false (and no change) for blank text.
fn add_item(list: &mut Vec<String>, text: &str) -> bool {
    let t = text.trim();
    if t.is_empty() {
        return false;
    }
    list.push(t.to_string());
    true
}

/// Add a member unless the group already has that name (usernames are
/// compared case-insensitively on Windows and groups should not repeat them).
fn add_member(g: &mut GroupRequirement, name: &str) -> bool {
    let t = name.trim();
    if t.is_empty() || g.members.iter().any(|m| m.eq_ignore_ascii_case(t)) {
        return false;
    }
    g.members.push(t.to_string());
    true
}

/// Record edited data as the run's README data.
fn commit(state: &mut AppState, data: ReadmeData) {
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

    /// What the tab does: copy what is in force, change it, commit.
    fn edit(state: &mut AppState, f: impl FnOnce(&mut ReadmeData)) {
        let mut d = state.readme_data().cloned().unwrap_or_default();
        f(&mut d);
        commit(state, d);
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
        edit(&mut s, |d| remove_at(&mut d.users, 0));
        assert!(can_continue(&s).is_err());
    }

    #[test]
    fn adding_an_account_to_an_empty_readme_unblocks_it() {
        let mut s = state_with(Some(ReadmeData::default()));
        edit(&mut s, |d| {
            d.administrators.push(new_account(" root2 ", true))
        });
        assert!(can_continue(&s).is_ok());
        let a = &s.edited.as_ref().unwrap().administrators[0];
        assert_eq!(a.username, "root2");
        assert!(a.is_admin);
    }

    #[test]
    fn a_scalar_edit_becomes_the_override_and_leaves_the_parse_alone() {
        let mut s = state_with(Some(ReadmeData {
            title: "Round".into(),
            critical_services: vec!["ssh".into()],
            ..Default::default()
        }));
        edit(&mut s, |d| {
            d.title = "Round 2".into();
            d.operating_system = "Ubuntu 22".into();
            d.scenario = "A small office.".into();
        });
        let e = s.edited.as_ref().unwrap();
        assert_eq!(e.title, "Round 2");
        assert_eq!(e.operating_system, "Ubuntu 22");
        assert_eq!(e.scenario, "A small office.");
        assert_eq!(e.critical_services, ["ssh"], "other fields carry over");
        let parsed = s.inspection.as_ref().unwrap().data.as_ref().unwrap();
        assert_eq!(parsed.title, "Round");
        assert_eq!(s.readme_data().unwrap().title, "Round 2");
    }

    #[test]
    fn a_user_row_edit_maps_each_column() {
        let mut s = state_with(Some(ReadmeData {
            users: vec![user("bob")],
            ..Default::default()
        }));
        edit(&mut s, |d| {
            let u = &mut d.users[0];
            u.username = "robert".into();
            set_optional(&mut u.password, "hunter2");
            u.is_admin = true;
            u.is_primary_user = true;
            set_optional(&mut u.notes, "the intern");
        });
        let u = &s.edited.as_ref().unwrap().users[0];
        assert_eq!(u.username, "robert");
        assert_eq!(u.password.as_deref(), Some("hunter2"));
        assert!(u.is_admin && u.is_primary_user);
        assert_eq!(u.notes.as_deref(), Some("the intern"));
    }

    #[test]
    fn a_software_row_edit_maps_each_column() {
        let mut s = state_with(Some(ReadmeData::default()));
        edit(&mut s, |d| {
            d.required_software.push(new_software("firefox"))
        });
        assert!(s.edited.as_ref().unwrap().required_software[0].is_required);
        edit(&mut s, |d| {
            let r = &mut d.required_software[0];
            set_optional(&mut r.version, "128");
            r.should_be_latest = true;
            r.is_required = false;
            set_optional(&mut r.notes, "ESR");
        });
        let r = &s.edited.as_ref().unwrap().required_software[0];
        assert_eq!(r.version.as_deref(), Some("128"));
        assert!(r.should_be_latest && !r.is_required);
        assert_eq!(r.notes.as_deref(), Some("ESR"));
    }

    #[test]
    fn emptying_an_optional_field_makes_it_absent() {
        let mut v = Some("1.0".to_string());
        set_optional(&mut v, "   ");
        assert_eq!(v, None);
    }

    #[test]
    fn group_members_add_remove_and_never_repeat() {
        let mut s = state_with(Some(ReadmeData::default()));
        edit(&mut s, |d| d.group_requirements.push(new_group(" devs ")));
        edit(&mut s, |d| {
            let g = &mut d.group_requirements[0];
            assert!(add_member(g, "alice"));
            assert!(add_member(g, "bob"));
            assert!(!add_member(g, "ALICE"), "case-insensitive duplicate");
            assert!(!add_member(g, "  "));
        });
        edit(&mut s, |d| {
            remove_at(&mut d.group_requirements[0].members, 0)
        });
        let g = &s.edited.as_ref().unwrap().group_requirements[0];
        assert_eq!(g.group_name, "devs");
        assert_eq!(g.members, ["bob"]);
        edit(&mut s, |d| remove_at(&mut d.group_requirements, 0));
        assert!(s.edited.as_ref().unwrap().group_requirements.is_empty());
    }

    #[test]
    fn plain_lists_add_trimmed_and_ignore_blanks() {
        let mut list = vec!["ssh".to_string()];
        assert!(add_item(&mut list, " cups "));
        assert!(!add_item(&mut list, ""));
        remove_at(&mut list, 0);
        remove_at(&mut list, 9);
        assert_eq!(list, ["cups"]);
    }

    #[test]
    fn successive_edits_accumulate() {
        let mut s = state_with(Some(ReadmeData::default()));
        edit(&mut s, |d| d.prohibited_software.push("nmap".into()));
        edit(&mut s, |d| d.prohibited_software.push("john".into()));
        edit(&mut s, |d| remove_at(&mut d.prohibited_software, 0));
        assert_eq!(s.edited.unwrap().prohibited_software, ["john"]);
    }

    #[test]
    fn passwords_are_masked_unless_shown() {
        assert!(password_masked(false));
        assert!(!password_masked(true));
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
