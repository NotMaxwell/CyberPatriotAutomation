// =============================================================================
// PinnacleCyPat GUI - File browser dialog
// Copyright 2026 Maxwell McCormick
// SPDX-License-Identifier: Apache-2.0
// =============================================================================

//! A modal file browser for choosing a README. The listing and the notion of
//! "README-like" come from `pinnacle_core::files`, shared with the web UI.
//!
//! Open/close state lives in egui memory so no tab has to carry it:
//! [`open`] from anywhere, [`show`] from an entry point that runs every frame.
//!
//! **Test hooks** (they only open a read-only dialog): `PINNACLE_GUI_BROWSE=1`
//! opens the browser on the first frame; `PINNACLE_GUI_BROWSE_DIR=<dir>`
//! starts it there.

use std::path::Path;
use std::sync::Arc;

use eframe::egui::{self, Align2, FontId, RichText, Sense};
use pinnacle_core::files::{self, Entry, Listing};

use crate::state::{Action, AppState};
use crate::theme::{self, Tone};

fn state_id() -> egui::Id {
    egui::Id::NULL.with("file-browser-state")
}
fn last_dir_id() -> egui::Id {
    egui::Id::NULL.with("file-browser-last-dir")
}
fn hook_id() -> egui::Id {
    egui::Id::NULL.with("file-browser-hook-done")
}

#[derive(Clone)]
struct Browser {
    open: bool,
    dir: String,
    /// The path bar's text; differs from `dir` while being typed.
    path_text: String,
    readme_only: bool,
    selected: Option<Selection>,
    /// What was last listed, so a change of directory or filter reloads.
    loaded: Option<(String, bool)>,
    listing: Option<Result<Arc<Listing>, String>>,
}

#[derive(Clone, PartialEq, Eq, Debug)]
struct Selection {
    path: String,
    is_dir: bool,
}

/// What activating a row or pressing Open does.
#[derive(Debug, PartialEq, Eq)]
enum Activate {
    Enter(String),
    Pick(String),
}

/// What a typed path names.
#[derive(Debug, PartialEq, Eq)]
enum Typed {
    Dir(String),
    File(String),
    Missing,
}

/// Open the browser at the last directory used (or the competition folder).
pub fn open(ctx: &egui::Context) {
    open_at(ctx, None);
}

fn open_at(ctx: &egui::Context, dir: Option<String>) {
    let dir = dir
        .or_else(|| ctx.data(|d| d.get_temp::<String>(last_dir_id())))
        .unwrap_or_else(|| files::start_dir().to_string_lossy().into_owned());
    ctx.data_mut(|d| {
        d.insert_temp(
            state_id(),
            Browser {
                open: true,
                path_text: dir.clone(),
                dir,
                readme_only: true,
                selected: None,
                loaded: None,
                listing: None,
            },
        )
    });
}

pub fn is_open(ctx: &egui::Context) -> bool {
    ctx.data(|d| d.get_temp::<Browser>(state_id()))
        .is_some_and(|b| b.open)
}

/// Draw the browser if it is open; `Some(UseReadme)` when a file was chosen.
pub fn show(ui: &mut egui::Ui, _state: &mut AppState) -> Option<Action> {
    let ctx = ui.ctx().clone();
    let first_frame = !ctx.data(|d| d.get_temp::<bool>(hook_id()).unwrap_or(false));
    if first_frame {
        ctx.data_mut(|d| d.insert_temp(hook_id(), true));
        if std::env::var("PINNACLE_GUI_BROWSE").is_ok_and(|v| v == "1") {
            open_at(&ctx, std::env::var("PINNACLE_GUI_BROWSE_DIR").ok());
        }
    }
    if !is_open(&ctx) {
        return None;
    }
    let mut b = ctx.data(|d| d.get_temp::<Browser>(state_id()))?;
    let mut picked = None;
    let mut cancel = false;

    if b.loaded.as_ref() != Some(&(b.dir.clone(), b.readme_only)) {
        b.listing = Some(
            files::list_dir(Path::new(&b.dir), b.readme_only)
                .map(Arc::new)
                .map_err(|e| format!("Cannot open {}: {e}", b.dir)),
        );
        b.loaded = Some((b.dir.clone(), b.readme_only));
        if let Some(Ok(l)) = &b.listing {
            // The listing canonicalises: follow it so Up works from symlinks.
            b.dir = l.path.clone();
            b.path_text = l.path.clone();
            b.loaded = Some((b.dir.clone(), b.readme_only));
            ctx.data_mut(|d| d.insert_temp(last_dir_id(), b.dir.clone()));
        }
    }

    let list_height = (ctx.content_rect().height() - 330.0).clamp(120.0, 320.0);
    let modal = egui::Modal::new(egui::Id::unique("file-browser"))
        .frame(egui::Frame::popup(ui.style()).inner_margin(egui::Margin::same(18)))
        .show(&ctx, |ui| {
        ui.set_width(620.0_f32.min(ctx.content_rect().width() - 80.0));
        ui.label(
            RichText::new("Choose a README file")
                .size(20.0)
                .family(theme::bold_family()),
        );
        ui.label(theme::muted(
            "Pick the round's README (.html), or a shortcut to it (.url, .desktop).",
        ));
        ui.add_space(theme::GAP);

        let parent = match &b.listing {
            Some(Ok(l)) => l.parent.clone(),
            _ => Path::new(&b.dir)
                .parent()
                .map(|p| p.to_string_lossy().into_owned()),
        };
        let mut goto: Option<String> = None;

        ui.horizontal(|ui| {
            if ui
                .add_enabled(parent.is_some(), theme::secondary_button("Up"))
                .clicked()
            {
                goto = parent;
            }
            let bar = ui.add(
                egui::TextEdit::singleline(&mut b.path_text)
                    .desired_width(ui.available_width())
                    .margin(egui::Margin::symmetric(8, 8)),
            );
            if bar.lost_focus() && ui.input(|i| i.key_pressed(egui::Key::Enter)) {
                match resolve_typed(&b.path_text) {
                    Typed::Dir(p) => goto = Some(p),
                    Typed::File(p) => {
                        b.selected = Some(Selection {
                            path: p,
                            is_dir: false,
                        })
                    }
                    Typed::Missing => {
                        b.listing = Some(Err(format!("{} does not exist.", b.path_text.trim())));
                    }
                }
            }
        });
        ui.add_space(6.0);
        ui.horizontal_wrapped(|ui| {
            ui.label(theme::muted("Go to"));
            for root in files::roots() {
                if ui.add(theme::secondary_button(&root)).clicked() {
                    goto = Some(root);
                }
            }
            if ui
                .add(theme::secondary_button("Competition folder"))
                .clicked()
            {
                goto = Some(files::start_dir().to_string_lossy().into_owned());
            }
        });
        ui.add_space(theme::GAP);

        let selected = b.selected.clone();
        let readme_only = b.readme_only;
        let listing = b.listing.clone();
        let mut new_selection = None;
        egui::Frame::new()
            .stroke(egui::Stroke::new(1.0, theme::BORDER))
            .corner_radius(egui::CornerRadius::same(8))
            .inner_margin(egui::Margin::same(4))
            .show(ui, |ui| {
                egui::ScrollArea::vertical()
                    .max_height(list_height)
                    .min_scrolled_height(list_height)
                    .auto_shrink([false, false])
                    .show(ui, |ui| match &listing {
                        Some(Err(msg)) => {
                            theme::callout(ui, Tone::Danger, |ui| {
                                ui.label(RichText::new(msg).color(theme::DANGER));
                            });
                        }
                        Some(Ok(l)) if l.entries.is_empty() => {
                            ui.add_space(8.0);
                            ui.label(theme::muted(if readme_only {
                                "No folders or README files here. Untick the filter to see every file."
                            } else {
                                "This folder is empty."
                            }));
                        }
                        Some(Ok(l)) => {
                            for e in &l.entries {
                                let is_sel = selected.as_ref().is_some_and(|s| s.path == e.path);
                                let r = entry_row(ui, e, is_sel);
                                if r.clicked() {
                                    new_selection = Some(Selection {
                                        path: e.path.clone(),
                                        is_dir: e.is_dir,
                                    });
                                }
                                if r.double_clicked() {
                                    match double_click(e) {
                                        Activate::Enter(p) => goto = Some(p),
                                        Activate::Pick(p) => picked = Some(p),
                                    }
                                }
                            }
                        }
                        None => {}
                    });
            });
        if new_selection.is_some() {
            b.selected = new_selection;
        }
        ui.add_space(8.0);
        if ui
            .checkbox(&mut b.readme_only, "Show only README files")
            .changed()
        {
            b.selected = None;
        }
        ui.add_space(theme::GAP);

        ui.horizontal(|ui| {
            let label = match &b.selected {
                Some(s) if s.is_dir => "Open folder",
                _ => "Open",
            };
            if ui
                .add_enabled(b.selected.is_some(), theme::primary_button(label))
                .clicked()
                && let Some(act) = open_target(b.selected.as_ref())
            {
                match act {
                    Activate::Enter(p) => goto = Some(p),
                    Activate::Pick(p) => picked = Some(p),
                }
            }
            if ui.add(theme::secondary_button("Cancel")).clicked() {
                cancel = true;
            }
            if let Some(s) = &b.selected {
                ui.label(theme::muted(file_name(&s.path)));
            }
        });

        if let Some(dir) = goto {
            b.path_text = dir.clone();
            b.dir = dir;
            b.selected = None;
        }
    });
    if modal.should_close() {
        cancel = true;
    }

    let action = picked.map(Action::UseReadme);
    b.open = !(cancel || action.is_some());
    ctx.data_mut(|d| d.insert_temp(state_id(), b));
    action
}

fn entry_row(ui: &mut egui::Ui, e: &Entry, selected: bool) -> egui::Response {
    let (rect, resp) =
        ui.allocate_exact_size(egui::vec2(ui.available_width(), 28.0), Sense::click());
    let fill = if selected {
        theme::ACCENT_SOFT
    } else if resp.hovered() {
        theme::BG
    } else {
        egui::Color32::TRANSPARENT
    };
    ui.painter()
        .rect_filled(rect, egui::CornerRadius::same(6), fill);
    let highlighted = e.readme_like;
    let colour = if highlighted {
        theme::ACCENT
    } else {
        theme::TEXT
    };
    let family = if highlighted || e.is_dir {
        theme::bold_family()
    } else {
        egui::FontFamily::Proportional
    };
    ui.painter().text(
        rect.left_center() + egui::vec2(10.0, 0.0),
        Align2::LEFT_CENTER,
        &e.name,
        FontId::new(14.0, family),
        colour,
    );
    let tag = if e.is_dir {
        "Folder"
    } else if highlighted {
        "README"
    } else {
        "File"
    };
    ui.painter().text(
        rect.right_center() - egui::vec2(10.0, 0.0),
        Align2::RIGHT_CENTER,
        tag,
        FontId::new(12.5, egui::FontFamily::Proportional),
        if highlighted {
            theme::ACCENT
        } else {
            theme::MUTED
        },
    );
    resp.on_hover_cursor(egui::CursorIcon::PointingHand)
}

// --- pure rules -------------------------------------------------------------

/// A folder is entered, a file is picked.
fn double_click(e: &Entry) -> Activate {
    if e.is_dir {
        Activate::Enter(e.path.clone())
    } else {
        Activate::Pick(e.path.clone())
    }
}

/// What the Open button does with the current selection.
fn open_target(sel: Option<&Selection>) -> Option<Activate> {
    sel.map(|s| {
        if s.is_dir {
            Activate::Enter(s.path.clone())
        } else {
            Activate::Pick(s.path.clone())
        }
    })
}

fn resolve_typed(text: &str) -> Typed {
    let text = text.trim();
    let p = Path::new(text);
    if text.is_empty() {
        Typed::Missing
    } else if p.is_dir() {
        Typed::Dir(text.to_string())
    } else if p.is_file() {
        Typed::File(text.to_string())
    } else {
        Typed::Missing
    }
}

fn file_name(path: &str) -> &str {
    path.rsplit(['/', '\\'])
        .find(|s| !s.is_empty())
        .unwrap_or(path)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry(name: &str, is_dir: bool) -> Entry {
        Entry {
            name: name.into(),
            path: format!("/x/{name}"),
            is_dir,
            readme_like: !is_dir && files::readme_like(name),
        }
    }

    #[test]
    fn double_clicking_a_folder_enters_and_a_file_picks() {
        assert_eq!(
            double_click(&entry("sub", true)),
            Activate::Enter("/x/sub".into())
        );
        assert_eq!(
            double_click(&entry("README.html", false)),
            Activate::Pick("/x/README.html".into())
        );
    }

    #[test]
    fn open_picks_a_file_enters_a_folder_and_needs_a_selection() {
        assert_eq!(open_target(None), None);
        let file = Selection {
            path: "/x/a.html".into(),
            is_dir: false,
        };
        let dir = Selection {
            path: "/x/d".into(),
            is_dir: true,
        };
        assert_eq!(
            open_target(Some(&file)),
            Some(Activate::Pick("/x/a.html".into()))
        );
        assert_eq!(
            open_target(Some(&dir)),
            Some(Activate::Enter("/x/d".into()))
        );
    }

    #[test]
    fn a_typed_path_is_classified_and_trimmed() {
        let root = std::env::temp_dir().join(format!("pinnacle-fb-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&root).unwrap();
        let f = root.join("README.html");
        std::fs::write(&f, "x").unwrap();
        let d = root.to_string_lossy().into_owned();
        assert_eq!(resolve_typed(&format!("  {d} ")), Typed::Dir(d.clone()));
        assert_eq!(
            resolve_typed(&f.to_string_lossy()),
            Typed::File(f.to_string_lossy().into_owned())
        );
        assert_eq!(resolve_typed(&format!("{d}/nope")), Typed::Missing);
        assert_eq!(resolve_typed("   "), Typed::Missing);
        std::fs::remove_dir_all(&root).unwrap();
    }

    #[test]
    fn up_is_offered_only_below_the_root() {
        let roots = files::roots();
        let root = files::list_dir(Path::new(&roots[0]), false).unwrap();
        assert_eq!(root.parent, None);
        let tmp = files::list_dir(&std::env::temp_dir(), false).unwrap();
        assert!(tmp.parent.is_some());
    }

    #[test]
    fn opening_marks_the_browser_open() {
        let ctx = egui::Context::default();
        assert!(!is_open(&ctx));
        open_at(&ctx, Some("/".into()));
        assert!(is_open(&ctx));
    }
}
