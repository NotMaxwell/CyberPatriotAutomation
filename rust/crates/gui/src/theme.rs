// =============================================================================
// PinnacleCyPat GUI - Design system
// Copyright 2026 Maxwell McCormick
// SPDX-License-Identifier: Apache-2.0
// =============================================================================

//! The light theme and the handful of components every tab is built from.
//!
//! Screens use these rather than raw colours so the app reads as one thing:
//! one accent, one danger colour, one card style. The danger colour is kept for
//! actions that change the machine, and nothing else, so it means something
//! when it appears.

use eframe::egui::{
    self, Color32, CornerRadius, FontFamily, FontId, Margin, RichText, Shadow, Stroke, TextStyle,
};

// --- palette -----------------------------------------------------------------

pub const BG: Color32 = Color32::from_rgb(0xF4, 0xF6, 0xFA);
pub const SURFACE: Color32 = Color32::WHITE;
pub const SIDEBAR: Color32 = Color32::from_rgb(0xEC, 0xEF, 0xF5);
pub const BORDER: Color32 = Color32::from_rgb(0xDD, 0xE2, 0xEA);
pub const TEXT: Color32 = Color32::from_rgb(0x1B, 0x23, 0x33);
pub const MUTED: Color32 = Color32::from_rgb(0x64, 0x6E, 0x80);
pub const ACCENT: Color32 = Color32::from_rgb(0x1D, 0x4E, 0xD8);
pub const ACCENT_SOFT: Color32 = Color32::from_rgb(0xE6, 0xEE, 0xFD);
pub const SUCCESS: Color32 = Color32::from_rgb(0x16, 0x65, 0x34);
pub const SUCCESS_SOFT: Color32 = Color32::from_rgb(0xE5, 0xF6, 0xEA);
pub const WARNING: Color32 = Color32::from_rgb(0xB4, 0x53, 0x09);
pub const WARNING_SOFT: Color32 = Color32::from_rgb(0xFD, 0xF2, 0xE1);
pub const DANGER: Color32 = Color32::from_rgb(0xC5, 0x22, 0x22);
pub const DANGER_SOFT: Color32 = Color32::from_rgb(0xFC, 0xE8, 0xE8);

pub const RADIUS: u8 = 10;
pub const GAP: f32 = 12.0;

/// The family name for the bold face, when one was found.
pub const BOLD: &str = "bold";

/// Regular and bold UI fonts to try, in order: the platform's own first.
///
/// Loaded from the operating system at run time rather than bundled: Segoe UI
/// may not be redistributed, a bundled pair would add hundreds of kilobytes to
/// a binary that ships to a competition image, and the system face is what the
/// rest of the desktop already looks like. egui's built-in font is the
/// fallback, and has no bold - `strong()` only changes its colour, which is why
/// titles looked thin without this.
const FONT_PAIRS: &[(&str, &str)] = &[
    (
        r"C:\Windows\Fonts\segoeui.ttf",
        r"C:\Windows\Fonts\seguisb.ttf",
    ),
    (
        r"C:\Windows\Fonts\segoeui.ttf",
        r"C:\Windows\Fonts\segoeuib.ttf",
    ),
    (
        "/usr/share/fonts/opentype/inter/Inter-Regular.otf",
        "/usr/share/fonts/opentype/inter/Inter-SemiBold.otf",
    ),
    (
        "/usr/share/fonts/truetype/ubuntu/Ubuntu-R.ttf",
        "/usr/share/fonts/truetype/ubuntu/Ubuntu-M.ttf",
    ),
    (
        "/usr/share/fonts/opentype/cantarell/Cantarell-Regular.otf",
        "/usr/share/fonts/opentype/cantarell/Cantarell-Bold.otf",
    ),
    (
        "/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf",
        "/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf",
    ),
];

/// Which pair to load: the first whose two files both exist.
pub fn pick_fonts(exists: impl Fn(&str) -> bool) -> Option<(&'static str, &'static str)> {
    FONT_PAIRS
        .iter()
        .copied()
        .find(|(regular, bold)| exists(regular) && exists(bold))
}

static HAS_BOLD: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

fn install_fonts(ctx: &egui::Context) -> bool {
    let Some((regular, bold)) = pick_fonts(|p| std::path::Path::new(p).is_file()) else {
        return false;
    };
    let (Ok(regular), Ok(bold)) = (std::fs::read(regular), std::fs::read(bold)) else {
        return false;
    };
    let mut fonts = egui::FontDefinitions::default();
    fonts
        .font_data
        .insert("ui".into(), egui::FontData::from_owned(regular).into());
    fonts
        .font_data
        .insert("ui-bold".into(), egui::FontData::from_owned(bold).into());
    // In front of egui's own font, which stays behind as the fallback for any
    // glyph the system face lacks.
    let proportional = fonts.families.entry(FontFamily::Proportional).or_default();
    proportional.insert(0, "ui".into());
    let mut bold_chain = vec!["ui-bold".to_string()];
    bold_chain.extend(proportional.iter().cloned());
    fonts
        .families
        .insert(FontFamily::Name(BOLD.into()), bold_chain);
    ctx.set_fonts(fonts);
    true
}

/// The bold face if one was loaded, otherwise the regular one. Use as
/// `RichText::new(..).family(theme::bold_family())`; `strong()` does not bold.
pub fn bold_family() -> FontFamily {
    if HAS_BOLD.load(std::sync::atomic::Ordering::Relaxed) {
        FontFamily::Name(BOLD.into())
    } else {
        FontFamily::Proportional
    }
}

/// Install the theme. Call once, at start-up.
pub fn apply(ctx: &egui::Context) {
    HAS_BOLD.store(install_fonts(ctx), std::sync::atomic::Ordering::Relaxed);
    ctx.set_theme(egui::Theme::Light);
    ctx.all_styles_mut(|style| {
        style.text_styles = [
            (
                TextStyle::Heading,
                FontId::new(22.0, FontFamily::Proportional),
            ),
            (TextStyle::Body, FontId::new(14.5, FontFamily::Proportional)),
            (
                TextStyle::Button,
                FontId::new(14.5, FontFamily::Proportional),
            ),
            (
                TextStyle::Small,
                FontId::new(12.0, FontFamily::Proportional),
            ),
            (
                TextStyle::Monospace,
                FontId::new(13.0, FontFamily::Monospace),
            ),
        ]
        .into();
        style.spacing.item_spacing = egui::vec2(8.0, 8.0);
        style.spacing.button_padding = egui::vec2(14.0, 7.0);
        style.spacing.interact_size.y = 30.0;

        let v = &mut style.visuals;
        *v = egui::Visuals::light();
        v.panel_fill = BG;
        v.window_fill = SURFACE;
        v.extreme_bg_color = Color32::from_rgb(0xF8, 0xF9, 0xFC);
        v.faint_bg_color = Color32::from_rgb(0xF6, 0xF8, 0xFB);
        v.override_text_color = Some(TEXT);
        v.hyperlink_color = ACCENT;
        v.selection.bg_fill = ACCENT_SOFT;
        v.selection.stroke = Stroke::new(1.0, ACCENT);
        v.window_corner_radius = CornerRadius::same(RADIUS + 2);
        v.window_stroke = Stroke::new(1.0, BORDER);
        v.window_shadow = Shadow {
            offset: [0, 8],
            blur: 24,
            spread: 0,
            color: Color32::from_black_alpha(40),
        };
        v.popup_shadow = Shadow {
            offset: [0, 4],
            blur: 12,
            spread: 0,
            color: Color32::from_black_alpha(30),
        };
        for w in [
            &mut v.widgets.noninteractive,
            &mut v.widgets.inactive,
            &mut v.widgets.hovered,
            &mut v.widgets.active,
            &mut v.widgets.open,
        ] {
            w.corner_radius = CornerRadius::same(8);
        }
        v.widgets.noninteractive.bg_stroke = Stroke::new(1.0, BORDER);
        v.widgets.inactive.bg_fill = Color32::from_rgb(0xEE, 0xF1, 0xF6);
        v.widgets.inactive.weak_bg_fill = Color32::from_rgb(0xEE, 0xF1, 0xF6);
        v.widgets.inactive.bg_stroke = Stroke::new(1.0, BORDER);
        v.widgets.hovered.weak_bg_fill = Color32::from_rgb(0xE3, 0xE8, 0xF1);
        v.widgets.hovered.bg_stroke = Stroke::new(1.0, Color32::from_rgb(0xC7, 0xCF, 0xDC));
    });
}

// --- components ----------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Tone {
    Neutral,
    Accent,
    Success,
    Warning,
    Danger,
}

impl Tone {
    pub fn fg(self) -> Color32 {
        match self {
            Tone::Neutral => MUTED,
            Tone::Accent => ACCENT,
            Tone::Success => SUCCESS,
            Tone::Warning => WARNING,
            Tone::Danger => DANGER,
        }
    }

    pub fn bg(self) -> Color32 {
        match self {
            Tone::Neutral => Color32::from_rgb(0xEE, 0xF1, 0xF6),
            Tone::Accent => ACCENT_SOFT,
            Tone::Success => SUCCESS_SOFT,
            Tone::Warning => WARNING_SOFT,
            Tone::Danger => DANGER_SOFT,
        }
    }
}

/// A white, bordered, rounded panel: the unit every tab is laid out in.
pub fn card<R>(ui: &mut egui::Ui, add_contents: impl FnOnce(&mut egui::Ui) -> R) -> R {
    egui::Frame::new()
        .fill(SURFACE)
        .stroke(Stroke::new(1.0, BORDER))
        .corner_radius(CornerRadius::same(RADIUS))
        .inner_margin(Margin::same(16))
        .shadow(Shadow {
            offset: [0, 1],
            blur: 3,
            spread: 0,
            color: Color32::from_black_alpha(10),
        })
        .show(ui, |ui| {
            ui.set_width(ui.available_width());
            add_contents(ui)
        })
        .inner
}

/// A tinted box for a message that must not be missed: warnings, refusals,
/// what a real run is about to do.
pub fn callout<R>(
    ui: &mut egui::Ui,
    tone: Tone,
    add_contents: impl FnOnce(&mut egui::Ui) -> R,
) -> R {
    egui::Frame::new()
        .fill(tone.bg())
        .stroke(Stroke::new(1.0, tone.fg().gamma_multiply(0.35)))
        .corner_radius(CornerRadius::same(8))
        .inner_margin(Margin::symmetric(14, 10))
        .show(ui, |ui| {
            ui.set_width(ui.available_width());
            add_contents(ui)
        })
        .inner
}

/// A small rounded status label.
pub fn pill(ui: &mut egui::Ui, text: impl Into<String>, tone: Tone) -> egui::Response {
    egui::Frame::new()
        .fill(tone.bg())
        .corner_radius(CornerRadius::same(255))
        .inner_margin(Margin::symmetric(9, 3))
        .show(ui, |ui| {
            ui.label(
                RichText::new(text.into())
                    .size(12.0)
                    .color(tone.fg())
                    .family(bold_family()),
            )
        })
        .inner
}

/// A card heading with an optional one-line explanation under it.
pub fn section(ui: &mut egui::Ui, title: &str, subtitle: Option<&str>) {
    ui.label(
        RichText::new(title)
            .size(16.5)
            .family(bold_family())
            .color(TEXT),
    );
    if let Some(sub) = subtitle {
        ui.label(RichText::new(sub).size(13.0).color(MUTED));
    }
    ui.add_space(4.0);
}

/// The page title at the top of a tab.
pub fn page_title(ui: &mut egui::Ui, title: &str, subtitle: &str) {
    ui.label(
        RichText::new(title)
            .size(24.0)
            .family(bold_family())
            .color(TEXT),
    );
    ui.label(RichText::new(subtitle).size(13.5).color(MUTED));
    ui.add_space(GAP);
}

/// Muted secondary text.
pub fn muted(text: impl Into<String>) -> RichText {
    RichText::new(text.into()).color(MUTED)
}

fn filled(text: &str, fill: Color32) -> egui::Button<'static> {
    egui::Button::new(
        RichText::new(text.to_string())
            .color(Color32::WHITE)
            .family(bold_family()),
    )
    .fill(fill)
    .stroke(Stroke::NONE)
    .corner_radius(CornerRadius::same(8))
    .min_size(egui::vec2(0.0, 34.0))
}

/// The one thing to do next on a screen.
pub fn primary_button(text: &str) -> egui::Button<'static> {
    filled(text, ACCENT)
}

/// Reserved for actions that change the machine.
pub fn danger_button(text: &str) -> egui::Button<'static> {
    filled(text, DANGER)
}

/// Everything else.
pub fn secondary_button(text: &str) -> egui::Button<'static> {
    egui::Button::new(RichText::new(text.to_string()).color(TEXT))
        .fill(SURFACE)
        .stroke(Stroke::new(1.0, BORDER))
        .corner_radius(CornerRadius::same(8))
        .min_size(egui::vec2(0.0, 34.0))
}

/// A number with a label under it, for the results and run summaries.
pub fn stat(ui: &mut egui::Ui, label: &str, value: impl Into<String>, tone: Tone) {
    egui::Frame::new()
        .fill(tone.bg())
        .corner_radius(CornerRadius::same(8))
        .inner_margin(Margin::symmetric(14, 10))
        .show(ui, |ui| {
            ui.vertical(|ui| {
                ui.label(
                    RichText::new(value.into())
                        .size(22.0)
                        .family(bold_family())
                        .color(tone.fg()),
                );
                ui.label(RichText::new(label).size(12.0).color(MUTED));
            });
        });
}

/// `mm:ss`, for elapsed times.
pub fn duration(d: std::time::Duration) -> String {
    let s = d.as_secs();
    format!("{}:{:02}", s / 60, s % 60)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_first_complete_font_pair_wins_and_none_falls_back() {
        assert_eq!(pick_fonts(|_| false), None);
        let pair = pick_fonts(|p| p.contains("dejavu") || p.contains("inter")).unwrap();
        assert!(pair.0.contains("Inter"), "Inter is preferred over DejaVu");
        // A regular face without its bold is skipped, not half-loaded.
        assert_eq!(pick_fonts(|p| p.ends_with("segoeui.ttf")), None);
    }

    #[test]
    fn durations_read_as_minutes_and_seconds() {
        assert_eq!(duration(std::time::Duration::from_secs(0)), "0:00");
        assert_eq!(duration(std::time::Duration::from_secs(75)), "1:15");
        assert_eq!(
            duration(std::time::Duration::from_millis(3_599_999)),
            "59:59"
        );
    }

    /// Text on its own soft background must stay readable; a pill whose
    /// colours were too close would be decoration, not a status.
    #[test]
    fn every_tone_contrasts_with_its_background() {
        fn luminance(c: Color32) -> f32 {
            let f = |v: u8| {
                let v = v as f32 / 255.0;
                if v <= 0.039_28 {
                    v / 12.92
                } else {
                    ((v + 0.055) / 1.055).powf(2.4)
                }
            };
            0.2126 * f(c.r()) + 0.7152 * f(c.g()) + 0.0722 * f(c.b())
        }
        for tone in [
            Tone::Neutral,
            Tone::Accent,
            Tone::Success,
            Tone::Warning,
            Tone::Danger,
        ] {
            let (a, b) = (luminance(tone.fg()), luminance(tone.bg()));
            let ratio = (a.max(b) + 0.05) / (a.min(b) + 0.05);
            assert!(
                ratio >= 4.5,
                "{tone:?} contrast {ratio:.2} is below WCAG AA"
            );
        }
    }
}
