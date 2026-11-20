// Copyright 2026 Maxwell McCormick
// SPDX-License-Identifier: Apache-2.0

//! Headless screen checks: render a few frames, save a PNG, close.
//!
//! This is how a screen is verified without a person at the display.

use std::path::PathBuf;

use eframe::egui;

/// Frames to draw before asking for the capture, so fonts and layout settle.
const WARMUP_FRAMES: u32 = 5;

pub struct Screenshot {
    path: PathBuf,
    frame: u32,
    requested: bool,
}

impl Screenshot {
    /// `Some` only when `PINNACLE_GUI_SCREENSHOT` names an output file.
    pub fn from_env() -> Option<Self> {
        let path = std::env::var_os("PINNACLE_GUI_SCREENSHOT")?;
        Some(Self {
            path: path.into(),
            frame: 0,
            requested: false,
        })
    }

    /// Call once per frame, after drawing. `settled` is false while work the
    /// screenshot should show the result of (an inspection, a run) is still in
    /// flight; warm-up frames are counted only once it is true.
    pub fn update(&mut self, ctx: &egui::Context, settled: bool) {
        // Keep frames coming; an idle egui app would never reach the capture.
        ctx.request_repaint();
        if !settled {
            self.frame = 0;
            return;
        }
        self.frame += 1;
        if !self.requested && self.frame >= WARMUP_FRAMES {
            self.requested = true;
            let (path, done) = (self.path.clone(), ctx.clone());
            ctx.send_viewport_cmd(egui::ViewportCommand::Screenshot(
                egui::ScreenshotCallback::new(move |image| {
                    if let Err(e) = save(&path, &image) {
                        eprintln!("screenshot failed: {e}");
                    }
                    done.send_viewport_cmd(egui::ViewportCommand::Close);
                    done.request_repaint();
                }),
            ));
        }
    }
}

fn save(path: &std::path::Path, image: &egui::ColorImage) -> image::ImageResult<()> {
    let [w, h] = image.size;
    image::save_buffer(
        path,
        image.as_raw(),
        w as u32,
        h as u32,
        image::ColorType::Rgba8,
    )
}
