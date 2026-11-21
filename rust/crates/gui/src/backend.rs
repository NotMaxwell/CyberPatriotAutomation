// =============================================================================
// PinnacleCyPat GUI - Engine bridge
// Copyright 2026 Maxwell McCormick
// SPDX-License-Identifier: Apache-2.0
// =============================================================================

//! Runs the engine off the UI thread and hands its results back.
//!
//! egui redraws only when something asks it to, so every message sent to the
//! UI is followed by `request_repaint`; without that the run view would sit
//! still until the mouse moved. The UI thread never blocks: it drains the
//! receivers with `try_recv` once per frame.

use std::sync::mpsc::{self, Receiver};

use eframe::egui;
use pinnacle_core::engine::{self, ReadmeChoice, ReadmeInspection, RunEvent, RunPlan};
use pinnacle_core::platform::Platform;

pub struct Backend {
    runtime: tokio::runtime::Runtime,
    ctx: egui::Context,
}

impl Backend {
    pub fn new(ctx: egui::Context) -> std::io::Result<Self> {
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .thread_name("pinnacle-engine")
            .build()?;
        Ok(Self { runtime, ctx })
    }

    pub fn ctx(&self) -> &egui::Context {
        &self.ctx
    }

    /// Every README location on the machine, for the picker. Read-only, though
    /// following a shortcut to a web address downloads the document.
    pub fn discover(&self) -> Receiver<Vec<pinnacle_core::app_config::ReadmeCandidate>> {
        let (tx, rx) = mpsc::channel();
        let ctx = self.ctx.clone();
        self.runtime.spawn(async move {
            let (found, _lines) =
                pinnacle_core::ui::capture(pinnacle_core::app_config::find_readme_candidates())
                    .await;
            let _ = tx.send(found);
            ctx.request_repaint();
        });
        rx
    }

    /// Find and parse the README. Changes nothing on the machine.
    pub fn inspect(&self, choice: ReadmeChoice) -> Receiver<ReadmeInspection> {
        let (tx, rx) = mpsc::channel();
        let ctx = self.ctx.clone();
        self.runtime.spawn(async move {
            // Captured, not printed: there is no console behind this window,
            // and the narration is already summarised by the inspection.
            let (inspection, _lines) =
                pinnacle_core::ui::capture(engine::inspect_readme(&choice)).await;
            let _ = tx.send(inspection);
            ctx.request_repaint();
        });
        rx
    }

    /// Start a run. Events arrive in order; the last one is `Finished`.
    pub fn run<P: Platform + 'static>(&self, plan: RunPlan) -> Receiver<RunEvent> {
        let (tx, rx) = mpsc::channel();
        let ctx = self.ctx.clone();
        self.runtime.spawn(async move {
            let (etx, mut erx) = tokio::sync::mpsc::unbounded_channel();
            let run = tokio::spawn(engine::run::<P>(plan, etx));
            while let Some(event) = erx.recv().await {
                if tx.send(event).is_err() {
                    // The window closed. Let the run finish on its own: it
                    // stops between tasks only via `cancel`, never mid-write.
                    break;
                }
                ctx.request_repaint();
            }
            let _ = run.await;
            ctx.request_repaint();
        });
        rx
    }
}
