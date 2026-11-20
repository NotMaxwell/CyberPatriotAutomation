// Copyright 2026 Maxwell McCormick
// SPDX-License-Identifier: Apache-2.0

use embed_manifest::manifest::{ActiveCodePage, DpiAwareness, ExecutionLevel};
use embed_manifest::{embed_manifest, new_manifest};

fn main() {
    println!("cargo:rerun-if-changed=build.rs");
    // CARGO_CFG_TARGET_OS, not cfg!(windows): build.rs runs on the host, and we
    // are usually cross-compiling from Linux.
    if std::env::var("CARGO_CFG_TARGET_OS").as_deref() == Ok("windows") {
        // requireAdministrator makes Windows raise the UAC prompt at launch;
        // hardening changes nothing useful without it.
        let manifest = new_manifest("PinnacleCyPat.Gui")
            .requested_execution_level(ExecutionLevel::RequireAdministrator)
            .dpi_awareness(DpiAwareness::PerMonitorV2)
            .active_code_page(ActiveCodePage::Utf8);
        embed_manifest(manifest).expect("unable to embed manifest");
    }
}
