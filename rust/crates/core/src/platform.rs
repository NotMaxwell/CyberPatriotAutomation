// =============================================================================
// PinnacleCyPat - The platform seam
// Author: Maxwell McCormick
// Copyright 2026 Maxwell McCormick
// SPDX-License-Identifier: Apache-2.0
// =============================================================================

//! How a platform crate tells the front end what it can do.
//!
//! Each supported operating system ships a crate (`pinnacle-windows`,
//! `pinnacle-linux`) whose only public surface is a list of [`TaskSpec`]. The
//! CLI and the interactive menu read that list and know nothing else about the
//! platform: the flag, the help line, the menu entry and the constructor all
//! come from the same row.
//!
//! That single-row rule is deliberate. Before this existed, adding a task meant
//! editing a flag table in `main.rs`, a registration block a few hundred lines
//! below it, and a menu table in `tui.rs` - three places for one fact, and they
//! were free to disagree. A task that reached the CLI but not the menu was
//! invisible to anyone who double-clicks `RUN.bat`, which is most users. Now
//! that state is unrepresentable.

use crate::models::ReadmeData;
use crate::task::Task;

/// Whether a task may overlap with others, or must have the machine to itself.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Concurrency {
    /// Runs in sequence with the other sequential tasks, in list order.
    ///
    /// The default, and correct unless you can name the state the task touches
    /// and show nothing else touches it.
    Sequential,
    /// Safe to run alongside the other concurrent tasks.
    ///
    /// Only for read-mostly audits over disjoint areas. The sequential tasks
    /// contend for the same accounts, services and configuration - user
    /// management and account permissions both rewrite accounts, service
    /// management and hardening both rewrite services - so overlapping them
    /// would race.
    Concurrent,
}

/// Builds a task, handing it the parsed README when there is one.
///
/// A plain `fn` pointer rather than a boxed closure: every implementation is a
/// non-capturing closure in the platform's task list, so there is nothing to
/// capture and nothing to allocate.
pub type TaskFactory = fn(Option<&ReadmeData>) -> Box<dyn Task>;

/// One task, described once: how to ask for it, how to explain it, how to build it.
pub struct TaskSpec {
    /// The long flag, including the leading dashes - `"--password-policy"`.
    pub flag: &'static str,
    /// The short flag, or `""` when the task has none.
    pub short: &'static str,
    /// One line for `--help`.
    pub help: &'static str,
    /// The name shown in the interactive menu.
    pub label: &'static str,
    /// The parenthetical shown after the label in the menu.
    pub detail: &'static str,
    /// Does this task do anything useful without a parsed README?
    ///
    /// The menu warns when one of these is selected and no README was given,
    /// because the failure is silent otherwise: the task runs, finds no
    /// instructions, and reports success having done nothing.
    pub needs_readme: bool,
    pub concurrency: Concurrency,
    pub build: TaskFactory,
}

impl TaskSpec {
    /// Does `arg` name this task?
    pub fn matches(&self, arg: &str) -> bool {
        arg == self.flag || (!self.short.is_empty() && arg == self.short)
    }
}

/// A platform's contribution: what to call it, and what it can do.
///
/// Implemented by a zero-sized type in each platform crate and selected by
/// `cfg` in the CLI, so the binary for one operating system carries neither the
/// task code nor the system bindings of the other.
pub trait Platform {
    /// Shown in the banner and stamped into the run log header.
    const NAME: &'static str;

    /// What to call the privileged account in a message to the user -
    /// "Administrator" on Windows, "root" on Linux.
    const PRIVILEGED_ROLE: &'static str;

    /// How to re-run with that privilege, in one line.
    ///
    /// Platform-supplied because the two remedies share nothing: telling a
    /// Linux user to right-click an executable is worse than saying nothing.
    const ELEVATION_HINT: &'static str;

    /// Every task this platform offers, in the order a full run executes them.
    ///
    /// Kept in run order rather than alphabetical so the confirmation summary
    /// reads as the sequence that is about to happen.
    fn tasks() -> &'static [TaskSpec];

    /// Can this process actually change the machine?
    ///
    /// Deliberately "can it write" rather than "is the token elevated": the
    /// answer the menu wants is whether the run will be able to do anything,
    /// and on Windows a token check would also have to account for UAC
    /// virtualisation to give it.
    fn is_privileged() -> bool;
}
