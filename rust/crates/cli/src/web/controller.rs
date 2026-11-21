// Copyright 2026 Maxwell McCormick
// SPDX-License-Identifier: Apache-2.0

//! The desktop GUI's `App`, without the window: owns the session, carries out
//! the page's actions, and tells the event streams when something changed.
//!
//! Discovery, README inspection and runs go on tokio tasks; each folds its
//! result into the state under the lock and bumps a version counter. Event
//! streams watch that counter rather than receiving every change, so a burst of
//! engine events collapses into the one snapshot sent after it.

use std::marker::PhantomData;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::{Duration, Instant};

use pinnacle_core::app_config;
use pinnacle_core::engine::{self, ReadmeChoice, ReadmeInspection};
use pinnacle_core::platform::Platform;
use pinnacle_core::session::{self, AppState, RunKind, Tab};
use pinnacle_core::ui;
use tokio::sync::{Notify, watch};

use super::api::{self, WebAction};

pub struct Controller<P> {
    state: Mutex<AppState>,
    version: watch::Sender<u64>,
    /// Bumped by every README request, so a slow inspection that finishes
    /// after a newer one was asked for cannot replace it.
    inspect_generation: AtomicUsize,
    /// A run task exists. Checked as well as `state.active`, because the run
    /// task outlives the `Finished` event by the time it takes to join.
    running: AtomicBool,
    streams: Mutex<Streams>,
    quit: Notify,
    _platform: PhantomData<fn() -> P>,
}

#[derive(Default)]
struct Streams {
    open: usize,
    /// When the last stream closed; `None` until one has been opened, so a
    /// browser that never arrives does not stop the server.
    last_closed: Option<Instant>,
}

/// Held by an event stream for as long as it is connected.
pub struct StreamGuard<P> {
    controller: Arc<Controller<P>>,
}

impl<P> Drop for StreamGuard<P> {
    fn drop(&mut self) {
        let mut streams = self
            .controller
            .streams
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        streams.open -= 1;
        if streams.open == 0 {
            streams.last_closed = Some(Instant::now());
        }
    }
}

impl<P: Platform + 'static> Controller<P> {
    pub fn new() -> Arc<Self> {
        Arc::new(Self::with_state(AppState::new(
            P::tasks(),
            P::is_privileged(),
            P::PRIVILEGED_ROLE,
            P::ELEVATION_HINT,
        )))
    }

    pub fn with_state(state: AppState) -> Self {
        Self {
            state: Mutex::new(state),
            version: watch::Sender::new(0),
            inspect_generation: AtomicUsize::new(0),
            running: AtomicBool::new(false),
            streams: Mutex::new(Streams::default()),
            quit: Notify::new(),
            _platform: PhantomData,
        }
    }

    fn lock(&self) -> MutexGuard<'_, AppState> {
        // A panic while holding the lock aborts the process (panic = "abort"
        // in release), so a poisoned lock only happens in a debug build, where
        // carrying on with the state as it was is still the most useful thing.
        self.state.lock().unwrap_or_else(|e| e.into_inner())
    }

    fn streams(&self) -> MutexGuard<'_, Streams> {
        self.streams.lock().unwrap_or_else(|e| e.into_inner())
    }

    fn changed(&self) {
        self.version.send_modify(|v| *v = v.wrapping_add(1));
    }

    pub fn subscribe(&self) -> watch::Receiver<u64> {
        self.version.subscribe()
    }

    pub fn snapshot_json(&self) -> String {
        let state = self.lock();
        let snapshot = api::snapshot(&state, P::NAME, Instant::now());
        serde_json::to_string(&snapshot).unwrap_or_else(|_| "{}".to_string())
    }

    /// The run log of the given run, once it has been written.
    pub fn log_path(&self, kind: RunKind) -> Option<PathBuf> {
        let state = self.lock();
        Some(state.record(kind)?.summary.as_ref()?.log_path.clone())
    }

    pub fn run_active(&self) -> bool {
        self.running.load(Ordering::SeqCst) || self.lock().active.is_some()
    }

    /// Is a run still doing work? Narrower than [`Self::run_active`]: the
    /// engine writes the run log *before* it sends `Finished`, so once the
    /// session has no active run there is nothing left to lose, even while the
    /// task is still being joined. Quitting waits on this; waiting on the join
    /// as well made a quit sent just after a run finished hang for seconds.
    pub fn run_in_progress(&self) -> bool {
        self.lock().active.is_some()
    }

    pub fn stream_opened(self: &Arc<Self>) -> StreamGuard<P> {
        self.streams().open += 1;
        StreamGuard {
            controller: self.clone(),
        }
    }

    /// Has the page been gone long enough to stop? Never while a run is going:
    /// closing the tab must not abandon a run's summary and log, and the run
    /// cannot be stopped mid-write anyway.
    pub fn abandoned(&self, now: Instant, after: Duration) -> bool {
        let gone = {
            let s = self.streams();
            s.open == 0
                && s.last_closed
                    .is_some_and(|t| now.duration_since(t) >= after)
        };
        gone && !self.run_active()
    }

    pub fn request_quit(&self) {
        self.quit.notify_one();
    }

    pub async fn quit_requested(&self) {
        self.quit.notified().await;
    }

    /// Ask the active run to stop at the next task boundary.
    pub fn cancel_active(&self) {
        let mut state = self.lock();
        if let Some(run) = state.active_record_mut() {
            run.cancel.store(true, Ordering::Relaxed);
            run.cancel_requested = true;
            drop(state);
            self.changed();
        }
    }

    /// Wait until no run is doing work.
    pub async fn wait_idle(&self) {
        while self.run_in_progress() {
            tokio::time::sleep(Duration::from_millis(200)).await;
        }
    }

    /// Once a second: expire the toast and move the elapsed-time counters.
    /// Engine events alone would leave a long task's timer frozen.
    pub async fn tick(self: Arc<Self>) {
        let mut interval = tokio::time::interval(Duration::from_secs(1));
        loop {
            interval.tick().await;
            let push = {
                let mut state = self.lock();
                let had_toast = state.toast.is_some();
                state.expire_toast(Instant::now());
                state.active.is_some() || had_toast != state.toast.is_some()
            };
            if push {
                self.changed();
            }
        }
    }

    /// Carry out one action from the page. `Err` is shown to the person; the
    /// state is unchanged by a refused action.
    pub fn perform(self: &Arc<Self>, action: WebAction) -> Result<(), String> {
        let result = self.apply(action);
        self.changed();
        result
    }

    fn apply(self: &Arc<Self>, action: WebAction) -> Result<(), String> {
        let mut state = self.lock();
        match action {
            WebAction::Discover => {
                if state.discovering {
                    return Ok(());
                }
                state.discovering = true;
                state.locations_open = true;
                drop(state);
                self.discover();
            }
            WebAction::UseReadme { path } => {
                idle(&state)?;
                if path.trim().is_empty() {
                    return Err("Enter the path of the README.".to_string());
                }
                state.readme_path = path.clone();
                state.locations_open = false;
                state.inspecting = true;
                state.tab = Tab::Readme;
                drop(state);
                self.inspect(path);
            }
            WebAction::ContinueWithoutReadme => {
                idle(&state)?;
                self.inspect_generation.fetch_add(1, Ordering::SeqCst);
                state.locations_open = false;
                state.set_inspection(ReadmeInspection::default());
                state.tab = Tab::Run;
            }
            WebAction::SetSelected { index, on } => {
                idle(&state)?;
                if index >= state.tasks.len() {
                    return Err(format!("There is no task {index}."));
                }
                if on && let Some(why) = api::task_blocked(&state, index) {
                    return Err(why.to_string());
                }
                state.selected[index] = on;
            }
            WebAction::SelectAll { on } => {
                idle(&state)?;
                for i in 0..state.tasks.len() {
                    let allowed = api::task_blocked(&state, i).is_none();
                    state.selected[i] = on && allowed;
                }
            }
            WebAction::SetReadme { data } => {
                idle(&state)?;
                if state.inspection.is_none() {
                    return Err("Load a README before editing it.".to_string());
                }
                state.edited = Some(*data);
            }
            WebAction::RevertReadme => {
                idle(&state)?;
                state.edited = None;
            }
            WebAction::SetHandDone { index, on } => match state.hand_done.get_mut(index) {
                Some(tick) => *tick = on,
                None => return Err(format!("There is no by-hand item {index}.")),
            },
            WebAction::StartPreview => {
                drop(state);
                self.start(RunKind::Preview)?;
            }
            WebAction::OpenApply => {
                state.real_run_gate()?;
                state.apply_confirmed = false;
                state.apply_dialog_open = true;
            }
            WebAction::CloseApply => {
                state.apply_dialog_open = false;
                state.apply_confirmed = false;
            }
            WebAction::SetApplyConfirmed { on } => {
                // Ticking the box only means something inside the dialog, which
                // is only open while the gate allows a real run.
                if on && !state.apply_dialog_open {
                    return Err("Open the real-run confirmation first.".to_string());
                }
                state.apply_confirmed = on;
            }
            WebAction::StartReal => {
                drop(state);
                self.start(RunKind::Real)?;
            }
            WebAction::Cancel => {
                drop(state);
                self.cancel_active();
            }
            WebAction::SetTab { tab } => state.tab = tab.into(),
            WebAction::SetResultsKind { kind } => state.results_kind = kind.into(),
            WebAction::DismissError => state.error = None,
        }
        Ok(())
    }

    fn discover(self: &Arc<Self>) {
        let this = self.clone();
        tokio::spawn(async move {
            // Captured: the narration belongs to a terminal nobody is reading.
            let (found, _lines) = ui::capture(app_config::find_readme_candidates()).await;
            {
                let mut state = this.lock();
                if let [only] = found.as_slice()
                    && state.readme_path.is_empty()
                {
                    state.readme_path = only.location.clone();
                }
                state.candidates = Some(found);
                state.discovering = false;
            }
            this.changed();
        });
    }

    fn inspect(self: &Arc<Self>, path: String) {
        let generation = self.inspect_generation.fetch_add(1, Ordering::SeqCst) + 1;
        let this = self.clone();
        tokio::spawn(async move {
            let (inspection, _lines) =
                ui::capture(engine::inspect_readme(&ReadmeChoice::Path(path))).await;
            {
                let mut state = this.lock();
                if this.inspect_generation.load(Ordering::SeqCst) != generation {
                    return;
                }
                if state.active.is_some() {
                    // A run started from the old README while this was parsing;
                    // swapping it now would change what the run is reported as.
                    state.inspecting = false;
                    state.error = Some("The README was not loaded: a run started.".to_string());
                } else {
                    state.set_inspection(inspection);
                }
            }
            this.changed();
        });
    }

    /// Plan and start a run. A real run gets its plan only from
    /// `AppState::plan`, which refuses without the gate and the tick.
    fn start(self: &Arc<Self>, kind: RunKind) -> Result<(), String> {
        let mut state = self.lock();
        if self.running.load(Ordering::SeqCst) {
            return Err("A run is in progress.".to_string());
        }
        if state.inspecting {
            return Err("Wait for the README to finish loading.".to_string());
        }
        let cancel = Arc::new(AtomicBool::new(false));
        let plan = state.plan(kind, session::default_log_path(), cancel)?;
        state.begin_run(kind, &plan, Instant::now());
        self.running.store(true, Ordering::SeqCst);
        drop(state);

        let this = self.clone();
        tokio::spawn(async move {
            let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();
            let run = tokio::spawn(engine::run::<P>(plan, tx));
            while let Some(event) = rx.recv().await {
                this.lock().apply_event(event, Instant::now());
                this.changed();
            }
            let outcome = run.await;
            {
                let mut state = this.lock();
                if state.active == Some(kind) {
                    // The engine ended without a summary, which only a panic in
                    // a debug build does; never leave the page showing a run
                    // that is not going.
                    state.active = None;
                    state.error = Some(match outcome {
                        Ok(_) => format!("The {} ended without a summary.", kind.title()),
                        Err(e) => format!("The {} stopped unexpectedly: {e}", kind.title()),
                    });
                }
            }
            this.running.store(false, Ordering::SeqCst);
            this.changed();
        });
        Ok(())
    }
}

fn idle(state: &AppState) -> Result<(), String> {
    match state.active {
        Some(_) => Err("A run is in progress.".to_string()),
        None => Ok(()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::web::test_support::{TestPlatform, state};
    use pinnacle_core::engine::{RunEvent, RunSummary};

    fn controller(privileged: bool) -> Arc<Controller<TestPlatform>> {
        Arc::new(Controller::with_state(state(privileged)))
    }

    fn act(c: &Arc<Controller<TestPlatform>>, json: &str) -> Result<(), String> {
        c.perform(serde_json::from_str(json).unwrap())
    }

    /// Stand in for the engine finishing a preview, without starting one.
    fn finish_preview_in_state(c: &Controller<TestPlatform>) {
        let mut s = c.lock();
        let plan = s
            .plan(
                RunKind::Preview,
                PathBuf::from("log.txt"),
                Arc::new(AtomicBool::new(false)),
            )
            .unwrap();
        let now = Instant::now();
        s.begin_run(RunKind::Preview, &plan, now);
        s.apply_event(
            RunEvent::Finished(RunSummary {
                results: Vec::new(),
                fixes: Vec::new(),
                log_path: PathBuf::from("log.txt"),
                log_error: None,
                cancelled: false,
            }),
            now,
        );
    }

    #[test]
    fn start_real_is_refused_without_a_finished_matching_dry_run() {
        let c = controller(true);
        let err = act(&c, r#"{"type":"start_real"}"#).unwrap_err();
        assert!(err.contains("dry run"), "{err}");
        assert!(c.lock().real.is_none() && c.lock().active.is_none());
        assert!(act(&c, r#"{"type":"open_apply"}"#).is_err());
        assert!(!c.lock().apply_dialog_open);
    }

    #[test]
    fn start_real_is_refused_without_the_confirmation_tick() {
        let c = controller(true);
        finish_preview_in_state(&c);
        let err = act(&c, r#"{"type":"start_real"}"#).unwrap_err();
        assert!(err.contains("Confirm"), "{err}");
        assert!(
            act(&c, r#"{"type":"set_apply_confirmed","on":true}"#).is_err(),
            "the tick needs the dialog open"
        );
        act(&c, r#"{"type":"open_apply"}"#).unwrap();
        act(&c, r#"{"type":"set_selected","index":0,"on":false}"#).unwrap();
        act(&c, r#"{"type":"set_apply_confirmed","on":true}"#).unwrap();
        let err = act(&c, r#"{"type":"start_real"}"#).unwrap_err();
        assert!(err.contains("selection changed"), "{err}");
        assert!(c.lock().real.is_none());
    }

    #[test]
    fn start_real_is_refused_unprivileged() {
        let c = controller(false);
        finish_preview_in_state(&c);
        assert!(act(&c, r#"{"type":"open_apply"}"#).is_err());
        c.lock().apply_confirmed = true;
        let err = act(&c, r#"{"type":"start_real"}"#).unwrap_err();
        assert!(err.contains("Not running as root"), "{err}");
    }

    #[test]
    fn a_readme_task_cannot_be_ticked_without_a_readme() {
        let c = controller(true);
        assert!(act(&c, r#"{"type":"set_selected","index":1,"on":true}"#).is_err());
        act(&c, r#"{"type":"select_all","on":true}"#).unwrap();
        assert_eq!(c.lock().selected, [true, false, true]);
        act(&c, r#"{"type":"select_all","on":false}"#).unwrap();
        assert_eq!(c.lock().selected, [false, false, false]);
        assert!(act(&c, r#"{"type":"set_selected","index":9,"on":true}"#).is_err());
    }

    #[test]
    fn edits_need_a_readme_and_revert_clears_them() {
        let c = controller(true);
        let set = r#"{"type":"set_readme","data":{"title":"t","operating_system":"","scenario":"",
            "administrators":[],"users":[],"required_software":[],"prohibited_software":[],
            "critical_services":[],"prohibited_services":[],"group_requirements":[],
            "users_to_create":[],"guidelines":[],"actionable_items":[],"sections":{}}}"#;
        assert!(act(&c, set).is_err());
        act(&c, r#"{"type":"continue_without_readme"}"#).unwrap();
        act(&c, set).unwrap();
        assert!(c.lock().edited.is_some());
        act(&c, r#"{"type":"revert_readme"}"#).unwrap();
        assert!(c.lock().edited.is_none());
    }

    #[test]
    fn every_action_bumps_the_version_the_streams_watch() {
        let c = controller(true);
        let mut rx = c.subscribe();
        rx.mark_unchanged();
        act(&c, r#"{"type":"set_tab","tab":"run"}"#).unwrap();
        assert!(rx.has_changed().unwrap());
        assert_eq!(c.lock().tab, Tab::Run);
    }

    #[test]
    fn the_server_is_abandoned_only_after_a_stream_came_and_went() {
        let c = controller(true);
        let later = Instant::now() + Duration::from_secs(300);
        let limit = Duration::from_secs(120);
        assert!(!c.abandoned(later, limit), "no browser has connected yet");
        let guard = c.stream_opened();
        assert!(!c.abandoned(later, limit), "a stream is open");
        drop(guard);
        assert!(!c.abandoned(Instant::now(), limit), "only just closed");
        assert!(c.abandoned(later, limit));
        c.running.store(true, Ordering::SeqCst);
        assert!(!c.abandoned(later, limit), "never mid-run");
    }
}
