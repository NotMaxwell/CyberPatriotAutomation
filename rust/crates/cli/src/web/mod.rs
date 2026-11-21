// Copyright 2026 Maxwell McCormick
// SPDX-License-Identifier: Apache-2.0

//! `--web`: the app as a page in the browser, served from loopback.
//!
//! The Linux front end, because a native window does not fit there: the
//! shipping binary is static musl and cannot load X11, Wayland or GL, and
//! Ubuntu's Wayland session refuses a window opened by root. A browser running
//! as the logged-in user, talking to this process running as root, has neither
//! problem. The screens and the rules are the desktop GUI's, through
//! `pinnacle_core::session`; only the drawing is different.

mod api;
mod controller;
mod server;

use std::sync::Arc;
use std::time::{Duration, Instant};

use pinnacle_core::platform::Platform;
use tokio::net::TcpListener;

use controller::Controller;
use server::Guard;

/// How long the server waits for the page to come back once its last event
/// stream closed - long enough to survive a reload or a flaky tab, short
/// enough that a forgotten server does not sit on a root port all round.
const ABANDONED_AFTER: Duration = Duration::from_secs(120);

/// Serve the web UI until it is quit, interrupted or abandoned.
pub async fn serve<P: Platform + 'static>(port: Option<u16>) -> std::io::Result<()> {
    // Loopback only: this server makes root changes on behalf of whoever
    // holds the token, and nobody off this machine should get to try.
    let listener = TcpListener::bind(("127.0.0.1", port.unwrap_or(0))).await?;
    let port = listener.local_addr()?.port();
    let guard = Arc::new(Guard {
        token: uuid::Uuid::new_v4().simple().to_string(),
        port,
    });
    let url = format!("http://127.0.0.1:{port}/?t={}", guard.token);
    // The one place the token is printed: the person needs it to open the
    // page, and it is never written to a log.
    println!("PinnacleCyPat web interface");
    println!("Open {url}");
    println!("Press Ctrl+C to stop.");
    open_browser(&url);

    let ctl = Controller::<P>::new();
    // Start where the desktop GUI starts: looking for the README.
    let _ = ctl.perform(api::WebAction::Discover);
    let ticker = tokio::spawn(ctl.clone().tick());

    let mut idle_check = tokio::time::interval(Duration::from_secs(1));
    // Registered once, before the loop: a listener re-created on every
    // iteration misses a signal that lands between two of them.
    let interrupted = tokio::signal::ctrl_c();
    tokio::pin!(interrupted);
    let reason = loop {
        tokio::select! {
            accepted = listener.accept() => {
                if let Ok((stream, _)) = accepted {
                    tokio::spawn(server::handle(stream, guard.clone(), ctl.clone()));
                }
            }
            _ = &mut interrupted => break "Interrupted",
            _ = ctl.quit_requested() => break "Quit from the page",
            _ = idle_check.tick() => {
                if ctl.abandoned(Instant::now(), ABANDONED_AFTER) {
                    break "The page was closed";
                }
            }
        }
    };
    drop(listener);
    ticker.abort();
    finish_run(&ctl, reason).await;
    Ok(())
}

/// Never exit under a running task: it stops between tasks, never mid-write,
/// and its summary and run log are written when it ends. A second Ctrl+C
/// leaves at once for whoever really means it.
async fn finish_run<P: Platform + 'static>(ctl: &Arc<Controller<P>>, reason: &str) {
    if !ctl.run_in_progress() {
        println!("{reason}; stopping.");
        return;
    }
    println!("{reason}; cancelling the run after the current task (Ctrl+C again to leave now).");
    ctl.cancel_active();
    tokio::select! {
        _ = ctl.wait_idle() => println!("Run stopped; exiting."),
        _ = tokio::signal::ctrl_c() => println!("Leaving with the run unfinished."),
    }
}

/// Best effort: the URL is printed either way, and a failure here must never
/// stop the server.
fn open_browser(url: &str) {
    let mut command = browser_command(url);
    command
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null());
    if let Ok(mut child) = command.spawn() {
        // Reap it, so a launcher that exits does not linger as a zombie.
        tokio::task::spawn_blocking(move || child.wait());
    }
}

#[cfg(windows)]
fn browser_command(url: &str) -> std::process::Command {
    let mut c = std::process::Command::new("explorer.exe");
    c.arg(url);
    c
}

/// Under sudo the browser must open as the person, not as root: root has no
/// session bus and Wayland refuses its windows. So the command runs as
/// `$SUDO_USER` with the session's addresses spelled out, since sudo strips
/// them from the environment.
#[cfg(not(windows))]
fn browser_command(url: &str) -> std::process::Command {
    let sudo_user = std::env::var("SUDO_USER").ok().filter(|u| u != "root");
    let Some(user) = sudo_user else {
        let mut c = std::process::Command::new("xdg-open");
        c.arg(url);
        return c;
    };
    let mut c = std::process::Command::new("sudo");
    c.args(["-u", &user, "env"]);
    for var in ["DISPLAY", "WAYLAND_DISPLAY"] {
        if let Ok(value) = std::env::var(var) {
            c.arg(format!("{var}={value}"));
        }
    }
    if let Ok(uid) = std::env::var("SUDO_UID") {
        c.arg(format!("XDG_RUNTIME_DIR=/run/user/{uid}"));
        c.arg(format!(
            "DBUS_SESSION_BUS_ADDRESS=unix:path=/run/user/{uid}/bus"
        ));
    }
    c.args(["xdg-open", url]);
    c
}

#[cfg(test)]
pub(crate) mod test_support {
    use pinnacle_core::models::{ReadmeData, SystemInfo, TaskResult};
    use pinnacle_core::platform::{Concurrency, Platform, TaskSpec};
    use pinnacle_core::session::AppState;
    use pinnacle_core::task::Task;

    struct Nothing;

    #[async_trait::async_trait]
    impl Task for Nothing {
        fn name(&self) -> &str {
            "nothing"
        }
        fn description(&self) -> &str {
            ""
        }
        fn dry_run(&self) -> bool {
            true
        }
        fn set_dry_run(&mut self, _: bool) {}
        async fn read_system_state(&mut self) -> SystemInfo {
            SystemInfo::default()
        }
        async fn execute(&mut self) -> TaskResult {
            TaskResult::default()
        }
        async fn verify(&mut self) -> bool {
            true
        }
    }

    fn build(_: Option<&ReadmeData>) -> Box<dyn Task> {
        Box::new(Nothing)
    }

    pub static TASKS: [TaskSpec; 3] = [
        TaskSpec {
            flag: "--password-policy",
            short: "-p",
            help: "",
            label: "Password Policy",
            detail: "",
            needs_readme: false,
            concurrency: Concurrency::Sequential,
            build,
        },
        TaskSpec {
            flag: "--user-management",
            short: "-u",
            help: "",
            label: "User Management",
            detail: "",
            needs_readme: true,
            concurrency: Concurrency::Sequential,
            build,
        },
        TaskSpec {
            flag: "--dns-settings",
            short: "",
            help: "",
            label: "DNS Settings Audit",
            detail: "",
            needs_readme: false,
            concurrency: Concurrency::Concurrent,
            build,
        },
    ];

    /// A platform whose tasks change nothing, so no test can touch the machine.
    pub struct TestPlatform;

    impl Platform for TestPlatform {
        const NAME: &'static str = "Test";
        const PRIVILEGED_ROLE: &'static str = "root";
        const ELEVATION_HINT: &'static str = "use sudo";
        fn tasks() -> &'static [TaskSpec] {
            &TASKS
        }
        fn is_privileged() -> bool {
            false
        }
    }

    pub fn state(privileged: bool) -> AppState {
        AppState::new(&TASKS, privileged, "root", "use sudo")
    }
}
