// =============================================================================
// PinnacleCyPat - Backdoor listeners (Linux)
// Copyright 2026 Maxwell McCormick
// SPDX-License-Identifier: Apache-2.0
// =============================================================================

//! Finds processes listening on the network that no package put there, kills
//! them, and removes what keeps them coming back.
//!
//! The round plants these as `nc.traditional -l -p 1337` launched from
//! `/etc/crontab`, or as `python3 /usr/share/zod/kneelB4zod.py` listening on the
//! same port. Neither can be found by looking at a port number: a legitimate
//! service may use any port, and a backdoor may use 80. So the decision is made
//! on *what is running*, from three signals:
//!
//! 1. the program is a raw listener (`nc`, `ncat`, `socat` ...) - nothing on a
//!    competition image has a reason to run one;
//! 2. the program is an interpreter running a script no package owns;
//! 3. the program is itself a binary no package owns, outside the few
//!    directories that legitimately hold unpackaged software.
//!
//! The scoring engine, `sshd` and anything the README marks critical are never
//! candidates, whatever they look like.
//!
//! Package-owned binaries (`/usr/bin/nc.traditional`) are deliberately left on
//! disk: removing them is Software Management's job, and doing it here by hand
//! would leave dpkg believing a file is present that is not.

use pinnacle_core::models::{ReadmeData, SystemInfo, TaskResult};
use pinnacle_core::task::Task;
use pinnacle_core::{command, impl_task_meta, remediation, run_log, ui};

use crate::{file_ops, readme_services, systemd_ops};
use async_trait::async_trait;
use std::collections::{BTreeSet, HashMap, HashSet};
use std::path::Path;
use std::time::Duration;

/// Programs whose only job is to listen and hand over a shell or a pipe.
const RAW_LISTENERS: &[&str] = &[
    "nc",
    "nc.traditional",
    "nc.openbsd",
    "ncat",
    "netcat",
    "socat",
];

/// Programs that run a script named on their command line.
const INTERPRETER_PREFIXES: &[&str] = &["python", "php"];
const INTERPRETERS: &[&str] = &["perl", "ruby", "node", "bash", "sh", "dash"];

/// Places unpackaged software legitimately lives.
const ALLOWED_UNOWNED_DIRS: &[&str] =
    &["/opt/CyberPatriot", "/snap", "/usr/local/lib/node_modules"];

/// Where cron jobs live. Mirrors `scheduled_tasks_audit`'s list, which is
/// private there and in a file this package does not own; the test below pins
/// the two-way agreement on the essentials.
const CRON_LOCATIONS: &[&str] = &[
    "/etc/crontab",
    "/etc/cron.d",
    "/etc/cron.hourly",
    "/etc/cron.daily",
    "/etc/cron.weekly",
    "/etc/cron.monthly",
    "/var/spool/cron/crontabs",
];

/// Marker put in front of a cron line this task disables.
const CRON_MARK: &str = "# disabled by pinnacle: ";

pub struct BackdoorListenersTask {
    name: String,
    description: String,
    dry_run: bool,
    readme_data: Option<ReadmeData>,
}

impl BackdoorListenersTask {
    pub fn new() -> Self {
        Self {
            name: "Backdoor Listeners".to_string(),
            description: "Kill and remove unpackaged network listeners".to_string(),
            dry_run: false,
            readme_data: None,
        }
    }

    pub fn set_readme_data(&mut self, data: ReadmeData) {
        self.readme_data = Some(data);
    }
}

impl Default for BackdoorListenersTask {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// Pure parsing and classification
// ---------------------------------------------------------------------------

/// One socket a process is listening on, from `ss -Htlnup`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Listener {
    pub proto: String,
    pub port: u16,
    pub pid: u32,
    pub process: String,
}

/// Parse `ss -Htlnup` output. A socket shared by several processes yields one
/// entry per process; a socket whose owner `ss` could not see (no `users:`) is
/// skipped, because there is nothing to act on.
pub fn parse_ss(text: &str) -> Vec<Listener> {
    let mut out = Vec::new();
    for line in text.lines() {
        let fields: Vec<&str> = line.split_whitespace().collect();
        if fields.len() < 6 {
            continue;
        }
        let proto = fields[0].to_string();
        let Some(port) = fields[4]
            .rsplit(':')
            .next()
            .and_then(|p| p.parse::<u16>().ok())
        else {
            continue;
        };
        let Some(users_at) = line.find("users:(") else {
            continue;
        };
        for (process, pid) in parse_users(&line[users_at..]) {
            out.push(Listener {
                proto: proto.clone(),
                port,
                pid,
                process,
            });
        }
    }
    out
}

/// `users:(("nc.traditional",pid=812,fd=3),("x",pid=9,fd=4))` -> name/pid pairs.
fn parse_users(text: &str) -> Vec<(String, u32)> {
    let mut out = Vec::new();
    let mut rest = text;
    while let Some(open) = rest.find("(\"") {
        let after = &rest[open + 2..];
        let Some(close) = after.find("\",pid=") else {
            break;
        };
        let name = &after[..close];
        let digits: String = after[close + 6..]
            .chars()
            .take_while(|c| c.is_ascii_digit())
            .collect();
        if let Ok(pid) = digits.parse() {
            out.push((name.to_string(), pid));
        }
        rest = &after[close + 6..];
    }
    out
}

/// What is known about a listening process.
#[derive(Debug, Clone, Default)]
pub struct ProcessFacts {
    pub pid: u32,
    /// The name `ss` reported (the kernel's `comm`).
    pub comm: String,
    /// `/proc/<pid>/exe`, without any ` (deleted)` suffix.
    pub exe: String,
    /// `/proc/<pid>/cmdline`, split.
    pub args: Vec<String>,
    pub cwd: Option<String>,
    /// The systemd unit from `/proc/<pid>/cgroup`, if it runs under one.
    pub unit: Option<String>,
}

/// Why a listener was judged a backdoor.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Kind {
    RawListener,
    UnownedScript,
    UnownedBinary,
}

/// The decision about one process: what it is, and what to remove with it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Verdict {
    pub kind: Kind,
    pub reason: String,
    /// Files to delete: only ever paths no package owns.
    pub delete: Vec<String>,
    /// A package-owned binary that is left for Software Management.
    pub left_for_purge: Option<String>,
    /// Paths a cron line may reference to be disabled.
    pub cron_paths: Vec<String>,
}

fn basename(path: &str) -> &str {
    path.rsplit('/').next().unwrap_or(path)
}

fn is_interpreter(name: &str) -> bool {
    INTERPRETERS.contains(&name) || INTERPRETER_PREFIXES.iter().any(|p| name.starts_with(p))
}

/// The script an interpreter was asked to run, made absolute. `None` for
/// inline code (`-c`, `-e`) and modules (`-m`), which name no file to judge.
pub fn script_path(args: &[String], cwd: Option<&str>) -> Option<String> {
    for arg in args.iter().skip(1) {
        if matches!(arg.as_str(), "-c" | "-e" | "-E" | "-m" | "-r" | "-p") {
            return None;
        }
        if arg.starts_with('-') {
            continue;
        }
        if arg.starts_with('/') {
            return Some(arg.clone());
        }
        return cwd.map(|c| {
            format!(
                "{}/{}",
                c.trim_end_matches('/'),
                arg.trim_start_matches("./")
            )
        });
    }
    None
}

/// Processes the run must never touch.
pub fn is_exempt(p: &ProcessFacts, readme: Option<&ReadmeData>) -> bool {
    let names = [p.comm.to_lowercase(), basename(&p.exe).to_lowercase()];
    if names
        .iter()
        .any(|n| n.starts_with("sshd") || n.contains("ccs") || n.contains("cyberpatriot"))
    {
        return true;
    }
    if p.exe.starts_with("/opt/CyberPatriot") || p.exe.to_lowercase().contains("cyberpatriot") {
        return true;
    }
    if let Some(unit) = &p.unit
        && readme_services::is_protected(readme, unit)
    {
        return true;
    }
    // A process outside any unit may still be a service the README names.
    readme_services::is_protected(readme, &format!("{}.service", p.comm))
}

/// Decide whether a listening process is a backdoor. `owned` answers "does a
/// package own this path", from a lookup done beforehand so this stays pure.
pub fn classify(
    p: &ProcessFacts,
    readme: Option<&ReadmeData>,
    owned: impl Fn(&str) -> bool,
) -> Option<Verdict> {
    if is_exempt(p, readme) {
        return None;
    }
    let exe_name = basename(&p.exe);

    if RAW_LISTENERS.contains(&exe_name) {
        let exe_owned = owned(&p.exe);
        return Some(Verdict {
            kind: Kind::RawListener,
            reason: format!("{exe_name} is a raw network listener"),
            delete: if exe_owned {
                vec![]
            } else {
                vec![p.exe.clone()]
            },
            left_for_purge: exe_owned.then(|| p.exe.clone()),
            cron_paths: vec![],
        });
    }

    if is_interpreter(exe_name)
        && let Some(script) = script_path(&p.args, p.cwd.as_deref())
    {
        if owned(&script) {
            return None;
        }
        return Some(Verdict {
            kind: Kind::UnownedScript,
            reason: format!("{exe_name} is running {script}, which no package owns"),
            delete: vec![script.clone()],
            left_for_purge: None,
            cron_paths: vec![script],
        });
    }

    if !p.exe.is_empty()
        && !owned(&p.exe)
        && !ALLOWED_UNOWNED_DIRS.iter().any(|d| p.exe.starts_with(d))
    {
        return Some(Verdict {
            kind: Kind::UnownedBinary,
            reason: format!("{} is listening and no package owns it", p.exe),
            delete: vec![p.exe.clone()],
            left_for_purge: None,
            cron_paths: vec![p.exe.clone()],
        });
    }
    None
}

/// `/system.slice/foo.service` out of `/proc/<pid>/cgroup` text.
pub fn unit_from_cgroup(text: &str) -> Option<String> {
    text.lines()
        .flat_map(|l| l.rsplit('/').next())
        .find(|seg| seg.ends_with(".service"))
        .map(str::to_string)
}

/// Does this cron line start a raw listener? Matches a `nc`-family word
/// together with a listen flag, so `nc -z host 22` (a port check) is left.
pub fn is_raw_listener_line(line: &str) -> bool {
    if !file_ops::is_active(line) {
        return false;
    }
    let words: Vec<&str> = line.split_whitespace().collect();
    let Some(at) = words
        .iter()
        .position(|w| RAW_LISTENERS.contains(&basename(w)))
    else {
        return false;
    };
    words[at + 1..].iter().any(|w| {
        w.to_uppercase().contains("LISTEN")
            || (w.starts_with('-') && !w.starts_with("--") && w[1..].contains('l'))
    })
}

/// Should this cron line be disabled for this verdict?
pub fn cron_line_matches(line: &str, verdict: &Verdict) -> bool {
    if !file_ops::is_active(line) {
        return false;
    }
    if verdict.kind == Kind::RawListener && is_raw_listener_line(line) {
        return true;
    }
    verdict.cron_paths.iter().any(|p| line.contains(p.as_str()))
}

/// The same line, disabled.
pub fn disable_cron_line(line: &str) -> String {
    format!("{CRON_MARK}{line}")
}

/// Other spellings dpkg may know a path by. Merged-/usr images record
/// `/bin/dash` while the kernel reports `/usr/bin/dash`.
pub fn dpkg_candidates(path: &str) -> Vec<String> {
    let mut out = vec![path.to_string()];
    for dir in ["bin", "sbin", "lib"] {
        if let Some(rest) = path.strip_prefix(&format!("/usr/{dir}/")) {
            out.push(format!("/{dir}/{rest}"));
        }
    }
    out
}

// ---------------------------------------------------------------------------
// Reading the machine
// ---------------------------------------------------------------------------

async fn dpkg_owns(path: &str) -> bool {
    if path.contains('"') {
        // Cannot be quoted for the command; treat as owned so it is not deleted.
        return true;
    }
    for candidate in dpkg_candidates(path) {
        let (ok, _o, _e) = command::execute("dpkg", Some(&format!("-S \"{candidate}\""))).await;
        if ok {
            return true;
        }
    }
    false
}

async fn gather(listener: &Listener) -> ProcessFacts {
    let proc = format!("/proc/{}", listener.pid);
    let exe = tokio::fs::read_link(format!("{proc}/exe"))
        .await
        .map(|p| {
            p.to_string_lossy()
                .trim_end_matches(" (deleted)")
                .to_string()
        })
        .unwrap_or_default();
    let args = tokio::fs::read(format!("{proc}/cmdline"))
        .await
        .map(|b| {
            b.split(|c| *c == 0)
                .filter(|s| !s.is_empty())
                .map(|s| String::from_utf8_lossy(s).to_string())
                .collect()
        })
        .unwrap_or_default();
    let cwd = tokio::fs::read_link(format!("{proc}/cwd"))
        .await
        .ok()
        .map(|p| p.to_string_lossy().to_string());
    let unit = tokio::fs::read_to_string(format!("{proc}/cgroup"))
        .await
        .ok()
        .and_then(|t| unit_from_cgroup(&t));
    ProcessFacts {
        pid: listener.pid,
        comm: listener.process.clone(),
        exe,
        args,
        cwd,
        unit,
    }
}

/// Every listening process judged a backdoor, with its facts and ports.
async fn find_backdoors(readme: Option<&ReadmeData>) -> Vec<(ProcessFacts, Verdict, Vec<u16>)> {
    let (_ok, out, _e) = command::execute("ss", Some("-Htlnup")).await;
    let mut ports: HashMap<u32, (Listener, BTreeSet<u16>)> = HashMap::new();
    for l in parse_ss(&out) {
        ports
            .entry(l.pid)
            .or_insert_with(|| (l.clone(), BTreeSet::new()))
            .1
            .insert(l.port);
    }
    let me = std::process::id();
    let mut found = Vec::new();
    for (pid, (listener, set)) in ports {
        if pid == me {
            continue;
        }
        let facts = gather(&listener).await;
        let mut owned: HashSet<String> = HashSet::new();
        let mut paths = vec![facts.exe.clone()];
        paths.extend(script_path(&facts.args, facts.cwd.as_deref()));
        for path in paths.into_iter().filter(|p| !p.is_empty()) {
            if dpkg_owns(&path).await {
                owned.insert(path);
            }
        }
        if let Some(verdict) = classify(&facts, readme, |p| owned.contains(p)) {
            found.push((facts, verdict, set.into_iter().collect()));
        }
    }
    found.sort_by_key(|(f, _, _)| f.pid);
    found
}

// ---------------------------------------------------------------------------
// Acting on a verdict
// ---------------------------------------------------------------------------

fn alive(pid: u32) -> bool {
    Path::new(&format!("/proc/{pid}")).exists()
}

async fn kill_process(p: &ProcessFacts, why: &str) -> Result<(), String> {
    let pid = p.pid;
    remediation::apply(
        &format!("process {pid} ({})", p.comm),
        &format!("not running ({why})"),
        || async { Some(if alive(pid) { "running" } else { "gone" }.to_string()) },
        |state| state == "gone",
        "sent TERM, then KILL after 3 seconds",
        || async {
            let _ = command::execute("kill", Some(&format!("-TERM {pid}"))).await;
            for _ in 0..6 {
                tokio::time::sleep(Duration::from_millis(500)).await;
                if !alive(pid) {
                    return Ok(());
                }
            }
            let _ = command::execute("kill", Some(&format!("-KILL {pid}"))).await;
            tokio::time::sleep(Duration::from_millis(500)).await;
            if alive(pid) {
                Err(format!("process {pid} survived KILL"))
            } else {
                Ok(())
            }
        },
    )
    .await
}

async fn delete_file(path: &str, why: &str) -> Result<(), String> {
    remediation::apply(
        &format!("file {path}"),
        &format!("deleted ({why})"),
        || async {
            Some(
                if Path::new(path).exists() {
                    "present"
                } else {
                    "absent"
                }
                .to_string(),
            )
        },
        |state| state == "absent",
        "deleted the file",
        || async {
            tokio::fs::remove_file(path)
                .await
                .map_err(|e| format!("could not delete {path}: {e}"))
        },
    )
    .await
}

/// Every regular file under the cron locations.
async fn cron_files() -> Vec<String> {
    let mut files = Vec::new();
    for location in CRON_LOCATIONS {
        let path = Path::new(location);
        if path.is_file() {
            files.push(location.to_string());
        } else if let Ok(mut dir) = tokio::fs::read_dir(path).await {
            while let Ok(Some(entry)) = dir.next_entry().await {
                if entry.path().is_file() {
                    files.push(entry.path().to_string_lossy().to_string());
                }
            }
        }
    }
    files
}

/// Comment out the cron lines that start this backdoor. Returns how many.
async fn disable_cron_lines(verdict: &Verdict) -> Result<usize, String> {
    let mut total = 0;
    for file in cron_files().await {
        let Ok(original) = tokio::fs::read_to_string(&file).await else {
            continue;
        };
        let hits = original
            .lines()
            .filter(|l| cron_line_matches(l, verdict))
            .count();
        if hits == 0 {
            continue;
        }
        total += hits;
        remediation::apply(
            &format!("cron entries in {file}"),
            "disabled, so the backdoor is not started again",
            || async {
                let text = tokio::fs::read_to_string(&file).await.ok()?;
                let live = text
                    .lines()
                    .filter(|l| cron_line_matches(l, verdict))
                    .count();
                Some(format!("{live} live entries"))
            },
            |state| state == "0 live entries",
            &format!("commented out {hits} line(s)"),
            || async {
                let updated: Vec<String> = original
                    .lines()
                    .map(|l| {
                        if cron_line_matches(l, verdict) {
                            disable_cron_line(l)
                        } else {
                            l.to_string()
                        }
                    })
                    .collect();
                file_ops::back_up(&file, &original).await?;
                file_ops::write_atomically(&file, &(updated.join("\n") + "\n")).await
            },
        )
        .await?;
    }
    Ok(total)
}

/// A unit file under /etc/systemd/system that no package owns.
async fn local_unit(unit: &str) -> bool {
    let path = format!("/etc/systemd/system/{unit}");
    Path::new(&path).is_file() && !dpkg_owns(&path).await
}

#[async_trait]
impl Task for BackdoorListenersTask {
    impl_task_meta!();

    async fn read_system_state(&mut self) -> SystemInfo {
        let (_ok, out, _e) = command::execute("ss", Some("-Htlnup")).await;
        SystemInfo {
            raw_output: Some(out),
            ..Default::default()
        }
    }

    async fn execute(&mut self) -> TaskResult {
        let mut result = TaskResult {
            task_name: self.name.clone(),
            success: true,
            ..Default::default()
        };
        let backdoors = find_backdoors(self.readme_data.as_ref()).await;
        result.items_attempted = backdoors.len() as i32;

        if backdoors.is_empty() {
            remediation::record_finding(
                "network listeners",
                "every listener is a package's own service",
                true,
                "no raw listener, unpackaged script or unpackaged binary is listening",
            );
            result.message = "No backdoor listeners found.".to_string();
            return result;
        }

        ui::markup_line(
            "[yellow]Forensics questions may ask about a backdoor's path or port. \
             Answer them before relying on this task's output being the only record.[/]",
        );

        let mut failures: Vec<String> = Vec::new();
        for (facts, verdict, ports) in &backdoors {
            let port_list = ports
                .iter()
                .map(|p| p.to_string())
                .collect::<Vec<_>>()
                .join(",");
            ui::markup_line(&format!(
                "[yellow]⚠ pid {} {} on port {}: {}[/]",
                facts.pid,
                ui::escape(&facts.comm),
                port_list,
                ui::escape(&verdict.reason)
            ));
            remediation::record_finding(
                &format!(
                    "listener pid {} ({}) port {port_list}",
                    facts.pid, facts.comm
                ),
                "not a backdoor",
                false,
                &format!("{}; command: {}", verdict.reason, facts.args.join(" ")),
            );

            if self.dry_run {
                ui::markup_line(&format!(
                    "[cyan]Would kill pid {} and delete {:?}, then disable its cron lines[/]",
                    facts.pid, verdict.delete
                ));
                run_log::record(&format!("DRY RUN: would remove backdoor pid {}", facts.pid));
                continue;
            }

            let mut ok = true;
            if let Err(e) = kill_process(facts, &verdict.reason).await {
                failures.push(format!("kill {}: {e}", facts.pid));
                ok = false;
            }
            for path in &verdict.delete {
                if let Err(e) = delete_file(path, &verdict.reason).await {
                    failures.push(e);
                    ok = false;
                }
            }
            if let Some(path) = &verdict.left_for_purge {
                ui::markup_line(&format!(
                    "[dim]{} is package-owned and was left in place; Software Management \
                     purges it.[/]",
                    ui::escape(path)
                ));
            }
            match disable_cron_lines(verdict).await {
                Ok(0) => {}
                Ok(n) => ui::markup_line(&format!("[green]✓ Disabled {n} cron line(s)[/]")),
                Err(e) => {
                    failures.push(e);
                    ok = false;
                }
            }
            if let Some(unit) = &facts.unit
                && local_unit(unit).await
                && let Err(e) = systemd_ops::disable(unit, &verdict.reason).await
            {
                failures.push(format!("{unit}: {e}"));
                ok = false;
            }
            if ok {
                result.items_succeeded += 1;
            }
        }

        result.success = failures.is_empty();
        result.message = if self.dry_run {
            format!(
                "DRY RUN: {} backdoor listeners would be removed.",
                backdoors.len()
            )
        } else {
            format!(
                "{} of {} backdoor listeners removed.",
                result.items_succeeded,
                backdoors.len()
            )
        };
        if !failures.is_empty() {
            result.error_details = Some(failures.join("; "));
        }
        result
    }

    async fn verify(&mut self) -> bool {
        if self.dry_run {
            return true;
        }
        find_backdoors(self.readme_data.as_ref()).await.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SS: &str = "\
tcp   LISTEN 0 4096  0.0.0.0:22     0.0.0.0:*   users:((\"sshd\",pid=700,fd=3))
tcp   LISTEN 0 1     0.0.0.0:1337   0.0.0.0:*   users:((\"nc.traditional\",pid=812,fd=3))
tcp   LISTEN 0 4096     [::]:631       [::]:*
udp   UNCONN 0 0   127.0.0.53%lo:53  0.0.0.0:*   users:((\"systemd-resolve\",pid=600,fd=13))
tcp   LISTEN 0 5     0.0.0.0:80     0.0.0.0:*   users:((\"a\",pid=1,fd=3),(\"b\",pid=2,fd=4))
";

    fn facts(comm: &str, exe: &str, args: &[&str]) -> ProcessFacts {
        ProcessFacts {
            pid: 10,
            comm: comm.to_string(),
            exe: exe.to_string(),
            args: args.iter().map(|s| s.to_string()).collect(),
            cwd: Some("/root".to_string()),
            unit: None,
        }
    }

    fn strings(items: &[&str]) -> Vec<String> {
        items.iter().map(|s| s.to_string()).collect()
    }

    fn nothing_owned(_: &str) -> bool {
        false
    }

    #[test]
    fn ss_output_yields_process_port_and_pid() {
        let l = parse_ss(SS);
        assert!(l.contains(&Listener {
            proto: "tcp".into(),
            port: 1337,
            pid: 812,
            process: "nc.traditional".into()
        }));
        assert!(
            l.iter()
                .any(|x| x.port == 53 && x.proto == "udp" && x.pid == 600)
        );
    }

    #[test]
    fn a_socket_with_no_visible_owner_is_skipped() {
        assert!(!parse_ss(SS).iter().any(|l| l.port == 631));
    }

    #[test]
    fn a_shared_socket_yields_each_process() {
        let pids: Vec<u32> = parse_ss(SS)
            .iter()
            .filter(|l| l.port == 80)
            .map(|l| l.pid)
            .collect();
        assert_eq!(pids, [1, 2]);
    }

    #[test]
    fn a_raw_listener_is_a_backdoor_even_when_package_owned() {
        let p = facts(
            "nc.traditional",
            "/usr/bin/nc.traditional",
            &["nc.traditional", "-l", "-p", "1337"],
        );
        let v = classify(&p, None, |path| path == "/usr/bin/nc.traditional").unwrap();
        assert_eq!(v.kind, Kind::RawListener);
        assert!(
            v.delete.is_empty(),
            "a package-owned binary is left for the purge"
        );
        assert_eq!(v.left_for_purge.as_deref(), Some("/usr/bin/nc.traditional"));
    }

    #[test]
    fn an_unowned_raw_listener_binary_is_deleted_too() {
        let p = facts("nc", "/tmp/nc", &["nc", "-l"]);
        let v = classify(&p, None, nothing_owned).unwrap();
        assert_eq!(v.delete, ["/tmp/nc"]);
    }

    #[test]
    fn an_interpreter_running_an_unowned_script_is_a_backdoor() {
        let p = facts(
            "python3",
            "/usr/bin/python3.10",
            &["python3", "/usr/share/zod/kneelB4zod.py"],
        );
        let v = classify(&p, None, |path| path == "/usr/bin/python3.10").unwrap();
        assert_eq!(v.kind, Kind::UnownedScript);
        assert_eq!(v.delete, ["/usr/share/zod/kneelB4zod.py"]);
    }

    #[test]
    fn an_interpreter_running_a_packaged_script_is_not() {
        let p = facts(
            "python3",
            "/usr/bin/python3.10",
            &["python3", "/usr/bin/unattended-upgrade-shutdown"],
        );
        assert!(classify(&p, None, |_| true).is_none());
    }

    #[test]
    fn a_relative_script_is_resolved_against_the_working_directory() {
        let args = strings(&["python3", "-u", "./x.py"]);
        assert_eq!(
            script_path(&args, Some("/root")).as_deref(),
            Some("/root/x.py")
        );
        let inline = strings(&["python3", "-c", "import os"]);
        assert_eq!(script_path(&inline, Some("/root")), None);
    }

    #[test]
    fn an_unowned_binary_outside_the_allowed_directories_is_a_backdoor() {
        let p = facts("svc", "/var/tmp/svc", &["/var/tmp/svc"]);
        assert_eq!(
            classify(&p, None, nothing_owned).unwrap().kind,
            Kind::UnownedBinary
        );
    }

    #[test]
    fn unowned_software_in_the_allowed_directories_is_left_alone() {
        for exe in [
            "/opt/CyberPatriot/x",
            "/snap/foo/1/bin/foo",
            "/usr/local/lib/node_modules/a/b",
        ] {
            assert!(
                classify(&facts("x", exe, &[exe]), None, nothing_owned).is_none(),
                "{exe}"
            );
        }
    }

    #[test]
    fn a_package_owned_service_is_not_a_backdoor() {
        let p = facts("cupsd", "/usr/sbin/cupsd", &["/usr/sbin/cupsd"]);
        assert!(classify(&p, None, |_| true).is_none());
    }

    #[test]
    fn sshd_and_the_scoring_engine_are_never_selected() {
        let sshd = facts("sshd", "/tmp/sshd", &["sshd"]);
        assert!(classify(&sshd, None, nothing_owned).is_none());
        let ccs = facts("CCSClient", "/opt/CyberPatriot/CCSClient", &["CCSClient"]);
        assert!(classify(&ccs, None, nothing_owned).is_none());
    }

    #[test]
    fn a_unit_the_readme_marks_critical_is_never_selected() {
        let readme = ReadmeData {
            critical_services: vec!["Apache".to_string()],
            ..Default::default()
        };
        let mut p = facts("apache2", "/srv/apache2", &["apache2"]);
        p.unit = Some("apache2.service".to_string());
        assert!(classify(&p, Some(&readme), nothing_owned).is_none());
        assert!(classify(&p, None, nothing_owned).is_some());
    }

    #[test]
    fn the_port_number_alone_never_decides() {
        // The classifier does not even see the port: a packaged service on the
        // backdoor's own port is not selected.
        let p = facts("nginx", "/usr/sbin/nginx", &["nginx"]);
        assert!(classify(&p, None, |_| true).is_none());
    }

    #[test]
    fn the_unit_is_read_from_the_cgroup() {
        assert_eq!(
            unit_from_cgroup("0::/system.slice/zod.service\n").as_deref(),
            Some("zod.service")
        );
        assert_eq!(
            unit_from_cgroup("0::/user.slice/user-1000.slice/session-2.scope\n"),
            None
        );
    }

    #[test]
    fn the_planted_cron_line_is_matched() {
        let v = classify(
            &facts(
                "nc.traditional",
                "/usr/bin/nc.traditional",
                &["nc.traditional", "-l", "-p", "1337"],
            ),
            None,
            |_| true,
        )
        .unwrap();
        assert!(cron_line_matches(
            "@reboot root nc.traditional -l -p 1337",
            &v
        ));
        assert!(cron_line_matches(
            "* * * * * root /usr/bin/nc -lvp 4444 -e /bin/sh",
            &v
        ));
        assert!(cron_line_matches(
            "@reboot root socat TCP-LISTEN:9 EXEC:sh",
            &v
        ));
        assert!(
            !cron_line_matches("0 * * * * root nc -z db 5432", &v),
            "a port check is not a listener"
        );
        assert!(!cron_line_matches("# @reboot root nc -l -p 1337", &v));
    }

    #[test]
    fn a_cron_line_naming_the_script_is_matched() {
        let p = facts(
            "python3",
            "/usr/bin/python3",
            &["python3", "/usr/share/zod/kneelB4zod.py"],
        );
        let v = classify(&p, None, |path| path == "/usr/bin/python3").unwrap();
        assert!(cron_line_matches(
            "@reboot root python3 /usr/share/zod/kneelB4zod.py &",
            &v
        ));
        assert!(!cron_line_matches("@reboot root /usr/bin/other", &v));
        assert_eq!(
            disable_cron_line("@reboot x"),
            "# disabled by pinnacle: @reboot x"
        );
    }

    #[test]
    fn every_cron_location_is_searched() {
        for expected in ["/etc/crontab", "/etc/cron.d", "/var/spool/cron/crontabs"] {
            assert!(CRON_LOCATIONS.contains(&expected), "{expected}");
        }
    }

    #[test]
    fn merged_usr_paths_are_looked_up_both_ways() {
        assert_eq!(
            dpkg_candidates("/usr/bin/dash"),
            ["/usr/bin/dash", "/bin/dash"]
        );
        assert_eq!(dpkg_candidates("/opt/x"), ["/opt/x"]);
    }
}
