# AI-Assisted Session Manager — Roadmap (mock-up)

Status: **planned**. Nothing here is implemented yet. Tracked as issues labelled
`ai`.

## What it is

An opt-in mode (`--ai`, and a screen in the GUI) that keeps the state of a whole
round in one place and asks an LLM to help **prioritise and explain**. It never
changes the machine itself.

The tool already knows most of what a team needs during a round: the parsed
README, the directives it could not automate (`directives.rs` → `Manual`), and
the remediation ledger (`Fixed` / `Failed` / `Unverified` / `Skipped`). What it
lacks is (a) a record that lasts across runs and (b) help turning the Manual pile
into an ordered to-do list. This roadmap adds both, and the first does not need AI.

## Hard rules

1. **The advisor proposes; a person decides.** The output is either a
   `TaskSpec` flag to run (shown, then confirmed) or a manual checklist item.
   The advisor never gets a shell, never writes files, never calls
   `remediation::apply`.
2. **Off by default.** `--ai` must be given each run. With no API key or no
   network, the session manager still works; only the advisor panel goes empty.
3. **Redact before sending.** Passwords from the README's authorised-users
   section, the API key, and anything matching a password-shaped field are
   replaced with placeholders before a prompt leaves the machine. Tested.
4. **Everything is logged.** Each prompt (redacted), response, and the person's
   accept/reject goes into the run log under its own section, tagged
   `Source: advisor`, so a reader can tell what the tool decided from what the
   model suggested.
5. **Competition use depends on the rules.** The current Rules Book has to
   permit AI tools during a round before `--ai` is used in one. Until that
   is confirmed, it is for practice images and Exhibition Rounds. The flag
   prints this on start.

## Milestones

### A1 — Session state (no AI)

`session.json` beside the run log, updated after every task:

- README digest (`ReadmeData`) and its hash, so a changed README is noticed
- directives with their classification
- every `FixRecord` from every run this round, newest first
- the manual checklist: `Manual` directives + `Failed`/`Unverified` ledger
  entries + forensic-question files found on the desktop, each with a
  `done` flag the person ticks

`--resume` reloads it, so a second run (or a crash) does not lose the
checklist. Lives in `pinnacle-core` (names no OS).

### A2 — Score feedback loop (no AI)

Parse the local CyberPatriot scoring report (the HTML the CCS Client writes)
into `(item, points)` after each task. Show the delta per task in the run
log and session: "Security Hardening: +12, −5 (Penalty: …)". A penalty that
appears right after a task names that task as the suspect, and the ledger
entry's `Before` value is offered as the rollback.

Start this read-only. Rollback only for changes whose `Before` was recorded and
can be written back through the same `*_ops` path.

### A3 — `Advisor` trait and provider

- `pinnacle_core::advisor::Advisor` trait: `async fn advise(&SessionSnapshot) -> Advice`
- `Advice` = ordered list of `{ kind: RunTask(flag) | Manual(text), reason, confidence }`;
  a `RunTask` whose flag is not in `Host::tasks()` is dropped, not shown
- First provider: Anthropic Messages API over `reqwest` with **rustls**,
  so the Linux binary stays static musl and passes `publish.sh`'s glibc check.
  Key from `ANTHROPIC_API_KEY`; never written to the log or session file.
- A `NullAdvisor` for tests and offline runs; snapshot tests on the prompt
  built from each README in the corpus (after redaction)

### A4 — What the advisor is asked

In order of value:

1. **Classify `Manual` directives**: map README prose the regexes do not
   understand onto existing flags, or into a manual checklist item that says
   where to click or what to run
2. **Prioritise the checklist** by likely points and risk to critical services
3. **Explain `Failed`/`Unverified` ledger entries** in plain words, with the
   command a person would try next
4. **Draft the end-of-round notes**: what was done, what is still open

Forensic questions are **not** sent to the model by default; that is the
part of the round most likely to count as outside help.

### A5 — GUI and TUI surfaces

- GUI: an "Advisor" panel next to the results screen (#5's screens), with
  accept/reject per item; accepted `RunTask` items go through the existing
  task-confirmation screen (#4), never straight to execution
- Linux web UI (#6): same panel, same token/Origin checks
- TUI: a menu entry that prints the advice and asks y/n per item. Removed with
  the TUI in #7.

## Out of scope

- Letting the model run commands (an agent loop). Revisit only if the
  rules explicitly allow it and A1–A5 have been used in real rounds.
- Local models. The trait allows one later; no GPU in a competition VM.
