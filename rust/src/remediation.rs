//! Applies one change and proves the result, recording all three parts - what
//! was wanted, what was done, what the machine says now - in the run log.
//!
//! The pattern this replaces was: call the API, look at what it returned, print
//! a tick. That reports the tool's own intention rather than the machine's
//! state, so a write that succeeded against the wrong key, a service that was
//! reconfigured but is still running, and a policy Windows silently normalised
//! all read as unqualified successes.
//!
//! Here the state is read before acting - which also makes "already compliant"
//! distinguishable from "fixed", worth knowing when deciding what a run actually
//! touched - and read again afterwards. The second read is the evidence. It
//! costs two extra API calls per change, which against a process launch per
//! change is not measurable.

use crate::models::FixOutcome;
use crate::run_log;
use std::future::Future;

/// Read the state, apply the change if it is not already right, then read it
/// back and record what happened.
///
/// Returns `Ok(())` on success or the reason the write failed, keeping the same
/// contract as the operation it wraps.
///
/// - `target` is the exact thing being changed, specific enough to check by hand.
/// - `intent` is the wanted end state, and why it matters.
/// - `read_state` reads the current state as text; `None` means it could not be
///   read, which is not the same as it being wrong.
/// - `action` names concretely what the write does.
pub async fn apply<Read, ReadFut, Apply, ApplyFut>(
    target: &str,
    intent: &str,
    read_state: Read,
    is_compliant: impl Fn(&str) -> bool,
    action: &str,
    apply_write: Apply,
) -> Result<(), String>
where
    Read: Fn() -> ReadFut,
    ReadFut: Future<Output = Option<String>>,
    Apply: FnOnce() -> ApplyFut,
    ApplyFut: Future<Output = Result<(), String>>,
{
    if run_log::dry_run() {
        let previewed = read_state().await;
        run_log::record_fix(
            target,
            intent,
            previewed,
            &format!("nothing - dry run. Would have: {action}"),
            FixOutcome::Skipped,
            "not attempted, so nothing to prove",
        );
        return Ok(());
    }

    let before = read_state().await;
    if let Some(state) = &before {
        if is_compliant(state) {
            run_log::record_fix(
                target,
                intent,
                before.clone(),
                "nothing - already in the wanted state",
                FixOutcome::AlreadyCompliant,
                &format!("read before acting: {state}"),
            );
            return Ok(());
        }
    }

    let result = apply_write().await;
    let after = read_state().await;

    if let Err(failure) = result {
        let evidence = match &after {
            None => format!("the write failed ({failure}) and the state could not be read back"),
            Some(state) => format!("reads {state} after the attempt; the write failed: {failure}"),
        };
        run_log::record_fix(
            target,
            intent,
            before,
            action,
            FixOutcome::Failed,
            &evidence,
        );
        return Err(failure);
    }

    let Some(state) = after else {
        run_log::record_fix(
            target,
            intent,
            before,
            action,
            FixOutcome::Unverified,
            "the write reported success but the state could not be read back",
        );
        return Ok(());
    };

    if is_compliant(&state) {
        run_log::record_fix(
            target,
            intent,
            before,
            action,
            FixOutcome::Fixed,
            &format!("read back after the write: {state}"),
        );
        return Ok(());
    }

    // The write said it worked and the machine disagrees. The operation is still
    // reported as succeeding, because that is what it did and a task cannot act
    // on this any differently - but the ledger says plainly that the change did
    // not land, which is the thing worth knowing afterwards.
    run_log::record_fix(
        target,
        intent,
        before,
        action,
        FixOutcome::Unverified,
        &format!("the write reported success but the state still reads {state}"),
    );
    Ok(())
}

/// Apply a change whose result cannot be read back, and say so rather than
/// claiming proof there is none of.
///
/// Setting a password is the case this exists for: Windows will not hand one
/// back, so the strongest available evidence is the status code the account
/// database returned. Recording that honestly is worth more than a tick that
/// implies a verification that never happened.
pub async fn apply_unprovable<Apply, ApplyFut>(
    target: &str,
    intent: &str,
    action: &str,
    why_unprovable: &str,
    apply_write: Apply,
) -> Result<(), String>
where
    Apply: FnOnce() -> ApplyFut,
    ApplyFut: Future<Output = Result<(), String>>,
{
    // `None` in the `before` field means "we looked and could not see". Nothing
    // here looks at all, so it says so rather than borrowing a stronger claim.
    let before = || Some(NOT_READ.to_string());

    if run_log::dry_run() {
        run_log::record_fix(
            target,
            intent,
            before(),
            &format!("nothing - dry run. Would have: {action}"),
            FixOutcome::Skipped,
            "not attempted, so nothing to prove",
        );
        return Ok(());
    }

    if let Err(failure) = apply_write().await {
        run_log::record_fix(
            target,
            intent,
            before(),
            action,
            FixOutcome::Failed,
            &failure,
        );
        return Err(failure);
    }

    run_log::record_fix(
        target,
        intent,
        before(),
        action,
        FixOutcome::Unverified,
        &format!("cannot be confirmed by reading - {why_unprovable}"),
    );
    Ok(())
}

/// Stands in the `before` field for a change that never read the state, keeping
/// it distinct from a read that was attempted and failed.
const NOT_READ: &str = "(not read)";

/// Record something the tool deliberately did not touch, so the ledger shows the
/// decision rather than a silent absence.
pub fn record_skipped(target: &str, intent: &str, why: &str) {
    run_log::record_fix(
        target,
        intent,
        Some(NOT_READ.to_string()),
        &format!("nothing - {why}"),
        FixOutcome::Skipped,
        "not attempted, so nothing to prove",
    );
}

/// Record a finding an audit task can only report, with the observation that
/// backs it.
///
/// The audit-only tasks - hosts file, scheduled tasks, DNS - have findings worth
/// carrying in the same ledger as the changes, so one place answers "what did
/// this run learn about the machine".
pub fn record_finding(target: &str, intent: &str, compliant: bool, evidence: &str) {
    run_log::record_fix(
        target,
        intent,
        Some(NOT_READ.to_string()),
        "nothing - this task reports rather than changes",
        if compliant {
            FixOutcome::AlreadyCompliant
        } else {
            FixOutcome::Failed
        },
        evidence,
    );
}

#[cfg(test)]
// The gate has to span the awaits, because what it is serialising is the whole
// record-then-inspect sequence against the process-global log. Nothing awaited
// under it ever waits on the gate itself, so it cannot deadlock: each
// `#[tokio::test]` drives its own current-thread runtime, and a test blocked on
// the gate is blocking an OS thread, not starving a runtime that holds it.
#[allow(clippy::await_holding_lock)]
mod tests {
    use super::*;
    use crate::run_log;
    use std::cell::Cell;

    /// Drive `apply` against a state that changes only if `writes` says so, and
    /// report the outcome the ledger recorded.
    async fn outcome_of(before: &str, after: &str, write: Result<(), String>) -> FixOutcome {
        let _gate = run_log::test_gate();
        run_log::clear();

        let acted = Cell::new(false);
        let _ = apply(
            "Thing",
            "wanted",
            || async { Some(if acted.get() { after } else { before }.to_string()) },
            |s| s == "wanted",
            "did the thing",
            || async {
                acted.set(true);
                write
            },
        )
        .await;

        let fixes = run_log::fixes();
        assert_eq!(fixes.len(), 1, "expected exactly one record: {fixes:?}");
        let outcome = fixes[0].outcome;
        run_log::clear();
        outcome
    }

    #[tokio::test]
    async fn a_write_that_lands_is_fixed() {
        assert_eq!(
            outcome_of("wrong", "wanted", Ok(())).await,
            FixOutcome::Fixed
        );
    }

    #[tokio::test]
    async fn a_state_already_right_is_not_written_again() {
        let _gate = run_log::test_gate();
        run_log::clear();

        let acted = Cell::new(false);
        let _ = apply(
            "Thing",
            "wanted",
            || async { Some("wanted".to_string()) },
            |s| s == "wanted",
            "did the thing",
            || async {
                acted.set(true);
                Ok(())
            },
        )
        .await;

        assert!(!acted.get(), "a compliant machine must not be written to");
        assert_eq!(run_log::fixes()[0].outcome, FixOutcome::AlreadyCompliant);
        run_log::clear();
    }

    #[tokio::test]
    async fn a_failed_write_is_failed() {
        assert_eq!(
            outcome_of("wrong", "wrong", Err("denied".to_string())).await,
            FixOutcome::Failed
        );
    }

    /// The case the ledger exists for: the API said yes and the machine did not
    /// change. Reporting this as a success is exactly the lie being fixed.
    #[tokio::test]
    async fn a_write_that_reports_success_but_does_not_land_is_unverified() {
        assert_eq!(
            outcome_of("wrong", "still wrong", Ok(())).await,
            FixOutcome::Unverified
        );
    }

    #[tokio::test]
    async fn a_dry_run_changes_nothing_and_records_the_intent() {
        let _gate = run_log::test_gate();
        run_log::clear();
        run_log::set_dry_run(true);

        let acted = Cell::new(false);
        let _ = apply(
            "Thing",
            "wanted",
            || async { Some("wrong".to_string()) },
            |s| s == "wanted",
            "did the thing",
            || async {
                acted.set(true);
                Ok(())
            },
        )
        .await;

        assert!(!acted.get(), "a dry run must not write");
        let fixes = run_log::fixes();
        assert_eq!(fixes[0].outcome, FixOutcome::Skipped);
        // The intent still has to be recorded - a dry run's whole purpose is to
        // report what it would have done.
        assert!(fixes[0].action.contains("Would have: did the thing"));

        run_log::clear();
    }
}
