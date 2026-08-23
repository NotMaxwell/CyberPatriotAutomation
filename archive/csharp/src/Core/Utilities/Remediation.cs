// =============================================================================
// PinnacleCyPat - Prove-and-record wrapper for every change
// Author: Maxwell McCormick
// Copyright (c) 2026 Maxwell McCormick. All Rights Reserved.
// =============================================================================
using PinnacleCyPat.Core.Models;

namespace PinnacleCyPat.Core.Utilities;

/// <summary>
/// Applies one change and proves the result, recording all three parts - what
/// was wanted, what was done, what the machine says now - in the run log.
/// </summary>
/// <remarks>
/// <para>
/// The pattern this replaces was: call the API, look at what it returned, print
/// a tick. That reports the tool's own intention rather than the machine's
/// state, so a write that succeeded against the wrong key, a service that was
/// reconfigured but is still running, and a policy Windows silently normalised
/// all read as unqualified successes.
/// </para>
/// <para>
/// Here the state is read before acting - which also makes "already compliant"
/// distinguishable from "fixed", worth knowing when deciding what a run actually
/// touched - and read again afterwards. The second read is the evidence. It
/// costs two extra API calls per change, which against a process launch per
/// change is not measurable.
/// </para>
/// </remarks>
public static class Remediation
{
    /// <summary>
    /// Read the state, apply the change if it is not already right, then read it
    /// back and record what happened. Returns null on success or the reason the
    /// write failed, keeping the same contract as the operation it wraps.
    /// </summary>
    /// <param name="target">
    /// The exact thing being changed, specific enough to check by hand.
    /// </param>
    /// <param name="intent">The wanted end state, and why it matters.</param>
    /// <param name="readState">
    /// Reads the current state as text. Null means it could not be read, which
    /// is not the same as it being wrong.
    /// </param>
    /// <param name="isCompliant">Is a state read by <paramref name="readState"/> the wanted one?</param>
    /// <param name="action">What the write does, named concretely.</param>
    /// <param name="apply">Performs the write. Null on success, or the reason.</param>
    public static async Task<string?> ApplyAsync(
        string target,
        string intent,
        Func<Task<string?>> readState,
        Func<string, bool> isCompliant,
        string action,
        Func<Task<string?>> apply
    )
    {
        if (RunLog.DryRun)
        {
            var previewed = await readState();
            RunLog.RecordFix(
                target,
                intent,
                previewed,
                $"nothing - dry run. Would have: {action}",
                FixOutcome.Skipped,
                "not attempted, so nothing to prove"
            );
            return null;
        }

        var before = await readState();
        if (before is not null && isCompliant(before))
        {
            RunLog.RecordFix(
                target,
                intent,
                before,
                "nothing - already in the wanted state",
                FixOutcome.AlreadyCompliant,
                $"read before acting: {before}"
            );
            return null;
        }

        var failure = await apply();
        var after = await readState();

        if (failure is not null)
        {
            RunLog.RecordFix(
                target,
                intent,
                before,
                action,
                FixOutcome.Failed,
                after is null
                    ? $"the write failed ({failure}) and the state could not be read back"
                    : $"reads {after} after the attempt; the write failed: {failure}"
            );
            return failure;
        }

        if (after is null)
        {
            RunLog.RecordFix(
                target,
                intent,
                before,
                action,
                FixOutcome.Unverified,
                "the write reported success but the state could not be read back"
            );
            return null;
        }

        if (isCompliant(after))
        {
            RunLog.RecordFix(
                target,
                intent,
                before,
                action,
                FixOutcome.Fixed,
                $"read back after the write: {after}"
            );
            return null;
        }

        // The write said it worked and the machine disagrees. The operation is
        // still reported as succeeding, because that is what it did and a task
        // cannot act on this any differently - but the ledger says plainly that
        // the change did not land, which is the thing worth knowing afterwards.
        RunLog.RecordFix(
            target,
            intent,
            before,
            action,
            FixOutcome.Unverified,
            $"the write reported success but the state still reads {after}"
        );
        return null;
    }

    /// <summary>
    /// Apply a change whose result cannot be read back, and say so rather than
    /// claiming proof there is none of.
    /// </summary>
    /// <remarks>
    /// Setting a password is the case this exists for: Windows will not hand one
    /// back, so the strongest available evidence is the status code the account
    /// database returned. Recording that honestly is worth more than a tick that
    /// implies a verification that never happened.
    /// </remarks>
    public static async Task<string?> ApplyUnprovableAsync(
        string target,
        string intent,
        string action,
        string whyUnprovable,
        Func<Task<string?>> apply
    )
    {
        if (RunLog.DryRun)
        {
            RunLog.RecordFix(
                target,
                intent,
                NotRead,
                $"nothing - dry run. Would have: {action}",
                FixOutcome.Skipped,
                "not attempted, so nothing to prove"
            );
            return null;
        }

        var failure = await apply();
        if (failure is not null)
        {
            RunLog.RecordFix(target, intent, NotRead, action, FixOutcome.Failed, failure);
            return failure;
        }

        RunLog.RecordFix(
            target,
            intent,
            NotRead,
            action,
            FixOutcome.Unverified,
            $"cannot be confirmed by reading - {whyUnprovable}"
        );
        return null;
    }

    /// <summary>
    /// Stands in the "before" field for a change that never read the state,
    /// keeping it distinct from a read that was attempted and failed.
    /// </summary>
    private const string NotRead = "(not read)";

    /// <summary>
    /// Record something the tool deliberately did not touch, so the ledger shows
    /// the decision rather than a silent absence.
    /// </summary>
    public static void RecordSkipped(string target, string intent, string why) =>
        RunLog.RecordFix(
            target,
            intent,
            NotRead,
            $"nothing - {why}",
            FixOutcome.Skipped,
            "not attempted, so nothing to prove"
        );

    /// <summary>
    /// Record a finding an audit task can only report, with the observation that
    /// backs it.
    /// </summary>
    /// <remarks>
    /// The audit-only tasks - hosts file, scheduled tasks, DNS - have findings
    /// worth carrying in the same ledger as the changes, so one place answers
    /// "what did this run learn about the machine".
    /// </remarks>
    public static void RecordFinding(
        string target,
        string intent,
        bool compliant,
        string evidence
    ) =>
        RunLog.RecordFix(
            target,
            intent,
            NotRead,
            "nothing - this task reports rather than changes",
            compliant ? FixOutcome.AlreadyCompliant : FixOutcome.Failed,
            evidence
        );
}
