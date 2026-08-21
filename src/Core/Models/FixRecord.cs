namespace CyberPatriotAutomation.Core.Models;

/// <summary>How one attempted change turned out.</summary>
public enum FixOutcome
{
    /// <summary>The machine was already in the wanted state; nothing was written.</summary>
    AlreadyCompliant,

    /// <summary>The change was made and reading the state back confirms it.</summary>
    Fixed,

    /// <summary>The change was attempted and did not take.</summary>
    Failed,

    /// <summary>
    /// The write reported success but the result could not be confirmed - either
    /// the state could not be read back, or it read back as something else.
    /// </summary>
    Unverified,

    /// <summary>Nothing was attempted; a dry run, or deliberately left alone.</summary>
    Skipped,
}

/// <summary>
/// One attempted change: what the tool wanted, what it did, and how it knows
/// whether it worked.
/// </summary>
/// <remarks>
/// <para>
/// The console narrative says "✓ Disabled TlntSvr" and the run log mirrors it,
/// but that line is the tool quoting its own intention back: it is written on the
/// strength of an exit code or a null return, not on the strength of having
/// looked. A record where the remediation silently did nothing is
/// indistinguishable from one where it worked.
/// </para>
/// <para>
/// Every field here exists so a competitor can audit a claim without re-running
/// anything. <see cref="Evidence"/> in particular is a re-read of the real state
/// taken after the write, not a restatement of <see cref="Action"/>.
/// </para>
/// </remarks>
/// <param name="Task">The task that wanted the change.</param>
/// <param name="Target">
/// The exact thing being changed, specific enough to check by hand - a full
/// registry path, a service name, an account name.
/// </param>
/// <param name="Intent">The wanted end state, and why it matters.</param>
/// <param name="Before">
/// The state observed before acting, or null when it could not be read.
/// </param>
/// <param name="Action">What the tool actually did, named concretely.</param>
/// <param name="Outcome">How it turned out.</param>
/// <param name="Evidence">
/// The proof: what reading the state back afterwards returned.
/// </param>
public sealed record FixRecord(
    string Task,
    string Target,
    string Intent,
    string? Before,
    string Action,
    FixOutcome Outcome,
    string Evidence
)
{
    public DateTime RecordedAt { get; init; } = DateTime.Now;

    /// <summary>The fixed-width tag the ledger and the narrative share.</summary>
    public string Tag =>
        Outcome switch
        {
            FixOutcome.Fixed => "FIXED",
            FixOutcome.AlreadyCompliant => "ALREADY OK",
            FixOutcome.Failed => "FAILED",
            FixOutcome.Unverified => "UNVERIFIED",
            FixOutcome.Skipped => "SKIPPED",
            _ => "?",
        };

    /// <summary>Did this leave the machine in the wanted state?</summary>
    public bool IsCompliant =>
        Outcome is FixOutcome.Fixed or FixOutcome.AlreadyCompliant;
}
