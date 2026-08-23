/// How one attempted change turned out.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FixOutcome {
    /// The machine was already in the wanted state; nothing was written.
    AlreadyCompliant,
    /// The change was made and reading the state back confirms it.
    Fixed,
    /// The change was attempted and did not take.
    Failed,
    /// The write reported success but the result could not be confirmed -
    /// either the state could not be read back, or it read back as something
    /// else.
    Unverified,
    /// Nothing was attempted; a dry run, or deliberately left alone.
    Skipped,
}

impl FixOutcome {
    /// The fixed-width tag the ledger and the narrative share.
    pub fn tag(self) -> &'static str {
        match self {
            FixOutcome::Fixed => "FIXED",
            FixOutcome::AlreadyCompliant => "ALREADY OK",
            FixOutcome::Failed => "FAILED",
            FixOutcome::Unverified => "UNVERIFIED",
            FixOutcome::Skipped => "SKIPPED",
        }
    }

    /// Did this leave the machine in the wanted state?
    pub fn is_compliant(self) -> bool {
        matches!(self, FixOutcome::Fixed | FixOutcome::AlreadyCompliant)
    }
}

/// One attempted change: what the tool wanted, what it did, and how it knows
/// whether it worked.
///
/// The console narrative says "✓ Disabled TlntSvr" and the run log mirrors it,
/// but that line is the tool quoting its own intention back: it is written on
/// the strength of an exit code or an `Ok(())`, not on the strength of having
/// looked. A record where the remediation silently did nothing is
/// indistinguishable from one where it worked.
///
/// Every field here exists so a competitor can audit a claim without re-running
/// anything. `evidence` in particular is a re-read of the real state taken after
/// the write, not a restatement of `action`.
#[derive(Debug, Clone)]
pub struct FixRecord {
    /// The task that wanted the change.
    pub task: String,
    /// The exact thing being changed, specific enough to check by hand - a full
    /// registry path, a service name, an account name.
    pub target: String,
    /// The wanted end state, and why it matters.
    pub intent: String,
    /// The state observed before acting, or `None` when it could not be read.
    pub before: Option<String>,
    /// What the tool actually did, named concretely.
    pub action: String,
    pub outcome: FixOutcome,
    /// The proof: what reading the state back afterwards returned.
    pub evidence: String,
}
