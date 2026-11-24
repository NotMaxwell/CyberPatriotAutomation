# STIG Alignment — Roadmap (mock-up)

Status: **planned**. Nothing here is implemented yet. Tracked as issues labelled
`stig`.

## Why

The knowledge tables (`crates/windows/src/knowledge.rs`,
`crates/linux/src/knowledge.rs`) were built from checklists and answer keys.
That has found what CyberPatriot scores, but nothing says *which published
control* a setting implements, or which controls the tool has never looked at.
DISA STIGs are the most complete public list of hardening controls for the
exact operating systems CyberPatriot ships, so they make a good coverage map.

**A STIG is not an answer key.** It is written for DoD networks. Some controls
score nothing in CyberPatriot, and some break the image (DoD banner text, DoD
time source, CAC/PKI, FIPS mode). The goal is *traceability and gap-finding*,
not "apply the whole STIG".

## Which STIG for which image

| Competition image | STIG | Notes |
|---|---|---|
| Windows 11 | Microsoft Windows 11 STIG (V2Rx) | Highest priority — CP-19 Round 1 image |
| Linux Mint 21 | Canonical Ubuntu 22.04 LTS STIG (V2Rx) | No Mint STIG exists. Mint 21 is built on Ubuntu 22.04; paths for the desktop and display manager (Cinnamon/LightDM vs GNOME/GDM) differ |
| Windows Server 2019 | Microsoft Windows Server 2019 STIG (V3Rx) | DC vs member-server rules: CyberPatriot images are usually standalone or member |
| Windows Server 2022 | Microsoft Windows Server 2022 STIG (V2Rx) | |
| Windows 10 | Microsoft Windows 10 STIG (V3Rx) | |
| Ubuntu 22.04 | Canonical Ubuntu 22.04 LTS STIG (V2Rx) | Same STIG as Mint |
| Debian | none from DISA — CIS Debian Benchmark | Out of scope until a Debian image reappears |

Source: <https://public.cyber.mil/stigs/downloads/> (public, no CAC). The
session sandbox cannot reach that host, so the zips are downloaded by hand.

## Status for every STIG rule

Every rule in an imported STIG gets exactly one status. An empty status
fails the tests.

| Status | Meaning |
|---|---|
| `Covered` | A table entry or task implements it; `covered_by` names it |
| `Gap` | Applicable and not implemented; `issue` names the GitHub issue |
| `ReadmeGated` | Applied only when the README does not require the service (RDP, SMB shares, FTP, SSH, Apache…). Gated through `readme_services`, never by string matching |
| `SkipDoD` | DoD-only: banner text, DoD time source, PKI/CAC, DoD-specific software. Scores nothing, can break the image |
| `SkipRisky` | Breaks scoring or required programs: FIPS mode, strict AppLocker/WDAC, blocking removable media, disabling the CCS Client's dependencies |
| `Manual` | Needs a human (physical security, documentation, site procedures) |

## Milestones

### S1 — STIG importer

A dev-only tool (`rust/xtask` or `scripts/stig_import.py`) that reads the
`*_Manual-xccdf.xml` inside a DISA STIG zip and writes
`docs/stig/<os>.csv` with one row per rule:

`vuln_id, rule_id, stig_id, severity, title, status, covered_by, issue, note`

- Re-running it on a newer release **keeps** the hand-written columns
  (`status`, `covered_by`, `issue`, `note`) and adds rows for new rules,
  marking dropped ones `Removed`, so a STIG revision shows up as a diff.
- STIG IDs come from the XCCDF, never typed by hand.
- DISA content is a US Government work; committing the extracted titles is
  fine. Do not commit the zips.

### S2 — Traceability in the tables

- Add `stig: &[&str]` to Linux `Setting` and an equivalent for the Windows
  registry, feature, service, audit and firewall tables. (The Windows registry
  table is a 5-tuple: convert it to a struct in its own commit first.)
- Table tests, in the style `knowledge.rs` already uses:
  - every `stig` ID in a table exists in the CSV for that OS
  - every CSV row marked `Covered` is referenced by at least one table entry
  - every CAT I row is `Covered`, `ReadmeGated`, `Skip*` with a `note`, or `Gap` with an `issue`
- `FixRecord` gains an optional `stig` field so the remediation ledger prints
  `WN11-…` next to the change.

### S3 — `--stig-report` (audit only)

A task that changes nothing: for each `Covered`/`ReadmeGated` rule, read the
machine through the **same read path the owning task's `verify()` uses**, and
record `Compliant` / `NonCompliant` / `Unreadable` with `RecordFinding`.
Output: a section of the run log, plus `stig-report.csv` beside it.

Use it on a fresh practice image *before* a run to see what is open, and
*after* to show what changed.

### S4 — Close the gaps (by priority)

1. Windows 11 CAT I, then CAT II
2. Ubuntu 22.04 STIG on Mint 21, CAT I then CAT II, with Mint path differences
3. Server 2019 / 2022 (member server)
4. Windows 10, Ubuntu 22.04 (mostly inherited from 1 and 2)

Each gap closed follows the existing workflow: table entry → `remediation::apply`
→ dry-run honoured → test. Where an Exhibition Round answer key covers the same
item, add the item to `answer_key.rs` as well — the answer key decides whether a
setting is worth points, the STIG decides whether it is a recognised control.

## Rules check

The CyberPatriot Rules Book governs whether a script may be run during a
round. CP-XI allowed scripts "at their own risk" and barred sharing them
between teams of the same school. Re-read the current season's rule 4009
before every season. Nothing in this roadmap changes how the tool is run.
