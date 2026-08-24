// =============================================================================
// PinnacleCyPat - README directives: what this round does differently
// Author: Maxwell McCormick
// Copyright 2026 Maxwell McCormick
// SPDX-License-Identifier: Apache-2.0
// =============================================================================

//! The instructions in a README that fall *outside* the standard checklist.
//!
//! Most of a hardening run is the same every round - Guest off, SMB1 gone,
//! firewall on, audit policy logging both success and failure. That part is
//! mechanical and the tasks handle it. What loses points is the other part: the
//! sentence buried in paragraph four saying this particular machine is
//! administered over SSH, or that Firefox must come from a PPA rather than a
//! snap, or that the display manager must stay as it is.
//!
//! A generic script does the standard thing and quietly gets those wrong. This
//! module reads the prose and says, for each such instruction, one of three
//! things:
//!
//! - **A task acts on it.** The README changed the tool's behaviour, and here is
//!   which task and how.
//! - **The tool never touches this.** The instruction is satisfied by inaction,
//!   which is worth saying explicitly - "do not change the time zone" is a
//!   promise the tool can keep only because it has no code that would.
//! - **A person has to do it.** The tool cannot, and saying so is the whole
//!   point: an unhandled instruction that nobody notices is a lost item, and
//!   before this there was no list of them.
//!
//! That last category is why this exists. The parser already extracts what it
//! can act on; everything it cannot act on used to vanish silently.

use crate::html;
use regex::Regex;
use std::sync::OnceLock;

/// What, if anything, the tool does about an instruction.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Handling {
    /// A task acts on it. The string names the task and what it does.
    Automated(&'static str),
    /// The tool has no code that would violate it. The string says why that is
    /// true, because "we do not do that" is only reassuring if it is checkable.
    SafeByInaction(&'static str),
    /// A person has to do it, and the string says what.
    Manual(&'static str),
}

impl Handling {
    /// Does this need a human?
    pub fn needs_a_person(self) -> bool {
        matches!(self, Handling::Manual(_))
    }

    /// The short tag used in reports.
    pub fn tag(self) -> &'static str {
        match self {
            Handling::Automated(_) => "AUTOMATED",
            Handling::SafeByInaction(_) => "NOT TOUCHED",
            Handling::Manual(_) => "BY HAND",
        }
    }

    /// The explanation, whichever variant this is.
    pub fn detail(self) -> &'static str {
        match self {
            Handling::Automated(s) | Handling::SafeByInaction(s) | Handling::Manual(s) => s,
        }
    }
}

/// One instruction found in the README.
#[derive(Debug, Clone)]
pub struct Directive {
    /// What it is about, in two or three words.
    pub subject: &'static str,
    /// The sentence, verbatim, so the reader can check the classification.
    pub sentence: String,
    pub handling: Handling,
}

/// One thing to look for, and what the tool does about it.
struct Pattern {
    /// Matched against a single sentence of the README's plain text.
    regex: &'static str,
    subject: &'static str,
    handling: Handling,
}

/// Everything worth recognising, in the order a report should list it.
///
/// Deliberately conservative: a pattern that fires on prose it does not
/// understand produces a confident, wrong classification, which is worse than
/// the sentence going unmentioned. Each is anchored on wording that has
/// actually appeared in a competition README.
const PATTERNS: &[Pattern] = &[
    // --- instructions that change what a task does -------------------------
    Pattern {
        regex: r"(?i)\b(\w+)\s+is\s+a\s+critical\s+service",
        subject: "a critical service",
        handling: Handling::Automated(
            "Service Management protects it and never masks it; Firewall opens its port",
        ),
    },
    Pattern {
        regex: r"(?i)must\s+be\s+able\s+to\s+log\s+in\s+remotely",
        subject: "remote access",
        handling: Handling::Automated(
            "the remote-access service is kept running and its port opened",
        ),
    },
    Pattern {
        regex: r"(?i)only\s+company\s+approved\s+firewall.*?\bis\s+(\w+)",
        subject: "which firewall",
        handling: Handling::Automated("Firewall configures ufw, and nothing else"),
    },
    Pattern {
        regex: r"(?i)never\s+let\s+users\s+log\s+in\s+as\s+root",
        subject: "root login",
        handling: Handling::Automated(
            "Security Hardening sets PermitRootLogin no; Account Permissions checks for a second uid 0",
        ),
    },
    Pattern {
        regex: r"(?i)required\s+to\s+use\s+the\s+.?sudo.?\s+command",
        subject: "sudo, not root",
        handling: Handling::Automated("User Management maintains the sudo group from the README"),
    },
    Pattern {
        regex: r"(?i)(?:not\s+required|NOT\s+required)\s+to\s+change\s+the\s+password\s+of\s+the\s+primary",
        subject: "the primary user's password",
        handling: Handling::Automated(
            "User Management never resets the primary auto-login account",
        ),
    },
    Pattern {
        regex: r"(?i)do\s+not\s+remove\s+any\s+authorized\s+users\s+or\s+their\s+home\s+directories",
        subject: "home directories",
        handling: Handling::Automated(
            "User Management removes only unauthorised accounts, and keeps every home directory",
        ),
    },
    Pattern {
        regex: r"(?i)do\s+not\s+(?:stop\s+or\s+)?disable\s+the\s+CCS\s+Client",
        subject: "the scoring engine",
        handling: Handling::Automated("CCS Client is on the never-disable list, README or not"),
    },
    Pattern {
        regex: r"(?i)use\s+only\s+the\s+latest,?\s+official,?\s+stable",
        subject: "package versions",
        handling: Handling::Automated(
            "Software Updates upgrades everything from the official repositories",
        ),
    },
    Pattern {
        regex: r"(?i)(?:presence\s+of\s+any\s+)?non-?work\s+related\s+media\s+files.*?prohibited",
        subject: "media files",
        handling: Handling::Automated(
            "Prohibited Media deletes them; without this sentence it only reports",
        ),
    },
    Pattern {
        regex: r"(?i)add\s+(?:the\s+)?users?\s+.{0,40}?\s+to\s+the\s+.{0,30}?\s+group",
        subject: "a group membership",
        handling: Handling::Automated("User Management adds the named members"),
    },
    Pattern {
        regex: r"(?i)(?:Action\s+Center|Security\s+Center)\s+should\s+be\s+enabled",
        subject: "Action Center",
        handling: Handling::Automated("Security Hardening leaves Action Center reporting enabled"),
    },
    // --- instructions the tool honours by having no code that would break them
    Pattern {
        regex: r"(?i)do\s+not\s+change\s+the\s+time\s*zone",
        subject: "the clock",
        handling: Handling::SafeByInaction("no task calls timedatectl, date or the time-zone APIs"),
    },
    Pattern {
        regex: r"(?i)do\s+not\s+disable\s+JavaScript",
        subject: "JavaScript",
        handling: Handling::SafeByInaction("no task changes browser settings"),
    },
    Pattern {
        regex: r"(?i)do\s+NOT\s+attempt\s+to\s+(?:install|use)\s+(?:Windows\s+)?.?(?:Feature\s+Updates|Insider|Reset\s+this\s+PC|Go\s+back)",
        subject: "Windows feature updates",
        handling: Handling::SafeByInaction(
            "Software Updates upgrades applications only, never the OS build",
        ),
    },
    Pattern {
        regex: r"(?i)Unique\s+Identifier",
        subject: "the unique identifier",
        handling: Handling::Manual(
            "enter it from the desktop icon before doing anything else, or the VM stops working",
        ),
    },
    // --- instructions a person has to carry out -----------------------------
    Pattern {
        regex: r"(?i)Forensics\s+Questions?",
        subject: "forensics questions",
        handling: Handling::Manual(
            "read them from the Desktop and answer them BEFORE running any task - a remediation can destroy the evidence",
        ),
    },
    Pattern {
        regex: r"(?i)must\s+remain\s+installed\s+using\s+the\s+official\s+(\w+)\s+PPA",
        subject: "install source",
        handling: Handling::Manual(
            "apt installs the snap transitional package on Ubuntu 22.04; add the PPA and pin it by hand",
        ),
    },
    Pattern {
        regex: r"(?i)\bNOT\s+as\s+a\s+SNAP\s+package",
        subject: "snap versus deb",
        handling: Handling::Manual(
            "check with `snap list`; removing a snap and installing the deb is not something this tool does",
        ),
    },
    Pattern {
        regex: r"(?i)display\s+manager\s+should\s+remain\s+set\s+to\s+(\w+)",
        subject: "the display manager",
        handling: Handling::Manual(
            "verify with `cat /etc/X11/default-display-manager`; no task changes it, but nothing checks either",
        ),
    },
    Pattern {
        regex: r"(?i)should\s+not\s+be\s+installed\s+using\s+the\s+Microsoft\s+[Ss]tore",
        subject: "install source",
        handling: Handling::Manual(
            "Software Management installs via Chocolatey, which satisfies this - but verify anything already present",
        ),
    },
    Pattern {
        regex: r"(?i)company\s+policy\s+to\s+use\s+only\s+(?:Windows|Ubuntu|Debian|Fedora)\s*[\d.]*",
        subject: "the operating system",
        handling: Handling::Manual(
            "do not upgrade or reinstall the OS; nothing here would, but nothing checks",
        ),
    },
];

fn compiled() -> &'static Vec<(Regex, &'static Pattern)> {
    static CACHE: OnceLock<Vec<(Regex, &'static Pattern)>> = OnceLock::new();
    CACHE.get_or_init(|| {
        PATTERNS
            .iter()
            .map(|p| {
                (
                    Regex::new(p.regex).unwrap_or_else(|e| {
                        panic!(
                            "directive pattern for {:?} does not compile: {e}",
                            p.subject
                        )
                    }),
                    p,
                )
            })
            .collect()
    })
}

/// Split text into sentences.
///
/// Split on sentence punctuation only, never on a line break. READMEs wrap
/// prose mid-sentence - the Ubuntu 22.04 one breaks *Please add the / user
/// "candace"* across two lines - so treating a newline as a boundary would cut
/// exactly the sentences worth matching in half. [`html::text`] has already
/// joined the wrapped lines by the time this sees them.
///
/// Crude beyond that, on purpose. The abbreviations that defeat the rule -
/// `O.W.C.A.`, `22.04`, `Node.js` - all produce a *shorter* sentence rather
/// than a wrong one, which costs nothing here: a pattern that matched the whole
/// sentence still matches the half it lands in.
pub fn sentences(text: &str) -> Vec<String> {
    let boundary = Regex::new(r"[.!?:]\s+").expect("static pattern");
    boundary
        .split(text)
        .map(|s| s.split_whitespace().collect::<Vec<_>>().join(" "))
        .filter(|s| s.chars().count() > 12)
        .collect()
}

/// Every recognised instruction in the README, in report order.
///
/// One directive per pattern: a README repeats itself - the scenario says media
/// is prohibited and so does a guideline - and listing the same instruction
/// three times trains the reader to skim.
pub fn extract(html_content: &str) -> Vec<Directive> {
    let text = html::text(html_content);
    let sentences = sentences(&text);

    let mut found: Vec<Directive> = Vec::new();
    let mut claimed: Vec<&str> = Vec::new();
    for (regex, pattern) in compiled() {
        let Some((sentence, m)) = sentences.iter().find_map(|s| regex.find(s).map(|m| (s, m)))
        else {
            continue;
        };
        // One directive per sentence. Two patterns can describe the same
        // instruction from different angles - the PPA requirement and the
        // "not a snap" requirement are one sentence - and printing it twice
        // makes a short report look padded.
        if claimed.contains(&sentence.as_str()) {
            continue;
        }
        claimed.push(sentence);
        found.push(Directive {
            subject: pattern.subject,
            sentence: excerpt(sentence, m.start(), m.end()),
            handling: pattern.handling,
        });
    }
    found
}

/// The directives a person has to act on.
pub fn manual(directives: &[Directive]) -> Vec<&Directive> {
    directives
        .iter()
        .filter(|d| d.handling.needs_a_person())
        .collect()
}

/// Print the directives, grouped by who has to act on them.
///
/// The by-hand group is printed last and in yellow, because it is the only part
/// that asks the reader to do something. Everything above it is there so the
/// classification can be checked rather than taken on trust.
pub fn display(directives: &[Directive]) {
    if directives.is_empty() {
        crate::ui::markup_line("[dim]No round-specific instructions recognised in this README.[/]");
        return;
    }

    crate::ui::write_line();
    crate::ui::rule("[bold blue]What this round does differently[/]");

    for (heading, wanted) in [
        (
            "[bold]Handled by a task[/] [dim]- the README changed what the run does[/]",
            Handling::Automated(""),
        ),
        (
            "[bold]Not touched[/] [dim]- no task has code that would break these[/]",
            Handling::SafeByInaction(""),
        ),
    ] {
        let group: Vec<&Directive> = directives
            .iter()
            .filter(|d| std::mem::discriminant(&d.handling) == std::mem::discriminant(&wanted))
            .collect();
        if group.is_empty() {
            continue;
        }
        crate::ui::write_line();
        crate::ui::markup_line(heading);
        for d in group {
            crate::ui::markup_line(&format!(
                "  [green]✓[/] [bold]{}[/] [dim]- {}[/]",
                crate::ui::escape(d.subject),
                crate::ui::escape(d.handling.detail())
            ));
            crate::ui::markup_line(&format!(
                "      [dim]\"{}\"[/]",
                crate::ui::escape(&d.sentence)
            ));
        }
    }

    let by_hand = manual(directives);
    if by_hand.is_empty() {
        return;
    }
    crate::ui::write_line();
    crate::ui::markup_line(&format!(
        "[bold yellow]Do these by hand ({})[/] [dim]- this tool cannot, and a missed one is a lost item[/]",
        by_hand.len()
    ));
    for d in by_hand {
        crate::ui::markup_line(&format!(
            "  [yellow]![/] [bold]{}[/] [yellow]- {}[/]",
            crate::ui::escape(d.subject),
            crate::ui::escape(d.handling.detail())
        ));
        crate::ui::markup_line(&format!(
            "      [dim]\"{}\"[/]",
            crate::ui::escape(&d.sentence)
        ));
    }
}

/// Record the directives in the remediation ledger.
///
/// The by-hand ones are recorded as `Skipped`, not `Failed`. Nothing was
/// attempted, so "attempted and did not take" would be false - and in a summary
/// where genuine failures also appear, an instruction the tool was never going
/// to carry out would be indistinguishable from a write that did not land.
/// `Skipped` is the outcome that means *deliberately left alone*, which is
/// exactly what these are.
///
/// They are still not counted as compliant, because they are outstanding work
/// and a ledger that marked them done would be lying about the machine.
pub fn record(directives: &[Directive]) {
    for d in directives {
        match d.handling {
            Handling::Manual(advice) => crate::run_log::record_fix(
                d.subject,
                &d.sentence,
                None,
                "nothing - this needs a person",
                crate::models::FixOutcome::Skipped,
                advice,
            ),
            Handling::Automated(_) | Handling::SafeByInaction(_) => {
                crate::remediation::record_finding(
                    d.subject,
                    &d.sentence,
                    true,
                    d.handling.detail(),
                )
            }
        }
    }
}

/// How much of a sentence to show around the phrase that matched.
const EXCERPT: usize = 190;

/// Show the part of the sentence the pattern actually matched.
///
/// Printing from the start of the sentence goes wrong on a real README, because
/// the sentence splitter is punctuation-based and some blocks have none: the
/// `<pre>` block of usernames runs straight into the guideline that follows it,
/// so the instruction about the primary user's password was displayed as
/// twenty-four usernames followed by an ellipsis.
///
/// Centring on the match makes the excerpt useful whatever the splitter did
/// with the surrounding text.
fn excerpt(sentence: &str, start: usize, end: usize) -> String {
    if sentence.len() <= EXCERPT {
        return sentence.to_string();
    }

    // Centre the window on the match, then pull it back inside the sentence.
    let width = end.saturating_sub(start);
    let padding = EXCERPT.saturating_sub(width) / 2;
    let mut from = start.saturating_sub(padding);
    let mut to = (end + padding).min(sentence.len());

    // Land on character boundaries, then on word boundaries, so the excerpt is
    // readable and the slicing cannot panic on a multi-byte character.
    while from > 0 && !sentence.is_char_boundary(from) {
        from -= 1;
    }
    while to < sentence.len() && !sentence.is_char_boundary(to) {
        to += 1;
    }
    if from > 0
        && let Some(space) = sentence[from..start.min(sentence.len())].find(' ')
    {
        from += space + 1;
    }
    if to < sentence.len()
        && let Some(space) = sentence[end.min(to)..to].rfind(' ')
    {
        to = end.min(to) + space;
    }

    format!(
        "{}{}{}",
        if from > 0 { "..." } else { "" },
        sentence[from..to].trim(),
        if to < sentence.len() { "..." } else { "" }
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A by-hand item is not a failure. In a summary where genuine failures
    /// also appear, an instruction the tool was never going to carry out must
    /// not look like a write that did not land.
    #[test]
    fn manual_directives_are_skipped_rather_than_failed() {
        crate::run_log::begin_task("(test)");
        record(&extract(
            "<p>The display manager should remain set to GDM3.</p>",
        ));
        let recorded = crate::run_log::fixes();
        let last = recorded.last().expect("a record was written");
        assert_eq!(last.outcome, crate::models::FixOutcome::Skipped);
        assert!(!last.outcome.is_compliant(), "it is still outstanding work");
    }

    #[test]
    fn every_pattern_compiles_and_is_described() {
        for (regex, pattern) in compiled() {
            assert!(!pattern.subject.is_empty(), "{} has no subject", regex);
            assert!(
                !pattern.handling.detail().is_empty(),
                "{} does not say what the tool does",
                pattern.subject
            );
        }
    }

    /// A pattern that matched everything would classify the whole document as
    /// instructions, which is the same as classifying none of it.
    #[test]
    fn nothing_matches_ordinary_prose() {
        let ordinary = "<p>You work for a small accounting firm in Ohio. \
             The office has twelve employees and one server.</p>";
        assert!(extract(ordinary).is_empty());
    }

    #[test]
    fn a_critical_service_sentence_is_recognised() {
        let html = "<p>Therefore, sshd is a critical service and needs to remain enabled.</p>";
        let found = extract(html);
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].subject, "a critical service");
        assert!(matches!(found[0].handling, Handling::Automated(_)));
    }

    /// The trap this module exists for. `apt install firefox` on Ubuntu 22.04
    /// installs a transitional package that pulls the snap, so a tool that
    /// "installed Firefox" satisfies nothing and the competitor never knows.
    #[test]
    fn the_ppa_requirement_is_reported_as_manual() {
        let html = "<p>Firefox must remain installed using the official Mozilla PPA, \
             and NOT as a SNAP package.</p>";
        let found = extract(html);
        assert!(!found.is_empty());
        assert!(
            found.iter().all(|d| d.handling.needs_a_person()),
            "the PPA requirement is not something this tool can satisfy"
        );
        assert!(!manual(&found).is_empty());
    }

    /// "The tool does not do that" is only reassuring if it is written down.
    #[test]
    fn an_instruction_satisfied_by_inaction_says_so() {
        let html = "<p>Please do not change the time zone, date, or time on this image.</p>";
        let found = extract(html);
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].handling.tag(), "NOT TOUCHED");
        assert!(!found[0].handling.needs_a_person());
    }

    /// A README says the same thing in the scenario and again in the
    /// guidelines. Reporting it twice trains the reader to skim.
    #[test]
    fn a_repeated_instruction_is_reported_once() {
        let html = "<p>Do not stop or disable the CCS Client service or process.</p>\
             <p>Remember: do not stop or disable the CCS Client service.</p>";
        assert_eq!(extract(html).len(), 1);
    }

    #[test]
    fn sentences_are_split_and_normalised() {
        let split = sentences("First sentence here.  Second   sentence here.");
        assert_eq!(split, ["First sentence here", "Second sentence here."]);
    }

    /// The case that made splitting on newlines wrong: a README wraps prose
    /// mid-sentence, and the wrapped half is where the instruction lives.
    #[test]
    fn a_sentence_wrapped_across_lines_stays_whole() {
        let html = "<p>Please add the\nuser \"candace\" to the\n\"firesidegirls\" group.</p>";
        let found = extract(html);
        assert_eq!(found.len(), 1, "the wrapped sentence was not matched");
        assert_eq!(found[0].subject, "a group membership");
    }

    /// Fragments are not instructions, and a document is full of them - table
    /// cells, headings, a bare username.
    #[test]
    fn short_fragments_are_not_sentences() {
        assert!(sentences("Yes. No. OK.").is_empty());
    }

    /// The real failure this replaced: the `<pre>` block of usernames has no
    /// punctuation, so it merges with the guideline after it and the excerpt
    /// showed twenty-four names instead of the instruction.
    #[test]
    fn the_excerpt_shows_the_phrase_that_matched_not_the_start_of_the_sentence() {
        let noise = "alice bob carol dave erin frank grace heidi ivan judy ".repeat(4);
        let html = format!(
            "<p>{noise} you are NOT required to change the password of the primary, \
             auto-login, user account.</p>"
        );
        let found = extract(&html);
        assert_eq!(found.len(), 1);
        assert!(
            found[0].sentence.contains("password of the primary"),
            "the excerpt missed the instruction: {}",
            found[0].sentence
        );
        assert!(
            found[0].sentence.starts_with("..."),
            "an excerpt taken from the middle should say so: {}",
            found[0].sentence
        );
    }

    /// Two patterns describing one sentence is one instruction, not two.
    #[test]
    fn one_sentence_yields_one_directive() {
        let html = "<p>Firefox must remain installed using the official Mozilla PPA, \
             and NOT as a SNAP package.</p>";
        assert_eq!(extract(html).len(), 1);
    }

    /// A multi-byte character near the window edge must not panic the slicing.
    #[test]
    fn an_excerpt_never_splits_a_multi_byte_character() {
        let padding = "é".repeat(300);
        let html = format!("<p>{padding} do not change the time zone here.</p>");
        let found = extract(&html);
        assert_eq!(found.len(), 1);
        assert!(found[0].sentence.contains("time zone"));
    }
}
