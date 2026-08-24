// =============================================================================
// PinnacleCyPat - Directive extraction against the real corpus
// Author: Maxwell McCormick
// Copyright 2026 Maxwell McCormick
// SPDX-License-Identifier: Apache-2.0
// =============================================================================

//! The directive scanner, run against the actual competition READMEs.
//!
//! The unit tests in `directives.rs` check each pattern against a sentence
//! written to exercise it. These check the thing that actually matters: that
//! the patterns fire on the documents as they are really written, wrapped lines
//! and merged blocks and all.

use pinnacle_core::directives::{self, Handling};

fn corpus(name: &str) -> String {
    let path = format!("{}/tests/corpus/{name}", env!("CARGO_MANIFEST_DIR"));
    std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("{path}: {e}"))
}

const UBUNTU: &str = "06-ubuntu-22-exhibition-round.html";
const WINDOWS: &str = "01-training-round-windows-10.html";

fn subjects(html: &str) -> Vec<&'static str> {
    directives::extract(html)
        .into_iter()
        .map(|d| d.subject)
        .collect()
}

/// The instruction that this whole module exists for.
///
/// `apt install firefox` on Ubuntu 22.04 installs a transitional package that
/// pulls the snap. A tool that reported "installed Firefox" would satisfy
/// nothing, and the competitor would never know - the README says so in one
/// sentence in the middle of a paragraph about browsers.
#[test]
fn the_firefox_ppa_trap_is_reported_as_manual() {
    let found = directives::extract(&corpus(UBUNTU));
    let ppa = found
        .iter()
        .find(|d| d.sentence.contains("PPA"))
        .expect("the PPA requirement should be found");
    assert!(
        ppa.handling.needs_a_person(),
        "the tool cannot satisfy this and must say so"
    );
    assert!(
        ppa.handling.detail().contains("snap"),
        "the advice should name the trap: {}",
        ppa.handling.detail()
    );
}

/// The README overrides the default posture for SSH. Both halves of that -
/// "sshd is critical" and "users must be able to log in remotely" - are
/// recognised, because a README states it once in each form.
#[test]
fn the_ubuntu_readme_overrides_are_all_recognised() {
    let subjects = subjects(&corpus(UBUNTU));
    for expected in [
        "a critical service",
        "remote access",
        "which firewall",
        "root login",
        "a group membership",
        "media files",
    ] {
        assert!(
            subjects.contains(&expected),
            "{expected} was not recognised; found {subjects:?}"
        );
    }
}

/// Every one of these is something a person has to do, and every one is easy to
/// miss on a first read of the document.
#[test]
fn the_ubuntu_readme_manual_items_are_all_reported() {
    let found = directives::extract(&corpus(UBUNTU));
    let manual: Vec<&'static str> = directives::manual(&found)
        .into_iter()
        .map(|d| d.subject)
        .collect();
    for expected in [
        "the unique identifier",
        "forensics questions",
        "install source",
        "the display manager",
        "the operating system",
    ] {
        assert!(
            manual.contains(&expected),
            "{expected} should need a person; manual list is {manual:?}"
        );
    }
}

/// The Windows README asks for different things, and the scanner must not
/// report the Linux ones against it.
#[test]
fn the_windows_readme_yields_its_own_instructions() {
    let found = directives::extract(&corpus(WINDOWS));
    let subjects: Vec<&'static str> = found.iter().map(|d| d.subject).collect();

    assert!(subjects.contains(&"the scoring engine"));
    assert!(subjects.contains(&"home directories"));
    assert!(subjects.contains(&"Action Center"));
    assert!(subjects.contains(&"Windows feature updates"));

    // Nothing Ubuntu-specific should appear.
    assert!(
        !subjects.contains(&"the display manager"),
        "a Linux instruction was reported against a Windows README"
    );
    assert!(!subjects.contains(&"which firewall"));
}

/// Both documents say the same things about the clock and about JavaScript, and
/// in both cases the honest answer is that no task would break them. Saying so
/// explicitly is the point: "we do not do that" is only reassuring written down.
#[test]
fn instructions_satisfied_by_inaction_are_reported_as_such() {
    for fixture in [UBUNTU, WINDOWS] {
        let found = directives::extract(&corpus(fixture));
        let clock = found
            .iter()
            .find(|d| d.subject == "the clock")
            .unwrap_or_else(|| panic!("{fixture}: the time-zone instruction was not found"));
        assert!(matches!(clock.handling, Handling::SafeByInaction(_)));
        assert!(!clock.handling.needs_a_person());
    }
}

/// Every directive carries the sentence it came from, so the classification can
/// be checked rather than taken on trust - and an excerpt that lost the phrase
/// it matched would defeat that.
#[test]
fn every_directive_quotes_the_sentence_it_came_from() {
    for fixture in [UBUNTU, WINDOWS] {
        for d in directives::extract(&corpus(fixture)) {
            assert!(
                !d.sentence.trim().is_empty(),
                "{fixture}: {} has no sentence",
                d.subject
            );
            assert!(
                d.sentence.chars().count() <= 200,
                "{fixture}: {} quotes {} characters",
                d.subject,
                d.sentence.chars().count()
            );
        }
    }
}

/// A short README reports only what it actually says.
///
/// This fixture has exactly two directive sentences - *Remote Desktop is a
/// critical service for this machine* and *Do not disable the CCS Client
/// service* - and reporting a third would mean a pattern was firing on prose it
/// does not understand, which is worse than saying nothing.
#[test]
fn a_short_readme_reports_only_the_instructions_it_contains() {
    let found = directives::extract(&corpus("02-users-in-br-list.html"));
    let subjects: Vec<&'static str> = found.iter().map(|d| d.subject).collect();
    assert_eq!(subjects, ["a critical service", "the scoring engine"]);
}

/// A document with no instructions at all produces nothing. The patterns are
/// deliberately conservative: a confident, wrong classification would be read
/// and believed.
#[test]
fn ordinary_prose_produces_no_directives() {
    let html = "<html><body><h1>Round 4</h1>\
        <p>You are the administrator for a small accounting firm in Ohio. \
        The office has twelve employees, one server and a printer nobody \
        has been able to configure since 2019.</p></body></html>";
    assert!(directives::extract(html).is_empty());
}
