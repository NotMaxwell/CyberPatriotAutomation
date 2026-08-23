// =============================================================================
// PinnacleCyPat - README corpus snapshot tests
// Author: Maxwell McCormick
// Copyright 2026 Maxwell McCormick
// SPDX-License-Identifier: Apache-2.0
// =============================================================================
//! Every README in `tests/corpus/` is parsed and the whole result snapshotted.
//!
//! The parser is a pile of heuristics about how a person writes English, and it
//! will always be. What it lacked was any way to tell whether a change to one
//! heuristic quietly broke another - the phrasings are only discovered by
//! reading real documents, and each fix so far has been made against a single
//! sentence with nothing checking the rest.
//!
//! So the unit of test here is not an assertion, it is a document. Add the
//! README, run the suite, read the snapshot it proposes, and commit it if it is
//! right. From then on any change that alters what that README produces shows
//! up as a reviewable diff instead of as silence.
//!
//! ```text
//! cargo test --test corpus_tests           # check every fixture
//! INSTA_UPDATE=always cargo test --test corpus_tests   # accept new output
//! cargo insta review                       # or step through the diffs
//! ```
//!
//! **Adding a README is the highest-value contribution to this parser.** Real
//! documents have found bugs that no amount of reading the code did: the
//! `<br>`-separated user list, the "into the group" phrasing, `Windows&nbsp;10`.
//! Drop any competition README into `tests/corpus/` and it is covered.

use pinnacle_core::models::ReadmeData;
use pinnacle_core::readme_parser;

/// Render the parse result as stable, readable text.
///
/// A `Debug` dump of `ReadmeData` would work but reads badly in a diff and
/// churns whenever a field is added. This prints only what the tool acts on,
/// one fact per line, so a snapshot diff points at a behaviour change rather
/// than at a struct change.
fn render(data: &ReadmeData) -> String {
    let mut out = String::new();
    let mut line = |s: String| {
        out.push_str(&s);
        out.push('\n');
    };

    line(format!("title:            {}", data.title));
    line(format!("operating system: {}", data.operating_system));
    line(format!("scenario:         {}", first_line(&data.scenario)));

    line("administrators:".to_string());
    for account in &data.administrators {
        line(format!(
            "  - {} (primary: {}, password: {})",
            account.username,
            account.is_primary_user,
            account.password.as_deref().unwrap_or("-")
        ));
    }

    line("users:".to_string());
    for account in &data.users {
        line(format!("  - {}", account.username));
    }

    line("groups:".to_string());
    for group in &data.group_requirements {
        line(format!(
            "  - {}: {}",
            group.group_name,
            group.members.join(", ")
        ));
    }

    line("users to create:".to_string());
    for user in &data.users_to_create {
        line(format!("  - {user}"));
    }

    line("required software:".to_string());
    for software in &data.required_software {
        line(format!(
            "  - {} (latest: {})",
            software.name, software.should_be_latest
        ));
    }

    line("prohibited software:".to_string());
    for software in &data.prohibited_software {
        line(format!("  - {software}"));
    }

    line("critical services:".to_string());
    for service in &data.critical_services {
        line(format!("  - {service}"));
    }

    line("prohibited services:".to_string());
    for service in &data.prohibited_services {
        line(format!("  - {service}"));
    }

    line("guidelines:".to_string());
    for guideline in &data.guidelines {
        line(format!("  - {guideline}"));
    }

    line("actionable items:".to_string());
    for item in &data.actionable_items {
        line(format!("  - [{:?}] {}", item.item_type, item.description));
    }

    line("sections:".to_string());
    let mut headings: Vec<&String> = data.sections.keys().collect();
    headings.sort();
    for heading in headings {
        line(format!("  - {heading}"));
    }

    out
}

/// Scenarios run to several paragraphs; the first line is enough to notice a
/// change without the snapshot becoming a copy of the document.
fn first_line(s: &str) -> String {
    let trimmed = s.trim();
    match trimmed.char_indices().nth(100) {
        Some((i, _)) => format!("{}...", &trimmed[..i]),
        None => trimmed.to_string(),
    }
}

async fn parse(path: &std::path::Path) -> ReadmeData {
    readme_parser::parse_html_readme_async(&path.to_string_lossy()).await
}

#[tokio::test]
async fn every_readme_in_the_corpus_parses_the_same_way_it_did() {
    let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/corpus");

    let mut files: Vec<std::path::PathBuf> = std::fs::read_dir(&dir)
        .expect("tests/corpus is missing")
        .filter_map(Result::ok)
        .map(|entry| entry.path())
        .filter(|path| path.extension().is_some_and(|e| e == "html"))
        .collect();
    files.sort();

    assert!(!files.is_empty(), "the corpus is empty");

    for path in files {
        let name = path.file_stem().unwrap().to_string_lossy().into_owned();
        let rendered = render(&parse(&path).await);
        insta::assert_snapshot!(name, rendered);
    }
}

/// The corpus is only worth having if a change to it is noticed, so the count
/// is pinned too - a fixture deleted by accident would otherwise just mean one
/// fewer snapshot to check.
#[test]
fn the_corpus_is_not_shrinking() {
    let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/corpus");
    let count = std::fs::read_dir(&dir)
        .expect("tests/corpus is missing")
        .filter_map(Result::ok)
        .filter(|e| e.path().extension().is_some_and(|x| x == "html"))
        .count();

    assert!(
        count >= 5,
        "the corpus has shrunk to {count} READMEs; adding documents is the point"
    );
}
