//! Parses CyberPatriot README HTML files to extract task requirements.
//!
//! Ported from the C# `ReadmeParser`. Rust's `regex` crate has no lookaround,
//! so the handful of patterns that relied on `(?=<h2|$)` lookahead or a
//! `(?<!do not )` lookbehind are reproduced with explicit scanning instead.

use crate::models::*;
use crate::ui;
use regex::Regex;
use std::collections::HashSet;

const PROHIBITED_SOFTWARE_KEYWORDS: &[&str] = &[
    "hacking tools",
    "hacking tool",
    "non-work related media",
    "unauthorized software",
    "prohibited software",
    "games",
    "peer-to-peer",
    "p2p",
    "torrent",
    "crack",
    "keygen",
];

fn re(pattern: &str) -> Regex {
    Regex::new(pattern).expect("invalid regex")
}

fn html_decode(s: &str) -> String {
    html_escape::decode_html_entities(s).into_owned()
}

/// Case-insensitive (ASCII) substring search returning the byte index.
fn index_of_ci(haystack: &str, needle: &str, from: usize) -> Option<usize> {
    let h = haystack.as_bytes();
    let n = needle.as_bytes();
    if n.is_empty() {
        return Some(from);
    }
    let mut i = from;
    while i + n.len() <= h.len() {
        if h[i..i + n.len()].eq_ignore_ascii_case(n) {
            return Some(i);
        }
        i += 1;
    }
    None
}

fn contains_ci(haystack: &str, needle: &str) -> bool {
    index_of_ci(haystack, needle, 0).is_some()
}

/// Parse a CyberPatriot README HTML file.
pub async fn parse_html_readme_async(file_path: &str) -> ReadmeData {
    let mut data = ReadmeData::default();

    if !std::path::Path::new(file_path).is_file() {
        ui::markup_line(&format!(
            "[red]README file not found: {}[/]",
            ui::escape(file_path)
        ));
        return data;
    }

    let content = match tokio::fs::read_to_string(file_path).await {
        Ok(c) => c,
        Err(e) => {
            ui::markup_line(&format!(
                "[red]Error parsing README: {}[/]",
                ui::escape(&e.to_string())
            ));
            return data;
        }
    };

    // Decode HTML entities.
    let content = html_decode(&content);

    data.title = extract_title(&content);
    data.operating_system = detect_operating_system(&content);
    data.sections = extract_sections(&content);
    parse_authorized_users(&content, &mut data);
    parse_software_requirements(&content, &mut data);
    parse_services(&content, &mut data);
    parse_group_requirements(&content, &mut data);
    parse_users_to_create(&content, &mut data);
    parse_actionable_items(&content, &mut data);
    parse_guidelines(&content, &mut data);
    data.scenario = extract_scenario(&content);

    data
}

fn extract_title(content: &str) -> String {
    let h1 = re(r"(?is)<h1[^>]*>(.*?)</h1>");
    if let Some(caps) = h1.captures(content) {
        return strip_html_tags(&caps[1]).trim().to_string();
    }
    let title = re(r"(?is)<title[^>]*>(.*?)</title>");
    if let Some(caps) = title.captures(content) {
        return strip_html_tags(&caps[1]).trim().to_string();
    }
    "Unknown".to_string()
}

/// Operating systems recognised in a README, most specific first.
///
/// Server editions precede the desktop entries so that "Windows Server 2022"
/// is not reported as a bare "Windows"; the two-digit desktop versions are
/// mutually exclusive strings and so may appear in any order between
/// themselves.
const OPERATING_SYSTEMS: &[(&str, &str)] = &[
    ("windows server 2025", "Windows Server 2025"),
    ("windows server 2022", "Windows Server 2022"),
    ("windows server 2019", "Windows Server 2019"),
    ("windows server 2016", "Windows Server 2016"),
    ("windows server 2012", "Windows Server 2012"),
    ("windows 11", "Windows 11"),
    ("windows 10", "Windows 10"),
    ("windows 8.1", "Windows 8.1"),
    ("windows 7", "Windows 7"),
    ("ubuntu", "Ubuntu Linux"),
    ("debian", "Debian Linux"),
    ("fedora", "Fedora Linux"),
    ("linux", "Linux"),
];

/// Flatten markup and whitespace so OS names survive however they were typed.
///
/// Matching against the raw HTML missed anything the author had split with
/// markup or a non-breaking space - `Windows&nbsp;10` decodes to a U+00A0 that
/// never equals the plain space in the search string, and `Windows <b>10</b>`
/// has a tag in the middle. Both are ordinary in hand-written READMEs and both
/// produced "Unknown".
fn normalize_for_os_match(content: &str) -> String {
    let text = strip_html_tags(content);
    text.split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
        .to_lowercase()
}

fn match_operating_system(haystack: &str) -> Option<&'static str> {
    OPERATING_SYSTEMS
        .iter()
        .find(|(needle, _)| haystack.contains(needle))
        .map(|(_, label)| *label)
}

fn detect_operating_system(content: &str) -> String {
    // The title and first heading name the image on essentially every official
    // README ("Training Round Windows 10 README"). Consulting them first avoids
    // misreading prose such as "do not upgrade from Windows 10" in a Windows 11
    // image, which a whole-document scan would match.
    let headline = re(r"(?is)<(?:title|h1)[^>]*>(.*?)</(?:title|h1)>");
    for caps in headline.captures_iter(content) {
        if let Some(os) = match_operating_system(&normalize_for_os_match(&caps[1])) {
            return os.to_string();
        }
    }

    match_operating_system(&normalize_for_os_match(content))
        .unwrap_or("Unknown")
        .to_string()
}

/// Extract all sections (h2 headers and their content). The C# version used a
/// `(?=<h2|$)` lookahead; here we locate each `<h2>...</h2>` and take everything
/// up to the next `<h2` as the section body.
fn extract_sections(content: &str) -> std::collections::HashMap<String, String> {
    let mut sections = std::collections::HashMap::new();
    let h2 = re(r"(?is)<h2[^>]*>(.*?)</h2>");

    let items: Vec<(usize, usize, String)> = h2
        .captures_iter(content)
        .map(|caps| {
            let whole = caps.get(0).unwrap();
            let header = strip_html_tags(&caps[1]).trim().to_string();
            (whole.start(), whole.end(), header)
        })
        .collect();

    for i in 0..items.len() {
        let content_start = items[i].1;
        let content_end = if i + 1 < items.len() {
            items[i + 1].0
        } else {
            content.len()
        };
        let section_content = &content[content_start..content_end];
        sections.insert(items[i].2.clone(), section_content.to_string());
    }

    sections
}

fn parse_authorized_users(content: &str, data: &mut ReadmeData) {
    let sec = re(r"(?i)Authorized\s+Administrators");
    if let Some(m) = sec.find(content) {
        let end = index_of_ci(content, "<h2", m.end()).unwrap_or(content.len());
        let block = &content[m.start()..end];
        parse_user_block(block, data);
        return;
    }

    // Alternative: look inside <pre> blocks.
    let pre = re(r"(?is)<pre[^>]*>(.*?)</pre>");
    for caps in pre.captures_iter(content) {
        let pre_content = &caps[1];
        let low = pre_content.to_lowercase();
        if low.contains("authorized") || low.contains("administrator") || low.contains("password") {
            parse_user_block(pre_content, data);
            return;
        }
    }
}

fn parse_user_block(content: &str, data: &mut ReadmeData) {
    // The C# original stripped every tag to "" and then split on newlines, which
    // only works when the user list is inside a <pre> block. READMEs that
    // separate entries with <br> or list/table markup instead would collapse
    // into a single long line and yield no users at all. Convert the tags that
    // represent a line break into newlines first so both layouts parse.
    let line_break = re(r"(?is)<\s*(?:br\s*/?|/p|/li|/div|/tr|/h[1-6])\s*>");
    let content = line_break.replace_all(content, "\n");

    let tag = re(r"<[^>]+>");
    let cleaned = tag.replace_all(&content, "");
    let cleaned = html_decode(&cleaned);

    let annotation = re(r"\s*\([^)]*\)\s*");

    let mut in_admin = false;
    let mut in_user = false;
    // Index of the current user being built, split across admins/users vectors.
    let mut current: Option<(bool, usize)> = None; // (is_admin_section, index)

    for raw in cleaned.split(['\r', '\n']).filter(|l| !l.is_empty()) {
        let line = raw.trim();
        if line.is_empty() {
            continue;
        }
        let lower = line.to_lowercase();

        if lower.contains("authorized administrators") || lower.contains("authorized admins") {
            in_admin = true;
            in_user = false;
            continue;
        }
        if lower.contains("authorized users") || lower.contains("authorized user") {
            in_admin = false;
            in_user = true;
            continue;
        }

        if lower.starts_with("password:") || lower.starts_with("password :") {
            if let Some((is_admin, idx)) = current {
                if let Some(colon) = line.find(':') {
                    let password = line[colon + 1..].trim().to_string();
                    if is_admin {
                        data.administrators[idx].password = Some(password);
                    } else {
                        data.users[idx].password = Some(password);
                    }
                }
            }
            continue;
        }

        if !lower.starts_with("password")
            && !lower.contains("authorized")
            && !line.is_empty()
            && !line.starts_with('<')
            && line.chars().count() < 100
        {
            let is_primary = lower.contains("(you)");
            // READMEs annotate entries as "alice (you)" but also "bob (Admin)".
            // The C# original only stripped "(you)"; strip any parenthetical so
            // the remaining token is validated as the account name it is.
            let username = annotation.replace_all(line, "").trim().to_string();

            if !username.is_empty() && is_valid_username(&username) {
                let user = AuthorizedUser {
                    username: username.clone(),
                    is_admin: in_admin,
                    is_primary_user: is_primary,
                    ..Default::default()
                };
                if in_admin {
                    data.administrators.push(user);
                    current = Some((true, data.administrators.len() - 1));
                } else if in_user {
                    data.users.push(user);
                    current = Some((false, data.users.len() - 1));
                } else {
                    // Not in a section yet; C# still assigns currentUser but never stores it.
                    current = None;
                }
            }
        }
    }
}

/// Characters Windows forbids in a local account name. Their presence is a
/// reliable sign the line is prose rather than a username.
const INVALID_USERNAME_CHARS: &[char] = &[
    '"', '/', '\\', '[', ']', ':', ';', '|', '=', ',', '+', '*', '?', '<', '>', '@', '.', '!',
];

fn is_valid_username(username: &str) -> bool {
    let username = username.trim();
    if username.is_empty() {
        return false;
    }
    // Windows caps local account names at 20 characters. The C# original
    // allowed 50, which let whole sentences from the surrounding prose be
    // recorded as users.
    if username.chars().count() > 20 {
        return false;
    }
    if contains_ci(username, "password") {
        return false;
    }
    if contains_ci(username, "authorized") {
        return false;
    }
    if username.contains(INVALID_USERNAME_CHARS) {
        return false;
    }
    // Windows does permit a space ("John Smith"), but a run of three or more
    // words is prose, not an account name. Erring permissive here is deliberate:
    // a real user wrongly rejected here is absent from the authorized set and
    // would be deleted, whereas a junk entry only ever protects an account.
    let words: Vec<&str> = username.split_whitespace().collect();
    if words.len() > 2 || words.iter().any(|w| is_common_word(w)) {
        return false;
    }
    username.chars().any(|c| c.is_alphabetic())
}

/// Does this captured fragment plausibly name a piece of software?
///
/// The extraction patterns (notably the broad `access to ... .` one) happily
/// capture ordinary prose — "access to administrative tools." would otherwise
/// be recorded as required software named "administrative tools". Real product
/// names are proper nouns, so require the fragment to start with an uppercase
/// letter and not be an everyday word. This mirrors the check already applied
/// to actionable software items in [`parse_software_item`].
fn is_plausible_software_name(name: &str) -> bool {
    /// Generic nouns that appear in these phrasings but never name a product.
    const NOISE: &[&str] = &[
        "a",
        "an",
        "use",
        "company",
        "software",
        "program",
        "programs",
        "application",
        "applications",
        "app",
        "apps",
        "tool",
        "tools",
        "version",
        "versions",
        "access",
        "browser",
        "browsers",
        "system",
        "systems",
        "file",
        "files",
        "data",
        "internet",
    ];
    if !name
        .chars()
        .next()
        .map(|c| c.is_uppercase())
        .unwrap_or(false)
    {
        return false;
    }
    if is_common_word(name) || NOISE.iter().any(|w| w.eq_ignore_ascii_case(name)) {
        return false;
    }
    // Multi-word fragments are almost always prose rather than a product name;
    // every word would need to be capitalised to read as one.
    name.split_whitespace()
        .all(|w| w.chars().next().map(|c| c.is_uppercase()).unwrap_or(false))
}

fn parse_software_requirements(content: &str, data: &mut ReadmeData) {
    let lower = content.to_lowercase();

    for keyword in PROHIBITED_SOFTWARE_KEYWORDS {
        if lower.contains(keyword)
            && !data
                .prohibited_software
                .iter()
                .any(|p| p.eq_ignore_ascii_case(keyword))
        {
            data.prohibited_software.push((*keyword).to_string());
        }
    }

    let patterns = [
        r"(?is)latest\s+(?:stable\s+)?version\s+of\s+([A-Za-z0-9]+)",
        r"(?is)access\s+to\s+(?:the\s+)?(?:latest\s+)?(?:stable\s+)?(?:version\s+of\s+)?([A-Za-z0-9,\s]+?)(?:\s+for\s+company|\s+for\s+use|\.)",
        r"(?is)should\s+(?:be\s+)?(?:using|have|install)\s+(?:the\s+)?(?:latest\s+)?(?:stable\s+)?(?:version\s+of\s+)?([A-Za-z0-9]+)",
        r"(?is)default\s+(?:web\s+)?browser.*?should\s+be\s+(?:the\s+)?(?:latest\s+)?(?:stable\s+)?(?:version\s+of\s+)?([A-Za-z0-9]+)",
    ];

    let splitter = re(r"(?i)\s*,\s*and\s+|\s*,\s*|\s+and\s+");
    let mut found: HashSet<String> = HashSet::new();

    for pat in patterns {
        let regex = re(pat);
        for caps in regex.captures_iter(content) {
            // The phrase this match came from, used to decide "latest" below.
            let matched_phrase = caps.get(0).map(|m| m.as_str()).unwrap_or("");
            let software_list = caps[1].trim();
            for name in splitter.split(software_list) {
                let clean = name
                    .trim()
                    .trim_matches(|c| c == ',' || c == '.' || c == ' ');
                let len = clean.chars().count();
                if clean.is_empty()
                    || !(2..=50).contains(&len)
                    || !is_plausible_software_name(clean)
                {
                    continue;
                }
                let key = clean.to_lowercase();
                if found.insert(key.clone()) {
                    data.required_software.push(SoftwareRequirement {
                        name: clean.to_string(),
                        // The C# original tested whether the *whole document*
                        // contained "latest", so a single mention anywhere
                        // flagged every package as "Latest Stable". Judge the
                        // matched phrase instead.
                        should_be_latest: contains_ci(matched_phrase, "latest"),
                        is_required: true,
                        ..Default::default()
                    });
                }
            }
        }
    }

    if lower.contains("should not be installed using the microsoft store")
        || lower.contains("not be installed using microsoft store")
    {
        for software in &mut data.required_software {
            let existing = software.notes.clone().unwrap_or_default();
            software.notes = Some(format!("{existing} Do not install via Microsoft Store."));
        }
    }
}

fn parse_services(content: &str, data: &mut ReadmeData) {
    let lower = content.to_lowercase();

    let critical = re(r"(?is)Critical\s+Services:?\s*(.*?)(?:<h2|</ul>|$)");
    if let Some(caps) = critical.captures(content) {
        let service_content = caps.get(1).map(|m| m.as_str()).unwrap_or("");
        let clean = strip_html_tags(service_content).to_lowercase();
        if !(clean.contains("none") || clean.contains("(none)")) {
            let li = re(r"(?is)<li[^>]*>(.*?)</li>");
            for lic in li.captures_iter(service_content) {
                let service = strip_html_tags(&lic[1]).trim().to_string();
                if !service.is_empty()
                    && !service.eq_ignore_ascii_case("none")
                    && !service.contains("(none)")
                {
                    data.critical_services.push(service);
                }
            }
        }
    }

    // Pattern 1 used a negative lookbehind `(?<!do not )`; reproduce by checking
    // the text immediately preceding "disable". The C# lookbehind only covered a
    // literal "do not " directly before "disable", so the very common competition
    // phrasing "do not stop or disable the X service" slipped through and queued a
    // critical service for disabling. Allow an intervening "<verb> or " and the
    // other negation forms READMEs use.
    let negated =
        re(r"(?i)(?:do\s+not|do\s*n'?t|never|must\s+not|should\s+not)\s+(?:\w+\s+or\s+)?$");
    let disable1 = re(r"(?i)disable\s+(?:the\s+)?([A-Za-z0-9\s]+?)\s+service");

    // Collect first so every "do not disable" is registered as critical before
    // any prohibited entry is added - `add_prohibited_service` skips names that
    // are already known to be critical.
    let mut to_prohibit: Vec<&str> = Vec::new();
    for caps in disable1.captures_iter(content) {
        let whole = caps.get(0).unwrap();
        let service = caps.get(1).unwrap().as_str().trim();
        if negated.is_match(&content[..whole.start()]) {
            // "Do not disable X" means X is critical, not merely not-prohibited.
            add_critical_service(service, data);
        } else {
            to_prohibit.push(service);
        }
    }
    for service in to_prohibit {
        add_prohibited_service(service, data);
    }

    let disable2 = re(r"(?i)([A-Za-z0-9\s]+?)\s+service\s+should\s+(?:be\s+)?disabled");
    for caps in disable2.captures_iter(content) {
        add_prohibited_service(caps[1].trim(), data);
    }

    if lower.contains("do not stop") && lower.contains("ccs client") {
        data.prohibited_services.retain(|s| !contains_ci(s, "CCS"));
        if !data
            .critical_services
            .iter()
            .any(|s| s.eq_ignore_ascii_case("CCS Client"))
        {
            data.critical_services.push("CCS Client".to_string());
        }
    }

    // Final safety net: a service named as critical must never also be queued
    // for disabling, whichever pattern happened to match it first. Disabling a
    // scored critical service is one of the costliest mistakes in competition.
    let critical = data.critical_services.clone();
    data.prohibited_services
        .retain(|p| !critical.iter().any(|c| c.eq_ignore_ascii_case(p)));
}

/// Record a service the README says must stay running, de-duplicated.
fn add_critical_service(service: &str, data: &mut ReadmeData) {
    if service.is_empty() || service.chars().count() >= 50 {
        return;
    }
    if !data
        .critical_services
        .iter()
        .any(|s| s.eq_ignore_ascii_case(service))
    {
        data.critical_services.push(service.to_string());
    }
}

fn add_prohibited_service(service: &str, data: &mut ReadmeData) {
    if service.is_empty() || service.chars().count() >= 50 {
        return;
    }
    let in_prohibited = data
        .prohibited_services
        .iter()
        .any(|s| s.eq_ignore_ascii_case(service));
    let in_critical = data
        .critical_services
        .iter()
        .any(|s| s.eq_ignore_ascii_case(service));
    if !in_prohibited && !in_critical {
        data.prohibited_services.push(service.to_string());
    }
}

fn parse_group_requirements(content: &str, data: &mut ReadmeData) {
    let group = re(
        r#"(?is)(?:make|create)\s+(?:a\s+)?(?:new\s+)?group\s+(?:called\s+)?["']?(\w+)["']?\s+and\s+add\s+(?:the\s+following\s+users?\s+to\s+(?:the\s+)?["']?\w+["']?\s+group:?\s*)?([^.]+)"#,
    );
    // The C# original used a single `Regex.Match`, so a README asking for two
    // groups only ever produced the first one. Iterate over every match.
    for caps in group.captures_iter(content) {
        let group_name = caps[1].trim().to_string();
        let members = extract_group_members(&strip_html_tags(&caps[2]));
        let already_present = data
            .group_requirements
            .iter()
            .any(|g| g.group_name.eq_ignore_ascii_case(&group_name));
        if !group_name.is_empty() && !members.is_empty() && !already_present {
            data.group_requirements.push(GroupRequirement {
                group_name,
                members,
            });
        }
    }
}

/// Words that describe the membership rather than name a member.
///
/// A README writes the list as prose - "add the users a, b and c into the
/// group" - and the connective words are captured along with the names. Most
/// are already rejected by [`is_common_word`], but "users" and "group" were
/// not: a real run parsed `Members: users, ggoddard, ealderson, amoss, lchong,
/// group` and issued `net localgroup allsafe "group" /add`, which failed.
///
/// This is deliberately a separate set from [`is_common_word`]. That one also
/// gates account names, where erring permissive is right because a wrongly
/// rejected user is deleted rather than protected. Here the opposite holds - a
/// junk member is a command that cannot succeed.
const MEMBERSHIP_WORDS: &[&str] = &[
    "user", "users", "account", "accounts", "group", "groups", "member", "members", "add", "to",
    "in", "as", "of",
];

/// Pull the member names out of the prose that follows "and add".
pub fn extract_group_members(members_text: &str) -> Vec<String> {
    // "... a, b and c into the group." - the trailing clause names the group
    // again. Only strip it at the end of the capture, so a lead-in like "the
    // following users to the allsafe group: a, b, c" is left for the word
    // filter rather than taking the whole list with it.
    let trailing = re(r#"(?is)\b(?:in|into|on|onto|to)\s+(?:the\s+)?["']?\w*["']?\s*group\s*[.,]?\s*$"#);
    let text = trailing.replace(members_text, "");

    // "the users", "the following users:", "these accounts" - lead-ins to the
    // list rather than part of it.
    let leading = re(
        r"(?i)^\s*(?:the\s+|these\s+|those\s+|following\s+|new\s+)*(?:users?|accounts?|members?)\s*:?\s*",
    );
    let text = leading.replace(&text, "");

    let splitter = re(r"[,\s]+");
    splitter
        .split(&text)
        .map(|m| m.trim().trim_matches(|c| c == ',' || c == '.').to_string())
        .filter(|m| {
            !m.is_empty()
                && !MEMBERSHIP_WORDS.iter().any(|w| w.eq_ignore_ascii_case(m))
                && is_valid_username(m)
        })
        .collect()
}

fn parse_users_to_create(content: &str, data: &mut ReadmeData) {
    let patterns = [
        r#"(?i)(?:make|create)\s+(?:a\s+)?(?:new\s+)?(?:account|user)\s+(?:for\s+)?(?:this\s+employee\s+)?(?:named|called)\s+["']?(\w+)["']?"#,
        r#"(?i)new\s+employee.*?(?:named|called)\s+["']?(\w+)["']?"#,
    ];
    for pat in patterns {
        let regex = re(pat);
        for caps in regex.captures_iter(content) {
            let username = caps[1].trim().to_string();
            if !username.is_empty()
                && is_valid_username(&username)
                && username.chars().count() >= 3
                && !is_common_word(&username)
                && !data
                    .users_to_create
                    .iter()
                    .any(|u| u.eq_ignore_ascii_case(&username))
            {
                data.users_to_create.push(username);
            }
        }
    }
}

fn is_common_word(word: &str) -> bool {
    const COMMON: &[&str] = &[
        "this",
        "that",
        "user",
        "account",
        "the",
        "new",
        "for",
        "and",
        "not",
        "all",
        "any",
        "are",
        "was",
        "were",
        "been",
        "being",
        "have",
        "has",
        "had",
        "having",
        "does",
        "did",
        "doing",
        "should",
        "would",
        "could",
        "must",
        "will",
        "shall",
        "may",
        "might",
        "can",
        "need",
        "home",
        "employee",
        "named",
        "called",
        "following",
        "with",
        "from",
        "into",
    ];
    COMMON.iter().any(|w| w.eq_ignore_ascii_case(word))
}

fn parse_actionable_items(content: &str, data: &mut ReadmeData) {
    let p = re(r"(?is)<p[^>]*>(.*?)</p>");
    for caps in p.captures_iter(content) {
        let paragraph_text = strip_html_tags(&caps[1]).trim().to_string();
        if paragraph_text.is_empty() || paragraph_text.chars().count() < 10 {
            continue;
        }
        let lower = paragraph_text.to_lowercase();

        if contains_user_creation_pattern(&lower) {
            if let Some(item) = parse_user_creation_item(&paragraph_text) {
                if !is_duplicate_action_item(data, &item) {
                    if let Some(username) = item.details.get("Username") {
                        if !data
                            .users_to_create
                            .iter()
                            .any(|u| u.eq_ignore_ascii_case(username))
                        {
                            data.users_to_create.push(username.clone());
                        }
                    }
                    data.actionable_items.push(item);
                }
            }
        }
        if contains_group_pattern(&lower) {
            if let Some(item) = parse_group_item(&paragraph_text) {
                if !is_duplicate_action_item(data, &item) {
                    data.actionable_items.push(item);
                }
            }
        }
        if contains_service_pattern(&lower) {
            if let Some(item) = parse_service_item(&paragraph_text) {
                if !is_duplicate_action_item(data, &item) {
                    data.actionable_items.push(item);
                }
            }
        }
        if contains_software_pattern(&lower) {
            if let Some(item) = parse_software_item(&paragraph_text) {
                if !is_duplicate_action_item(data, &item) {
                    data.actionable_items.push(item);
                }
            }
        }
        if contains_security_policy_pattern(&lower) {
            if let Some(item) = parse_security_policy_item(&paragraph_text) {
                if !is_duplicate_action_item(data, &item) {
                    data.actionable_items.push(item);
                }
            }
        }
        if contains_file_operation_pattern(&lower) {
            if let Some(item) = parse_file_operation_item(&paragraph_text) {
                if !is_duplicate_action_item(data, &item) {
                    data.actionable_items.push(item);
                }
            }
        }
    }
}

fn contains_user_creation_pattern(t: &str) -> bool {
    (t.contains("create") && (t.contains("user") || t.contains("account")))
        || (t.contains("add") && t.contains("user"))
        || t.contains("new employee")
        || t.contains("new user")
        || t.contains("new account")
}

fn contains_group_pattern(t: &str) -> bool {
    ((t.contains("create") || t.contains("make")) && t.contains("group"))
        || (t.contains("add") && t.contains("to") && t.contains("group"))
        || (t.contains("remove") && t.contains("from") && t.contains("group"))
        || (t.contains("member") && t.contains("group"))
}

fn contains_service_pattern(t: &str) -> bool {
    ((t.contains("enable")
        || t.contains("disable")
        || t.contains("start")
        || t.contains("stop")
        || t.contains("running")
        || t.contains("not running"))
        && t.contains("service"))
        || t.contains("should be running")
        || t.contains("must be running")
        || t.contains("should not be running")
}

fn contains_software_pattern(t: &str) -> bool {
    (t.contains("install")
        || t.contains("uninstall")
        || t.contains("remove")
        || t.contains("update"))
        && (t.contains("software")
            || t.contains("program")
            || t.contains("application")
            || t.contains("app"))
}

fn contains_security_policy_pattern(t: &str) -> bool {
    (t.contains("password")
        && (t.contains("policy") || t.contains("require") || t.contains("complexity")))
        || t.contains("firewall")
        || (t.contains("audit") && t.contains("policy"))
        || t.contains("security policy")
        || t.contains("local security")
        || t.contains("action center")
        || t.contains("windows defender")
        || t.contains("antivirus")
}

fn contains_file_operation_pattern(t: &str) -> bool {
    ((t.contains("delete") || t.contains("remove"))
        && (t.contains("file") || t.contains("folder") || t.contains("directory")))
        || (t.contains("prohibited") && t.contains("file"))
        || t.contains("media file")
        || t.contains("unauthorized file")
}

fn parse_user_creation_item(text: &str) -> Option<ActionableItem> {
    let mut item = ActionableItem {
        item_type: ActionableItemType::CreateUser,
        raw_text: text.to_string(),
        ..Default::default()
    };

    let patterns = [
        r#"(?i)(?:create|make)\s+(?:a\s+)?(?:new\s+)?(?:user\s+)?(?:account\s+)?(?:for\s+)?(?:this\s+employee\s+)?(?:named|called)\s+["']?([a-zA-Z][a-zA-Z0-9_]+)["']?"#,
        r#"(?i)new\s+(?:employee|user|account)\s+(?:named|called)\s+["']?([a-zA-Z][a-zA-Z0-9_]+)["']?"#,
        r#"(?i)add\s+(?:a\s+)?(?:new\s+)?(?:user|account)\s+(?:named|called)\s+["']?([a-zA-Z][a-zA-Z0-9_]+)["']?"#,
    ];
    for pat in patterns {
        if let Some(caps) = re(pat).captures(text) {
            let username = caps[1].trim().to_string();
            if is_valid_username(&username)
                && username.chars().count() >= 3
                && !is_common_word(&username)
            {
                item.details
                    .insert("Username".to_string(), username.clone());
                item.description = format!("Create user account: {username}");
                return Some(item);
            }
        }
    }

    let low = text.to_lowercase();
    if low.contains("create")
        && (low.contains("account") || low.contains("user"))
        && low.contains("named")
    {
        item.description = "Create new user account (review text for details)".to_string();
        return Some(item);
    }

    None
}

fn parse_group_item(text: &str) -> Option<ActionableItem> {
    let lower = text.to_lowercase();
    let mut item = ActionableItem {
        raw_text: text.to_string(),
        ..Default::default()
    };

    if lower.contains("create") || lower.contains("make") {
        item.item_type = ActionableItemType::CreateGroup;
        let group = re(
            r#"(?i)(?:create|make)\s+(?:a\s+)?(?:new\s+)?group\s+(?:called\s+)?["']?(\w+)["']?"#,
        );
        if let Some(caps) = group.captures(text) {
            let name = caps[1].trim().to_string();
            item.description = format!("Create group: {name}");
            item.details.insert("GroupName".to_string(), name);
        } else {
            item.description = "Create new group (review text for details)".to_string();
        }
    } else if lower.contains("add") && lower.contains("to") && lower.contains("group") {
        item.item_type = ActionableItemType::AddUserToGroup;
        let add = re(
            r#"(?i)add\s+(?:user\s+)?["']?(\w+)["']?\s+to\s+(?:the\s+)?["']?(\w+)["']?\s+group"#,
        );
        if let Some(caps) = add.captures(text) {
            let user = caps[1].trim().to_string();
            let group = caps[2].trim().to_string();
            item.description = format!("Add {user} to group {group}");
            item.details.insert("Username".to_string(), user);
            item.details.insert("GroupName".to_string(), group);
        } else {
            item.description = "Add user to group (review text for details)".to_string();
        }
    } else if lower.contains("remove") && lower.contains("from") && lower.contains("group") {
        item.item_type = ActionableItemType::RemoveUserFromGroup;
        let remove = re(
            r#"(?i)remove\s+(?:user\s+)?["']?(\w+)["']?\s+from\s+(?:the\s+)?["']?(\w+)["']?\s+group"#,
        );
        if let Some(caps) = remove.captures(text) {
            let user = caps[1].trim().to_string();
            let group = caps[2].trim().to_string();
            item.description = format!("Remove {user} from group {group}");
            item.details.insert("Username".to_string(), user);
            item.details.insert("GroupName".to_string(), group);
        } else {
            item.description = "Remove user from group (review text for details)".to_string();
        }
    } else {
        item.item_type = ActionableItemType::CreateGroup;
        item.description = "Group management task (review text for details)".to_string();
    }

    Some(item)
}

fn parse_service_item(text: &str) -> Option<ActionableItem> {
    let lower = text.to_lowercase();
    let mut item = ActionableItem {
        raw_text: text.to_string(),
        ..Default::default()
    };

    if lower.contains("do not disable")
        || lower.contains("don't disable")
        || lower.contains("do not stop")
        || lower.contains("don't stop")
    {
        let critical = re(
            r"(?i)do\s+not\s+(?:stop|disable)\s+(?:or\s+\w+\s+)?(?:the\s+)?([A-Za-z0-9\s]+?)(?:\s+service|\s+process|\.|$)",
        );
        if let Some(caps) = critical.captures(text) {
            let service = caps[1].trim().to_string();
            let len = service.chars().count();
            if !service.is_empty() && len > 2 && len < 50 {
                item.item_type = ActionableItemType::EnableService;
                item.details
                    .insert("ServiceName".to_string(), service.clone());
                item.details.insert(
                    "Warning".to_string(),
                    "Do NOT disable this service".to_string(),
                );
                item.description = format!("Critical service (do NOT disable): {service}");
                return Some(item);
            }
        }
        return None;
    }

    let should_enable = lower.contains("enable")
        || lower.contains("start")
        || lower.contains("should be running")
        || lower.contains("must be running");
    let should_disable = lower.contains("disable")
        || lower.contains("stop")
        || lower.contains("should not be running")
        || lower.contains("must not be running");

    if !should_enable && !should_disable {
        return None;
    }

    item.item_type = if should_disable {
        ActionableItemType::DisableService
    } else {
        ActionableItemType::EnableService
    };

    let patterns = [
        r#"(?i)(?:enable|disable|start|stop)\s+(?:the\s+)?["']?([A-Za-z][A-Za-z0-9\s]{2,30}?)["']?\s+service"#,
        r#"(?i)["']?([A-Za-z][A-Za-z0-9\s]{2,30}?)["']?\s+service\s+(?:should|must|needs)\s+(?:be\s+)?(?:enabled|disabled|started|stopped|running)"#,
    ];
    for pat in patterns {
        if let Some(caps) = re(pat).captures(text) {
            let service = caps[1].trim().to_string();
            let len = service.chars().count();
            if !service.is_empty() && (3..40).contains(&len) && !is_common_word(&service) {
                item.description = if should_disable {
                    format!("Disable service: {service}")
                } else {
                    format!("Enable/ensure running: {service}")
                };
                item.details.insert("ServiceName".to_string(), service);
                return Some(item);
            }
        }
    }

    None
}

fn parse_software_item(text: &str) -> Option<ActionableItem> {
    let lower = text.to_lowercase();
    let mut item = ActionableItem {
        raw_text: text.to_string(),
        ..Default::default()
    };

    if lower.contains("user") || lower.contains("account") || lower.contains("home director") {
        return None;
    }

    let should_install = lower.contains("install") || lower.contains("update");
    let should_remove = lower.contains("uninstall")
        || (lower.contains("remove") && !lower.contains("user") && !lower.contains("account"));

    if !should_install && !should_remove {
        return None;
    }

    item.item_type = if should_remove {
        ActionableItemType::RemoveSoftware
    } else {
        ActionableItemType::InstallSoftware
    };

    let patterns = [
        r#"(?s)(?:install|uninstall|update)\s+(?:the\s+)?(?:latest\s+)?(?:version\s+of\s+)?["']?([A-Z][A-Za-z0-9\s]{1,25})["']?(?:\.|,|$|\s+for)"#,
        r#"(?s)["']?([A-Z][A-Za-z0-9]+)["']?\s+(?:should|must|needs)\s+(?:be\s+)?(?:installed|removed|uninstalled|updated)"#,
    ];
    for pat in patterns {
        if let Some(caps) = re(pat).captures(text) {
            let software = caps[1].trim().to_string();
            let len = software.chars().count();
            if !software.is_empty()
                && (2..30).contains(&len)
                && !is_common_word(&software)
                && software
                    .chars()
                    .next()
                    .map(|c| c.is_uppercase())
                    .unwrap_or(false)
            {
                item.description = if should_remove {
                    format!("Remove software: {software}")
                } else {
                    format!("Install/update software: {software}")
                };
                item.details.insert("SoftwareName".to_string(), software);
                return Some(item);
            }
        }
    }

    None
}

fn parse_security_policy_item(text: &str) -> Option<ActionableItem> {
    let lower = text.to_lowercase();
    let mut item = ActionableItem {
        item_type: ActionableItemType::SecurityPolicy,
        raw_text: text.to_string(),
        ..Default::default()
    };

    if lower.contains("password") {
        item.details
            .insert("Category".to_string(), "Password Policy".to_string());
        item.description = if lower.contains("complexity") {
            "Configure password complexity requirements"
        } else if lower.contains("length") {
            "Configure password length requirements"
        } else if lower.contains("history") {
            "Configure password history policy"
        } else if lower.contains("age") || lower.contains("expir") {
            "Configure password expiration policy"
        } else {
            "Configure password policy"
        }
        .to_string();
    } else if lower.contains("firewall") {
        item.details
            .insert("Category".to_string(), "Firewall".to_string());
        item.description = "Configure Windows Firewall settings".to_string();
    } else if lower.contains("audit") {
        item.details
            .insert("Category".to_string(), "Audit Policy".to_string());
        item.description = "Configure audit policy settings".to_string();
    } else if lower.contains("action center") {
        item.details
            .insert("Category".to_string(), "Action Center".to_string());
        item.description = "Configure Windows Action Center".to_string();
    } else if lower.contains("defender") || lower.contains("antivirus") {
        item.details
            .insert("Category".to_string(), "Antivirus".to_string());
        item.description = "Configure Windows Defender/Antivirus".to_string();
    } else {
        item.details
            .insert("Category".to_string(), "General".to_string());
        item.description = "Configure security policy (review text for details)".to_string();
    }

    Some(item)
}

fn parse_file_operation_item(text: &str) -> Option<ActionableItem> {
    let lower = text.to_lowercase();

    if lower.contains("user") && lower.contains("account") {
        return None;
    }
    if lower.contains("do not remove") || lower.contains("don't remove") {
        return None;
    }

    let mut item = ActionableItem {
        item_type: ActionableItemType::FileOperation,
        raw_text: text.to_string(),
        ..Default::default()
    };

    if (lower.contains("delete") || lower.contains("remove"))
        && (lower.contains("file") || lower.contains("media"))
    {
        if lower.contains("media") && lower.contains("prohibited") {
            item.description = "Remove prohibited media files".to_string();
            item.details
                .insert("FileType".to_string(), "Media files".to_string());
            return Some(item);
        } else if lower.contains("hacking") || lower.contains("unauthorized") {
            item.description = "Remove unauthorized/hacking tool files".to_string();
            item.details.insert(
                "FileType".to_string(),
                "Unauthorized software/tools".to_string(),
            );
            return Some(item);
        }
    }

    None
}

fn is_duplicate_action_item(data: &ReadmeData, new_item: &ActionableItem) -> bool {
    data.actionable_items.iter().any(|existing| {
        existing.item_type == new_item.item_type && existing.description == new_item.description
    })
}

fn parse_guidelines(content: &str, data: &mut ReadmeData) {
    if let Some(guidelines_content) = data.section("Competition Guidelines").cloned() {
        extract_guidelines_from_html(&guidelines_content, data);
    } else {
        let pattern = re(r"(?is)Competition\s+Guidelines.*?<ul[^>]*>(.*?)</ul>");
        if let Some(caps) = pattern.captures(content) {
            let inner = caps[1].to_string();
            extract_guidelines_from_html(&inner, data);
        }
    }
}

fn extract_guidelines_from_html(html_content: &str, data: &mut ReadmeData) {
    let li = re(r"(?is)<li[^>]*>(.*?)</li>");
    for caps in li.captures_iter(html_content) {
        let guideline = strip_html_tags(&caps[1]).trim().to_string();
        if !guideline.is_empty() {
            data.guidelines.push(guideline);
        }
    }
}

/// Extract the competition scenario. The C# version used a `(?=<h2|$)` lookahead;
/// here we take everything after the `Competition Scenario</h2>` prefix up to the
/// next `<h2`.
fn extract_scenario(content: &str) -> String {
    if !contains_ci(content, "Competition Scenario") {
        return String::new();
    }
    let prefix = re(r"(?is)Competition\s+Scenario\s*</h2>\s*");
    if let Some(m) = prefix.find(content) {
        let end = index_of_ci(content, "<h2", m.end()).unwrap_or(content.len());
        return strip_html_tags(&content[m.end()..end]).trim().to_string();
    }
    String::new()
}

/// Remove HTML tags from a string.
pub fn strip_html_tags(html: &str) -> String {
    if html.is_empty() {
        return String::new();
    }
    let script = re(r"(?is)<script[^>]*>.*?</script>");
    let style = re(r"(?is)<style[^>]*>.*?</style>");
    let tag = re(r"<[^>]+>");
    let ws = re(r"\s+");

    let s = script.replace_all(html, "");
    let s = style.replace_all(&s, "");
    let s = tag.replace_all(&s, " ");
    let s = html_decode(&s);
    let s = ws.replace_all(&s, " ");
    s.trim().to_string()
}

/// Display parsed README data in a formatted way.
pub fn display_parsed_data(data: &ReadmeData) {
    ui::rule(&format!("[bold blue]{}[/]", ui::escape(&data.title)));
    ui::write_line();

    ui::markup_line(&format!(
        "[bold]Operating System:[/] [cyan]{}[/]",
        ui::escape(&data.operating_system)
    ));
    ui::write_line();

    if !data.scenario.trim().is_empty() {
        ui::markup_line("[bold]Competition Scenario[/]");
        ui::markup_line(&ui::escape(&data.scenario));
        ui::write_line();
    }

    if !data.administrators.is_empty() {
        let mut t = ui::TableBuilder::new()
            .title("[bold red]Authorized Administrators[/]")
            .columns(&["[bold]Username[/]", "[bold]Password[/]", "[bold]Notes[/]"]);
        for admin in &data.administrators {
            let notes = if admin.is_primary_user {
                "[yellow](Primary User)[/]".to_string()
            } else {
                String::new()
            };
            t.add_row([
                format!("[red]{}[/]", ui::escape(&admin.username)),
                admin
                    .password
                    .clone()
                    .map(|p| ui::escape(&p))
                    .unwrap_or_else(|| "[dim]N/A[/]".to_string()),
                notes,
            ]);
        }
        t.print();
        ui::write_line();
    }

    if !data.users.is_empty() {
        let mut t = ui::TableBuilder::new()
            .title("[bold green]Authorized Users[/]")
            .columns(&["[bold]Username[/]"]);
        for user in &data.users {
            t.add_row([format!("[green]{}[/]", ui::escape(&user.username))]);
        }
        t.print();
        ui::write_line();
    }

    if !data.users_to_create.is_empty() {
        ui::markup_line("[bold yellow]Users to Create:[/]");
        for user in &data.users_to_create {
            ui::markup_line(&format!("  [yellow]+ {}[/]", ui::escape(user)));
        }
        ui::write_line();
    }

    if !data.group_requirements.is_empty() {
        ui::markup_line("[bold cyan]Group Requirements:[/]");
        for group in &data.group_requirements {
            ui::markup_line(&format!(
                "  [cyan]Group: {}[/]",
                ui::escape(&group.group_name)
            ));
            ui::markup_line(&format!(
                "    Members: {}",
                ui::escape(&group.members.join(", "))
            ));
        }
        ui::write_line();
    }

    if !data.required_software.is_empty() {
        let mut t = ui::TableBuilder::new()
            .title("[bold blue]Required Software[/]")
            .columns(&["[bold]Software[/]", "[bold]Version[/]", "[bold]Notes[/]"]);
        for software in &data.required_software {
            let version = if software.should_be_latest {
                "[green]Latest Stable[/]".to_string()
            } else {
                software
                    .version
                    .clone()
                    .map(|v| ui::escape(&v))
                    .unwrap_or_else(|| "[dim]Any[/]".to_string())
            };
            t.add_row([
                format!("[blue]{}[/]", ui::escape(&software.name)),
                version,
                software
                    .notes
                    .clone()
                    .map(|n| ui::escape(&n))
                    .unwrap_or_default(),
            ]);
        }
        t.print();
        ui::write_line();
    }

    if !data.prohibited_software.is_empty() {
        ui::markup_line("[bold red]Prohibited Software/Content:[/]");
        for software in &data.prohibited_software {
            ui::markup_line(&format!("  [red]✗ {}[/]", ui::escape(software)));
        }
        ui::write_line();
    }

    if !data.critical_services.is_empty() {
        ui::markup_line("[bold green]Critical Services (Do NOT disable):[/]");
        for service in &data.critical_services {
            ui::markup_line(&format!("  [green]● {}[/]", ui::escape(service)));
        }
        ui::write_line();
    }

    if !data.prohibited_services.is_empty() {
        ui::markup_line("[bold red]Services to Disable:[/]");
        for service in &data.prohibited_services {
            ui::markup_line(&format!("  [red]○ {}[/]", ui::escape(service)));
        }
        ui::write_line();
    }

    if !data.guidelines.is_empty() {
        ui::rule("[bold yellow]Competition Guidelines[/]");
        for guideline in &data.guidelines {
            ui::markup_line(&format!("  [yellow]•[/] {}", ui::escape(guideline)));
        }
        ui::write_line();
    }
}
