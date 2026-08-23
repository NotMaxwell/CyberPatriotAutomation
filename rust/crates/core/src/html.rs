//! HTML structure, read with a real HTML parser.
//!
//! Everything structural about a README - its title, its `<h2>` sections, its
//! paragraphs, its list items, where one line ends and the next begins - is
//! answered here, so the parser above can spend its regexes on English prose
//! instead of on markup.
//!
//! It used to do both with regex, and the markup half kept losing. `<[^>]+>`
//! does not know that `<b>` inside `Windows <b>10</b>` is not a word boundary,
//! that `&nbsp;` is a space, that `<p>` implies the end of the previous one, or
//! that an unclosed `<li>` still ends where the next begins. Every one of those
//! is ordinary in hand-written HTML, and each was found the same way: a README
//! parsed to nothing and someone went looking.
//!
//! `scraper` (html5ever) applies the HTML5 parsing algorithm, including its
//! error recovery, so malformed markup produces the tree a browser would show
//! rather than a regex's best guess. It costs about 470 KB in the shipped
//! binary, which is the largest single dependency here and deliberate: README
//! parsing is where this tool is most often wrong, and disk is the cheapest
//! thing a competition image has.

use scraper::{Html, Selector};

/// Elements whose boundaries are line breaks when a README is read as text.
///
/// A user list written one-per-`<p>` or separated by `<br>` has to come out as
/// separate lines; run together, the whole block reads as a single over-long
/// username and the README yields no users at all.
const BLOCK_ELEMENTS: &[&str] = &[
    "address",
    "article",
    "aside",
    "blockquote",
    "br",
    "div",
    "dd",
    "dl",
    "dt",
    "fieldset",
    "figcaption",
    "figure",
    "footer",
    "form",
    "h1",
    "h2",
    "h3",
    "h4",
    "h5",
    "h6",
    "header",
    "hr",
    "li",
    "main",
    "nav",
    "ol",
    "p",
    "pre",
    "section",
    "table",
    "td",
    "th",
    "tr",
    "ul",
];

/// Elements whose text is markup machinery, not content.
const IGNORED_ELEMENTS: &[&str] = &["script", "style", "head", "template", "noscript"];

fn selector(css: &str) -> Selector {
    Selector::parse(css).expect("invalid selector")
}

/// Parse a document, or a fragment that may not have `<html>` around it.
fn document(html: &str) -> Html {
    Html::parse_document(html)
}

/// The visible text, with runs of whitespace collapsed to single spaces.
///
/// This is the replacement for the old `strip_html_tags`, and the difference
/// that matters is that entities are decoded and element boundaries separate
/// words: `Windows&nbsp;10` and `Windows <b>10</b>` both come out as
/// `Windows 10`, where the regex produced `Windows\u{a0}10` and `Windows10`.
pub fn text(html: &str) -> String {
    // Block boundaries are emitted and then collapsed, rather than skipped.
    // Without that, `<p>one</p><p>two</p>` reads as "onetwo" - the same class
    // of mistake as the old `<[^>]+>` regex, which at least replaced each tag
    // with a space. Inline elements still join, so `Windows<b>10</b>` is
    // "Windows10", which is what a browser shows.
    collapse(&raw_text(html, true))
}

/// The visible text with block elements and `<br>` rendered as line breaks.
///
/// Leading and trailing space is trimmed from each line and empty lines are
/// dropped, so the result is the lines a reader would see.
pub fn text_with_breaks(html: &str) -> String {
    raw_text(html, true)
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty())
        .collect::<Vec<_>>()
        .join("\n")
}

fn raw_text(html: &str, break_blocks: bool) -> String {
    let doc = document(html);
    let mut out = String::new();
    walk(doc.tree.root(), break_blocks, &mut out);
    out
}

fn walk(node: ego_tree::NodeRef<scraper::Node>, break_blocks: bool, out: &mut String) {
    match node.value() {
        scraper::Node::Text(t) => out.push_str(t),
        scraper::Node::Element(e) => {
            let name = e.name();
            if IGNORED_ELEMENTS.contains(&name) {
                return;
            }
            let is_block = break_blocks && BLOCK_ELEMENTS.contains(&name);
            if is_block && !out.ends_with('\n') && !out.is_empty() {
                out.push('\n');
            }
            for child in node.children() {
                walk(child, break_blocks, out);
            }
            if is_block && !out.ends_with('\n') {
                out.push('\n');
            }
            return;
        }
        _ => {}
    }
    for child in node.children() {
        walk(child, break_blocks, out);
    }
}

fn collapse(s: &str) -> String {
    s.split_whitespace().collect::<Vec<_>>().join(" ")
}

/// The document title: the first `<h1>`, falling back to `<title>`.
pub fn title(html: &str) -> Option<String> {
    let doc = document(html);
    for css in ["h1", "title"] {
        if let Some(element) = doc.select(&selector(css)).next() {
            let t = collapse(&element.text().collect::<String>());
            if !t.is_empty() {
                return Some(t);
            }
        }
    }
    None
}

/// The text of every heading that names the image, most authoritative first.
///
/// The title and first heading name the image on essentially every official
/// README ("Training Round Windows 10 README"), so they are consulted before
/// the body - a whole-document scan matches prose such as "do not go back to
/// Windows 10" in a Windows 11 image.
pub fn headline_texts(html: &str) -> Vec<String> {
    let doc = document(html);
    doc.select(&selector("title, h1"))
        .map(|e| collapse(&e.text().collect::<String>()))
        .filter(|t| !t.is_empty())
        .collect()
}

/// One `<h2>` section: its heading, and the markup up to the next `<h2>`.
pub struct Section {
    pub heading: String,
    pub html: String,
}

/// Every `<h2>` heading paired with the markup that follows it.
///
/// The old version sliced the raw string between regex match offsets, which
/// works only while the document is flat; a heading nested one level deeper
/// than the next took the enclosing element's markup with it.
pub fn sections(html: &str) -> Vec<Section> {
    let doc = document(html);
    let mut out = Vec::new();

    for h2 in doc.select(&selector("h2")) {
        // An unclosed <h2> does not end at the next paragraph - the HTML5
        // parsing algorithm nests that paragraph *inside* the heading, which is
        // also how a browser renders it. Taking `h2.text()` whole then produces
        // a "heading" that is the entire section, and the section body comes
        // out empty. So the heading is only the phrasing content before the
        // first block child, and any block children that followed are the start
        // of the body.
        let mut heading = String::new();
        let mut body = String::new();
        let mut past_heading = false;
        for child in h2.children() {
            let is_block = scraper::ElementRef::wrap(child)
                .is_some_and(|e| BLOCK_ELEMENTS.contains(&e.value().name()));
            if is_block {
                past_heading = true;
            }
            if past_heading {
                if let Some(element) = scraper::ElementRef::wrap(child) {
                    body.push_str(&element.html());
                } else if let scraper::Node::Text(t) = child.value() {
                    body.push_str(t);
                }
            } else {
                walk(child, false, &mut heading);
            }
        }
        let heading = collapse(&heading);
        if heading.is_empty() {
            continue;
        }
        for sibling in h2.next_siblings() {
            if let Some(element) = scraper::ElementRef::wrap(sibling) {
                if element.value().name() == "h2" {
                    break;
                }
                body.push_str(&element.html());
            } else if let scraper::Node::Text(t) = sibling.value() {
                body.push_str(t);
            }
        }
        out.push(Section {
            heading,
            html: body,
        });
    }

    out
}

/// The text of every element matching `css`, in document order.
///
/// Empty matches are dropped: a `<p>` used for spacing is not a paragraph of
/// the document as far as any caller here is concerned.
pub fn texts_of(html: &str, css: &str) -> Vec<String> {
    let doc = document(html);
    doc.select(&selector(css))
        .map(|e| collapse(&e.text().collect::<String>()))
        .filter(|t| !t.is_empty())
        .collect()
}

/// The text of every element matching `css`, with line breaks preserved.
pub fn broken_texts_of(html: &str, css: &str) -> Vec<String> {
    let doc = document(html);
    doc.select(&selector(css))
        .map(|e| {
            let mut buf = String::new();
            walk(*e, true, &mut buf);
            buf.lines()
                .map(str::trim)
                .filter(|l| !l.is_empty())
                .collect::<Vec<_>>()
                .join("\n")
        })
        .filter(|t| !t.is_empty())
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The two shapes that produced "Unknown" for the operating system.
    #[test]
    fn markup_and_entities_do_not_run_words_together() {
        assert_eq!(
            text("<h1>Windows <b>10</b> README</h1>"),
            "Windows 10 README"
        );
        assert_eq!(text("<p>Windows&nbsp;10</p>"), "Windows 10");
        assert_eq!(text("<p>a\n\n  b\tc</p>"), "a b c");
    }

    #[test]
    fn script_and_style_contribute_no_text() {
        let html = "<style>p{color:red}</style><p>real</p><script>var x=1;</script>";
        assert_eq!(text(html), "real");
    }

    /// A user list written with <br> or one <p> each must not collapse into a
    /// single line - that is what made such a README yield zero users.
    #[test]
    fn block_elements_and_br_become_line_breaks() {
        assert_eq!(
            text_with_breaks("<p>alice<br>bob<br/>carol</p>"),
            "alice\nbob\ncarol"
        );
        assert_eq!(text_with_breaks("<p>alice</p><p>bob</p>"), "alice\nbob");
        assert_eq!(text_with_breaks("<ul><li>a</li><li>b</li></ul>"), "a\nb");
    }

    /// html5ever's error recovery is the reason for the dependency.
    #[test]
    fn malformed_markup_still_parses() {
        // Unclosed <li> - a browser ends each at the next one.
        assert_eq!(text_with_breaks("<ul><li>a<li>b</ul>"), "a\nb");
        // Unclosed <p>, stray close tag, and an unquoted attribute.
        assert_eq!(text("<p class=x>one<p>two</b>"), "one two");
    }

    #[test]
    fn the_title_prefers_the_first_heading() {
        assert_eq!(
            title(
                "<html><head><title>Round 1</title></head><body><h1>Windows 11</h1></body></html>"
            )
            .as_deref(),
            Some("Windows 11")
        );
        assert_eq!(
            title("<html><head><title>Round 1</title></head><body></body></html>").as_deref(),
            Some("Round 1")
        );
        assert_eq!(title("<p>no headings</p>"), None);
    }

    #[test]
    fn sections_run_from_one_heading_to_the_next() {
        let html = "<h2>First</h2><p>one</p><h2>Second</h2><p>two</p><p>three</p>";
        let sections = sections(html);
        assert_eq!(sections.len(), 2);
        assert_eq!(sections[0].heading, "First");
        assert_eq!(text(&sections[0].html), "one");
        assert_eq!(sections[1].heading, "Second");
        assert_eq!(text(&sections[1].html), "two three");
    }

    /// An unclosed heading nests the section inside itself. The heading must
    /// still be the heading, and the section must still have a body.
    #[test]
    fn an_unclosed_heading_does_not_swallow_its_section() {
        let html =
            "<h2>Competition Scenario<p>You were hired.<p>Disable Telnet.<h2>Next</h2><p>after</p>";
        let sections = sections(html);
        assert_eq!(sections[0].heading, "Competition Scenario");
        assert_eq!(text(&sections[0].html), "You were hired. Disable Telnet.");
        assert_eq!(sections[1].heading, "Next");
        assert_eq!(text(&sections[1].html), "after");
    }

    #[test]
    fn texts_of_returns_each_match_separately() {
        assert_eq!(
            texts_of("<p>one</p><p></p><p>two</p>", "p"),
            vec!["one".to_string(), "two".to_string()]
        );
    }
}
