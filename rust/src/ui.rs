//! Console UI helpers that approximate the Spectre.Console features used by the
//! original tool: markup, rules, tables, and bar charts.
//!
//! Markup uses the familiar `[style]...[/]` syntax (e.g. `[bold green]OK[/]`).
//! Literal brackets can be produced with `[[` and `]]`.

use comfy_table::modifiers::UTF8_ROUND_CORNERS;
use comfy_table::presets::UTF8_FULL;
use comfy_table::{Cell, ContentArrangement, Table};
use owo_colors::OwoColorize;

/// Convert Spectre-style markup into an ANSI-colored string.
pub fn markup(input: &str) -> String {
    let chars: Vec<char> = input.chars().collect();
    let mut out = String::new();
    let mut stack: Vec<String> = Vec::new();
    let mut i = 0;

    while i < chars.len() {
        let c = chars[i];
        if c == '[' {
            if i + 1 < chars.len() && chars[i + 1] == '[' {
                out.push('[');
                i += 2;
                continue;
            }
            // Find the closing bracket.
            if let Some(rel) = chars[i + 1..].iter().position(|&x| x == ']') {
                let tag: String = chars[i + 1..i + 1 + rel].iter().collect();
                i = i + 1 + rel + 1;
                if tag == "/" {
                    stack.pop();
                    out.push_str("\x1b[0m");
                    for codes in &stack {
                        out.push_str(&format!("\x1b[{codes}m"));
                    }
                } else {
                    let codes = style_to_codes(&tag);
                    out.push_str(&format!("\x1b[{codes}m"));
                    stack.push(codes);
                }
            } else {
                out.push(c);
                i += 1;
            }
        } else if c == ']' {
            if i + 1 < chars.len() && chars[i + 1] == ']' {
                out.push(']');
                i += 2;
                continue;
            }
            out.push(c);
            i += 1;
        } else {
            out.push(c);
            i += 1;
        }
    }

    if !stack.is_empty() {
        out.push_str("\x1b[0m");
    }
    out
}

fn style_to_codes(tag: &str) -> String {
    let mut codes: Vec<&str> = Vec::new();
    for tok in tag.split_whitespace() {
        let code = match tok.to_ascii_lowercase().as_str() {
            "bold" => "1",
            "dim" => "2",
            "italic" => "3",
            "underline" => "4",
            "black" => "30",
            "red" => "31",
            "green" => "32",
            "yellow" => "33",
            "blue" => "34",
            "magenta" | "magenta1" => "35",
            "cyan" => "36",
            "white" => "37",
            "grey" | "gray" => "90",
            "orange3" => "38;5;172",
            _ => continue,
        };
        codes.push(code);
    }
    if codes.is_empty() {
        "39".to_string()
    } else {
        codes.join(";")
    }
}

/// Escape a string so its brackets are treated as literals by [`markup`].
pub fn escape(input: &str) -> String {
    input.replace('[', "[[").replace(']', "]]")
}

/// Print a markup string followed by a newline.
pub fn markup_line(input: &str) {
    println!("{}", markup(input));
}

/// Print an empty line.
pub fn write_line() {
    println!();
}

/// Print a horizontal rule with a centered, markup-styled title.
pub fn rule(title: &str) {
    let width = 80usize;
    let rendered = markup(title);
    let visible = visible_len(&rendered);
    if visible + 2 >= width {
        println!("── {rendered} ──");
        return;
    }
    let remaining = width - visible - 2;
    let left = remaining / 2;
    let right = remaining - left;
    println!("{} {} {}", "─".repeat(left), rendered, "─".repeat(right));
}

/// Print an exception-style error block.
pub fn write_exception(message: &str) {
    markup_line(&format!("[red]{}[/]", escape(message)));
}

fn visible_len(s: &str) -> usize {
    // Count characters that are not part of an ANSI escape sequence.
    let mut len = 0;
    let mut chars = s.chars().peekable();
    while let Some(c) = chars.next() {
        if c == '\x1b' {
            // Skip until 'm'.
            for e in chars.by_ref() {
                if e == 'm' {
                    break;
                }
            }
        } else {
            len += 1;
        }
    }
    len
}

/// A simple table builder mirroring the subset of Spectre.Console's Table API used here.
pub struct TableBuilder {
    title: Option<String>,
    headers: Vec<String>,
    rows: Vec<Vec<String>>,
    footnote: Option<String>,
}

impl TableBuilder {
    pub fn new() -> Self {
        Self {
            title: None,
            headers: Vec::new(),
            rows: Vec::new(),
            footnote: None,
        }
    }

    pub fn title(mut self, title: &str) -> Self {
        self.title = Some(title.to_string());
        self
    }

    pub fn columns(mut self, headers: &[&str]) -> Self {
        self.headers = headers.iter().map(|h| h.to_string()).collect();
        self
    }

    pub fn add_row<I, S>(&mut self, cells: I)
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        self.rows
            .push(cells.into_iter().map(|c| c.into()).collect());
    }

    pub fn footnote(&mut self, note: &str) {
        self.footnote = Some(note.to_string());
    }

    pub fn print(&self) {
        if let Some(title) = &self.title {
            markup_line(title);
        }
        let mut table = Table::new();
        table
            .load_preset(UTF8_FULL)
            .apply_modifier(UTF8_ROUND_CORNERS)
            .set_content_arrangement(ContentArrangement::Dynamic);

        if !self.headers.is_empty() {
            table.set_header(self.headers.iter().map(|h| Cell::new(markup(h))));
        }
        for row in &self.rows {
            table.add_row(row.iter().map(|c| Cell::new(markup(c))));
        }
        println!("{table}");
        if let Some(note) = &self.footnote {
            markup_line(note);
        }
    }
}

impl Default for TableBuilder {
    fn default() -> Self {
        Self::new()
    }
}

/// Bar-chart color options.
#[derive(Clone, Copy)]
pub enum BarColor {
    Green,
    Yellow,
    Red,
    Grey,
}

/// Render a simple horizontal bar chart.
pub fn bar_chart(label: &str, items: &[(String, f64, BarColor)]) {
    markup_line(label);
    let max = items.iter().map(|i| i.1).fold(0.0_f64, f64::max).max(1.0);
    let width = 50.0_f64;
    for (name, value, color) in items {
        let filled = ((value / max) * width).round() as usize;
        let bar = "█".repeat(filled);
        let colored = match color {
            BarColor::Green => bar.green().to_string(),
            BarColor::Yellow => bar.yellow().to_string(),
            BarColor::Red => bar.red().to_string(),
            BarColor::Grey => bar.bright_black().to_string(),
        };
        println!("{name:<12} {colored} {value:.2}");
    }
}
