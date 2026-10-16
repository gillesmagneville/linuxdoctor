// SPDX-License-Identifier: GPL-3.0-only

//! Text that came from somewhere the program does not control -- a log
//! line, a report file written on another machine, a process or virtual
//! machine name -- and is about to be shown to someone.
//!
//! Two functions, for two jobs: [`clean`] flattens one value to a single
//! line of bounded length (for tables and one-line messages), and
//! [`printable`] keeps text as it is, line breaks included, and only takes
//! out what could act on the reader's terminal.

use std::borrow::Cow;

/// Characters that change how surrounding text is displayed without being
/// visible themselves: the bidirectional overrides and isolates.
fn is_bidi_control(c: char) -> bool {
    matches!(c, '\u{200e}' | '\u{200f}' | '\u{202a}'..='\u{202e}' | '\u{2066}'..='\u{2069}')
}

/// Replaces control characters (including ESC, which starts a terminal
/// escape sequence) and invisible direction overrides with `?`, and keeps
/// at most `max` characters, ending with `…` when something was cut.
pub fn clean(text: &str, max: usize) -> String {
    let mut out = String::new();
    for (i, c) in text.chars().enumerate() {
        if i == max {
            out.push('…');
            break;
        }
        out.push(if c.is_control() || is_bidi_control(c) {
            '?'
        } else {
            c
        });
    }
    out
}

/// The text with everything that could act on a terminal taken out, and
/// nothing else changed: line breaks and layout are kept, so explanations
/// with aligned columns keep their shape.
///
/// * a line feed is kept, and so is a carriage return that ends a line (it
///   is dropped); a carriage return anywhere else would let a name
///   overwrite what was printed before it, so it becomes `?`
/// * a tab becomes a space (a terminal would jump to a tab stop)
/// * any other control character -- ESC, which starts a terminal escape
///   sequence, and its relatives: BEL, backspace, NUL, DEL, the C1 range --
///   becomes `?`
/// * the bidirectional overrides and isolates, which make text read in a
///   different order than it is written, become `?`
///
/// Returns the input itself, without copying, when there is nothing to
/// change, which is almost always.
pub fn printable(text: &str) -> Cow<'_, str> {
    let needs_work = |c: char| (c.is_control() && c != '\n') || is_bidi_control(c);
    if !text.chars().any(needs_work) {
        return Cow::Borrowed(text);
    }
    let mut out = String::with_capacity(text.len());
    let mut chars = text.chars().peekable();
    while let Some(c) = chars.next() {
        match c {
            '\n' => out.push('\n'),
            '\r' if chars.peek() == Some(&'\n') => {}
            '\t' => out.push(' '),
            c if c.is_control() || is_bidi_control(c) => out.push('?'),
            c => out.push(c),
        }
    }
    Cow::Owned(out)
}

/// [`printable`], in place.
pub fn make_printable(text: &mut String) {
    if let Cow::Owned(safe) = printable(text) {
        *text = safe;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn printable_takes_out_escape_sequences_and_keeps_the_layout() {
        assert_eq!(
            printable("a\u{1b}[2Jb\u{1b}]0;title\u{7}c"),
            "a?[2Jb?]0;title?c"
        );
        let table = "  name    size\n  root    10 MB\n\n    indented";
        assert!(
            matches!(printable(table), Cow::Borrowed(_)),
            "unchanged text is not copied"
        );
        assert_eq!(printable(table), table);
    }

    #[test]
    fn printable_handles_carriage_returns_tabs_and_the_rest_of_the_controls() {
        // A line ending is harmless; a lone CR would overwrite the line.
        assert_eq!(printable("one\r\ntwo"), "one\ntwo");
        assert_eq!(printable("GOOD\rEVIL"), "GOOD?EVIL");
        assert_eq!(printable("a\tb"), "a b");
        assert_eq!(printable("x\u{8}\u{0}\u{7f}\u{9b}y"), "x????y");
    }

    #[test]
    fn printable_neutralises_direction_overrides_but_not_ordinary_text() {
        assert_eq!(printable("evil\u{202e}gnp.exe"), "evil?gnp.exe");
        assert_eq!(printable("\u{2066}x\u{2069}"), "?x?");
        let ordinary = "Wörter, 日本語, Ελληνικά, العربية, emoji 🙂, — · → ✓ ⚠";
        assert_eq!(
            printable(ordinary),
            ordinary,
            "right-to-left scripts are not touched"
        );
    }

    #[test]
    fn make_printable_changes_the_string_in_place() {
        let mut s = String::from("a\u{1b}b");
        make_printable(&mut s);
        assert_eq!(s, "a?b");
        let mut clean = String::from("fine");
        make_printable(&mut clean);
        assert_eq!(clean, "fine");
    }

    #[test]
    fn clean_removes_escape_sequences_and_direction_overrides() {
        assert_eq!(clean("a\u{1b}[31mred", 40), "a?[31mred");
        assert_eq!(clean("tab\there\nnewline", 40), "tab?here?newline");
        assert_eq!(clean("evil\u{202e}gnp.exe", 40), "evil?gnp.exe");
        assert_eq!(clean("c1\u{9b}", 40), "c1?");
    }

    #[test]
    fn clean_cuts_long_text_and_says_so() {
        assert_eq!(clean("abcdef", 6), "abcdef");
        assert_eq!(clean("abcdefg", 6), "abcdef…");
        assert_eq!(clean("", 6), "");
        assert_eq!(clean("é".repeat(10).as_str(), 3), "ééé…");
    }
}
