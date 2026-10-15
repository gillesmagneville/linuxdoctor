// SPDX-License-Identifier: GPL-3.0-only

//! Text that came from somewhere the program does not control -- a log
//! line, a report file written on another machine -- and is about to be
//! shown to someone.

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

#[cfg(test)]
mod tests {
    use super::*;

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
