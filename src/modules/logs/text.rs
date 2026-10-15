// SPDX-License-Identifier: GPL-3.0-only

//! Small helpers for text that comes out of log files.
//!
//! Log lines are written by programs, and some of what they contain is
//! chosen by strangers: an attacker picks the user name they try over SSH,
//! a local user picks the name of their own process. Everything that
//! reaches a finding passes through [`clean`] first, so a hostile line can
//! neither smuggle terminal escape sequences into the report nor flood it,
//! and a name only ever becomes part of a suggested command through
//! [`is_safe_word`].

pub use crate::core::text::clean;

/// `true` when `word` can be placed in a suggested shell command exactly as
/// it is: letters, digits and `_ . @ : - / +`, not starting with `-`, at
/// most 64 characters. Anything else (a stranger's user name, a program
/// name with spaces) is replaced by a placeholder in commands instead.
pub fn is_safe_word(word: &str) -> bool {
    !word.is_empty()
        && word.len() <= 64
        && !word.starts_with('-')
        && word.chars().all(|c| {
            c.is_ascii_alphanumeric() || matches!(c, '_' | '.' | '@' | ':' | '-' | '/' | '+')
        })
}

/// `word` if it is safe in a command, otherwise `placeholder`.
pub fn word_or<'a>(word: &'a str, placeholder: &'a str) -> &'a str {
    if is_safe_word(word) {
        word
    } else {
        placeholder
    }
}

/// Collapses the parts of a message that change from one occurrence to the
/// next (numbers, hexadecimal values) so identical complaints group
/// together: `"timeout after 30 s on 0x1f"` becomes `"timeout after N s on 0xN"`.
pub fn normalize(message: &str) -> String {
    let chars: Vec<char> = message.chars().collect();
    let mut out = String::with_capacity(message.len());
    let mut i = 0;
    while i < chars.len() {
        let c = chars[i];
        if c == '0'
            && chars.get(i + 1) == Some(&'x')
            && chars.get(i + 2).is_some_and(|d| d.is_ascii_hexdigit())
        {
            i += 2;
            while i < chars.len() && chars[i].is_ascii_hexdigit() {
                i += 1;
            }
            out.push_str("0xN");
        } else if c.is_ascii_digit() {
            while i < chars.len() && chars[i].is_ascii_digit() {
                i += 1;
            }
            out.push('N');
        } else {
            out.push(c);
            i += 1;
        }
    }
    out
}

/// A size in bytes as `1.5 GiB`, `300 MiB`, `12 KiB` or `0 B`.
pub fn human_size(bytes: u64) -> String {
    const UNITS: [&str; 5] = ["B", "KiB", "MiB", "GiB", "TiB"];
    let mut value = bytes as f64;
    let mut unit = 0;
    while value >= 1024.0 && unit < UNITS.len() - 1 {
        value /= 1024.0;
        unit += 1;
    }
    if unit == 0 {
        format!("{bytes} B")
    } else if value >= 100.0 {
        format!("{value:.0} {}", UNITS[unit])
    } else {
        format!("{value:.1} {}", UNITS[unit])
    }
}

/// Lays rows out as a column-aligned table whose lines all start with two
/// spaces — the convention that tells every renderer "this is a table, keep
/// its columns" (see `output::common::explanation_blocks`).
pub fn table(header: &[&str], rows: &[Vec<String>]) -> String {
    let columns = header.len();
    let mut widths: Vec<usize> = header.iter().map(|h| h.chars().count()).collect();
    for row in rows {
        for (i, cell) in row.iter().enumerate().take(columns) {
            widths[i] = widths[i].max(cell.chars().count());
        }
    }
    let line = |cells: Vec<&str>| -> String {
        let mut out = String::from("  ");
        for (i, cell) in cells.iter().enumerate() {
            if i + 1 == columns {
                out.push_str(cell);
            } else {
                out.push_str(&format!("{:<width$}  ", cell, width = widths[i]));
            }
        }
        out.trim_end().to_string()
    };
    let mut lines = vec![line(header.to_vec())];
    for row in rows {
        lines.push(line(row.iter().map(String::as_str).collect()));
    }
    lines.join("\n")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_plain_words_enter_commands() {
        for ok in [
            "bob",
            "www-data",
            "user@host",
            "nginx.service",
            "/var/log/x.log",
        ] {
            assert!(is_safe_word(ok), "{ok}");
        }
        for bad in [
            "",
            "-rf",
            "a b",
            "x;rm",
            "$(id)",
            "a`b`",
            "it's",
            "a|b",
            "a\nb",
            "é",
            &"x".repeat(65),
        ] {
            assert!(!is_safe_word(bad), "{bad:?}");
        }
        assert_eq!(word_or("bob", "<user>"), "bob");
        assert_eq!(word_or("a;b", "<user>"), "<user>");
    }

    #[test]
    fn normalize_groups_messages_that_differ_only_by_numbers() {
        assert_eq!(
            normalize("timeout after 30 s on 0x1F3a, retry 7"),
            "timeout after N s on 0xN, retry N"
        );
        assert_eq!(normalize("no digits"), "no digits");
        assert_eq!(
            normalize("0x"),
            "Nx",
            "a bare prefix is not a hexadecimal value"
        );
        assert_eq!(normalize("eth0 up"), "ethN up");
    }

    #[test]
    fn sizes_read_naturally() {
        assert_eq!(human_size(0), "0 B");
        assert_eq!(human_size(1023), "1023 B");
        assert_eq!(human_size(1536), "1.5 KiB");
        assert_eq!(human_size(300 * 1024 * 1024), "300 MiB");
        assert_eq!(human_size(5 * 1024 * 1024 * 1024 / 2), "2.5 GiB");
    }

    #[test]
    fn tables_align_columns_and_start_with_two_spaces() {
        let t = table(
            &["Count", "Source"],
            &[
                vec!["412".into(), "203.0.113.7".into()],
                vec!["3".into(), "10.0.0.1".into()],
            ],
        );
        assert_eq!(
            t,
            "  Count  Source\n  412    203.0.113.7\n  3      10.0.0.1"
        );
        for l in t.lines() {
            assert!(l.starts_with("  ") && !l.starts_with("   "));
        }
    }
}
