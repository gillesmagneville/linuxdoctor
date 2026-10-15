// SPDX-License-Identifier: GPL-3.0-only

//! Reading log lines into one common shape, whatever they came from: the
//! systemd journal (JSON), a classic syslog file such as `auth.log`, or the
//! kernel ring buffer (`dmesg`). Pure parsing, no I/O.
//!
//! Parsers never fail: a line they do not understand is skipped, because a
//! log always contains lines nobody planned for. Every message is passed
//! through [`clean`] so nothing a program (or an attacker) put in a log can
//! carry control characters into a report.

use serde_json::Value;

use super::text::clean;

/// Longest message kept; the rest is cut. Long enough for any diagnostic
/// line, short enough that one hostile line cannot bloat a report.
pub const MAX_MESSAGE_CHARS: usize = 300;

/// One log line.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Entry {
    /// Syslog priority, 0 (emergency) to 7 (debug), when the source has one.
    pub priority: Option<u8>,
    /// The program that wrote it (`sshd`, `kernel`, ...).
    pub identifier: String,
    /// The systemd unit it ran in, when known.
    pub unit: Option<String>,
    pub message: String,
}

impl Entry {
    pub fn new(identifier: &str, message: &str) -> Self {
        Self {
            priority: None,
            identifier: clean(identifier, 64),
            unit: None,
            message: clean(message, MAX_MESSAGE_CHARS),
        }
    }

    pub fn with_priority(mut self, priority: u8) -> Self {
        self.priority = Some(priority);
        self
    }

    pub fn with_unit(mut self, unit: &str) -> Self {
        self.unit = Some(clean(unit, 128));
        self
    }
}

/// A journal field as text. The journal stores most fields as strings, but
/// a message that is not valid UTF-8 comes out as an array of byte values,
/// and a field present twice as an array of values.
fn field_text(value: &Value) -> Option<String> {
    match value {
        Value::String(s) => Some(s.clone()),
        Value::Number(n) => Some(n.to_string()),
        Value::Array(items) if !items.is_empty() => {
            if items.iter().all(|x| x.as_u64().is_some_and(|b| b <= 255)) {
                let bytes: Vec<u8> = items
                    .iter()
                    .filter_map(|x| x.as_u64().map(|b| b as u8))
                    .collect();
                Some(String::from_utf8_lossy(&bytes).into_owned())
            } else {
                items.first().and_then(field_text)
            }
        }
        _ => None,
    }
}

/// Parses the output of `journalctl -o json`: one JSON object per line.
pub fn parse_journal_json(text: &str) -> Vec<Entry> {
    text.lines()
        .filter_map(|line| {
            let value: Value = serde_json::from_str(line.trim()).ok()?;
            let map = value.as_object()?;
            let message = map.get("MESSAGE").and_then(field_text)?;
            let identifier = map
                .get("SYSLOG_IDENTIFIER")
                .or_else(|| map.get("_COMM"))
                .and_then(field_text)
                .unwrap_or_default();
            let priority = map
                .get("PRIORITY")
                .and_then(field_text)
                .and_then(|p| p.parse::<u8>().ok())
                .filter(|p| *p <= 7);
            let unit = map
                .get("_SYSTEMD_UNIT")
                .and_then(field_text)
                .filter(|u| !u.is_empty());
            Some(Entry {
                priority,
                identifier: clean(&identifier, 64),
                unit: unit.map(|u| clean(&u, 128)),
                message: clean(&message, MAX_MESSAGE_CHARS),
            })
        })
        .collect()
}

/// Parses a classic syslog file (`auth.log`, `secure`, `messages`). Both
/// timestamp styles are understood: the traditional `Oct 14 12:00:01` and
/// the ISO 8601 one rsyslog uses by default on recent Debian and Ubuntu.
///
/// ```text
/// Oct 14 12:00:01 web01 sshd[812]: Failed password for root from 203.0.113.7 port 51322 ssh2
/// 2026-10-14T12:00:01.123456+02:00 web01 sudo:   bob : user NOT in sudoers ; ...
/// ```
pub fn parse_syslog(text: &str) -> Vec<Entry> {
    text.lines().filter_map(parse_syslog_line).collect()
}

fn parse_syslog_line(line: &str) -> Option<Entry> {
    let mut words = line.split_whitespace();
    let first = words.next()?;
    let is_iso = first.len() >= 19
        && first.as_bytes().get(4) == Some(&b'-')
        && first.as_bytes().get(10) == Some(&b'T');
    let skip = if is_iso { 1 } else { 3 };
    if !is_iso {
        // "Oct 14 12:00:01": a month name, a day, a time.
        let day = words.next()?;
        let time = words.next()?;
        if first.len() != 3 || !day.bytes().all(|b| b.is_ascii_digit()) || !time.contains(':') {
            return None;
        }
    }
    let _host = words.next()?;

    // Everything after the host name: "prog[pid]: message".
    let mut rest = line.trim_start();
    for _ in 0..(skip + 1) {
        let end = rest.find(char::is_whitespace)?;
        rest = rest[end..].trim_start();
    }
    let (tag, message) = match rest.split_once(": ") {
        Some((tag, message)) if !tag.contains(char::is_whitespace) => (tag, message),
        _ => ("", rest),
    };
    let identifier = tag.split('[').next().unwrap_or("");
    Some(Entry::new(identifier, message.trim()))
}

/// Parses `dmesg` output, with or without its `[   12.345678]` prefix.
pub fn parse_dmesg(text: &str) -> Vec<Entry> {
    text.lines()
        .filter(|l| !l.trim().is_empty())
        .map(|line| {
            let message = match line.strip_prefix('[').and_then(|r| r.split_once(']')) {
                Some((stamp, rest))
                    if stamp.len() <= 20
                        && stamp
                            .chars()
                            .all(|c| c.is_ascii_digit() || c == '.' || c == ' ') =>
                {
                    rest.trim_start()
                }
                _ => line,
            };
            Entry::new("kernel", message)
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn journal_lines_become_entries() {
        let text = concat!(
            r#"{"MESSAGE":"Failed password for root from 1.2.3.4 port 22 ssh2","PRIORITY":"6","SYSLOG_IDENTIFIER":"sshd","_PID":"812","_SYSTEMD_UNIT":"ssh.service"}"#,
            "\n",
            r#"{"MESSAGE":"disk full","PRIORITY":"3","_COMM":"backup"}"#,
            "\n",
        );
        let e = parse_journal_json(text);
        assert_eq!(e.len(), 2);
        assert_eq!(e[0].identifier, "sshd");
        assert_eq!(e[0].priority, Some(6));
        assert_eq!(e[0].unit.as_deref(), Some("ssh.service"));
        assert_eq!(e[1].identifier, "backup", "falls back to the command name");
        assert_eq!(e[1].unit, None);
    }

    #[test]
    fn binary_and_repeated_fields_are_handled() {
        let text = concat!(
            r#"{"MESSAGE":[104,105,255,33],"SYSLOG_IDENTIFIER":"x"}"#,
            "\n",
            r#"{"MESSAGE":"ok","SYSLOG_IDENTIFIER":["first","second"],"PRIORITY":3}"#,
            "\n",
        );
        let e = parse_journal_json(text);
        assert_eq!(e[0].message, "hi\u{fffd}!");
        assert_eq!(e[1].identifier, "first");
        assert_eq!(e[1].priority, Some(3), "a numeric priority works too");
    }

    #[test]
    fn bad_lines_and_missing_messages_are_skipped() {
        let text = "not json\n{}\n[1,2]\n{\"PRIORITY\":\"3\"}\n\n{\"MESSAGE\":\"kept\"}\n";
        let e = parse_journal_json(text);
        assert_eq!(e.len(), 1);
        assert_eq!(e[0].message, "kept");
        assert!(parse_journal_json("").is_empty());
    }

    #[test]
    fn out_of_range_priorities_are_dropped() {
        let e = parse_journal_json(r#"{"MESSAGE":"m","PRIORITY":"9"}"#);
        assert_eq!(e[0].priority, None);
    }

    #[test]
    fn hostile_messages_are_cleaned_and_bounded() {
        let long = "x".repeat(1000);
        let text =
            format!(r#"{{"MESSAGE":"\u001b[2Jwipe {long}","SYSLOG_IDENTIFIER":"ev\u001bil"}}"#);
        let e = parse_journal_json(&text);
        assert!(!e[0].message.contains('\u{1b}'));
        assert!(!e[0].identifier.contains('\u{1b}'));
        assert_eq!(e[0].message.chars().count(), MAX_MESSAGE_CHARS + 1);
        assert!(e[0].message.ends_with('…'));
    }

    #[test]
    fn traditional_syslog_lines() {
        let e = parse_syslog(
            "Oct 14 12:00:01 web01 sshd[812]: Failed password for root from 1.2.3.4 port 22 ssh2\n\
             Oct  4 03:00:00 web01 CRON[5]: (root) CMD (run-parts)\n",
        );
        assert_eq!(e.len(), 2);
        assert_eq!(e[0].identifier, "sshd");
        assert_eq!(
            e[0].message,
            "Failed password for root from 1.2.3.4 port 22 ssh2"
        );
        assert_eq!(e[1].identifier, "CRON");
    }

    #[test]
    fn iso_timestamps_and_padded_sudo_lines() {
        let e = parse_syslog(
            "2026-10-14T12:00:01.123456+02:00 web01 sudo:     bob : user NOT in sudoers ; TTY=pts/0 ; COMMAND=/bin/sh\n",
        );
        assert_eq!(e.len(), 1);
        assert_eq!(e[0].identifier, "sudo");
        assert!(e[0].message.starts_with("bob : user NOT in sudoers"));
    }

    #[test]
    fn lines_without_a_tag_keep_their_text() {
        let e = parse_syslog("Oct 14 12:00:01 web01 something happened without a tag\n");
        assert_eq!(e[0].identifier, "");
        assert_eq!(e[0].message, "something happened without a tag");
    }

    #[test]
    fn garbage_lines_are_skipped_not_fatal() {
        assert!(parse_syslog("\n   \nrandom words here\nOct x\n").is_empty());
        assert!(parse_syslog("").is_empty());
    }

    #[test]
    fn dmesg_prefix_is_removed() {
        let e = parse_dmesg(
            "[    0.000000] Linux version 6.8\n[12345.678901] EXT4-fs error (device sda1)\nplain line\n\n",
        );
        assert_eq!(e.len(), 3);
        assert_eq!(e[0].message, "Linux version 6.8");
        assert_eq!(e[1].message, "EXT4-fs error (device sda1)");
        assert_eq!(e[2].message, "plain line");
        assert!(e.iter().all(|x| x.identifier == "kernel"));
    }

    #[test]
    fn a_bracket_that_is_not_a_timestamp_stays() {
        let e = parse_dmesg("[Hardware Error]: something\n");
        assert_eq!(e[0].message, "[Hardware Error]: something");
    }
}
