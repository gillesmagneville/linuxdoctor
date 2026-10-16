// SPDX-License-Identifier: GPL-3.0-only

//! What the interactive screen shows of a report: a *view*, never a change to
//! the report. Two independent narrowings, combined with "and":
//!
//! - a minimum severity (`f` cycles it: everything, warning and above, error
//!   and above, critical only -- the same four levels as `--min-severity`);
//! - a piece of text (`/`), looked for without regard to case in a finding's
//!   id, title, explanation, recommendation, instance and evidence.
//!
//! The report itself is untouched: the module list's status symbols still
//! describe the whole module, and the exit code of `linuxdoctor tui` is still
//! computed from every finding. Hiding a finding on screen must never be able
//! to hide it from the exit code.
//!
//! The text typed here comes from the keyboard, not from the audited machine,
//! so it is not subject to the hostile-text cleaning; it is still limited in
//! length and refuses control characters, because it is drawn back.

use crate::models::{Finding, Severity};

/// Longest search text accepted. Enough for an id, a path or a service name;
/// short enough to always fit the status line.
pub const MAX_QUERY_CHARS: usize = 40;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ViewFilter {
    min_severity: Severity,
    query: String,
    /// `query` lowercased once, instead of once per finding per frame.
    needle: String,
}

impl Default for ViewFilter {
    fn default() -> Self {
        ViewFilter {
            min_severity: Severity::Info,
            query: String::new(),
            needle: String::new(),
        }
    }
}

impl ViewFilter {
    /// True when the filter hides anything it could: some severity level is
    /// cut off, or a text is being looked for.
    pub fn is_active(&self) -> bool {
        self.min_severity > Severity::Info || !self.query.is_empty()
    }

    pub fn min_severity(&self) -> Severity {
        self.min_severity
    }

    pub fn query(&self) -> &str {
        &self.query
    }

    /// Info -> Warning -> Error -> Critical -> Info.
    pub fn cycle_severity(&mut self) {
        self.min_severity = match self.min_severity {
            Severity::Info => Severity::Warning,
            Severity::Warning => Severity::Error,
            Severity::Error => Severity::Critical,
            Severity::Critical => Severity::Info,
        };
    }

    /// Add a typed character. Returns whether the text changed: a control
    /// character, or one past `MAX_QUERY_CHARS`, is refused.
    pub fn push_char(&mut self, c: char) -> bool {
        if c.is_control() || self.query.chars().count() >= MAX_QUERY_CHARS {
            return false;
        }
        self.query.push(c);
        self.refresh_needle();
        true
    }

    /// Remove the last typed character. Returns whether there was one.
    pub fn pop_char(&mut self) -> bool {
        let removed = self.query.pop().is_some();
        if removed {
            self.refresh_needle();
        }
        removed
    }

    /// Forget the typed text, keeping the severity. Returns whether there was
    /// any.
    pub fn clear_query(&mut self) -> bool {
        let had = !self.query.is_empty();
        self.query.clear();
        self.refresh_needle();
        had
    }

    /// Back to showing everything.
    pub fn clear(&mut self) {
        *self = ViewFilter::default();
    }

    fn refresh_needle(&mut self) {
        self.needle = self.query.to_lowercase();
    }

    /// Does this finding pass both narrowings?
    pub fn matches(&self, finding: &Finding) -> bool {
        if finding.severity < self.min_severity {
            return false;
        }
        if self.needle.is_empty() {
            return true;
        }
        let n = self.needle.as_str();
        contains(&finding.id, n)
            || contains(&finding.title, n)
            || contains(&finding.explanation, n)
            || finding
                .recommendation
                .as_deref()
                .is_some_and(|r| contains(r, n))
            || finding.instance.as_deref().is_some_and(|i| contains(i, n))
            || finding
                .evidence
                .iter()
                .any(|(key, value)| contains(key, n) || contains(value, n))
    }

    /// The filter in words, for the status line and the detail pane:
    /// `severity ≥ warning · search "ssh"`.
    pub fn describe(&self) -> String {
        let mut parts: Vec<String> = Vec::new();
        if self.min_severity > Severity::Info {
            parts.push(format!(
                "severity \u{2265} {}",
                severity_word(self.min_severity)
            ));
        }
        if !self.query.is_empty() {
            parts.push(format!("search \u{201c}{}\u{201d}", self.query));
        }
        parts.join(" \u{00b7} ")
    }
}

fn severity_word(severity: Severity) -> &'static str {
    match severity {
        Severity::Info => "info",
        Severity::Warning => "warning",
        Severity::Error => "error",
        Severity::Critical => "critical",
    }
}

/// `needle` is already lowercase.
fn contains(haystack: &str, needle: &str) -> bool {
    haystack.to_lowercase().contains(needle)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::{Category, Confidence};

    fn finding(id: &str, severity: Severity) -> Finding {
        Finding::builder(
            id,
            "Some Title",
            Category::Security,
            severity,
            Confidence::direct_observation(),
        )
        .build()
    }

    fn typed(text: &str) -> ViewFilter {
        let mut filter = ViewFilter::default();
        for c in text.chars() {
            assert!(filter.push_char(c), "{c:?} refused");
        }
        filter
    }

    #[test]
    fn nothing_is_hidden_by_default() {
        let filter = ViewFilter::default();
        assert!(!filter.is_active());
        assert!(filter.matches(&finding("A001", Severity::Info)));
        assert!(filter.matches(&finding("A002", Severity::Critical)));
        assert_eq!(filter.describe(), "");
    }

    #[test]
    fn the_severity_cycles_through_the_four_levels_and_comes_back() {
        let mut filter = ViewFilter::default();
        let mut seen = vec![filter.min_severity()];
        for _ in 0..4 {
            filter.cycle_severity();
            seen.push(filter.min_severity());
        }
        assert_eq!(
            seen,
            [
                Severity::Info,
                Severity::Warning,
                Severity::Error,
                Severity::Critical,
                Severity::Info
            ]
        );
        assert!(!filter.is_active(), "back to showing everything");
    }

    #[test]
    fn a_minimum_severity_hides_what_is_below_it_and_keeps_what_is_above() {
        let mut filter = ViewFilter::default();
        filter.cycle_severity(); // warning
        assert!(filter.is_active());
        assert!(!filter.matches(&finding("A001", Severity::Info)));
        assert!(filter.matches(&finding("A002", Severity::Warning)));
        assert!(filter.matches(&finding("A003", Severity::Error)));
        assert!(filter.matches(&finding("A004", Severity::Critical)));
        filter.cycle_severity(); // error
        assert!(!filter.matches(&finding("A002", Severity::Warning)));
        filter.cycle_severity(); // critical
        assert!(!filter.matches(&finding("A003", Severity::Error)));
        assert!(filter.matches(&finding("A004", Severity::Critical)));
    }

    #[test]
    fn the_text_is_looked_for_everywhere_a_person_would_look_and_ignores_case() {
        let f = Finding::builder(
            "SEC001",
            "Root Login Over SSH",
            Category::Security,
            Severity::Warning,
            Confidence::direct_observation(),
        )
        .evidence("permit_root_login", "Yes")
        .explanation("The daemon accepts passwords for root.")
        .recommendation("Set PermitRootLogin to no, then restart the service.")
        .instance("nginx.service")
        .build();

        for needle in [
            "sec001",      // id
            "root login",  // title
            "daemon",      // explanation
            "restart",     // recommendation
            "NGINX",       // instance
            "permit_root", // evidence key
            "yes",         // evidence value
        ] {
            assert!(typed(needle).matches(&f), "{needle:?} should be found");
        }
        assert!(!typed("postgres").matches(&f));
    }

    #[test]
    fn the_text_is_taken_as_typed_not_split_into_words() {
        let f = Finding::builder(
            "A001",
            "Swap Activity",
            Category::Memory,
            Severity::Info,
            Confidence::direct_observation(),
        )
        .build();
        assert!(typed("swap act").matches(&f));
        assert!(!typed("activity swap").matches(&f));
    }

    #[test]
    fn severity_and_text_must_both_hold() {
        let loud = Finding::builder(
            "A001",
            "Disk almost full",
            Category::Storage,
            Severity::Critical,
            Confidence::direct_observation(),
        )
        .build();
        let quiet = Finding::builder(
            "A002",
            "Disk layout",
            Category::Storage,
            Severity::Info,
            Confidence::direct_observation(),
        )
        .build();
        let mut filter = typed("disk");
        assert!(filter.matches(&loud) && filter.matches(&quiet));
        filter.cycle_severity();
        assert!(filter.matches(&loud));
        assert!(
            !filter.matches(&quiet),
            "matches the text, not the severity"
        );
        let mut other = typed("network");
        other.cycle_severity();
        assert!(!other.matches(&loud), "right severity, wrong text");
    }

    #[test]
    fn control_characters_are_refused_because_the_text_is_drawn_back() {
        let mut filter = ViewFilter::default();
        for c in ['\u{1b}', '\u{7}', '\n', '\t', '\u{9b}'] {
            assert!(!filter.push_char(c), "{c:?} accepted");
        }
        assert_eq!(filter.query(), "");
        assert!(!filter.is_active());
    }

    #[test]
    fn the_text_is_limited_in_characters_not_in_bytes() {
        let mut filter = ViewFilter::default();
        for _ in 0..MAX_QUERY_CHARS {
            assert!(filter.push_char('\u{e9}'), "two bytes, one character");
        }
        assert!(!filter.push_char('x'), "one past the limit");
        assert_eq!(filter.query().chars().count(), MAX_QUERY_CHARS);
        assert!(filter.pop_char());
        assert!(filter.push_char('x'), "room again after a deletion");
    }

    #[test]
    fn deleting_and_clearing_report_whether_anything_changed() {
        let mut filter = ViewFilter::default();
        assert!(!filter.pop_char());
        assert!(!filter.clear_query());
        let mut filter = typed("ab");
        assert!(filter.pop_char());
        assert_eq!(filter.query(), "a");
        filter.cycle_severity();
        assert!(filter.clear_query());
        assert_eq!(filter.query(), "");
        assert!(filter.is_active(), "the severity is kept");
        filter.clear();
        assert!(!filter.is_active());
    }

    #[test]
    fn the_filter_is_described_in_words() {
        let mut filter = typed("ssh");
        assert_eq!(filter.describe(), "search \u{201c}ssh\u{201d}");
        filter.cycle_severity();
        assert_eq!(
            filter.describe(),
            "severity \u{2265} warning \u{00b7} search \u{201c}ssh\u{201d}"
        );
        filter.clear_query();
        assert_eq!(filter.describe(), "severity \u{2265} warning");
    }

    #[test]
    fn emptying_the_text_after_typing_shows_everything_again() {
        let f = finding("A001", Severity::Info);
        let mut filter = typed("zzz");
        assert!(!filter.matches(&f));
        while filter.pop_char() {}
        assert!(filter.matches(&f), "the cached needle was emptied too");
    }
}
