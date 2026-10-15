// SPDX-License-Identifier: GPL-3.0-only

//! What has been complaining since the last boot: error-level messages
//! from the journal, grouped by the service or program that wrote them,
//! with the message each one repeats most.
//!
//! Pure functions over [`Entry`] values.

use std::collections::{BTreeMap, HashMap};

use crate::models::{Category, Confidence, Finding, Severity};
use crate::modules::recommend::Steps;

use super::journal::Entry;
use super::text::{clean, is_safe_word, normalize, table};

/// Errors from one service that make it worth a warning: a service that
/// logs this many errors since boot is failing, restarting in a loop or
/// stuck on something.
pub const NOISY_SERVICE: u32 = 50;
/// Errors in total that make the boot worth a warning.
pub const NOISY_TOTAL: u32 = 200;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ErrorGroup {
    /// The unit (`nginx.service`) or, failing that, the program name.
    pub name: String,
    pub count: u32,
    /// The most severe priority seen (0 is the most severe).
    pub worst_priority: u8,
    /// The message this group repeats most, as it was first written.
    pub example: String,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ErrorSummary {
    pub total: u32,
    /// Most noisy first.
    pub groups: Vec<ErrorGroup>,
    /// Messages at priority 2 (critical) or worse.
    pub critical: u32,
    /// Messages at priority 1 (alert) or 0 (emergency).
    pub alerts: u32,
}

#[derive(Default)]
struct Accumulator {
    count: u32,
    worst: u8,
    /// Normalised message -> (times seen, first original wording).
    messages: BTreeMap<String, (u32, String)>,
}

pub fn summarize(entries: &[Entry]) -> ErrorSummary {
    let mut groups: HashMap<String, Accumulator> = HashMap::new();
    let mut summary = ErrorSummary::default();
    for e in entries {
        let priority = e.priority.unwrap_or(3);
        summary.total += 1;
        if priority <= 2 {
            summary.critical += 1;
        }
        if priority <= 1 {
            summary.alerts += 1;
        }
        let name = e
            .unit
            .clone()
            .filter(|u| !u.is_empty())
            .or_else(|| Some(e.identifier.clone()).filter(|i| !i.is_empty()))
            .unwrap_or_else(|| "(unknown)".to_string());
        let acc = groups.entry(name).or_insert_with(|| Accumulator {
            worst: 7,
            ..Default::default()
        });
        acc.count += 1;
        acc.worst = acc.worst.min(priority);
        let slot = acc
            .messages
            .entry(normalize(&e.message))
            .or_insert_with(|| (0, e.message.clone()));
        slot.0 += 1;
    }
    summary.groups = groups
        .into_iter()
        .map(|(name, acc)| {
            // Most repeated wording; on a tie, the alphabetically first.
            let example = acc
                .messages
                .iter()
                .max_by(|a, b| a.1 .0.cmp(&b.1 .0).then_with(|| b.0.cmp(a.0)))
                .map(|(_, (_, original))| original.clone())
                .unwrap_or_default();
            ErrorGroup {
                name,
                count: acc.count,
                worst_priority: acc.worst,
                example,
            }
        })
        .collect();
    summary
        .groups
        .sort_by(|a, b| b.count.cmp(&a.count).then_with(|| a.name.cmp(&b.name)));
    summary
}

impl ErrorSummary {
    pub fn severity(&self) -> Severity {
        if self.alerts > 0 {
            Severity::Error
        } else if self.critical > 0
            || self.total >= NOISY_TOTAL
            || self
                .groups
                .first()
                .is_some_and(|g| g.count >= NOISY_SERVICE)
        {
            Severity::Warning
        } else {
            Severity::Info
        }
    }
}

/// LOG005 — errors since boot.
pub fn finding(summary: &ErrorSummary, source: &str, truncated: bool) -> Finding {
    let severity = summary.severity();
    let mut text = String::new();
    if summary.total == 0 {
        text.push_str("No error was logged since the last boot.");
    } else {
        text.push_str(&format!(
            "{} error message(s) since the last boot, from {} source(s).",
            summary.total,
            summary.groups.len()
        ));
        if summary.alerts > 0 {
            text.push_str(&format!(
                " {} of them are at the alert or emergency level, the most serious the \
                 system uses.",
                summary.alerts
            ));
        } else if summary.critical > 0 {
            text.push_str(&format!(
                " {} of them are at the critical level.",
                summary.critical
            ));
        }
        match severity {
            Severity::Info => text.push_str(
                " A handful of errors from a few sources is ordinary: hardware without a \
                 driver, a service that could not reach a server once. What matters is a \
                 source that keeps repeating.",
            ),
            _ => text.push_str(
                " A source that logs this many errors is failing, restarting in a loop or \
                 stuck on something; the table shows what it keeps saying.",
            ),
        }
    }
    if truncated {
        text.push_str(
            "\n\nThe journal holds more error messages than were read; the oldest were left \
             out, so the counts are a minimum.",
        );
    }
    if !summary.groups.is_empty() {
        let rows: Vec<Vec<String>> = summary
            .groups
            .iter()
            .take(10)
            .map(|g| vec![g.count.to_string(), g.name.clone(), clean(&g.example, 90)])
            .collect();
        text.push_str("\n\nNoisiest sources:\n");
        text.push_str(&table(
            &["Count", "Source", "Message it repeats most"],
            &rows,
        ));
        if summary.groups.len() > 10 {
            text.push_str(&format!(
                "\n\n... and {} more sources",
                summary.groups.len() - 10
            ));
        }
    }

    let mut builder = Finding::builder(
        "LOG005",
        "System Errors Since Boot",
        Category::Logs,
        severity,
        Confidence::direct_observation(),
    )
    .evidence("source", source)
    .evidence("errors", summary.total.to_string())
    .evidence("sources", summary.groups.len().to_string())
    .evidence("critical_or_worse", summary.critical.to_string());
    if let Some(top) = summary.groups.first() {
        builder = builder.evidence("noisiest_source", format!("{} ({})", top.name, top.count));
    }
    builder = builder.explanation(text);

    if severity >= Severity::Warning {
        let mut steps = Steps::new();
        if summary.critical > 0 {
            steps = steps.step(
                "Read the most serious messages first:",
                &["sudo journalctl -b -p crit --no-pager"],
            );
        }
        if let Some(top) = summary.groups.first() {
            if is_safe_word(&top.name) && top.name.contains('.') {
                steps = steps
                    .step(
                        format!("See everything {} reported, newest last:", top.name),
                        &[&format!(
                            "sudo journalctl -b -p err -u {} --no-pager | tail -40",
                            top.name
                        )],
                    )
                    .step(
                        "Check whether it is healthy now, and whether it keeps restarting:",
                        &[
                            &format!("systemctl status {}", top.name),
                            &format!("systemctl show {} -p NRestarts -p Result", top.name),
                        ],
                    );
            } else if is_safe_word(&top.name) {
                steps = steps.step(
                    format!("See everything {} reported, newest last:", top.name),
                    &[&format!(
                        "sudo journalctl -b -p err -t {} --no-pager | tail -40",
                        top.name
                    )],
                );
            } else {
                steps = steps.step(
                    "See the errors of the noisiest source, newest last:",
                    &["sudo journalctl -b -p err --no-pager | tail -60"],
                );
            }
        }
        steps = steps.step(
            "Once the cause is fixed, check that the errors stopped (the count should no \
             longer grow):",
            &["sudo journalctl -b -p err --no-pager | wc -l"],
        );
        builder = builder.recommendation(steps.build());
    }
    builder.build()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn err(unit: &str, message: &str) -> Entry {
        Entry::new("prog", message).with_priority(3).with_unit(unit)
    }

    #[test]
    fn an_empty_boot_is_a_quiet_info() {
        let s = summarize(&[]);
        assert_eq!(s.severity(), Severity::Info);
        let f = finding(&s, "journal", false);
        assert!(f.explanation.contains("No error was logged"));
        assert!(f.recommendation.is_none());
    }

    #[test]
    fn groups_by_unit_and_falls_back_to_the_program() {
        let entries = vec![
            err("a.service", "boom"),
            err("a.service", "boom"),
            err("b.service", "bang"),
            Entry::new("kernel", "ACPI error").with_priority(3),
            Entry::new("", "anonymous").with_priority(3),
        ];
        let s = summarize(&entries);
        assert_eq!(s.total, 5);
        let names: Vec<&str> = s.groups.iter().map(|g| g.name.as_str()).collect();
        assert_eq!(names[0], "a.service");
        assert!(names.contains(&"kernel") && names.contains(&"(unknown)"));
    }

    #[test]
    fn messages_that_differ_by_numbers_count_as_one() {
        let entries: Vec<Entry> = (1..=5)
            .map(|i| err("a.service", &format!("connection {i} lost after {}0 ms", i)))
            .chain([err("a.service", "other")])
            .collect();
        let g = &summarize(&entries).groups[0];
        assert_eq!(g.count, 6);
        assert!(g.example.starts_with("connection 1 lost"), "{}", g.example);
    }

    #[test]
    fn a_few_errors_are_only_information() {
        let entries: Vec<Entry> = (0..10).map(|_| err("a.service", "boom")).collect();
        assert_eq!(summarize(&entries).severity(), Severity::Info);
    }

    #[test]
    fn one_noisy_service_is_a_warning() {
        let entries: Vec<Entry> = (0..NOISY_SERVICE)
            .map(|_| err("a.service", "boom"))
            .collect();
        let s = summarize(&entries);
        assert_eq!(s.severity(), Severity::Warning);
        let rec = finding(&s, "journal", false).recommendation.unwrap();
        assert!(rec.starts_with("1. "));
        assert!(rec.contains("journalctl -b -p err -u a.service"));
        assert!(rec.contains("systemctl status a.service"));
    }

    #[test]
    fn many_sources_adding_up_is_a_warning() {
        let entries: Vec<Entry> = (0..NOISY_TOTAL)
            .map(|i| err(&format!("s{}.service", i % 40), "boom"))
            .collect();
        let s = summarize(&entries);
        assert!(s.groups[0].count < NOISY_SERVICE);
        assert_eq!(s.severity(), Severity::Warning);
    }

    #[test]
    fn critical_and_alert_messages_raise_the_severity() {
        let crit = [Entry::new("x", "bad").with_priority(2)];
        let s = summarize(&crit);
        assert_eq!(s.severity(), Severity::Warning);
        assert!(finding(&s, "journal", false)
            .recommendation
            .unwrap()
            .contains("journalctl -b -p crit"));
        let alert = [Entry::new("x", "worse").with_priority(1)];
        assert_eq!(summarize(&alert).severity(), Severity::Error);
    }

    #[test]
    fn a_source_name_that_is_not_a_plain_word_stays_out_of_commands() {
        let entries: Vec<Entry> = (0..NOISY_SERVICE)
            .map(|_| Entry::new("a; reboot", "boom").with_priority(3))
            .collect();
        let rec = finding(&summarize(&entries), "journal", false)
            .recommendation
            .unwrap();
        assert!(!rec.contains("reboot"));
        assert!(rec.contains("sudo journalctl -b -p err --no-pager | tail -60"));
    }

    #[test]
    fn a_program_without_a_unit_is_looked_up_by_identifier() {
        let entries: Vec<Entry> = (0..NOISY_SERVICE)
            .map(|_| Entry::new("myapp", "boom").with_priority(3))
            .collect();
        let rec = finding(&summarize(&entries), "journal", false)
            .recommendation
            .unwrap();
        assert!(rec.contains("journalctl -b -p err -t myapp"));
    }

    #[test]
    fn the_table_lists_the_noisiest_ten_and_says_how_many_more() {
        let entries: Vec<Entry> = (0..15)
            .map(|i| err(&format!("s{i:02}.service"), "boom"))
            .collect();
        let f = finding(&summarize(&entries), "journal", false);
        assert!(f.explanation.contains("Noisiest sources:"));
        assert!(f.explanation.contains("... and 5 more sources"));
    }

    #[test]
    fn truncation_is_disclosed() {
        let f = finding(&summarize(&[err("a.service", "x")]), "journal", true);
        assert!(f.explanation.contains("a minimum"));
    }
}
