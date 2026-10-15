// SPDX-License-Identifier: GPL-3.0-only

//! Puts the topics together: runs each one's analysis, builds the overview
//! (including what could not be read) and orders the findings the way the
//! module is read.

use std::cmp::Reverse;

use crate::core::context::Context;
use crate::models::{Category, Confidence, Finding, Severity};
use crate::modules::recommend::{family_of, Steps};

use super::auth::{self, AuthSummary, WINDOW_HOURS};
use super::collect::{Gap, LogsRawData, Source};
use super::errors::{self, ErrorSummary};
use super::health::{self, JournalInfo, LogFiles, Storage};
use super::kernel::{self, KernelSummary, Kind};
use super::text::{human_size, table};

/// The pages of the module's submenu, in the order they are shown.
pub const TOPICS: [&str; 4] = [
    "Authentication",
    "System errors",
    "Kernel messages",
    "Journal & log files",
];

/// Order of the findings within a page (also the tie-break between equal
/// severities): a suspected break-in before anything else.
const ORDER: [&str; 9] = [
    "LOG001", "LOG003", "LOG002", "LOG004", "LOG005", "LOG006", "LOG007", "LOG008", "LOG009",
];

fn topic_of(id: &str) -> Option<&'static str> {
    match id {
        "LOG002" | "LOG003" | "LOG004" => Some(TOPICS[0]),
        "LOG005" => Some(TOPICS[1]),
        "LOG006" | "LOG007" => Some(TOPICS[2]),
        "LOG008" | "LOG009" => Some(TOPICS[3]),
        _ => None,
    }
}

fn topic_rank(topic: &str) -> usize {
    TOPICS
        .iter()
        .position(|t| *t == topic)
        .unwrap_or(TOPICS.len())
}

fn order_rank(id: &str) -> usize {
    ORDER.iter().position(|o| *o == id).unwrap_or(ORDER.len())
}

/// Pure function: RawData -> Findings. No I/O — see ARCHITECTURE.md
/// "Testing Strategy".
///
/// Layout of the result: the top page first — the overview and anything of
/// Warning severity or above, worst first, so a problem is never buried in
/// a submenu — then the remaining findings grouped by topic.
pub fn analyze(data: &LogsRawData, ctx: &Context) -> Vec<Finding> {
    let family = family_of(ctx.distro.as_deref());
    let mut findings: Vec<Finding> = Vec::new();
    let mut lines = OverviewLines::default();

    match &data.auth {
        Some(source) => {
            let summary = auth::summarize(&source.entries);
            lines.authentication = authentication_line(&summary);
            findings.push(auth::activity_finding(
                &summary,
                &source.name,
                source.truncated,
                family,
            ));
            findings.extend(auth::break_in_findings(&summary, family));
            findings.push(auth::local_finding(&summary, family));
        }
        None => lines.authentication = "not readable".to_string(),
    }

    match &data.errors {
        Some(source) => {
            let summary = errors::summarize(&source.entries);
            lines.errors = errors_line(&summary);
            findings.push(errors::finding(&summary, &source.name, source.truncated));
        }
        None => lines.errors = "not readable".to_string(),
    }

    match &data.kernel {
        Some(source) => {
            let summary = kernel::summarize(&source.entries);
            lines.kernel = kernel_line(&summary);
            findings.push(kernel::hardware_finding(&summary, &source.name));
            findings.push(kernel::crash_finding(&summary, &source.name));
        }
        None => lines.kernel = "not readable".to_string(),
    }

    lines.journal = journal_line(&data.journal);
    findings.push(health::journal_finding(&data.journal));
    lines.files = files_line(&data.files);
    findings.push(health::files_finding(&data.files, family));

    lines.sources = sources_line(data);
    findings.insert(0, overview_finding(&findings, &lines, data));

    for f in &mut findings {
        f.instance = if f.id == "LOG001" || f.severity >= Severity::Warning {
            None
        } else {
            topic_of(&f.id).map(str::to_string)
        };
    }
    findings.sort_by_key(|f| {
        (
            f.instance.is_some(),
            f.instance.as_deref().map(topic_rank).unwrap_or(0),
            f.id != "LOG001", // the overview leads its page
            Reverse(f.severity),
            order_rank(&f.id),
        )
    });
    findings
}

// ---------------------------------------------------------------------------
// Overview
// ---------------------------------------------------------------------------

#[derive(Default)]
struct OverviewLines {
    sources: String,
    authentication: String,
    errors: String,
    kernel: String,
    journal: String,
    files: String,
}

fn authentication_line(s: &AuthSummary) -> String {
    let suspicious = s.suspicious_logins().len();
    let verdict = if suspicious > 0 {
        format!("{suspicious} suspicious login(s)")
    } else {
        "no suspicious login".to_string()
    };
    format!(
        "{} failed SSH attempt(s) from {} address(es), {} successful login(s), {verdict}",
        s.attempts,
        s.sources.len(),
        s.logins.len()
    )
}

fn errors_line(s: &ErrorSummary) -> String {
    if s.total == 0 {
        return "no error since boot".to_string();
    }
    format!("{} error(s) from {} source(s)", s.total, s.groups.len())
}

fn kernel_line(s: &KernelSummary) -> String {
    let mut problems: Vec<&str> = s
        .kinds
        .keys()
        .filter(|k| **k != Kind::PcieCorrected)
        .map(|k| k.label())
        .collect();
    if problems.is_empty() {
        return "no storage, hardware or crash message".to_string();
    }
    problems.truncate(3);
    problems.join(", ").to_lowercase()
}

fn journal_line(j: &JournalInfo) -> String {
    let storage = match j.storage {
        Storage::Persistent => "kept across reboots",
        Storage::Volatile => "in memory only",
        Storage::Absent => "no systemd journal",
    };
    match j.size_bytes {
        Some(size) => format!("{storage}, {}", human_size(size)),
        None => storage.to_string(),
    }
}

fn files_line(f: &LogFiles) -> String {
    if !f.scanned {
        return "/var/log not readable".to_string();
    }
    match f.largest.first() {
        Some(biggest) => format!(
            "{} in /var/log, largest file {}",
            human_size(f.total_bytes),
            human_size(biggest.size)
        ),
        None => format!("{} in /var/log", human_size(f.total_bytes)),
    }
}

fn sources_line(data: &LogsRawData) -> String {
    let name = |s: &Option<Source>| {
        s.as_ref()
            .map(|s| s.name.clone())
            .unwrap_or_else(|| "none".to_string())
    };
    format!(
        "authentication: {}; errors: {}; kernel: {}",
        name(&data.auth),
        name(&data.errors),
        name(&data.kernel)
    )
}

/// LOG001 — the top page: one line per area, which findings need
/// attention, and what could not be read.
fn overview_finding(findings: &[Finding], lines: &OverviewLines, data: &LogsRawData) -> Finding {
    let mut attention: Vec<&Finding> = findings
        .iter()
        .filter(|f| f.severity >= Severity::Warning)
        .collect();
    attention.sort_by_key(|f| Reverse(f.severity));

    let mut text = String::new();
    if attention.is_empty() {
        text.push_str(
            "Nothing needs attention in the logs that could be read: no suspicious login, no \
             flood of errors, no storage or hardware error, no crash, and no log growing out \
             of control.",
        );
        if !data.gaps.is_empty() {
            text.push_str(" Some logs could not be read, though — see below.");
        }
    } else {
        text.push_str(&format!(
            "{} finding(s) need attention, worst first:\n",
            attention.len()
        ));
        for f in attention.iter().take(8) {
            text.push_str(&format!(
                "\n  [{}] {}",
                f.severity.to_string().to_uppercase(),
                f.title
            ));
        }
        if attention.len() > 8 {
            text.push_str(&format!("\n  ... and {} more", attention.len() - 8));
        }
    }
    text.push_str(&format!(
        "\n\nLogins are examined over the last {WINDOW_HOURS} hours; errors and kernel messages \
         over the time since the last boot. Older history is not looked at. Every check is \
         read-only: LinuxDoctor reads logs, it never rotates, cleans or changes them."
    ));

    let readable_gaps: Vec<&Gap> = data.gaps.iter().collect();
    if !readable_gaps.is_empty() {
        let rows: Vec<Vec<String>> = readable_gaps
            .iter()
            .map(|g| vec![g.what.clone(), g.why.clone()])
            .collect();
        text.push_str(
            "\n\nSome logs could not be read, so the report says nothing about them — a \
             quiet result for these is not a clean one:\n",
        );
        text.push_str(&table(&["Not readable", "Why"], &rows));
    }

    let mut builder = Finding::builder(
        "LOG001",
        "Logs Overview",
        Category::Logs,
        Severity::Info,
        Confidence::direct_observation(),
    )
    .evidence(
        "running_as",
        if data.is_root {
            "root"
        } else {
            "unprivileged user"
        },
    )
    .evidence("sources", lines.sources.clone())
    .evidence("authentication", lines.authentication.clone())
    .evidence("system_errors", lines.errors.clone())
    .evidence("kernel_messages", lines.kernel.clone())
    .evidence("journal", lines.journal.clone())
    .evidence("log_files", lines.files.clone());
    if !data.gaps.is_empty() {
        builder = builder.evidence(
            "not_readable",
            data.gaps
                .iter()
                .map(|g| g.what.as_str())
                .collect::<Vec<_>>()
                .join(", "),
        );
    }
    builder = builder.explanation(text);

    if data.gaps.iter().any(|g| g.group_fixes_it) && !data.is_root {
        builder = builder.recommendation(
            Steps::new()
                .step(
                    "Let your account read the logs. Log out and back in afterwards for the \
                     groups to apply:",
                    &["sudo usermod -aG adm,systemd-journal $USER"],
                )
                .step(
                    "Or run this audit with sudo, which sees everything without changing \
                     your account:",
                    &["sudo linuxdoctor audit --modules logs"],
                )
                .build(),
        );
    }
    builder.build()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::modules::logs::collect::Gap;
    use crate::modules::logs::health::{LogFile, LogFiles};
    use crate::modules::logs::journal::Entry;

    fn ctx() -> Context {
        Context {
            hostname: "test".into(),
            kernel_version: "6.8".into(),
            distro: Some("Debian GNU/Linux 12".into()),
            architecture: "x86_64".into(),
            cpu_count: 4,
            mem_total_kb: 16_000_000,
            boot_time_unix: 0,
        }
    }

    fn source(name: &str, entries: Vec<Entry>) -> Option<Source> {
        Some(Source {
            name: name.into(),
            entries,
            truncated: false,
        })
    }

    fn failed(ip: &str, port: u16) -> Entry {
        Entry::new(
            "sshd",
            &format!("Failed password for root from {ip} port {port} ssh2"),
        )
    }

    fn healthy() -> LogsRawData {
        LogsRawData {
            is_root: true,
            auth: source(
                "systemd journal",
                vec![
                    failed("203.0.113.7", 1),
                    Entry::new(
                        "sshd",
                        "Accepted publickey for bob from 192.0.2.9 port 22 ssh2: ED25519 SHA256:x",
                    ),
                ],
            ),
            errors: source(
                "systemd journal",
                vec![Entry::new("x", "boom").with_priority(3)],
            ),
            kernel: source(
                "systemd journal",
                vec![Entry::new("kernel", "Linux version 6.8")],
            ),
            journal: JournalInfo {
                storage: Storage::Persistent,
                size_bytes: Some(200 * 1024 * 1024),
                ..Default::default()
            },
            files: LogFiles {
                scanned: true,
                total_bytes: 50 * 1024 * 1024,
                largest: vec![LogFile {
                    path: "/var/log/syslog".into(),
                    size: 20 * 1024 * 1024,
                }],
                unreadable_dirs: 0,
                logrotate_installed: true,
            },
            gaps: Vec::new(),
        }
    }

    fn attacked() -> LogsRawData {
        let mut data = healthy();
        let mut entries: Vec<Entry> = (0..30).map(|i| failed("203.0.113.7", 1000 + i)).collect();
        entries.push(Entry::new(
            "sshd",
            "Accepted password for deploy from 203.0.113.7 port 40000 ssh2",
        ));
        data.auth = source("systemd journal", entries);
        data.kernel = source(
            "systemd journal",
            vec![Entry::new(
                "kernel",
                "EXT4-fs (sda1): Remounting filesystem read-only",
            )],
        );
        data
    }

    #[test]
    fn a_healthy_machine_has_nothing_above_info() {
        let findings = analyze(&healthy(), &ctx());
        assert!(
            findings.iter().all(|f| f.severity == Severity::Info),
            "{:?}",
            findings
                .iter()
                .map(|f| (&f.id, f.severity))
                .collect::<Vec<_>>()
        );
        assert_eq!(findings[0].id, "LOG001");
        assert!(findings[0].explanation.contains("Nothing needs attention"));
        assert!(
            findings
                .iter()
                .all(|f| f.id == "LOG001" || f.instance.is_some()),
            "everything else goes to a submenu"
        );
    }

    #[test]
    fn every_finding_id_is_present_on_a_machine_that_can_read_everything() {
        let mut ids: Vec<String> = analyze(&healthy(), &ctx())
            .iter()
            .map(|f| f.id.clone())
            .collect();
        ids.sort();
        assert_eq!(
            ids,
            ["LOG001", "LOG002", "LOG004", "LOG005", "LOG006", "LOG007", "LOG008", "LOG009"]
        );
    }

    #[test]
    fn problems_lead_the_top_page_worst_first() {
        let findings = analyze(&attacked(), &ctx());
        assert_eq!(findings[0].id, "LOG001");
        let top: Vec<(&str, Severity)> = findings
            .iter()
            .take_while(|f| f.instance.is_none())
            .map(|f| (f.id.as_str(), f.severity))
            .collect();
        assert_eq!(
            top,
            vec![
                ("LOG001", Severity::Info),
                ("LOG003", Severity::Critical), // a suspected break-in first
                ("LOG006", Severity::Critical),
                ("LOG002", Severity::Warning),
            ],
            "{top:?}"
        );
        assert!(findings[0]
            .explanation
            .contains("3 finding(s) need attention"));
        assert!(findings[0]
            .explanation
            .contains("[CRITICAL] Possible Break-in"));
        // What is left is grouped by topic.
        let rest: Vec<&Finding> = findings.iter().skip(top.len()).collect();
        assert!(rest.iter().all(|f| f.instance.is_some()));
        let ranks: Vec<usize> = rest
            .iter()
            .map(|f| topic_rank(f.instance.as_deref().unwrap()))
            .collect();
        assert!(ranks.windows(2).all(|w| w[0] <= w[1]), "{ranks:?}");
    }

    #[test]
    fn every_problem_comes_with_numbered_steps() {
        for f in analyze(&attacked(), &ctx()) {
            if f.severity >= Severity::Warning {
                let rec = f
                    .recommendation
                    .as_ref()
                    .unwrap_or_else(|| panic!("{} has none", f.id));
                assert!(rec.starts_with("1. "), "{}: {rec}", f.id);
            }
        }
    }

    #[test]
    fn the_overview_has_one_line_per_area() {
        let f = &analyze(&attacked(), &ctx())[0];
        let keys: Vec<&str> = f.evidence.iter().map(|(k, _)| k.as_str()).collect();
        assert_eq!(
            keys,
            [
                "running_as",
                "sources",
                "authentication",
                "system_errors",
                "kernel_messages",
                "journal",
                "log_files"
            ]
        );
        let get = |k: &str| &f.evidence.iter().find(|(key, _)| key == k).unwrap().1;
        assert!(get("authentication").contains("30 failed SSH attempt(s) from 1 address(es)"));
        assert!(get("authentication").contains("1 suspicious login(s)"));
        assert!(get("kernel_messages").contains("filesystem switched to read-only"));
        assert_eq!(get("running_as"), "root");
    }

    #[test]
    fn what_could_not_be_read_is_said_loudly_with_the_way_to_fix_it() {
        let data = LogsRawData {
            is_root: false,
            gaps: vec![
                Gap {
                    what: "systemd journal".into(),
                    why: "the journal exists but this user may not read it".into(),
                    group_fixes_it: true,
                },
                Gap {
                    what: "kernel messages".into(),
                    why: "dmesg: Operation not permitted".into(),
                    group_fixes_it: false,
                },
            ],
            ..Default::default()
        };
        let findings = analyze(&data, &ctx());
        let ids: Vec<&str> = findings.iter().map(|f| f.id.as_str()).collect();
        assert_eq!(ids[0], "LOG001");
        assert!(ids.contains(&"LOG008") && ids.contains(&"LOG009"));
        assert!(!ids.contains(&"LOG002") && !ids.contains(&"LOG005") && !ids.contains(&"LOG006"));
        let o = &findings[0];
        assert!(o
            .explanation
            .contains("a quiet result for these is not a clean one"));
        assert!(o.explanation.contains("dmesg: Operation not permitted"));
        let rec = o.recommendation.as_ref().unwrap();
        assert!(rec.contains("sudo usermod -aG adm,systemd-journal $USER"));
        assert!(rec.contains("sudo linuxdoctor audit --modules logs"));
        assert!(o
            .evidence
            .iter()
            .any(|(k, v)| k == "not_readable" && v.contains("kernel messages")));
        assert!(o
            .evidence
            .iter()
            .any(|(k, v)| k == "authentication" && v == "not readable"));
    }

    #[test]
    fn root_is_never_told_to_join_a_group() {
        let data = LogsRawData {
            is_root: true,
            gaps: vec![Gap {
                what: "systemd journal".into(),
                why: "journalctl is not installed".into(),
                group_fixes_it: true,
            }],
            ..Default::default()
        };
        assert!(analyze(&data, &ctx())[0].recommendation.is_none());
    }

    #[test]
    fn empty_raw_data_is_coherent() {
        let findings = analyze(&LogsRawData::default(), &ctx());
        assert_eq!(findings[0].id, "LOG001");
        assert!(findings.iter().all(|f| f.category == Category::Logs));
        assert!(findings.iter().all(|f| f.confidence.percent >= 60));
    }

    #[test]
    fn no_template_placeholder_leaks_into_the_text() {
        for data in [healthy(), attacked(), LogsRawData::default()] {
            for f in analyze(&data, &ctx()) {
                let text = format!(
                    "{} {} {}",
                    f.title,
                    f.explanation,
                    f.recommendation.clone().unwrap_or_default()
                );
                for bad in ["{}", "{:", "TODO", "None", "Some("] {
                    assert!(!text.contains(bad), "{}: {bad}", f.id);
                }
            }
        }
    }
}
