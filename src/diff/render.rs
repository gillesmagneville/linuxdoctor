// SPDX-License-Identifier: GPL-3.0-only

//! Turning a [`Comparison`] into text: terminal, Markdown or JSON.
//!
//! Like the report renderers, these only lay out what the comparison already
//! decided. One thing is different: a comparison reads *files*, possibly
//! written on another machine, so every string that comes out of them (finding
//! titles, instances, evidence, error messages, even the host name) is
//! untrusted. The terminal text strips control characters from all of it
//! (a hostile file must not be able to send escape sequences to your
//! terminal), and the Markdown text escapes it like the audit's own Markdown
//! report does. JSON escapes everything by construction.

use serde::Serialize;

use crate::core::text::clean;
use crate::models::Severity;
use crate::output::common::format_utc;
use crate::output::markdown::{code_span, escape_text};

use super::compare::{
    Availability, Caveat, Change, ChangeKind, Comparison, FactChange, Incomplete, MachineFacts,
    NotCompared, Section, Side,
};

/// Version of the `--output json` layout of `linuxdoctor diff`, in the
/// document's `schema_version` field. Same rule as the audit report's:
/// adding a field never changes it; removing, renaming or re-typing one does.
pub const COMPARISON_SCHEMA_VERSION: u32 = 1;

/// What the two reports are called in the output: the paths the user typed,
/// and the version of LinuxDoctor that wrote each, when the report says.
pub struct Labels<'a> {
    pub before: &'a str,
    pub after: &'a str,
    /// `None` for a report written by a version that did not record it.
    pub before_version: Option<&'a str>,
    pub after_version: Option<&'a str>,
}

/// Who wrote a report, as one phrase. The version comes from a file, so it
/// is untrusted text.
fn written_by(version: Option<&str>) -> String {
    match version {
        Some(version) => format!("LinuxDoctor {}", clean(version, MAX_NAME)),
        None => "LinuxDoctor version not recorded".to_string(),
    }
}

const RESET: &str = "\x1b[0m";
const DIM: &str = "\x1b[2m";
const BOLD: &str = "\x1b[1m";
const GREEN: &str = "\x1b[32m";

/// Longest text kept from a title or message, from a name, and from a value.
const MAX_TEXT: usize = 160;
const MAX_NAME: usize = 64;
const MAX_VALUE: usize = 96;
const MAX_ID: usize = 24;
/// Evidence lines shown under one change before "… and N more".
const MAX_EVIDENCE_LINES: usize = 6;

const SECTIONS: [Section; 3] = [Section::Worse, Section::Better, Section::Other];

fn word(severity: Severity) -> String {
    severity.to_string().to_lowercase()
}

fn plural(n: usize, one: &str, many: &str) -> String {
    format!("{n} {}", if n == 1 { one } else { many })
}

/// "warning → error", "new (warning)", "resolved (was error)", with a `?`
/// when incomplete data makes the change uncertain.
fn status(change: &Change) -> String {
    let base = match change.kind {
        ChangeKind::New => format!("new ({})", word(change.severity())),
        ChangeKind::Resolved => format!("resolved (was {})", word(change.severity())),
        ChangeKind::Worse | ChangeKind::Better => format!(
            "{} → {}",
            word(change.before.unwrap_or(Severity::Info)),
            word(change.after.unwrap_or(Severity::Info))
        ),
    };
    if change.doubt.is_some() {
        format!("{base} ?")
    } else {
        base
    }
}

/// The finding's title, followed by its instance unless the title already
/// names it.
fn subject(change: &Change) -> String {
    let title = clean(&change.title, MAX_TEXT);
    match &change.instance {
        Some(instance) if !change.title.contains(instance.as_str()) => {
            format!("{title} [{}]", clean(instance, MAX_NAME))
        }
        _ => title,
    }
}

fn machine_line(machine: &MachineFacts) -> String {
    let mut parts = vec![
        clean(&machine.hostname, MAX_NAME),
        machine
            .distro
            .as_deref()
            .map(|d| clean(d, MAX_NAME))
            .unwrap_or_else(|| "unknown distribution".to_string()),
        format!("kernel {}", clean(&machine.kernel_version, MAX_NAME)),
    ];
    if machine.boot_time_unix != 0 {
        parts.push(format!("booted {}", format_utc(machine.boot_time_unix)));
    }
    parts.join(" · ")
}

fn availability(state: &Availability) -> String {
    match state {
        Availability::Ran => "ran".to_string(),
        Availability::Skipped => "skipped".to_string(),
        Availability::Failed { error } => format!("failed ({})", clean(error, MAX_TEXT)),
        Availability::Missing => "not in the report".to_string(),
    }
}

/// Why a module's findings could not be compared, in a sentence.
fn not_compared_detail(n: &NotCompared) -> Option<String> {
    if n.before == Availability::Ran && n.findings_before > 0 {
        Some(format!(
            "{} in the first report could not be re-checked",
            plural(n.findings_before, "finding", "findings")
        ))
    } else if n.after == Availability::Ran && n.findings_after > 0 {
        Some(format!(
            "{} in the second report have nothing to be compared with",
            plural(n.findings_after, "finding", "findings")
        ))
    } else {
        None
    }
}

fn caveat_text(caveat: &Caveat) -> String {
    match caveat {
        Caveat::DifferentMachines { before, after } => format!(
            "These reports describe different machines ({} and {}): a difference may \
             come from the machines, not from something that changed on one of them.",
            clean(before, MAX_NAME),
            clean(after, MAX_NAME)
        ),
        Caveat::ReportsLookReversed => "The second report was taken during an earlier boot than \
             the first: they may have been given in the wrong order (the earlier report comes first)."
            .to_string(),
        Caveat::Filtered {
            floor,
            before,
            after,
        } => {
            let which = match (before.is_some(), after.is_some()) {
                (true, true) => "Both reports were",
                (true, false) => "The first report was",
                _ => "The second report was",
            };
            format!(
                "{which} written with --min-severity: only findings at {} or above \
                 were compared.",
                word(*floor)
            )
        }
        Caveat::DifferentVersions { before, after } => {
            // From files: untrusted text, like the host names above.
            let name = |version: &Option<String>| match version {
                Some(version) => clean(version, MAX_NAME),
                None => "not recorded".to_string(),
            };
            format!(
                "These reports were written by different versions of LinuxDoctor ({} and {}): \
                 checks are added and thresholds change between versions, so a finding that \
                 appeared or disappeared may come from the program, not from the machine.",
                name(before),
                name(after)
            )
        }
    }
}

fn section_title(section: Section) -> &'static str {
    match section {
        Section::Worse => "Got worse",
        Section::Better => "Got better",
        Section::Other => "Other changes",
    }
}

fn side_label(side: Side) -> &'static str {
    match side {
        Side::Before => "first report",
        Side::After => "second report",
    }
}

/// Every note of every compared module, with the module and the side.
fn incomplete_notes(c: &Comparison) -> Vec<(&str, &Incomplete)> {
    c.compared
        .iter()
        .flat_map(|m| m.incomplete.iter().map(move |i| (m.module_id.as_str(), i)))
        .collect()
}

fn terminal_value(value: &Option<String>) -> String {
    match value {
        Some(v) => clean(v, MAX_VALUE),
        None => "(absent)".to_string(),
    }
}

// ---------------------------------------------------------------------------
// Terminal
// ---------------------------------------------------------------------------

pub fn terminal(c: &Comparison, labels: &Labels) -> String {
    let warning = Severity::Warning.ansi_color();
    let mut out = String::new();
    out.push_str(&format!(
        "{BOLD}LinuxDoctor {}{RESET} — report comparison\n\n",
        crate::VERSION
    ));
    for (name, label, version, machine) in [
        ("before", labels.before, labels.before_version, &c.before),
        ("after", labels.after, labels.after_version, &c.after),
    ] {
        out.push_str(&format!(
            "  {name:<7} {} {DIM}({}){RESET}\n          {DIM}{}{RESET}\n",
            clean(label, MAX_TEXT),
            written_by(version),
            machine_line(machine)
        ));
    }
    out.push('\n');

    if !c.machine_changes.is_empty() {
        out.push_str(&format!("{BOLD}Machine changes{RESET}\n"));
        for fact in &c.machine_changes {
            out.push_str(&format!(
                "  {:<14}{} → {}\n",
                fact.fact,
                clean(&fact.before, MAX_TEXT),
                clean(&fact.after, MAX_TEXT)
            ));
        }
        out.push('\n');
    }

    for caveat in &c.caveats {
        out.push_str(&format!(
            "{warning}\u{26a0} {}{RESET}\n",
            caveat_text(caveat)
        ));
    }
    if !c.caveats.is_empty() {
        out.push('\n');
    }

    let counts: Vec<usize> = SECTIONS.iter().map(|&s| c.changes_in(s).len()).collect();
    let totals = c.totals();
    out.push_str(&format!(
        "{BOLD}Summary{RESET}  {} got worse · {} got better · {} other · {} unchanged",
        counts[0], counts[1], counts[2], totals.unchanged
    ));
    if totals.not_compared > 0 {
        out.push_str(&format!(
            " · {} not compared",
            plural(totals.not_compared, "module", "modules")
        ));
    }
    out.push_str("\n\n");

    for (&section, &count) in SECTIONS.iter().zip(&counts) {
        if count == 0 {
            continue;
        }
        out.push_str(&format!(
            "{BOLD}{} ({count}){RESET}\n",
            section_title(section)
        ));
        for change in c.changes_in(section) {
            let color = match section {
                Section::Worse => change.severity().ansi_color(),
                Section::Better => GREEN,
                Section::Other => DIM,
            };
            out.push_str(&format!(
                "  {color}{:<26}{RESET} {:<14} {:<8} {}\n",
                status(change),
                clean(&change.module_id, MAX_ID),
                clean(&change.id, MAX_NAME),
                subject(change)
            ));
            for e in change.evidence.iter().take(MAX_EVIDENCE_LINES) {
                out.push_str(&format!(
                    "      {DIM}{}: {} → {}{RESET}\n",
                    clean(&e.key, MAX_NAME),
                    terminal_value(&e.before),
                    terminal_value(&e.after)
                ));
            }
            if change.evidence.len() > MAX_EVIDENCE_LINES {
                out.push_str(&format!(
                    "      {DIM}… and {} more{RESET}\n",
                    change.evidence.len() - MAX_EVIDENCE_LINES
                ));
            }
        }
        out.push('\n');
    }

    if counts.iter().all(|&n| n == 0) && c.hidden == 0 {
        out.push_str(&format!(
            "No change in the {} that could be compared.\n\n",
            plural(totals.unchanged, "finding", "findings")
        ));
    }
    if let (true, Some(min)) = (c.hidden > 0, c.hidden_below) {
        out.push_str(&format!(
            "{DIM}{} below {} hidden (--min-severity {}){RESET}\n\n",
            plural(c.hidden, "change", "changes"),
            word(min),
            word(min)
        ));
    }

    let incomplete = incomplete_notes(c);
    if !incomplete.is_empty() {
        out.push_str(&format!("{BOLD}Incomplete data{RESET}\n"));
        for (module, report) in incomplete {
            for note in &report.notes {
                out.push_str(&format!(
                    "  {warning}\u{26a0}{RESET} {} ({}): {}\n",
                    clean(module, MAX_ID),
                    side_label(report.side),
                    clean(note, MAX_TEXT)
                ));
            }
        }
        out.push_str(&format!(
            "  {DIM}A change marked ? involves one of these modules and may not be real.{RESET}\n\n"
        ));
    }

    if !c.not_compared.is_empty() {
        out.push_str(&format!(
            "{BOLD}Not compared ({}){RESET}\n",
            c.not_compared.len()
        ));
        for n in &c.not_compared {
            out.push_str(&format!(
                "  {warning}\u{26a0}{RESET} {:<14} first report: {} · second report: {}\n",
                clean(&n.module_id, MAX_ID),
                availability(&n.before),
                availability(&n.after)
            ));
            if let Some(detail) = not_compared_detail(n) {
                out.push_str(&format!("      {DIM}{detail}{RESET}\n"));
            }
        }
        out.push('\n');
    }

    if !c.skipped_in_both.is_empty() {
        let names: Vec<String> = c.skipped_in_both.iter().map(|m| clean(m, MAX_ID)).collect();
        out.push_str(&format!(
            "{DIM}Skipped in both reports: {}{RESET}\n",
            names.join(", ")
        ));
    }
    out
}

// ---------------------------------------------------------------------------
// Markdown
// ---------------------------------------------------------------------------

fn markdown_value(value: &Option<String>) -> String {
    match value {
        Some(v) => code_span(&clean(v, MAX_VALUE)),
        None => "*(absent)*".to_string(),
    }
}

/// Text for a table cell: escaped like prose, and the pipe cannot end the cell.
fn cell(text: &str) -> String {
    escape_text(text).replace('|', "\\|")
}

pub fn markdown(c: &Comparison, labels: &Labels) -> String {
    let mut out = String::from("# LinuxDoctor report comparison\n\n");
    out.push_str(&format!(
        "Compared with LinuxDoctor {}.\n\n",
        crate::VERSION
    ));
    out.push_str("| | Report | Written by | Machine |\n|---|---|---|---|\n");
    for (name, label, version, machine) in [
        ("before", labels.before, labels.before_version, &c.before),
        ("after", labels.after, labels.after_version, &c.after),
    ] {
        out.push_str(&format!(
            "| **{name}** | {} | {} | {} |\n",
            cell(&clean(label, MAX_TEXT)),
            cell(&written_by(version)),
            cell(&machine_line(machine))
        ));
    }
    out.push('\n');

    if !c.machine_changes.is_empty() {
        out.push_str("## Machine changes\n\n");
        for fact in &c.machine_changes {
            out.push_str(&format!(
                "- **{}**: {} → {}\n",
                fact.fact,
                code_span(&clean(&fact.before, MAX_TEXT)),
                code_span(&clean(&fact.after, MAX_TEXT))
            ));
        }
        out.push('\n');
    }
    for caveat in &c.caveats {
        out.push_str(&format!("> ⚠ {}\n\n", escape_text(&caveat_text(caveat))));
    }

    let totals = c.totals();
    let counts: Vec<usize> = SECTIONS.iter().map(|&s| c.changes_in(s).len()).collect();
    out.push_str("## Summary\n\n");
    out.push_str(&format!(
        "- **{}** got worse\n- **{}** got better\n- **{}** other changes (informational)\n\
         - **{}** unchanged\n",
        counts[0], counts[1], counts[2], totals.unchanged
    ));
    if totals.not_compared > 0 {
        out.push_str(&format!(
            "- **{}** {} not compared\n",
            totals.not_compared,
            if totals.not_compared == 1 {
                "module"
            } else {
                "modules"
            }
        ));
    }
    out.push('\n');

    for (&section, &count) in SECTIONS.iter().zip(&counts) {
        if count == 0 {
            continue;
        }
        out.push_str(&format!("## {} ({count})\n\n", section_title(section)));
        for change in c.changes_in(section) {
            out.push_str(&format!(
                "- **{}** · {} {} — {}\n",
                escape_text(&status(change)),
                code_span(&clean(&change.module_id, MAX_ID)),
                code_span(&clean(&change.id, MAX_NAME)),
                escape_text(&subject(change))
            ));
            for e in change.evidence.iter().take(MAX_EVIDENCE_LINES) {
                out.push_str(&format!(
                    "  - {}: {} → {}\n",
                    code_span(&clean(&e.key, MAX_NAME)),
                    markdown_value(&e.before),
                    markdown_value(&e.after)
                ));
            }
            if change.evidence.len() > MAX_EVIDENCE_LINES {
                out.push_str(&format!(
                    "  - … and {} more\n",
                    change.evidence.len() - MAX_EVIDENCE_LINES
                ));
            }
        }
        out.push('\n');
    }

    if counts.iter().all(|&n| n == 0) && c.hidden == 0 {
        out.push_str(&format!(
            "No change in the {} that could be compared.\n\n",
            plural(totals.unchanged, "finding", "findings")
        ));
    }
    if let (true, Some(min)) = (c.hidden > 0, c.hidden_below) {
        out.push_str(&format!(
            "*{} below {} hidden (`--min-severity {}`).*\n\n",
            plural(c.hidden, "change", "changes"),
            word(min),
            word(min)
        ));
    }

    let incomplete = incomplete_notes(c);
    if !incomplete.is_empty() {
        out.push_str("## Incomplete data\n\n");
        for (module, report) in incomplete {
            for note in &report.notes {
                out.push_str(&format!(
                    "- {} ({}): {}\n",
                    code_span(&clean(module, MAX_ID)),
                    side_label(report.side),
                    escape_text(&clean(note, MAX_TEXT))
                ));
            }
        }
        out.push_str("\nA change marked ? involves one of these modules and may not be real.\n\n");
    }

    if !c.not_compared.is_empty() {
        out.push_str(&format!("## Not compared ({})\n\n", c.not_compared.len()));
        for n in &c.not_compared {
            out.push_str(&format!(
                "- {} — first report: {} · second report: {}",
                code_span(&clean(&n.module_id, MAX_ID)),
                escape_text(&availability(&n.before)),
                escape_text(&availability(&n.after))
            ));
            if let Some(detail) = not_compared_detail(n) {
                out.push_str(&format!(" — {}", escape_text(&detail)));
            }
            out.push('\n');
        }
        out.push('\n');
    }

    if !c.skipped_in_both.is_empty() {
        let names: Vec<String> = c
            .skipped_in_both
            .iter()
            .map(|m| code_span(&clean(m, MAX_ID)))
            .collect();
        out.push_str(&format!("Skipped in both reports: {}\n", names.join(", ")));
    }
    out
}

// ---------------------------------------------------------------------------
// JSON
// ---------------------------------------------------------------------------

#[derive(Serialize)]
struct ReportRef<'a> {
    report: &'a str,
    /// The version of LinuxDoctor that wrote the report; `null` when it
    /// does not say (written by a version that did not record it).
    linuxdoctor_version: Option<&'a str>,
    machine: &'a MachineFacts,
}

#[derive(Serialize)]
struct Summary {
    worse: usize,
    better: usize,
    other: usize,
    unchanged: usize,
    not_compared: usize,
}

#[derive(Serialize)]
struct ChangeJson<'a> {
    section: &'static str,
    #[serde(flatten)]
    change: &'a Change,
}

#[derive(Serialize)]
struct IncompleteJson<'a> {
    module_id: &'a str,
    #[serde(flatten)]
    incomplete: &'a Incomplete,
}

#[derive(Serialize)]
struct Envelope<'a> {
    schema_version: u32,
    kind: &'static str,
    /// The version of LinuxDoctor that made this comparison.
    linuxdoctor_version: &'static str,
    before: ReportRef<'a>,
    after: ReportRef<'a>,
    machine_changes: &'a [FactChange],
    rebooted: bool,
    caveats: &'a [Caveat],
    floor: Severity,
    summary: Summary,
    changes: Vec<ChangeJson<'a>>,
    incomplete: Vec<IncompleteJson<'a>>,
    not_compared: &'a [NotCompared],
    skipped_in_both: &'a [String],
    hidden: usize,
    #[serde(skip_serializing_if = "Option::is_none")]
    hidden_below: Option<Severity>,
}

fn section_name(section: Section) -> &'static str {
    match section {
        Section::Worse => "worse",
        Section::Better => "better",
        Section::Other => "other",
    }
}

pub fn json(c: &Comparison, labels: &Labels) -> serde_json::Result<String> {
    let mut changes = Vec::new();
    let mut counts = [0usize; 3];
    for (slot, &section) in SECTIONS.iter().enumerate() {
        for change in c.changes_in(section) {
            counts[slot] += 1;
            changes.push(ChangeJson {
                section: section_name(section),
                change,
            });
        }
    }
    let totals = c.totals();
    serde_json::to_string_pretty(&Envelope {
        schema_version: COMPARISON_SCHEMA_VERSION,
        kind: "comparison",
        linuxdoctor_version: crate::VERSION,
        before: ReportRef {
            report: labels.before,
            linuxdoctor_version: labels.before_version,
            machine: &c.before,
        },
        after: ReportRef {
            report: labels.after,
            linuxdoctor_version: labels.after_version,
            machine: &c.after,
        },
        machine_changes: &c.machine_changes,
        rebooted: c.rebooted,
        caveats: &c.caveats,
        floor: c.floor,
        summary: Summary {
            worse: counts[0],
            better: counts[1],
            other: counts[2],
            unchanged: totals.unchanged,
            not_compared: totals.not_compared,
        },
        changes,
        incomplete: incomplete_notes(c)
            .into_iter()
            .map(|(module_id, incomplete)| IncompleteJson {
                module_id,
                incomplete,
            })
            .collect(),
        not_compared: &c.not_compared,
        skipped_in_both: &c.skipped_in_both,
        hidden: c.hidden,
        hidden_below: c.hidden_below,
    })
}

#[cfg(test)]
mod tests {
    use super::super::compare::compare;
    use super::super::compare::testkit::*;
    use super::*;
    use serde_json::json as j;

    const LABELS: Labels = Labels {
        before: "before.json",
        after: "after.json",
        before_version: Some("1.7.0"),
        after_version: None,
    };

    /// A comparison with a change of each kind, a module that failed, one
    /// whose data is incomplete, a skipped one, and a reboot.
    fn rich() -> Comparison {
        let before = report_on(
            "web01",
            1_000_000,
            vec![
                with_evidence(
                    module(
                        "security",
                        &[
                            ("SEC005", Some("sshd"), "warning"),
                            ("SEC009", None, "error"),
                        ],
                    ),
                    0,
                    &[("permit_root_login", "no")],
                ),
                module("network", &[("NET001", None, "error")]),
                with_notes(
                    module("storage", &[("STOR001", Some("/"), "warning")]),
                    &["smartctl stopped"],
                ),
                skipped("numa"),
            ],
        );
        let mut after = report_on(
            "web01",
            1_900_000,
            vec![
                with_evidence(
                    module(
                        "security",
                        &[
                            ("SEC005", Some("sshd"), "error"),
                            ("SEC002", Some("tcp/23"), "critical"),
                            ("SEC003", None, "info"),
                        ],
                    ),
                    0,
                    &[("permit_root_login", "yes")],
                ),
                failed("network", "cannot read /proc/net/dev"),
                with_notes(module("storage", &[]), &["smartctl stopped"]),
                skipped("numa"),
            ],
        );
        after.context.kernel_version = "6.8.0-40".into();
        compare(&before, &after)
    }

    /// Removes the ANSI colour sequences the renderer itself adds.
    fn strip_ansi(text: &str) -> String {
        let mut out = String::new();
        let mut chars = text.chars().peekable();
        while let Some(c) = chars.next() {
            if c == '\x1b' && chars.peek() == Some(&'[') {
                for d in chars.by_ref() {
                    if d.is_ascii_alphabetic() {
                        break;
                    }
                }
            } else {
                out.push(c);
            }
        }
        out
    }

    #[test]
    fn the_terminal_text_has_the_expected_structure() {
        let plain = strip_ansi(&terminal(&rich(), &LABELS));
        let title = format!("LinuxDoctor {} — report comparison", crate::VERSION);
        for expected in [
            title.as_str(),
            "before  before.json (LinuxDoctor 1.7.0)",
            "after   after.json (LinuxDoctor version not recorded)",
            "Machine changes",
            "kernel        6.8.0-31 → 6.8.0-40",
            "Summary  2 got worse · 2 got better · 1 other · 0 unchanged · 1 module not compared",
            "Got worse (2)",
            "new (critical)",
            "warning → error",
            "permit_root_login: no → yes",
            "Got better (2)",
            "resolved (was error)",
            "Other changes (1)",
            "new (info)",
            "Incomplete data",
            "storage (second report): smartctl stopped",
            "Not compared (1)",
            "first report: ran · second report: failed (cannot read /proc/net/dev)",
            "1 finding in the first report could not be re-checked",
            "Skipped in both reports: numa",
        ] {
            assert!(
                plain.contains(expected),
                "missing `{expected}` in:\n{plain}"
            );
        }
        // The failed module's finding is not called resolved.
        assert!(!plain.contains("NET001"), "{plain}");
    }

    #[test]
    fn a_resolved_finding_of_a_module_with_incomplete_data_is_marked() {
        let plain = strip_ansi(&terminal(&rich(), &LABELS));
        let line = plain
            .lines()
            .find(|l| l.contains("STOR001"))
            .expect("the storage finding is listed");
        assert!(line.contains("resolved (was warning) ?"), "{line}");
        let sure = plain
            .lines()
            .find(|l| l.contains("SEC009"))
            .expect("the security finding is listed");
        assert!(!sure.contains('?'), "{sure}");
    }

    #[test]
    fn nothing_to_report_says_so_plainly() {
        let r = || {
            report(vec![module(
                "m",
                &[("A", None, "info"), ("B", None, "warning")],
            )])
        };
        let text = strip_ansi(&terminal(&compare(&r(), &r()), &LABELS));
        assert!(
            text.contains("No change in the 2 findings that could be compared."),
            "{text}"
        );
        assert!(!text.contains("Got worse"));
    }

    #[test]
    fn the_hidden_changes_are_counted() {
        let mut c = rich();
        let dropped = c.retain_at_or_above(Severity::Error);
        assert!(dropped > 0);
        let text = strip_ansi(&terminal(&c, &LABELS));
        assert!(
            text.contains(&format!(
                "{} below error hidden (--min-severity error)",
                plural(dropped, "change", "changes")
            )),
            "{text}"
        );
        // What decides whether the comparison worked is never hidden.
        assert!(text.contains("Not compared (1)"), "{text}");
    }

    #[test]
    fn long_evidence_is_cut_with_a_count() {
        let mk = |severity: &str, value: &str| {
            let mut m = module("m", &[("X", None, severity)]);
            m["findings"][0]["evidence"] =
                j!((0..9).map(|i| (format!("k{i}"), value)).collect::<Vec<_>>());
            m
        };
        let c = compare(
            &report(vec![mk("warning", "1")]),
            &report(vec![mk("error", "2")]),
        );
        let text = strip_ansi(&terminal(&c, &LABELS));
        assert!(text.contains("k5: 1 → 2"), "{text}");
        assert!(!text.contains("k6: 1 → 2"), "{text}");
        assert!(text.contains("… and 3 more"), "{text}");
    }

    #[test]
    fn caveats_are_stated_before_the_changes() {
        let before = report_on("web01", 1_000_000, vec![module("m", &[])]);
        let after = report_on("db02", 1_000_000, vec![module("m", &[])]);
        let text = strip_ansi(&terminal(&compare(&before, &after), &LABELS));
        let caveat = text.find("different machines").expect("caveat shown");
        let summary = text.find("Summary").expect("summary shown");
        assert!(caveat < summary, "{text}");
    }

    // ----- the version caveat -----------------------------------------------------

    fn two_versions() -> Comparison {
        compare(
            &by_version(
                report(vec![module("m", &[("A", None, "warning")])]),
                "1.8.1",
            ),
            &by_version(report(vec![module("m", &[("A", None, "error")])]), "1.9.0"),
        )
    }

    #[test]
    fn the_terminal_says_the_reports_come_from_different_versions_before_the_changes() {
        let text = strip_ansi(&terminal(&two_versions(), &LABELS));
        let caveat = text
            .find("different versions of LinuxDoctor (1.8.1 and 1.9.0)")
            .expect("caveat shown");
        assert!(text.contains("not from the machine"), "{text}");
        assert!(caveat < text.find("Summary").unwrap(), "{text}");
    }

    #[test]
    fn a_report_without_a_version_is_named_as_such_in_the_caveat() {
        let c = compare(&report(vec![]), &by_version(report(vec![]), "1.9.0"));
        let text = strip_ansi(&terminal(&c, &LABELS));
        assert!(
            text.contains("different versions of LinuxDoctor (not recorded and 1.9.0)"),
            "{text}"
        );
    }

    #[test]
    fn the_same_version_gets_no_caveat_in_any_format() {
        let c = compare(
            &by_version(report(vec![]), "1.9.0"),
            &by_version(report(vec![]), "1.9.0"),
        );
        assert!(!strip_ansi(&terminal(&c, &LABELS)).contains("different versions"));
        assert!(!markdown(&c, &LABELS).contains("different versions"));
        let v: serde_json::Value = serde_json::from_str(&json(&c, &LABELS).unwrap()).unwrap();
        assert_eq!(v["caveats"], j!([]));
    }

    #[test]
    fn markdown_quotes_the_version_caveat_like_the_others() {
        let md = markdown(&two_versions(), &LABELS);
        assert!(
            md.contains("> ⚠ These reports were written by different versions of LinuxDoctor (1.8.1 and 1.9.0)"),
            "{md}"
        );
    }

    #[test]
    fn json_records_the_version_caveat_with_both_versions() {
        let v: serde_json::Value =
            serde_json::from_str(&json(&two_versions(), &LABELS).unwrap()).unwrap();
        assert_eq!(
            v["caveats"],
            j!([{"kind": "different_versions", "before": "1.8.1", "after": "1.9.0"}])
        );
        let c = compare(&report(vec![]), &by_version(report(vec![]), "1.9.0"));
        let v: serde_json::Value = serde_json::from_str(&json(&c, &LABELS).unwrap()).unwrap();
        assert_eq!(
            v["caveats"][0],
            j!({"kind": "different_versions", "before": null, "after": "1.9.0"})
        );
    }

    #[test]
    fn a_version_read_from_a_file_cannot_act_on_the_terminal_through_the_caveat() {
        let evil = "1.\u{1b}[2J\u{1b}]0;pwned\u{7}\u{202e}0";
        let c = compare(
            &by_version(report(vec![]), evil),
            &by_version(report(vec![]), "<b>2|0</b>"),
        );
        let plain = strip_ansi(&terminal(&c, &LABELS));
        assert_no_control_characters(&plain);
        assert!(
            plain.contains("different versions of LinuxDoctor (1.?[2J?]0;pwned??0 and"),
            "{plain}"
        );
        let md = markdown(&c, &LABELS);
        assert_no_control_characters(&md);
        // Every `<` is escaped, so no tag can open.
        let bare = md
            .char_indices()
            .any(|(i, c)| c == '<' && !md[..i].ends_with('\\'));
        assert!(!bare, "markup must be escaped: {md}");
        assert!(md.contains("\\<b>2|0\\</b>"), "{md}");
        // A very long version is cut, not printed whole.
        let long = "9".repeat(5_000);
        let c = compare(
            &by_version(report(vec![]), &long),
            &by_version(report(vec![]), "1.9.0"),
        );
        assert!(terminal(&c, &LABELS).len() < 3_000);
    }

    // ----- hostile files ----------------------------------------------------------

    fn hostile() -> Comparison {
        let evil = "\u{1b}[2J\u{1b}]0;pwned\u{7}evil\u{202e}";
        let mut b = module("m", &[("X", Some(evil), "warning")]);
        b["findings"][0]["title"] = j!(evil);
        let mut a = module("m", &[("X", Some(evil), "error")]);
        a["findings"][0]["title"] = j!(evil);
        a["findings"][0]["evidence"] = j!([[evil, evil]]);
        let mut after = report_on(evil, 1_000_000, vec![a, failed("bad", evil)]);
        after.context.kernel_version = evil.into();
        let before = report_on(
            "web01",
            1_000_000,
            vec![b, module("bad", &[("Y", None, "error")])],
        );
        compare(&before, &after)
    }

    fn assert_no_control_characters(text: &str) {
        for c in text.chars() {
            assert!(
                c == '\n'
                    || !(c.is_control()
                        || matches!(c, '\u{202a}'..='\u{202e}' | '\u{2066}'..='\u{2069}')),
                "control character {c:?} survived in:\n{text}"
            );
        }
    }

    #[test]
    fn terminal_text_from_a_hostile_file_has_no_control_characters() {
        let text = terminal(
            &hostile(),
            &Labels {
                before: "a\u{1b}[31m.json",
                after: "b\n.json",
                before_version: Some("1.\u{1b}]0;pwned\u{7}.0"),
                after_version: Some("\u{202e}9.9"),
            },
        );
        // The renderer's own colours are the only escape sequences.
        let plain = strip_ansi(&text);
        assert_no_control_characters(&plain);
        assert!(plain.contains("evil?"), "{plain}");
    }

    #[test]
    fn markdown_from_a_hostile_file_has_no_control_characters() {
        let md = markdown(
            &hostile(),
            &Labels {
                before: "a|b.json",
                after: "c.json",
                before_version: Some("1|2"),
                after_version: Some("<b>1</b>"),
            },
        );
        assert_no_control_characters(&md);
        // The table keeps its shape: one row per report.
        let rows = md.lines().filter(|l| l.starts_with("| **")).count();
        assert_eq!(rows, 2, "{md}");
        assert!(md.contains("a\\|b.json"), "{md}");
    }

    #[test]
    fn markdown_escapes_markup_in_titles() {
        let title = "a <script>alert(1)</script> *bold* [link](http://x)";
        let mut b = module("m", &[("X", None, "warning")]);
        b["findings"][0]["title"] = j!(title);
        let mut a = module("m", &[("X", None, "error")]);
        a["findings"][0]["title"] = j!(title);
        let md = markdown(&compare(&report(vec![b]), &report(vec![a])), &LABELS);
        // Every `<` is escaped, so no tag can open.
        let bare = md
            .char_indices()
            .any(|(i, c)| c == '<' && !md[..i].ends_with('\\'));
        assert!(!bare, "{md}");
        assert!(md.contains("\\<script>"), "{md}");
        assert!(md.contains("\\*bold\\*"), "{md}");
        assert!(md.contains("\\[link\\]"), "{md}");
    }

    #[test]
    fn json_from_a_hostile_file_stays_valid_json() {
        let text = json(&hostile(), &LABELS).unwrap();
        // Escaped by serde_json: no raw control characters in the document.
        assert!(!text.contains('\u{1b}'), "raw escape in JSON output");
        serde_json::from_str::<serde_json::Value>(&text).unwrap();
    }

    // ----- Markdown and JSON shape -----------------------------------------------------

    #[test]
    fn markdown_has_a_section_per_kind_of_change() {
        let md = markdown(&rich(), &LABELS);
        for expected in [
            "# LinuxDoctor report comparison",
            "## Machine changes",
            "## Summary",
            "## Got worse (2)",
            "## Got better (2)",
            "## Other changes (1)",
            "## Incomplete data",
            "## Not compared (1)",
            "- **warning → error** · `security` `SEC005`",
            "  - `permit_root_login`: `no` → `yes`",
            "Skipped in both reports: `numa`",
        ] {
            assert!(md.contains(expected), "missing `{expected}` in:\n{md}");
        }
    }

    #[test]
    fn json_is_versioned_and_lists_every_change_with_its_section() {
        let text = json(&rich(), &LABELS).unwrap();
        let v: serde_json::Value = serde_json::from_str(&text).unwrap();
        assert_eq!(v["schema_version"], j!(COMPARISON_SCHEMA_VERSION));
        assert_eq!(v["kind"], "comparison");
        assert!(
            text.lines()
                .nth(1)
                .unwrap()
                .trim()
                .starts_with("\"schema_version\""),
            "schema_version comes first"
        );
        assert_eq!(v["before"]["report"], "before.json");
        assert_eq!(v["after"]["machine"]["kernel_version"], "6.8.0-40");
        assert_eq!(v["rebooted"], true);
        assert_eq!(v["floor"], "info");
        assert_eq!(v["summary"]["worse"], 2);
        assert_eq!(v["summary"]["better"], 2);
        assert_eq!(v["summary"]["other"], 1);
        assert_eq!(v["summary"]["not_compared"], 1);

        let changes = v["changes"].as_array().unwrap();
        assert_eq!(changes.len(), 5);
        let first = &changes[0];
        assert_eq!(first["section"], "worse");
        assert_eq!(first["id"], "SEC002");
        assert_eq!(first["kind"], "new");
        assert_eq!(first["after"], "critical");
        assert!(first["before"].is_null());
        let worse = changes.iter().find(|c| c["id"] == "SEC005").unwrap();
        assert_eq!(worse["kind"], "worse");
        assert_eq!(worse["evidence"][0]["key"], "permit_root_login");
        let resolved = changes.iter().find(|c| c["id"] == "STOR001").unwrap();
        assert_eq!(resolved["doubt"], "after");

        assert_eq!(v["not_compared"][0]["module_id"], "network");
        assert_eq!(v["not_compared"][0]["after"]["state"], "failed");
        assert_eq!(v["incomplete"][0]["module_id"], "storage");
        assert_eq!(v["skipped_in_both"][0], "numa");
        assert_eq!(v["hidden"], 0);
        assert!(v.get("hidden_below").is_none());
    }

    #[test]
    fn markdown_says_which_version_compared_and_which_wrote_each_report() {
        let md = markdown(&rich(), &LABELS);
        let mut lines = md.lines();
        assert_eq!(lines.next(), Some("# LinuxDoctor report comparison"));
        assert_eq!(lines.next(), Some(""));
        assert_eq!(
            lines.next(),
            Some(format!("Compared with LinuxDoctor {}.", crate::VERSION).as_str())
        );
        assert!(md.contains("| | Report | Written by | Machine |"), "{md}");
        assert!(
            md.contains("| **before** | before.json | LinuxDoctor 1.7.0 |"),
            "{md}"
        );
        assert!(
            md.contains("| **after** | after.json | LinuxDoctor version not recorded |"),
            "{md}"
        );
    }

    #[test]
    fn json_records_the_comparing_version_and_the_version_of_each_report() {
        let v: serde_json::Value = serde_json::from_str(&json(&rich(), &LABELS).unwrap()).unwrap();
        assert_eq!(v["linuxdoctor_version"], crate::VERSION);
        assert_eq!(v["before"]["linuxdoctor_version"], "1.7.0");
        assert!(v["after"]["linuxdoctor_version"].is_null(), "not recorded");
        // The same key means the same thing at both levels: who wrote it.
        assert!(v["after"].get("linuxdoctor_version").is_some());
    }

    #[test]
    fn a_version_read_from_a_file_cannot_act_on_the_terminal() {
        // The labels of `hostile_text_cannot_...` carry escape sequences and
        // a right-to-left override in the versions; these are their cleaned
        // forms, shown rather than dropped.
        let plain = strip_ansi(&terminal(
            &hostile(),
            &Labels {
                before: "a.json",
                after: "b.json",
                before_version: Some("1.\u{1b}]0;pwned\u{7}.0"),
                after_version: Some("\u{202e}9.9"),
            },
        ));
        assert!(plain.contains("(LinuxDoctor 1.?]0;pwned?.0)"), "{plain}");
        assert!(plain.contains("(LinuxDoctor ?9.9)"), "{plain}");
    }

    #[test]
    fn json_records_the_display_filter() {
        let mut c = rich();
        let dropped = c.retain_at_or_above(Severity::Error);
        let v: serde_json::Value = serde_json::from_str(&json(&c, &LABELS).unwrap()).unwrap();
        assert_eq!(v["hidden"], j!(dropped));
        assert_eq!(v["hidden_below"], "error");
    }
}
