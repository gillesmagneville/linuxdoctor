// SPDX-License-Identifier: GPL-3.0-only

//! Pieces shared by the document-style renderers (Markdown and HTML) and by
//! the options every non-interactive renderer receives. Nothing here
//! diagnoses anything: it only describes how already-produced text is
//! laid out.

use std::time::{SystemTime, UNIX_EPOCH};

use crate::core::engine::ModuleRunResult;
use crate::models::Severity;

/// Set when `--min-severity` removed findings from the report, so a
/// filtered report never looks like a complete one.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FilterInfo {
    pub min_severity: Severity,
    /// Number of findings removed by the filter.
    pub hidden: usize,
}

/// Everything a renderer needs besides the report itself.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RenderMeta {
    /// Version of the tool that produced the report.
    pub tool_version: &'static str,
    /// When the report was produced, in seconds since the Unix epoch.
    /// Passed in (not read inside the renderers) so output is testable.
    pub generated_at_unix: u64,
    pub filter: Option<FilterInfo>,
}

impl Default for RenderMeta {
    fn default() -> Self {
        RenderMeta {
            tool_version: env!("CARGO_PKG_VERSION"),
            generated_at_unix: 0,
            filter: None,
        }
    }
}

impl RenderMeta {
    /// Metadata for a report produced right now.
    pub fn now(filter: Option<FilterInfo>) -> Self {
        let generated_at_unix = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        RenderMeta {
            generated_at_unix,
            filter,
            ..RenderMeta::default()
        }
    }
}

/// Date and time pieces of a Unix timestamp, in UTC.
fn civil_from_unix(secs: u64) -> (i64, u32, u32, u32, u32, u32) {
    let days = (secs / 86_400) as i64;
    let rem = secs % 86_400;
    // Howard Hinnant's days -> civil date algorithm.
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1_460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let month = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    let year = yoe + era * 400 + i64::from(month <= 2);
    (
        year,
        month,
        day,
        (rem / 3_600) as u32,
        (rem % 3_600 / 60) as u32,
        (rem % 60) as u32,
    )
}

/// "2026-10-14 18:30:00 UTC"
pub fn format_utc(secs: u64) -> String {
    let (y, mo, d, h, mi, s) = civil_from_unix(secs);
    format!("{y:04}-{mo:02}-{d:02} {h:02}:{mi:02}:{s:02} UTC")
}

/// "2026-10-14T18:30:00Z" (machine-readable, for `<time datetime>`).
pub fn format_utc_iso(secs: u64) -> String {
    let (y, mo, d, h, mi, s) = civil_from_unix(secs);
    format!("{y:04}-{mo:02}-{d:02}T{h:02}:{mi:02}:{s:02}Z")
}

/// Findings per severity, worst first: `[critical, error, warning, info]`.
pub fn severity_counts(result: &ModuleRunResult) -> [usize; 4] {
    let mut counts = [0; 4];
    for f in &result.findings {
        let slot = match f.severity {
            Severity::Critical => 0,
            Severity::Error => 1,
            Severity::Warning => 2,
            Severity::Info => 3,
        };
        counts[slot] += 1;
    }
    counts
}

/// How a module ended, for the summary tables.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ModuleStatus {
    Skipped,
    /// The module could not run; carries its error text.
    Failed(String),
    /// The module ran. `worst` is the highest severity it reported, and
    /// `incomplete` is set when a tool was cut short, which means a clean
    /// result cannot be trusted as clean.
    Ran {
        worst: Option<Severity>,
        incomplete: bool,
    },
}

pub fn module_status(result: &ModuleRunResult) -> ModuleStatus {
    if result.skipped {
        return ModuleStatus::Skipped;
    }
    if let Some(err) = &result.error {
        return ModuleStatus::Failed(err.clone());
    }
    ModuleStatus::Ran {
        worst: result.findings.iter().map(|f| f.severity).max(),
        incomplete: !result.notes.is_empty(),
    }
}

// ---------------------------------------------------------------------------
// Recommendation layout
// ---------------------------------------------------------------------------

/// One numbered step of a recommendation, with the commands to copy.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Step {
    pub text: String,
    pub commands: Vec<String>,
}

/// A recommendation, classified by the shape modules write it in.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Recommendation<'a> {
    /// One line of advice.
    Inline(&'a str),
    /// Numbered steps (`1. text`), commands on their own lines indented
    /// by four spaces underneath.
    Steps(Vec<Step>),
    /// Several lines that do not follow the numbered-step convention.
    Text(&'a str),
}

/// If `line` starts with `N. ` (digits, a dot, a space), the text after it.
fn numbered_text(line: &str) -> Option<&str> {
    let digits = line.bytes().take_while(u8::is_ascii_digit).count();
    if digits == 0 {
        return None;
    }
    line[digits..].strip_prefix(". ")
}

pub fn parse_recommendation(rec: &str) -> Recommendation<'_> {
    let rec = rec.trim_end();
    if !rec.contains('\n') {
        return Recommendation::Inline(rec.trim());
    }
    let mut steps: Vec<Step> = Vec::new();
    for line in rec.lines() {
        if line.trim().is_empty() {
            continue;
        }
        if let Some(text) = numbered_text(line) {
            steps.push(Step {
                text: text.trim().to_string(),
                commands: Vec::new(),
            });
        } else if line.starts_with([' ', '\t']) {
            match steps.last_mut() {
                Some(step) => {
                    let command = line
                        .strip_prefix("    ")
                        .unwrap_or_else(|| line.trim_start());
                    step.commands.push(command.trim_end().to_string());
                }
                // A command line before any step: not our convention.
                None => return Recommendation::Text(rec),
            }
        } else {
            match steps.last_mut() {
                // A wrapped continuation of the step's sentence.
                Some(step) if step.commands.is_empty() => {
                    step.text.push(' ');
                    step.text.push_str(line.trim());
                }
                _ => return Recommendation::Text(rec),
            }
        }
    }
    if steps.is_empty() {
        Recommendation::Text(rec)
    } else {
        Recommendation::Steps(steps)
    }
}

// ---------------------------------------------------------------------------
// Explanation layout
// ---------------------------------------------------------------------------

/// A piece of an explanation. Modules lay out tables and lists with
/// leading spaces; prose is unindented. Keeping that distinction lets the
/// document renderers print aligned columns in monospace and wrap prose.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Block {
    Paragraph(String),
    /// Indented lines, with their common indentation removed.
    Preformatted(Vec<String>),
}

pub fn explanation_blocks(text: &str) -> Vec<Block> {
    let mut blocks: Vec<Block> = Vec::new();
    let mut prose: Vec<&str> = Vec::new();
    let mut table: Vec<&str> = Vec::new();

    fn flush_prose(prose: &mut Vec<&str>, blocks: &mut Vec<Block>) {
        if !prose.is_empty() {
            blocks.push(Block::Paragraph(prose.join("\n")));
            prose.clear();
        }
    }
    fn flush_table(table: &mut Vec<&str>, blocks: &mut Vec<Block>) {
        if table.is_empty() {
            return;
        }
        let indent = table
            .iter()
            .filter(|l| !l.trim().is_empty())
            .map(|l| l.len() - l.trim_start().len())
            .min()
            .unwrap_or(0);
        let lines = table
            .iter()
            .map(|l| l.get(indent..).unwrap_or("").trim_end().to_string())
            .collect();
        blocks.push(Block::Preformatted(lines));
        table.clear();
    }

    for line in text.lines() {
        if line.trim().is_empty() {
            flush_prose(&mut prose, &mut blocks);
            flush_table(&mut table, &mut blocks);
        } else if line.starts_with([' ', '\t']) {
            flush_prose(&mut prose, &mut blocks);
            table.push(line);
        } else {
            flush_table(&mut table, &mut blocks);
            prose.push(line.trim_end());
        }
    }
    flush_prose(&mut prose, &mut blocks);
    flush_table(&mut table, &mut blocks);
    blocks
}

#[cfg(test)]
mod tests {
    use super::*;

    // ----- time ------------------------------------------------------

    #[test]
    fn epoch_is_1970() {
        assert_eq!(format_utc(0), "1970-01-01 00:00:00 UTC");
        assert_eq!(format_utc_iso(0), "1970-01-01T00:00:00Z");
    }

    #[test]
    fn known_timestamps_format_correctly() {
        assert_eq!(format_utc(951_782_400), "2000-02-29 00:00:00 UTC"); // leap day
        assert_eq!(format_utc(1_700_000_000), "2023-11-14 22:13:20 UTC");
        assert_eq!(format_utc(1_791_959_400), "2026-10-14 06:30:00 UTC");
        assert_eq!(format_utc(4_102_444_799), "2099-12-31 23:59:59 UTC");
        assert_eq!(format_utc(4_102_444_800), "2100-01-01 00:00:00 UTC");
    }

    #[test]
    fn day_boundaries_and_non_leap_century() {
        assert_eq!(format_utc(86_399), "1970-01-01 23:59:59 UTC");
        assert_eq!(format_utc(86_400), "1970-01-02 00:00:00 UTC");
        // 2100 is not a leap year: Feb 28 is followed by Mar 1.
        assert_eq!(format_utc(4_107_456_000), "2100-02-28 00:00:00 UTC");
        assert_eq!(format_utc(4_107_542_400), "2100-03-01 00:00:00 UTC");
    }

    #[test]
    fn now_is_after_2025() {
        // A sanity bound on the real clock, not a precise check.
        assert!(RenderMeta::now(None).generated_at_unix > 1_735_689_600);
    }

    // ----- recommendation ---------------------------------------------

    #[test]
    fn single_line_is_inline() {
        assert_eq!(
            parse_recommendation("Add more RAM.\n"),
            Recommendation::Inline("Add more RAM.")
        );
    }

    #[test]
    fn numbered_steps_collect_their_commands() {
        let rec = "1. Check the tool:\n    vmstat 1 5\n2. Then reload:\n    sudo sysctl --system\n    sudo systemctl restart foo\n3. Done.";
        let Recommendation::Steps(steps) = parse_recommendation(rec) else {
            panic!("expected steps");
        };
        assert_eq!(steps.len(), 3);
        assert_eq!(steps[0].text, "Check the tool:");
        assert_eq!(steps[0].commands, ["vmstat 1 5"]);
        assert_eq!(
            steps[1].commands,
            ["sudo sysctl --system", "sudo systemctl restart foo"]
        );
        assert!(steps[2].commands.is_empty());
    }

    #[test]
    fn command_keeps_indentation_beyond_the_four_space_margin() {
        let rec = "1. Do it:\n    for x in a b; do\n      echo $x\n    done";
        let Recommendation::Steps(steps) = parse_recommendation(rec) else {
            panic!("expected steps");
        };
        assert_eq!(steps[0].commands, ["for x in a b; do", "  echo $x", "done"]);
    }

    #[test]
    fn wrapped_step_sentence_is_joined() {
        let rec = "1. A long sentence that the\nmodule wrapped onto a second line.\n    cmd";
        let Recommendation::Steps(steps) = parse_recommendation(rec) else {
            panic!("expected steps");
        };
        assert_eq!(
            steps[0].text,
            "A long sentence that the module wrapped onto a second line."
        );
        assert_eq!(steps[0].commands, ["cmd"]);
    }

    #[test]
    fn blank_lines_between_steps_are_ignored() {
        let rec = "1. One\n\n2. Two\n    cmd\n";
        let Recommendation::Steps(steps) = parse_recommendation(rec) else {
            panic!("expected steps");
        };
        assert_eq!(steps.len(), 2);
    }

    #[test]
    fn multi_line_without_numbering_is_plain_text() {
        let rec = "First line.\nSecond line.";
        assert_eq!(parse_recommendation(rec), Recommendation::Text(rec));
    }

    #[test]
    fn indented_line_before_any_step_is_plain_text() {
        let rec = "    stray command\n1. A step";
        assert!(matches!(parse_recommendation(rec), Recommendation::Text(_)));
    }

    #[test]
    fn text_after_a_command_that_is_not_a_step_is_plain_text() {
        let rec = "1. Step\n    cmd\ntrailing prose";
        assert!(matches!(parse_recommendation(rec), Recommendation::Text(_)));
    }

    #[test]
    fn numbers_without_a_dot_and_space_are_not_steps() {
        assert_eq!(numbered_text("10. ten"), Some("ten"));
        assert_eq!(numbered_text("1.5 GB of RAM"), None);
        assert_eq!(numbered_text("a. no"), None);
        assert_eq!(numbered_text(". no"), None);
    }

    // ----- explanation ------------------------------------------------

    #[test]
    fn prose_and_tables_are_separated() {
        let text = "Intro line.\n\nWhere it goes:\n  Programs    191 MB   2.4%\n  Cache       714 MB   8.9%\n\nClosing.";
        assert_eq!(
            explanation_blocks(text),
            vec![
                Block::Paragraph("Intro line.".into()),
                Block::Paragraph("Where it goes:".into()),
                Block::Preformatted(vec![
                    "Programs    191 MB   2.4%".into(),
                    "Cache       714 MB   8.9%".into()
                ]),
                Block::Paragraph("Closing.".into()),
            ]
        );
    }

    #[test]
    fn relative_indentation_inside_a_table_is_kept() {
        let text = "  1. first\n     detail\n  2. second";
        assert_eq!(
            explanation_blocks(text),
            vec![Block::Preformatted(vec![
                "1. first".into(),
                "   detail".into(),
                "2. second".into()
            ])]
        );
    }

    #[test]
    fn indented_lines_right_after_prose_still_split_without_a_blank_line() {
        let blocks = explanation_blocks("Heading:\n  a\n  b\nTail");
        assert_eq!(blocks.len(), 3);
        assert!(matches!(blocks[1], Block::Preformatted(_)));
    }

    #[test]
    fn empty_explanation_has_no_blocks() {
        assert!(explanation_blocks("").is_empty());
        assert!(explanation_blocks("\n\n  \n").is_empty());
    }

    // ----- status -----------------------------------------------------

    fn result(findings: Vec<(&str, Severity)>) -> ModuleRunResult {
        use crate::models::{Category, Confidence, Finding};
        ModuleRunResult {
            module_id: "m",
            findings: findings
                .into_iter()
                .map(|(id, sev)| {
                    Finding::builder(
                        id,
                        "t",
                        Category::Memory,
                        sev,
                        Confidence::direct_observation(),
                    )
                    .build()
                })
                .collect(),
            error: None,
            skipped: false,
            notes: vec![],
        }
    }

    #[test]
    fn counts_are_worst_first() {
        let r = result(vec![
            ("a", Severity::Info),
            ("b", Severity::Info),
            ("c", Severity::Warning),
            ("d", Severity::Critical),
        ]);
        assert_eq!(severity_counts(&r), [1, 0, 1, 2]);
    }

    #[test]
    fn status_reflects_skip_error_notes_and_worst_severity() {
        let mut r = result(vec![("a", Severity::Warning), ("b", Severity::Info)]);
        assert_eq!(
            module_status(&r),
            ModuleStatus::Ran {
                worst: Some(Severity::Warning),
                incomplete: false
            }
        );
        r.notes.push("cut short".into());
        assert_eq!(
            module_status(&r),
            ModuleStatus::Ran {
                worst: Some(Severity::Warning),
                incomplete: true
            }
        );
        r.error = Some("boom".into());
        assert_eq!(module_status(&r), ModuleStatus::Failed("boom".into()));
        r.skipped = true;
        assert_eq!(module_status(&r), ModuleStatus::Skipped);
    }
}
