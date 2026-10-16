// SPDX-License-Identifier: GPL-3.0-only

use crate::core::engine::Report;
use crate::models::Severity;

use super::common::{display_safe, RenderMeta};

const RESET: &str = "\x1b[0m";
const DIM: &str = "\x1b[2m";
const BOLD: &str = "\x1b[1m";

/// Renders a Report as human-readable terminal output. Only formats
/// `Finding`s it's given — never computes severity, confidence, or
/// evidence itself. See ARCHITECTURE.md "Output Engine".
pub fn render(report: &Report) -> String {
    render_with(report, &RenderMeta::default())
}

/// Like `render`, adding a closing line when `--min-severity` hid findings.
pub fn render_with(report: &Report, meta: &RenderMeta) -> String {
    // Text the audited machine chose (a process or VM name, a message from a
    // tool) must not be able to act on this terminal.
    let report = &display_safe(report);
    let mut out = String::new();

    out.push_str(&format!(
        "{BOLD}LinuxDoctor {}{RESET} — {}\n",
        meta.tool_version, report.context.hostname
    ));
    out.push_str(&format!(
        "{DIM}kernel {} · {} · {} CPUs · {} MB RAM{RESET}\n\n",
        report.context.kernel_version,
        report.context.distro.as_deref().unwrap_or("unknown distro"),
        report.context.cpu_count,
        report.context.mem_total_kb / 1024,
    ));

    // Per-module status line first, matching the compact summary from
    // ARCHITECTURE.md's Terminal Renderer example.
    for result in &report.results {
        if result.skipped {
            out.push_str(&format!("{DIM}- {} (skipped){RESET}\n", result.module_id));
            continue;
        }
        if let Some(err) = &result.error {
            out.push_str(&format!(
                "{}\u{2717} {} (error: {}){}\n",
                Severity::Error.ansi_color(),
                result.module_id,
                err,
                RESET
            ));
        } else {
            let worst = result.findings.iter().map(|f| f.severity).max();
            let (symbol, color) = match worst {
                Some(sev) if sev > Severity::Info => (sev.symbol(), sev.ansi_color()),
                // Cut-short commands mean the module may be missing the
                // finding that would have flagged something: not a clean
                // green check.
                _ if !result.notes.is_empty() => {
                    (Severity::Warning.symbol(), Severity::Warning.ansi_color())
                }
                _ => (Severity::Info.symbol(), Severity::Info.ansi_color()),
            };
            out.push_str(&format!("{color}{symbol} {}{RESET}\n", result.module_id));
        }
        for note in &result.notes {
            out.push_str(&format!(
                "{}    \u{21b3} incomplete data: {note}{RESET}\n",
                Severity::Warning.ansi_color()
            ));
        }
    }
    out.push('\n');

    // Full detail for anything above INFO.
    for finding in report
        .all_findings()
        .filter(|f| f.severity > Severity::Info)
    {
        out.push_str(&render_finding(finding));
        out.push('\n');
    }

    if let Some(filter) = &meta.filter {
        out.push_str(&format!(
            "{DIM}{} finding(s) below {} hidden (--min-severity {}){RESET}\n",
            filter.hidden,
            filter.min_severity,
            filter.min_severity.to_string().to_lowercase()
        ));
    }

    out
}

fn render_finding(finding: &crate::models::Finding) -> String {
    let mut s = String::new();
    let color = finding.severity.ansi_color();
    s.push_str(&format!(
        "{BOLD}{} — {}{RESET}\n",
        finding.id, finding.title
    ));
    s.push_str(&format!(
        "{color}{}{RESET} · Confidence: {}% ({})\n",
        finding.severity, finding.confidence.percent, finding.confidence.reason
    ));
    if !finding.evidence.is_empty() {
        s.push_str("\nEvidence\n");
        for (k, v) in &finding.evidence {
            s.push_str(&format!("  {k}: {v}\n"));
        }
    }
    if !finding.explanation.is_empty() {
        s.push_str(&format!("\n{}\n", finding.explanation));
    }
    if let Some(rec) = &finding.recommendation {
        s.push_str(&format_recommendation(rec));
    }
    s
}

/// One-line recommendations keep the compact form. Numbered steps with
/// commands on their own lines are printed under a heading, indented, so
/// the commands can be copied straight out of the terminal.
fn format_recommendation(rec: &str) -> String {
    if !rec.contains('\n') {
        return format!("\n{DIM}Recommendation: {rec}{RESET}\n");
    }
    let mut out = format!("\n{BOLD}Recommendation:{RESET}\n");
    for line in rec.lines() {
        out.push_str(&format!("  {line}\n"));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::context::Context;
    use crate::core::engine::ModuleRunResult;

    fn report_with(results: Vec<ModuleRunResult>) -> Report {
        Report {
            context: Context {
                hostname: "host".into(),
                kernel_version: "6.0".into(),
                distro: None,
                architecture: "x86_64".into(),
                cpu_count: 4,
                mem_total_kb: 8 * 1024 * 1024,
                boot_time_unix: 0,
            },
            results,
        }
    }

    fn result(id: &'static str, notes: &[&str]) -> ModuleRunResult {
        ModuleRunResult {
            module_id: id,
            findings: Vec::new(),
            error: None,
            skipped: false,
            notes: notes.iter().map(|n| n.to_string()).collect(),
        }
    }

    #[test]
    fn the_first_line_says_which_version_and_which_machine() {
        let meta = RenderMeta {
            tool_version: "9.9.9",
            ..RenderMeta::default()
        };
        let out = render_with(&report_with(vec![]), &meta);
        let first = out.lines().next().unwrap();
        assert_eq!(first, format!("{BOLD}LinuxDoctor 9.9.9{RESET} — host"));
        // Without metadata, the version of this build.
        let out = render(&report_with(vec![]));
        assert!(
            out.starts_with(&format!(
                "{BOLD}LinuxDoctor {}{RESET} — host",
                crate::VERSION
            )),
            "{out}"
        );
    }

    #[test]
    fn healthy_module_has_no_incomplete_data_line() {
        let out = render(&report_with(vec![result("memory", &[])]));
        assert!(!out.contains("incomplete data"), "{out}");
    }

    #[test]
    fn stopped_command_is_shown_under_its_module_with_a_warning_symbol() {
        let out = render(&report_with(vec![result(
            "storage",
            &["'smartctl -a /dev/sda' did not finish within 20s and was stopped"],
        )]));
        assert!(
            out.contains("incomplete data: 'smartctl -a /dev/sda'"),
            "{out}"
        );
        // Not the clean-module symbol: data is missing.
        let storage_line = out
            .lines()
            .find(|l| l.contains("storage") && !l.contains("incomplete"))
            .unwrap();
        assert!(
            storage_line.contains(Severity::Warning.symbol()),
            "{storage_line}"
        );
    }

    #[test]
    fn one_line_recommendation_keeps_the_compact_form() {
        let out = format_recommendation("Check the logs.");
        assert!(out.contains("Recommendation: Check the logs."), "{out}");
    }

    #[test]
    fn numbered_steps_are_printed_under_a_heading_with_commands_on_their_own_lines() {
        let out = format_recommendation("1. Find the cause:\n    ps aux | head\n2. Restart it.");
        assert!(out.contains("Recommendation:"), "{out}");
        assert!(
            !out.contains("Recommendation: 1."),
            "heading stands alone: {out}"
        );
        assert!(out.contains("\n  1. Find the cause:\n"), "{out}");
        assert!(
            out.contains("\n      ps aux | head\n"),
            "commands stay indented under their step: {out}"
        );
        assert!(out.contains("\n  2. Restart it.\n"), "{out}");
    }

    #[test]
    fn notes_are_also_shown_for_a_module_that_failed() {
        let mut failed = result(
            "virtualization",
            &["'virsh list' did not finish within 10s and was stopped"],
        );
        failed.error = Some("could not run command".into());
        let out = render(&report_with(vec![failed]));
        assert!(out.contains("error: could not run command"), "{out}");
        assert!(out.contains("incomplete data: 'virsh list'"), "{out}");
    }

    #[test]
    fn text_from_the_audited_machine_cannot_act_on_the_terminal() {
        use crate::output::common::testkit::{hostile_report, unsafe_char, without_own_colours};
        let out = render_with(&hostile_report(), &RenderMeta::default());
        let foreign = without_own_colours(&out);
        assert_eq!(unsafe_char(&foreign), None, "{foreign:?}");
        // Neutralised, not removed: the reader still sees something happened.
        assert!(foreign.contains("?[2J"), "{foreign}");
        // Everything is shown: the failed module's error, the notes, the
        // evidence, both forms of recommendation.
        for shown in [
            "error ?",
            "note ?",
            "key ?",
            "value ?",
            "Recommendation: fix ?",
        ] {
            assert!(foreign.contains(shown), "{shown} missing from:\n{foreign}");
        }
    }
}
