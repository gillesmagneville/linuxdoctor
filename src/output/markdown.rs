// SPDX-License-Identifier: GPL-3.0-only

//! Markdown report (`--output markdown`): meant to be pasted into an issue,
//! a wiki or a ticket, or committed next to a change. Like every renderer
//! it only lays out `Finding`s it is given.
//!
//! Everything that comes from the machine being audited (host name,
//! instance names, process names in evidence, tool error text...) is
//! treated as untrusted text: inline text is backslash-escaped, values
//! are put in code spans, and tables or code fences cannot be broken out
//! of by the content.

use crate::core::engine::{ModuleRunResult, Report};
use crate::models::{Finding, Severity};

use super::common::{
    explanation_blocks, format_utc, module_status, parse_recommendation, severity_counts, Block,
    ModuleStatus, Recommendation, RenderMeta,
};

pub fn render(report: &Report, meta: &RenderMeta) -> String {
    let mut out = String::new();
    let ctx = &report.context;

    out.push_str(&format!(
        "# LinuxDoctor report \u{2014} {}\n\n",
        escape_text(&ctx.hostname)
    ));
    out.push_str(&format!(
        "- **Kernel:** {}\n",
        code_span(&ctx.kernel_version)
    ));
    out.push_str(&format!(
        "- **Distribution:** {}\n",
        escape_text(ctx.distro.as_deref().unwrap_or("unknown"))
    ));
    out.push_str(&format!(
        "- **Hardware:** {} \u{00b7} {} CPUs \u{00b7} {} MB RAM\n",
        escape_text(&ctx.architecture),
        ctx.cpu_count,
        ctx.mem_total_kb / 1024
    ));
    out.push_str(&format!(
        "- **Generated:** {} by LinuxDoctor {}\n\n",
        format_utc(meta.generated_at_unix),
        meta.tool_version
    ));

    if let Some(filter) = &meta.filter {
        out.push_str(&format!(
            "> **Filtered view:** only findings of severity {} or above are shown; \
             {} lower-severity finding(s) were hidden (`--min-severity {}`).\n\n",
            filter.min_severity,
            filter.hidden,
            filter.min_severity.to_string().to_lowercase()
        ));
    }

    out.push_str("## Summary\n\n");
    out.push_str("| Module | Status | Critical | Error | Warning | Info |\n");
    out.push_str("|---|---|---:|---:|---:|---:|\n");
    for result in &report.results {
        out.push_str(&summary_row(result));
    }
    out.push('\n');

    for result in &report.results {
        out.push_str(&module_section(result, meta));
    }

    out.push_str(&format!(
        "---\n\n*Read-only diagnostics: LinuxDoctor {} only reads system state. \
         Commands in recommendations are suggestions and are never run by the tool.*\n",
        meta.tool_version
    ));
    out
}

fn status_label(status: &ModuleStatus) -> String {
    match status {
        ModuleStatus::Skipped => "skipped".to_string(),
        ModuleStatus::Failed(_) => "\u{2717} failed".to_string(),
        ModuleStatus::Ran { worst, incomplete } => match worst {
            Some(sev) if *sev > Severity::Info => {
                let base = format!("{} {}", sev.symbol(), title_case(*sev));
                if *incomplete {
                    format!("{base} (incomplete data)")
                } else {
                    base
                }
            }
            // A tool was cut short, so "nothing found" cannot be trusted:
            // not a clean check mark (the terminal output does the same).
            _ if *incomplete => format!("{} Incomplete data", Severity::Warning.symbol()),
            _ => format!("{} OK", Severity::Info.symbol()),
        },
    }
}

fn title_case(sev: Severity) -> &'static str {
    match sev {
        Severity::Info => "Info",
        Severity::Warning => "Warning",
        Severity::Error => "Error",
        Severity::Critical => "Critical",
    }
}

fn summary_row(result: &ModuleRunResult) -> String {
    let status = module_status(result);
    let counts = match status {
        ModuleStatus::Skipped | ModuleStatus::Failed(_) => {
            std::array::from_fn(|_| "\u{2013}".to_string())
        }
        ModuleStatus::Ran { .. } => severity_counts(result).map(|n| n.to_string()),
    };
    format!(
        "| {} | {} | {} | {} | {} | {} |\n",
        table_cell(result.module_id),
        table_cell(&status_label(&status)),
        counts[0],
        counts[1],
        counts[2],
        counts[3]
    )
}

fn module_section(result: &ModuleRunResult, meta: &RenderMeta) -> String {
    let status = module_status(result);
    let mut out = String::new();
    let marker = match &status {
        ModuleStatus::Ran { worst, .. } => worst.map(|s| s.symbol()).unwrap_or("\u{2713}"),
        ModuleStatus::Failed(_) => "\u{2717}",
        ModuleStatus::Skipped => "",
    };
    out.push_str(&format!("## {}", escape_text(result.module_id)));
    if !marker.is_empty() {
        out.push_str(&format!(" {marker}"));
    }
    out.push_str("\n\n");

    match &status {
        ModuleStatus::Skipped => {
            out.push_str("_Skipped: this module does not apply to this system._\n\n");
            return out;
        }
        ModuleStatus::Failed(err) => {
            out.push_str(&format!(
                "**Error:** the module could not run: {}\n\n",
                code_span(err)
            ));
            return out;
        }
        ModuleStatus::Ran { .. } => {}
    }

    for note in &result.notes {
        out.push_str(&format!(
            "> \u{21b3} **Incomplete data:** {}\n",
            escape_text(note)
        ));
    }
    if !result.notes.is_empty() {
        out.push('\n');
    }

    if result.findings.is_empty() {
        match &meta.filter {
            Some(f) => out.push_str(&format!(
                "_No findings at {} or above._\n\n",
                f.min_severity
            )),
            None => out.push_str("_No findings._\n\n"),
        }
        return out;
    }

    for finding in &result.findings {
        out.push_str(&finding_section(finding));
    }
    out
}

fn finding_section(f: &Finding) -> String {
    let mut out = String::new();
    out.push_str(&format!(
        "### {} {} \u{2014} {}\n\n",
        f.severity.symbol(),
        escape_text(&f.id),
        escape_text(&f.title)
    ));
    out.push_str(&format!(
        "**{}** \u{00b7} Confidence {}% ({})",
        f.severity,
        f.confidence.percent,
        escape_text(&f.confidence.reason)
    ));
    if let Some(instance) = &f.instance {
        out.push_str(&format!(" \u{00b7} Section: {}", escape_text(instance)));
    }
    out.push_str("\n\n");

    if !f.evidence.is_empty() {
        out.push_str("**Evidence**\n\n");
        for (key, value) in &f.evidence {
            out.push_str(&format!("- {}: {}\n", code_span(key), code_span(value)));
        }
        out.push('\n');
    }

    let blocks = explanation_blocks(&f.explanation);
    if !blocks.is_empty() {
        out.push_str("**Explanation**\n\n");
        for block in blocks {
            match block {
                Block::Paragraph(text) => {
                    out.push_str(&escape_block_text(&text));
                    out.push_str("\n\n");
                }
                Block::Preformatted(lines) => {
                    out.push_str(&fenced("", &lines, ""));
                    out.push('\n');
                }
            }
        }
    }

    if let Some(rec) = &f.recommendation {
        out.push_str("**Recommendation**\n\n");
        match parse_recommendation(rec) {
            Recommendation::Inline(text) => {
                out.push_str(&escape_block_text(text));
                out.push_str("\n\n");
            }
            Recommendation::Text(text) => {
                let lines: Vec<String> = text.lines().map(str::to_string).collect();
                out.push_str(&fenced("", &lines, ""));
                out.push('\n');
            }
            Recommendation::Steps(steps) => {
                for (i, step) in steps.iter().enumerate() {
                    let marker = format!("{}. ", i + 1);
                    out.push_str(&format!("{marker}{}\n", escape_text(&step.text)));
                    if !step.commands.is_empty() {
                        let indent = " ".repeat(marker.len());
                        out.push('\n');
                        out.push_str(&fenced("bash", &step.commands, &indent));
                    }
                    out.push('\n');
                }
            }
        }
    }
    out
}

// ---------------------------------------------------------------------------
// Escaping and code
// ---------------------------------------------------------------------------

/// Escapes inline text so Markdown shows it literally: backslash, backtick,
/// asterisk, square brackets and `<` (which could start an HTML tag or an
/// autolink). Newlines become spaces. Underscores are left alone: inside
/// words, as in `vm.dirty_ratio`, they are not emphasis.
fn escape_text(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '\\' | '`' | '*' | '[' | ']' | '<' => {
                out.push('\\');
                out.push(c);
            }
            '\n' | '\r' => out.push(' '),
            _ => out.push(c),
        }
    }
    out
}

/// Like `escape_text` but keeps line breaks and also protects a line that
/// would otherwise open a heading (`#`) or a quote (`>`).
fn escape_block_text(s: &str) -> String {
    s.lines()
        .map(|line| {
            let escaped = escape_text(line);
            if escaped.starts_with(['#', '>']) {
                format!("\\{escaped}")
            } else {
                escaped
            }
        })
        .collect::<Vec<_>>()
        .join("\n")
}

/// A Markdown table cell: escaped, with `|` and line breaks neutralised.
fn table_cell(s: &str) -> String {
    escape_text(s).replace('|', "\\|")
}

/// Longest run of consecutive backticks in `s`.
fn longest_backtick_run(s: &str) -> usize {
    let mut longest = 0;
    let mut current = 0;
    for c in s.chars() {
        if c == '`' {
            current += 1;
            longest = longest.max(current);
        } else {
            current = 0;
        }
    }
    longest
}

/// An inline code span that survives any content: the delimiter is one
/// backtick longer than the longest run inside, with padding spaces when
/// the content starts or ends with a backtick.
fn code_span(s: &str) -> String {
    let flat: String = s
        .chars()
        .map(|c| if c == '\n' || c == '\r' { ' ' } else { c })
        .collect();
    if flat.is_empty() {
        return "` `".to_string();
    }
    let fence = "`".repeat(longest_backtick_run(&flat) + 1);
    let pad = if flat.starts_with('`') || flat.ends_with('`') || flat.trim().is_empty() {
        " "
    } else {
        ""
    };
    format!("{fence}{pad}{flat}{pad}{fence}")
}

/// A fenced code block whose fence is longer than any backtick run inside,
/// every line prefixed with `indent` (for use inside a list item).
fn fenced(lang: &str, lines: &[String], indent: &str) -> String {
    let longest = lines
        .iter()
        .map(|l| longest_backtick_run(l))
        .max()
        .unwrap_or(0);
    let fence = "`".repeat((longest + 1).max(3));
    let mut out = format!("{indent}{fence}{lang}\n");
    for line in lines {
        if line.is_empty() {
            out.push('\n');
        } else {
            out.push_str(&format!("{indent}{line}\n"));
        }
    }
    out.push_str(&format!("{indent}{fence}\n"));
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::context::Context;
    use crate::models::{Category, Confidence};
    use crate::output::common::FilterInfo;

    fn meta() -> RenderMeta {
        RenderMeta {
            tool_version: "9.9.9",
            generated_at_unix: 1_791_959_400,
            filter: None,
        }
    }

    fn finding(id: &str, sev: Severity) -> Finding {
        Finding::builder(
            id,
            "A Title",
            Category::Memory,
            sev,
            Confidence::direct_observation(),
        )
        .build()
    }

    fn module(id: &'static str, findings: Vec<Finding>) -> ModuleRunResult {
        ModuleRunResult {
            module_id: id,
            findings,
            error: None,
            skipped: false,
            notes: vec![],
        }
    }

    fn report(results: Vec<ModuleRunResult>) -> Report {
        Report {
            context: Context {
                hostname: "web01".into(),
                kernel_version: "6.8.0-31-generic".into(),
                distro: Some("Ubuntu 24.04".into()),
                architecture: "x86_64".into(),
                cpu_count: 8,
                mem_total_kb: 16_384_000,
                boot_time_unix: 0,
            },
            results,
        }
    }

    // ----- header, summary, footer -------------------------------------

    #[test]
    fn header_and_footer_describe_the_machine_and_the_run() {
        let md = render(&report(vec![]), &meta());
        assert!(
            md.starts_with("# LinuxDoctor report \u{2014} web01\n"),
            "{md}"
        );
        assert!(md.contains("- **Kernel:** `6.8.0-31-generic`"));
        assert!(md.contains("- **Distribution:** Ubuntu 24.04"));
        assert!(md.contains("x86_64 \u{00b7} 8 CPUs \u{00b7} 16000 MB RAM"));
        assert!(md.contains("- **Generated:** 2026-10-14 06:30:00 UTC by LinuxDoctor 9.9.9"));
        assert!(md.contains("never run by the tool"));
    }

    #[test]
    fn summary_table_has_one_row_per_module_with_counts() {
        let md = render(
            &report(vec![
                module(
                    "memory",
                    vec![
                        finding("M1", Severity::Warning),
                        finding("M2", Severity::Info),
                        finding("M3", Severity::Info),
                    ],
                ),
                module("cpu", vec![finding("C1", Severity::Critical)]),
            ]),
            &meta(),
        );
        assert!(md.contains("| Module | Status | Critical | Error | Warning | Info |"));
        assert!(
            md.contains("| memory | \u{26a0} Warning | 0 | 0 | 1 | 2 |"),
            "{md}"
        );
        assert!(
            md.contains("| cpu | \u{2757} Critical | 1 | 0 | 0 | 0 |"),
            "{md}"
        );
    }

    #[test]
    fn clean_module_is_ok_and_skipped_or_failed_have_dashes() {
        let mut failed = module("net", vec![]);
        failed.error = Some("boom".into());
        let mut skipped = module("ntp", vec![]);
        skipped.skipped = true;
        let md = render(
            &report(vec![
                module("cpu", vec![finding("C1", Severity::Info)]),
                failed,
                skipped,
            ]),
            &meta(),
        );
        assert!(md.contains("| cpu | \u{2713} OK | 0 | 0 | 0 | 1 |"), "{md}");
        assert!(
            md.contains("| net | \u{2717} failed | \u{2013} | \u{2013} | \u{2013} | \u{2013} |")
        );
        assert!(md.contains("| ntp | skipped |"));
    }

    #[test]
    fn incomplete_data_is_flagged_in_the_summary_and_the_section() {
        let mut m = module("virtualization", vec![finding("V1", Severity::Info)]);
        m.notes = vec!["`virsh list` did not finish within 10s".into()];
        let md = render(&report(vec![m]), &meta());
        assert!(
            md.contains("| virtualization | \u{26a0} Incomplete data |"),
            "{md}"
        );
        assert!(md.contains("> \u{21b3} **Incomplete data:** \\`virsh list\\` did not finish"));
    }

    #[test]
    fn a_real_problem_with_incomplete_data_keeps_its_severity() {
        let mut m = module("storage", vec![finding("S1", Severity::Error)]);
        m.notes = vec!["smartctl did not finish".into()];
        let md = render(&report(vec![m]), &meta());
        assert!(
            md.contains("| storage | \u{2717} Error (incomplete data) |"),
            "{md}"
        );
        assert!(!md.contains("Incomplete data |"));
    }

    #[test]
    fn filter_banner_and_empty_module_message() {
        let mut meta = meta();
        meta.filter = Some(FilterInfo {
            min_severity: Severity::Warning,
            hidden: 7,
        });
        let md = render(&report(vec![module("cpu", vec![])]), &meta);
        assert!(md.contains("> **Filtered view:** only findings of severity WARNING or above"));
        assert!(md.contains("7 lower-severity finding(s) were hidden (`--min-severity warning`)"));
        assert!(md.contains("_No findings at WARNING or above._"));
    }

    #[test]
    fn unfiltered_empty_module_says_no_findings() {
        let md = render(&report(vec![module("cpu", vec![])]), &meta());
        assert!(md.contains("_No findings._"));
        assert!(!md.contains("Filtered view"));
    }

    #[test]
    fn failed_and_skipped_sections_explain_themselves() {
        let mut failed = module("net", vec![]);
        failed.error = Some("cannot read /proc/net".into());
        let mut skipped = module("ntp", vec![]);
        skipped.skipped = true;
        let md = render(&report(vec![failed, skipped]), &meta());
        assert!(md.contains("## net \u{2717}\n"), "{md}");
        assert!(md.contains("**Error:** the module could not run: `cannot read /proc/net`"));
        assert!(md.contains("## ntp\n"));
        assert!(md.contains("_Skipped: this module does not apply to this system._"));
    }

    // ----- findings ------------------------------------------------------

    fn rich_finding() -> Finding {
        Finding::builder(
            "MEM009",
            "Memory Pressure",
            Category::Memory,
            Severity::Warning,
            Confidence::new(85, "strong indication"),
        )
        .evidence("swap_used_kb", "4200000")
        .evidence("top_process", "chrome (PID 2100)")
        .explanation(
            "The system is <swapping> a lot.\n\nWhere it goes:\n  Programs   191 MB   2.4%\n  Cache      714 MB   8.9%\n\nClosing remark.",
        )
        .recommendation(
            "1. See who is in swap:\n    grep -H VmSwap /proc/[0-9]*/status | sort -k2 -n -r | head\n2. Check live activity:\n    vmstat 1 5\n3. Add RAM.",
        )
        .instance("Swap")
        .build()
    }

    #[test]
    fn finding_heading_severity_confidence_and_section() {
        let md = render(
            &report(vec![module("memory", vec![rich_finding()])]),
            &meta(),
        );
        assert!(
            md.contains("### \u{26a0} MEM009 \u{2014} Memory Pressure\n"),
            "{md}"
        );
        assert!(md.contains(
            "**WARNING** \u{00b7} Confidence 85% (strong indication) \u{00b7} Section: Swap"
        ));
    }

    #[test]
    fn evidence_is_a_list_of_code_spans() {
        let md = render(
            &report(vec![module("memory", vec![rich_finding()])]),
            &meta(),
        );
        assert!(md.contains("- `swap_used_kb`: `4200000`\n"));
        assert!(md.contains("- `top_process`: `chrome (PID 2100)`\n"));
    }

    #[test]
    fn explanation_prose_is_escaped_and_tables_are_fenced() {
        let md = render(
            &report(vec![module("memory", vec![rich_finding()])]),
            &meta(),
        );
        assert!(md.contains("The system is \\<swapping> a lot.\n"), "{md}");
        assert!(
            md.contains("```\nPrograms   191 MB   2.4%\nCache      714 MB   8.9%\n```\n"),
            "{md}"
        );
        assert!(md.contains("Closing remark.\n"));
    }

    #[test]
    fn numbered_steps_get_indented_bash_blocks() {
        let md = render(
            &report(vec![module("memory", vec![rich_finding()])]),
            &meta(),
        );
        assert!(
            md.contains(
                "1. See who is in swap:\n\n   ```bash\n   grep -H VmSwap /proc/[0-9]*/status | sort -k2 -n -r | head\n   ```\n"
            ),
            "{md}"
        );
        assert!(md.contains("2. Check live activity:\n\n   ```bash\n   vmstat 1 5\n   ```\n"));
        assert!(md.contains("\n3. Add RAM.\n"));
    }

    #[test]
    fn ten_or_more_steps_indent_their_blocks_under_the_wider_marker() {
        let rec = (1..=10)
            .map(|i| format!("{i}. step {i}\n    cmd{i}"))
            .collect::<Vec<_>>()
            .join("\n");
        let f = Finding::builder(
            "X1",
            "T",
            Category::Memory,
            Severity::Warning,
            Confidence::direct_observation(),
        )
        .recommendation(rec)
        .build();
        let md = render(&report(vec![module("m", vec![f])]), &meta());
        assert!(
            md.contains("10. step 10\n\n    ```bash\n    cmd10\n    ```\n"),
            "{md}"
        );
    }

    #[test]
    fn single_line_recommendation_is_a_paragraph() {
        let f = Finding::builder(
            "X1",
            "T",
            Category::Memory,
            Severity::Warning,
            Confidence::direct_observation(),
        )
        .recommendation("Add more RAM.")
        .build();
        let md = render(&report(vec![module("m", vec![f])]), &meta());
        assert!(md.contains("**Recommendation**\n\nAdd more RAM.\n"));
    }

    #[test]
    fn unstructured_multiline_recommendation_is_fenced() {
        let f = Finding::builder(
            "X1",
            "T",
            Category::Memory,
            Severity::Warning,
            Confidence::direct_observation(),
        )
        .recommendation("Line one.\nLine two.")
        .build();
        let md = render(&report(vec![module("m", vec![f])]), &meta());
        assert!(
            md.contains("**Recommendation**\n\n```\nLine one.\nLine two.\n```\n"),
            "{md}"
        );
    }

    #[test]
    fn finding_without_optional_parts_has_only_the_heading_lines() {
        let md = render(
            &report(vec![module("m", vec![finding("X1", Severity::Info)])]),
            &meta(),
        );
        assert!(!md.contains("**Evidence**"));
        assert!(!md.contains("**Explanation**"));
        assert!(!md.contains("**Recommendation**"));
        assert!(!md.contains("Section:"));
    }

    // ----- escaping and hostile input ------------------------------------

    #[test]
    fn hostile_text_cannot_inject_markup() {
        let mut r = report(vec![module(
            "m",
            vec![Finding::builder(
                "X1",
                "Title [link](http://evil) *b*",
                Category::Memory,
                Severity::Warning,
                Confidence::direct_observation(),
            )
            .evidence("k`ey", "va`lue ``` x")
            .explanation("# not a heading\n> not a quote <script>alert(1)</script>")
            .instance("/mnt/<b>x</b>")
            .build()],
        )]);
        r.context.hostname = "evil\n# injected".into();
        let md = render(&r, &meta());
        assert!(
            md.contains("# LinuxDoctor report \u{2014} evil # injected\n"),
            "{md}"
        );
        assert!(md.contains("Title \\[link\\](http://evil) \\*b\\*"), "{md}");
        assert!(
            md.contains("\\# not a heading\n\\> not a quote \\<script>alert(1)\\</script>"),
            "{md}"
        );
        assert!(md.contains("Section: /mnt/\\<b>x\\</b>"));
        // The evidence value contains a run of three backticks: the span
        // must use a longer delimiter.
        assert!(md.contains("- ``k`ey``: ````va`lue ``` x````"), "{md}");
        // Every `<` outside code is backslash-escaped, so no tag survives.
        for (i, c) in md.char_indices() {
            if c == '<' {
                assert!(md[..i].ends_with('\\'), "unescaped < at {i}: {md}");
            }
        }
    }

    #[test]
    fn table_cells_cannot_break_the_table() {
        let mut m = module("a|b", vec![finding("X1", Severity::Info)]);
        m.notes = vec!["x".into()];
        let md = render(&report(vec![m]), &meta());
        assert!(md.contains("| a\\|b |"), "{md}");
    }

    #[test]
    fn code_fence_grows_past_backticks_in_content() {
        let block = fenced("", &["a ``` b".to_string()], "");
        assert_eq!(block, "````\na ``` b\n````\n");
        assert_eq!(
            fenced("bash", &["x".to_string()], "  "),
            "  ```bash\n  x\n  ```\n"
        );
    }

    #[test]
    fn code_span_handles_edges() {
        assert_eq!(code_span("plain"), "`plain`");
        assert_eq!(code_span("a`b"), "``a`b``");
        assert_eq!(code_span("`x"), "`` `x ``");
        assert_eq!(code_span(""), "` `");
        assert_eq!(code_span("two\nlines"), "`two lines`");
    }

    #[test]
    fn output_is_stable_for_identical_input() {
        let r = report(vec![module("memory", vec![rich_finding()])]);
        assert_eq!(render(&r, &meta()), render(&r, &meta()));
    }
}
