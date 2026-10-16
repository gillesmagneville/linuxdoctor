// SPDX-License-Identifier: GPL-3.0-only

//! HTML report (`--output html`): one self-contained page, with its style
//! inline, no script and no external file, so it can be mailed, attached
//! to a ticket or archived as is. It only lays out `Finding`s it is given.
//!
//! Everything that comes from the audited machine (host name, instance
//! names, process names in evidence, tool error text...) is untrusted:
//! every dynamic string goes through `esc()`, and the page also carries a
//! Content-Security-Policy that forbids scripts, so even a missed escape
//! could not run code.

use crate::core::engine::{ModuleRunResult, Report};
use crate::models::{Finding, Severity};

use super::common::{
    display_safe, explanation_blocks, format_utc, format_utc_iso, module_status,
    parse_recommendation, severity_counts, Block, ModuleStatus, Recommendation, RenderMeta,
};

const STYLE: &str = r#"
:root{color-scheme:light dark;--bg:#fff;--fg:#1c2230;--muted:#586174;--line:#d5dbe5;--card:#f5f7fb;--code:#eaeef5;--info:#1c6e46;--warning:#8f5f00;--error:#b8322a;--critical:#8e1a4d;--link:#0b57c8}
@media (prefers-color-scheme:dark){:root{--bg:#12161d;--fg:#e6e9ef;--muted:#9ba5b6;--line:#2b3342;--card:#1a202b;--code:#232b39;--info:#58c68a;--warning:#e3b341;--error:#ff7b72;--critical:#ff7ab6;--link:#79b0ff}}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--fg);font:16px/1.55 system-ui,-apple-system,"Segoe UI",Roboto,sans-serif}
main{max-width:62rem;margin:0 auto;padding:1.5rem 1rem 3rem}
h1{margin:0;font-size:1.75rem}
h2{margin:2.2rem 0 .8rem;font-size:1.3rem;border-bottom:1px solid var(--line);padding-bottom:.3rem}
a{color:var(--link)}
code,pre{font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;font-size:.9em}
code{background:var(--code);padding:.05em .3em;border-radius:4px}
pre{background:var(--code);padding:.7rem .9rem;border-radius:6px;overflow-x:auto;margin:.5rem 0;white-space:pre}
pre code{background:none;padding:0;font-size:1em}
.host{margin:.1rem 0 1rem;font-size:1.15rem;color:var(--muted)}
.facts{display:grid;grid-template-columns:repeat(auto-fit,minmax(13rem,1fr));gap:.6rem;margin:0}
.facts div{background:var(--card);border:1px solid var(--line);border-radius:8px;padding:.5rem .8rem}
.facts dt{font-size:.8rem;color:var(--muted);text-transform:uppercase;letter-spacing:.04em}
.facts dd{margin:0;overflow-wrap:anywhere}
.banner{margin:1.2rem 0 0;padding:.7rem 1rem;border-left:4px solid var(--warning);background:var(--card);border-radius:4px}
.table-wrap{overflow-x:auto}
table{border-collapse:collapse;width:100%}
th,td{padding:.4rem .6rem;border-bottom:1px solid var(--line);text-align:left;vertical-align:top}
th{font-weight:600}
.summary td.n,.summary th.n{text-align:right;font-variant-numeric:tabular-nums}
.badge{display:inline-block;font-size:.78rem;font-weight:700;letter-spacing:.03em;padding:.05rem .5rem;border-radius:999px;border:1.5px solid currentColor;white-space:nowrap}
.sev-info .badge,.badge.sev-info{color:var(--info)}
.sev-warning .badge,.badge.sev-warning{color:var(--warning)}
.sev-error .badge,.badge.sev-error{color:var(--error)}
.sev-critical .badge,.badge.sev-critical{color:var(--critical)}
.muted{color:var(--muted)}
.note{margin:.4rem 0;padding:.4rem .8rem;border-left:4px solid var(--warning);background:var(--card);border-radius:4px}
.note.err{border-left-color:var(--error)}
details.finding{border:1px solid var(--line);border-left-width:5px;border-radius:8px;margin:.7rem 0;background:var(--card)}
details.sev-info{border-left-color:var(--info)}
details.sev-warning{border-left-color:var(--warning)}
details.sev-error{border-left-color:var(--error)}
details.sev-critical{border-left-color:var(--critical)}
details.finding>summary{cursor:pointer;padding:.6rem .9rem;display:flex;flex-wrap:wrap;gap:.5rem;align-items:center}
details.finding>summary .fid{font-family:ui-monospace,Menlo,Consolas,monospace;font-weight:600}
details.finding>summary .ftitle{font-weight:600}
.chip{font-size:.8rem;color:var(--muted);border:1px solid var(--line);border-radius:6px;padding:0 .4rem}
.body{padding:0 1rem 1rem;border-top:1px solid var(--line)}
.body h3{margin:1rem 0 .3rem;font-size:.85rem;text-transform:uppercase;letter-spacing:.05em;color:var(--muted)}
.evidence th{width:40%;font-weight:400}
.evidence code{overflow-wrap:anywhere}
.expl p{white-space:pre-line;margin:.5rem 0}
ol.steps{padding-left:1.4rem;margin:.3rem 0}
ol.steps li{margin:.5rem 0}
footer{margin-top:2.5rem;color:var(--muted);font-size:.9rem;border-top:1px solid var(--line);padding-top:1rem}
.short{display:none}
@media (max-width:560px){th,td{padding:.35rem .4rem}.summary{font-size:.85rem}.badge{font-size:.7rem;padding:.05rem .4rem}.full{display:none}.short{display:inline}.evidence tr{display:block;padding:.3rem 0;border-bottom:1px solid var(--line)}.evidence th,.evidence td{display:block;width:auto;border:0;padding:.05rem .4rem}}
@media print{body{font-size:12px}details.finding{break-inside:avoid}}
"#;

/// HTML-escapes text for element content and quoted attribute values.
fn esc(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&#39;"),
            _ => out.push(c),
        }
    }
    out
}

/// An id/fragment-safe version of a module id.
fn slug(s: &str) -> String {
    s.chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '-' || c == '_' {
                c
            } else {
                '-'
            }
        })
        .collect()
}

fn sev_class(sev: Severity) -> &'static str {
    match sev {
        Severity::Info => "sev-info",
        Severity::Warning => "sev-warning",
        Severity::Error => "sev-error",
        Severity::Critical => "sev-critical",
    }
}

fn badge(sev: Severity) -> String {
    format!(
        "<span class=\"badge {}\">{} {}</span>",
        sev_class(sev),
        sev.symbol(),
        sev
    )
}

pub fn render(report: &Report, meta: &RenderMeta) -> String {
    // See `markdown::render`: no control characters from the audited machine.
    let report = &display_safe(report);
    let ctx = &report.context;
    let mut out = String::new();

    out.push_str("<!DOCTYPE html>\n<html lang=\"en\">\n<head>\n<meta charset=\"utf-8\">\n");
    out.push_str(
        "<meta http-equiv=\"Content-Security-Policy\" content=\"default-src 'none'; \
         style-src 'unsafe-inline'; base-uri 'none'; form-action 'none'\">\n",
    );
    out.push_str("<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">\n");
    out.push_str(&format!(
        "<meta name=\"generator\" content=\"LinuxDoctor {}\">\n",
        esc(meta.tool_version)
    ));
    out.push_str(&format!(
        "<title>LinuxDoctor report \u{2014} {}</title>\n",
        esc(&ctx.hostname)
    ));
    out.push_str(&format!(
        "<style>{STYLE}</style>\n</head>\n<body>\n<main>\n"
    ));

    out.push_str("<header>\n<h1>LinuxDoctor report</h1>\n");
    out.push_str(&format!("<p class=\"host\">{}</p>\n", esc(&ctx.hostname)));
    out.push_str("<dl class=\"facts\">\n");
    let fact =
        |label: &str, value: String| format!("<div><dt>{label}</dt><dd>{value}</dd></div>\n");
    out.push_str(&fact(
        "Kernel",
        format!("<code>{}</code>", esc(&ctx.kernel_version)),
    ));
    out.push_str(&fact(
        "Distribution",
        esc(ctx.distro.as_deref().unwrap_or("unknown")),
    ));
    out.push_str(&fact(
        "Hardware",
        format!(
            "{} \u{00b7} {} CPUs \u{00b7} {} MB RAM",
            esc(&ctx.architecture),
            ctx.cpu_count,
            ctx.mem_total_kb / 1024
        ),
    ));
    out.push_str(&fact(
        "Generated",
        format!(
            "<time datetime=\"{}\">{}</time> by LinuxDoctor {}",
            format_utc_iso(meta.generated_at_unix),
            format_utc(meta.generated_at_unix),
            esc(meta.tool_version)
        ),
    ));
    out.push_str("</dl>\n</header>\n");

    if let Some(filter) = &meta.filter {
        out.push_str(&format!(
            "<p class=\"banner\" role=\"note\"><strong>Filtered view:</strong> only findings of \
             severity {} or above are shown; {} lower-severity finding(s) were hidden \
             (<code>--min-severity {}</code>).</p>\n",
            filter.min_severity,
            filter.hidden,
            filter.min_severity.to_string().to_lowercase()
        ));
    }

    out.push_str(
        "<section>\n<h2>Summary</h2>\n<div class=\"table-wrap\">\n<table class=\"summary\">\n<thead><tr>",
    );
    out.push_str("<th>Module</th><th>Status</th>");
    for (full, short) in [
        ("Critical", "Crit"),
        ("Error", "Err"),
        ("Warning", "Warn"),
        ("Info", "Info"),
    ] {
        out.push_str(&format!(
            "<th class=\"n\"><span class=\"full\">{full}</span><span class=\"short\">{short}</span></th>"
        ));
    }
    out.push_str("</tr></thead>\n<tbody>\n");
    for result in &report.results {
        out.push_str(&summary_row(result));
    }
    out.push_str("</tbody>\n</table>\n</div>\n</section>\n");

    let mut finding_index = 0usize;
    for result in &report.results {
        out.push_str(&module_section(result, meta, &mut finding_index));
    }

    out.push_str(&format!(
        "<footer><p>Read-only diagnostics: LinuxDoctor {} only reads system state. \
         Commands in recommendations are suggestions and are never run by the tool.</p></footer>\n",
        esc(meta.tool_version)
    ));
    out.push_str("</main>\n</body>\n</html>\n");
    out
}

fn status_cell(status: &ModuleStatus) -> String {
    match status {
        ModuleStatus::Skipped => "<span class=\"muted\">skipped</span>".to_string(),
        ModuleStatus::Failed(_) => format!(
            "<span class=\"badge sev-error\">{} failed</span>",
            "\u{2717}"
        ),
        ModuleStatus::Ran { worst, incomplete } => match worst {
            Some(sev) if *sev > Severity::Info => {
                let base = badge(*sev);
                if *incomplete {
                    format!("{base} <span class=\"muted\">(incomplete data)</span>")
                } else {
                    base
                }
            }
            // A tool was cut short, so "nothing found" cannot be trusted.
            _ if *incomplete => format!(
                "<span class=\"badge sev-warning\">{} INCOMPLETE DATA</span>",
                Severity::Warning.symbol()
            ),
            _ => badge(Severity::Info).replace(" INFO<", " OK<"),
        },
    }
}

fn summary_row(result: &ModuleRunResult) -> String {
    let status = module_status(result);
    let counts: [String; 4] = match status {
        ModuleStatus::Skipped | ModuleStatus::Failed(_) => {
            std::array::from_fn(|_| "\u{2013}".to_string())
        }
        ModuleStatus::Ran { .. } => severity_counts(result).map(|n| n.to_string()),
    };
    let mut row = format!(
        "<tr><td><a href=\"#mod-{}\">{}</a></td><td>{}</td>",
        esc(&slug(result.module_id)),
        esc(result.module_id),
        status_cell(&status)
    );
    for c in &counts {
        row.push_str(&format!("<td class=\"n\">{c}</td>"));
    }
    row.push_str("</tr>\n");
    row
}

fn module_section(result: &ModuleRunResult, meta: &RenderMeta, index: &mut usize) -> String {
    let status = module_status(result);
    let mut out = format!(
        "<section class=\"module\" id=\"mod-{}\">\n<h2>{}</h2>\n",
        esc(&slug(result.module_id)),
        esc(result.module_id)
    );

    match &status {
        ModuleStatus::Skipped => {
            out.push_str(
                "<p class=\"muted\">Skipped: this module does not apply to this system.</p>\n</section>\n",
            );
            return out;
        }
        ModuleStatus::Failed(err) => {
            out.push_str(&format!(
                "<p class=\"note err\"><strong>Error:</strong> the module could not run: <code>{}</code></p>\n</section>\n",
                esc(err)
            ));
            return out;
        }
        ModuleStatus::Ran { .. } => {}
    }

    for note in &result.notes {
        out.push_str(&format!(
            "<p class=\"note\" role=\"note\">\u{21b3} <strong>Incomplete data:</strong> {}</p>\n",
            esc(note)
        ));
    }

    if result.findings.is_empty() {
        match &meta.filter {
            Some(f) => out.push_str(&format!(
                "<p class=\"muted\">No findings at {} or above.</p>\n",
                f.min_severity
            )),
            None => out.push_str("<p class=\"muted\">No findings.</p>\n"),
        }
    }
    for finding in &result.findings {
        *index += 1;
        out.push_str(&finding_block(finding, *index));
    }
    out.push_str("</section>\n");
    out
}

fn finding_block(f: &Finding, index: usize) -> String {
    let open = if f.severity > Severity::Info {
        " open"
    } else {
        ""
    };
    let mut out = format!(
        "<details class=\"finding {}\" id=\"f{index}\"{open}>\n<summary>{} <span class=\"fid\">{}</span> <span class=\"ftitle\">{}</span>",
        sev_class(f.severity),
        badge(f.severity),
        esc(&f.id),
        esc(&f.title)
    );
    if let Some(instance) = &f.instance {
        out.push_str(&format!(" <span class=\"chip\">{}</span>", esc(instance)));
    }
    out.push_str("</summary>\n<div class=\"body\">\n");
    out.push_str(&format!(
        "<p class=\"muted\">Confidence {}% ({})</p>\n",
        f.confidence.percent,
        esc(&f.confidence.reason)
    ));

    if !f.evidence.is_empty() {
        out.push_str(
            "<h3>Evidence</h3>\n<div class=\"table-wrap\"><table class=\"evidence\"><tbody>\n",
        );
        for (key, value) in &f.evidence {
            out.push_str(&format!(
                "<tr><th scope=\"row\"><code>{}</code></th><td><code>{}</code></td></tr>\n",
                esc(key),
                esc(value)
            ));
        }
        out.push_str("</tbody></table></div>\n");
    }

    let blocks = explanation_blocks(&f.explanation);
    if !blocks.is_empty() {
        out.push_str("<h3>Explanation</h3>\n<div class=\"expl\">\n");
        for block in blocks {
            match block {
                Block::Paragraph(text) => {
                    out.push_str(&format!("<p>{}</p>\n", esc(&text)));
                }
                Block::Preformatted(lines) => {
                    out.push_str(&format!("<pre>{}</pre>\n", esc(&lines.join("\n"))));
                }
            }
        }
        out.push_str("</div>\n");
    }

    if let Some(rec) = &f.recommendation {
        out.push_str("<h3>Recommendation</h3>\n");
        match parse_recommendation(rec) {
            Recommendation::Inline(text) => {
                out.push_str(&format!("<p>{}</p>\n", esc(text)));
            }
            Recommendation::Text(text) => {
                out.push_str(&format!("<pre>{}</pre>\n", esc(text)));
            }
            Recommendation::Steps(steps) => {
                out.push_str("<ol class=\"steps\">\n");
                for step in &steps {
                    out.push_str(&format!("<li>{}", esc(&step.text)));
                    if !step.commands.is_empty() {
                        out.push_str(&format!(
                            "<pre><code>{}</code></pre>",
                            esc(&step.commands.join("\n"))
                        ));
                    }
                    out.push_str("</li>\n");
                }
                out.push_str("</ol>\n");
            }
        }
    }

    out.push_str("</div>\n</details>\n");
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

    fn rich_finding() -> Finding {
        Finding::builder(
            "MEM009",
            "Memory Pressure",
            Category::Memory,
            Severity::Warning,
            Confidence::new(85, "strong indication"),
        )
        .evidence("swap_used_kb", "4200000")
        .explanation(
            "The system is swapping.\n\nWhere it goes:\n  Programs   191 MB   2.4%\n  Cache      714 MB   8.9%\n\nClosing remark.",
        )
        .recommendation(
            "1. See who is in swap:\n    grep -H VmSwap /proc/[0-9]*/status | head\n2. Check live activity:\n    vmstat 1 5\n3. Add RAM.",
        )
        .instance("Swap")
        .build()
    }

    // ----- document shell -------------------------------------------------

    #[test]
    fn page_is_a_complete_self_contained_document() {
        let html = render(&report(vec![]), &meta());
        assert!(html.starts_with("<!DOCTYPE html>\n<html lang=\"en\">"));
        assert!(html.contains("<meta charset=\"utf-8\">"));
        assert!(html.contains("name=\"viewport\""));
        assert!(html.contains("<title>LinuxDoctor report \u{2014} web01</title>"));
        assert!(html.trim_end().ends_with("</html>"));
        assert!(html.contains("<style>"));
        assert!(html.contains("prefers-color-scheme:dark"));
        // No script, no external resource of any kind.
        assert!(!html.contains("<script"));
        assert!(!html.contains("<link"));
        assert!(!html.contains("src="));
        assert!(!html.contains("http://") && !html.contains("https://"));
    }

    #[test]
    fn content_security_policy_forbids_scripts_and_network() {
        let html = render(&report(vec![]), &meta());
        assert!(html.contains("Content-Security-Policy"));
        assert!(html.contains("default-src 'none'"));
        assert!(!html.contains("script-src"));
    }

    #[test]
    fn facts_describe_the_machine_and_the_run() {
        let html = render(&report(vec![]), &meta());
        assert!(html.contains("<code>6.8.0-31-generic</code>"));
        assert!(html.contains("Ubuntu 24.04"));
        assert!(html.contains("x86_64 \u{00b7} 8 CPUs \u{00b7} 16000 MB RAM"));
        assert!(html.contains(
            "<time datetime=\"2026-10-14T06:30:00Z\">2026-10-14 06:30:00 UTC</time> by LinuxDoctor 9.9.9"
        ));
        assert!(html.contains("never run by the tool"));
    }

    // ----- summary ----------------------------------------------------------

    #[test]
    fn summary_links_to_module_sections_and_counts_findings() {
        let html = render(
            &report(vec![
                module(
                    "memory",
                    vec![
                        finding("M1", Severity::Warning),
                        finding("M2", Severity::Info),
                    ],
                ),
                module("cpu", vec![finding("C1", Severity::Critical)]),
            ]),
            &meta(),
        );
        assert!(
            html.contains("<a href=\"#mod-memory\">memory</a>"),
            "{html}"
        );
        assert!(html.contains("id=\"mod-memory\""));
        assert!(
            html.contains("<td class=\"n\">0</td><td class=\"n\">0</td><td class=\"n\">1</td><td class=\"n\">1</td></tr>"),
            "{html}"
        );
        assert!(html.contains("badge sev-critical"));
    }

    #[test]
    fn clean_skipped_failed_and_incomplete_modules_are_labelled() {
        let mut failed = module("net", vec![]);
        failed.error = Some("cannot read /proc/net".into());
        let mut skipped = module("ntp", vec![]);
        skipped.skipped = true;
        let mut noted = module("virt", vec![finding("V1", Severity::Info)]);
        noted.notes = vec!["virsh list did not finish within 10s".into()];
        let html = render(
            &report(vec![
                module("cpu", vec![finding("C1", Severity::Info)]),
                failed,
                skipped,
                noted,
            ]),
            &meta(),
        );
        assert!(html.contains("\u{2713} OK</span>"), "{html}");
        assert!(html.contains("\u{2717} failed"));
        assert!(html.contains("<span class=\"muted\">skipped</span>"));
        assert!(html.contains("\u{26a0} INCOMPLETE DATA</span>"), "{html}");
        assert!(html.contains("<strong>Incomplete data:</strong> virsh list did not finish"));
        assert!(html.contains("the module could not run: <code>cannot read /proc/net</code>"));
        assert!(html.contains("Skipped: this module does not apply to this system."));
    }

    #[test]
    fn a_real_problem_with_incomplete_data_keeps_its_severity() {
        let mut m = module("storage", vec![finding("S1", Severity::Error)]);
        m.notes = vec!["smartctl did not finish".into()];
        let html = render(&report(vec![m]), &meta());
        assert!(html.contains("badge sev-error"));
        assert!(html.contains("(incomplete data)"));
        assert!(!html.contains("INCOMPLETE DATA"));
    }

    #[test]
    fn filter_banner_and_empty_module_message() {
        let mut meta = meta();
        meta.filter = Some(FilterInfo {
            min_severity: Severity::Error,
            hidden: 4,
        });
        let html = render(&report(vec![module("cpu", vec![])]), &meta);
        assert!(html
            .contains("<strong>Filtered view:</strong> only findings of severity ERROR or above"));
        assert!(html.contains(
            "4 lower-severity finding(s) were hidden (<code>--min-severity error</code>)"
        ));
        assert!(html.contains("No findings at ERROR or above."));
        let plain = render(&report(vec![module("cpu", vec![])]), &self::meta());
        assert!(plain.contains("No findings.</p>"));
        assert!(!plain.contains("Filtered view"));
    }

    // ----- findings ---------------------------------------------------------

    #[test]
    fn problems_are_expanded_and_info_is_collapsed() {
        let html = render(
            &report(vec![module(
                "m",
                vec![
                    finding("W1", Severity::Warning),
                    finding("I1", Severity::Info),
                    finding("E1", Severity::Error),
                ],
            )]),
            &meta(),
        );
        assert!(html.contains("<details class=\"finding sev-warning\" id=\"f1\" open>"));
        assert!(html.contains("<details class=\"finding sev-info\" id=\"f2\">"));
        assert!(html.contains("<details class=\"finding sev-error\" id=\"f3\" open>"));
    }

    #[test]
    fn finding_ids_are_unique_across_modules() {
        let html = render(
            &report(vec![
                module("a", vec![finding("X1", Severity::Info)]),
                module("b", vec![finding("X1", Severity::Info)]),
            ]),
            &meta(),
        );
        assert!(html.contains("id=\"f1\""));
        assert!(html.contains("id=\"f2\""));
        assert_eq!(html.matches("id=\"f1\"").count(), 1);
    }

    #[test]
    fn finding_shows_badge_id_title_section_confidence_and_evidence() {
        let html = render(
            &report(vec![module("memory", vec![rich_finding()])]),
            &meta(),
        );
        assert!(html.contains("<span class=\"badge sev-warning\">\u{26a0} WARNING</span>"));
        assert!(html.contains("<span class=\"fid\">MEM009</span>"));
        assert!(html.contains("<span class=\"ftitle\">Memory Pressure</span>"));
        assert!(html.contains("<span class=\"chip\">Swap</span>"));
        assert!(html.contains("Confidence 85% (strong indication)"));
        assert!(html.contains(
            "<tr><th scope=\"row\"><code>swap_used_kb</code></th><td><code>4200000</code></td></tr>"
        ));
    }

    #[test]
    fn explanation_prose_is_paragraphs_and_tables_are_preformatted() {
        let html = render(
            &report(vec![module("memory", vec![rich_finding()])]),
            &meta(),
        );
        assert!(html.contains("<p>The system is swapping.</p>"), "{html}");
        assert!(
            html.contains("<pre>Programs   191 MB   2.4%\nCache      714 MB   8.9%</pre>"),
            "{html}"
        );
        assert!(html.contains("<p>Closing remark.</p>"));
    }

    #[test]
    fn steps_become_an_ordered_list_with_command_blocks() {
        let html = render(
            &report(vec![module("memory", vec![rich_finding()])]),
            &meta(),
        );
        assert!(html.contains("<ol class=\"steps\">"));
        assert!(
            html.contains("<li>See who is in swap:<pre><code>grep -H VmSwap /proc/[0-9]*/status | head</code></pre></li>"),
            "{html}"
        );
        assert!(html.contains("<li>Check live activity:<pre><code>vmstat 1 5</code></pre></li>"));
        assert!(html.contains("<li>Add RAM.</li>"));
    }

    #[test]
    fn single_line_and_unstructured_recommendations() {
        let one = Finding::builder(
            "X1",
            "T",
            Category::Memory,
            Severity::Warning,
            Confidence::direct_observation(),
        )
        .recommendation("Add more RAM.")
        .build();
        let multi = Finding::builder(
            "X2",
            "T",
            Category::Memory,
            Severity::Warning,
            Confidence::direct_observation(),
        )
        .recommendation("Line one.\nLine two.")
        .build();
        let html = render(&report(vec![module("m", vec![one, multi])]), &meta());
        assert!(
            html.contains("<h3>Recommendation</h3>\n<p>Add more RAM.</p>"),
            "{html}"
        );
        assert!(html.contains("<pre>Line one.\nLine two.</pre>"));
    }

    #[test]
    fn finding_without_optional_parts_has_no_empty_sections() {
        let html = render(
            &report(vec![module("m", vec![finding("X1", Severity::Info)])]),
            &meta(),
        );
        assert!(!html.contains("<h3>Evidence</h3>"));
        assert!(!html.contains("<h3>Explanation</h3>"));
        assert!(!html.contains("<h3>Recommendation</h3>"));
        assert!(!html.contains("class=\"chip\""));
    }

    // ----- escaping ---------------------------------------------------------

    #[test]
    fn escaping_covers_the_five_special_characters() {
        assert_eq!(
            esc("<a href=\"x\">'&'</a>"),
            "&lt;a href=&quot;x&quot;&gt;&#39;&amp;&#39;&lt;/a&gt;"
        );
        assert_eq!(esc("plain \u{00e9}\u{2014}"), "plain \u{00e9}\u{2014}");
    }

    #[test]
    fn slug_keeps_ids_fragment_safe() {
        assert_eq!(slug("memory"), "memory");
        assert_eq!(slug("a b\"c<d"), "a-b-c-d");
    }

    /// Every `<` in the page must open one of our own template tags: any
    /// markup coming from the audited machine would show up here as an
    /// unknown tag name.
    fn assert_only_template_tags(html: &str) {
        const ALLOWED: &[&str] = &[
            "html", "head", "meta", "title", "style", "body", "main", "header", "h1", "h2", "h3",
            "dl", "div", "dt", "dd", "code", "time", "p", "section", "table", "thead", "tbody",
            "tr", "th", "td", "a", "details", "summary", "span", "pre", "ol", "li", "strong",
            "footer",
        ];
        // The stylesheet contains `>` selectors but no `<`.
        let mut rest = html;
        while let Some(pos) = rest.find('<') {
            let after = &rest[pos + 1..];
            let name: String = after
                .trim_start_matches(['/', '!'])
                .chars()
                .take_while(|c| c.is_ascii_alphanumeric())
                .collect();
            assert!(
                name.eq_ignore_ascii_case("doctype") || ALLOWED.contains(&name.as_str()),
                "unexpected tag <{name}> near: {}",
                &rest[pos..(pos + 60).min(rest.len())]
            );
            rest = after;
        }
    }

    #[test]
    fn hostile_content_cannot_inject_markup_or_script() {
        let attack = "<script>alert(1)</script>\"><img src=x onerror=alert(1)>";
        let mut failed = module("net", vec![]);
        failed.error = Some(attack.into());
        let mut noted = module("virt", vec![]);
        noted.notes = vec![attack.into()];
        let evil = Finding::builder(
            attack,
            attack,
            Category::Memory,
            Severity::Critical,
            Confidence::new(80, attack),
        )
        .evidence(attack, attack)
        .explanation(format!("{attack}\n\nTable:\n  {attack}"))
        .recommendation(format!("1. {attack}\n    {attack}\n2. {attack}"))
        .instance(attack)
        .build();
        let mut r = report(vec![module("memory", vec![evil]), failed, noted]);
        r.context.hostname = attack.into();
        r.context.kernel_version = attack.into();
        r.context.distro = Some(attack.into());
        r.context.architecture = attack.into();
        let html = render(&r, &meta());

        assert_only_template_tags(&html);
        assert!(!html.contains("<script"));
        assert!(!html.contains("<img"));
        assert!(html.contains("&lt;script&gt;alert(1)&lt;/script&gt;&quot;&gt;&lt;img"));
        // The attack string is still shown, escaped, everywhere it was given.
        assert!(html.matches("&lt;script&gt;").count() >= 15, "{html}");
    }

    #[test]
    fn hostile_module_id_cannot_break_out_of_attributes() {
        // Module ids are static strings today, but the renderer must not
        // depend on that.
        let r = report(vec![module("x\"onmouseover=\"alert(1)", vec![])]);
        let html = render(&r, &meta());
        assert!(!html.contains("onmouseover=\"alert"), "{html}");
        assert!(
            html.contains("id=\"mod-x-onmouseover--alert-1-\""),
            "{html}"
        );
        assert_only_template_tags(&html);
    }

    #[test]
    fn output_is_stable_for_identical_input() {
        let r = report(vec![module("memory", vec![rich_finding()])]);
        assert_eq!(render(&r, &meta()), render(&r, &meta()));
    }

    #[test]
    fn text_from_the_audited_machine_has_no_control_characters() {
        use crate::output::common::testkit::{hostile_report, unsafe_char};
        let out = render(&hostile_report(), &RenderMeta::default());
        assert_eq!(unsafe_char(&out), None, "{out:?}");
        assert!(out.contains("EVIL"), "{out}");
    }
}
