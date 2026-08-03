use crate::core::engine::Report;
use crate::models::Severity;

const RESET: &str = "\x1b[0m";
const DIM: &str = "\x1b[2m";
const BOLD: &str = "\x1b[1m";

/// Renders a Report as human-readable terminal output. Only formats
/// `Finding`s it's given — never computes severity, confidence, or
/// evidence itself. See ARCHITECTURE.md "Output Engine".
pub fn render(report: &Report) -> String {
    let mut out = String::new();

    out.push_str(&format!(
        "{BOLD}LinuxDoctor{RESET} — {}\n",
        report.context.hostname
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
            continue;
        }
        let worst = result.findings.iter().map(|f| f.severity).max();
        let (symbol, color) = match worst {
            Some(sev) if sev > Severity::Info => (sev.symbol(), sev.ansi_color()),
            _ => (Severity::Info.symbol(), Severity::Info.ansi_color()),
        };
        out.push_str(&format!("{color}{symbol} {}{RESET}\n", result.module_id));
    }
    out.push('\n');

    // Full detail for anything above INFO.
    for finding in report.all_findings().filter(|f| f.severity > Severity::Info) {
        out.push_str(&render_finding(finding));
        out.push('\n');
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
        s.push_str(&format!("\n{DIM}Recommendation: {rec}{RESET}\n"));
    }
    s
}
