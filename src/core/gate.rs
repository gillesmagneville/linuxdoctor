// SPDX-License-Identifier: GPL-3.0-only

//! The pass/fail decision behind the process exit status (`--fail-on`).
//! Pure: it only counts findings, so it is tested without running an audit.

use crate::core::engine::Report;
use crate::models::Severity;

/// Severity from which the exit status becomes 1 when `--fail-on` is not
/// given. This has always been the behaviour (Error and Critical fail),
/// so it stays the default.
pub const DEFAULT_FAIL_ON: Severity = Severity::Error;

/// Outcome of comparing a report against a `--fail-on` threshold.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GateResult {
    /// `None` means "never fail on findings".
    pub threshold: Option<Severity>,
    /// Findings at or above the threshold.
    pub failing: usize,
}

impl GateResult {
    pub fn failed(&self) -> bool {
        self.failing > 0
    }

    /// One-line explanation for stderr, only when the gate failed.
    pub fn message(&self) -> Option<String> {
        let threshold = self.threshold?;
        if self.failing == 0 {
            return None;
        }
        Some(format!(
            "{} finding(s) at {} or above (--fail-on {}); exiting with status 1",
            self.failing,
            threshold,
            threshold.to_string().to_lowercase()
        ))
    }
}

/// Counts the report's findings against `threshold`. The whole report is
/// judged: a `--min-severity` display filter is applied *after* this, so
/// hiding findings from the output never changes the exit status.
pub fn evaluate(report: &Report, threshold: Option<Severity>) -> GateResult {
    let failing = threshold.map_or(0, |t| report.count_at_or_above(t));
    GateResult { threshold, failing }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::context::Context;
    use crate::core::engine::ModuleRunResult;
    use crate::models::{Category, Confidence, Finding};

    fn report(severities: &[Severity]) -> Report {
        Report {
            context: Context {
                hostname: "h".into(),
                kernel_version: "6".into(),
                distro: None,
                architecture: "x86_64".into(),
                cpu_count: 1,
                mem_total_kb: 1024,
                boot_time_unix: 0,
            },
            results: vec![ModuleRunResult {
                module_id: "m",
                findings: severities
                    .iter()
                    .map(|&s| {
                        Finding::builder(
                            "X1",
                            "t",
                            Category::Memory,
                            s,
                            Confidence::direct_observation(),
                        )
                        .build()
                    })
                    .collect(),
                error: None,
                skipped: false,
                notes: vec![],
            }],
        }
    }

    #[test]
    fn default_threshold_is_error_as_it_always_was() {
        assert_eq!(DEFAULT_FAIL_ON, Severity::Error);
        let warn_only = report(&[Severity::Info, Severity::Warning]);
        assert!(!evaluate(&warn_only, Some(DEFAULT_FAIL_ON)).failed());
        let with_error = report(&[Severity::Warning, Severity::Error]);
        assert!(evaluate(&with_error, Some(DEFAULT_FAIL_ON)).failed());
        let with_critical = report(&[Severity::Critical]);
        assert!(evaluate(&with_critical, Some(DEFAULT_FAIL_ON)).failed());
    }

    #[test]
    fn lower_thresholds_fail_on_lower_findings() {
        let r = report(&[Severity::Info, Severity::Warning]);
        assert!(evaluate(&r, Some(Severity::Warning)).failed());
        assert!(evaluate(&r, Some(Severity::Info)).failed());
        assert!(!evaluate(&r, Some(Severity::Error)).failed());
        assert!(!evaluate(&r, Some(Severity::Critical)).failed());
    }

    #[test]
    fn info_threshold_fails_on_any_finding_but_not_on_an_empty_report() {
        assert!(evaluate(&report(&[Severity::Info]), Some(Severity::Info)).failed());
        assert!(!evaluate(&report(&[]), Some(Severity::Info)).failed());
    }

    #[test]
    fn never_does_not_fail_even_on_critical() {
        let r = report(&[Severity::Critical, Severity::Error]);
        let g = evaluate(&r, None);
        assert!(!g.failed());
        assert_eq!(g.failing, 0);
        assert_eq!(g.message(), None);
    }

    #[test]
    fn counts_every_finding_at_or_above() {
        let r = report(&[
            Severity::Info,
            Severity::Warning,
            Severity::Warning,
            Severity::Error,
        ]);
        assert_eq!(evaluate(&r, Some(Severity::Warning)).failing, 3);
    }

    #[test]
    fn message_names_count_level_and_flag() {
        let r = report(&[Severity::Warning, Severity::Critical]);
        let g = evaluate(&r, Some(Severity::Warning));
        assert_eq!(
            g.message().unwrap(),
            "2 finding(s) at WARNING or above (--fail-on warning); exiting with status 1"
        );
    }

    #[test]
    fn no_message_when_the_gate_passes() {
        let r = report(&[Severity::Info]);
        assert_eq!(evaluate(&r, Some(Severity::Error)).message(), None);
    }
}
