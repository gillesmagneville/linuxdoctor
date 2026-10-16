// SPDX-License-Identifier: GPL-3.0-only

//! End-to-end checks of the export formats and the severity options, with
//! the real binary and the real machine. Only the memory module runs: it is
//! always available, quick, and always reports at least one Info finding
//! (the overview), which is what makes the expectations below deterministic
//! on any host without depending on how healthy that host is.

use std::process::{Command, Output};

fn run(args: &[&str]) -> Output {
    let mut full = vec!["audit", "--modules", "memory"];
    full.extend_from_slice(args);
    Command::new(env!("CARGO_BIN_EXE_linuxdoctor"))
        // Never the configuration file of whoever runs the tests.
        .env("XDG_CONFIG_HOME", "/nonexistent")
        .args(full)
        .output()
        .expect("linuxdoctor binary should start")
}

fn stdout(o: &Output) -> String {
    String::from_utf8(o.stdout.clone()).expect("stdout is UTF-8")
}

fn stderr(o: &Output) -> String {
    String::from_utf8_lossy(&o.stderr).to_string()
}

fn json(o: &Output) -> serde_json::Value {
    serde_json::from_slice(&o.stdout).unwrap_or_else(|e| {
        panic!(
            "stdout was not JSON ({e}): {}\nstderr: {}",
            stdout(o),
            stderr(o)
        )
    })
}

fn severities(report: &serde_json::Value) -> Vec<String> {
    report["results"]
        .as_array()
        .unwrap()
        .iter()
        .flat_map(|r| r["findings"].as_array().unwrap().iter())
        .map(|f| f["severity"].as_str().unwrap().to_string())
        .collect()
}

// ----- export formats ------------------------------------------------------

#[test]
fn markdown_report_is_a_complete_document() {
    let o = run(&["--output", "markdown"]);
    let md = stdout(&o);
    assert!(md.starts_with("# LinuxDoctor report \u{2014} "), "{md}");
    assert!(md.contains("\n## Summary\n"));
    assert!(md.contains("| memory |"));
    assert!(md.contains("\n## memory"));
    assert!(md.contains("### "), "finding headings are present");
    assert!(
        !md.contains('\x1b'),
        "no terminal colour codes in a document"
    );
    assert!(stderr(&o).is_empty(), "{}", stderr(&o));
}

#[test]
fn md_is_an_alias_for_markdown() {
    let a = stdout(&run(&["--output", "md"]));
    assert!(a.starts_with("# LinuxDoctor report"));
}

#[test]
fn html_report_is_one_self_contained_page() {
    let o = run(&["--output", "html"]);
    let html = stdout(&o);
    assert!(html.starts_with("<!DOCTYPE html>"), "{html}");
    assert!(html.trim_end().ends_with("</html>"));
    assert!(html.contains("<title>LinuxDoctor report \u{2014} "));
    assert!(html.contains("<details class=\"finding"));
    assert!(!html.contains("<script"));
    assert!(!html.contains("<link"));
    assert!(!html.contains('\x1b'));
    assert!(stderr(&o).is_empty(), "{}", stderr(&o));
}

// ----- --min-severity ----------------------------------------------------------

#[test]
fn min_severity_critical_keeps_only_critical_findings_and_says_so() {
    let o = run(&["--output", "json", "--min-severity", "critical"]);
    let report = json(&o);
    assert!(severities(&report).iter().all(|s| s == "critical"));
    assert_eq!(report["filter"]["min_severity"], "critical");
    assert!(
        report["filter"]["hidden_findings"].as_u64().unwrap() >= 1,
        "the memory overview (Info) is always hidden by this filter: {report}"
    );
    // The module itself is still listed.
    assert_eq!(report["results"][0]["module_id"], "memory");
}

#[test]
fn min_severity_info_hides_nothing_but_still_declares_the_filter() {
    let report = json(&run(&["--output", "json", "--min-severity", "info"]));
    assert_eq!(report["filter"]["min_severity"], "info");
    assert_eq!(report["filter"]["hidden_findings"], 0);
}

#[test]
fn no_filter_means_no_filter_key() {
    let report = json(&run(&["--output", "json"]));
    assert!(report.get("filter").is_none());
}

#[test]
fn terminal_markdown_and_html_all_announce_a_filter() {
    let term = stdout(&run(&["--min-severity", "critical"]));
    assert!(term.contains("hidden (--min-severity critical)"), "{term}");
    let md = stdout(&run(&[
        "--output",
        "markdown",
        "--min-severity",
        "critical",
    ]));
    assert!(md.contains("> **Filtered view:**"), "{md}");
    let html = stdout(&run(&["--output", "html", "--min-severity", "critical"]));
    assert!(html.contains("<strong>Filtered view:</strong>"), "{html}");
}

// ----- --fail-on -------------------------------------------------------------------

#[test]
fn fail_on_info_fails_because_the_overview_always_exists() {
    let o = run(&["--output", "json", "--fail-on", "info"]);
    assert_eq!(o.status.code(), Some(1), "{}", stderr(&o));
    let err = stderr(&o);
    assert!(err.contains("--fail-on info"), "{err}");
    assert!(err.contains("exiting with status 1"), "{err}");
    // stdout stays clean, parseable JSON.
    json(&o);
}

#[test]
fn fail_on_never_always_succeeds() {
    let o = run(&["--output", "json", "--fail-on", "never"]);
    assert_eq!(o.status.code(), Some(0), "{}", stderr(&o));
    assert!(stderr(&o).is_empty(), "{}", stderr(&o));
}

#[test]
fn exit_status_matches_the_findings_for_every_threshold() {
    // One run per threshold; each run's own findings decide the expected
    // status, so this holds whatever state the host is in.
    for (word, rank) in [("info", 0), ("warning", 1), ("error", 2), ("critical", 3)] {
        let o = run(&["--output", "json", "--fail-on", word]);
        let worst = severities(&json(&o))
            .iter()
            .map(|s| match s.as_str() {
                "info" => 0,
                "warning" => 1,
                "error" => 2,
                _ => 3,
            })
            .max();
        let expected = if worst.is_some_and(|w| w >= rank) {
            1
        } else {
            0
        };
        assert_eq!(
            o.status.code(),
            Some(expected),
            "--fail-on {word}: {}",
            stderr(&o)
        );
    }
}

#[test]
fn display_filter_never_changes_the_exit_status() {
    // The full report has an Info finding, so `--fail-on info` fails even
    // though `--min-severity critical` shows nothing from it.
    let o = run(&[
        "--output",
        "json",
        "--fail-on",
        "info",
        "--min-severity",
        "critical",
    ]);
    assert_eq!(o.status.code(), Some(1), "{}", stderr(&o));
    assert!(severities(&json(&o)).iter().all(|s| s == "critical"));
}

#[test]
fn without_fail_on_the_historic_error_threshold_applies_silently() {
    let o = run(&["--output", "json"]);
    let has_error = severities(&json(&o))
        .iter()
        .any(|s| s == "error" || s == "critical");
    assert_eq!(o.status.code(), Some(if has_error { 1 } else { 0 }));
    assert!(
        stderr(&o).is_empty(),
        "the default gate has no stderr message"
    );
}

// ----- argument errors ---------------------------------------------------------------

#[test]
fn unknown_severity_word_is_a_usage_error() {
    let o = run(&["--min-severity", "high"]);
    assert_eq!(o.status.code(), Some(2));
    assert!(stderr(&o).contains("--min-severity"), "{}", stderr(&o));
    let o = run(&["--fail-on", "fatal"]);
    assert_eq!(o.status.code(), Some(2));
}

#[test]
fn unknown_output_format_is_a_usage_error() {
    let o = run(&["--output", "pdf"]);
    assert_eq!(o.status.code(), Some(2));
}
