// SPDX-License-Identifier: GPL-3.0-only

//! `linuxdoctor diff`, with the real binary. The reports are written by the
//! tests (small literal documents in the JSON report format), except in the
//! first tests, which also check that `diff` reads what `audit` really writes.

use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};

use serde_json::{json, Value};

/// A throwaway directory for the report files of one test.
struct Dir {
    path: PathBuf,
}

impl Dir {
    fn new(name: &str) -> Self {
        let path =
            std::env::temp_dir().join(format!("linuxdoctor-diff-{name}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&path);
        fs::create_dir_all(&path).unwrap();
        Dir { path }
    }

    /// Writes `report` as `name` and returns the path, as a string.
    fn write(&self, name: &str, report: &Value) -> String {
        self.write_text(name, &report.to_string())
    }

    fn write_text(&self, name: &str, text: &str) -> String {
        let path = self.path.join(name);
        fs::write(&path, text).unwrap();
        path.to_string_lossy().into_owned()
    }
}

impl Drop for Dir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.path);
    }
}

fn run(args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_linuxdoctor"))
        .args(args)
        .output()
        .expect("linuxdoctor binary should start")
}

/// Runs with `stdin` as standard input.
fn run_with_stdin(args: &[&str], stdin: &str) -> Output {
    let mut child = Command::new(env!("CARGO_BIN_EXE_linuxdoctor"))
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("linuxdoctor binary should start");
    child
        .stdin
        .take()
        .unwrap()
        .write_all(stdin.as_bytes())
        // The program may exit without reading its input (a usage error).
        .ok();
    child.wait_with_output().unwrap()
}

fn stdout(o: &Output) -> String {
    String::from_utf8(o.stdout.clone()).expect("stdout is UTF-8")
}

fn stderr(o: &Output) -> String {
    String::from_utf8_lossy(&o.stderr).to_string()
}

/// The terminal text without the colour sequences the program adds.
fn plain(o: &Output) -> String {
    let text = stdout(o);
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

// ----- literal reports -------------------------------------------------------------------

fn finding(id: &str, severity: &str) -> Value {
    json!({
        "id": id,
        "title": format!("Title of {id}"),
        "category": "security",
        "severity": severity,
        "confidence": {"level": "high"},
        "evidence": [],
        "explanation": "x",
        "recommendation": null,
        "instance": null,
    })
}

fn module(id: &str, findings: Vec<Value>) -> Value {
    json!({"module_id": id, "findings": findings, "error": null, "skipped": false, "notes": []})
}

fn failed_module(id: &str, error: &str) -> Value {
    json!({"module_id": id, "findings": [], "error": error, "skipped": false, "notes": []})
}

fn report(modules: Vec<Value>) -> Value {
    json!({
        "schema_version": 1,
        "context": {
            "hostname": "web01", "kernel_version": "6.8.0-31", "distro": "Ubuntu 24.04",
            "architecture": "x86_64", "cpu_count": 4, "mem_total_kb": 8_388_608,
            "boot_time_unix": 1_000_000,
        },
        "results": modules,
    })
}

// ----- the reports `audit` really writes -----------------------------------------------------

fn real_report() -> Value {
    let o = run(&["audit", "--modules", "memory", "--output", "json"]);
    serde_json::from_slice(&o.stdout).expect("audit writes a JSON report")
}

#[test]
fn a_real_report_compared_with_itself_has_no_change() {
    let dir = Dir::new("real-same");
    let file = dir.write("audit.json", &real_report());
    let o = run(&["diff", &file, &file]);
    assert_eq!(o.status.code(), Some(0), "{}", stderr(&o));
    assert!(plain(&o).contains("No change in the"), "{}", plain(&o));
    assert!(stderr(&o).is_empty(), "{}", stderr(&o));
}

#[test]
fn a_real_report_with_a_finding_made_critical_is_a_regression() {
    let dir = Dir::new("real-worse");
    let before = real_report();
    let mut after = before.clone();
    after["results"][0]["findings"][0]["severity"] = json!("critical");
    // The memory module always reports at least one finding; if it were to
    // report none the premise of this test would be gone.
    assert!(before["results"][0]["findings"][0].is_object());
    let (a, b) = (dir.write("a.json", &before), dir.write("b.json", &after));
    let o = run(&["diff", &a, &b]);
    assert_eq!(o.status.code(), Some(1), "{}", stderr(&o));
    assert!(plain(&o).contains("Got worse (1)"), "{}", plain(&o));
}

// ----- exit status ---------------------------------------------------------------------------

#[test]
fn a_finding_that_got_worse_exits_1_and_says_what_changed() {
    let dir = Dir::new("worse");
    let a = dir.write(
        "a.json",
        &report(vec![module("m", vec![finding("X1", "warning")])]),
    );
    let b = dir.write(
        "b.json",
        &report(vec![module("m", vec![finding("X1", "error")])]),
    );
    let o = run(&["diff", &a, &b]);
    assert_eq!(o.status.code(), Some(1));
    let text = plain(&o);
    assert!(text.contains("Got worse (1)"), "{text}");
    assert!(text.contains("warning → error"), "{text}");
    assert!(text.contains("X1"), "{text}");
    // The default gate has always been silent, as for `audit`.
    assert!(stderr(&o).is_empty(), "{}", stderr(&o));
}

#[test]
fn a_new_serious_finding_exits_1() {
    let dir = Dir::new("new");
    let a = dir.write("a.json", &report(vec![module("m", vec![])]));
    let b = dir.write(
        "b.json",
        &report(vec![module("m", vec![finding("N1", "critical")])]),
    );
    let o = run(&["diff", &a, &b]);
    assert_eq!(o.status.code(), Some(1));
    assert!(plain(&o).contains("new (critical)"), "{}", plain(&o));
}

#[test]
fn getting_better_exits_0() {
    let dir = Dir::new("better");
    let a = dir.write(
        "a.json",
        &report(vec![module(
            "m",
            vec![finding("GONE", "critical"), finding("DOWN", "error")],
        )]),
    );
    let b = dir.write(
        "b.json",
        &report(vec![module("m", vec![finding("DOWN", "info")])]),
    );
    let o = run(&["diff", &a, &b]);
    assert_eq!(o.status.code(), Some(0), "{}", stderr(&o));
    let text = plain(&o);
    assert!(text.contains("Got better (2)"), "{text}");
    assert!(text.contains("resolved (was critical)"), "{text}");
    assert!(text.contains("error → info"), "{text}");
}

#[test]
fn a_serious_finding_that_did_not_change_is_not_a_regression() {
    // That is the business of `audit --fail-on`, not of a comparison.
    let dir = Dir::new("still");
    let r = report(vec![module("m", vec![finding("OLD", "critical")])]);
    let (a, b) = (dir.write("a.json", &r), dir.write("b.json", &r));
    assert_eq!(run(&["diff", &a, &b]).status.code(), Some(0));
}

#[test]
fn fail_on_moves_the_threshold_and_explains_itself_when_given() {
    let dir = Dir::new("fail-on");
    let a = dir.write(
        "a.json",
        &report(vec![module("m", vec![finding("X1", "info")])]),
    );
    let b = dir.write(
        "b.json",
        &report(vec![module("m", vec![finding("X1", "warning")])]),
    );

    // Warning is below the default threshold (error).
    assert_eq!(run(&["diff", &a, &b]).status.code(), Some(0));

    let o = run(&["diff", &a, &b, "--fail-on", "warning"]);
    assert_eq!(o.status.code(), Some(1));
    let message = stderr(&o);
    assert!(message.contains("--fail-on warning"), "{message}");
    assert!(message.contains("status 1"), "{message}");

    assert_eq!(
        run(&["diff", &a, &b, "--fail-on", "critical"])
            .status
            .code(),
        Some(0)
    );
    assert_eq!(
        run(&["diff", &a, &b, "--fail-on", "never"]).status.code(),
        Some(0)
    );
}

#[test]
fn never_means_never_even_for_a_critical_regression() {
    let dir = Dir::new("never");
    let a = dir.write("a.json", &report(vec![module("m", vec![])]));
    let b = dir.write(
        "b.json",
        &report(vec![module("m", vec![finding("N1", "critical")])]),
    );
    let o = run(&["diff", &a, &b, "--fail-on", "never"]);
    assert_eq!(o.status.code(), Some(0));
    assert!(plain(&o).contains("new (critical)"), "{}", plain(&o));
}

#[test]
fn min_severity_hides_changes_but_never_the_exit_status() {
    let dir = Dir::new("min-severity");
    let a = dir.write(
        "a.json",
        &report(vec![module("m", vec![finding("LOW", "info")])]),
    );
    let b = dir.write(
        "b.json",
        &report(vec![module(
            "m",
            vec![finding("LOW", "warning"), finding("BAD", "error")],
        )]),
    );
    let o = run(&["diff", &a, &b, "--min-severity", "critical"]);
    assert_eq!(o.status.code(), Some(1), "an Error appeared");
    let text = plain(&o);
    assert!(!text.contains("BAD"), "{text}");
    assert!(
        text.contains("2 changes below critical hidden (--min-severity critical)"),
        "{text}"
    );
}

// ----- incomplete data is never good news ---------------------------------------------------------

#[test]
fn a_module_that_failed_is_not_compared_and_nothing_is_called_resolved() {
    let dir = Dir::new("failed");
    let a = dir.write(
        "a.json",
        &report(vec![
            module("network", vec![finding("NET1", "critical")]),
            module("memory", vec![finding("MEM1", "info")]),
        ]),
    );
    let b = dir.write(
        "b.json",
        &report(vec![
            failed_module("network", "cannot read /proc/net/dev"),
            module("memory", vec![finding("MEM1", "info")]),
        ]),
    );
    let o = run(&["diff", &a, &b]);
    assert_eq!(o.status.code(), Some(0), "{}", stderr(&o));
    let text = plain(&o);
    assert!(!text.contains("resolved"), "{text}");
    assert!(!text.contains("Got better"), "{text}");
    assert!(text.contains("Not compared (1)"), "{text}");
    assert!(
        text.contains("second report: failed (cannot read /proc/net/dev)"),
        "{text}"
    );
    assert!(
        text.contains("1 finding in the first report could not be re-checked"),
        "{text}"
    );
}

#[test]
fn a_module_missing_from_one_report_is_not_compared() {
    let dir = Dir::new("missing-module");
    let a = dir.write(
        "a.json",
        &report(vec![
            module("memory", vec![finding("MEM1", "warning")]),
            module("cpu", vec![finding("CPU1", "error")]),
        ]),
    );
    // Written with `--modules memory`: cpu was simply not run.
    let b = dir.write(
        "b.json",
        &report(vec![module("memory", vec![finding("MEM1", "warning")])]),
    );
    let o = run(&["diff", &a, &b]);
    assert_eq!(o.status.code(), Some(0));
    let text = plain(&o);
    assert!(text.contains("Not compared (1)"), "{text}");
    assert!(text.contains("second report: not in the report"), "{text}");
    assert!(!text.contains("resolved"), "{text}");
}

#[test]
fn reports_of_two_machines_are_flagged() {
    let dir = Dir::new("machines");
    let mut other = report(vec![module("m", vec![])]);
    other["context"]["hostname"] = json!("db02");
    let a = dir.write("a.json", &report(vec![module("m", vec![])]));
    let b = dir.write("b.json", &other);
    let text = plain(&run(&["diff", &a, &b]));
    assert!(text.contains("different machines"), "{text}");
}

// ----- standard input ---------------------------------------------------------------------------

#[test]
fn either_report_can_come_from_standard_input() {
    let dir = Dir::new("stdin");
    let worse = report(vec![module("m", vec![finding("X1", "critical")])]);
    let fine = report(vec![module("m", vec![])]);
    let file = dir.write("file.json", &fine);

    let o = run_with_stdin(&["diff", &file, "-"], &worse.to_string());
    assert_eq!(o.status.code(), Some(1), "{}", stderr(&o));
    let text = plain(&o);
    assert!(text.contains("standard input"), "{text}");
    assert!(text.contains("new (critical)"), "{text}");

    let o = run_with_stdin(&["diff", "-", &file], &worse.to_string());
    assert_eq!(o.status.code(), Some(0), "{}", stderr(&o));
    assert!(plain(&o).contains("resolved (was critical)"));
}

#[test]
fn standard_input_cannot_be_both_reports() {
    let o = run_with_stdin(&["diff", "-", "-"], "{}");
    assert_eq!(o.status.code(), Some(2));
    assert!(
        stderr(&o).contains("only one of the two reports"),
        "{}",
        stderr(&o)
    );
    assert!(o.stdout.is_empty());
}

// ----- reports that cannot be compared: exit 2, with a message naming the file ----------------------

#[test]
fn a_missing_file_exits_2_and_names_it() {
    let dir = Dir::new("nofile");
    let good = dir.write("good.json", &report(vec![]));
    let o = run(&["diff", &good, "/nonexistent/after.json"]);
    assert_eq!(o.status.code(), Some(2));
    assert!(
        stderr(&o).contains("/nonexistent/after.json"),
        "{}",
        stderr(&o)
    );
    assert!(o.stdout.is_empty());
}

#[test]
fn a_directory_exits_2() {
    let dir = Dir::new("directory");
    let good = dir.write("good.json", &report(vec![]));
    let o = run(&["diff", &good, &dir.path.to_string_lossy()]);
    assert_eq!(o.status.code(), Some(2));
    assert!(!stderr(&o).is_empty());
}

#[test]
fn something_that_is_not_a_report_exits_2_with_a_hint() {
    let dir = Dir::new("not-a-report");
    let good = dir.write("good.json", &report(vec![]));
    for (name, text) in [
        ("empty.json", ""),
        ("text.json", "this is not JSON"),
        ("list.json", "[1, 2, 3]"),
        ("other.json", r#"{"hello": "world"}"#),
    ] {
        let bad = dir.write_text(name, text);
        let o = run(&["diff", &good, &bad]);
        assert_eq!(o.status.code(), Some(2), "{name}: {}", stderr(&o));
        let message = stderr(&o);
        assert!(message.contains(name), "{name}: {message}");
        assert!(
            message.contains("linuxdoctor audit --output json"),
            "{name}: {message}"
        );
        assert!(o.stdout.is_empty(), "{name}");
    }
}

#[test]
fn a_report_from_a_newer_version_is_refused_not_guessed_at() {
    let dir = Dir::new("newer");
    let good = dir.write("good.json", &report(vec![]));
    let newer = dir.write(
        "newer.json",
        &json!({"schema_version": 99, "something": "entirely different"}),
    );
    let o = run(&["diff", &good, &newer]);
    assert_eq!(o.status.code(), Some(2));
    let message = stderr(&o);
    assert!(message.contains("newer.json"), "{message}");
    assert!(message.contains("upgrade"), "{message}");
}

#[test]
fn keys_this_version_does_not_know_are_ignored() {
    let dir = Dir::new("unknown-keys");
    let mut r = report(vec![module("m", vec![finding("X1", "warning")])]);
    r["added_in_the_future"] = json!({"anything": [1, 2, 3]});
    r["results"][0]["findings"][0]["new_field"] = json!("x");
    let (a, b) = (dir.write("a.json", &r), dir.write("b.json", &r));
    let o = run(&["diff", &a, &b]);
    assert_eq!(o.status.code(), Some(0), "{}", stderr(&o));
}

#[test]
fn both_reports_are_required() {
    let dir = Dir::new("usage");
    let good = dir.write("good.json", &report(vec![]));
    assert_eq!(run(&["diff", &good]).status.code(), Some(2));
    assert_eq!(run(&["diff"]).status.code(), Some(2));
}

// ----- output formats ----------------------------------------------------------------------------

fn worse_pair(dir: &Dir) -> (String, String) {
    let a = dir.write(
        "a.json",
        &report(vec![module("m", vec![finding("X1", "warning")])]),
    );
    let b = dir.write(
        "b.json",
        &report(vec![module(
            "m",
            vec![finding("X1", "error"), finding("N1", "info")],
        )]),
    );
    (a, b)
}

#[test]
fn json_output_is_a_versioned_document() {
    let dir = Dir::new("json");
    let (a, b) = worse_pair(&dir);
    let o = run(&["diff", &a, &b, "--output", "json"]);
    assert_eq!(
        o.status.code(),
        Some(1),
        "the exit status does not depend on the format"
    );
    let text = stdout(&o);
    assert!(
        text.lines()
            .nth(1)
            .unwrap()
            .trim()
            .starts_with("\"schema_version\": 1"),
        "{text}"
    );
    let v: Value = serde_json::from_str(&text).expect("valid JSON");
    assert_eq!(v["kind"], "comparison");
    assert_eq!(v["summary"]["worse"], 1);
    assert_eq!(v["summary"]["other"], 1);
    assert_eq!(v["changes"][0]["id"], "X1");
    assert_eq!(v["changes"][0]["section"], "worse");
    assert_eq!(v["changes"][0]["before"], "warning");
    assert_eq!(v["changes"][0]["after"], "error");
    assert_eq!(v["before"]["report"], a);
    assert!(v["not_compared"].as_array().unwrap().is_empty());
}

#[test]
fn markdown_output_is_a_document() {
    let dir = Dir::new("markdown");
    let (a, b) = worse_pair(&dir);
    for flag in ["markdown", "md"] {
        let o = run(&["diff", &a, &b, "--output", flag]);
        let text = stdout(&o);
        assert!(
            text.starts_with("# LinuxDoctor report comparison"),
            "{text}"
        );
        assert!(text.contains("## Got worse (1)"), "{text}");
        assert!(text.contains("- **warning → error** · `m` `X1`"), "{text}");
        assert!(!text.contains('\u{1b}'), "no colour codes in a document");
    }
}

// ----- files written by someone else -------------------------------------------------------------------

#[test]
fn a_hostile_report_cannot_drive_the_terminal() {
    let dir = Dir::new("hostile");
    let evil = "\u{1b}[2J\u{1b}]0;pwned\u{7} <script>alert(1)</script> \u{202e}";
    let a = dir.write(
        "a.json",
        &report(vec![module("m", vec![finding("X1", "warning")])]),
    );
    let mut after = report(vec![
        module("m", vec![finding("X1", "error")]),
        failed_module("broken", evil),
    ]);
    after["results"][0]["findings"][0]["title"] = json!(evil);
    after["results"][0]["findings"][0]["instance"] = json!(evil);
    after["results"][0]["findings"][0]["evidence"] = json!([[evil, evil]]);
    after["context"]["hostname"] = json!(evil);
    after["context"]["kernel_version"] = json!(evil);
    let b = dir.write("b.json", &after);

    let o = run(&["diff", &a, &b]);
    let raw = stdout(&o);
    assert!(
        !raw.contains("\u{1b}[2J"),
        "clear-screen sequence reached the terminal"
    );
    assert!(
        !raw.contains("\u{1b}]"),
        "OSC sequence reached the terminal"
    );
    assert!(!raw.contains('\u{7}'), "bell reached the terminal");
    assert!(
        !raw.contains('\u{202e}'),
        "bidi override reached the terminal"
    );
    // Whatever escape sequences remain are the program's own colours.
    for (i, _) in raw.match_indices('\u{1b}') {
        let rest = &raw[i..];
        assert!(
            rest.starts_with("\u{1b}[0m")
                || rest.starts_with("\u{1b}[1m")
                || rest.starts_with("\u{1b}[2m")
                || rest.starts_with("\u{1b}[3")
                || rest.starts_with("\u{1b}[1;31m"),
            "unexpected escape sequence: {:?}",
            &rest[..rest.len().min(12)]
        );
    }

    let md = stdout(&run(&["diff", &a, &b, "--output", "markdown"]));
    // Outside code spans, every `<` is escaped, so no tag can open.
    let outside_code: String = md
        .split('`')
        .step_by(2)
        .collect::<Vec<_>>()
        .join("")
        .replace("\\<", "");
    assert!(
        !outside_code.contains('<'),
        "an HTML tag reached the Markdown: {md}"
    );
    assert!(!md.chars().any(|c| c.is_control() && c != '\n'), "{md:?}");

    let json = stdout(&run(&["diff", &a, &b, "--output", "json"]));
    serde_json::from_str::<Value>(&json).expect("still valid JSON");
    assert!(!json.contains('\u{1b}'));
}

#[test]
fn a_huge_file_is_refused_without_being_read_whole() {
    // 70 MiB of spaces: past the 64 MiB limit on report size.
    let dir = Dir::new("huge");
    let good = dir.write("good.json", &report(vec![]));
    let huge = dir.path.join("huge.json");
    let file = fs::File::create(&huge).unwrap();
    file.set_len(70 * 1024 * 1024).unwrap();
    let o = run(&["diff", &good, &huge.to_string_lossy()]);
    assert_eq!(o.status.code(), Some(2));
    assert!(
        stderr(&o).contains("not a LinuxDoctor report"),
        "{}",
        stderr(&o)
    );
}

#[test]
fn help_describes_the_command() {
    let o = run(&["diff", "--help"]);
    assert_eq!(o.status.code(), Some(0));
    let text = stdout(&o);
    for expected in [
        "<BEFORE>",
        "<AFTER>",
        "--output",
        "--min-severity",
        "--fail-on",
    ] {
        assert!(text.contains(expected), "{expected} missing from:\n{text}");
    }
    assert!(Path::new(env!("CARGO_BIN_EXE_linuxdoctor")).exists());
}
