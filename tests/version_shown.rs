// SPDX-License-Identifier: GPL-3.0-only

//! Which version of LinuxDoctor produced what a person is reading, in every
//! place they read it: the first lines of each report format, the JSON
//! record, the comparison of two reports. The real binary is run, and the
//! expected version is the one this build was compiled as -- so the tests
//! need no change when the version does.

use std::fs;
use std::path::PathBuf;
use std::process::{Command, Output};

const VERSION: &str = env!("CARGO_PKG_VERSION");

fn run(args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_linuxdoctor"))
        // Never the configuration file of whoever runs the tests.
        .env("XDG_CONFIG_HOME", "/nonexistent")
        .args(args)
        .output()
        .expect("linuxdoctor binary should start")
}

fn stdout(o: &Output) -> String {
    String::from_utf8(o.stdout.clone()).expect("output is UTF-8")
}

fn stderr(o: &Output) -> String {
    String::from_utf8_lossy(&o.stderr).to_string()
}

/// A real, quick audit in one format.
fn audit(format: &str) -> String {
    let o = run(&[
        "audit",
        "--modules",
        "memory",
        "--fail-on",
        "never",
        "--output",
        format,
    ]);
    assert_eq!(o.status.code(), Some(0), "{}", stderr(&o));
    stdout(&o)
}

/// The text without the colour sequences (`ESC [ digits ; m`).
fn plain(text: &str) -> String {
    let mut out = String::new();
    let mut rest = text;
    while let Some(at) = rest.find("\u{1b}[") {
        out.push_str(&rest[..at]);
        let after = &rest[at + 2..];
        let end = after
            .find(|c: char| !(c.is_ascii_digit() || c == ';'))
            .unwrap_or(after.len());
        rest = after[end..].strip_prefix('m').unwrap_or(&after[end..]);
    }
    out.push_str(rest);
    out
}

// ----- the reports ------------------------------------------------------------------------------

#[test]
fn the_terminal_report_starts_with_the_version() {
    let report = plain(&audit("terminal"));
    let first = report.lines().next().unwrap();
    assert!(
        first.starts_with(&format!("LinuxDoctor {VERSION} — ")),
        "{first}"
    );
}

#[test]
fn the_markdown_report_has_the_version_first_under_its_title() {
    let report = audit("markdown");
    let lines: Vec<&str> = report.lines().take(3).collect();
    assert!(lines[0].starts_with("# LinuxDoctor report"), "{lines:?}");
    assert_eq!(
        lines[2],
        format!("- **LinuxDoctor:** {VERSION}"),
        "{lines:?}"
    );
}

#[test]
fn the_html_report_has_the_version_first_among_the_facts() {
    let report = audit("html");
    assert!(
        report.contains(&format!(
            "<dl class=\"facts\">\n<div><dt>LinuxDoctor</dt><dd>{VERSION}</dd></div>"
        )),
        "{report}"
    );
}

#[test]
fn the_json_report_records_the_version_right_after_the_layout_version() {
    let text = audit("json");
    let lines: Vec<&str> = text.lines().map(str::trim).collect();
    assert!(lines[1].starts_with("\"schema_version\":"), "{}", lines[1]);
    assert_eq!(lines[2], format!("\"linuxdoctor_version\": \"{VERSION}\","));
    let json: serde_json::Value = serde_json::from_str(&text).unwrap();
    assert_eq!(
        json["schema_version"], 1,
        "adding a field is not a new layout"
    );
}

#[test]
fn every_place_agrees_with_dash_dash_version() {
    let o = run(&["--version"]);
    assert_eq!(stdout(&o).trim(), format!("linuxdoctor {VERSION}"));
}

#[test]
fn the_version_file_and_cargo_toml_say_the_same_thing() {
    // Packaging reads VERSION, the binary reads Cargo.toml: a release that
    // bumps one and forgets the other would ship mismatched.
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let file = fs::read_to_string(root.join("VERSION")).unwrap();
    assert_eq!(file.trim(), VERSION, "VERSION and Cargo.toml disagree");
}

// ----- the comparison -----------------------------------------------------------------------------

struct Reports {
    dir: PathBuf,
}

impl Reports {
    fn new(name: &str) -> Reports {
        let dir =
            std::env::temp_dir().join(format!("linuxdoctor-version-{name}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        Reports { dir }
    }

    fn write(&self, name: &str, content: &str) -> String {
        let path = self.dir.join(name);
        fs::write(&path, content).unwrap();
        path.to_string_lossy().to_string()
    }
}

impl Drop for Reports {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.dir);
    }
}

/// A report as 1.7.0 wrote it: no `linuxdoctor_version`.
const OLD_REPORT: &str = r#"{
    "schema_version": 1,
    "context": {"hostname": "web01", "kernel_version": "6.8.0", "distro": null,
                "architecture": "x86_64", "cpu_count": 4, "mem_total_kb": 8388608,
                "boot_time_unix": 1000000},
    "results": []
}"#;

#[test]
fn a_comparison_says_which_version_wrote_each_report_and_which_compared() {
    let reports = Reports::new("compare");
    let old = reports.write("old.json", OLD_REPORT);
    let new = reports.write("new.json", &audit("json"));

    let o = run(&["diff", &old, &new, "--fail-on", "never"]);
    let terminal = plain(&stdout(&o));
    assert!(
        terminal.starts_with(&format!("LinuxDoctor {VERSION} — report comparison")),
        "{terminal}"
    );
    assert!(
        terminal.contains("(LinuxDoctor version not recorded)"),
        "{terminal}"
    );
    assert!(
        terminal.contains(&format!("{new} (LinuxDoctor {VERSION})")),
        "{terminal}"
    );

    let o = run(&[
        "diff",
        &old,
        &new,
        "--fail-on",
        "never",
        "--output",
        "markdown",
    ]);
    let md = stdout(&o);
    assert!(
        md.contains(&format!("Compared with LinuxDoctor {VERSION}.")),
        "{md}"
    );
    assert!(md.contains("| LinuxDoctor version not recorded |"), "{md}");
    assert!(md.contains(&format!("| LinuxDoctor {VERSION} |")), "{md}");

    let o = run(&["diff", &old, &new, "--fail-on", "never", "--output", "json"]);
    let json: serde_json::Value = serde_json::from_slice(&o.stdout).unwrap();
    assert_eq!(json["linuxdoctor_version"], VERSION);
    assert!(json["before"]["linuxdoctor_version"].is_null());
    assert_eq!(json["after"]["linuxdoctor_version"], VERSION);
}

#[test]
fn a_version_written_in_a_report_file_cannot_act_on_the_terminal() {
    let reports = Reports::new("hostile");
    let mut hostile: serde_json::Value = serde_json::from_str(OLD_REPORT).unwrap();
    hostile["linuxdoctor_version"] = serde_json::json!("1.\u{1b}[2J\u{1b}]0;pwned\u{7}\u{202e}0");
    let hostile = reports.write("hostile.json", &hostile.to_string());
    let clean = reports.write("clean.json", OLD_REPORT);

    for format in ["terminal", "markdown"] {
        let o = run(&[
            "diff",
            &hostile,
            &clean,
            "--fail-on",
            "never",
            "--output",
            format,
        ]);
        let text = plain(&stdout(&o));
        assert!(!text.contains('\u{1b}'), "{format}: {text:?}");
        assert!(!text.contains('\u{7}'), "{format}: {text:?}");
        assert!(!text.contains('\u{202e}'), "{format}: {text:?}");
        // Neutralised, not removed (Markdown also escapes the brackets).
        assert!(text.contains("pwned"), "{format}: {text}");
        if format == "terminal" {
            assert!(text.contains("1.?[2J?]0;pwned??0"), "{text}");
        }
    }
}
