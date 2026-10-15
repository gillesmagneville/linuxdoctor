// SPDX-License-Identifier: GPL-3.0-only

//! Names chosen by the audited machine -- a mount point, here -- reach the
//! reader's terminal, a file or a browser through the reports. The real
//! binary is run against a fake `df` whose only filesystem has a name made
//! of escape sequences, and every output format is checked.
//!
//! The reports must neutralise the sequences; the JSON report must keep the
//! name exactly as it was observed (JSON escapes control characters by
//! construction, so it is safe to read as text).

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;
use std::process::{Command, Output};

/// What the fake `df` calls its mount point: a screen clear, a window title
/// ended by BEL, and a right-to-left override, around a word to look for.
const HOSTILE_NAME: &str = "/mnt/evil\u{1b}[2J\u{1b}]0;pwned\u{7}EVIL\u{202e}gnp";

/// A directory of fake tools, put first on PATH.
struct FakeBin {
    dir: PathBuf,
}

impl FakeBin {
    fn new(name: &str) -> Self {
        let dir = std::env::temp_dir().join(format!("linuxdoctor-{name}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        let bin = FakeBin { dir };
        // No SMART data from the machine running the tests.
        bin.script("smartctl", "exit 127");
        // The same file system for the space and the inode query, almost full.
        bin.script(
            "df",
            r#"name='/mnt/evil\033[2J\033]0;pwned\007EVIL\342\200\256gnp'
case "$1" in
  -kPT)
    printf 'Filesystem Type 1024-blocks Used Available Capacity Mounted on\n'
    printf "/dev/sdb1 ext4 1000000 970000 30000 97%% $name\n" ;;
  -iPT)
    printf 'Filesystem Type Inodes IUsed IFree IUse%% Mounted on\n'
    printf "/dev/sdb1 ext4 1000 10 990 1%% $name\n" ;;
  *) exit 1 ;;
esac"#,
        );
        bin
    }

    fn script(&self, program: &str, body: &str) {
        let path = self.dir.join(program);
        fs::write(&path, format!("#!/bin/sh\n{body}\n")).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o755)).unwrap();
    }

    fn audit(&self, extra: &[&str]) -> Output {
        Command::new(env!("CARGO_BIN_EXE_linuxdoctor"))
            .args(["audit", "--modules", "storage", "--timeout", "5"])
            .args(extra)
            .env("PATH", format!("{}:/usr/bin:/bin", self.dir.display()))
            .output()
            .expect("linuxdoctor binary should start")
    }
}

impl Drop for FakeBin {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.dir);
    }
}

fn text(o: &Output) -> String {
    String::from_utf8(o.stdout.clone()).expect("output is UTF-8")
}

/// The first character that could act on a terminal or reorder the text.
fn unsafe_char(text: &str) -> Option<char> {
    text.chars().find(|&c| {
        (c.is_control() && c != '\n')
            || matches!(c, '\u{200e}' | '\u{200f}' | '\u{202a}'..='\u{202e}' | '\u{2066}'..='\u{2069}')
    })
}

/// The text without the colour sequences (`ESC [ digits ; m`) the terminal
/// report writes itself. Anything else that starts with ESC is kept.
fn without_own_colours(text: &str) -> String {
    let mut out = String::new();
    let mut rest = text;
    while let Some(at) = rest.find("\u{1b}[") {
        out.push_str(&rest[..at]);
        let after = &rest[at + 2..];
        let digits = after
            .find(|c: char| !(c.is_ascii_digit() || c == ';'))
            .unwrap_or(after.len());
        if after[digits..].starts_with('m') {
            rest = &after[digits + 1..];
        } else {
            out.push_str("\u{1b}[");
            rest = after;
        }
    }
    out.push_str(rest);
    out
}

#[test]
fn the_fake_df_really_puts_the_hostile_name_in_a_finding() {
    // Guards the other tests against passing because nothing was shown.
    let bin = FakeBin::new("hostile-json");
    let o = bin.audit(&["--output", "json"]);
    let report: serde_json::Value = serde_json::from_slice(&o.stdout).expect("JSON report");
    let instances: Vec<&str> = report["results"][0]["findings"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|f| f["instance"].as_str())
        .collect();
    assert!(instances.contains(&HOSTILE_NAME), "{instances:?}");
}

#[test]
fn json_keeps_the_name_as_observed_and_stays_free_of_raw_control_characters() {
    let bin = FakeBin::new("hostile-json-raw");
    let o = bin.audit(&["--output", "json"]);
    let raw = text(&o);
    assert!(!raw.contains('\u{1b}'), "a raw ESC in the JSON");
    assert!(!raw.contains('\u{7}'), "a raw BEL in the JSON");
    assert!(
        raw.contains("\\u001b"),
        "the escape is written as an escape"
    );
}

#[test]
fn the_terminal_report_neutralises_the_name() {
    let bin = FakeBin::new("hostile-terminal");
    let o = bin.audit(&[]);
    // A nearly full file system is an Error or worse: exit status 1.
    assert_eq!(
        o.status.code(),
        Some(1),
        "{}",
        String::from_utf8_lossy(&o.stderr)
    );
    let foreign = without_own_colours(&text(&o));
    assert_eq!(unsafe_char(&foreign), None, "{foreign:?}");
    assert!(
        foreign.contains("/mnt/evil?[2J?]0;pwned?EVIL?gnp"),
        "{foreign}"
    );
}

#[test]
fn the_markdown_report_neutralises_the_name() {
    let bin = FakeBin::new("hostile-markdown");
    let report = text(&bin.audit(&["--output", "markdown"]));
    assert_eq!(unsafe_char(&report), None, "{report:?}");
    assert!(report.contains("EVIL"), "{report}");
}

#[test]
fn the_html_report_neutralises_the_name() {
    let bin = FakeBin::new("hostile-html");
    let report = text(&bin.audit(&["--output", "html"]));
    assert_eq!(unsafe_char(&report), None, "{report:?}");
    assert!(report.contains("EVIL"), "{report}");
}

#[test]
fn a_comparison_of_two_such_reports_neutralises_the_name_as_well() {
    let bin = FakeBin::new("hostile-diff");
    let json = text(&bin.audit(&["--output", "json"]));
    let dir = std::env::temp_dir().join(format!(
        "linuxdoctor-hostile-diff-files-{}",
        std::process::id()
    ));
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(&dir).unwrap();
    // The earlier report: the same machine before the file system filled up.
    let mut earlier: serde_json::Value = serde_json::from_str(&json).unwrap();
    for finding in earlier["results"][0]["findings"].as_array_mut().unwrap() {
        finding["severity"] = serde_json::json!("info");
    }
    let (before, after) = (dir.join("before.json"), dir.join("after.json"));
    fs::write(&before, earlier.to_string()).unwrap();
    fs::write(&after, &json).unwrap();

    let o = Command::new(env!("CARGO_BIN_EXE_linuxdoctor"))
        .args(["diff"])
        .arg(&before)
        .arg(&after)
        .output()
        .unwrap();
    let _ = fs::remove_dir_all(&dir);
    assert_eq!(o.status.code(), Some(1));
    let foreign = without_own_colours(&text(&o));
    assert_eq!(unsafe_char(&foreign), None, "{foreign:?}");
    assert!(foreign.contains("EVIL"), "{foreign}");
}
