// SPDX-License-Identifier: GPL-3.0-only

//! The manual page, the shell completions and the `--modules` check, with
//! the real binary. None of this needs the audited machine: the commands
//! print generated text and exit, so the results are the same everywhere.

use std::io::Write;
use std::process::{Command, Output, Stdio};

const MODULE_IDS: [&str; 13] = [
    "memory",
    "cpu",
    "numa",
    "gpu",
    "storage",
    "systemd",
    "ntp",
    "network",
    "security",
    "logs",
    "kernel",
    "firmware",
    "virtualization",
];

fn run(args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_linuxdoctor"))
        .args(args)
        .output()
        .expect("linuxdoctor binary should start")
}

fn stdout(o: &Output) -> String {
    String::from_utf8(o.stdout.clone()).expect("stdout is UTF-8")
}

fn stderr(o: &Output) -> String {
    String::from_utf8_lossy(&o.stderr).to_string()
}

// ----- manual page -------------------------------------------------------------------

#[test]
fn man_prints_a_roff_page_and_nothing_else() {
    let o = run(&["man"]);
    assert_eq!(o.status.code(), Some(0), "{}", stderr(&o));
    assert!(stderr(&o).is_empty(), "{}", stderr(&o));
    let page = stdout(&o);
    assert!(page.contains(".TH LINUXDOCTOR 1"), "{page}");
    assert!(page.contains(".SH NAME"), "{page}");
    assert!(page.contains(".SH \"EXIT STATUS\""), "{page}");
}

#[test]
fn man_lists_every_module_the_program_runs() {
    let page = stdout(&run(&["man"]));
    for id in MODULE_IDS {
        assert!(page.contains(&format!("\\fB{id}\\fR")), "{id} missing");
    }
}

#[test]
fn man_is_the_same_every_time() {
    assert_eq!(run(&["man"]).stdout, run(&["man"]).stdout);
}

#[test]
fn man_page_is_accepted_by_groff_without_a_single_warning() {
    // groff ships with every system that has man pages, but not with every
    // build machine; without it there is nothing to check against.
    let probe = Command::new("groff").arg("--version").output();
    if probe.map(|o| !o.status.success()).unwrap_or(true) {
        eprintln!("groff is not installed: skipping");
        return;
    }
    let page = run(&["man"]).stdout;
    let mut groff = Command::new("groff")
        .args(["-man", "-Tutf8", "-ww", "-z"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("groff starts");
    groff
        .stdin
        .take()
        .expect("stdin is piped")
        .write_all(&page)
        .expect("groff reads the page");
    let result = groff.wait_with_output().expect("groff finishes");
    assert!(result.status.success(), "{}", stderr(&result));
    assert!(
        result.stderr.is_empty(),
        "groff complained about the page:\n{}",
        stderr(&result)
    );
}

// ----- completions ---------------------------------------------------------------------

#[test]
fn completions_print_a_script_for_each_main_shell() {
    for (shell, marker) in [
        ("bash", "_linuxdoctor()"),
        ("zsh", "#compdef linuxdoctor"),
        ("fish", "complete -c linuxdoctor"),
    ] {
        let o = run(&["completions", shell]);
        assert_eq!(o.status.code(), Some(0), "{shell}: {}", stderr(&o));
        assert!(stderr(&o).is_empty(), "{shell}: {}", stderr(&o));
        let script = stdout(&o);
        assert!(script.contains(marker), "{shell}: {script}");
        for id in MODULE_IDS {
            assert!(script.contains(id), "{shell}: module {id} is not offered");
        }
    }
}

#[test]
fn completions_for_an_unknown_shell_is_a_usage_error() {
    let o = run(&["completions", "tcsh"]);
    assert_eq!(o.status.code(), Some(2));
    assert!(o.stdout.is_empty());
    assert!(stderr(&o).contains("tcsh"), "{}", stderr(&o));
}

#[test]
fn completions_without_a_shell_is_a_usage_error() {
    assert_eq!(run(&["completions"]).status.code(), Some(2));
}

// ----- --modules -----------------------------------------------------------------------

#[test]
fn a_mistyped_module_id_is_a_usage_error_not_an_empty_clean_report() {
    // Before the check, this selected no module at all and printed an empty
    // report with exit status 0: a pass nobody had verified.
    let o = run(&["audit", "--modules", "memroy"]);
    assert_eq!(o.status.code(), Some(2));
    assert!(
        o.stdout.is_empty(),
        "no report may be printed: {}",
        stdout(&o)
    );
    let message = stderr(&o);
    assert!(message.contains("memroy"), "{message}");
    assert!(
        message.contains("memory"),
        "the close match is suggested: {message}"
    );
}

#[test]
fn one_mistyped_id_in_a_list_stops_the_whole_run() {
    let o = run(&["audit", "--modules", "memory,logz"]);
    assert_eq!(o.status.code(), Some(2));
    assert!(o.stdout.is_empty(), "{}", stdout(&o));
}

#[test]
fn the_tui_checks_module_ids_too() {
    let o = run(&["tui", "--modules", "nope"]);
    assert_eq!(o.status.code(), Some(2));
}

#[test]
fn a_correct_module_id_still_runs() {
    let o = run(&["audit", "--modules", "memory", "--output", "json"]);
    assert!(
        matches!(o.status.code(), Some(0) | Some(1)),
        "{}",
        stderr(&o)
    );
    assert!(
        stdout(&o).contains("\"module_id\": \"memory\""),
        "{}",
        stdout(&o)
    );
}
