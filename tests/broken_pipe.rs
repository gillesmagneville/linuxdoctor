// SPDX-License-Identifier: GPL-3.0-only

//! A reader that goes away before the output is written
//! (`linuxdoctor audit | head -1`, a pager that is quit at once) must not
//! make the program panic, and must not change its verdict: what the audit
//! found, and so its exit status, does not depend on who was listening.
//!
//! The read end of the pipe is closed *before* the program writes, which
//! the audits make certain of: they take far longer to run than it takes
//! to close the pipe.

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;
use std::process::{Command, Output, Stdio};

/// Runs the program with its standard output already closed at the other end.
fn run_into_a_closed_pipe(args: &[&str], path: Option<&str>) -> Output {
    let mut command = Command::new(env!("CARGO_BIN_EXE_linuxdoctor"));
    command
        .args(args)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    if let Some(path) = path {
        command.env("PATH", path);
    }
    let mut child = command.spawn().expect("linuxdoctor binary should start");
    drop(child.stdout.take());
    child.wait_with_output().expect("the program ends")
}

fn stderr(o: &Output) -> String {
    String::from_utf8_lossy(&o.stderr).to_string()
}

/// No panic: a Rust panic exits with status 101 and says so on stderr.
fn assert_no_panic(o: &Output, what: &str) {
    assert_ne!(o.status.code(), Some(101), "{what} panicked: {}", stderr(o));
    assert!(!stderr(o).contains("panicked"), "{what}: {}", stderr(o));
}

// ----- audit -----------------------------------------------------------------------------------

#[test]
fn audit_does_not_panic_when_the_reader_has_gone_in_any_format() {
    for format in ["terminal", "json", "markdown", "html"] {
        let o = run_into_a_closed_pipe(
            &[
                "audit",
                "--modules",
                "memory",
                "--output",
                format,
                "--fail-on",
                "never",
            ],
            None,
        );
        assert_no_panic(&o, format);
        assert_eq!(o.status.code(), Some(0), "{format}: {}", stderr(&o));
        assert!(
            stderr(&o).is_empty(),
            "a reader that leaves is not worth a message ({format}): {}",
            stderr(&o)
        );
    }
}

/// A directory with a fake `df` whose only file system is nearly full, so
/// that the storage audit is certain to fail the default gate.
struct FullDisk {
    dir: PathBuf,
}

impl FullDisk {
    fn new(name: &str) -> Self {
        let dir = std::env::temp_dir().join(format!("linuxdoctor-{name}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        let tool = |program: &str, body: &str| {
            let path = dir.join(program);
            fs::write(&path, format!("#!/bin/sh\n{body}\n")).unwrap();
            fs::set_permissions(&path, fs::Permissions::from_mode(0o755)).unwrap();
        };
        tool("smartctl", "exit 127");
        tool(
            "df",
            r#"case "$1" in
  -kPT)
    printf 'Filesystem Type 1024-blocks Used Available Capacity Mounted on\n'
    printf '/dev/sdb1 ext4 1000000 970000 30000 97%% /mnt/data\n' ;;
  -iPT)
    printf 'Filesystem Type Inodes IUsed IFree IUse%% Mounted on\n'
    printf '/dev/sdb1 ext4 1000 10 990 1%% /mnt/data\n' ;;
  *) exit 1 ;;
esac"#,
        );
        FullDisk { dir }
    }

    fn path(&self) -> String {
        format!("{}:/usr/bin:/bin", self.dir.display())
    }
}

impl Drop for FullDisk {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.dir);
    }
}

#[test]
fn audit_keeps_its_verdict_when_the_reader_has_gone() {
    let disk = FullDisk::new("broken-pipe-verdict");
    let o = run_into_a_closed_pipe(&["audit", "--modules", "storage"], Some(&disk.path()));
    assert_no_panic(&o, "audit");
    assert_eq!(
        o.status.code(),
        Some(1),
        "the file system is nearly full: the audit still fails ({})",
        stderr(&o)
    );
    assert!(
        stderr(&o).is_empty(),
        "the default gate is silent: {}",
        stderr(&o)
    );
}

#[test]
fn an_explicit_fail_on_still_explains_itself_when_the_reader_has_gone() {
    let disk = FullDisk::new("broken-pipe-fail-on");
    let o = run_into_a_closed_pipe(
        &["audit", "--modules", "storage", "--fail-on", "warning"],
        Some(&disk.path()),
    );
    assert_no_panic(&o, "audit");
    assert_eq!(o.status.code(), Some(1));
    assert!(stderr(&o).contains("--fail-on warning"), "{}", stderr(&o));
}

// ----- the other commands -------------------------------------------------------------------------

#[test]
fn man_and_completions_are_quiet_and_successful_when_the_reader_has_gone() {
    for args in [&["man"][..], &["completions", "bash"][..]] {
        let o = run_into_a_closed_pipe(args, None);
        assert_no_panic(&o, &args.join(" "));
        assert_eq!(o.status.code(), Some(0), "{args:?}: {}", stderr(&o));
        assert!(stderr(&o).is_empty(), "{args:?}: {}", stderr(&o));
    }
}

#[test]
fn diff_keeps_its_verdict_when_the_reader_has_gone() {
    let dir = std::env::temp_dir().join(format!(
        "linuxdoctor-broken-pipe-diff-{}",
        std::process::id()
    ));
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(&dir).unwrap();
    let report = |severity: &str| {
        serde_json::json!({
            "schema_version": 1,
            "context": {
                "hostname": "web01", "kernel_version": "6.8.0", "distro": null,
                "architecture": "x86_64", "cpu_count": 4, "mem_total_kb": 8_388_608,
                "boot_time_unix": 1_000_000,
            },
            "results": [{
                "module_id": "m",
                "findings": [{"id": "X1", "title": "A finding", "severity": severity,
                              "evidence": [], "instance": null}],
                "error": null, "skipped": false, "notes": [],
            }],
        })
        .to_string()
    };
    let (before, after) = (dir.join("before.json"), dir.join("after.json"));
    fs::write(&before, report("info")).unwrap();
    fs::write(&after, report("critical")).unwrap();

    let o = run_into_a_closed_pipe(
        &["diff", &before.to_string_lossy(), &after.to_string_lossy()],
        None,
    );
    let _ = fs::remove_dir_all(&dir);
    assert_no_panic(&o, "diff");
    assert_eq!(o.status.code(), Some(1), "{}", stderr(&o));
}
