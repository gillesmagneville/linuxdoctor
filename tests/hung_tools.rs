// SPDX-License-Identifier: GPL-3.0-only

//! End-to-end: the real `linuxdoctor` binary against fake external tools
//! that hang, to prove a wedged `virsh` costs one time limit (not a frozen
//! terminal) and that the report says the data is incomplete.

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;
use std::process::Command;
use std::time::{Duration, Instant};

/// A throwaway directory holding fake executables, put first on PATH.
struct FakeBin {
    dir: PathBuf,
}

impl FakeBin {
    fn new(name: &str) -> Self {
        let dir = std::env::temp_dir().join(format!("linuxdoctor-{name}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        let bin = FakeBin { dir };
        // The virtualization module also probes for container runtimes. A
        // real docker on the machine running the tests (a Go binary that
        // can take over a second on a cold, busy machine) must not eat
        // the 1-second limit these tests rely on: pretend neither exists.
        bin.script("docker", "exit 127");
        bin.script("podman", "exit 127");
        bin
    }

    fn script(&self, program: &str, body: &str) {
        let path = self.dir.join(program);
        fs::write(&path, format!("#!/bin/sh\n{body}\n")).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o755)).unwrap();
    }

    fn path_env(&self) -> String {
        format!("{}:/usr/local/bin:/usr/bin:/bin", self.dir.display())
    }
}

impl Drop for FakeBin {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.dir);
    }
}

/// Runs `linuxdoctor audit --modules virtualization --output json` with the
/// fake tools first on PATH and returns (elapsed, parsed JSON).
fn audit_virtualization(bin: &FakeBin, timeout_secs: &str) -> (Duration, serde_json::Value) {
    let started = Instant::now();
    let output = Command::new(env!("CARGO_BIN_EXE_linuxdoctor"))
        // Never the configuration file of whoever runs the tests.
        .env("XDG_CONFIG_HOME", "/nonexistent")
        .args([
            "audit",
            "--modules",
            "virtualization",
            "--output",
            "json",
            "--timeout",
            timeout_secs,
        ])
        .env("PATH", bin.path_env())
        .output()
        .expect("linuxdoctor binary should start");
    let elapsed = started.elapsed();
    let json: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap_or_else(|e| {
        panic!(
            "stdout was not JSON ({e}): {}\nstderr: {}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        )
    });
    (elapsed, json)
}

fn module<'a>(report: &'a serde_json::Value, id: &str) -> &'a serde_json::Value {
    report["results"]
        .as_array()
        .unwrap()
        .iter()
        .find(|r| r["module_id"] == id)
        .unwrap_or_else(|| panic!("module {id} missing from report"))
}

#[test]
fn a_virsh_that_never_answers_costs_one_time_limit_and_is_reported() {
    let bin = FakeBin::new("virsh-hang");
    bin.script(
        "virsh",
        r#"case "$1" in
  --version) echo 9.0.0 ;;
  *) exec sleep 60 ;;
esac"#,
    );

    let (elapsed, report) = audit_virtualization(&bin, "1");

    // 60 s of sleeping must be cut at the 1 s limit; a generous bound for
    // slow CI machines, still far below what the hang would take.
    assert!(elapsed < Duration::from_secs(15), "took {elapsed:?}");

    let result = module(&report, "virtualization");
    assert!(
        result["error"].is_null(),
        "a hung tool is a note, not a crash: {result}"
    );
    let notes = result["notes"].as_array().unwrap();
    assert_eq!(notes.len(), 1, "{notes:?}");
    let note = notes[0].as_str().unwrap();
    assert!(note.contains("virsh list --all --name"), "{note}");
    assert!(note.contains("did not finish within 1s"), "{note}");
}

#[test]
fn a_virsh_that_hangs_midway_stops_the_per_vm_calls_after_the_first_timeout() {
    let bin = FakeBin::new("virsh-midway");
    // `list` and the first `dominfo` answer; everything after hangs. Without
    // the session guard each of the remaining ~8 per-VM calls would wait
    // out its own limit.
    bin.script(
        "virsh",
        r#"case "$1" in
  --version) echo 9.0.0 ;;
  list) echo vm1 ;;
  dominfo)
    echo "Id:             1"
    echo "Name:           vm1"
    echo "OS Type:        hvm"
    echo "State:          running"
    echo "CPU(s):         2"
    echo "CPU time:       10.0s"
    echo "Max memory:     2097152 KiB"
    echo "Used memory:    2097152 KiB"
    ;;
  *) exec sleep 60 ;;
esac"#,
    );

    let (elapsed, report) = audit_virtualization(&bin, "1");

    assert!(
        elapsed < Duration::from_secs(6),
        "took {elapsed:?}: later calls were not skipped after the first timeout"
    );
    let result = module(&report, "virtualization");
    let notes = result["notes"].as_array().unwrap();
    assert_eq!(
        notes.len(),
        1,
        "exactly one stopped command expected: {notes:?}"
    );
    assert!(
        notes[0].as_str().unwrap().contains("virsh vcpupin vm1"),
        "{notes:?}"
    );

    // The VM found before the hang is still reported.
    let text = serde_json::to_string(result).unwrap();
    assert!(
        text.contains("vm1"),
        "VM discovered before the hang was lost: {text}"
    );
}

#[test]
fn healthy_tools_produce_no_notes() {
    let bin = FakeBin::new("virsh-healthy");
    bin.script(
        "virsh",
        r#"case "$1" in
  --version) echo 9.0.0 ;;
  list) ;;
  *) exit 1 ;;
esac"#,
    );
    let (_, report) = audit_virtualization(&bin, "5");
    let result = module(&report, "virtualization");
    assert!(result["notes"].as_array().unwrap().is_empty(), "{result}");
}
