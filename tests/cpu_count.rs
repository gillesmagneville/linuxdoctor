// SPDX-License-Identifier: GPL-3.0-only

//! The CPU count in a report is the machine's, not the process's.
//!
//! A machine that sets some of its CPUs aside (a virtual machine pinned to
//! its own cores, a cpuset) must not be reported with fewer CPUs because the
//! audit itself runs on the others. The test runs the real binary confined
//! to one CPU, as `taskset` does, and compares with an unconfined run.

use std::process::Command;

fn cpu_count(confine_to: Option<u32>) -> Option<u64> {
    let binary = env!("CARGO_BIN_EXE_linuxdoctor");
    let mut command = match confine_to {
        Some(cpu) => {
            let mut c = Command::new("taskset");
            c.args(["-c", &cpu.to_string(), binary]);
            c
        }
        None => Command::new(binary),
    };
    let output = command
        .args([
            "audit",
            "--modules",
            "cpu",
            "--no-config",
            "--output",
            "json",
        ])
        .env("HOME", "/nonexistent")
        .stdin(std::process::Stdio::null())
        .output()
        .ok()?;
    let report: serde_json::Value = serde_json::from_slice(&output.stdout).ok()?;
    report["context"]["cpu_count"].as_u64()
}

/// The first CPU this test may run on: the confinement has to name one the
/// process is allowed to use, and CPU 0 is not always among them.
fn first_allowed_cpu() -> Option<u32> {
    let status = std::fs::read_to_string("/proc/self/status").ok()?;
    let list = status
        .lines()
        .find_map(|l| l.strip_prefix("Cpus_allowed_list:"))?
        .trim();
    list.split(['-', ',']).next()?.parse().ok()
}

#[test]
fn confining_the_audit_to_one_cpu_does_not_change_the_count() {
    let Some(cpu) = first_allowed_cpu() else {
        return;
    };
    let Some(unconfined) = cpu_count(None) else {
        panic!("the audit did not report a CPU count");
    };
    // `taskset` is part of util-linux; without it there is nothing to confine
    // the audit with.
    let Some(confined) = cpu_count(Some(cpu)) else {
        return;
    };
    assert_eq!(confined, unconfined);
}
