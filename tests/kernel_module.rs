// SPDX-License-Identifier: GPL-3.0-only

use linuxdoctor::core::context::Context;
use linuxdoctor::models::Severity;
use linuxdoctor::modules::kernel::analyze::analyze;
use linuxdoctor::modules::kernel::collect::{count_oom_kills, parse_tainted, KernelRawData};
use linuxdoctor::modules::kernel::limits::{parse_file_nr, parse_task_count, Limits, Tasks};

fn test_context() -> Context {
    Context {
        hostname: "test-host".into(),
        kernel_version: "6.8.0-test".into(),
        distro: Some("Test Linux".into()),
        architecture: "x86_64".into(),
        cpu_count: 4,
        mem_total_kb: 16_384_000,
        boot_time_unix: 0,
    }
}

#[test]
fn clean_system_fixture_produces_only_info_findings() {
    let tainted = parse_tainted("0\n").unwrap();
    let dmesg = "[0.0] Linux version 6.8.0\n[1.0] Some unrelated boot message\n";

    let data = KernelRawData {
        tainted_raw: tainted,
        oom_kill_count: Some(count_oom_kills(dmesg)),
        dmesg_error: None,
        build_info: Default::default(),
        reboot_required: Default::default(),
        aslr_mode: Some(2),
        notable_cmdline_flags: vec![],
        ..Default::default()
    };

    let findings = analyze(&data, &test_context());
    assert!(findings.iter().all(|f| f.severity == Severity::Info));
    assert!(findings.iter().any(|f| f.id == "KERN001"));
    assert!(findings.iter().any(|f| f.id == "KERN002"));
}

/// The kernel documentation's own worked example (4609 = P, W, O).
#[test]
fn kernel_docs_worked_example_fixture() {
    let tainted = parse_tainted("4609\n").unwrap();
    let data = KernelRawData {
        tainted_raw: tainted,
        oom_kill_count: Some(0),
        dmesg_error: None,
        build_info: Default::default(),
        reboot_required: Default::default(),
        aslr_mode: Some(2),
        notable_cmdline_flags: vec![],
        ..Default::default()
    };

    let findings = analyze(&data, &test_context());
    let kern001 = findings.iter().find(|f| f.id == "KERN001").unwrap();
    // W (kernel warning) is the most severe of the three -> Warning overall.
    assert_eq!(kern001.severity, Severity::Warning);
    assert!(kern001
        .evidence
        .iter()
        .any(|(k, v)| k == "active_flags" && v == "P,W,O"));
}

#[test]
fn oom_kills_and_dmesg_unavailable_fixtures() {
    let dmesg_with_kills = "\
[100.0] Out of memory: Killed process 111 (a) total-vm:1kB
[200.0] Out of memory: Killed process 222 (b) total-vm:1kB
[300.0] Out of memory: Killed process 333 (c) total-vm:1kB
";
    let data_with_kills = KernelRawData {
        tainted_raw: 0,
        oom_kill_count: Some(count_oom_kills(dmesg_with_kills)),
        dmesg_error: None,
        build_info: Default::default(),
        reboot_required: Default::default(),
        aslr_mode: Some(2),
        notable_cmdline_flags: vec![],
        ..Default::default()
    };
    let findings = analyze(&data_with_kills, &test_context());
    let kern002 = findings.iter().find(|f| f.id == "KERN002").unwrap();
    assert_eq!(kern002.severity, Severity::Error); // 3 kills

    let data_unavailable = KernelRawData {
        tainted_raw: 0,
        oom_kill_count: None,
        dmesg_error: Some("permission denied".to_string()),
        build_info: Default::default(),
        reboot_required: Default::default(),
        aslr_mode: Some(2),
        notable_cmdline_flags: vec![],
        ..Default::default()
    };
    let findings2 = analyze(&data_unavailable, &test_context());
    let kern002b = findings2.iter().find(|f| f.id == "KERN002").unwrap();
    assert_eq!(kern002b.severity, Severity::Info);
    assert!(kern002b.explanation.contains("Could not check"));
}

/// A table that is nearly full, and one that has room, from the text the
/// kernel prints, through the whole analysis.
#[test]
fn full_tables_from_kernel_text_are_found_and_roomy_ones_are_not() {
    let data = KernelRawData {
        limits: Limits {
            files: parse_file_nr("98000\t0\t100000\n"),
            tasks: parse_task_count("0.10 0.20 0.30 2/900 4242\n").map(|count| Tasks {
                count,
                pid_max: Some(32768),
                threads_max: Some(64088),
            }),
        },
        ..Default::default()
    };
    let findings = analyze(&data, &test_context());
    let kern007 = findings.iter().find(|f| f.id == "KERN007").unwrap();
    assert_eq!(kern007.severity, Severity::Error);
    assert!(kern007
        .evidence
        .iter()
        .any(|(k, v)| k == "usage_percent" && v == "98"));
    let kern008 = findings.iter().find(|f| f.id == "KERN008").unwrap();
    assert_eq!(kern008.severity, Severity::Info);
    assert!(kern008
        .evidence
        .iter()
        .any(|(k, v)| k == "processes_and_threads" && v == "900"));
}

/// The real binary reads the real tables: the limits are the host's own, so
/// they are compared with what `/proc` says, not with a severity.
#[test]
fn the_real_binary_reports_the_tables_of_this_host() {
    let out = std::process::Command::new(env!("CARGO_BIN_EXE_linuxdoctor"))
        .args([
            "--no-config",
            "audit",
            "--modules",
            "kernel",
            "--fail-on",
            "never",
            "--output",
            "json",
        ])
        .stdin(std::process::Stdio::null())
        .output()
        .expect("linuxdoctor binary should start");
    let report: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    let findings = report["results"][0]["findings"].as_array().unwrap();
    let find = |id: &str| findings.iter().find(|f| f["id"] == id);
    let value = |finding: &serde_json::Value, key: &str| {
        finding["evidence"]
            .as_array()
            .unwrap()
            .iter()
            .find_map(|pair| (pair[0] == key).then(|| pair[1].as_str().unwrap().to_string()))
    };
    let number = |path: &str| {
        std::fs::read_to_string(path)
            .ok()
            .map(|text| text.trim().to_string())
    };

    let kern007 = find("KERN007").expect("every Linux has a file table");
    assert_eq!(kern007["title"], "File Handle Table");
    assert_eq!(
        value(kern007, "file_max"),
        number("/proc/sys/fs/file-max"),
        "{kern007}"
    );
    let kern008 = find("KERN008").expect("every Linux has a process table");
    assert_eq!(kern008["title"], "Process and Thread Table");
    assert_eq!(
        value(kern008, "pid_max"),
        number("/proc/sys/kernel/pid_max")
    );
    assert_eq!(
        value(kern008, "threads_max"),
        number("/proc/sys/kernel/threads-max")
    );
    let tasks: u64 = value(kern008, "processes_and_threads")
        .unwrap()
        .parse()
        .unwrap();
    assert!(tasks >= 1, "{kern008}");
}
