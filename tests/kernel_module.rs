// SPDX-License-Identifier: GPL-3.0-only

use linuxdoctor::core::context::Context;
use linuxdoctor::models::Severity;
use linuxdoctor::modules::kernel::analyze::analyze;
use linuxdoctor::modules::kernel::collect::{count_oom_kills, parse_tainted, KernelRawData};

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
    };
    let findings2 = analyze(&data_unavailable, &test_context());
    let kern002b = findings2.iter().find(|f| f.id == "KERN002").unwrap();
    assert_eq!(kern002b.severity, Severity::Info);
    assert!(kern002b.explanation.contains("Could not check"));
}
