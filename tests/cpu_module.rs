// SPDX-License-Identifier: GPL-3.0-only

use linuxdoctor::core::context::Context;
use linuxdoctor::models::Severity;
use linuxdoctor::modules::cpu::analyze::analyze;
use linuxdoctor::modules::cpu::collect::{parse_loadavg, parse_model_name, CpuRawData};

fn test_context(cpu_count: usize) -> Context {
    Context {
        hostname: "test-host".into(),
        kernel_version: "6.8.0-test".into(),
        distro: Some("Test Linux".into()),
        architecture: "x86_64".into(),
        cpu_count,
        mem_total_kb: 16_384_000,
        boot_time_unix: 0,
    }
}

#[test]
fn idle_system_fixture_produces_only_info_findings() {
    let loadavg = "0.12 0.04 0.01 1/75 476\n";
    let cpuinfo = "processor\t: 0\nmodel name\t: Test CPU @ 2.10GHz\n";

    let (load_1m, load_5m, load_15m) = parse_loadavg(loadavg).unwrap();
    let model_name = parse_model_name(cpuinfo);

    let data = CpuRawData {
        load_1m,
        load_5m,
        load_15m,
        model_name,
    };

    let findings = analyze(&data, &test_context(4));
    assert!(findings.iter().all(|f| f.severity == Severity::Info));
    assert!(findings.iter().any(|f| f.id == "CPU001"));
    assert!(findings.iter().any(|f| f.id == "CPU002"));
    assert!(!findings.iter().any(|f| f.id == "CPU003"));
}

#[test]
fn sustained_overload_fixture_produces_critical_finding() {
    let loadavg = "9.10 8.50 7.90 12/300 9999\n";
    let (load_1m, load_5m, load_15m) = parse_loadavg(loadavg).unwrap();

    let data = CpuRawData {
        load_1m,
        load_5m,
        load_15m,
        model_name: None,
    };

    let findings = analyze(&data, &test_context(4));
    let cpu003 = findings.iter().find(|f| f.id == "CPU003").unwrap();
    assert_eq!(cpu003.severity, Severity::Critical);
}
