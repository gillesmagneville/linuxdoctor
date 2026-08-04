// SPDX-License-Identifier: GPL-3.0-only

//! Integration-level test for the memory module: fixture text in,
//! `Finding`s out, through the real parse + analyze pipeline. The only
//! piece intentionally not exercised here is the live `fs::read_to_string`
//! call in `collect::collect()` — that's what end-to-end tests against a
//! real system are for (ARCHITECTURE.md "Testing Strategy").

use linuxdoctor::core::context::Context;
use linuxdoctor::models::Severity;
use linuxdoctor::modules::memory::analyze::analyze;
use linuxdoctor::modules::memory::collect::{parse_meminfo, parse_swappiness, MemoryRawData};

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
fn healthy_system_fixture_produces_only_info_findings() {
    let meminfo = "\
MemTotal:       16384000 kB
MemFree:         9000000 kB
MemAvailable:   12000000 kB
SwapTotal:       4194300 kB
SwapFree:        4194300 kB
";
    let swappiness_text = "60\n";

    let fields = parse_meminfo(meminfo).expect("meminfo should parse");
    let swappiness = parse_swappiness(swappiness_text).expect("swappiness should parse");

    let data = MemoryRawData {
        mem_total_kb: fields["MemTotal"],
        mem_available_kb: fields["MemAvailable"],
        swap_total_kb: fields["SwapTotal"],
        swap_free_kb: fields["SwapFree"],
        swappiness,
    };

    let findings = analyze(&data, &test_context());

    assert_eq!(findings.len(), 1, "only MEM001 should fire on a healthy system");
    assert_eq!(findings[0].id, "MEM001");
    assert_eq!(findings[0].severity, Severity::Info);
}

#[test]
fn under_pressure_fixture_produces_warning_and_no_critical() {
    let meminfo = "\
MemTotal:       16384000 kB
MemFree:          800000 kB
MemAvailable:    1300000 kB
SwapTotal:       4194300 kB
SwapFree:         150000 kB
";
    let swappiness_text = "10\n";

    let fields = parse_meminfo(meminfo).unwrap();
    let swappiness = parse_swappiness(swappiness_text).unwrap();

    let data = MemoryRawData {
        mem_total_kb: fields["MemTotal"],
        mem_available_kb: fields["MemAvailable"],
        swap_total_kb: fields["SwapTotal"],
        swap_free_kb: fields["SwapFree"],
        swappiness,
    };

    let findings = analyze(&data, &test_context());
    let ids: Vec<&str> = findings.iter().map(|f| f.id.as_str()).collect();

    assert!(ids.contains(&"MEM001"));
    assert!(ids.contains(&"MEM002"));
    assert!(!ids.contains(&"MEM003"), "swap still has headroom, shouldn't hit CRITICAL");

    let mem002 = findings.iter().find(|f| f.id == "MEM002").unwrap();
    assert_eq!(mem002.severity, Severity::Warning);
}
