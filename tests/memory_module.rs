// SPDX-License-Identifier: GPL-3.0-only

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

fn build_from_fixture(meminfo: &str, swappiness: &str, dirty_ratio: u8, dirty_bg_ratio: u8) -> MemoryRawData {
    let fields = parse_meminfo(meminfo).expect("meminfo should parse");
    MemoryRawData {
        mem_total_kb: fields["MemTotal"],
        mem_free_kb: *fields.get("MemFree").unwrap_or(&0),
        mem_available_kb: fields["MemAvailable"],
        cached_kb: fields.get("Buffers").unwrap_or(&0) + fields.get("Cached").unwrap_or(&0),
        shmem_kb: *fields.get("Shmem").unwrap_or(&0),
        dirty_kb: *fields.get("Dirty").unwrap_or(&0),
        swap_total_kb: fields["SwapTotal"],
        swap_free_kb: fields["SwapFree"],
        swappiness: parse_swappiness(swappiness).expect("swappiness should parse"),
        dirty_ratio,
        dirty_background_ratio: dirty_bg_ratio,
    }
}

#[test]
fn healthy_system_fixture_produces_only_info_findings() {
    let meminfo = "\
MemTotal:       16384000 kB
MemFree:         9000000 kB
MemAvailable:   12000000 kB
Buffers:          300000 kB
Cached:          3500000 kB
Shmem:            180000 kB
Dirty:               800 kB
SwapTotal:       4194300 kB
SwapFree:        4194300 kB
";
    let data = build_from_fixture(meminfo, "60\n", 20, 10);

    let findings = analyze(&data, &test_context());

    assert!(findings.iter().all(|f| f.severity == Severity::Info));
    let ids: Vec<&str> = findings.iter().map(|f| f.id.as_str()).collect();
    assert!(ids.contains(&"MEM001"));
    assert!(ids.contains(&"MEM004"));
    assert!(ids.contains(&"MEM005"));
    assert!(ids.contains(&"MEM006"));
    assert!(!ids.contains(&"MEM002")); // swap unused
    assert!(!ids.contains(&"MEM003"));
}

#[test]
fn under_pressure_fixture_produces_warning_and_no_critical() {
    let meminfo = "\
MemTotal:       16384000 kB
MemFree:          800000 kB
MemAvailable:    1300000 kB
Buffers:          200000 kB
Cached:          1800000 kB
Shmem:            150000 kB
Dirty:               900 kB
SwapTotal:       4194300 kB
SwapFree:         150000 kB
";
    let data = build_from_fixture(meminfo, "10\n", 20, 10);

    let findings = analyze(&data, &test_context());
    let ids: Vec<&str> = findings.iter().map(|f| f.id.as_str()).collect();

    assert!(ids.contains(&"MEM001"));
    assert!(ids.contains(&"MEM002"));
    assert!(!ids.contains(&"MEM003"), "swap still has headroom, shouldn't hit CRITICAL");

    let mem002 = findings.iter().find(|f| f.id == "MEM002").unwrap();
    assert_eq!(mem002.severity, Severity::Warning);
    // swappiness=10 is <=10, so the cross-reference note should appear.
    assert!(mem002.explanation.contains("stronger signal"));
}

#[test]
fn heavy_writeback_and_shared_memory_fixture_flags_both() {
    let meminfo = "\
MemTotal:       16384000 kB
MemFree:         6000000 kB
MemAvailable:    9000000 kB
Buffers:          200000 kB
Cached:          2000000 kB
Shmem:           4500000 kB
Dirty:           3500000 kB
SwapTotal:              0 kB
SwapFree:               0 kB
";
    let data = build_from_fixture(meminfo, "60\n", 20, 10);

    let findings = analyze(&data, &test_context());

    let mem005 = findings.iter().find(|f| f.id == "MEM005").unwrap();
    assert_eq!(mem005.severity, Severity::Error); // 3_500_000/16_384_000 ~21.4% >= 20%
    assert!(mem005.recommendation.is_some());

    let mem006 = findings.iter().find(|f| f.id == "MEM006").unwrap();
    assert_eq!(mem006.severity, Severity::Error); // 4_500_000/16_384_000 ~27.5% >= 25%
    assert!(mem006.recommendation.is_some());
}
