// SPDX-License-Identifier: GPL-3.0-only

use linuxdoctor::core::context::Context;
use linuxdoctor::models::Severity;
use linuxdoctor::modules::virtualization::analyze::analyze;
use linuxdoctor::modules::virtualization::collect::VirtualizationRawData;

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
fn bare_metal_fixture_is_info() {
    let data = VirtualizationRawData {
        tool_available: true,
        vm_type: Some("none".to_string()),
        container_type: Some("none".to_string()),
        cpuinfo_hypervisor_flag: false,
    };
    let findings = analyze(&data, &test_context());
    assert!(findings.iter().all(|f| f.severity == Severity::Info));
    assert!(findings[0].explanation.contains("bare metal"));
}

/// Mirrors this sandbox's real, verified result: `systemd-detect-virt`
/// works even without systemd as PID 1, reporting a nested
/// container-on-VM environment (docker on kvm).
#[test]
fn real_sandbox_nested_fixture() {
    let data = VirtualizationRawData {
        tool_available: true,
        vm_type: Some("kvm".to_string()),
        container_type: Some("docker".to_string()),
        cpuinfo_hypervisor_flag: true,
    };
    let findings = analyze(&data, &test_context());
    assert_eq!(findings[0].severity, Severity::Info);
    assert!(findings[0].explanation.contains("Nested"));
    assert!(findings[0]
        .evidence
        .iter()
        .any(|(k, v)| k == "vm_type" && v == "kvm"));
    assert!(findings[0]
        .evidence
        .iter()
        .any(|(k, v)| k == "container_type" && v == "docker"));
}
