// SPDX-License-Identifier: GPL-3.0-only

use linuxdoctor::core::context::Context;
use linuxdoctor::models::Severity;
use linuxdoctor::modules::gpu::analyze::analyze;
use linuxdoctor::modules::gpu::collect::{GpuInfo, GpuProcess, GpuRawData, GpuVendor};

fn test_context() -> Context {
    Context {
        hostname: "test-host".into(),
        kernel_version: "6.8.0-test".into(),
        distro: Some("Test Linux".into()),
        architecture: "x86_64".into(),
        cpu_count: 8,
        mem_total_kb: 16_384_000,
        boot_time_unix: 0,
    }
}

/// This sandbox's real case: no GPU exposed at all (a minimal microVM).
#[test]
fn no_gpu_fixture_is_all_info() {
    let data = GpuRawData {
        gpus: vec![],
        nvidia_max_cuda_version: None,
    };
    let findings = analyze(&data, &test_context());
    assert!(findings.iter().all(|f| f.severity == Severity::Info));
    assert_eq!(findings.len(), 1);
    assert!(findings[0].explanation.contains("No GPU detected"));
}

#[test]
fn mixed_amd_and_nvidia_system_with_one_overheating() {
    let amd = GpuInfo {
        name: "card0".to_string(),
        pci_address: "0000:01:00.0".to_string(),
        vendor: GpuVendor::Amd,
        vendor_name: None,
        drm_card: true,
        description: Some("Radeon RX 6800".to_string()),
        driver: Some("amdgpu".to_string()),
        driver_version: None,
        vram_total_mb: Some(16384),
        vram_used_mb: Some(2048),
        utilization_percent: Some(12.0),
        memory_utilization_percent: Some(5.0),
        temperature_c: Some(55.0),
        temperature_crit_c: Some(110.0),
        power_draw_w: Some(80.0),
        power_limit_w: Some(250.0),
        fan_percent: None,
        fan_rpm: Some(1200),
        clock_core_mhz: None,
        clock_memory_mhz: None,
        clock_hw_max_mhz: None,
        clock_limit_mhz: None,
        idle: None,
        throttled: None,
        throttle_reasons: vec![],
        pcie_link_speed_current: None,
        pcie_link_speed_max: None,
        pcie_link_width_current: None,
        pcie_link_width_max: None,
        pcie_port_width_max: None,
        processes: vec![],
    };

    let nvidia = GpuInfo {
        name: "card1".to_string(),
        pci_address: "0000:02:00.0".to_string(),
        vendor: GpuVendor::Nvidia,
        vendor_name: None,
        drm_card: true,
        description: Some("NVIDIA GeForce RTX 4090".to_string()),
        driver: Some("nvidia".to_string()),
        driver_version: Some("550.78".to_string()),
        vram_total_mb: Some(24576),
        vram_used_mb: Some(23000),
        utilization_percent: Some(99.0),
        memory_utilization_percent: Some(95.0),
        temperature_c: Some(96.0), // above the generic 95C caution point
        temperature_crit_c: None,
        power_draw_w: Some(448.0),
        power_limit_w: Some(450.0),
        fan_percent: Some(87.0),
        fan_rpm: None,
        clock_core_mhz: Some(2520),
        clock_memory_mhz: Some(10501),
        clock_hw_max_mhz: None,
        clock_limit_mhz: None,
        idle: None,
        throttled: None,
        throttle_reasons: vec![],
        pcie_link_speed_current: Some("16.0 GT/s PCIe".to_string()),
        pcie_link_speed_max: Some("16.0 GT/s PCIe".to_string()),
        pcie_link_width_current: Some(16),
        pcie_link_width_max: Some(16),
        pcie_port_width_max: None,
        processes: vec![GpuProcess {
            pid: 12345,
            name: "python3".to_string(),
            memory_mb: Some(22000),
        }],
    };

    let data = GpuRawData {
        gpus: vec![amd, nvidia],
        nvidia_max_cuda_version: Some("12.4".to_string()),
    };
    let findings = analyze(&data, &test_context());

    let gpu001 = findings.iter().find(|f| f.id == "GPU001").unwrap();
    assert!(gpu001.explanation.contains("1 AMD"));
    assert!(gpu001.explanation.contains("1 NVIDIA"));

    let amd_finding = findings
        .iter()
        .find(|f| f.id == "GPU002" && f.instance.as_deref() == Some("card0"))
        .unwrap();
    assert_eq!(amd_finding.severity, Severity::Info);

    let nvidia_finding = findings
        .iter()
        .find(|f| f.id == "GPU002" && f.instance.as_deref() == Some("card1"))
        .unwrap();
    assert_eq!(nvidia_finding.severity, Severity::Warning);
    assert!(nvidia_finding
        .explanation
        .contains("python3 (pid 12345, 22000 MB)"));
    assert!(nvidia_finding
        .explanation
        .contains("NVIDIA GeForce RTX 4090"));
    // High utilization/VRAM/power on the busy card must not, on their
    // own, push severity any higher than the temperature check already
    // set it to.
    assert_eq!(nvidia_finding.severity, Severity::Warning);
}

/// An integrated Intel GPU reports no temperature at all, only what the
/// driver says about frequency and throttling -- and that is enough to raise
/// a Warning when the driver itself says heat is slowing the GPU down.
#[test]
fn intel_integrated_gpu_throttled_by_heat_is_a_warning() {
    let intel = GpuInfo {
        name: "card0".to_string(),
        pci_address: "0000:00:02.0".to_string(),
        vendor: GpuVendor::Intel,
        vendor_name: None,
        drm_card: true,
        description: Some("Alder Lake-P GT2 [Iris Xe Graphics]".to_string()),
        driver: Some("i915".to_string()),
        driver_version: None,
        vram_total_mb: None,
        vram_used_mb: None,
        utilization_percent: None,
        memory_utilization_percent: None,
        temperature_c: None,
        temperature_crit_c: None,
        power_draw_w: None,
        power_limit_w: None,
        fan_percent: None,
        fan_rpm: None,
        clock_core_mhz: Some(400),
        clock_memory_mhz: None,
        clock_hw_max_mhz: Some(1400),
        clock_limit_mhz: Some(1400),
        idle: Some(false),
        throttled: Some(true),
        throttle_reasons: vec!["thermal".to_string(), "pl1".to_string()],
        pcie_link_speed_current: None,
        pcie_link_speed_max: None,
        pcie_link_width_current: None,
        pcie_link_width_max: None,
        pcie_port_width_max: None,
        processes: vec![],
    };
    let data = GpuRawData {
        gpus: vec![intel],
        nvidia_max_cuda_version: None,
    };
    let findings = analyze(&data, &test_context());

    let gpu001 = findings.iter().find(|f| f.id == "GPU001").unwrap();
    assert!(gpu001.explanation.contains("1 Intel"));

    let gpu002 = findings.iter().find(|f| f.id == "GPU002").unwrap();
    assert_eq!(gpu002.severity, Severity::Warning);
    assert!(gpu002.explanation.contains("Thermal throttling"));
    assert!(gpu002.explanation.contains("Clock: 400 MHz core."));
    assert!(gpu002.recommendation.is_some());
    assert!(gpu002
        .evidence
        .iter()
        .any(|(k, v)| k == "throttle_reasons" && v == "thermal,pl1"));
}

/// A virtualization host as seen on the maintainer's own machine: one NVIDIA
/// card in use by the host, one reserved for VM passthrough (no DRM card),
/// and a management controller's video chip with no driver. Nothing here is
/// a problem, and nothing should be reported as one.
#[test]
fn a_passthrough_host_is_reported_without_raising_any_alarm() {
    let in_use = GpuInfo::new(
        "card0".to_string(),
        "0000:02:00.0".to_string(),
        GpuVendor::Nvidia,
        Some("NVIDIA GeForce GTX 1050 Ti".to_string()),
        Some("nvidia".to_string()),
        true,
    );
    let reserved = GpuInfo::new(
        "0000:04:00.0".to_string(),
        "0000:04:00.0".to_string(),
        GpuVendor::Nvidia,
        Some("NVIDIA GP102 [TITAN X Pascal]".to_string()),
        Some("vfio-pci".to_string()),
        false,
    );
    let bmc = GpuInfo::new(
        "0000:0b:00.0".to_string(),
        "0000:0b:00.0".to_string(),
        GpuVendor::Other,
        Some("ASPEED Graphics Family".to_string()),
        None,
        false,
    );
    let data = GpuRawData {
        gpus: vec![in_use, reserved, bmc],
        nvidia_max_cuda_version: None,
    };
    let findings = analyze(&data, &test_context());

    assert!(
        findings.iter().all(|f| f.severity == Severity::Info),
        "{:?}",
        findings
            .iter()
            .map(|f| (&f.id, f.severity))
            .collect::<Vec<_>>()
    );
    let gpu001 = findings.iter().find(|f| f.id == "GPU001").unwrap();
    assert!(gpu001
        .explanation
        .contains("3 GPUs detected: 2 NVIDIA, 1 unknown vendor."));
    assert!(gpu001.explanation.contains("1 of 3 is bound to vfio-pci"));
    assert_eq!(findings.iter().filter(|f| f.id == "GPU002").count(), 3);
}
