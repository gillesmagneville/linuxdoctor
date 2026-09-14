// SPDX-License-Identifier: GPL-3.0-only

use linuxdoctor::core::context::Context;
use linuxdoctor::models::Severity;
use linuxdoctor::modules::firmware::analyze::analyze;
use linuxdoctor::modules::firmware::collect::{BootMode, FirmwareRawData};

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

/// A minimal/virtualized system (this sandbox's real shape): no
/// firmware identity exposed, legacy boot, no TPM, no virtualization
/// extensions visible. Everything should stay Info -- none of this is
/// a real problem on a microVM.
#[test]
fn minimal_vm_fixture_is_all_info() {
    let data = FirmwareRawData {
        bios_vendor: None,
        bios_version: None,
        bios_date: None,
        bios_release: None,
        board_vendor: None,
        board_name: None,
        boot_mode: BootMode::Legacy,
        secure_boot_enabled: None,
        tpm_present: false,
        virt_flag_present: false,
        kvm_module_loaded: false,
        dmesg_shows_bios_disabled: false,
        iommu_kernel_param_requested: false,
        iommu_active: false,
    };
    let findings = analyze(&data, &test_context());
    assert!(findings.iter().all(|f| f.severity == Severity::Info));
    assert_eq!(findings.len(), 4);
}

/// Realistic desktop scenario: a user wants to enable virtualization
/// and passthrough, and both are actually blocked at the BIOS level --
/// exactly the situation this module exists to surface.
#[test]
fn desktop_with_virtualization_and_iommu_both_blocked_by_bios() {
    let data = FirmwareRawData {
        bios_vendor: Some("American Megatrends Inc.".to_string()),
        bios_version: Some("3402".to_string()),
        bios_date: Some("03/14/2023".to_string()),
        bios_release: Some("5.17".to_string()),
        board_vendor: Some("ASRock".to_string()),
        board_name: Some("B550M Steel Legend".to_string()),
        boot_mode: BootMode::Uefi,
        secure_boot_enabled: Some(false),
        tpm_present: true,
        virt_flag_present: true,
        kvm_module_loaded: false,
        dmesg_shows_bios_disabled: true,
        iommu_kernel_param_requested: true,
        iommu_active: false,
    };
    let findings = analyze(&data, &test_context());

    let firm001 = findings.iter().find(|f| f.id == "FIRM001").unwrap();
    assert!(firm001.explanation.contains("ASRock B550M Steel Legend"));

    let firm002 = findings.iter().find(|f| f.id == "FIRM002").unwrap();
    assert_eq!(firm002.severity, Severity::Warning);
    assert!(firm002.explanation.contains("BIOS has disabled it"));

    let firm003 = findings.iter().find(|f| f.id == "FIRM003").unwrap();
    assert_eq!(firm003.severity, Severity::Warning);
    assert!(firm003.explanation.contains("isn't taking effect"));

    // Both warnings should be independently actionable with their own
    // BIOS-menu recommendation, since they're two genuinely separate
    // settings a user could easily conflate.
    assert!(firm002.recommendation.as_deref().unwrap().contains("VT-x"));
    assert!(firm003.recommendation.as_deref().unwrap().contains("VT-d"));
}
