// SPDX-License-Identifier: GPL-3.0-only

use crate::core::context::Context;
use crate::models::{Category, Confidence, Finding, Severity};

use super::collect::{BootMode, FirmwareRawData};

/// Pure function: RawData -> Findings. No I/O — see ARCHITECTURE.md
/// "Testing Strategy".
pub fn analyze(data: &FirmwareRawData, ctx: &Context) -> Vec<Finding> {
    let mut findings = vec![identity_finding(data)];
    // VT-x/AMD-V is x86-specific terminology; on other architectures
    // this finding would be inapplicable rather than merely absent, so
    // it's skipped entirely there rather than reported with the wrong
    // vocabulary — same reasoning as the CUDA-core-count omission in
    // the GPU module: don't present something under vocabulary that
    // doesn't fit the platform.
    if ctx.architecture.starts_with("x86") {
        findings.push(virt_extensions_finding(data));
    }
    findings.push(iommu_finding(data));
    findings.push(tpm_finding(data));
    findings
}

fn identity_finding(data: &FirmwareRawData) -> Finding {
    let vendor = data.bios_vendor.as_deref().unwrap_or("unknown vendor");
    let version_note = data
        .bios_version
        .as_deref()
        .map(|v| format!(", version {v}"))
        .unwrap_or_default();
    let date_note = data
        .bios_date
        .as_deref()
        .map(|d| format!(", dated {d}"))
        .unwrap_or_default();
    let release_note = data
        .bios_release
        .as_deref()
        .map(|r| format!(" (SMBIOS BIOS Revision {r})"))
        .unwrap_or_default();
    let board_note = match (&data.board_vendor, &data.board_name) {
        (Some(v), Some(n)) => format!(" Motherboard: {v} {n}."),
        (Some(v), None) => format!(" Motherboard vendor: {v}."),
        (None, Some(n)) => format!(" Motherboard: {n}."),
        (None, None) => String::new(),
    };
    let boot_mode_str = match data.boot_mode {
        BootMode::Uefi => "UEFI",
        BootMode::Legacy => "Legacy BIOS (CSM)",
    };
    let secure_boot_note = match data.secure_boot_enabled {
        Some(true) => " Secure Boot is enabled.".to_string(),
        Some(false) => " Secure Boot is disabled — a legitimate choice for many setups \
                        (e.g. some out-of-tree drivers, dual-boot configurations), not \
                        inherently a problem."
            .to_string(),
        None => {
            " Secure Boot state could not be determined (`mokutil` isn't installed).".to_string()
        }
    };

    let explanation = format!(
        "{vendor}{version_note}{date_note}{release_note}.{board_note} Boot mode: {boot_mode_str}.{secure_boot_note}"
    );

    let mut builder = Finding::builder(
        "FIRM001",
        "Firmware Identity & Boot Mode",
        Category::Firmware,
        Severity::Info,
        Confidence::direct_observation(),
    );

    if let Some(v) = &data.bios_vendor {
        builder = builder.evidence("bios_vendor", v.clone());
    }
    if let Some(v) = &data.bios_version {
        builder = builder.evidence("bios_version", v.clone());
    }
    if let Some(v) = &data.bios_date {
        builder = builder.evidence("bios_date", v.clone());
    }
    if let Some(v) = &data.bios_release {
        builder = builder.evidence("bios_release", v.clone());
    }
    if let Some(v) = &data.board_vendor {
        builder = builder.evidence("board_vendor", v.clone());
    }
    if let Some(v) = &data.board_name {
        builder = builder.evidence("board_name", v.clone());
    }
    builder = builder.evidence("boot_mode", boot_mode_str.to_string());
    if let Some(sb) = data.secure_boot_enabled {
        builder = builder.evidence("secure_boot_enabled", sb.to_string());
    }

    builder.explanation(explanation).build()
}

/// FIRM002 — VT-x/AMD-V. Only produced on x86 (see `analyze()`).
/// Severity only escalates for the one case with a direct confirming
/// signal (`dmesg` explicitly says so) — everything else, including the
/// flag being entirely absent, stays Info: a machine that was never
/// meant to run VMs not supporting/exposing virtualization is not a
/// problem on its own, and the flag's absence alone can't distinguish
/// "unsupported hardware" from "BIOS-disabled" (a real, confirmed
/// ambiguity — see collect.rs).
fn virt_extensions_finding(data: &FirmwareRawData) -> Finding {
    let (severity, confidence, explanation, recommendation) = match (
        data.virt_flag_present,
        data.kvm_module_loaded,
        data.dmesg_shows_bios_disabled,
    ) {
        (true, true, _) => (
            Severity::Info,
            Confidence::direct_observation(),
            "Hardware virtualization (Intel VT-x / AMD-V) is supported and \
                 currently active — the kvm_intel/kvm_amd kernel module is loaded."
                .to_string(),
            None,
        ),
        (true, false, true) => (
            Severity::Warning,
            Confidence::strong_indication(80),
            "The CPU supports hardware virtualization (Intel VT-x / AMD-V), \
                 but the BIOS has disabled it — confirmed by a \"disabled by bios\" \
                 message in the current dmesg buffer."
                .to_string(),
            Some(
                "Enter BIOS/UEFI Setup and enable the virtualization extension \
                     (often labeled \"Intel VT-x\", \"AMD-V\", \"SVM Mode\", or just \
                     \"Virtualization\", typically under a CPU or Advanced menu)."
                    .to_string(),
            ),
        ),
        (true, false, false) => (
            Severity::Info,
            Confidence::direct_observation(),
            "The CPU supports hardware virtualization (Intel VT-x / AMD-V). \
                 The kvm_intel/kvm_amd kernel module isn't currently loaded — this \
                 is expected if nothing has needed it yet, not itself a sign of a \
                 problem."
                .to_string(),
            None,
        ),
        (false, _, _) => (
            Severity::Info,
            Confidence::weak_indication(60),
            "The CPU doesn't report hardware virtualization support (no \
                 vmx/svm flag in /proc/cpuinfo). This means either the CPU \
                 genuinely lacks Intel VT-x / AMD-V, or the BIOS has disabled it \
                 in a way that hides the flag entirely — the two look identical \
                 from this data alone. Almost all x86_64 CPUs from the last \
                 decade support this, so if you believe this one should, it's \
                 worth checking BIOS Setup."
                .to_string(),
            None,
        ),
    };

    let mut builder = Finding::builder(
        "FIRM002",
        "Virtualization Extensions (VT-x/AMD-V)",
        Category::Firmware,
        severity,
        confidence,
    )
    .evidence("virt_flag_present", data.virt_flag_present.to_string())
    .evidence("kvm_module_loaded", data.kvm_module_loaded.to_string());

    if data.dmesg_shows_bios_disabled {
        builder = builder.evidence("dmesg_shows_bios_disabled", "true".to_string());
    }

    builder = builder.explanation(explanation);
    if let Some(rec) = recommendation {
        builder = builder.recommendation(rec);
    }
    builder.build()
}

/// FIRM003 — IOMMU (Intel VT-d / AMD-Vi). Directly relevant to PCI
/// passthrough — cross-references with the GPU module's SR-IOV/
/// passthrough findings and Virtualization's VFIO device handling.
fn iommu_finding(data: &FirmwareRawData) -> Finding {
    let (severity, explanation, recommendation) =
        match (data.iommu_kernel_param_requested, data.iommu_active) {
            (true, true) => (
                Severity::Info,
                "IOMMU (Intel VT-d / AMD-Vi) was requested on the kernel command \
                 line and is active — /sys/class/iommu/ shows real IOMMU devices. \
                 PCI passthrough (SR-IOV, VFIO) is usable on this system."
                    .to_string(),
                None,
            ),
            (true, false) => (
                Severity::Warning,
                "IOMMU was requested on the kernel command line (an *_iommu= \
                 parameter is set), but /sys/class/iommu/ shows nothing active — \
                 the request isn't taking effect. Most likely cause: Intel VT-d / \
                 AMD-Vi is disabled in BIOS, or this hardware doesn't support it. \
                 PCI passthrough (SR-IOV, VFIO) won't work until this is resolved."
                    .to_string(),
                Some(
                    "Enter BIOS/UEFI Setup and enable \"Intel VT-d\" or \"AMD-Vi/IOMMU\" \
                     (often under an Advanced or Chipset menu), then reboot."
                        .to_string(),
                ),
            ),
            (false, true) => (
                Severity::Info,
                "IOMMU (Intel VT-d / AMD-Vi) is active even without an explicit \
                 kernel parameter requesting it — likely a platform/distro default."
                    .to_string(),
                None,
            ),
            (false, false) => (
                Severity::Info,
                "IOMMU (Intel VT-d / AMD-Vi) isn't requested and isn't active. \
                 Expected unless PCI passthrough (SR-IOV, VFIO — see the \
                 virtualization and GPU modules) is needed."
                    .to_string(),
                None,
            ),
        };

    let mut builder = Finding::builder(
        "FIRM003",
        "IOMMU (VT-d/AMD-Vi)",
        Category::Firmware,
        severity,
        Confidence::direct_observation(),
    )
    .evidence(
        "iommu_kernel_param_requested",
        data.iommu_kernel_param_requested.to_string(),
    )
    .evidence("iommu_active", data.iommu_active.to_string())
    .explanation(explanation);

    if let Some(rec) = recommendation {
        builder = builder.recommendation(rec);
    }
    builder.build()
}

/// FIRM004 — TPM presence. Purely informational either way: a home
/// system without a TPM isn't "broken", it just lacks that specific
/// security feature.
fn tpm_finding(data: &FirmwareRawData) -> Finding {
    let explanation = if data.tpm_present {
        "A TPM (Trusted Platform Module) is present (/sys/class/tpm/ has an \
         entry) — usable for full-disk encryption key sealing (LUKS+TPM, \
         BitLocker-equivalent setups) and measured boot."
            .to_string()
    } else {
        "No TPM detected under /sys/class/tpm/. Not inherently a problem — \
         relevant mainly if you want hardware-backed disk encryption key \
         sealing or measured boot."
            .to_string()
    };

    Finding::builder(
        "FIRM004",
        "TPM Presence",
        Category::Firmware,
        Severity::Info,
        Confidence::direct_observation(),
    )
    .evidence("tpm_present", data.tpm_present.to_string())
    .explanation(explanation)
    .build()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ctx_x86() -> Context {
        Context {
            hostname: "test".into(),
            kernel_version: "test".into(),
            distro: None,
            architecture: "x86_64".into(),
            cpu_count: 8,
            mem_total_kb: 16_000_000,
            boot_time_unix: 0,
        }
    }

    fn ctx_arm() -> Context {
        Context {
            architecture: "aarch64".into(),
            ..ctx_x86()
        }
    }

    fn base_data() -> FirmwareRawData {
        FirmwareRawData {
            bios_vendor: Some("American Megatrends Inc.".to_string()),
            bios_version: Some("GL702ZC.305".to_string()),
            bios_date: Some("05/10/2018".to_string()),
            bios_release: Some("5.13".to_string()),
            board_vendor: Some("ASUSTeK COMPUTER INC.".to_string()),
            board_name: Some("GL702ZC".to_string()),
            boot_mode: BootMode::Uefi,
            secure_boot_enabled: Some(true),
            tpm_present: true,
            virt_flag_present: true,
            kvm_module_loaded: true,
            dmesg_shows_bios_disabled: false,
            iommu_kernel_param_requested: true,
            iommu_active: true,
        }
    }

    #[test]
    fn identity_finding_reads_naturally() {
        let findings = analyze(&base_data(), &ctx_x86());
        let f = findings.iter().find(|f| f.id == "FIRM001").unwrap();
        assert!(f.explanation.contains("American Megatrends Inc."));
        assert!(f.explanation.contains("GL702ZC.305"));
        assert!(f.explanation.contains("SMBIOS BIOS Revision 5.13"));
        assert!(f.explanation.contains("ASUSTeK COMPUTER INC. GL702ZC"));
        assert!(f.explanation.contains("Boot mode: UEFI"));
        assert!(f.explanation.contains("Secure Boot is enabled"));
        assert_eq!(f.severity, Severity::Info);
    }

    #[test]
    fn secure_boot_disabled_is_still_info_not_a_warning() {
        let mut data = base_data();
        data.secure_boot_enabled = Some(false);
        let findings = analyze(&data, &ctx_x86());
        let f = findings.iter().find(|f| f.id == "FIRM001").unwrap();
        assert!(f.explanation.contains("Secure Boot is disabled"));
        assert!(f.explanation.contains("legitimate choice"));
        assert_eq!(f.severity, Severity::Info);
    }

    #[test]
    fn secure_boot_unknown_when_mokutil_absent() {
        let mut data = base_data();
        data.secure_boot_enabled = None;
        let findings = analyze(&data, &ctx_x86());
        let f = findings.iter().find(|f| f.id == "FIRM001").unwrap();
        assert!(f.explanation.contains("could not be determined"));
        assert!(!f.evidence.iter().any(|(k, _)| k == "secure_boot_enabled"));
    }

    #[test]
    fn virt_extensions_skipped_on_non_x86() {
        let findings = analyze(&base_data(), &ctx_arm());
        assert!(!findings.iter().any(|f| f.id == "FIRM002"));
    }

    #[test]
    fn virt_extensions_active_via_kvm_is_info() {
        let findings = analyze(&base_data(), &ctx_x86());
        let f = findings.iter().find(|f| f.id == "FIRM002").unwrap();
        assert_eq!(f.severity, Severity::Info);
        assert!(f.explanation.contains("currently active"));
    }

    #[test]
    fn virt_extensions_confirmed_disabled_by_bios_is_warning() {
        let mut data = base_data();
        data.kvm_module_loaded = false;
        data.dmesg_shows_bios_disabled = true;
        let findings = analyze(&data, &ctx_x86());
        let f = findings.iter().find(|f| f.id == "FIRM002").unwrap();
        assert_eq!(f.severity, Severity::Warning);
        assert!(f.explanation.contains("BIOS has disabled it"));
        assert!(f.recommendation.is_some());
    }

    #[test]
    fn virt_extensions_supported_but_module_not_loaded_is_not_alarming() {
        let mut data = base_data();
        data.kvm_module_loaded = false;
        data.dmesg_shows_bios_disabled = false;
        let findings = analyze(&data, &ctx_x86());
        let f = findings.iter().find(|f| f.id == "FIRM002").unwrap();
        assert_eq!(f.severity, Severity::Info);
        assert!(f.explanation.contains("not itself a sign of a problem"));
    }

    #[test]
    fn virt_extensions_flag_absent_is_hedged_not_alarming() {
        let mut data = base_data();
        data.virt_flag_present = false;
        data.kvm_module_loaded = false;
        let findings = analyze(&data, &ctx_x86());
        let f = findings.iter().find(|f| f.id == "FIRM002").unwrap();
        assert_eq!(f.severity, Severity::Info);
        assert!(f
            .explanation
            .contains("look identical from this data alone"));
        assert!(f.confidence.percent < 70);
    }

    #[test]
    fn iommu_requested_and_active_is_info() {
        let findings = analyze(&base_data(), &ctx_x86());
        let f = findings.iter().find(|f| f.id == "FIRM003").unwrap();
        assert_eq!(f.severity, Severity::Info);
        assert!(f.explanation.contains("passthrough"));
    }

    #[test]
    fn iommu_requested_but_not_active_is_warning() {
        let mut data = base_data();
        data.iommu_active = false;
        let findings = analyze(&data, &ctx_x86());
        let f = findings.iter().find(|f| f.id == "FIRM003").unwrap();
        assert_eq!(f.severity, Severity::Warning);
        assert!(f.explanation.contains("isn't taking effect"));
        assert!(f.recommendation.is_some());
    }

    #[test]
    fn iommu_neither_requested_nor_active_is_info() {
        let mut data = base_data();
        data.iommu_kernel_param_requested = false;
        data.iommu_active = false;
        let findings = analyze(&data, &ctx_x86());
        let f = findings.iter().find(|f| f.id == "FIRM003").unwrap();
        assert_eq!(f.severity, Severity::Info);
    }

    #[test]
    fn tpm_present_and_absent_are_both_info() {
        let mut data = base_data();
        let findings_present = analyze(&data, &ctx_x86());
        assert_eq!(
            findings_present
                .iter()
                .find(|f| f.id == "FIRM004")
                .unwrap()
                .severity,
            Severity::Info
        );
        data.tpm_present = false;
        let findings_absent = analyze(&data, &ctx_x86());
        let f = findings_absent.iter().find(|f| f.id == "FIRM004").unwrap();
        assert_eq!(f.severity, Severity::Info);
        assert!(f.explanation.contains("No TPM detected"));
    }

    #[test]
    fn confidence_never_reported_below_60() {
        for data in [base_data(), {
            let mut d = base_data();
            d.virt_flag_present = false;
            d.secure_boot_enabled = None;
            d
        }] {
            for f in analyze(&data, &ctx_x86()) {
                assert!(f.confidence.percent >= 60);
            }
        }
    }
}
