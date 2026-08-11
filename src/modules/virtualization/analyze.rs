// SPDX-License-Identifier: GPL-3.0-only

use crate::core::context::Context;
use crate::models::{Category, Confidence, Finding, Severity};

use super::collect::{friendly_name, VirtualizationRawData};

/// Pure function: RawData -> Findings. No I/O — see ARCHITECTURE.md
/// "Testing Strategy".
pub fn analyze(data: &VirtualizationRawData, _ctx: &Context) -> Vec<Finding> {
    vec![detection_finding(data)]
}

/// VIRT001 — always reported. Purely descriptive: being virtualized (or
/// not) isn't inherently good or bad, so this never goes above Info.
fn detection_finding(data: &VirtualizationRawData) -> Finding {
    let explanation = if !data.tool_available {
        format!(
            "systemd-detect-virt isn't installed, so the specific \
             virtualization technology couldn't be identified. The CPU {} \
             a hypervisor flag (a weaker, less specific signal) — this {} \
             running under some form of hardware virtualization.",
            if data.cpuinfo_hypervisor_flag {
                "reports"
            } else {
                "does not report"
            },
            if data.cpuinfo_hypervisor_flag {
                "suggests the system is"
            } else {
                "doesn't confirm the system is"
            },
        )
    } else {
        let vm = data.vm_type.as_deref().unwrap_or("none");
        let container = data.container_type.as_deref().unwrap_or("none");

        match (vm, container) {
            ("none", "none") => "No virtualization detected — this appears \
                 to be running directly on physical hardware (bare metal)."
                .to_string(),
            (vm, "none") if vm != "none" => {
                format!("Running in a virtual machine ({}).", friendly_name(vm))
            }
            ("none", container) if container != "none" => format!(
                "Running in a container ({}), directly on the host's \
                 kernel (not inside a VM).",
                friendly_name(container),
            ),
            (vm, container) => format!(
                "Nested: running in a container ({}) on top of a virtual \
                 machine ({}).",
                friendly_name(container),
                friendly_name(vm),
            ),
        }
    };

    let mut builder = Finding::builder(
        "VIRT001",
        "Virtualization Detection",
        Category::Virtualization,
        Severity::Info,
        Confidence::direct_observation(),
    )
    .evidence("tool_available", data.tool_available.to_string());

    if let Some(vm) = &data.vm_type {
        builder = builder.evidence("vm_type", vm.clone());
    }
    if let Some(c) = &data.container_type {
        builder = builder.evidence("container_type", c.clone());
    }
    builder = builder.evidence(
        "cpuinfo_hypervisor_flag",
        data.cpuinfo_hypervisor_flag.to_string(),
    );

    builder.explanation(explanation).build()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ctx() -> Context {
        Context {
            hostname: "test".into(),
            kernel_version: "test".into(),
            distro: None,
            architecture: "x86_64".into(),
            cpu_count: 4,
            mem_total_kb: 16_384_000,
            boot_time_unix: 0,
        }
    }

    fn data(vm: &str, container: &str) -> VirtualizationRawData {
        VirtualizationRawData {
            tool_available: true,
            vm_type: Some(vm.to_string()),
            container_type: Some(container.to_string()),
            cpuinfo_hypervisor_flag: vm != "none",
        }
    }

    #[test]
    fn always_reports_one_finding() {
        let findings = analyze(&data("none", "none"), &ctx());
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].id, "VIRT001");
    }

    #[test]
    fn bare_metal_is_info() {
        let findings = analyze(&data("none", "none"), &ctx());
        assert_eq!(findings[0].severity, Severity::Info);
        assert!(findings[0].explanation.contains("bare metal"));
    }

    #[test]
    fn vm_only_reports_friendly_name() {
        let findings = analyze(&data("kvm", "none"), &ctx());
        assert!(findings[0].explanation.contains("virtual machine (KVM)"));
    }

    #[test]
    fn container_only_reports_friendly_name() {
        let findings = analyze(&data("none", "docker"), &ctx());
        assert!(findings[0].explanation.contains("container (Docker)"));
        assert!(findings[0].explanation.contains("not inside a VM"));
    }

    #[test]
    fn nested_vm_and_container_both_reported() {
        // Mirrors this sandbox's real result: docker on top of kvm.
        let findings = analyze(&data("kvm", "docker"), &ctx());
        assert!(findings[0].explanation.contains("Nested"));
        assert!(findings[0].explanation.contains("Docker"));
        assert!(findings[0].explanation.contains("KVM"));
    }

    #[test]
    fn tool_unavailable_falls_back_to_cpuinfo_flag() {
        let data = VirtualizationRawData {
            tool_available: false,
            vm_type: None,
            container_type: None,
            cpuinfo_hypervisor_flag: true,
        };
        let findings = analyze(&data, &ctx());
        assert!(findings[0].explanation.contains("isn't installed"));
        assert!(findings[0].explanation.contains("reports"));
    }

    #[test]
    fn confidence_never_reported_below_60() {
        for d in [
            data("none", "none"),
            data("kvm", "docker"),
            VirtualizationRawData {
                tool_available: false,
                vm_type: None,
                container_type: None,
                cpuinfo_hypervisor_flag: false,
            },
        ] {
            for f in analyze(&d, &ctx()) {
                assert!(f.confidence.percent >= 60);
            }
        }
    }
}
