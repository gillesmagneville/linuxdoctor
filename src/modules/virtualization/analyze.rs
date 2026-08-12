// SPDX-License-Identifier: GPL-3.0-only

use crate::core::context::Context;
use crate::models::{Category, Confidence, Finding, Severity};

use super::collect::{friendly_name, ContainerInfo, VirtualizationRawData, VmDisk, VmInfo};

/// Pure function: RawData -> Findings. No I/O — see ARCHITECTURE.md
/// "Testing Strategy".
pub fn analyze(data: &VirtualizationRawData, _ctx: &Context) -> Vec<Finding> {
    let mut findings = vec![detection_finding(data), vm_summary_finding(data)];
    for vm in &data.vm_inventory.items {
        findings.push(vm_detail_finding(vm));
    }
    findings.push(container_summary_finding(data));
    for c in &data.container_inventory.items {
        findings.push(container_detail_finding(c));
    }
    findings
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

/// VIRT002 — always reported. Same "always present" reasoning as
/// STOR003/CPU005: a missing VM finding should never be ambiguous
/// between "no VMs" and "didn't check".
fn vm_summary_finding(data: &VirtualizationRawData) -> Finding {
    let inv = &data.vm_inventory;

    let explanation = if !inv.available {
        format!(
            "No VM inventory available: {}.",
            inv.unavailable_reason.as_deref().unwrap_or("virsh not found")
        )
    } else {
        let total = inv.items.len();
        let running = inv.items.iter().filter(|v| v.state == "running").count();
        if total == 0 {
            "virsh is available and reachable, but no VMs are currently defined."
                .to_string()
        } else {
            format!(
                "{total} VM{s} defined via libvirt, {running} currently running.",
                s = if total == 1 { "" } else { "s" },
            )
        }
    };

    Finding::builder(
        "VIRT002",
        "VM Inventory Summary",
        Category::Virtualization,
        Severity::Info,
        Confidence::direct_observation(),
    )
    .evidence("available", inv.available.to_string())
    .evidence("vm_count", inv.items.len().to_string())
    .explanation(explanation)
    .build()
}

/// VIRT003 — one finding per VM. Purely descriptive: resource
/// consumption here reflects what the admin already provisioned, not a
/// threshold to alert on.
/// Group consecutive vCPUs sharing the same host affinity into one
/// readable clause, e.g. "vCPUs 0-1: host 0-3; vCPUs 2-3: host 4-7"
/// rather than one line per vCPU.
fn format_vcpu_pinning(pinning: &[(u32, String)]) -> Option<String> {
    if pinning.is_empty() {
        return None;
    }
    let mut groups: Vec<(Vec<u32>, String)> = Vec::new();
    for (vcpu, affinity) in pinning {
        if let Some(last) = groups.last_mut() {
            if last.1 == *affinity {
                last.0.push(*vcpu);
                continue;
            }
        }
        groups.push((vec![*vcpu], affinity.clone()));
    }
    let parts: Vec<String> = groups
        .iter()
        .map(|(vcpus, affinity)| {
            let label = match (vcpus.first(), vcpus.last()) {
                (Some(first), Some(last)) if first != last => format!("vCPUs {first}-{last}"),
                (Some(first), _) => format!("vCPU {first}"),
                _ => "vCPU".to_string(),
            };
            format!("{label}: host {affinity}")
        })
        .collect();
    Some(parts.join("; "))
}

/// Summarize per-disk capacity/allocation, e.g. "vda (22.5 GB allocated
/// of 50.0 GB capacity)" — allocation is the figure that actually
/// matters for thin-provisioned formats like qcow2, where it's normally
/// well under capacity.
fn format_disks(disks: &[VmDisk]) -> Option<String> {
    if disks.is_empty() {
        return None;
    }
    let to_gb = |b: u64| b as f64 / 1024.0 / 1024.0 / 1024.0;
    let parts: Vec<String> = disks
        .iter()
        .map(|d| match (d.capacity_bytes, d.allocation_bytes) {
            (Some(cap), Some(alloc)) => format!(
                "{} ({:.1} GB allocated of {:.1} GB capacity)",
                d.target,
                to_gb(alloc),
                to_gb(cap),
            ),
            (Some(cap), None) => format!("{} ({:.1} GB capacity)", d.target, to_gb(cap)),
            _ => d.target.clone(),
        })
        .collect();
    Some(parts.join(", "))
}

fn vm_detail_finding(vm: &VmInfo) -> Finding {
    let to_gb = |kb: u64| kb as f64 / 1024.0 / 1024.0;

    let vcpu_note = vm
        .vcpus
        .map(|n| format!(", {n} vCPU{s}", s = if n == 1 { "" } else { "s" }))
        .unwrap_or_default();
    let max_mem_note = vm
        .max_memory_kb
        .map(|kb| format!(", up to {:.1} GB memory", to_gb(kb)))
        .unwrap_or_default();
    let used_mem_note = vm
        .used_memory_kb
        .map(|kb| format!(" Currently using {:.1} GB on the host.", to_gb(kb)))
        .unwrap_or_default();
    let autostart_mismatch = vm.autostart == Some(true) && vm.state != "running";
    let autostart_note = if autostart_mismatch {
        " Configured to autostart, but is not currently running — worth \
         confirming that's intentional (e.g. stopped for maintenance)."
    } else {
        ""
    };
    let pinning_summary = format_vcpu_pinning(&vm.vcpu_pinning);
    let pinning_note = pinning_summary
        .as_ref()
        .map(|p| format!(" CPU pinning — {p}."))
        .unwrap_or_default();
    let disks_summary = format_disks(&vm.disks);
    let disks_note = disks_summary
        .as_ref()
        .map(|d| format!(" Storage: {d}."))
        .unwrap_or_default();

    let explanation = format!(
        "{}: {}{vcpu_note}{max_mem_note}.{used_mem_note}{autostart_note}{pinning_note}{disks_note}",
        vm.name, vm.state,
    );

    let mut builder = Finding::builder(
        "VIRT003",
        format!("Virtual Machine \u{2014} {}", vm.name),
        Category::Virtualization,
        Severity::Info,
        Confidence::direct_observation(),
    )
    .instance(vm.name.clone())
    .evidence("state", vm.state.clone());

    if let Some(n) = vm.vcpus {
        builder = builder.evidence("vcpus", n.to_string());
    }
    if let Some(kb) = vm.max_memory_kb {
        builder = builder.evidence("max_memory_kb", kb.to_string());
    }
    if let Some(kb) = vm.used_memory_kb {
        builder = builder.evidence("used_memory_kb", kb.to_string());
    }
    if let Some(t) = vm.cpu_time_seconds {
        builder = builder.evidence("cpu_time_seconds", format!("{t:.1}"));
    }
    if let Some(a) = vm.autostart {
        builder = builder.evidence("autostart", a.to_string());
    }
    if let Some(p) = &pinning_summary {
        builder = builder.evidence("vcpu_pinning", p.clone());
    }
    for disk in &vm.disks {
        builder = builder.evidence(
            format!("disk:{}", disk.target),
            disk.source.clone().unwrap_or_else(|| "unknown source".to_string()),
        );
        if let Some(cap) = disk.capacity_bytes {
            builder = builder.evidence(format!("disk:{}:capacity_bytes", disk.target), cap.to_string());
        }
        if let Some(alloc) = disk.allocation_bytes {
            builder = builder.evidence(
                format!("disk:{}:allocation_bytes", disk.target),
                alloc.to_string(),
            );
        }
    }

    builder.explanation(explanation).build()
}

/// VIRT004 — always reported, mirrors VIRT002 for containers.
fn container_summary_finding(data: &VirtualizationRawData) -> Finding {
    let inv = &data.container_inventory;

    let explanation = if !inv.available {
        format!(
            "No container inventory available: {}.",
            inv.unavailable_reason
                .as_deref()
                .unwrap_or("neither docker nor podman found")
        )
    } else {
        let total = inv.items.len();
        let running = inv.items.iter().filter(|c| c.state == "running").count();
        let runtime = inv.runtime.as_deref().unwrap_or("container runtime");
        if total == 0 {
            format!("{runtime} is available, but no containers are currently defined.")
        } else {
            format!(
                "{total} container{s} found via {runtime}, {running} currently running.",
                s = if total == 1 { "" } else { "s" },
            )
        }
    };

    let mut builder = Finding::builder(
        "VIRT004",
        "Container Inventory Summary",
        Category::Virtualization,
        Severity::Info,
        Confidence::direct_observation(),
    )
    .evidence("available", inv.available.to_string())
    .evidence("container_count", inv.items.len().to_string());

    if let Some(r) = &inv.runtime {
        builder = builder.evidence("runtime", r.clone());
    }

    builder.explanation(explanation).build()
}

/// VIRT005 — one finding per container.
fn container_detail_finding(c: &ContainerInfo) -> Finding {
    let resource_note = match (&c.cpu_percent, &c.mem_usage, &c.mem_percent) {
        (Some(cpu), Some(mem), Some(mem_pct)) => {
            format!(" Currently using {cpu} CPU and {mem} memory ({mem_pct}).")
        }
        _ => String::new(),
    };

    let explanation = format!(
        "{}: {} (image: {}).{resource_note}",
        c.name, c.status, c.image,
    );

    let mut builder = Finding::builder(
        "VIRT005",
        format!("Container \u{2014} {}", c.name),
        Category::Virtualization,
        Severity::Info,
        Confidence::direct_observation(),
    )
    .instance(c.name.clone())
    .evidence("state", c.state.clone())
    .evidence("status", c.status.clone())
    .evidence("image", c.image.clone());

    if let Some(v) = &c.cpu_percent {
        builder = builder.evidence("cpu_percent", v.clone());
    }
    if let Some(v) = &c.mem_usage {
        builder = builder.evidence("mem_usage", v.clone());
    }
    if let Some(v) = &c.mem_percent {
        builder = builder.evidence("mem_percent", v.clone());
    }

    builder.explanation(explanation).build()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::modules::virtualization::collect::ToolInventory;

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

    fn empty_inventories() -> (ToolInventory<VmInfo>, ToolInventory<ContainerInfo>) {
        (
            ToolInventory {
                runtime: None,
                available: false,
                unavailable_reason: Some("virsh is not installed".to_string()),
                items: vec![],
            },
            ToolInventory {
                runtime: None,
                available: false,
                unavailable_reason: Some("neither docker nor podman is installed".to_string()),
                items: vec![],
            },
        )
    }

    fn data(vm: &str, container: &str) -> VirtualizationRawData {
        let (vm_inventory, container_inventory) = empty_inventories();
        VirtualizationRawData {
            tool_available: true,
            vm_type: Some(vm.to_string()),
            container_type: Some(container.to_string()),
            cpuinfo_hypervisor_flag: vm != "none",
            vm_inventory,
            container_inventory,
        }
    }

    #[test]
    fn always_reports_three_summary_findings_with_empty_inventories() {
        let findings = analyze(&data("none", "none"), &ctx());
        assert_eq!(findings.len(), 3); // VIRT001, VIRT002, VIRT004 -- no per-item findings
        assert_eq!(findings[0].id, "VIRT001");
        assert!(findings.iter().any(|f| f.id == "VIRT002"));
        assert!(findings.iter().any(|f| f.id == "VIRT004"));
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
        let (vm_inventory, container_inventory) = empty_inventories();
        let data = VirtualizationRawData {
            tool_available: false,
            vm_type: None,
            container_type: None,
            cpuinfo_hypervisor_flag: true,
            vm_inventory,
            container_inventory,
        };
        let findings = analyze(&data, &ctx());
        assert!(findings[0].explanation.contains("isn't installed"));
        assert!(findings[0].explanation.contains("reports"));
    }

    fn running_vm() -> VmInfo {
        VmInfo {
            name: "web1".to_string(),
            state: "running".to_string(),
            vcpus: Some(4),
            max_memory_kb: Some(4_194_304),
            used_memory_kb: Some(4_194_304),
            cpu_time_seconds: Some(12345.6),
            autostart: Some(true),
            vcpu_pinning: vec![
                (0, "0-3".to_string()),
                (1, "0-3".to_string()),
                (2, "4-7".to_string()),
                (3, "4-7".to_string()),
            ],
            disks: vec![VmDisk {
                target: "vda".to_string(),
                source: Some("/var/lib/libvirt/images/web1.qcow2".to_string()),
                capacity_bytes: Some(53_687_091_200),
                allocation_bytes: Some(22_548_578_304),
            }],
        }
    }

    #[test]
    fn vm_summary_reports_count_and_running_when_available() {
        let mut d = data("none", "none");
        d.vm_inventory = ToolInventory {
            runtime: Some("virsh".to_string()),
            available: true,
            unavailable_reason: None,
            items: vec![running_vm()],
        };
        let findings = analyze(&d, &ctx());
        let virt002 = findings.iter().find(|f| f.id == "VIRT002").unwrap();
        assert!(virt002.explanation.contains("1 VM"));
        assert!(virt002.explanation.contains("1 currently running"));
        let virt003 = findings.iter().find(|f| f.id == "VIRT003").unwrap();
        assert_eq!(virt003.instance.as_deref(), Some("web1"));
        assert_eq!(virt003.severity, Severity::Info);
    }

    #[test]
    fn vm_detail_surfaces_pinning_and_disk_info() {
        let mut d = data("none", "none");
        d.vm_inventory = ToolInventory {
            runtime: Some("virsh".to_string()),
            available: true,
            unavailable_reason: None,
            items: vec![running_vm()],
        };
        let findings = analyze(&d, &ctx());
        let virt003 = findings.iter().find(|f| f.id == "VIRT003").unwrap();
        assert!(virt003.explanation.contains("vCPUs 0-1: host 0-3"));
        assert!(virt003.explanation.contains("vCPUs 2-3: host 4-7"));
        assert!(virt003.explanation.contains("vda"));
        assert!(virt003.explanation.contains("21.0 GB allocated"));
        assert!(virt003
            .evidence
            .iter()
            .any(|(k, _)| k == "disk:vda"));
    }

    #[test]
    fn stopped_vm_configured_to_autostart_gets_a_note() {
        let mut vm = running_vm();
        vm.state = "shut off".to_string();
        vm.used_memory_kb = None;
        let mut d = data("none", "none");
        d.vm_inventory = ToolInventory {
            runtime: Some("virsh".to_string()),
            available: true,
            unavailable_reason: None,
            items: vec![vm],
        };
        let findings = analyze(&d, &ctx());
        let virt003 = findings.iter().find(|f| f.id == "VIRT003").unwrap();
        // Still Info -- not an alarm, just a note.
        assert_eq!(virt003.severity, Severity::Info);
        assert!(virt003.explanation.contains("worth confirming"));
    }

    fn running_container() -> ContainerInfo {
        ContainerInfo {
            name: "web-frontend".to_string(),
            state: "running".to_string(),
            status: "Up 3 hours".to_string(),
            image: "nginx:latest".to_string(),
            cpu_percent: Some("1.23%".to_string()),
            mem_usage: Some("45.6MiB / 2GiB".to_string()),
            mem_percent: Some("2.28%".to_string()),
        }
    }

    #[test]
    fn container_summary_and_detail_when_available() {
        let mut d = data("none", "none");
        d.container_inventory = ToolInventory {
            runtime: Some("docker".to_string()),
            available: true,
            unavailable_reason: None,
            items: vec![running_container()],
        };
        let findings = analyze(&d, &ctx());
        let virt004 = findings.iter().find(|f| f.id == "VIRT004").unwrap();
        assert!(virt004.explanation.contains("1 container"));
        let virt005 = findings.iter().find(|f| f.id == "VIRT005").unwrap();
        assert_eq!(virt005.instance.as_deref(), Some("web-frontend"));
        assert!(virt005.explanation.contains("1.23% CPU"));
        assert!(virt005.explanation.contains("45.6MiB / 2GiB"));
    }

    #[test]
    fn confidence_never_reported_below_60() {
        let mut nested = data("kvm", "docker");
        nested.vm_inventory = ToolInventory {
            runtime: Some("virsh".to_string()),
            available: true,
            unavailable_reason: None,
            items: vec![running_vm()],
        };
        nested.container_inventory = ToolInventory {
            runtime: Some("docker".to_string()),
            available: true,
            unavailable_reason: None,
            items: vec![running_container()],
        };

        let (vm_inv, container_inv) = empty_inventories();
        let unavailable = VirtualizationRawData {
            tool_available: false,
            vm_type: None,
            container_type: None,
            cpuinfo_hypervisor_flag: false,
            vm_inventory: vm_inv,
            container_inventory: container_inv,
        };

        for d in [data("none", "none"), nested, unavailable] {
            for f in analyze(&d, &ctx()) {
                assert!(f.confidence.percent >= 60);
            }
        }
    }
}
