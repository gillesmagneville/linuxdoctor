// SPDX-License-Identifier: GPL-3.0-only

use crate::core::context::Context;
use crate::models::{Category, Confidence, Finding, Severity};

use super::collect::{
    friendly_name, ContainerInfo, HostDevice, HostDeviceKind, VirtualizationRawData, VmDisk,
    VmInfo, VmNetworkInterface,
};

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
/// Adaptive-unit byte formatter — GB for anything substantial, falling
/// back to MB then KB so a genuinely small-but-real value (a freshly
/// created or lightly used thin-provisioned disk, for instance) reads as
/// "196 KB" rather than a misleading, indistinguishable-from-broken
/// "0.0 GB".
fn format_bytes_adaptive(bytes: u64) -> String {
    let gb = bytes as f64 / 1024.0 / 1024.0 / 1024.0;
    if gb >= 0.1 {
        return format!("{gb:.1} GB");
    }
    let mb = bytes as f64 / 1024.0 / 1024.0;
    if mb >= 0.1 {
        return format!("{mb:.1} MB");
    }
    format!("{} KB", bytes / 1024)
}

/// Group consecutive vCPUs sharing the same host affinity into one
/// readable clause, e.g. "vCPUs 0-1: host 0-3 (NUMA node 0); vCPUs 2-3:
/// host 4-7 (NUMA node 1)" — the NUMA node is resolved per group here
/// rather than only reported as a VM-wide aggregate, so "which CPUs does
/// it run on, and which node are those on" is answered together, not in
/// two disconnected places.
fn format_vcpu_pinning(pinning: &[(u32, String)], cpu_numa_nodes: &[(u32, u32)]) -> Option<String> {
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
            let host_cpus = crate::modules::cpu::collect::parse_cpu_list(affinity);
            let mut nodes: Vec<u32> = host_cpus
                .iter()
                .filter_map(|cpu| {
                    cpu_numa_nodes
                        .iter()
                        .find(|(c, _)| c == cpu)
                        .map(|(_, n)| *n)
                })
                .collect();
            nodes.sort_unstable();
            nodes.dedup();
            let node_note = match nodes.len() {
                0 => String::new(),
                1 => format!(" (NUMA node {})", nodes[0]),
                _ => format!(
                    " (NUMA nodes {})",
                    nodes.iter().map(u32::to_string).collect::<Vec<_>>().join(","),
                ),
            };
            format!("{label}: host {affinity}{node_note}")
        })
        .collect();
    Some(parts.join("; "))
}

/// Summarize per-disk capacity/allocation, e.g. "vda (22.5 GB allocated
/// of 50.0 GB capacity)" — allocation is the figure that actually
/// matters for thin-provisioned formats like qcow2, where it's normally
/// well under capacity. Uses `format_bytes_adaptive` so a small real
/// allocation doesn't round to the same "0.0 GB" a genuine failure to
/// read it would (visually) resemble.
fn format_disks(disks: &[VmDisk]) -> Option<String> {
    if disks.is_empty() {
        return None;
    }
    let parts: Vec<String> = disks
        .iter()
        .map(|d| match (d.capacity_bytes, d.allocation_bytes) {
            (Some(cap), Some(alloc)) => format!(
                "{} ({} allocated of {} capacity)",
                d.target,
                format_bytes_adaptive(alloc),
                format_bytes_adaptive(cap),
            ),
            (Some(cap), None) => format!("{} ({} capacity)", d.target, format_bytes_adaptive(cap)),
            _ => d.target.clone(),
        })
        .collect();
    Some(parts.join(", "))
}

/// A short, honest hint about what a NIC model implies performance-wise.
/// Deliberately doesn't fabricate a "speed" figure — paravirtualized
/// models like virtio don't have one (throughput is bounded by host CPU/
/// memory bandwidth, not a fixed link rate the way real hardware has).
fn nic_model_hint(model: &str) -> Option<&'static str> {
    match model {
        "virtio" => Some(
            "paravirtualized, no fixed link speed — throughput is bounded \
             by host CPU/memory bandwidth, not emulated hardware",
        ),
        "e1000" | "e1000e" => Some("emulates a 1 Gbps Intel NIC"),
        "rtl8139" => Some("emulates a 100 Mbps Realtek NIC"),
        "vmxnet3" => Some("VMware's paravirtualized NIC, no fixed link speed"),
        _ => None,
    }
}

/// Summarize the VM's regular virtual NICs, e.g. "network on default,
/// virtio (paravirtualized...), MAC 52:54:00:12:34:56".
fn format_network_interfaces(interfaces: &[VmNetworkInterface]) -> Option<String> {
    if interfaces.is_empty() {
        return None;
    }
    let parts: Vec<String> = interfaces
        .iter()
        .map(|i| {
            let source_note = i
                .source
                .as_deref()
                .map(|s| format!(" on {s}"))
                .unwrap_or_default();
            let model_note = match &i.model {
                Some(m) => match nic_model_hint(m) {
                    Some(hint) => format!(", {m} ({hint})"),
                    None => format!(", {m}"),
                },
                None => String::new(),
            };
            let mac_note = i
                .mac_address
                .as_deref()
                .map(|m| format!(", MAC {m}"))
                .unwrap_or_default();
            format!("{}{source_note}{model_note}{mac_note}", i.interface_type)
        })
        .collect();
    Some(parts.join("; "))
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
    let cpu_percent_note = vm
        .cpu_percent
        .map(|p| {
            format!(
                " Approximate host-observed CPU usage: {p:.1}% (brief sample \
                 taken during this scan, not a precise reading)."
            )
        })
        .unwrap_or_default();
    let pinning_summary = format_vcpu_pinning(&vm.vcpu_pinning, &vm.cpu_numa_nodes);
    let pinning_note = pinning_summary
        .as_ref()
        .map(|p| format!(" CPU pinning — {p}."))
        .unwrap_or_default();
    let isolated_note = if vm.isolated_cpus_used.is_empty() {
        String::new()
    } else {
        let cpus: Vec<String> = vm.isolated_cpus_used.iter().map(u32::to_string).collect();
        format!(
            " Pinned to isolated host CPU{s} {} — reserved from the general \
             host scheduler for exclusive use like this.",
            cpus.join(", "),
            s = if vm.isolated_cpus_used.len() == 1 { "" } else { "s" },
        )
    };
    let numa_policy_note = vm
        .numa_policy
        .as_ref()
        .map(|p| format!(" NUMA policy: {} on node(s) {}.", p.mode, p.nodeset))
        .unwrap_or_default();
    let numa_span_note = if vm.numa_nodes_used.len() > 1 {
        " Pinned vCPUs span more than one NUMA node, so some vCPU-to-memory \
         accesses cross nodes — slower than staying within one."
    } else {
        ""
    };
    let guest_mem_note = if vm.state != "running" {
        String::new()
    } else {
        match &vm.guest_memory {
            None => " Guest-internal memory stats unavailable.".to_string(),
            Some(m) => match (m.actual_kb, m.unused_kb) {
                (Some(actual), Some(unused)) if actual > 0 => {
                    let used_kb = actual.saturating_sub(unused);
                    let pct = used_kb as f64 / actual as f64 * 100.0;
                    let caveat = if unused == 0 {
                        " (some hypervisor/guest combinations report this as \
                         0 even when the guest genuinely has free memory, if \
                         the balloon driver's periodic stats collection \
                         isn't enabled in the guest — worth treating with \
                         some caution)"
                    } else {
                        ""
                    };
                    format!(" Guest-reported memory: {pct:.1}% used internally by the guest OS{caveat}.")
                }
                _ => " Guest-internal memory stats unavailable (needs the \
                      guest's balloon driver stats collection enabled)."
                    .to_string(),
            },
        }
    };
    let disks_summary = format_disks(&vm.disks);
    let disks_note = disks_summary
        .as_ref()
        .map(|d| format!(" Storage: {d}."))
        .unwrap_or_default();
    let devices_summary = format_host_devices(&vm.host_devices);
    let devices_note = devices_summary
        .as_ref()
        .map(|d| format!(" Passthrough devices: {d}."))
        .unwrap_or_default();
    let network_summary = format_network_interfaces(&vm.network_interfaces);
    let network_note = network_summary
        .as_ref()
        .map(|n| format!(" Network interfaces: {n}."))
        .unwrap_or_default();

    let explanation = format!(
        "{}: {}{vcpu_note}{max_mem_note}.{used_mem_note}{cpu_percent_note}{autostart_note}{pinning_note}{isolated_note}{numa_policy_note}{numa_span_note}{guest_mem_note}{disks_note}{devices_note}{network_note}",
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
    if let Some(p) = vm.cpu_percent {
        builder = builder.evidence("cpu_percent_approx", format!("{p:.1}"));
    }
    if let Some(a) = vm.autostart {
        builder = builder.evidence("autostart", a.to_string());
    }
    if let Some(p) = &pinning_summary {
        builder = builder.evidence("vcpu_pinning", p.clone());
    }
    if !vm.isolated_cpus_used.is_empty() {
        let cpus: Vec<String> = vm.isolated_cpus_used.iter().map(u32::to_string).collect();
        builder = builder.evidence("isolated_cpus_used", cpus.join(","));
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
    if let Some(p) = &vm.numa_policy {
        builder = builder.evidence("numa_policy_mode", p.mode.clone());
        builder = builder.evidence("numa_policy_nodeset", p.nodeset.clone());
    }
    if !vm.numa_nodes_used.is_empty() {
        let nodes: Vec<String> = vm.numa_nodes_used.iter().map(u32::to_string).collect();
        builder = builder.evidence("numa_nodes_used", nodes.join(","));
    }
    if let Some(m) = &vm.guest_memory {
        if let Some(actual) = m.actual_kb {
            builder = builder.evidence("guest_actual_kb", actual.to_string());
        }
        if let Some(unused) = m.unused_kb {
            builder = builder.evidence("guest_unused_kb", unused.to_string());
        }
        if let Some(rss) = m.rss_kb {
            builder = builder.evidence("qemu_rss_kb", rss.to_string());
        }
    }
    for (i, dev) in vm.host_devices.iter().enumerate() {
        builder = builder.evidence(format!("hostdev:{i}:pci_address"), dev.pci_address.clone());
        builder = builder.evidence(
            format!("hostdev:{i}:kind"),
            match dev.kind {
                HostDeviceKind::PciPassthrough => "pci_passthrough".to_string(),
                HostDeviceKind::SriovNetworkInterface => "sriov_network_interface".to_string(),
            },
        );
        if let Some(mac) = &dev.mac_address {
            builder = builder.evidence(format!("hostdev:{i}:mac_address"), mac.clone());
        }
        if let Some(desc) = &dev.description {
            builder = builder.evidence(format!("hostdev:{i}:description"), desc.clone());
        }
    }
    for (i, iface) in vm.network_interfaces.iter().enumerate() {
        builder = builder.evidence(format!("netif:{i}:type"), iface.interface_type.clone());
        if let Some(s) = &iface.source {
            builder = builder.evidence(format!("netif:{i}:source"), s.clone());
        }
        if let Some(m) = &iface.model {
            builder = builder.evidence(format!("netif:{i}:model"), m.clone());
        }
        if let Some(mac) = &iface.mac_address {
            builder = builder.evidence(format!("netif:{i}:mac_address"), mac.clone());
        }
    }

    builder.explanation(explanation).build()
}

/// Summarize passthrough devices, e.g. "0000:01:00.0 (PCI passthrough —
/// VGA compatible controller: NVIDIA Corporation GA104 [GeForce RTX
/// 3070]), 0000:02:10.1 (SR-IOV network interface, MAC 52:54:00:6d:90:02
/// — Ethernet controller: Intel Corporation 82576 Virtual Function)".
fn format_host_devices(devices: &[HostDevice]) -> Option<String> {
    if devices.is_empty() {
        return None;
    }
    let parts: Vec<String> = devices
        .iter()
        .map(|d| {
            let desc_note = d
                .description
                .as_deref()
                .map(|desc| format!(" \u{2014} {desc}"))
                .unwrap_or_default();
            match (&d.kind, &d.mac_address) {
                (HostDeviceKind::PciPassthrough, _) => {
                    format!("{} (PCI passthrough{desc_note})", d.pci_address)
                }
                (HostDeviceKind::SriovNetworkInterface, Some(mac)) => {
                    format!(
                        "{} (SR-IOV network interface, MAC {mac}{desc_note})",
                        d.pci_address
                    )
                }
                (HostDeviceKind::SriovNetworkInterface, None) => {
                    format!("{} (SR-IOV network interface{desc_note})", d.pci_address)
                }
            }
        })
        .collect();
    Some(parts.join(", "))
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
    use crate::modules::virtualization::collect::{HostDevice, HostDeviceKind, ToolInventory, VmMemoryStats, VmNetworkInterface, VmNumaPolicy};

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
            numa_policy: Some(VmNumaPolicy {
                mode: "strict".to_string(),
                nodeset: "0".to_string(),
            }),
            numa_nodes_used: vec![0, 1],
            cpu_numa_nodes: vec![(0, 0), (1, 0), (2, 0), (3, 0), (4, 1), (5, 1), (6, 1), (7, 1)],
            host_devices: vec![
                HostDevice {
                    pci_address: "0000:01:00.0".to_string(),
                    kind: HostDeviceKind::PciPassthrough,
                    mac_address: None,
                    description: Some(
                        "VGA compatible controller: NVIDIA Corporation GA104 [GeForce RTX 3070]"
                            .to_string(),
                    ),
                },
                HostDevice {
                    pci_address: "0000:02:10.1".to_string(),
                    kind: HostDeviceKind::SriovNetworkInterface,
                    mac_address: Some("52:54:00:6d:90:02".to_string()),
                    description: Some(
                        "Ethernet controller: Intel Corporation 82576 Virtual Function"
                            .to_string(),
                    ),
                },
            ],
            isolated_cpus_used: vec![0, 1, 2, 3],
            cpu_percent: Some(37.5),
            guest_memory: Some(VmMemoryStats {
                actual_kb: Some(4_194_304),
                unused_kb: Some(1_048_576),
                available_kb: Some(4_000_000),
                rss_kb: Some(4_300_000),
            }),
            network_interfaces: vec![
                VmNetworkInterface {
                    interface_type: "network".to_string(),
                    source: Some("default".to_string()),
                    model: Some("virtio".to_string()),
                    mac_address: Some("52:54:00:12:34:56".to_string()),
                },
                VmNetworkInterface {
                    interface_type: "bridge".to_string(),
                    source: Some("br0".to_string()),
                    model: Some("e1000".to_string()),
                    mac_address: Some("52:54:00:aa:bb:cc".to_string()),
                },
            ],
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
    fn vm_detail_surfaces_numa_policy_and_effective_nodes() {
        let mut d = data("none", "none");
        d.vm_inventory = ToolInventory {
            runtime: Some("virsh".to_string()),
            available: true,
            unavailable_reason: None,
            items: vec![running_vm()],
        };
        let findings = analyze(&d, &ctx());
        let virt003 = findings.iter().find(|f| f.id == "VIRT003").unwrap();
        assert!(virt003.explanation.contains("NUMA policy: strict on node(s) 0"));
        // Per-CPU-group node is now integrated into the pinning clause itself.
        assert!(virt003.explanation.contains("vCPUs 0-1: host 0-3 (NUMA node 0)"));
        assert!(virt003.explanation.contains("vCPUs 2-3: host 4-7 (NUMA node 1)"));
        assert!(virt003.explanation.contains("span more than one NUMA node"));
        assert!(virt003
            .evidence
            .iter()
            .any(|(k, v)| k == "numa_nodes_used" && v == "0,1"));
    }

    #[test]
    fn vm_detail_singular_numa_node_wording() {
        let mut vm = running_vm();
        // Genuinely single-node: both fields need to agree, not just
        // numa_nodes_used -- the per-group display reads cpu_numa_nodes.
        vm.numa_nodes_used = vec![0];
        vm.cpu_numa_nodes = vec![(0, 0), (1, 0), (2, 0), (3, 0), (4, 0), (5, 0), (6, 0), (7, 0)];
        let mut d = data("none", "none");
        d.vm_inventory = ToolInventory {
            runtime: Some("virsh".to_string()),
            available: true,
            unavailable_reason: None,
            items: vec![vm],
        };
        let findings = analyze(&d, &ctx());
        let virt003 = findings.iter().find(|f| f.id == "VIRT003").unwrap();
        assert!(virt003.explanation.contains("(NUMA node 0)"));
        assert!(!virt003.explanation.contains("span more than one"));
    }

    #[test]
    fn vm_detail_omits_numa_clauses_when_absent() {
        let mut vm = running_vm();
        vm.numa_policy = None;
        vm.numa_nodes_used = vec![];
        vm.cpu_numa_nodes = vec![]; // nothing to resolve per-group either
        let mut d = data("none", "none");
        d.vm_inventory = ToolInventory {
            runtime: Some("virsh".to_string()),
            available: true,
            unavailable_reason: None,
            items: vec![vm],
        };
        let findings = analyze(&d, &ctx());
        let virt003 = findings.iter().find(|f| f.id == "VIRT003").unwrap();
        assert!(!virt003.explanation.contains("NUMA policy"));
        assert!(!virt003.explanation.contains("NUMA node"));
    }

    #[test]
    fn vm_detail_surfaces_passthrough_and_sriov_devices() {
        let mut d = data("none", "none");
        d.vm_inventory = ToolInventory {
            runtime: Some("virsh".to_string()),
            available: true,
            unavailable_reason: None,
            items: vec![running_vm()],
        };
        let findings = analyze(&d, &ctx());
        let virt003 = findings.iter().find(|f| f.id == "VIRT003").unwrap();
        assert!(virt003
            .explanation
            .contains("0000:01:00.0 (PCI passthrough \u{2014} VGA compatible controller"));
        assert!(virt003
            .explanation
            .contains("0000:02:10.1 (SR-IOV network interface, MAC 52:54:00:6d:90:02"));
        assert!(virt003.explanation.contains("Ethernet controller"));
        assert!(virt003
            .evidence
            .iter()
            .any(|(k, v)| k == "hostdev:1:kind" && v == "sriov_network_interface"));
        assert!(virt003
            .evidence
            .iter()
            .any(|(k, _)| k == "hostdev:0:description"));
    }

    #[test]
    fn vm_detail_no_devices_note_when_none_passed_through() {
        let mut vm = running_vm();
        vm.host_devices = vec![];
        let mut d = data("none", "none");
        d.vm_inventory = ToolInventory {
            runtime: Some("virsh".to_string()),
            available: true,
            unavailable_reason: None,
            items: vec![vm],
        };
        let findings = analyze(&d, &ctx());
        let virt003 = findings.iter().find(|f| f.id == "VIRT003").unwrap();
        assert!(!virt003.explanation.contains("Passthrough"));
    }

    #[test]
    fn small_disk_allocation_shown_in_mb_not_misleading_0_0_gb() {
        // 200_704 bytes ~= 0.19 MB -- above the MB threshold, so shown
        // there rather than falling misleadingly to "0.0 GB".
        assert_eq!(format_bytes_adaptive(200_704), "0.2 MB".to_string());
    }

    #[test]
    fn tiny_allocation_shown_in_kb() {
        // Genuinely below the MB threshold.
        assert_eq!(format_bytes_adaptive(51_200), "50 KB".to_string());
    }

    #[test]
    fn moderate_allocation_shown_in_mb() {
        // 50 MB -- big enough that "0.0 GB" would be actively misleading,
        // small enough that GB would round away the actual magnitude.
        assert_eq!(format_bytes_adaptive(50 * 1024 * 1024), "50.0 MB".to_string());
    }

    #[test]
    fn large_allocation_still_shown_in_gb() {
        assert_eq!(
            format_bytes_adaptive(22_548_578_304),
            "21.0 GB".to_string()
        );
    }

    #[test]
    fn disk_with_small_real_allocation_does_not_read_as_zero() {
        let disks = vec![VmDisk {
            target: "vda".to_string(),
            source: Some("/tmp/fresh.qcow2".to_string()),
            capacity_bytes: Some(10_737_418_240),
            allocation_bytes: Some(200_704), // real captured value from this sandbox's own test
        }];
        let summary = format_disks(&disks).unwrap();
        assert!(summary.contains("0.2 MB allocated"));
        // Check precisely for "the allocation reads as zero", not just
        // the substring "0.0 GB" -- which "10.0 GB" (the capacity) would
        // also (correctly) contain.
        assert!(!summary.contains("(0.0 GB allocated"));
    }

    #[test]
    fn vm_detail_surfaces_isolated_cpu_cross_reference() {
        let mut d = data("none", "none");
        d.vm_inventory = ToolInventory {
            runtime: Some("virsh".to_string()),
            available: true,
            unavailable_reason: None,
            items: vec![running_vm()],
        };
        let findings = analyze(&d, &ctx());
        let virt003 = findings.iter().find(|f| f.id == "VIRT003").unwrap();
        assert!(virt003.explanation.contains("isolated host CPUs 0, 1, 2, 3"));
        assert!(virt003
            .evidence
            .iter()
            .any(|(k, v)| k == "isolated_cpus_used" && v == "0,1,2,3"));
    }

    #[test]
    fn vm_detail_no_isolated_cpu_note_when_none_isolated() {
        let mut vm = running_vm();
        vm.isolated_cpus_used = vec![];
        let mut d = data("none", "none");
        d.vm_inventory = ToolInventory {
            runtime: Some("virsh".to_string()),
            available: true,
            unavailable_reason: None,
            items: vec![vm],
        };
        let findings = analyze(&d, &ctx());
        let virt003 = findings.iter().find(|f| f.id == "VIRT003").unwrap();
        assert!(!virt003.explanation.contains("isolated"));
    }

    #[test]
    fn vm_detail_surfaces_approximate_cpu_percent() {
        let mut d = data("none", "none");
        d.vm_inventory = ToolInventory {
            runtime: Some("virsh".to_string()),
            available: true,
            unavailable_reason: None,
            items: vec![running_vm()],
        };
        let findings = analyze(&d, &ctx());
        let virt003 = findings.iter().find(|f| f.id == "VIRT003").unwrap();
        assert!(virt003.explanation.contains("37.5%"));
        assert!(virt003.explanation.contains("brief sample"));
    }

    #[test]
    fn vm_detail_surfaces_guest_memory_when_running() {
        let mut d = data("none", "none");
        d.vm_inventory = ToolInventory {
            runtime: Some("virsh".to_string()),
            available: true,
            unavailable_reason: None,
            items: vec![running_vm()],
        };
        let findings = analyze(&d, &ctx());
        let virt003 = findings.iter().find(|f| f.id == "VIRT003").unwrap();
        // actual=4_194_304, unused=1_048_576 -> used = 3_145_728 -> 75.0%
        assert!(virt003.explanation.contains("75.0% used internally"));
        assert!(!virt003.explanation.contains("some hypervisor")); // unused != 0 here, no caveat
    }

    #[test]
    fn vm_detail_guest_memory_caveat_when_unused_is_zero() {
        let mut vm = running_vm();
        vm.guest_memory = Some(VmMemoryStats {
            actual_kb: Some(4_194_304),
            unused_kb: Some(0),
            available_kb: None,
            rss_kb: None,
        });
        let mut d = data("none", "none");
        d.vm_inventory = ToolInventory {
            runtime: Some("virsh".to_string()),
            available: true,
            unavailable_reason: None,
            items: vec![vm],
        };
        let findings = analyze(&d, &ctx());
        let virt003 = findings.iter().find(|f| f.id == "VIRT003").unwrap();
        assert!(virt003.explanation.contains("worth treating with"));
    }

    #[test]
    fn vm_detail_no_guest_memory_note_when_stopped() {
        let mut vm = running_vm();
        vm.state = "shut off".to_string();
        vm.guest_memory = None;
        let mut d = data("none", "none");
        d.vm_inventory = ToolInventory {
            runtime: Some("virsh".to_string()),
            available: true,
            unavailable_reason: None,
            items: vec![vm],
        };
        let findings = analyze(&d, &ctx());
        let virt003 = findings.iter().find(|f| f.id == "VIRT003").unwrap();
        assert!(!virt003.explanation.contains("Guest-"));
    }

    #[test]
    fn vm_detail_surfaces_network_interfaces_with_model_hint() {
        let mut d = data("none", "none");
        d.vm_inventory = ToolInventory {
            runtime: Some("virsh".to_string()),
            available: true,
            unavailable_reason: None,
            items: vec![running_vm()],
        };
        let findings = analyze(&d, &ctx());
        let virt003 = findings.iter().find(|f| f.id == "VIRT003").unwrap();
        assert!(virt003.explanation.contains("network on default"));
        assert!(virt003.explanation.contains("paravirtualized"));
        assert!(virt003.explanation.contains("bridge on br0"));
        assert!(virt003.explanation.contains("emulates a 1 Gbps"));
        assert!(virt003
            .evidence
            .iter()
            .any(|(k, v)| k == "netif:0:model" && v == "virtio"));
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
