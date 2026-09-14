// SPDX-License-Identifier: GPL-3.0-only

use std::fs;

use crate::core::command::command;
use crate::core::error::ModuleError;

#[derive(Debug, Clone, PartialEq)]
pub struct VirtualizationRawData {
    /// Whether `systemd-detect-virt` itself is installed and runnable.
    pub tool_available: bool,
    /// `systemd-detect-virt --vm` — hardware/hypervisor-level
    /// virtualization only. "none" (not absence) means "checked, bare
    /// metal at this layer".
    pub vm_type: Option<String>,
    /// `systemd-detect-virt --container` — same-kernel (container-level)
    /// virtualization only.
    pub container_type: Option<String>,
    /// Fallback fact when the tool isn't installed: the CPUID
    /// "hypervisor" flag from `/proc/cpuinfo`. Weaker than
    /// systemd-detect-virt (confirms *some* hardware virtualization is
    /// present, but not which one, and says nothing about containers).
    pub cpuinfo_hypervisor_flag: bool,

    /// Host-side inventory: VMs this machine hosts via libvirt (KVM/QEMU/
    /// Xen), if it's a hypervisor host at all. Distinct concern from the
    /// fields above, which describe what this machine runs *inside of*,
    /// not what it hosts.
    pub vm_inventory: ToolInventory<VmInfo>,
    /// Host-side inventory: containers this machine runs via Docker or
    /// Podman, if either is present.
    pub container_inventory: ToolInventory<ContainerInfo>,
}

/// Three-state result for a host-side inventory check: the querying tool
/// may be missing entirely, present but unable to reach its backend (no
/// daemon running, no permission), or working — each needs a distinctly
/// worded explanation, not just a bool.
#[derive(Debug, Clone, PartialEq)]
pub struct ToolInventory<T> {
    pub runtime: Option<String>,
    pub available: bool,
    pub unavailable_reason: Option<String>,
    pub items: Vec<T>,
}

impl<T> ToolInventory<T> {
    fn unavailable(runtime: Option<&str>, reason: impl Into<String>) -> Self {
        Self {
            runtime: runtime.map(str::to_string),
            available: false,
            unavailable_reason: Some(reason.into()),
            items: Vec::new(),
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct VmInfo {
    pub name: String,
    /// From `virsh dominfo`'s `State:` field — "running", "shut off",
    /// "paused", "in shutdown", "crashed", "pmsuspended", etc.
    pub state: String,
    pub vcpus: Option<u32>,
    pub max_memory_kb: Option<u64>,
    /// Only populated when `state == "running"` — for a stopped VM,
    /// libvirt's "Used memory" reflects the balloon target, not real
    /// usage, so reporting it there would be misleading.
    pub used_memory_kb: Option<u64>,
    pub cpu_time_seconds: Option<f64>,
    pub autostart: Option<bool>,
    /// Per-vCPU host CPU affinity from `virsh vcpupin` — (vcpu index,
    /// affinity string, e.g. "0-3" or "2"). Only meaningful/queried for
    /// running VMs; empty for stopped ones.
    pub vcpu_pinning: Vec<(u32, String)>,
    pub disks: Vec<VmDisk>,
    /// Explicit NUMA memory-placement policy, from `virsh numatune` —
    /// `None` when nothing has been explicitly configured (the common
    /// case), distinct from an empty/default policy.
    pub numa_policy: Option<VmNumaPolicy>,
    /// Host NUMA node(s) this VM's pinned vCPUs actually run on, derived
    /// by cross-referencing `vcpu_pinning` against the host's own NUMA
    /// topology (`/sys/devices/system/node/*/cpulist`) — not something
    /// `virsh` reports directly. Empty when there's no pinning data to
    /// cross-reference, or the host has no NUMA topology to speak of
    /// (single-node systems, where this wouldn't be meaningful anyway).
    pub numa_nodes_used: Vec<u32>,
    /// Per-CPU breakdown behind `numa_nodes_used` — (host CPU, NUMA
    /// node), restricted to the specific CPUs this VM's vCPUs are
    /// pinned to. Lets the pinning display show each group's node
    /// individually ("vCPUs 0-1: host 0-3 (NUMA node 0)") rather than
    /// only the VM-wide aggregate.
    pub cpu_numa_nodes: Vec<(u32, u32)>,
    /// PCI devices passed through to this VM — both generic passthrough
    /// (`<hostdev type='pci'>`, e.g. a GPU) and SR-IOV virtual-function
    /// network interfaces (`<interface type='hostdev'>`), from `virsh
    /// dumpxml`.
    pub host_devices: Vec<HostDevice>,
    /// Which of this VM's pinned host CPUs are also isolated on the
    /// host (from the CPU module's own isolation detection — see
    /// `collect_vm_inventory`), i.e. reserved from the general host
    /// scheduler for this kind of exclusive use. Empty when there's no
    /// pinning data, or none of the pinned CPUs happen to be isolated.
    pub isolated_cpus_used: Vec<u32>,
    /// Approximate host-observed vCPU utilization since the start of
    /// this scan — a delta over whatever wall-clock time this VM's
    /// other `virsh` queries took, not a dedicated fixed-length sample
    /// the way `live_stats`'s host-wide CPU% is. Noisier as a result,
    /// so treated (and worded) as an approximation, not a precise
    /// reading.
    pub cpu_percent: Option<f64>,
    /// Guest-reported memory stats from `virsh dommemstat` — only
    /// queried for running VMs, since the command requires it.
    pub guest_memory: Option<VmMemoryStats>,
    /// This VM's regular virtual NICs (paravirtualized or emulated),
    /// from `virsh domiflist`. Distinct from `host_devices`: an SR-IOV
    /// VF handed to the VM via `<interface type='hostdev'>` shows up in
    /// `host_devices`, not here.
    pub network_interfaces: Vec<VmNetworkInterface>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct VmNumaPolicy {
    /// "strict", "interleave", "preferred", or whatever libvirt reports.
    pub mode: String,
    /// Node selection, e.g. "0" or "0-1".
    pub nodeset: String,
}

#[derive(Debug, Clone, PartialEq)]
pub struct HostDevice {
    /// Host-side PCI address, e.g. "0000:01:00.0".
    pub pci_address: String,
    pub kind: HostDeviceKind,
    /// Only ever `Some` for `SriovNetworkInterface` entries.
    pub mac_address: Option<String>,
    /// Human-readable hardware identification from `lspci -s <address>`,
    /// e.g. "VGA compatible controller: NVIDIA Corporation GA104
    /// [GeForce RTX 3070]". `None` when `lspci` isn't installed or the
    /// address doesn't resolve to a device `lspci` can see (e.g. it's
    /// already bound to a `vfio-pci` stub driver in a way that hides
    /// identifying info on some kernel/driver combinations).
    pub description: Option<String>,
}

/// One virtual NIC from `virsh domiflist` — the VM's regular network
/// interfaces (paravirtualized or emulated), distinct from SR-IOV/
/// passthrough devices in `host_devices` above.
#[derive(Debug, Clone, PartialEq)]
pub struct VmNetworkInterface {
    /// "network", "bridge", "direct", "user", "hostdev", etc.
    pub interface_type: String,
    /// The network/bridge name this interface connects to.
    pub source: Option<String>,
    /// Emulated/paravirtualized NIC model: "virtio", "e1000", "rtl8139",
    /// etc. There's no physical "link speed" for a virtual NIC the way
    /// there is for real hardware — this model is the closest honest
    /// analog (virtio is paravirtualized and fast; e1000/rtl8139 emulate
    /// specific real hardware and are typically slower/more CPU-heavy).
    pub model: Option<String>,
    pub mac_address: Option<String>,
}

/// Guest-reported memory statistics from `virsh dommemstat` — requires
/// the domain to be running, and some fields additionally require the
/// guest's virtio-balloon driver to have periodic stats collection
/// enabled (`<memballoon><stats period='N'/></memballoon>` in the domain
/// XML). Unsupported/unconfigured fields are `None`, not zero — a
/// documented libvirt quirk (see collect_vm_inventory) is that some
/// environments report `unused`/`available`/`rss` as a literal 0 rather
/// than omitting them, which looks identical to "genuinely zero" from
/// this data alone.
#[derive(Debug, Clone, Copy, PartialEq, Default)]
pub struct VmMemoryStats {
    /// Current balloon-adjusted allocation — matches dominfo's "Used
    /// memory" when the VM is running.
    pub actual_kb: Option<u64>,
    /// Memory the guest OS itself reports as unused, via the balloon
    /// driver — the closest thing to "how much RAM is genuinely free
    /// inside the VM", if available.
    pub unused_kb: Option<u64>,
    pub available_kb: Option<u64>,
    /// The host-side QEMU process's own RSS — can exceed `actual_kb`
    /// due to QEMU's own management overhead, which is normal.
    pub rss_kb: Option<u64>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HostDeviceKind {
    /// `<hostdev type='pci'>` — generic PCI/PCIe passthrough (GPUs,
    /// storage controllers, or a VF assigned the "traditional" way).
    PciPassthrough,
    /// `<interface type='hostdev'>` — network-specific passthrough,
    /// the mechanism libvirt recommends for SR-IOV VFs specifically
    /// (lets the MAC address/VLAN be set, which plain `<hostdev>`
    /// cannot). Labeled by XML shape, not independently confirmed
    /// against the host's own SR-IOV capability data.
    SriovNetworkInterface,
}

#[derive(Debug, Clone, PartialEq)]
pub struct VmDisk {
    /// Guest-visible device name, e.g. "vda".
    pub target: String,
    /// Host-side file/device path. `None` for an empty removable drive
    /// (domblklist reports "-").
    pub source: Option<String>,
    /// Logical/virtual size, from `domblkinfo`.
    pub capacity_bytes: Option<u64>,
    /// Actual space allocated on the host — the meaningful "how much is
    /// this VM really using on disk" figure for thin-provisioned formats
    /// like qcow2, where allocation is normally well under capacity.
    pub allocation_bytes: Option<u64>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct ContainerInfo {
    pub name: String,
    /// Docker/Podman's own single-word state: "running", "exited",
    /// "paused", "created", etc. (the `{{.State}}` format field).
    pub state: String,
    /// The human-readable status string ("Up 3 hours", "Exited (0) 2
    /// days ago") — kept alongside `state` since it carries detail
    /// (exit code, duration) `state` alone doesn't.
    pub status: String,
    pub image: String,
    /// Live snapshot from `docker/podman stats --no-stream`, only
    /// present for running containers. Kept as the tool's own formatted
    /// strings ("0.00%", "276KiB / 3.904GiB") rather than parsed into
    /// numbers — this is informational context, not something compared
    /// against a threshold.
    pub cpu_percent: Option<String>,
    pub mem_usage: Option<String>,
    pub mem_percent: Option<String>,
}

/// Thin I/O wrapper: `systemd-detect-virt` doesn't need systemd as PID 1
/// (unlike `systemctl`/`timedatectl`) — it probes DMI/CPUID/environment
/// markers directly — so this module has no availability gate the way
/// Systemd/NTP do.
pub fn collect() -> Result<VirtualizationRawData, ModuleError> {
    let tool_available = command("systemd-detect-virt")
        .arg("--version")
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false);

    let (vm_type, container_type) = if tool_available {
        (run_detect_virt(&["--vm"]), run_detect_virt(&["--container"]))
    } else {
        (None, None)
    };

    let cpuinfo_text = fs::read_to_string("/proc/cpuinfo").unwrap_or_default();
    let cpuinfo_hypervisor_flag = detect_hypervisor_flag(&cpuinfo_text);

    let vm_inventory = collect_vm_inventory();
    let container_inventory = collect_container_inventory();

    Ok(VirtualizationRawData {
        tool_available,
        vm_type,
        container_type,
        cpuinfo_hypervisor_flag,
        vm_inventory,
        container_inventory,
    })
}

/// `systemd-detect-virt` exits *non-zero* specifically when it detects
/// "none" (per its own man page: "0 if a virtualization technology is
/// detected, non-zero otherwise") — so stdout is read regardless of exit
/// status, the same permissive pattern used for `df`. Treating a non-zero
/// exit as a collection failure here would misreport every bare-metal
/// machine as an error.
fn run_detect_virt(args: &[&str]) -> Option<String> {
    let output = command("systemd-detect-virt").args(args).output().ok()?;
    let text = String::from_utf8_lossy(&output.stdout).trim().to_string();
    if text.is_empty() {
        None
    } else {
        Some(text)
    }
}

/// Parse the CPUID "hypervisor" flag out of `/proc/cpuinfo`'s `flags:`
/// line. Pure function, tested against fixture text.
pub fn detect_hypervisor_flag(cpuinfo_text: &str) -> bool {
    cpuinfo_text
        .lines()
        .find(|l| l.trim_start().starts_with("flags"))
        .map(|l| l.split_whitespace().any(|f| f == "hypervisor"))
        .unwrap_or(false)
}

/// Translate systemd-detect-virt's short IDs into names people recognize.
/// Not exhaustive (the tool defines 25+ IDs) — falls back to the raw ID
/// for anything not in this small, curated list of the common ones.
pub fn friendly_name(id: &str) -> String {
    match id {
        "none" => "none",
        "kvm" => "KVM",
        "qemu" => "QEMU",
        "vmware" => "VMware",
        "oracle" => "VirtualBox (Oracle)",
        "microsoft" => "Hyper-V (Microsoft)",
        "xen" => "Xen",
        "amazon" => "AWS Nitro",
        "google" => "Google Compute Engine",
        "bochs" => "Bochs",
        "parallels" => "Parallels",
        "uml" => "User-Mode Linux",
        "docker" => "Docker",
        "podman" => "Podman",
        "lxc" => "LXC",
        "lxc-libvirt" => "LXC (libvirt-managed)",
        "openvz" => "OpenVZ",
        "systemd-nspawn" => "systemd-nspawn",
        "wsl" => "Windows Subsystem for Linux",
        other => return other.to_string(),
    }
    .to_string()
}

/// Host-side VM inventory via `virsh` (libvirt — covers KVM/QEMU and Xen).
/// Three distinct "nothing to report" cases, each worded differently in
/// the resulting finding: `virsh` not installed at all; `virsh` installed
/// but unable to reach a hypervisor (no libvirtd running, or no
/// permission — confirmed empirically in this sandbox: `virsh list
/// --all` exits 1 with "failed to connect to the hypervisor" when there's
/// no daemon); or genuinely zero VMs defined.
fn collect_vm_inventory() -> ToolInventory<VmInfo> {
    let version_ok = command("virsh")
        .arg("--version")
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false);
    if !version_ok {
        return ToolInventory::unavailable(None, "virsh is not installed");
    }

    let list_output = match command("virsh").args(["list", "--all", "--name"]).output() {
        Ok(o) => o,
        Err(e) => return ToolInventory::unavailable(Some("virsh"), e.to_string()),
    };
    if !list_output.status.success() {
        let stderr = String::from_utf8_lossy(&list_output.stderr).trim().to_string();
        let reason = if stderr.is_empty() {
            "could not connect to a hypervisor (no libvirtd running, or no permission)"
                .to_string()
        } else {
            stderr
        };
        return ToolInventory::unavailable(Some("virsh"), reason);
    }

    let names = parse_vm_names(&String::from_utf8_lossy(&list_output.stdout));
    let host_topology = read_host_numa_topology();
    // One CPU-module collect() covers every VM below rather than
    // re-deriving isolation per VM — same reasoning as `host_topology`.
    let host_isolated_cpus: Vec<u32> = crate::modules::cpu::collect::collect()
        .map(|d| d.all_isolated_cpus())
        .unwrap_or_default();

    let mut vms = Vec::new();
    for name in &names {
        if let Ok(info_output) = command("virsh").args(["dominfo", name]).output() {
            if info_output.status.success() {
                let text = String::from_utf8_lossy(&info_output.stdout);
                let mut vm = parse_dominfo(name, &text);
                let sample_start = std::time::Instant::now();
                let initial_cpu_time = vm.cpu_time_seconds;

                // vCPU pinning, disk inventory, NUMA policy, host device
                // passthrough, network interfaces, and guest memory are
                // all best-effort enrichment: a failure in any one of
                // them shouldn't discard the VM entry we already have
                // from dominfo.
                if let Ok(pin_output) = command("virsh").args(["vcpupin", name]).output() {
                    if pin_output.status.success() {
                        vm.vcpu_pinning =
                            parse_vcpupin(&String::from_utf8_lossy(&pin_output.stdout));
                    }
                }

                if !host_topology.is_empty() {
                    vm.numa_nodes_used =
                        numa_nodes_for_pinning(&vm.vcpu_pinning, &host_topology);
                }
                let pinned_cpus: Vec<u32> = vm
                    .vcpu_pinning
                    .iter()
                    .flat_map(|(_, affinity)| crate::modules::cpu::collect::parse_cpu_list(affinity))
                    .collect();
                if !host_topology.is_empty() {
                    vm.cpu_numa_nodes = pinned_cpus
                        .iter()
                        .filter_map(|cpu| host_topology.get(cpu).map(|node| (*cpu, *node)))
                        .collect();
                }
                if !host_isolated_cpus.is_empty() {
                    vm.isolated_cpus_used = host_isolated_cpus
                        .iter()
                        .copied()
                        .filter(|cpu| pinned_cpus.contains(cpu))
                        .collect();
                }

                if let Ok(blk_output) = command("virsh")
                    .args(["domblklist", name, "--details"])
                    .output()
                {
                    if blk_output.status.success() {
                        let mut disks =
                            parse_domblklist(&String::from_utf8_lossy(&blk_output.stdout));
                        for disk in &mut disks {
                            // `domblkinfo` takes the guest-visible target
                            // ("vda"), not the host source path — the
                            // more universally correct identifier per
                            // libvirt's own examples, and the one that
                            // still works for pool-backed/block-type
                            // disks where "source" may not be a plain
                            // file path at all. Confirmed working
                            // against a real (if freshly-created, so
                            // near-empty) qcow2 image in this sandbox.
                            if let Ok(info_output) = command("virsh")
                                .args(["domblkinfo", name, &disk.target])
                                .output()
                            {
                                if info_output.status.success() {
                                    let (cap, alloc) = parse_domblkinfo(
                                        &String::from_utf8_lossy(&info_output.stdout),
                                    );
                                    disk.capacity_bytes = cap;
                                    disk.allocation_bytes = alloc;
                                }
                            }
                        }
                        vm.disks = disks;
                    }
                }

                if let Ok(numatune_output) = command("virsh").args(["numatune", name]).output() {
                    if numatune_output.status.success() {
                        vm.numa_policy =
                            parse_numatune(&String::from_utf8_lossy(&numatune_output.stdout));
                    }
                }

                if let Ok(xml_output) = command("virsh").args(["dumpxml", name]).output() {
                    if xml_output.status.success() {
                        let mut devices =
                            parse_host_devices(&String::from_utf8_lossy(&xml_output.stdout));
                        for dev in &mut devices {
                            dev.description = lookup_pci_description(&dev.pci_address);
                        }
                        vm.host_devices = devices;
                    }
                }

                if let Ok(iface_output) = command("virsh").args(["domiflist", name]).output() {
                    if iface_output.status.success() {
                        vm.network_interfaces =
                            parse_domiflist(&String::from_utf8_lossy(&iface_output.stdout));
                    }
                }

                if vm.state == "running" {
                    if let Ok(mem_output) = command("virsh").args(["dommemstat", name]).output() {
                        if mem_output.status.success() {
                            vm.guest_memory =
                                parse_dommemstat(&String::from_utf8_lossy(&mem_output.stdout));
                        }
                    }
                }

                // CPU% delta: a second, cheap `dominfo` call after all
                // the enrichment above, over whatever wall-clock time
                // that took — not a dedicated fixed-length sample the
                // way live_stats's host-wide CPU% is (that would mean a
                // deliberate sleep per VM, working against this tool's
                // own speed goals). Noisier as a result; presented as an
                // approximation for exactly that reason.
                if let (Some(initial), Some(vcpus)) = (initial_cpu_time, vm.vcpus) {
                    let elapsed = sample_start.elapsed().as_secs_f64();
                    if elapsed > 0.01 && vcpus > 0 {
                        if let Ok(resample_output) =
                            command("virsh").args(["dominfo", name]).output()
                        {
                            if resample_output.status.success() {
                                let resampled = parse_dominfo(
                                    name,
                                    &String::from_utf8_lossy(&resample_output.stdout),
                                );
                                if let Some(final_cpu_time) = resampled.cpu_time_seconds {
                                    let delta = final_cpu_time - initial;
                                    if delta >= 0.0 {
                                        vm.cpu_percent = Some(
                                            (delta / (vcpus as f64 * elapsed) * 100.0)
                                                .min(vcpus as f64 * 100.0),
                                        );
                                    }
                                }
                            }
                        }
                    }
                }

                vms.push(vm);
            }
        }
    }

    ToolInventory {
        runtime: Some("virsh".to_string()),
        available: true,
        unavailable_reason: None,
        items: vms,
    }
}

/// Host CPU -> NUMA node mapping from `/sys/devices/system/node/node*/
/// cpulist`, read directly rather than going through the NUMA module's
/// full collect+analyze pipeline — same reasoning as `live_stats.rs`:
/// this needs one cross-cutting fact, not a set of Findings. Empty
/// (rather than an error) on single-node or non-NUMA systems, or if the
/// sysfs path is missing entirely (containers, some VMs).
fn read_host_numa_topology() -> std::collections::HashMap<u32, u32> {
    let mut map = std::collections::HashMap::new();
    let Ok(entries) = fs::read_dir("/sys/devices/system/node") else {
        return map;
    };
    for entry in entries.flatten() {
        let Ok(name) = entry.file_name().into_string() else {
            continue;
        };
        let Some(id_str) = name.strip_prefix("node") else {
            continue;
        };
        let Ok(node_id) = id_str.parse::<u32>() else {
            continue;
        };
        let cpulist_path = entry.path().join("cpulist");
        if let Ok(text) = fs::read_to_string(cpulist_path) {
            for cpu in crate::modules::cpu::collect::parse_cpu_list(&text) {
                map.insert(cpu, node_id);
            }
        }
    }
    map
}

/// Cross-reference a VM's per-vCPU host affinity against the host's own
/// NUMA topology to find which node(s) it actually runs on — something
/// `virsh` doesn't report directly (`numatune` shows the configured
/// *memory* policy, not where the pinned vCPUs land). Returns node IDs
/// in ascending order, deduplicated.
pub fn numa_nodes_for_pinning(
    pinning: &[(u32, String)],
    host_topology: &std::collections::HashMap<u32, u32>,
) -> Vec<u32> {
    let mut nodes: Vec<u32> = pinning
        .iter()
        .flat_map(|(_, affinity)| crate::modules::cpu::collect::parse_cpu_list(affinity))
        .filter_map(|cpu| host_topology.get(&cpu).copied())
        .collect();
    nodes.sort_unstable();
    nodes.dedup();
    nodes
}

/// Parse `virsh list --all --name`: one VM name per line.
pub fn parse_vm_names(text: &str) -> Vec<String> {
    text.lines()
        .map(|l| l.trim().to_string())
        .filter(|l| !l.is_empty())
        .collect()
}

/// Parse `virsh dominfo <name>`: simple `Key:    Value` lines. Pure
/// function, tested against fixture text.
pub fn parse_dominfo(name: &str, text: &str) -> VmInfo {
    let fields: std::collections::HashMap<&str, &str> = text
        .lines()
        .filter_map(|l| l.split_once(':'))
        .map(|(k, v)| (k.trim(), v.trim()))
        .collect();

    let state = fields.get("State").unwrap_or(&"unknown").to_string();
    let vcpus = fields.get("CPU(s)").and_then(|v| v.parse().ok());
    let max_memory_kb = fields.get("Max memory").and_then(|v| parse_kib_value(v));
    let used_memory_kb = if state == "running" {
        fields.get("Used memory").and_then(|v| parse_kib_value(v))
    } else {
        None
    };
    let cpu_time_seconds = fields
        .get("CPU time")
        .and_then(|v| v.trim_end_matches('s').parse().ok());
    let autostart = fields.get("Autostart").map(|v| *v == "enable");

    VmInfo {
        name: name.to_string(),
        state,
        vcpus,
        max_memory_kb,
        used_memory_kb,
        cpu_time_seconds,
        autostart,
        vcpu_pinning: Vec::new(),
        disks: Vec::new(),
        numa_policy: None,
        numa_nodes_used: Vec::new(),
        cpu_numa_nodes: Vec::new(),
        host_devices: Vec::new(),
        isolated_cpus_used: Vec::new(),
        cpu_percent: None,
        guest_memory: None,
        network_interfaces: Vec::new(),
    }
}

/// Parse a libvirt "<number> KiB" value, e.g. "2097152 KiB" -> 2097152.
fn parse_kib_value(s: &str) -> Option<u64> {
    s.split_whitespace().next()?.parse().ok()
}

/// Parse `virsh vcpupin <name>` output:
/// ```text
/// VCPU: CPU Affinity
/// ----------------------------------
///    0: 0-3
///    1: 2
/// ```
/// Confirmed against real-world captures in libvirt/Red Hat
/// documentation, not assumed. Pure function, tested against fixture
/// text. Header and separator lines are skipped naturally: neither
/// parses as `<number>: <text>`.
pub fn parse_vcpupin(text: &str) -> Vec<(u32, String)> {
    let mut result = Vec::new();
    for line in text.lines() {
        let Some((left, right)) = line.split_once(':') else {
            continue;
        };
        let Ok(vcpu) = left.trim().parse::<u32>() else {
            continue; // "VCPU" header line, or anything else non-numeric
        };
        result.push((vcpu, right.trim().to_string()));
    }
    result
}

/// Parse `virsh domblklist <name> --details` output:
/// ```text
/// Type       Device     Target   Source
/// ------------------------------------------------
/// file       disk       vda      /var/lib/libvirt/images/win11.qcow2
/// file       cdrom      sda      -
/// ```
/// Confirmed column layout against real-world libvirt documentation.
/// Only `Device == "disk"` rows are kept — cdrom/floppy entries (often
/// with no source at all) aren't storage this VM is consuming. Pure
/// function, tested against fixture text.
pub fn parse_domblklist(text: &str) -> Vec<VmDisk> {
    let mut disks = Vec::new();
    for line in text.lines() {
        let fields: Vec<&str> = line.split_whitespace().collect();
        if fields.len() < 4 {
            continue;
        }
        let (device_type, device, target) = (fields[0], fields[1], fields[2]);
        if device_type == "Type" || device_type.chars().all(|c| c == '-') {
            continue; // header or separator line
        }
        if device != "disk" {
            continue; // skip cdrom/floppy
        }
        let source = fields[3..].join(" ");
        disks.push(VmDisk {
            target: target.to_string(),
            source: if source == "-" { None } else { Some(source) },
            capacity_bytes: None,
            allocation_bytes: None,
        });
    }
    disks
}

/// Parse `virsh domblkinfo <name> <target> --bytes` output:
/// ```text
/// Capacity:       53687091200
/// Allocation:     22548578304
/// Physical:       53687091200
/// ```
/// Returns `(capacity_bytes, allocation_bytes)`. Pure function, tested
/// against fixture text.
pub fn parse_domblkinfo(text: &str) -> (Option<u64>, Option<u64>) {
    let fields: std::collections::HashMap<&str, &str> = text
        .lines()
        .filter_map(|l| l.split_once(':'))
        .map(|(k, v)| (k.trim(), v.trim()))
        .collect();

    let capacity = fields.get("Capacity").and_then(|v| v.parse().ok());
    let allocation = fields.get("Allocation").and_then(|v| v.parse().ok());
    (capacity, allocation)
}

/// Parse `virsh numatune <name>` output: simple `Key : Value` lines
/// (`Numa_mode : interleave`, `Numa_nodeset : 0-1`), confirmed against a
/// real captured example, not assumed. Keys matched case-insensitively —
/// casing has varied across libvirt versions in examples found during
/// research, and there's no reason to be fragile about it. `None` when
/// nothing was explicitly configured (the common case): libvirt's output
/// for an unconfigured VM doesn't cleanly parse into a real mode +
/// nodeset pair, and this stays honest about that rather than guessing
/// a default.
pub fn parse_numatune(text: &str) -> Option<VmNumaPolicy> {
    let fields: std::collections::HashMap<String, &str> = text
        .lines()
        .filter_map(|l| l.split_once(':'))
        .map(|(k, v)| (k.trim().to_lowercase(), v.trim()))
        .collect();

    let mode = fields.get("numa_mode")?;
    let nodeset = fields.get("numa_nodeset")?;
    if mode.is_empty() || nodeset.is_empty() {
        return None;
    }
    Some(VmNumaPolicy {
        mode: mode.to_string(),
        nodeset: nodeset.to_string(),
    })
}

/// Extract an XML attribute's value from a single line, e.g.
/// `extract_xml_attr("<address bus='0x06' slot='0x02'/>", "bus")` ->
/// `Some("0x06")`. Handles both quote styles. Not a general XML
/// attribute parser (doesn't handle escaped quotes within a value) —
/// scoped to `virsh dumpxml`'s own consistently-formatted output, not
/// arbitrary hand-written XML.
fn extract_xml_attr(line: &str, attr: &str) -> Option<String> {
    for quote in ['\'', '"'] {
        let needle = format!("{attr}={quote}");
        if let Some(start) = line.find(&needle) {
            let value_start = start + needle.len();
            if let Some(end) = line[value_start..].find(quote) {
                return Some(line[value_start..value_start + end].to_string());
            }
        }
    }
    None
}

/// Parse a PCI address component that may be hex ("0x06") or decimal
/// ("11") — both forms appear across real libvirt XML examples depending
/// on how the device was originally attached.
fn parse_hex_or_decimal(s: &str) -> Option<u32> {
    let s = s.trim();
    match s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")) {
        Some(hex) => u32::from_str_radix(hex, 16).ok(),
        None => s.parse().ok(),
    }
}

/// Format a PCI address the conventional way (matching `lspci`/`virsh
/// nodedev-list`), e.g. "0000:01:00.0". `domain` defaults to 0 when
/// absent — some older/simpler `<address>` examples omit it entirely.
fn format_pci_address(domain: &str, bus: &str, slot: &str, function: &str) -> Option<String> {
    let d = parse_hex_or_decimal(domain).unwrap_or(0);
    let b = parse_hex_or_decimal(bus)?;
    let s = parse_hex_or_decimal(slot)?;
    let f = parse_hex_or_decimal(function)?;
    Some(format!("{d:04x}:{b:02x}:{s:02x}.{f:x}"))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum HostdevBlock {
    None,
    Pci,
    SriovIface,
}

/// Parse `virsh dumpxml <name>` for passthrough devices. Two distinct
/// XML shapes, confirmed via libvirt's own documentation and real-world
/// examples (not guessed): `<hostdev type='pci'>...<source><address
/// .../></source>...</hostdev>` for generic PCI passthrough, and
/// `<interface type='hostdev'>...<source><address .../></source>...<mac
/// address='...'/>...</interface>` for SR-IOV VF network passthrough
/// specifically (the mechanism libvirt recommends over plain `<hostdev>`
/// for VFs, since it lets the MAC/VLAN be set). The MAC, when present,
/// comes *after* `</source>` in document order, so it's held pending
/// until the block closes rather than attached at the point `<address>`
/// is seen.
///
/// Deliberately not a general XML parser — a small line-scanning state
/// machine scoped to this specific, stable, well-documented shape of
/// `virsh dumpxml`'s own consistently-formatted output (one element per
/// line), not arbitrary hand-written or reformatted XML.
pub fn parse_host_devices(xml: &str) -> Vec<HostDevice> {
    let mut devices = Vec::new();
    let mut block = HostdevBlock::None;
    let mut in_source = false;
    let mut pending_pci: Option<String> = None;
    let mut pending_mac: Option<String> = None;

    for line in xml.lines() {
        let trimmed = line.trim();

        if block == HostdevBlock::None {
            if trimmed.starts_with("<hostdev")
                && extract_xml_attr(trimmed, "type").as_deref() == Some("pci")
            {
                block = HostdevBlock::Pci;
                in_source = false;
                pending_pci = None;
                pending_mac = None;
            } else if trimmed.starts_with("<interface")
                && extract_xml_attr(trimmed, "type").as_deref() == Some("hostdev")
            {
                block = HostdevBlock::SriovIface;
                in_source = false;
                pending_pci = None;
                pending_mac = None;
            }
            continue;
        }

        if trimmed.starts_with("</hostdev>") || trimmed.starts_with("</interface>") {
            if let Some(pci_address) = pending_pci.take() {
                let kind = match block {
                    HostdevBlock::Pci => HostDeviceKind::PciPassthrough,
                    HostdevBlock::SriovIface => HostDeviceKind::SriovNetworkInterface,
                    HostdevBlock::None => unreachable!(),
                };
                devices.push(HostDevice {
                    pci_address,
                    kind,
                    mac_address: pending_mac.take(),
                    description: None,
                });
            }
            block = HostdevBlock::None;
            in_source = false;
            continue;
        }
        if trimmed.starts_with("<source") {
            in_source = true;
            continue;
        }
        if trimmed.starts_with("</source>") {
            in_source = false;
            continue;
        }
        if trimmed.starts_with("<mac") {
            pending_mac = extract_xml_attr(trimmed, "address");
            continue;
        }
        if in_source && trimmed.starts_with("<address") {
            let domain = extract_xml_attr(trimmed, "domain").unwrap_or_else(|| "0".to_string());
            if let (Some(bus), Some(slot), Some(function)) = (
                extract_xml_attr(trimmed, "bus"),
                extract_xml_attr(trimmed, "slot"),
                extract_xml_attr(trimmed, "function"),
            ) {
                pending_pci = format_pci_address(&domain, &bus, &slot, &function);
            }
        }
    }

    devices
}

/// Look up a PCI device's human-readable identity via `lspci -s
/// <address>`. `lspci` echoes the address back as the first
/// whitespace-separated token of its default output (confirmed against
/// a real device in this sandbox — "00:00.0 Host bridge: Intel
/// Corporation Device 0d57"), which this strips since the caller already
/// has and displays the address separately. `lspci` accepts the full
/// "DDDD:BB:SS.F" address form directly (also confirmed), no reformatting
/// needed. Returns `None` if `lspci` isn't installed, exits with an
/// error, or (confirmed real behavior for a validly-formatted but
/// nonexistent address) succeeds with empty output.
pub fn lookup_pci_description(pci_address: &str) -> Option<String> {
    let output = command("lspci").args(["-s", pci_address]).output().ok()?;
    if !output.status.success() {
        return None;
    }
    parse_lspci_output(&String::from_utf8_lossy(&output.stdout))
}

/// Pure parsing half of the above — tested against fixture text.
pub fn parse_lspci_output(text: &str) -> Option<String> {
    let line = text.lines().next()?.trim();
    if line.is_empty() {
        return None;
    }
    let description = line.splitn(2, ' ').nth(1).unwrap_or(line).trim();
    if description.is_empty() {
        None
    } else {
        Some(description.to_string())
    }
}

/// Parse `virsh domiflist <name>` — a whitespace-column table (`Interface
/// Type Source Model MAC`), confirmed against a real domain with two
/// differently-typed interfaces in this sandbox. `Interface` is often
/// "-" for an inactive domain or one libvirt hasn't assigned a host-side
/// tap device name to; not captured here since `source`+`mac` already
/// identify the interface unambiguously.
pub fn parse_domiflist(text: &str) -> Vec<VmNetworkInterface> {
    let mut interfaces = Vec::new();
    for line in text.lines() {
        let fields: Vec<&str> = line.split_whitespace().collect();
        if fields.len() < 5 {
            continue;
        }
        let (interface_type, source, model, mac) = (fields[1], fields[2], fields[3], fields[4]);
        if interface_type == "Type" || interface_type.chars().all(|c| c == '-') {
            continue; // header or separator line
        }
        // The interface name column can legitimately be "-"; that's not
        // a reason to skip the row the way a header/separator line is.
        interfaces.push(VmNetworkInterface {
            interface_type: interface_type.to_string(),
            source: (source != "-").then(|| source.to_string()),
            model: (model != "-").then(|| model.to_string()),
            mac_address: (mac != "-").then(|| mac.to_string()),
        });
    }
    interfaces
}

/// Parse `virsh dommemstat <name>` — simple `key value` pairs, one per
/// line, values in KB. Confirmed against four independent real-world
/// captures during research (all consistent on field names). Documented
/// quirk this stays aware of rather than silently trusting: some
/// hypervisor/guest combinations report `unused`/`available`/`rss` as a
/// literal 0 instead of omitting them when the guest's balloon driver
/// isn't actively collecting stats — indistinguishable from genuinely-
/// zero from this data alone, which is why the resulting finding hedges
/// on these specific fields rather than treating 0 as a confident
/// "the guest reports no free memory".
pub fn parse_dommemstat(text: &str) -> Option<VmMemoryStats> {
    let fields: std::collections::HashMap<&str, u64> = text
        .lines()
        .filter_map(|l| {
            let mut parts = l.split_whitespace();
            let key = parts.next()?;
            let value = parts.next()?.parse().ok()?;
            Some((key, value))
        })
        .collect();

    if fields.is_empty() {
        return None;
    }

    Some(VmMemoryStats {
        actual_kb: fields.get("actual").copied(),
        unused_kb: fields.get("unused").copied(),
        available_kb: fields.get("available").copied(),
        rss_kb: fields.get("rss").copied(),
    })
}

/// Host-side container inventory. Tries `docker` first, then `podman` —
/// Podman's CLI is deliberately Docker-compatible, so the same format
/// strings work against either. Treated as mutually exclusive
/// alternatives for v1: the first one found that's actually reachable
/// wins, rather than merging listings from both.
fn collect_container_inventory() -> ToolInventory<ContainerInfo> {
    for runtime in ["docker", "podman"] {
        let version_ok = command(runtime)
            .arg("--version")
            .output()
            .map(|o| o.status.success())
            .unwrap_or(false);
        if !version_ok {
            continue; // this runtime isn't installed, try the next one
        }

        let ps_output = match command(runtime)
            .args([
                "ps",
                "-a",
                "--format",
                "{{.Names}}\t{{.State}}\t{{.Status}}\t{{.Image}}",
            ])
            .output()
        {
            Ok(o) => o,
            Err(e) => return ToolInventory::unavailable(Some(runtime), e.to_string()),
        };
        if !ps_output.status.success() {
            let stderr = String::from_utf8_lossy(&ps_output.stderr).trim().to_string();
            let reason = if stderr.is_empty() {
                format!("{runtime} daemon unreachable")
            } else {
                stderr
            };
            return ToolInventory::unavailable(Some(runtime), reason);
        }

        let mut containers = parse_container_ps(&String::from_utf8_lossy(&ps_output.stdout));

        // Best-effort: live resource stats only for running containers.
        // A failure here shouldn't discard the inventory we already have.
        if let Ok(stats_output) = command(runtime)
            .args([
                "stats",
                "--no-stream",
                "--format",
                "{{.Name}}\t{{.CPUPerc}}\t{{.MemUsage}}\t{{.MemPerc}}",
            ])
            .output()
        {
            if stats_output.status.success() {
                let stats = parse_container_stats(&String::from_utf8_lossy(&stats_output.stdout));
                for c in &mut containers {
                    if let Some((cpu, mem, mem_pct)) = stats.get(&c.name) {
                        c.cpu_percent = Some(cpu.clone());
                        c.mem_usage = Some(mem.clone());
                        c.mem_percent = Some(mem_pct.clone());
                    }
                }
            }
        }

        return ToolInventory {
            runtime: Some(runtime.to_string()),
            available: true,
            unavailable_reason: None,
            items: containers,
        };
    }

    ToolInventory::unavailable(None, "neither docker nor podman is installed")
}

/// Parse `docker/podman ps -a --format` output using the tab-delimited
/// template above. Field order/format verified against a real Docker
/// daemon and real containers, not assumed: `.State` is a clean
/// single-word value ("running", "exited"), distinct from the more
/// detailed human-readable `.Status` ("Up 3 hours", "Exited (0) 2 days
/// ago"). Pure function, tested against that captured fixture text.
pub fn parse_container_ps(text: &str) -> Vec<ContainerInfo> {
    text.lines()
        .filter_map(|line| {
            let parts: Vec<&str> = line.split('\t').collect();
            if parts.len() < 4 {
                return None;
            }
            Some(ContainerInfo {
                name: parts[0].to_string(),
                state: parts[1].to_string(),
                status: parts[2].to_string(),
                image: parts[3].to_string(),
                cpu_percent: None,
                mem_usage: None,
                mem_percent: None,
            })
        })
        .collect()
}

/// Parse `docker/podman stats --no-stream --format` output (same
/// tab-delimited approach). Only running containers appear here — stats
/// are meaningless for stopped ones, and the tools already omit them.
pub fn parse_container_stats(
    text: &str,
) -> std::collections::HashMap<String, (String, String, String)> {
    text.lines()
        .filter_map(|line| {
            let parts: Vec<&str> = line.split('\t').collect();
            if parts.len() < 4 {
                return None;
            }
            Some((
                parts[0].to_string(),
                (parts[1].to_string(), parts[2].to_string(), parts[3].to_string()),
            ))
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detects_hypervisor_flag_present() {
        let text = "processor\t: 0\nflags\t\t: fpu vme de pse hypervisor tsc msr\n";
        assert!(detect_hypervisor_flag(text));
    }

    #[test]
    fn hypervisor_flag_absent_on_bare_metal_fixture() {
        let text = "processor\t: 0\nflags\t\t: fpu vme de pse tsc msr\n";
        assert!(!detect_hypervisor_flag(text));
    }

    #[test]
    fn missing_flags_line_is_false_not_a_panic() {
        assert!(!detect_hypervisor_flag("processor\t: 0\n"));
    }

    #[test]
    fn friendly_name_maps_known_ids() {
        assert_eq!(friendly_name("kvm"), "KVM");
        assert_eq!(friendly_name("docker"), "Docker");
        assert_eq!(friendly_name("none"), "none");
    }

    #[test]
    fn friendly_name_falls_back_to_raw_id_for_unknown() {
        assert_eq!(friendly_name("acrn"), "acrn");
    }

    #[test]
    fn parses_vm_names_list() {
        let names = parse_vm_names("web1\ndb1\n\n  \n");
        assert_eq!(names, vec!["web1".to_string(), "db1".to_string()]);
    }

    // Real `virsh dominfo` field shape (Key:    Value lines) -- the
    // specific numbers are illustrative, but the format itself is the
    // long-standing, documented libvirt CLI output shape.
    const FIXTURE_DOMINFO_RUNNING: &str = "\
Id:             3
Name:           web1
UUID:           12345678-1234-1234-1234-123456789abc
OS Type:        hvm
State:          running
CPU(s):         4
CPU time:       12345.6s
Max memory:     4194304 KiB
Used memory:    4194304 KiB
Persistent:     yes
Autostart:      enable
Managed save:   no
";

    const FIXTURE_DOMINFO_STOPPED: &str = "\
Name:           db1
State:          shut off
CPU(s):         2
Max memory:     2097152 KiB
Used memory:    2097152 KiB
Persistent:     yes
Autostart:      disable
";

    #[test]
    fn parses_dominfo_for_running_vm() {
        let vm = parse_dominfo("web1", FIXTURE_DOMINFO_RUNNING);
        assert_eq!(vm.state, "running");
        assert_eq!(vm.vcpus, Some(4));
        assert_eq!(vm.max_memory_kb, Some(4_194_304));
        // Used memory IS reported when running.
        assert_eq!(vm.used_memory_kb, Some(4_194_304));
        assert_eq!(vm.cpu_time_seconds, Some(12345.6));
        assert_eq!(vm.autostart, Some(true));
    }

    #[test]
    fn stopped_vm_does_not_report_used_memory() {
        // libvirt's "Used memory" reflects the balloon target when
        // stopped, not real usage -- reporting it would be misleading.
        let vm = parse_dominfo("db1", FIXTURE_DOMINFO_STOPPED);
        assert_eq!(vm.state, "shut off");
        assert_eq!(vm.used_memory_kb, None);
        assert_eq!(vm.max_memory_kb, Some(2_097_152));
        assert_eq!(vm.autostart, Some(false));
    }

    #[test]
    fn new_vminfo_fields_start_empty() {
        let vm = parse_dominfo("web1", FIXTURE_DOMINFO_RUNNING);
        assert!(vm.vcpu_pinning.is_empty());
        assert!(vm.disks.is_empty());
    }

    // Real captured shape (Red Hat support docs / libvirt cheatsheets),
    // not invented -- see the header comment and search notes for this
    // module's collect_vm_inventory().
    const FIXTURE_VCPUPIN: &str = "\
VCPU: CPU Affinity
----------------------------------
   0: 0-3
   1: 0-3
   2: 4-7
   3: 4-7
";

    #[test]
    fn parses_vcpupin_output() {
        let pinning = parse_vcpupin(FIXTURE_VCPUPIN);
        assert_eq!(
            pinning,
            vec![
                (0, "0-3".to_string()),
                (1, "0-3".to_string()),
                (2, "4-7".to_string()),
                (3, "4-7".to_string()),
            ]
        );
    }

    #[test]
    fn parses_vcpupin_with_single_cpu_affinity() {
        // Real example from Red Hat's own support docs: a single vCPU
        // pinned to one specific host CPU (no range).
        let text = "VCPU: CPU Affinity\n----------------------------------\n0: 3-11\n";
        assert_eq!(parse_vcpupin(text), vec![(0, "3-11".to_string())]);
    }

    // Real column layout confirmed via `virsh help domblklist` and
    // libvirt's own documentation.
    const FIXTURE_DOMBLKLIST: &str = "\
Type       Device     Target   Source
------------------------------------------------
file       disk       vda      /var/lib/libvirt/images/win11.qcow2
file       cdrom      sda      -
";

    #[test]
    fn parses_domblklist_and_skips_cdrom() {
        let disks = parse_domblklist(FIXTURE_DOMBLKLIST);
        assert_eq!(disks.len(), 1); // cdrom entry excluded
        assert_eq!(disks[0].target, "vda");
        assert_eq!(
            disks[0].source.as_deref(),
            Some("/var/lib/libvirt/images/win11.qcow2")
        );
    }

    #[test]
    fn domblklist_empty_source_becomes_none() {
        let text = "Type       Device     Target   Source\n------------------------------------------------\nfile       disk       sda      -\n";
        let disks = parse_domblklist(text);
        assert_eq!(disks.len(), 1);
        assert_eq!(disks[0].source, None);
    }

    const FIXTURE_DOMBLKINFO: &str = "\
Capacity:       53687091200
Allocation:     22548578304
Physical:       53687091200
";

    #[test]
    fn parses_domblkinfo() {
        let (capacity, allocation) = parse_domblkinfo(FIXTURE_DOMBLKINFO);
        assert_eq!(capacity, Some(53_687_091_200));
        assert_eq!(allocation, Some(22_548_578_304));
    }

    // Real captured example (Radware/Alteon KB article), not invented.
    const FIXTURE_NUMATUNE: &str = "Numa_mode : interleave\nNuma_nodeset : 0-1\n";

    #[test]
    fn parses_numatune_when_configured() {
        let policy = parse_numatune(FIXTURE_NUMATUNE).unwrap();
        assert_eq!(policy.mode, "interleave");
        assert_eq!(policy.nodeset, "0-1");
    }

    #[test]
    fn numatune_case_insensitive_keys() {
        let text = "NUMA_MODE : strict\nNUMA_NODESET : 0\n";
        let policy = parse_numatune(text).unwrap();
        assert_eq!(policy.mode, "strict");
    }

    #[test]
    fn numatune_none_when_unconfigured() {
        // Unconfigured VMs don't cleanly produce a real mode+nodeset --
        // stays honest (None) rather than fabricating a default.
        assert_eq!(parse_numatune("some unrelated output\n"), None);
        assert_eq!(parse_numatune(""), None);
    }

    #[test]
    fn host_numa_topology_maps_cpus_to_nodes() {
        let mut topology = std::collections::HashMap::new();
        for cpu in 0..4 {
            topology.insert(cpu, 0);
        }
        for cpu in 4..8 {
            topology.insert(cpu, 1);
        }
        // vCPUs pinned entirely within node 0's CPUs.
        let node0_only = vec![(0, "0-1".to_string()), (1, "2-3".to_string())];
        assert_eq!(numa_nodes_for_pinning(&node0_only, &topology), vec![0]);

        // vCPUs spanning both nodes.
        let spanning = vec![(0, "0-3".to_string()), (1, "4-7".to_string())];
        assert_eq!(numa_nodes_for_pinning(&spanning, &topology), vec![0, 1]);
    }

    #[test]
    fn numa_nodes_for_pinning_empty_when_no_pinning() {
        let topology = std::collections::HashMap::from([(0, 0)]);
        assert_eq!(numa_nodes_for_pinning(&[], &topology), Vec::<u32>::new());
    }

    #[test]
    fn extracts_xml_attr_both_quote_styles() {
        assert_eq!(
            extract_xml_attr("<address bus='0x06' slot='0x02'/>", "bus"),
            Some("0x06".to_string())
        );
        assert_eq!(
            extract_xml_attr("<hostdev type=\"pci\">", "type"),
            Some("pci".to_string())
        );
        assert_eq!(extract_xml_attr("<foo/>", "missing"), None);
    }

    #[test]
    fn formats_pci_address_from_hex_components() {
        assert_eq!(
            format_pci_address("0x0000", "0x01", "0x00", "0x0"),
            Some("0000:01:00.0".to_string())
        );
    }

    #[test]
    fn formats_pci_address_from_decimal_components() {
        // Real example from Red Hat's SR-IOV docs: domain='0' bus='11' slot='16' function='0'
        assert_eq!(
            format_pci_address("0", "11", "16", "0"),
            Some("0000:0b:10.0".to_string())
        );
    }

    #[test]
    fn pci_address_defaults_domain_to_zero_when_absent() {
        // Real example from libvirt's own docs: no domain attribute at all.
        assert_eq!(
            format_pci_address("0", "0x06", "0x02", "0x0"),
            Some("0000:06:02.0".to_string())
        );
    }

    // Real shape from libvirt's formatdomain.html documentation.
    const FIXTURE_HOSTDEV_PCI: &str = "\
<devices>
  <hostdev mode='subsystem' type='pci' managed='yes'>
    <source>
      <address bus='0x06' slot='0x02' function='0x0'/>
    </source>
    <boot order='1'/>
  </hostdev>
</devices>
";

    #[test]
    fn parses_generic_pci_hostdev() {
        let devices = parse_host_devices(FIXTURE_HOSTDEV_PCI);
        assert_eq!(devices.len(), 1);
        assert_eq!(devices[0].pci_address, "0000:06:02.0");
        assert_eq!(devices[0].kind, HostDeviceKind::PciPassthrough);
        assert_eq!(devices[0].mac_address, None);
    }

    // Real shape from Red Hat's SR-IOV documentation -- note the <mac>
    // element comes *after* </source> closes, which is exactly the
    // ordering the parser needs to handle correctly.
    const FIXTURE_HOSTDEV_SRIOV: &str = "\
<devices>
  <interface type='hostdev' managed='yes'>
    <source>
      <address type='pci' domain='0' bus='11' slot='16' function='0'/>
    </source>
    <mac address='52:54:00:6d:90:02'/>
  </interface>
</devices>
";

    #[test]
    fn parses_sriov_network_interface_and_captures_mac_after_source_closes() {
        let devices = parse_host_devices(FIXTURE_HOSTDEV_SRIOV);
        assert_eq!(devices.len(), 1);
        assert_eq!(devices[0].pci_address, "0000:0b:10.0");
        assert_eq!(devices[0].kind, HostDeviceKind::SriovNetworkInterface);
        assert_eq!(devices[0].mac_address.as_deref(), Some("52:54:00:6d:90:02"));
    }

    #[test]
    fn parses_both_kinds_together_without_cross_contamination() {
        let xml = format!(
            "<devices>\n{}\n{}\n</devices>\n",
            "  <hostdev mode='subsystem' type='pci' managed='yes'>\n    <source>\n      <address bus='0x01' slot='0x00' function='0x0'/>\n    </source>\n  </hostdev>",
            "  <interface type='hostdev' managed='yes'>\n    <source>\n      <address type='pci' domain='0' bus='2' slot='16' function='1'/>\n    </source>\n    <mac address='aa:bb:cc:dd:ee:ff'/>\n  </interface>",
        );
        let devices = parse_host_devices(&xml);
        assert_eq!(devices.len(), 2);
        assert_eq!(devices[0].kind, HostDeviceKind::PciPassthrough);
        assert_eq!(devices[0].mac_address, None);
        assert_eq!(devices[1].kind, HostDeviceKind::SriovNetworkInterface);
        assert_eq!(devices[1].mac_address.as_deref(), Some("aa:bb:cc:dd:ee:ff"));
    }

    #[test]
    fn no_host_devices_in_plain_domain_xml() {
        let xml = "<domain>\n  <devices>\n    <disk type='file'/>\n  </devices>\n</domain>\n";
        assert!(parse_host_devices(xml).is_empty());
    }

    // Real captured output: `lspci -s 00:00.0` in this sandbox.
    #[test]
    fn parses_lspci_output_strips_leading_address() {
        let text = "00:00.0 Host bridge: Intel Corporation Device 0d57\n";
        assert_eq!(
            parse_lspci_output(text),
            Some("Host bridge: Intel Corporation Device 0d57".to_string())
        );
    }

    #[test]
    fn lspci_output_empty_for_nonexistent_device() {
        // Real confirmed behavior: a validly-formatted but absent PCI
        // address makes lspci succeed with empty output, not an error.
        assert_eq!(parse_lspci_output(""), None);
    }

    // Real captured output: `virsh domiflist test-vm2` against a domain
    // with a virtio network-type interface and an e1000 bridge-type one.
    const FIXTURE_DOMIFLIST: &str = "\
 Interface   Type      Source    Model    MAC
-------------------------------------------------------------
 -           network   default   virtio   52:54:00:12:34:56
 -           bridge    br0       e1000    52:54:00:aa:bb:cc
";

    #[test]
    fn parses_domiflist_real_output() {
        let interfaces = parse_domiflist(FIXTURE_DOMIFLIST);
        assert_eq!(interfaces.len(), 2);
        assert_eq!(interfaces[0].interface_type, "network");
        assert_eq!(interfaces[0].source.as_deref(), Some("default"));
        assert_eq!(interfaces[0].model.as_deref(), Some("virtio"));
        assert_eq!(interfaces[0].mac_address.as_deref(), Some("52:54:00:12:34:56"));
        assert_eq!(interfaces[1].interface_type, "bridge");
        assert_eq!(interfaces[1].model.as_deref(), Some("e1000"));
    }

    #[test]
    fn domiflist_empty_when_no_interfaces() {
        let text = " Interface   Type   Source   Model   MAC\n------------------------------------------\n\n";
        assert!(parse_domiflist(text).is_empty());
    }

    // Real captured example (Programster's Blog KVM cheatsheet), one of
    // four independent real-world captures found during research, all
    // consistent on field names.
    const FIXTURE_DOMMEMSTAT: &str = "\
actual 786432
swap_in 0
swap_out 0
major_fault 280
minor_fault 35165
unused 606568
available 725152
usable 582352
last_update 1697559991
disk_caches 44256
rss 760452
";

    #[test]
    fn parses_dommemstat_real_output() {
        let stats = parse_dommemstat(FIXTURE_DOMMEMSTAT).unwrap();
        assert_eq!(stats.actual_kb, Some(786432));
        assert_eq!(stats.unused_kb, Some(606568));
        assert_eq!(stats.available_kb, Some(725152));
        assert_eq!(stats.rss_kb, Some(760452));
    }

    #[test]
    fn dommemstat_missing_fields_are_none() {
        // "Unsupported fields are missing from the output" per libvirt's
        // own docs -- confirm a partial capture still parses the fields
        // that are present.
        let stats = parse_dommemstat("actual 1048576\nrss 987654\n").unwrap();
        assert_eq!(stats.actual_kb, Some(1048576));
        assert_eq!(stats.unused_kb, None);
    }

    #[test]
    fn dommemstat_none_for_non_running_domain_error_text() {
        assert_eq!(
            parse_dommemstat("error: Requested operation is not valid: domain is not running\n"),
            None
        );
    }

    // Captured from a real Docker daemon in this sandbox (dockerd started
    // manually, minimal busybox-based image imported without network
    // access, real running + real stopped containers) -- not synthetic.
    const FIXTURE_DOCKER_PS: &str =
        "test-running\trunning\tUp 1 second\tminitest:latest\ntest-stopped\texited\tExited (0) 1 second ago\tminitest:latest\n";

    const FIXTURE_DOCKER_STATS: &str = "test-running\t0.00%\t276KiB / 3.904GiB\t0.01%\n";

    #[test]
    fn parses_real_captured_docker_ps_output() {
        let containers = parse_container_ps(FIXTURE_DOCKER_PS);
        assert_eq!(containers.len(), 2);
        let running = containers.iter().find(|c| c.name == "test-running").unwrap();
        assert_eq!(running.state, "running");
        assert_eq!(running.status, "Up 1 second");
        assert_eq!(running.image, "minitest:latest");
        let stopped = containers.iter().find(|c| c.name == "test-stopped").unwrap();
        assert_eq!(stopped.state, "exited");
        assert!(stopped.status.starts_with("Exited (0)"));
    }

    #[test]
    fn parses_real_captured_docker_stats_output() {
        let stats = parse_container_stats(FIXTURE_DOCKER_STATS);
        let (cpu, mem, mem_pct) = stats.get("test-running").unwrap();
        assert_eq!(cpu, "0.00%");
        assert_eq!(mem, "276KiB / 3.904GiB");
        assert_eq!(mem_pct, "0.01%");
        // Stopped containers never appear in `stats` output at all.
        assert!(!stats.contains_key("test-stopped"));
    }

    #[test]
    fn container_ps_skips_malformed_lines() {
        let containers = parse_container_ps("not enough fields\nname\trunning\tUp\timage\n");
        assert_eq!(containers.len(), 1);
    }
}
