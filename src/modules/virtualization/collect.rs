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

    let mut vms = Vec::new();
    for name in &names {
        if let Ok(info_output) = command("virsh").args(["dominfo", name]).output() {
            if info_output.status.success() {
                let text = String::from_utf8_lossy(&info_output.stdout);
                let mut vm = parse_dominfo(name, &text);

                // vCPU pinning and disk inventory are best-effort
                // enrichment: a failure here shouldn't discard the VM
                // entry we already have from dominfo.
                if let Ok(pin_output) = command("virsh").args(["vcpupin", name]).output() {
                    if pin_output.status.success() {
                        vm.vcpu_pinning =
                            parse_vcpupin(&String::from_utf8_lossy(&pin_output.stdout));
                    }
                }

                if let Ok(blk_output) = command("virsh")
                    .args(["domblklist", name, "--details"])
                    .output()
                {
                    if blk_output.status.success() {
                        let mut disks =
                            parse_domblklist(&String::from_utf8_lossy(&blk_output.stdout));
                        for disk in &mut disks {
                            let Some(source) = &disk.source else { continue };
                            if let Ok(info_output) = command("virsh")
                                .args(["domblkinfo", name, source])
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
