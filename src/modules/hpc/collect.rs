// SPDX-License-Identifier: GPL-3.0-only

//! What the checks of the `hpc` module read:
//!
//! * the CPU frequency policy of every CPU -- the governor, the driver behind
//!   it and, where the driver has one, the energy/performance preference --
//!   from `/sys/devices/system/cpu/cpu<N>/cpufreq/`;
//! * the locked-memory limit of this process, from `/proc/self/limits`;
//! * the RDMA devices (InfiniBand, RoCE), from `/sys/class/infiniband/`;
//! * the automatic NUMA balancing switch, from `/proc/sys/kernel/numa_balancing`,
//!   and the number of NUMA nodes, from `/sys/devices/system/node/`;
//! * the SMT (hyper-threading) state, from `/sys/devices/system/cpu/smt/`, and
//!   how many logical CPUs share each core, from `cpu<N>/topology/`.

use std::collections::BTreeMap;
use std::fs;
use std::path::Path;

use crate::core::error::ModuleError;
use crate::core::text::clean;

/// Where the per-CPU directories live.
const CPU_ROOT: &str = "/sys/devices/system/cpu";

/// The limits of this very process.
const LIMITS_FILE: &str = "/proc/self/limits";

/// One entry per RDMA device (`mlx5_0`, `rxe0`...).
const RDMA_ROOT: &str = "/sys/class/infiniband";

/// One `node<N>` directory per NUMA node.
const NODE_ROOT: &str = "/sys/devices/system/node";

/// Automatic NUMA balancing: `0` off, bit 0 (`1`) balancing between nodes,
/// bit 1 (`2`) memory tiering.
const NUMA_BALANCING_FILE: &str = "/proc/sys/kernel/numa_balancing";

/// Longest value kept from a sysfs file. The real ones are a word; the limit
/// only keeps a hostile or broken file from filling a report.
const MAX_VALUE: usize = 64;

/// The frequency policy of one online CPU that has one.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CpuFreq {
    pub cpu: u32,
    /// `scaling_driver`: `intel_pstate`, `acpi-cpufreq`, `amd-pstate-epp`...
    pub driver: Option<String>,
    /// `scaling_governor`: `performance`, `powersave`, `schedutil`...
    pub governor: String,
    /// `energy_performance_preference`: only the drivers that steer the
    /// hardware with a hint have it (`intel_pstate` with HWP, the `amd-pstate`
    /// active mode).
    pub epp: Option<String>,
}

/// One resource limit, as `/proc/self/limits` writes it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Limit {
    Unlimited,
    Bytes(u64),
}

/// The locked-memory limits (`RLIMIT_MEMLOCK`) of this process: the soft one
/// is what applies, the hard one is how far the soft one can be raised
/// without privileges.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MemLock {
    pub soft: Limit,
    pub hard: Limit,
}

/// One RDMA device.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RdmaDevice {
    pub name: String,
    /// The link layer of each of its ports, sorted and without repeats:
    /// `InfiniBand`, or `Ethernet` for RDMA over Ethernet (RoCE).
    pub link_layers: Vec<String>,
}

/// What the kernel says about SMT (simultaneous multithreading, called
/// hyper-threading by Intel), from `/sys/devices/system/cpu/smt/`.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Smt {
    /// `control`: `on`, `off`, `forceoff` (cannot be changed), `notsupported`
    /// (the processor has none) or `notimplemented` (the architecture cannot
    /// switch it at run time). Nothing if the file is missing.
    pub control: Option<String>,
    /// `active`: whether any core currently runs more than one thread.
    pub active: Option<bool>,
}

/// How the online logical CPUs are spread over cores, from the
/// `thread_siblings_list` of each CPU (the CPUs sharing its core).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CpuTopology {
    /// CPUs that reported their siblings.
    pub logical: usize,
    /// Distinct cores among them.
    pub cores: usize,
    /// The number of logical CPUs on each core, when it is the same for all
    /// (it is not on a processor mixing performance and efficiency cores).
    pub threads_per_core: Option<usize>,
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct HpcRawData {
    /// Every CPU with a frequency policy, by CPU number. Empty on a machine
    /// that exposes none (a virtual machine, a platform with a fixed
    /// frequency, a driver not loaded).
    pub cpufreq: Vec<CpuFreq>,
    /// The locked-memory limit of this process; nothing if the line could not
    /// be read.
    pub memlock: Option<MemLock>,
    /// The RDMA devices, by name. Empty when there are none.
    pub rdma: Vec<RdmaDevice>,
    /// The value of `numa_balancing`; nothing if the kernel has no such file
    /// (it is built without automatic NUMA balancing) or it holds no number.
    pub numa_balancing: Option<u32>,
    /// The NUMA nodes found; 0 when the directory cannot be read.
    pub numa_nodes: usize,
    pub smt: Smt,
    /// Nothing if no CPU reported its siblings.
    pub topology: Option<CpuTopology>,
}

/// Where each reading comes from, so that the three together are tested on
/// fake files.
pub struct Sources<'a> {
    pub cpu: &'a Path,
    pub limits: &'a Path,
    pub rdma: &'a Path,
    pub nodes: &'a Path,
    pub numa_balancing: &'a Path,
}

impl Sources<'static> {
    pub fn system() -> Self {
        Sources {
            cpu: Path::new(CPU_ROOT),
            limits: Path::new(LIMITS_FILE),
            rdma: Path::new(RDMA_ROOT),
            nodes: Path::new(NODE_ROOT),
            numa_balancing: Path::new(NUMA_BALANCING_FILE),
        }
    }
}

pub fn collect() -> Result<HpcRawData, ModuleError> {
    Ok(collect_from(&Sources::system()))
}

/// [`collect`] on the given places.
pub fn collect_from(sources: &Sources) -> HpcRawData {
    HpcRawData {
        cpufreq: read_cpufreq(sources.cpu),
        memlock: fs::read_to_string(sources.limits)
            .ok()
            .and_then(|text| parse_memlock(&text)),
        rdma: read_rdma(sources.rdma),
        numa_balancing: read_number(sources.numa_balancing),
        numa_nodes: count_numa_nodes(sources.nodes),
        smt: read_smt(sources.cpu),
        topology: read_topology(sources.cpu),
    }
}

/// A file holding one non-negative number (`0`, `1`...). Nothing if it is
/// missing, empty, or anything else: `str::parse` alone would take `+1`.
fn read_number(path: &Path) -> Option<u32> {
    let text = read_value(path)?;
    if !text.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    text.parse().ok()
}

/// The `node<N>` directories of a directory laid out like
/// `/sys/devices/system/node` (which also holds `online`, `possible`...).
pub fn count_numa_nodes(root: &Path) -> usize {
    fs::read_dir(root)
        .into_iter()
        .flatten()
        .flatten()
        .filter(|entry| {
            entry
                .file_name()
                .to_str()
                .and_then(|name| name.strip_prefix("node"))
                .is_some_and(|digits| {
                    !digits.is_empty() && digits.bytes().all(|b| b.is_ascii_digit())
                })
        })
        .count()
}

/// `smt/control` and `smt/active` of a directory laid out like
/// `/sys/devices/system/cpu`.
pub fn read_smt(cpu_root: &Path) -> Smt {
    let smt = cpu_root.join("smt");
    Smt {
        control: read_value(&smt.join("control")),
        active: match read_value(&smt.join("active")).as_deref() {
            Some("1") => Some(true),
            Some("0") => Some(false),
            _ => None,
        },
    }
}

/// How the online CPUs of a directory laid out like `/sys/devices/system/cpu`
/// are spread over cores: every CPU names the CPUs sharing its core
/// (`0,28`), so the same list read from `n` CPUs is one core of `n` threads.
pub fn read_topology(cpu_root: &Path) -> Option<CpuTopology> {
    let mut cores: BTreeMap<String, usize> = BTreeMap::new();
    for entry in fs::read_dir(cpu_root).into_iter().flatten().flatten() {
        if entry.file_name().to_str().and_then(cpu_number).is_none() {
            continue;
        }
        if let Some(siblings) = read_value(&entry.path().join("topology/thread_siblings_list")) {
            *cores.entry(siblings).or_default() += 1;
        }
    }
    let logical = cores.values().sum();
    let mut sizes = cores.values().copied();
    let first = sizes.next()?;
    let threads_per_core = sizes.all(|n| n == first).then_some(first);
    Some(CpuTopology {
        logical,
        cores: cores.len(),
        threads_per_core,
    })
}

/// The `Max locked memory` line of `/proc/self/limits`:
///
/// ```text
/// Max locked memory         8388608              8388608              bytes
/// ```
///
/// Both limits are numbers or `unlimited`; the unit must be `bytes`, so that
/// a different file layout is not read as a size it does not mean.
pub fn parse_memlock(text: &str) -> Option<MemLock> {
    let rest = text
        .lines()
        .find_map(|line| line.strip_prefix("Max locked memory"))?;
    let mut columns = rest.split_whitespace();
    let soft = parse_limit(columns.next()?)?;
    let hard = parse_limit(columns.next()?)?;
    if columns.next() != Some("bytes") {
        return None;
    }
    Some(MemLock { soft, hard })
}

fn parse_limit(text: &str) -> Option<Limit> {
    if text == "unlimited" {
        return Some(Limit::Unlimited);
    }
    // `parse` alone would accept a sign.
    if !text.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    text.parse().ok().map(Limit::Bytes)
}

/// The RDMA devices under a directory laid out like `/sys/class/infiniband`
/// (`<device>/ports/<n>/link_layer`).
pub fn read_rdma(root: &Path) -> Vec<RdmaDevice> {
    let mut devices: Vec<RdmaDevice> = fs::read_dir(root)
        .into_iter()
        .flatten()
        .flatten()
        .filter_map(|entry| {
            let name = clean(entry.file_name().to_str()?, MAX_VALUE);
            let mut link_layers: Vec<String> = fs::read_dir(entry.path().join("ports"))
                .into_iter()
                .flatten()
                .flatten()
                .filter_map(|port| read_value(&port.path().join("link_layer")))
                .collect();
            link_layers.sort();
            link_layers.dedup();
            Some(RdmaDevice { name, link_layers })
        })
        .collect();
    devices.sort_by(|a, b| a.name.cmp(&b.name));
    devices
}

/// The frequency policy of every CPU under a directory laid out like
/// `/sys/devices/system/cpu`, so the reading is tested on a fake tree.
pub fn read_cpufreq(root: &Path) -> Vec<CpuFreq> {
    let mut cpufreq = Vec::new();
    if let Ok(entries) = fs::read_dir(root) {
        for entry in entries.flatten() {
            let name = entry.file_name();
            let Some(cpu) = name.to_str().and_then(cpu_number) else {
                continue;
            };
            let policy = entry.path().join("cpufreq");
            // An offline CPU has no policy directory; a CPU whose governor
            // cannot be read has nothing to report.
            let Some(governor) = read_value(&policy.join("scaling_governor")) else {
                continue;
            };
            cpufreq.push(CpuFreq {
                cpu,
                driver: read_value(&policy.join("scaling_driver")),
                governor,
                epp: read_value(&policy.join("energy_performance_preference")),
            });
        }
    }
    cpufreq.sort_by_key(|c| c.cpu);
    cpufreq
}

/// `7` for `cpu7`; nothing for `cpufreq`, `cpuidle`, `cpu`, `cpu-1`...
fn cpu_number(name: &str) -> Option<u32> {
    let digits = name.strip_prefix("cpu")?;
    // Digits only: `parse` alone would accept a sign (`cpu+1`).
    if !digits.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    digits.parse().ok()
}

/// A one-line value from a sysfs file, or nothing if it is missing, empty or
/// unreadable.
fn read_value(path: &Path) -> Option<String> {
    let text = fs::read_to_string(path).ok()?;
    let text = text.trim();
    if text.is_empty() {
        None
    } else {
        Some(clean(text, MAX_VALUE))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn tree(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("ld-hpc-{name}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn put(root: &Path, relative: &str, text: &str) {
        let path = root.join(relative);
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(path, text).unwrap();
    }

    fn policy(root: &Path, cpu: u32, driver: Option<&str>, governor: &str, epp: Option<&str>) {
        put(
            root,
            &format!("cpu{cpu}/cpufreq/scaling_governor"),
            &format!("{governor}\n"),
        );
        if let Some(driver) = driver {
            put(
                root,
                &format!("cpu{cpu}/cpufreq/scaling_driver"),
                &format!("{driver}\n"),
            );
        }
        if let Some(epp) = epp {
            put(
                root,
                &format!("cpu{cpu}/cpufreq/energy_performance_preference"),
                &format!("{epp}\n"),
            );
        }
    }

    #[test]
    fn reads_governor_driver_and_preference_of_every_cpu_in_order() {
        let root = tree("order");
        // Created out of order and past a digit boundary: sorted by number,
        // not by name (cpu10 sorts before cpu2 as text).
        for cpu in [10, 2, 0, 1] {
            policy(
                &root,
                cpu,
                Some("intel_pstate"),
                "powersave",
                Some("balance_performance"),
            );
        }
        let cpufreq = read_cpufreq(&root);
        let cpus: Vec<u32> = cpufreq.iter().map(|c| c.cpu).collect();
        assert_eq!(cpus, [0, 1, 2, 10]);
        assert_eq!(
            cpufreq[0],
            CpuFreq {
                cpu: 0,
                driver: Some("intel_pstate".into()),
                governor: "powersave".into(),
                epp: Some("balance_performance".into()),
            }
        );
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn a_driver_without_a_preference_gives_none_for_it() {
        let root = tree("no-epp");
        policy(&root, 0, Some("acpi-cpufreq"), "ondemand", None);
        let cpufreq = read_cpufreq(&root);
        assert_eq!(cpufreq[0].epp, None);
        assert_eq!(cpufreq[0].driver.as_deref(), Some("acpi-cpufreq"));
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn a_missing_driver_file_is_not_a_missing_cpu() {
        let root = tree("no-driver");
        policy(&root, 0, None, "performance", None);
        let cpufreq = read_cpufreq(&root);
        assert_eq!(cpufreq.len(), 1);
        assert_eq!(cpufreq[0].driver, None);
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn only_cpu_directories_count() {
        let root = tree("names");
        policy(&root, 0, None, "performance", None);
        // The directories next to the CPUs in the real tree, and lookalikes.
        for name in [
            "cpufreq", "cpuidle", "cpu", "cpu-1", "cpu+1", "cpu0x", "cpu1a", "Cpu2",
        ] {
            put(
                &root,
                &format!("{name}/cpufreq/scaling_governor"),
                "powersave\n",
            );
        }
        let cpufreq = read_cpufreq(&root);
        assert_eq!(cpufreq.len(), 1, "{cpufreq:?}");
        assert_eq!(cpufreq[0].governor, "performance");
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn an_offline_cpu_or_one_without_a_readable_governor_is_left_out() {
        let root = tree("offline");
        policy(&root, 0, None, "performance", None);
        // Offline: no cpufreq directory at all.
        put(&root, "cpu1/online", "0\n");
        // A policy directory with an empty, then a missing, governor.
        put(&root, "cpu2/cpufreq/scaling_governor", "\n");
        put(&root, "cpu3/cpufreq/scaling_driver", "intel_pstate\n");
        let cpufreq = read_cpufreq(&root);
        let cpus: Vec<u32> = cpufreq.iter().map(|c| c.cpu).collect();
        assert_eq!(cpus, [0]);
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn no_cpu_tree_means_no_policies() {
        let root = tree("none");
        assert!(read_cpufreq(&root).is_empty());
        assert!(read_cpufreq(&root.join("does-not-exist")).is_empty());
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn a_hostile_value_is_flattened_and_cut() {
        let root = tree("hostile");
        put(
            &root,
            "cpu0/cpufreq/scaling_governor",
            &format!("evil\u{1b}[31m{}\n", "x".repeat(500)),
        );
        let governor = read_cpufreq(&root)[0].governor.clone();
        assert!(!governor.contains('\u{1b}'));
        assert!(governor.starts_with("evil?[31m"));
        assert_eq!(
            governor.chars().count(),
            MAX_VALUE + 1,
            "cut, with an ellipsis"
        );
        let _ = fs::remove_dir_all(root);
    }

    const LIMITS_SAMPLE: &str = "\
Limit                     Soft Limit           Hard Limit           Units     
Max cpu time              unlimited            unlimited            seconds   
Max core file size        0                    unlimited            bytes     
Max locked memory         8388608              8388608              bytes     
Max address space         unlimited            unlimited            bytes     
";

    #[test]
    fn the_memlock_line_is_found_among_the_other_limits() {
        assert_eq!(
            parse_memlock(LIMITS_SAMPLE),
            Some(MemLock {
                soft: Limit::Bytes(8_388_608),
                hard: Limit::Bytes(8_388_608),
            })
        );
    }

    #[test]
    fn each_memlock_limit_is_a_number_or_unlimited_on_its_own() {
        let line = |soft: &str, hard: &str| {
            parse_memlock(&format!(
                "Max locked memory         {soft}              {hard}              bytes\n"
            ))
        };
        assert_eq!(
            line("unlimited", "unlimited"),
            Some(MemLock {
                soft: Limit::Unlimited,
                hard: Limit::Unlimited
            })
        );
        assert_eq!(
            line("65536", "unlimited"),
            Some(MemLock {
                soft: Limit::Bytes(65_536),
                hard: Limit::Unlimited
            })
        );
        assert_eq!(
            line("unlimited", "65536"),
            Some(MemLock {
                soft: Limit::Unlimited,
                hard: Limit::Bytes(65_536)
            })
        );
    }

    #[test]
    fn a_memlock_line_that_is_not_in_bytes_or_not_a_number_is_not_read() {
        let line = |rest: &str| parse_memlock(&format!("Max locked memory {rest}\n"));
        assert!(line("8388608 8388608 bytes").is_some());
        // Another unit: not a size we know how to read.
        assert_eq!(line("8192 8192 kbytes"), None);
        assert_eq!(line("8192 8192"), None);
        // Not numbers.
        assert_eq!(line("-1 -1 bytes"), None);
        assert_eq!(line("+8 8 bytes"), None);
        assert_eq!(line("8k 8 bytes"), None);
        assert_eq!(line("8 Unlimited bytes"), None);
        // Too big for 64 bits.
        assert_eq!(line("99999999999999999999999 8 bytes"), None);
        // A column missing.
        assert_eq!(line("8388608"), None);
        assert_eq!(line(""), None);
    }

    #[test]
    fn no_memlock_line_means_nothing_read() {
        assert_eq!(parse_memlock(""), None);
        assert_eq!(
            parse_memlock(
                "Max cpu time              unlimited            unlimited            seconds\n"
            ),
            None
        );
    }

    fn port(root: &Path, device: &str, number: u32, layer: &str) {
        put(
            root,
            &format!("{device}/ports/{number}/link_layer"),
            &format!("{layer}\n"),
        );
    }

    #[test]
    fn rdma_devices_are_listed_by_name_with_their_link_layers() {
        let root = tree("rdma");
        // Created in no particular order, whatever order the file system
        // lists them in.
        for (device, layer) in [
            ("mlx5_3", "Ethernet"),
            ("mlx5_0", "InfiniBand"),
            ("mlx5_4", "Ethernet"),
            ("mlx5_1", "Ethernet"),
            ("mlx5_2", "InfiniBand"),
        ] {
            port(&root, device, 1, layer);
        }
        port(&root, "mlx5_0", 2, "InfiniBand");
        // Ports that alternate: neither sorting nor removing repeats alone
        // gives the answer.
        for number in 2..=7 {
            let layer = if number % 2 == 0 {
                "Ethernet"
            } else {
                "InfiniBand"
            };
            port(&root, "mlx5_2", number, layer);
        }
        let devices = read_rdma(&root);
        let summary: Vec<(&str, Vec<&str>)> = devices
            .iter()
            .map(|d| {
                (
                    d.name.as_str(),
                    d.link_layers.iter().map(String::as_str).collect(),
                )
            })
            .collect();
        assert_eq!(
            summary,
            [
                ("mlx5_0", vec!["InfiniBand"]),
                ("mlx5_1", vec!["Ethernet"]),
                ("mlx5_2", vec!["Ethernet", "InfiniBand"]),
                ("mlx5_3", vec!["Ethernet"]),
                ("mlx5_4", vec!["Ethernet"]),
            ]
        );
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn an_rdma_device_whose_ports_cannot_be_read_is_still_a_device() {
        let root = tree("rdma-noports");
        fs::create_dir_all(root.join("rxe0")).unwrap();
        // A port without a readable link layer.
        put(&root, "rxe1/ports/1/state", "4: ACTIVE\n");
        let devices = read_rdma(&root);
        assert_eq!(devices.len(), 2, "{devices:?}");
        assert!(devices.iter().all(|d| d.link_layers.is_empty()));
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn no_rdma_directory_means_no_device() {
        let root = tree("rdma-none");
        assert!(read_rdma(&root).is_empty());
        assert!(read_rdma(&root.join("does-not-exist")).is_empty());
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn a_hostile_rdma_name_and_link_layer_are_flattened_and_cut() {
        let root = tree("rdma-hostile");
        // A file name is at most 255 bytes: long enough to be cut at 64.
        let name = format!("ev\u{1b}[31mil{}", "n".repeat(200));
        port(&root, &name, 1, "Eth\u{1b}[0mernet");
        let devices = read_rdma(&root);
        assert_eq!(devices.len(), 1);
        assert!(devices[0].name.starts_with("ev?[31mil"));
        assert_eq!(devices[0].name.chars().count(), MAX_VALUE + 1);
        assert_eq!(devices[0].link_layers, ["Eth?[0mernet"]);
        let _ = fs::remove_dir_all(root);
    }

    /// The places of a fake machine laid out under `root`.
    fn sources(root: &Path, limits: &str) -> Sources<'static> {
        // The `Path`s must outlive the call: leak the few bytes in a test.
        let leak =
            |relative: &str| -> &'static Path { Box::leak(root.join(relative).into_boxed_path()) };
        Sources {
            cpu: leak("cpu"),
            limits: leak(limits),
            rdma: leak("rdma"),
            nodes: leak("node"),
            numa_balancing: leak("numa_balancing"),
        }
    }

    #[test]
    fn the_readings_are_put_together_from_their_own_places() {
        let root = tree("together");
        policy(
            &root.join("cpu"),
            0,
            Some("intel_cpufreq"),
            "schedutil",
            None,
        );
        put(&root, "limits", LIMITS_SAMPLE);
        port(&root.join("rdma"), "mlx5_0", 1, "InfiniBand");
        put(&root, "numa_balancing", "1\n");
        put(&root, "node/node0/cpulist", "0\n");
        put(&root, "node/node1/cpulist", "1\n");
        put(&root, "cpu/smt/control", "on\n");
        put(&root, "cpu/smt/active", "1\n");
        put(&root, "cpu/cpu0/topology/thread_siblings_list", "0,1\n");
        put(&root, "cpu/cpu1/topology/thread_siblings_list", "0,1\n");
        let data = collect_from(&sources(&root, "limits"));
        assert_eq!(data.cpufreq.len(), 1, "{data:?}");
        assert_eq!(data.cpufreq[0].governor, "schedutil");
        assert_eq!(
            data.memlock,
            Some(MemLock {
                soft: Limit::Bytes(8_388_608),
                hard: Limit::Bytes(8_388_608)
            })
        );
        assert_eq!(data.rdma.len(), 1, "{data:?}");
        assert_eq!(data.rdma[0].name, "mlx5_0");
        assert_eq!(data.numa_balancing, Some(1));
        assert_eq!(data.numa_nodes, 2);
        assert_eq!(data.smt.control.as_deref(), Some("on"));
        assert_eq!(data.smt.active, Some(true));
        assert_eq!(
            data.topology,
            Some(CpuTopology {
                logical: 2,
                cores: 1,
                threads_per_core: Some(2)
            })
        );
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn a_machine_that_exposes_nothing_gives_empty_readings() {
        let root = tree("nothing");
        let data = collect_from(&sources(&root, "limits"));
        assert_eq!(data, HpcRawData::default());
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn a_file_of_limits_that_is_missing_or_unreadable_is_no_reading() {
        let root = tree("nolimits");
        assert_eq!(collect_from(&sources(&root, "absent")).memlock, None);
        put(&root, "garbled", "Max locked memory lots\n");
        assert_eq!(collect_from(&sources(&root, "garbled")).memlock, None);
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn the_numa_balancing_switch_is_a_number_or_nothing() {
        let root = tree("balancing");
        let value = |text: &str| {
            put(&root, "numa_balancing", text);
            read_number(&root.join("numa_balancing"))
        };
        assert_eq!(value("0\n"), Some(0));
        assert_eq!(value("1"), Some(1));
        assert_eq!(value("2\n"), Some(2));
        assert_eq!(value("3\n"), Some(3));
        assert_eq!(value("12"), Some(12));
        for bad in ["", "\n", "-1", "+1", "on", "1 2", "0x1", "99999999999"] {
            assert_eq!(value(bad), None, "{bad:?}");
        }
        assert_eq!(read_number(&root.join("absent")), None);
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn only_node_directories_are_counted_as_numa_nodes() {
        let root = tree("nodes");
        for name in ["node0", "node1", "node12"] {
            fs::create_dir_all(root.join(name)).unwrap();
        }
        // Not nodes: the other entries of /sys/devices/system/node.
        for name in ["nodeX", "node", "node-1", "node1x", "mynode3", "online"] {
            fs::create_dir_all(root.join(name)).unwrap();
        }
        put(&root, "possible", "0-1\n");
        put(&root, "has_cpu", "0-1\n");
        assert_eq!(count_numa_nodes(&root), 3);
        assert_eq!(count_numa_nodes(&root.join("does-not-exist")), 0);
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn smt_control_and_active_are_read_as_they_are_written() {
        let root = tree("smt");
        assert_eq!(read_smt(&root), Smt::default());
        put(&root, "smt/control", "forceoff\n");
        put(&root, "smt/active", "0\n");
        assert_eq!(
            read_smt(&root),
            Smt {
                control: Some("forceoff".to_string()),
                active: Some(false)
            }
        );
        put(&root, "smt/active", "1\n");
        assert_eq!(read_smt(&root).active, Some(true));
        // Anything else than 0 and 1 is not a reading.
        for bad in ["2", "yes", "", "01"] {
            put(&root, "smt/active", bad);
            assert_eq!(read_smt(&root).active, None, "{bad:?}");
        }
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn the_smt_value_is_flattened_and_cut() {
        let root = tree("smt-hostile");
        put(
            &root,
            "smt/control",
            &format!("on\u{1b}[31m{}\n", "x".repeat(300)),
        );
        let control = read_smt(&root).control.unwrap();
        assert!(control.starts_with("on?[31m"));
        assert_eq!(control.chars().count(), MAX_VALUE + 1);
        let _ = fs::remove_dir_all(root);
    }

    fn siblings(root: &Path, cpu: u32, list: &str) {
        put(
            root,
            &format!("cpu{cpu}/topology/thread_siblings_list"),
            &format!("{list}\n"),
        );
    }

    #[test]
    fn cores_are_the_distinct_lists_of_siblings() {
        let root = tree("topology");
        // Four CPUs, two cores of two threads; CPU numbers deliberately
        // not consecutive within a core.
        siblings(&root, 0, "0,2");
        siblings(&root, 1, "1,3");
        siblings(&root, 2, "0,2");
        siblings(&root, 3, "1,3");
        assert_eq!(
            read_topology(&root),
            Some(CpuTopology {
                logical: 4,
                cores: 2,
                threads_per_core: Some(2)
            })
        );
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn one_thread_per_core_is_reported_as_such() {
        let root = tree("topology-one");
        for cpu in 0..3 {
            siblings(&root, cpu, &cpu.to_string());
        }
        assert_eq!(
            read_topology(&root),
            Some(CpuTopology {
                logical: 3,
                cores: 3,
                threads_per_core: Some(1)
            })
        );
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn cores_of_different_sizes_have_no_single_thread_count() {
        let root = tree("topology-hybrid");
        // One core of 2 threads and two of 1: four CPUs on three cores.
        siblings(&root, 0, "0-1");
        siblings(&root, 1, "0-1");
        siblings(&root, 2, "2");
        siblings(&root, 3, "3");
        let topology = read_topology(&root).unwrap();
        assert_eq!((topology.logical, topology.cores), (4, 3));
        assert_eq!(topology.threads_per_core, None);
        // A multiple by chance: cores of 1, 2 and 3 threads, 6 CPUs on 3
        // cores, which is not "2 per core".
        let root2 = tree("topology-chance");
        siblings(&root2, 0, "0");
        siblings(&root2, 1, "1-2");
        siblings(&root2, 2, "1-2");
        siblings(&root2, 3, "3-5");
        siblings(&root2, 4, "3-5");
        siblings(&root2, 5, "3-5");
        let chance = read_topology(&root2).unwrap();
        assert_eq!((chance.logical, chance.cores), (6, 3));
        assert_eq!(chance.threads_per_core, None);
        // Sizes 2, 1, 2: the first size comes back, but the middle one
        // differs.
        let root3 = tree("topology-middle");
        siblings(&root3, 0, "0-1");
        siblings(&root3, 1, "0-1");
        siblings(&root3, 2, "2");
        siblings(&root3, 3, "3-4");
        siblings(&root3, 4, "3-4");
        let middle = read_topology(&root3).unwrap();
        assert_eq!((middle.logical, middle.cores), (5, 3));
        assert_eq!(middle.threads_per_core, None);
        let _ = fs::remove_dir_all(root);
        let _ = fs::remove_dir_all(root2);
        let _ = fs::remove_dir_all(root3);
    }

    #[test]
    fn cpus_that_do_not_report_their_siblings_are_left_out() {
        let root = tree("topology-partial");
        siblings(&root, 0, "0");
        // Offline: no topology directory. Not a CPU: a stray entry.
        put(&root, "cpu1/online", "0\n");
        put(&root, "cpu2/topology/core_id", "2\n");
        siblings(&root, 99, "99");
        put(&root, "cpufreq/topology/thread_siblings_list", "7\n");
        let topology = read_topology(&root).unwrap();
        assert_eq!((topology.logical, topology.cores), (2, 2));
        assert_eq!(read_topology(&root.join("does-not-exist")), None);
        let _ = fs::remove_dir_all(root);
    }
}
