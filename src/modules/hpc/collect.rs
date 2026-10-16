// SPDX-License-Identifier: GPL-3.0-only

//! What the checks of the `hpc` module read:
//!
//! * the CPU frequency policy of every CPU -- the governor, the driver behind
//!   it and, where the driver has one, the energy/performance preference --
//!   from `/sys/devices/system/cpu/cpu<N>/cpufreq/`;
//! * the locked-memory limit of this process, from `/proc/self/limits`;
//! * the RDMA devices (InfiniBand, RoCE), from `/sys/class/infiniband/`.

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
}

pub fn collect() -> Result<HpcRawData, ModuleError> {
    Ok(collect_from(
        Path::new(CPU_ROOT),
        Path::new(LIMITS_FILE),
        Path::new(RDMA_ROOT),
    ))
}

/// [`collect`] on the given places, so that putting the three readings
/// together is tested on fake files.
pub fn collect_from(cpu_root: &Path, limits_file: &Path, rdma_root: &Path) -> HpcRawData {
    HpcRawData {
        cpufreq: read_cpufreq(cpu_root),
        memlock: fs::read_to_string(limits_file)
            .ok()
            .and_then(|text| parse_memlock(&text)),
        rdma: read_rdma(rdma_root),
    }
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

    #[test]
    fn the_three_readings_are_put_together_from_their_own_places() {
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
        let data = collect_from(&root.join("cpu"), &root.join("limits"), &root.join("rdma"));
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
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn a_file_of_limits_that_is_missing_or_unreadable_is_no_reading() {
        let root = tree("nolimits");
        let places =
            |limits: &str| collect_from(&root.join("cpu"), &root.join(limits), &root.join("rdma"));
        assert_eq!(places("absent").memlock, None);
        put(&root, "garbled", "Max locked memory lots\n");
        assert_eq!(places("garbled").memlock, None);
        let _ = fs::remove_dir_all(root);
    }
}
