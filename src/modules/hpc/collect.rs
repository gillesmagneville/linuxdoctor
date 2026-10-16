// SPDX-License-Identifier: GPL-3.0-only

//! What the CPU frequency policy of every CPU says: the governor, the driver
//! behind it and, where the driver has one, the energy/performance
//! preference. Read from `/sys/devices/system/cpu/cpu<N>/cpufreq/`.

use std::fs;
use std::path::Path;

use crate::core::error::ModuleError;
use crate::core::text::clean;

/// Where the per-CPU directories live.
const CPU_ROOT: &str = "/sys/devices/system/cpu";

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

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct HpcRawData {
    /// Every CPU with a frequency policy, by CPU number. Empty on a machine
    /// that exposes none (a virtual machine, a platform with a fixed
    /// frequency, a driver not loaded).
    pub cpufreq: Vec<CpuFreq>,
}

pub fn collect() -> Result<HpcRawData, ModuleError> {
    Ok(collect_from(Path::new(CPU_ROOT)))
}

/// [`collect`] on a directory laid out like `/sys/devices/system/cpu`, so
/// the reading is tested on a fake tree.
pub fn collect_from(root: &Path) -> HpcRawData {
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
    HpcRawData { cpufreq }
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
        let data = collect_from(&root);
        let cpus: Vec<u32> = data.cpufreq.iter().map(|c| c.cpu).collect();
        assert_eq!(cpus, [0, 1, 2, 10]);
        assert_eq!(
            data.cpufreq[0],
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
        let data = collect_from(&root);
        assert_eq!(data.cpufreq[0].epp, None);
        assert_eq!(data.cpufreq[0].driver.as_deref(), Some("acpi-cpufreq"));
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn a_missing_driver_file_is_not_a_missing_cpu() {
        let root = tree("no-driver");
        policy(&root, 0, None, "performance", None);
        let data = collect_from(&root);
        assert_eq!(data.cpufreq.len(), 1);
        assert_eq!(data.cpufreq[0].driver, None);
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
        let data = collect_from(&root);
        assert_eq!(data.cpufreq.len(), 1, "{data:?}");
        assert_eq!(data.cpufreq[0].governor, "performance");
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
        let data = collect_from(&root);
        let cpus: Vec<u32> = data.cpufreq.iter().map(|c| c.cpu).collect();
        assert_eq!(cpus, [0]);
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn no_cpu_tree_means_no_policies() {
        let root = tree("none");
        assert!(collect_from(&root).cpufreq.is_empty());
        assert!(collect_from(&root.join("does-not-exist"))
            .cpufreq
            .is_empty());
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
        let governor = collect_from(&root).cpufreq[0].governor.clone();
        assert!(!governor.contains('\u{1b}'));
        assert!(governor.starts_with("evil?[31m"));
        assert_eq!(
            governor.chars().count(),
            MAX_VALUE + 1,
            "cut, with an ellipsis"
        );
        let _ = fs::remove_dir_all(root);
    }
}
