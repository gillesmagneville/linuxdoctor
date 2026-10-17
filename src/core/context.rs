// SPDX-License-Identifier: GPL-3.0-only

use std::fs;
use std::time::{SystemTime, UNIX_EPOCH};

use serde::Serialize;

use crate::core::error::CoreError;

/// System facts gathered once at startup. Immutable for the lifetime of the
/// run — modules receive `&Context` and cannot mutate it. See
/// ARCHITECTURE.md "Context".
#[derive(Debug, Clone, Serialize)]
pub struct Context {
    pub hostname: String,
    pub kernel_version: String,
    pub distro: Option<String>,
    pub architecture: String,
    pub cpu_count: usize,
    pub mem_total_kb: u64,
    pub boot_time_unix: u64,
}

/// The effective user id of this process, from `/proc/self/status`
/// ("Uid: real effective saved fs"), so no C library call is needed.
/// `None` if it cannot be read.
pub fn effective_uid() -> Option<u32> {
    let status = fs::read_to_string("/proc/self/status").ok()?;
    status
        .lines()
        .find_map(|l| l.strip_prefix("Uid:"))?
        .split_whitespace()
        .nth(1)?
        .parse()
        .ok()
}

impl Context {
    /// Build a Context from the live system. Any single fact that can't be
    /// read falls back to a placeholder rather than failing the whole run —
    /// the audit itself should still proceed.
    pub fn detect() -> Result<Context, CoreError> {
        Ok(Context {
            hostname: read_hostname(),
            kernel_version: read_kernel_version(),
            distro: read_distro(),
            architecture: std::env::consts::ARCH.to_string(),
            cpu_count: cpu_count_from(fs::read_to_string(ONLINE_CPUS).ok().as_deref()),
            mem_total_kb: read_mem_total_kb().unwrap_or(0),
            boot_time_unix: read_boot_time().unwrap_or_else(|| {
                SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .map(|d| d.as_secs())
                    .unwrap_or(0)
            }),
        })
    }
}

/// The CPUs the kernel has online, as a list (`0-55`).
const ONLINE_CPUS: &str = "/sys/devices/system/cpu/online";

/// How many CPUs the machine has: the ones online, from the text of
/// [`ONLINE_CPUS`]. Not `available_parallelism()`, which counts the CPUs this
/// process is *allowed to run on* and so leaves out those reserved for
/// something else (a virtual machine pinned to its own cores, a cgroup
/// limit): on a machine with 56 CPUs of which 24 are set aside, a report
/// would say 32. That number stays the fallback when the list cannot be
/// read.
fn cpu_count_from(online: Option<&str>) -> usize {
    online
        .and_then(parse_cpu_list)
        .or_else(|| std::thread::available_parallelism().ok().map(|n| n.get()))
        .unwrap_or(1)
}

/// The number of CPUs in a kernel CPU list: `0-55`, `0-3,8-11`, `0`. Nothing
/// if the text is not such a list.
fn parse_cpu_list(text: &str) -> Option<usize> {
    let mut total = 0usize;
    for part in text.trim().split(',') {
        let (first, last) = match part.split_once('-') {
            Some((first, last)) => (cpu_id(first)?, cpu_id(last)?),
            None => {
                let cpu = cpu_id(part)?;
                (cpu, cpu)
            }
        };
        if last < first {
            return None;
        }
        total = total.checked_add(((last - first) as usize).checked_add(1)?)?;
    }
    Some(total)
}

/// A CPU number: digits only (`str::parse` would also take `+3`).
fn cpu_id(text: &str) -> Option<u32> {
    if !text.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    text.parse().ok()
}

fn read_hostname() -> String {
    fs::read_to_string("/proc/sys/kernel/hostname")
        .map(|s| s.trim().to_string())
        .unwrap_or_else(|_| "unknown".to_string())
}

fn read_kernel_version() -> String {
    fs::read_to_string("/proc/sys/kernel/osrelease")
        .map(|s| s.trim().to_string())
        .unwrap_or_else(|_| "unknown".to_string())
}

fn read_distro() -> Option<String> {
    let text = fs::read_to_string("/etc/os-release").ok()?;
    for line in text.lines() {
        if let Some(value) = line.strip_prefix("PRETTY_NAME=") {
            return Some(value.trim_matches('"').to_string());
        }
    }
    None
}

fn read_mem_total_kb() -> Option<u64> {
    let text = fs::read_to_string("/proc/meminfo").ok()?;
    for line in text.lines() {
        if let Some(rest) = line.strip_prefix("MemTotal:") {
            return rest.split_whitespace().next()?.parse().ok();
        }
    }
    None
}

fn read_boot_time() -> Option<u64> {
    let text = fs::read_to_string("/proc/stat").ok()?;
    for line in text.lines() {
        if let Some(rest) = line.strip_prefix("btime ") {
            return rest.trim().parse().ok();
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_range_counts_both_ends() {
        assert_eq!(parse_cpu_list("0-55\n"), Some(56));
        assert_eq!(parse_cpu_list("0-0"), Some(1));
        assert_eq!(parse_cpu_list("4-7"), Some(4));
    }

    #[test]
    fn a_single_cpu_and_a_list_of_ranges_add_up() {
        assert_eq!(parse_cpu_list("0\n"), Some(1));
        assert_eq!(parse_cpu_list("3"), Some(1));
        // Some CPUs offline or set aside: the list has holes.
        assert_eq!(parse_cpu_list("0-3,8-11"), Some(8));
        assert_eq!(parse_cpu_list("0,2,4-5"), Some(4));
        assert_eq!(parse_cpu_list("0-27,56-83"), Some(56));
    }

    #[test]
    fn what_is_not_a_cpu_list_is_not_counted() {
        for text in [
            "", "\n", ",", "0,", ",0", "0-", "-3", "a", "0-a", "3-1", "0 - 3", "0-3, 8", "+3",
            "0--3", "1-2-3", "0x10", "-1",
        ] {
            assert_eq!(parse_cpu_list(text), None, "{text:?}");
        }
        // Too many CPUs for one number.
        assert_eq!(parse_cpu_list("99999999999999999999"), None);
    }

    #[test]
    fn a_huge_list_does_not_overflow() {
        let all = format!("0-{}", u32::MAX);
        assert_eq!(parse_cpu_list(&all), (u32::MAX as usize).checked_add(1));
    }

    #[test]
    fn the_online_list_decides_when_it_is_there() {
        assert_eq!(cpu_count_from(Some("0-55\n")), 56);
        assert_eq!(cpu_count_from(Some("0")), 1);
    }

    #[test]
    fn without_a_readable_list_the_cpus_this_process_may_use_are_counted() {
        let usable = std::thread::available_parallelism().map_or(1, |n| n.get());
        assert_eq!(cpu_count_from(None), usable);
        assert_eq!(cpu_count_from(Some("not a list")), usable);
    }

    #[test]
    fn the_machine_has_at_least_the_cpus_this_process_may_use() {
        let usable = std::thread::available_parallelism().map_or(1, |n| n.get());
        let counted = Context::detect().unwrap().cpu_count;
        assert!(counted >= usable, "{counted} < {usable}");
    }
}
