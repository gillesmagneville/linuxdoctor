// SPDX-License-Identifier: GPL-3.0-only

use std::fs;
use std::path::Path;

use crate::core::error::ModuleError;
use crate::modules::cpu::collect::parse_cpu_list;

#[derive(Debug, Clone, PartialEq)]
pub struct NumaNode {
    pub id: u32,
    pub cpus: Vec<u32>,
    pub mem_total_kb: u64,
    pub mem_free_kb: u64,
}

impl NumaNode {
    pub fn mem_used_percent(&self) -> f64 {
        if self.mem_total_kb == 0 {
            return 0.0;
        }
        let used = self.mem_total_kb.saturating_sub(self.mem_free_kb);
        (used as f64 / self.mem_total_kb as f64) * 100.0
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct NumaRawData {
    pub nodes: Vec<NumaNode>,
}

const NODE_DIR: &str = "/sys/devices/system/node";

/// Whether this system exposes NUMA node information at all. Used by the
/// module's `is_available()` so systems without it (rare, but possible on
/// minimal/embedded kernels) get a clean "skipped" rather than a collect
/// error.
pub fn numa_supported() -> bool {
    Path::new(NODE_DIR).is_dir()
}

/// Thin I/O wrapper: lists node directories, reads each one's cpulist and
/// meminfo, delegates parsing to the pure functions below.
pub fn collect() -> Result<NumaRawData, ModuleError> {
    let entries = fs::read_dir(NODE_DIR).map_err(|source| ModuleError::Io {
        path: NODE_DIR.to_string(),
        source,
    })?;

    let mut node_ids: Vec<u32> = Vec::new();
    for entry in entries.flatten() {
        let name = entry.file_name();
        let Some(name) = name.to_str() else { continue };
        if let Some(id_str) = name.strip_prefix("node") {
            if let Ok(id) = id_str.parse::<u32>() {
                node_ids.push(id);
            }
        }
    }
    node_ids.sort_unstable();

    let mut nodes = Vec::new();
    for id in node_ids {
        let cpulist_path = format!("{NODE_DIR}/node{id}/cpulist");
        let meminfo_path = format!("{NODE_DIR}/node{id}/meminfo");

        let cpus = fs::read_to_string(&cpulist_path)
            .map(|text| parse_cpu_list(&text))
            .unwrap_or_default();

        let meminfo_text = fs::read_to_string(&meminfo_path).map_err(|source| ModuleError::Io {
            path: meminfo_path,
            source,
        })?;
        let (mem_total_kb, mem_free_kb) = parse_node_meminfo(&meminfo_text)?;

        nodes.push(NumaNode {
            id,
            cpus,
            mem_total_kb,
            mem_free_kb,
        });
    }

    Ok(NumaRawData { nodes })
}

/// Parse a `nodeN/meminfo` file, e.g. "Node 0 MemTotal:   4093748 kB".
/// Pure function, tested against fixture text.
pub fn parse_node_meminfo(text: &str) -> Result<(u64, u64), ModuleError> {
    let mut mem_total: Option<u64> = None;
    let mut mem_free: Option<u64> = None;

    for line in text.lines() {
        let Some(colon) = line.find(':') else { continue };
        let key = line[..colon].split_whitespace().last().unwrap_or("");
        let value = line[colon + 1..]
            .trim()
            .split_whitespace()
            .next()
            .and_then(|v| v.parse::<u64>().ok());

        match key {
            "MemTotal" => mem_total = value,
            "MemFree" => mem_free = value,
            _ => {}
        }
    }

    match (mem_total, mem_free) {
        (Some(total), Some(free)) => Ok((total, free)),
        _ => Err(ModuleError::Parse {
            what: "node meminfo".to_string(),
            reason: "missing MemTotal or MemFree field".to_string(),
        }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const FIXTURE_NODE_MEMINFO: &str = "\
Node 0 MemTotal:        4093748 kB
Node 0 MemFree:         3992528 kB
Node 0 MemUsed:          101220 kB
Node 0 Active:             5520 kB
";

    #[test]
    fn parses_node_meminfo() {
        let (total, free) = parse_node_meminfo(FIXTURE_NODE_MEMINFO).unwrap();
        assert_eq!(total, 4_093_748);
        assert_eq!(free, 3_992_528);
    }

    #[test]
    fn errors_when_fields_missing() {
        assert!(parse_node_meminfo("Node 0 Active: 5520 kB\n").is_err());
    }

    #[test]
    fn mem_used_percent_computed_correctly() {
        let node = NumaNode {
            id: 0,
            cpus: vec![0, 1],
            mem_total_kb: 1_000_000,
            mem_free_kb: 250_000,
        };
        assert_eq!(node.mem_used_percent(), 75.0);
    }

    #[test]
    fn mem_used_percent_zero_total_does_not_divide_by_zero() {
        let node = NumaNode {
            id: 0,
            cpus: vec![],
            mem_total_kb: 0,
            mem_free_kb: 0,
        };
        assert_eq!(node.mem_used_percent(), 0.0);
    }
}
