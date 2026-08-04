// SPDX-License-Identifier: GPL-3.0-only

use std::collections::HashMap;
use std::fs;

use crate::core::error::ModuleError;

/// Raw facts read from the system, before any interpretation. Collectors
/// never interpret — see ARCHITECTURE.md "Collectors".
#[derive(Debug, Clone, PartialEq)]
pub struct MemoryRawData {
    pub mem_total_kb: u64,
    pub mem_available_kb: u64,
    pub swap_total_kb: u64,
    pub swap_free_kb: u64,
    pub swappiness: u8,
}

/// Thin I/O wrapper: reads the two source files and delegates all
/// interpretation to the pure parse functions below.
pub fn collect() -> Result<MemoryRawData, ModuleError> {
    let meminfo_text =
        fs::read_to_string("/proc/meminfo").map_err(|source| ModuleError::Io {
            path: "/proc/meminfo".to_string(),
            source,
        })?;
    let swappiness_text = fs::read_to_string("/proc/sys/vm/swappiness").map_err(|source| {
        ModuleError::Io {
            path: "/proc/sys/vm/swappiness".to_string(),
            source,
        }
    })?;

    let fields = parse_meminfo(&meminfo_text)?;
    let swappiness = parse_swappiness(&swappiness_text)?;

    Ok(MemoryRawData {
        mem_total_kb: *fields.get("MemTotal").unwrap_or(&0),
        mem_available_kb: *fields.get("MemAvailable").unwrap_or(&0),
        swap_total_kb: *fields.get("SwapTotal").unwrap_or(&0),
        swap_free_kb: *fields.get("SwapFree").unwrap_or(&0),
        swappiness,
    })
}

/// Parse `/proc/meminfo` text into a key -> kB map. Pure function, tested
/// directly against fixture strings (no filesystem access needed).
pub fn parse_meminfo(text: &str) -> Result<HashMap<String, u64>, ModuleError> {
    let mut fields = HashMap::new();
    for line in text.lines() {
        let Some((key, rest)) = line.split_once(':') else {
            continue;
        };
        let Some(value_str) = rest.trim().split_whitespace().next() else {
            continue;
        };
        if let Ok(value) = value_str.parse::<u64>() {
            fields.insert(key.trim().to_string(), value);
        }
    }
    if fields.is_empty() {
        return Err(ModuleError::Parse {
            what: "/proc/meminfo".to_string(),
            reason: "no recognizable key: value lines".to_string(),
        });
    }
    Ok(fields)
}

/// Parse the single-integer contents of `/proc/sys/vm/swappiness`.
pub fn parse_swappiness(text: &str) -> Result<u8, ModuleError> {
    text.trim().parse::<u8>().map_err(|e| ModuleError::Parse {
        what: "/proc/sys/vm/swappiness".to_string(),
        reason: e.to_string(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    const FIXTURE_MEMINFO: &str = "\
MemTotal:       16384000 kB
MemFree:         1200000 kB
MemAvailable:    2000000 kB
Buffers:          300000 kB
Cached:          4000000 kB
SwapTotal:       4194300 kB
SwapFree:         100000 kB
";

    #[test]
    fn parses_known_fields() {
        let fields = parse_meminfo(FIXTURE_MEMINFO).unwrap();
        assert_eq!(fields.get("MemTotal"), Some(&16384000));
        assert_eq!(fields.get("MemAvailable"), Some(&2000000));
        assert_eq!(fields.get("SwapTotal"), Some(&4194300));
        assert_eq!(fields.get("SwapFree"), Some(&100000));
    }

    #[test]
    fn ignores_unparseable_lines() {
        let text = "MemTotal:       16384000 kB\nNotAField without a colon value\n";
        let fields = parse_meminfo(text).unwrap();
        assert_eq!(fields.len(), 1);
    }

    #[test]
    fn errors_on_empty_input() {
        assert!(parse_meminfo("").is_err());
    }

    #[test]
    fn parses_swappiness() {
        assert_eq!(parse_swappiness("60\n").unwrap(), 60);
    }

    #[test]
    fn errors_on_malformed_swappiness() {
        assert!(parse_swappiness("not-a-number").is_err());
    }
}
