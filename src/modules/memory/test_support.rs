// SPDX-License-Identifier: GPL-3.0-only

//! Fixtures shared by the memory unit tests.

use crate::core::context::Context;
use crate::models::Finding;

use super::collect::{MeminfoDetail, MemoryRawData, ProcessMemory};

pub fn ctx() -> Context {
    Context {
        hostname: "test".into(),
        kernel_version: "test".into(),
        distro: None,
        architecture: "x86_64".into(),
        cpu_count: 4,
        mem_total_kb: 16_000_000,
        boot_time_unix: 0,
    }
}

/// A healthy 16 GB machine with the extended /proc/meminfo fields filled
/// in: 56% available, plenty of cache, swap unused, defaults everywhere.
pub fn healthy() -> MemoryRawData {
    MemoryRawData {
        mem_total_kb: 16_000_000,
        mem_free_kb: 4_000_000,
        mem_available_kb: 9_000_000,
        cached_kb: 5_000_000, // buffers 200k + cached 4.8M
        shmem_kb: 300_000,
        dirty_kb: 16_000,
        swap_total_kb: 4_000_000,
        swap_free_kb: 4_000_000,
        swappiness: 60,
        dirty_ratio: 20,
        dirty_background_ratio: 10,
        detail: MeminfoDetail {
            buffers_kb: 200_000,
            cached_incl_shmem_kb: 4_800_000,
            anon_pages_kb: 5_000_000,
            sreclaimable_kb: 400_000,
            sunreclaim_kb: 200_000,
            kernel_stack_kb: 30_000,
            page_tables_kb: 60_000,
            percpu_kb: 10_000,
            ..Default::default()
        },
        ..Default::default()
    }
}

pub fn proc(pid: u32, name: &str, anon: u64) -> ProcessMemory {
    ProcessMemory {
        pid,
        name: name.into(),
        rss_anon_kb: anon,
        rss_file_kb: 0,
        rss_shmem_kb: 0,
        swap_kb: 0,
    }
}

pub fn evidence<'a>(f: &'a Finding, key: &str) -> Option<&'a str> {
    f.evidence
        .iter()
        .find(|(k, _)| k == key)
        .map(|(_, v)| v.as_str())
}
