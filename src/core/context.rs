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
            cpu_count: std::thread::available_parallelism()
                .map(|n| n.get())
                .unwrap_or(1),
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
