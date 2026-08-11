// SPDX-License-Identifier: GPL-3.0-only

pub mod cpu;
pub mod kernel;
pub mod memory;
pub mod network;
pub mod ntp;
pub mod numa;
pub mod storage;
pub mod systemd;

use crate::core::context::Context;
use crate::core::error::ModuleError;
use crate::models::{Category, Finding};

/// See ARCHITECTURE.md "Diagnostic Modules". One object-safe entry point;
/// implementations keep `collect()` (I/O) and `analyze()` (pure logic) as
/// separate internal functions so `analyze()` stays unit-testable without
/// touching the filesystem.
pub trait Module: Send + Sync {
    /// Stable identifier, e.g. "memory".
    fn id(&self) -> &'static str;

    fn category(&self) -> Category;

    /// Whether this module applies to the current system. Default: always.
    fn is_available(&self, _ctx: &Context) -> bool {
        true
    }

    fn run(&self, ctx: &Context) -> Result<Vec<Finding>, ModuleError>;
}

/// All modules that ship in v1. Extend this as new modules are added — the
/// engine never needs to change.
pub fn all_modules() -> Vec<Box<dyn Module>> {
    vec![
        Box::new(memory::MemoryModule),
        Box::new(cpu::CpuModule),
        Box::new(numa::NumaModule),
        Box::new(storage::StorageModule),
        Box::new(systemd::SystemdModule),
        Box::new(ntp::NtpModule),
        Box::new(network::NetworkModule),
        Box::new(kernel::KernelModule),
    ]
}
