// SPDX-License-Identifier: GPL-3.0-only

pub mod analyze;
pub mod collect;

use crate::core::context::Context;
use crate::core::error::ModuleError;
use crate::models::{Category, Finding};

use super::Module;

pub struct NumaModule;

impl Module for NumaModule {
    fn id(&self) -> &'static str {
        "numa"
    }

    fn category(&self) -> Category {
        Category::Numa
    }

    /// Every modern Linux system exposes at least one NUMA node, but the
    /// sysfs interface itself isn't guaranteed present (older or minimal
    /// kernels) — skip cleanly rather than erroring when it's missing.
    fn is_available(&self, _ctx: &Context) -> bool {
        collect::numa_supported()
    }

    fn run(&self, ctx: &Context) -> Result<Vec<Finding>, ModuleError> {
        let data = collect::collect()?;
        Ok(analyze::analyze(&data, ctx))
    }
}
