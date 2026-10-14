// SPDX-License-Identifier: GPL-3.0-only

pub mod analyze;
mod cache;
pub mod collect;
mod format;
mod kernel;
mod pressure;
mod shared;
mod swap;
#[cfg(test)]
mod test_support;
mod tuning;
mod used;

use crate::core::context::Context;
use crate::core::error::ModuleError;
use crate::models::{Category, Finding};

use super::Module;

pub struct MemoryModule;

impl Module for MemoryModule {
    fn id(&self) -> &'static str {
        "memory"
    }

    fn category(&self) -> Category {
        Category::Memory
    }

    fn run(&self, ctx: &Context) -> Result<Vec<Finding>, ModuleError> {
        let data = collect::collect()?;
        Ok(analyze::analyze(&data, ctx))
    }
}
