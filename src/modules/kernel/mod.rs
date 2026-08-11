// SPDX-License-Identifier: GPL-3.0-only

pub mod analyze;
pub mod collect;

use crate::core::context::Context;
use crate::core::error::ModuleError;
use crate::models::{Category, Finding};

use super::Module;

pub struct KernelModule;

impl Module for KernelModule {
    fn id(&self) -> &'static str {
        "kernel"
    }

    fn category(&self) -> Category {
        Category::Kernel
    }

    fn run(&self, ctx: &Context) -> Result<Vec<Finding>, ModuleError> {
        let data = collect::collect()?;
        Ok(analyze::analyze(&data, ctx))
    }
}
