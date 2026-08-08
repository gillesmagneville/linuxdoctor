// SPDX-License-Identifier: GPL-3.0-only

pub mod analyze;
pub mod collect;

use crate::core::context::Context;
use crate::core::error::ModuleError;
use crate::models::{Category, Finding};

use super::Module;

pub struct NetworkModule;

impl Module for NetworkModule {
    fn id(&self) -> &'static str {
        "network"
    }

    fn category(&self) -> Category {
        Category::Network
    }

    fn run(&self, ctx: &Context) -> Result<Vec<Finding>, ModuleError> {
        let data = collect::collect()?;
        Ok(analyze::analyze(&data, ctx))
    }
}
