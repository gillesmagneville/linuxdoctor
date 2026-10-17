// SPDX-License-Identifier: GPL-3.0-only

pub mod analyze;
pub mod collect;
pub mod device;
pub mod mounts;
pub mod raid;

use crate::core::context::Context;
use crate::core::error::ModuleError;
use crate::models::{Category, Finding};

use super::Module;

pub struct StorageModule;

impl Module for StorageModule {
    fn id(&self) -> &'static str {
        "storage"
    }

    fn category(&self) -> Category {
        Category::Storage
    }

    fn run(&self, ctx: &Context) -> Result<Vec<Finding>, ModuleError> {
        let data = collect::collect()?;
        Ok(analyze::analyze(&data, ctx))
    }
}
