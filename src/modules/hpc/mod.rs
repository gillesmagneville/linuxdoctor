// SPDX-License-Identifier: GPL-3.0-only

//! The checks that only make sense on a compute node (`--profile hpc`).
//!
//! Unlike the other modules, this one is not part of every audit: it is
//! added by the profile (see [`crate::profile::Profile::modules`]), because
//! what it looks at -- whether the CPUs are left free to run at full speed --
//! is a question for a machine whose job is computing, and a finding "your
//! desktop is not set to `performance`" would be noise. A profile can only
//! lower the severity of an existing finding, so a check that is wrong on one
//! kind of machine and right on another has to live in a module of its own.

pub mod analyze;
pub mod collect;

use crate::core::context::Context;
use crate::core::error::ModuleError;
use crate::models::{Category, Finding};

use super::Module;

pub struct HpcModule;

impl Module for HpcModule {
    fn id(&self) -> &'static str {
        "hpc"
    }

    fn category(&self) -> Category {
        Category::Performance
    }

    fn run(&self, ctx: &Context) -> Result<Vec<Finding>, ModuleError> {
        let data = collect::collect()?;
        Ok(analyze::analyze(&data, ctx))
    }
}
