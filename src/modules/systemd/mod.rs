// SPDX-License-Identifier: GPL-3.0-only

pub mod analyze;
pub mod collect;

use crate::core::context::Context;
use crate::core::error::ModuleError;
use crate::models::{Category, Finding};

use super::Module;

pub struct SystemdModule;

impl Module for SystemdModule {
    fn id(&self) -> &'static str {
        "systemd"
    }

    fn category(&self) -> Category {
        Category::Systemd
    }

    /// systemctl can be *installed* without systemd actually being PID 1
    /// (e.g. a base container image) -- checking for the binary alone
    /// isn't enough, so this checks the same marker libsystemd's
    /// `sd_booted()` does.
    fn is_available(&self, _ctx: &Context) -> bool {
        collect::systemd_available()
    }

    fn run(&self, ctx: &Context) -> Result<Vec<Finding>, ModuleError> {
        let data = collect::collect()?;
        Ok(analyze::analyze(&data, ctx))
    }
}
