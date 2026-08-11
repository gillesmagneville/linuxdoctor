// SPDX-License-Identifier: GPL-3.0-only

pub mod analyze;
pub mod collect;

use crate::core::context::Context;
use crate::core::error::ModuleError;
use crate::models::{Category, Finding};

use super::Module;

pub struct NtpModule;

impl Module for NtpModule {
    fn id(&self) -> &'static str {
        "ntp"
    }

    fn category(&self) -> Category {
        Category::Ntp
    }

    /// `timedatectl` is part of systemd core, so this needs systemd as
    /// PID 1 for exactly the same reason the Systemd module does.
    fn is_available(&self, _ctx: &Context) -> bool {
        collect::systemd_available()
    }

    fn run(&self, ctx: &Context) -> Result<Vec<Finding>, ModuleError> {
        let data = collect::collect()?;
        Ok(analyze::analyze(&data, ctx))
    }
}
