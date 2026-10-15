// SPDX-License-Identifier: GPL-3.0-only

//! Logs: who tried to log in and whether anyone got in, what has been
//! failing since boot, what the kernel reported about disks, memory and
//! crashes, and the state of the logging itself.
//!
//! Strictly read-only. The module reads the systemd journal, falling back
//! to the classic `auth.log`/`secure` and `dmesg`. Without root the journal
//! shows only the user's own entries and the classic files are usually
//! unreadable; whatever could not be read is listed in the overview, never
//! passed off as a clean result.

pub mod analyze;
pub mod auth;
pub mod collect;
pub mod errors;
pub mod health;
pub mod journal;
pub mod kernel;
pub mod text;

use crate::core::context::Context;
use crate::core::error::ModuleError;
use crate::models::{Category, Finding};

use super::Module;

pub struct LogsModule;

impl Module for LogsModule {
    fn id(&self) -> &'static str {
        "logs"
    }

    fn category(&self) -> Category {
        Category::Logs
    }

    fn run(&self, ctx: &Context) -> Result<Vec<Finding>, ModuleError> {
        let data = collect::collect()?;
        Ok(analyze::analyze(&data, ctx))
    }
}
