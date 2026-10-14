// SPDX-License-Identifier: GPL-3.0-only

//! Security: what is exposed to the network, whether something stands in
//! front of it, how the SSH server is set up, whether the system confines
//! its programs, which kernel settings weaken it, and the state of the
//! accounts and files that protect it.
//!
//! Strictly read-only, and usable without root (root only adds visibility;
//! each finding says what it could not see).

pub mod access;
pub mod accounts;
pub mod analyze;
pub mod collect;
pub mod firewall;
pub mod listeners;
pub mod ssh;

use crate::core::context::Context;
use crate::core::error::ModuleError;
use crate::models::{Category, Finding};

use super::Module;

pub struct SecurityModule;

impl Module for SecurityModule {
    fn id(&self) -> &'static str {
        "security"
    }

    fn category(&self) -> Category {
        Category::Security
    }

    fn run(&self, ctx: &Context) -> Result<Vec<Finding>, ModuleError> {
        let data = collect::collect()?;
        Ok(analyze::analyze(&data, ctx))
    }
}
