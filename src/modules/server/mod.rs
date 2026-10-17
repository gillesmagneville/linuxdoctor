// SPDX-License-Identifier: GPL-3.0-only

//! The checks that only make sense on a server (`--profile server`).
//!
//! Like the `hpc` module, this one is not part of every audit: it is added by
//! the profile (see [`crate::profile::Profile::modules`]). What it looks at is
//! a question for a machine nobody sits at, and a finding "this desktop does
//! not update itself unattended" would be noise: a desktop shows its updates
//! to the person using it. A profile can only lower the severity of an
//! existing finding, so a check that is wrong on one kind of machine and right
//! on another has to live in a module of its own.
//!
//! * `SRV001`: whether security updates are installed without anyone asking
//!   ([`analyze`], [`collect`]).
//! * `SRV002`: whether the logs survive a reboot ([`journal`]).
//! * `SRV003`: whether a reboot has been waiting for days ([`reboot`]).
//! * `SRV004`: the package updates that are waiting ([`pending`]).
//! * `SRV005`: whether a newer kernel is installed than the one running
//!   ([`kernel`]).

pub mod age;
pub mod analyze;
pub mod collect;
pub mod journal;
pub mod kernel;
pub mod pending;
pub mod reboot;

use crate::core::context::Context;
use crate::core::error::ModuleError;
use crate::models::{Category, Finding};
use crate::modules::recommend::family_of;

use super::Module;

pub struct ServerModule;

impl Module for ServerModule {
    fn id(&self) -> &'static str {
        "server"
    }

    fn category(&self) -> Category {
        Category::Security
    }

    fn run(&self, ctx: &Context) -> Result<Vec<Finding>, ModuleError> {
        let data = collect::collect(family_of(ctx.distro.as_deref()))?;
        Ok(analyze::analyze(&data, ctx))
    }
}
