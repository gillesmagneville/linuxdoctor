// SPDX-License-Identifier: GPL-3.0-only

/// The version of this build, as `linuxdoctor --version` prints it. Every
/// place that tells a reader which version produced what they are looking
/// at -- the reports, the interactive UI, the comparison -- uses this one
/// constant.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

pub mod core;
pub mod diff;
pub mod models;
pub mod modules;
pub mod output;
