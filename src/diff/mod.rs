// SPDX-License-Identifier: GPL-3.0-only

//! `linuxdoctor diff`: what changed between two JSON reports.
//!
//! * [`report`] reads a report file (`audit --output json`) leniently: keys it
//!   does not know are ignored, as the report format's contract promises.
//! * [`compare`] is pure: two parsed reports in, a [`compare::Comparison`]
//!   out. It is where the one rule that matters lives -- a finding that is
//!   missing from a report only counts as *resolved* when the module that
//!   would have reported it really ran and finished; otherwise it is
//!   *not compared*, never a quiet good news.
//! * [`render`] turns a comparison into terminal text, Markdown or JSON.
//!
//! See ARCHITECTURE.md "Report Diff".

pub mod compare;
pub mod render;
pub mod report;
