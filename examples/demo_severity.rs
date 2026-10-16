// SPDX-License-Identifier: GPL-3.0-only

//! Not part of the shipping tool — a throwaway example to eyeball the
//! terminal renderer against synthetic low-memory data, since a healthy
//! sandbox container won't naturally produce WARNING/ERROR/CRITICAL
//! findings. Run with `cargo run --example demo_severity`.

use linuxdoctor::core::context::Context;
use linuxdoctor::core::engine::{ModuleRunResult, Report};
use linuxdoctor::modules::memory::analyze::analyze;
use linuxdoctor::modules::memory::collect::MemoryRawData;
use linuxdoctor::output::terminal;

fn main() {
    let ctx = Context {
        hostname: "prod-web-03".into(),
        kernel_version: "6.8.0-31-generic".into(),
        distro: Some("Ubuntu 24.04.4 LTS".into()),
        architecture: "x86_64".into(),
        cpu_count: 8,
        mem_total_kb: 16_384_000,
        boot_time_unix: 0,
    };

    let critical_data = MemoryRawData {
        mem_total_kb: 16_384_000,
        mem_free_kb: 150_000,
        mem_available_kb: 200_000, // ~1.2% available
        cached_kb: 50_000,
        shmem_kb: 300_000,
        dirty_kb: 20_000,
        swap_total_kb: 4_194_300,
        swap_free_kb: 0, // swap exhausted
        swappiness: 10,
        dirty_ratio: 20,
        dirty_background_ratio: 10,
        ..Default::default()
    };

    let findings = analyze(&critical_data, &ctx);
    let report = Report {
        profile: None,
        context: ctx,
        results: vec![ModuleRunResult {
            module_id: "memory",
            findings,
            error: None,
            skipped: false,
            notes: Vec::new(),
        }],
    };

    print!("{}", terminal::render(&report));
}
