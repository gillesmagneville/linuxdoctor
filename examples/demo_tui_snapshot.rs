// SPDX-License-Identifier: GPL-3.0-only

//! Not part of the shipping tool. Renders the TUI headlessly via
//! ratatui's `TestBackend` and prints the resulting screen buffer as
//! plain text, so the layout can be eyeballed without a real terminal.
//! Run with `cargo run --example demo_tui_snapshot`.

use linuxdoctor::core::context::Context;
use linuxdoctor::core::engine::{ModuleRunResult, Report};
use linuxdoctor::modules::cpu::analyze::analyze as analyze_cpu;
use linuxdoctor::modules::cpu::collect::{CpuRawData, CpuSocket};
use linuxdoctor::modules::memory::analyze::analyze as analyze_memory;
use linuxdoctor::modules::memory::collect::MemoryRawData;
use linuxdoctor::modules::storage::analyze::analyze as analyze_storage;
use linuxdoctor::modules::storage::collect::{DiskHealth, StorageRawData};
use linuxdoctor::output::tui::{draw, draw_progress_screen, TuiApp};

use ratatui::backend::TestBackend;
use ratatui::Terminal;

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

    let critical_mem_data = MemoryRawData {
        mem_total_kb: 16_384_000,
        mem_free_kb: 150_000,
        mem_available_kb: 200_000,
        cached_kb: 50_000,
        shmem_kb: 300_000,
        dirty_kb: 20_000,
        swap_total_kb: 4_194_300,
        swap_free_kb: 0,
        swappiness: 10,
        dirty_ratio: 20,
        dirty_background_ratio: 10,
        ..Default::default()
    };
    let memory_findings = analyze_memory(&critical_mem_data, &ctx);

    // Real CPU module, fed a synthetic dual-socket + isolated-CPU fixture
    // instead of this sandbox's actual single-CPU idle load — same real
    // analyze() logic that ships in the tool, exercised against a richer
    // topology to show off the per-socket and isolated-CPU findings.
    let overloaded_cpu_data = CpuRawData {
        load_1m: 18.4,
        load_5m: 16.1,
        load_15m: 14.7,
        sockets: vec![
            CpuSocket {
                physical_id: 0,
                model_name: Some("Intel(R) Xeon(R) Processor @ 2.10GHz".to_string()),
                cores: 8,
                threads: 16,
                logical_cpus: (0..16).collect(),
            },
            CpuSocket {
                physical_id: 1,
                model_name: Some("Intel(R) Xeon(R) Processor @ 2.10GHz".to_string()),
                cores: 8,
                threads: 16,
                logical_cpus: (16..32).collect(),
            },
        ],
        isolcpus: vec![0, 1, 16, 17],
        nohz_full: vec![],
        cgroup_isolated: vec![],
        system_slice_excluded: vec![],
        offline_cpus: vec![],
    };
    let cpu_findings = analyze_cpu(&overloaded_cpu_data, &ctx);

    // Real Storage module: one filesystem plus two synthetic disks (one
    // healthy, one failing) to show that filesystem-instances and
    // device-instances coexist correctly in the same submenu.
    let storage_data = StorageRawData {
        filesystems: vec![],
        inodes: vec![],
        smartctl_available: true,
        disks_checked: 2,
        disk_health: vec![
            DiskHealth {
                device: "/dev/sda".to_string(),
                model: Some("Samsung SSD 870 EVO 1TB".to_string()),
                device_type: Some("sat".to_string()),
                smart_passed: Some(true),
                temperature_celsius: Some(34),
                power_on_hours: Some(8760),
                reallocated_sectors: Some(0),
                pending_sectors: Some(0),
                uncorrectable_sectors: Some(0),
                nvme_critical_warning: None,
                nvme_percentage_used: None,
                nvme_media_errors: None,
            },
            DiskHealth {
                device: "/dev/sdb".to_string(),
                model: Some("WDC WD40EFRX-68N32N0".to_string()),
                device_type: Some("sat".to_string()),
                smart_passed: Some(true), // overall status still "passes"...
                temperature_celsius: Some(48),
                power_on_hours: Some(45000),
                reallocated_sectors: Some(87), // ...but attributes tell a different story
                pending_sectors: Some(12),
                uncorrectable_sectors: Some(3),
                nvme_critical_warning: None,
                nvme_percentage_used: None,
                nvme_media_errors: None,
            },
        ],
        running_as_root: true,
    };
    let storage_findings = analyze_storage(&storage_data, &ctx);

    let report = Report {
        context: ctx,
        results: vec![
            ModuleRunResult {
                module_id: "memory",
                findings: memory_findings,
                error: None,
                skipped: false,
                notes: Vec::new(),
            },
            ModuleRunResult {
                module_id: "cpu",
                findings: cpu_findings,
                error: None,
                skipped: false,
                notes: Vec::new(),
            },
            ModuleRunResult {
                module_id: "storage",
                findings: storage_findings,
                error: None,
                skipped: false,
                notes: Vec::new(),
            },
        ],
    };

    let mut app = TuiApp::new(report);
    app.refresh_live_stats();
    let backend = TestBackend::new(100, 32);
    let mut terminal = Terminal::new(backend).unwrap();

    println!("--- startup progress screen (mid-scan, module 3 of 9) ---\n");
    terminal
        .draw(|f| draw_progress_screen(f, 3, 9, &["storage", "virtualization"]))
        .unwrap();
    print_buffer(&terminal);

    terminal.draw(|f| draw(f, &mut app)).unwrap();

    println!("\n--- memory selected: header now shows live CPU/Mem/Disk gauges ---\n");
    print_buffer(&terminal);

    println!("\n--- PgDn to 'cpu' (2 sockets -- module view shows only the global overview + a hint) ---\n");
    app.next();
    terminal.draw(|f| draw(f, &mut app)).unwrap();
    print_buffer(&terminal);

    println!("\n--- Enter to drill in: socket 0's detail only ---\n");
    app.drill_in();
    terminal.draw(|f| draw(f, &mut app)).unwrap();
    print_buffer(&terminal);

    println!("\n--- PgDn within the submenu: socket 1's detail (isolated CPUs, distinct from socket 0) ---\n");
    app.page_next();
    terminal.draw(|f| draw(f, &mut app)).unwrap();
    print_buffer(&terminal);

    println!("\n--- Esc back, PgDn to 'storage', Enter: submenu lists both disks ---\n");
    app.back_out();
    app.next();
    app.drill_in();
    terminal.draw(|f| draw(f, &mut app)).unwrap();
    print_buffer(&terminal);

    println!("\n--- PgDn to /dev/sdb: overall status still passes, but attributes flag real concern ---\n");
    app.page_next();
    terminal.draw(|f| draw(f, &mut app)).unwrap();
    print_buffer(&terminal);

    println!("\n--- f: warnings and above only. Counts appear next to each module, the ones left with nothing are greyed, the bottom bar says the view is filtered ---\n");
    app.back_out();
    app.cycle_severity();
    terminal.draw(|f| draw(f, &mut app)).unwrap();
    print_buffer(&terminal);

    println!(
        "\n--- /sdb: typing a search (the screen jumps to the first module that matches) ---\n"
    );
    app.clear_filter();
    app.start_search();
    for c in "sdb".chars() {
        app.search_type(c);
    }
    terminal.draw(|f| draw(f, &mut app)).unwrap();
    print_buffer(&terminal);

    println!("\n--- Enter keeps the search as a filter; Esc would clear it ---\n");
    app.finish_search();
    terminal.draw(|f| draw(f, &mut app)).unwrap();
    print_buffer(&terminal);
}

fn print_buffer(terminal: &Terminal<TestBackend>) {
    let buffer = terminal.backend().buffer();
    let area = buffer.area;
    for y in 0..area.height {
        let mut line = String::new();
        for x in 0..area.width {
            line.push_str(buffer.get(x, y).symbol());
        }
        println!("{line}");
    }
}
