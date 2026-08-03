//! Not part of the shipping tool. Renders the TUI headlessly via
//! ratatui's `TestBackend` and prints the resulting screen buffer as
//! plain text, so the layout can be eyeballed without a real terminal.
//! Run with `cargo run --example demo_tui_snapshot`.

use linuxdoctor::core::context::Context;
use linuxdoctor::core::engine::{ModuleRunResult, Report};
use linuxdoctor::models::{Category, Confidence, Finding, Severity};
use linuxdoctor::modules::memory::analyze::analyze;
use linuxdoctor::modules::memory::collect::MemoryRawData;
use linuxdoctor::output::tui::{draw, TuiApp};

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
        mem_available_kb: 200_000,
        swap_total_kb: 4_194_300,
        swap_free_kb: 0,
        swappiness: 10,
    };
    let memory_findings = analyze(&critical_mem_data, &ctx);

    let cpu_finding = Finding::builder(
        "CPU001",
        "High Load Average",
        Category::Cpu,
        Severity::Warning,
        Confidence::strong_indication(80),
    )
    .evidence("load_1m", "9.4")
    .evidence("cpu_count", "8")
    .explanation("1-minute load average is well above the core count, suggesting CPU contention.")
    .recommendation("Check for runaway processes with `top` or `htop`.")
    .build();

    let report = Report {
        context: ctx,
        results: vec![
            ModuleRunResult {
                module_id: "memory",
                findings: memory_findings,
                error: None,
                skipped: false,
            },
            ModuleRunResult {
                module_id: "cpu",
                findings: vec![cpu_finding],
                error: None,
                skipped: false,
            },
            ModuleRunResult {
                module_id: "smart",
                findings: vec![],
                error: Some("smartctl not found in PATH".to_string()),
                skipped: false,
            },
        ],
    };

    let mut app = TuiApp::new(&report);
    let backend = TestBackend::new(100, 32);
    let mut terminal = Terminal::new(backend).unwrap();
    terminal.draw(|f| draw(f, &mut app)).unwrap();

    print_buffer(&terminal);

    println!("\n--- pressing Down to select 'cpu' ---\n");
    app.next();
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
