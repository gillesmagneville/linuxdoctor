//! Interactive terminal UI. Consumes the same `Report` that `terminal.rs`
//! and `json.rs` consume — only formats what the engine already produced,
//! per ARCHITECTURE.md "Output formatters never perform diagnostics".
//!
//! `draw()` is a pure function of `(Frame, &TuiApp)` with no dependency on
//! a real terminal, so it's testable via ratatui's `TestBackend` — see the
//! `demo_tui_snapshot` example, which renders headlessly and prints the
//! result as text. `run()` is the thin wrapper that wires it to a real
//! terminal (crossterm, raw mode, alternate screen) and the event loop.

use std::io;
use std::time::Duration;

use crossterm::event::{self, Event, KeyCode, KeyEventKind};
use crossterm::execute;
use crossterm::terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen};
use ratatui::backend::{Backend, CrosstermBackend};
use ratatui::layout::{Constraint, Direction, Layout};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, List, ListItem, ListState, Paragraph, Wrap};
use ratatui::{Frame, Terminal};

use crate::core::engine::{ModuleRunResult, Report};
use crate::models::{Finding, Severity};

pub struct TuiApp<'a> {
    report: &'a Report,
    list_state: ListState,
    detail_scroll: u16,
}

impl<'a> TuiApp<'a> {
    pub fn new(report: &'a Report) -> Self {
        let mut list_state = ListState::default();
        if !report.results.is_empty() {
            list_state.select(Some(0));
        }
        Self {
            report,
            list_state,
            detail_scroll: 0,
        }
    }

    fn selected(&self) -> usize {
        self.list_state.selected().unwrap_or(0)
    }

    /// Select the next module, wrapping around. `pub` so it's callable
    /// from tests/examples without a real terminal driving key events.
    pub fn next(&mut self) {
        if self.report.results.is_empty() {
            return;
        }
        let i = (self.selected() + 1) % self.report.results.len();
        self.list_state.select(Some(i));
        self.detail_scroll = 0;
    }

    /// Select the previous module, wrapping around.
    pub fn previous(&mut self) {
        if self.report.results.is_empty() {
            return;
        }
        let len = self.report.results.len();
        let i = (self.selected() + len - 1) % len;
        self.list_state.select(Some(i));
        self.detail_scroll = 0;
    }

    pub fn scroll_down(&mut self) {
        self.detail_scroll = self.detail_scroll.saturating_add(5);
    }

    pub fn scroll_up(&mut self) {
        self.detail_scroll = self.detail_scroll.saturating_sub(5);
    }
}

fn severity_color(sev: Severity) -> Color {
    match sev {
        Severity::Info => Color::Green,
        Severity::Warning => Color::Yellow,
        Severity::Error => Color::Red,
        Severity::Critical => Color::LightRed,
    }
}

fn module_status(result: &ModuleRunResult) -> (&'static str, Color) {
    if result.skipped {
        return ("-", Color::DarkGray);
    }
    if result.error.is_some() {
        return (Severity::Error.symbol(), Color::Red);
    }
    match result.findings.iter().map(|f| f.severity).max() {
        Some(sev) if sev > Severity::Info => (sev.symbol(), severity_color(sev)),
        _ => (Severity::Info.symbol(), severity_color(Severity::Info)),
    }
}

/// Pure rendering function: no I/O, no terminal access. Takes `&mut
/// TuiApp` only because `ListState` requires `&mut` to render selection —
/// it never mutates report data.
pub fn draw(f: &mut Frame, app: &mut TuiApp) {
    let area = f.size();
    let outer = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3),
            Constraint::Min(0),
            Constraint::Length(1),
        ])
        .split(area);

    draw_header(f, app, outer[0]);

    let body = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(28), Constraint::Percentage(72)])
        .split(outer[1]);

    draw_module_list(f, app, body[0]);
    draw_detail_pane(f, app, body[1]);

    let help = Paragraph::new(" \u{2191}/\u{2193} select module  \u{00b7}  PgUp/PgDn scroll  \u{00b7}  q quit")
        .style(Style::default().fg(Color::DarkGray));
    f.render_widget(help, outer[2]);
}

fn draw_header(f: &mut Frame, app: &TuiApp, area: ratatui::layout::Rect) {
    let ctx = &app.report.context;
    let text = vec![Line::from(vec![
        Span::styled("LinuxDoctor", Style::default().add_modifier(Modifier::BOLD)),
        Span::raw(format!(
            " \u{2014} {}  |  kernel {} \u{00b7} {} \u{00b7} {} CPUs \u{00b7} {} MB RAM",
            ctx.hostname,
            ctx.kernel_version,
            ctx.distro.as_deref().unwrap_or("unknown distro"),
            ctx.cpu_count,
            ctx.mem_total_kb / 1024,
        )),
    ])];
    let header = Paragraph::new(text).block(Block::default().borders(Borders::ALL));
    f.render_widget(header, area);
}

fn draw_module_list(f: &mut Frame, app: &mut TuiApp, area: ratatui::layout::Rect) {
    let items: Vec<ListItem> = app
        .report
        .results
        .iter()
        .map(|r| {
            let (symbol, color) = module_status(r);
            ListItem::new(Line::from(vec![
                Span::styled(format!("{symbol} "), Style::default().fg(color)),
                Span::raw(r.module_id),
            ]))
        })
        .collect();

    let list = List::new(items)
        .block(Block::default().borders(Borders::ALL).title("Modules"))
        .highlight_style(Style::default().add_modifier(Modifier::REVERSED));

    f.render_stateful_widget(list, area, &mut app.list_state);
}

fn draw_detail_pane(f: &mut Frame, app: &TuiApp, area: ratatui::layout::Rect) {
    let title = app
        .report
        .results
        .get(app.selected())
        .map(|r| r.module_id)
        .unwrap_or("no module");

    let lines = match app.report.results.get(app.selected()) {
        None => vec![Line::from("No modules ran.")],
        Some(r) if r.skipped => vec![Line::from("Skipped: not applicable to this system.")],
        Some(r) if r.error.is_some() => vec![Line::from(Span::styled(
            format!("Error: {}", r.error.as_deref().unwrap_or("unknown error")),
            Style::default().fg(Color::Red),
        ))],
        Some(r) => render_findings(&r.findings),
    };

    let detail = Paragraph::new(lines)
        .block(Block::default().borders(Borders::ALL).title(title))
        .wrap(Wrap { trim: false })
        .scroll((app.detail_scroll, 0));

    f.render_widget(detail, area);
}

fn render_findings(findings: &[Finding]) -> Vec<Line<'static>> {
    if findings.is_empty() {
        return vec![Line::from("No findings for this module.")];
    }

    let mut lines = Vec::new();
    for f in findings {
        lines.push(Line::from(Span::styled(
            format!("{} \u{2014} {}", f.id, f.title),
            Style::default().add_modifier(Modifier::BOLD),
        )));
        lines.push(Line::from(vec![
            Span::styled(
                f.severity.to_string(),
                Style::default().fg(severity_color(f.severity)),
            ),
            Span::raw(format!(
                "  \u{00b7} Confidence: {}% ({})",
                f.confidence.percent, f.confidence.reason
            )),
        ]));
        lines.push(Line::from(""));

        if !f.evidence.is_empty() {
            lines.push(Line::from(Span::styled(
                "Evidence",
                Style::default().add_modifier(Modifier::UNDERLINED),
            )));
            for (k, v) in &f.evidence {
                lines.push(Line::from(format!("  {k}: {v}")));
            }
            lines.push(Line::from(""));
        }

        if !f.explanation.is_empty() {
            lines.push(Line::from(f.explanation.clone()));
            lines.push(Line::from(""));
        }

        if let Some(rec) = &f.recommendation {
            lines.push(Line::from(Span::styled(
                format!("Recommendation: {rec}"),
                Style::default().fg(Color::DarkGray),
            )));
            lines.push(Line::from(""));
        }

        lines.push(Line::from("\u{2500}".repeat(60)));
        lines.push(Line::from(""));
    }
    lines
}

/// Wires `draw()` to a real terminal (crossterm, raw mode, alternate
/// screen) and runs the event loop until the user quits. Kept separate
/// from `draw()` on purpose so the rendering logic stays testable without
/// a real TTY.
pub fn run(report: &Report) -> io::Result<()> {
    enable_raw_mode()?;
    let mut stdout = io::stdout();
    execute!(stdout, EnterAlternateScreen)?;
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend)?;

    let mut app = TuiApp::new(report);
    let result = event_loop(&mut terminal, &mut app);

    disable_raw_mode()?;
    execute!(terminal.backend_mut(), LeaveAlternateScreen)?;
    terminal.show_cursor()?;

    result
}

fn event_loop<B: Backend>(terminal: &mut Terminal<B>, app: &mut TuiApp) -> io::Result<()> {
    loop {
        terminal.draw(|f| draw(f, app))?;

        if event::poll(Duration::from_millis(250))? {
            if let Event::Key(key) = event::read()? {
                if key.kind == KeyEventKind::Press {
                    match key.code {
                        KeyCode::Char('q') | KeyCode::Esc => break,
                        KeyCode::Down | KeyCode::Char('j') => app.next(),
                        KeyCode::Up | KeyCode::Char('k') => app.previous(),
                        KeyCode::PageDown => app.scroll_down(),
                        KeyCode::PageUp => app.scroll_up(),
                        _ => {}
                    }
                }
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::context::Context;
    use crate::models::{Category, Confidence};
    use ratatui::backend::TestBackend;

    fn sample_report() -> Report {
        let context = Context {
            hostname: "test-host".into(),
            kernel_version: "6.8.0-test".into(),
            distro: Some("Test Linux".into()),
            architecture: "x86_64".into(),
            cpu_count: 4,
            mem_total_kb: 16_384_000,
            boot_time_unix: 0,
        };
        let finding = Finding::builder(
            "MEM002",
            "Swap Activity",
            Category::Memory,
            Severity::Warning,
            Confidence::strong_indication(85),
        )
        .evidence("swap_used_kb", "4194300")
        .explanation("Swapping while memory is tight.")
        .build();

        Report {
            context,
            results: vec![ModuleRunResult {
                module_id: "memory",
                findings: vec![finding],
                error: None,
                skipped: false,
            }],
        }
    }

    #[test]
    fn draws_without_panicking_and_shows_module_and_finding() {
        let report = sample_report();
        let mut app = TuiApp::new(&report);
        let backend = TestBackend::new(80, 20);
        let mut terminal = Terminal::new(backend).unwrap();

        terminal.draw(|f| draw(f, &mut app)).unwrap();

        let content: String = terminal
            .backend()
            .buffer()
            .content()
            .iter()
            .map(|c| c.symbol())
            .collect();

        assert!(content.contains("memory"));
        assert!(content.contains("MEM002"));
        assert!(content.contains("test-host"));
    }

    #[test]
    fn navigation_wraps_around() {
        let report = sample_report();
        let mut app = TuiApp::new(&report);
        assert_eq!(app.selected(), 0);
        app.next(); // only one module, should wrap back to 0
        assert_eq!(app.selected(), 0);
        app.previous();
        assert_eq!(app.selected(), 0);
    }
}
