// SPDX-License-Identifier: GPL-3.0-only

//! Interactive terminal UI. Consumes the same `Report` that `terminal.rs`
//! and `json.rs` consume — only formats what the engine already produced,
//! per ARCHITECTURE.md "Output formatters never perform diagnostics".
//!
//! Modules whose findings include 2+ distinct `Finding.instance` values
//! (sockets, filesystems, NUMA nodes, failed units...) get a real,
//! navigable submenu: the module's top-level view shows only its global
//! findings (`instance: None`) plus a hint, and drilling in (Enter) shows
//! one instance's findings at a time. Modules with fewer than 2 instances
//! show everything flat, exactly as before this existed — drilling into
//! "the one thing" would just be friction for no benefit. This grouping
//! is driven entirely by `Finding.instance`, not by hardcoded knowledge
//! of which check IDs happen to be per-instance for which modules.
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
use ratatui::layout::{Constraint, Direction, Layout, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, List, ListItem, ListState, Paragraph, Wrap};
use ratatui::{Frame, Terminal};

use crate::core::engine::{ModuleRunResult, Report};
use crate::models::{Finding, Severity};

/// Minimum number of distinct sub-items before a module gets a real,
/// navigable submenu. Below this, everything is shown flat instead.
const MIN_ITEMS_FOR_SUBMENU: usize = 2;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Focus {
    Modules,
    Submenu,
}

pub struct TuiApp<'a> {
    report: &'a Report,
    module_state: ListState,
    submenu_state: ListState,
    focus: Focus,
    detail_scroll: u16,
}

impl<'a> TuiApp<'a> {
    pub fn new(report: &'a Report) -> Self {
        let mut module_state = ListState::default();
        if !report.results.is_empty() {
            module_state.select(Some(0));
        }
        Self {
            report,
            module_state,
            submenu_state: ListState::default(),
            focus: Focus::Modules,
            detail_scroll: 0,
        }
    }

    fn selected_module_index(&self) -> usize {
        self.module_state.selected().unwrap_or(0)
    }

    fn selected_module(&self) -> Option<&'a ModuleRunResult> {
        self.report.results.get(self.selected_module_index())
    }

    /// Distinct instance names for the currently selected module, in
    /// first-seen order. Empty if that module has no per-instance
    /// findings at all.
    fn submenu_items(&self) -> Vec<&'a str> {
        self.selected_module().map(submenu_items_for).unwrap_or_default()
    }

    fn has_submenu(&self) -> bool {
        self.submenu_items().len() >= MIN_ITEMS_FOR_SUBMENU
    }

    fn selected_submenu_index(&self) -> usize {
        self.submenu_state.selected().unwrap_or(0)
    }

    /// Select the next module, wrapping around. `pub` so it's callable
    /// from tests/examples without a real terminal driving key events.
    pub fn next(&mut self) {
        if self.report.results.is_empty() {
            return;
        }
        let i = (self.selected_module_index() + 1) % self.report.results.len();
        self.module_state.select(Some(i));
        self.detail_scroll = 0;
    }

    /// Select the previous module, wrapping around.
    pub fn previous(&mut self) {
        if self.report.results.is_empty() {
            return;
        }
        let len = self.report.results.len();
        let i = (self.selected_module_index() + len - 1) % len;
        self.module_state.select(Some(i));
        self.detail_scroll = 0;
    }

    /// Select the next item within the current module's submenu.
    pub fn submenu_next(&mut self) {
        let len = self.submenu_items().len();
        if len == 0 {
            return;
        }
        let i = (self.selected_submenu_index() + 1) % len;
        self.submenu_state.select(Some(i));
        self.detail_scroll = 0;
    }

    /// Select the previous item within the current module's submenu.
    pub fn submenu_previous(&mut self) {
        let len = self.submenu_items().len();
        if len == 0 {
            return;
        }
        let i = (self.selected_submenu_index() + len - 1) % len;
        self.submenu_state.select(Some(i));
        self.detail_scroll = 0;
    }

    /// PgUp/PgDn dispatch to whichever list is currently focused: modules
    /// at the top level, submenu items once drilled in.
    pub fn page_next(&mut self) {
        match self.focus {
            Focus::Modules => self.next(),
            Focus::Submenu => self.submenu_next(),
        }
    }

    pub fn page_previous(&mut self) {
        match self.focus {
            Focus::Modules => self.previous(),
            Focus::Submenu => self.submenu_previous(),
        }
    }

    /// Enter: drill into the selected module's submenu, if it has one.
    /// No-op if the module has no submenu, or one is already open.
    pub fn drill_in(&mut self) {
        if self.focus == Focus::Modules && self.has_submenu() {
            self.focus = Focus::Submenu;
            self.submenu_state.select(Some(0));
            self.detail_scroll = 0;
        }
    }

    /// Esc: back out of a submenu. Returns `true` if it did so; `false`
    /// means focus was already at the top level, so the caller should
    /// treat this key press as "quit" instead.
    pub fn back_out(&mut self) -> bool {
        if self.focus == Focus::Submenu {
            self.focus = Focus::Modules;
            self.detail_scroll = 0;
            true
        } else {
            false
        }
    }

    /// Fine, line-by-line scroll — bound to the arrow keys, which
    /// conventionally scroll one line at a time (unlike PgUp/PgDn, which
    /// navigate lists here rather than scrolling at all).
    pub fn scroll_down(&mut self) {
        self.detail_scroll = self.detail_scroll.saturating_add(1);
    }

    pub fn scroll_up(&mut self) {
        self.detail_scroll = self.detail_scroll.saturating_sub(1);
    }
}

/// Distinct instance names for a module's findings, in first-seen order.
/// A free function (not a `TuiApp` method) so `draw_module_list` can call
/// it per-row to show a submenu indicator, without going through "the
/// currently selected" module.
fn submenu_items_for(result: &ModuleRunResult) -> Vec<&str> {
    let mut seen: Vec<&str> = Vec::new();
    for f in &result.findings {
        if let Some(name) = f.instance.as_deref() {
            if !seen.contains(&name) {
                seen.push(name);
            }
        }
    }
    seen
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

    draw_left_pane(f, app, body[0]);
    draw_detail_pane(f, app, body[1]);

    let help = Paragraph::new(help_text(app)).style(Style::default().fg(Color::DarkGray));
    f.render_widget(help, outer[2]);
}

fn help_text(app: &TuiApp) -> &'static str {
    match app.focus {
        Focus::Modules if app.has_submenu() => {
            " PgUp/PgDn select module  \u{00b7}  Enter for detail  \u{00b7}  \u{2191}/\u{2193} scroll  \u{00b7}  q quit"
        }
        Focus::Modules => " PgUp/PgDn select module  \u{00b7}  \u{2191}/\u{2193} scroll  \u{00b7}  q quit",
        Focus::Submenu => {
            " PgUp/PgDn select item  \u{00b7}  Esc back  \u{00b7}  \u{2191}/\u{2193} scroll  \u{00b7}  q quit"
        }
    }
}

fn draw_header(f: &mut Frame, app: &TuiApp, area: Rect) {
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

fn draw_left_pane(f: &mut Frame, app: &mut TuiApp, area: Rect) {
    match app.focus {
        Focus::Modules => draw_module_list(f, app, area),
        Focus::Submenu => draw_submenu_list(f, app, area),
    }
}

fn draw_module_list(f: &mut Frame, app: &mut TuiApp, area: Rect) {
    let items: Vec<ListItem> = app
        .report
        .results
        .iter()
        .map(|r| {
            let (symbol, color) = module_status(r);
            let has_submenu = submenu_items_for(r).len() >= MIN_ITEMS_FOR_SUBMENU;
            let suffix = if has_submenu { " \u{203a}" } else { "" };
            ListItem::new(Line::from(vec![
                Span::styled(format!("{symbol} "), Style::default().fg(color)),
                Span::raw(format!("{}{suffix}", r.module_id)),
            ]))
        })
        .collect();

    let list = List::new(items)
        .block(Block::default().borders(Borders::ALL).title("Modules"))
        .highlight_style(Style::default().add_modifier(Modifier::REVERSED));

    f.render_stateful_widget(list, area, &mut app.module_state);
}

fn draw_submenu_list(f: &mut Frame, app: &mut TuiApp, area: Rect) {
    let module_id = app.selected_module().map(|r| r.module_id).unwrap_or("?");
    let items: Vec<ListItem> = app
        .submenu_items()
        .iter()
        .map(|name| ListItem::new(Line::from(Span::raw(*name))))
        .collect();

    let list = List::new(items)
        .block(Block::default().borders(Borders::ALL).title(module_id))
        .highlight_style(Style::default().add_modifier(Modifier::REVERSED));

    f.render_stateful_widget(list, area, &mut app.submenu_state);
}

fn draw_detail_pane(f: &mut Frame, app: &TuiApp, area: Rect) {
    let Some(result) = app.selected_module() else {
        let detail = Paragraph::new("No modules ran.")
            .block(Block::default().borders(Borders::ALL).title("no module"));
        f.render_widget(detail, area);
        return;
    };

    if result.skipped {
        let detail = Paragraph::new("Skipped: not applicable to this system.")
            .block(Block::default().borders(Borders::ALL).title(result.module_id));
        f.render_widget(detail, area);
        return;
    }
    if let Some(err) = &result.error {
        let detail = Paragraph::new(Line::from(Span::styled(
            format!("Error: {err}"),
            Style::default().fg(Color::Red),
        )))
        .block(Block::default().borders(Borders::ALL).title(result.module_id));
        f.render_widget(detail, area);
        return;
    }

    let items = app.submenu_items();
    let (title, lines) = if items.len() >= MIN_ITEMS_FOR_SUBMENU {
        match app.focus {
            Focus::Modules => {
                let mut lines =
                    render_findings(result.findings.iter().filter(|f| f.instance.is_none()));
                lines.push(Line::from(Span::styled(
                    format!(
                        "\u{25b8} {} item{} \u{2014} press Enter for detail",
                        items.len(),
                        if items.len() == 1 { "" } else { "s" },
                    ),
                    Style::default()
                        .add_modifier(Modifier::BOLD)
                        .fg(Color::Cyan),
                )));
                (result.module_id.to_string(), lines)
            }
            Focus::Submenu => {
                let selected_name = items
                    .get(app.selected_submenu_index())
                    .copied()
                    .unwrap_or("");
                let lines = render_findings(
                    result
                        .findings
                        .iter()
                        .filter(|f| f.instance.as_deref() == Some(selected_name)),
                );
                (
                    format!("{} \u{203a} {selected_name}", result.module_id),
                    lines,
                )
            }
        }
    } else {
        (
            result.module_id.to_string(),
            render_findings(result.findings.iter()),
        )
    };

    let detail = Paragraph::new(lines)
        .block(Block::default().borders(Borders::ALL).title(title))
        .wrap(Wrap { trim: false })
        .scroll((app.detail_scroll, 0));

    f.render_widget(detail, area);
}

fn render_findings<'f>(findings: impl Iterator<Item = &'f Finding>) -> Vec<Line<'static>> {
    let mut lines = Vec::new();
    let mut any = false;

    for f in findings {
        any = true;
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

    if !any {
        return vec![Line::from("No findings here.")];
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
                        KeyCode::Char('q') => break,
                        KeyCode::Esc => {
                            if !app.back_out() {
                                break;
                            }
                        }
                        KeyCode::Enter => app.drill_in(),
                        KeyCode::PageDown => app.page_next(),
                        KeyCode::PageUp => app.page_previous(),
                        KeyCode::Down | KeyCode::Char('j') => app.scroll_down(),
                        KeyCode::Up | KeyCode::Char('k') => app.scroll_up(),
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

    fn ctx() -> Context {
        Context {
            hostname: "test-host".into(),
            kernel_version: "6.8.0-test".into(),
            distro: Some("Test Linux".into()),
            architecture: "x86_64".into(),
            cpu_count: 4,
            mem_total_kb: 16_384_000,
            boot_time_unix: 0,
        }
    }

    fn flat_report() -> Report {
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
            context: ctx(),
            results: vec![ModuleRunResult {
                module_id: "memory",
                findings: vec![finding],
                error: None,
                skipped: false,
            }],
        }
    }

    /// A module with 3 filesystems -- exercises the submenu path.
    fn report_with_submenu() -> Report {
        let global = Finding::builder(
            "CPU001",
            "CPU Overview",
            Category::Cpu,
            Severity::Info,
            Confidence::direct_observation(),
        )
        .evidence("sockets", "2")
        .explanation("This machine has 2 sockets.")
        .build();

        let socket0 = Finding::builder(
            "CPU004",
            "Socket Detail \u{2014} socket 0",
            Category::Cpu,
            Severity::Info,
            Confidence::direct_observation(),
        )
        .instance("socket 0")
        .explanation("Socket 0 detail.")
        .build();

        let socket1 = Finding::builder(
            "CPU004",
            "Socket Detail \u{2014} socket 1",
            Category::Cpu,
            Severity::Warning,
            Confidence::direct_observation(),
        )
        .instance("socket 1")
        .explanation("Socket 1 detail, something's off.")
        .build();

        Report {
            context: ctx(),
            results: vec![ModuleRunResult {
                module_id: "cpu",
                findings: vec![global, socket0, socket1],
                error: None,
                skipped: false,
            }],
        }
    }

    #[test]
    fn draws_without_panicking_and_shows_module_and_finding() {
        let report = flat_report();
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
        let report = flat_report();
        let mut app = TuiApp::new(&report);
        assert_eq!(app.selected_module_index(), 0);
        app.next(); // only one module, should wrap back to 0
        assert_eq!(app.selected_module_index(), 0);
        app.previous();
        assert_eq!(app.selected_module_index(), 0);
    }

    #[test]
    fn single_instance_module_has_no_submenu() {
        // flat_report()'s one finding has no .instance() set at all.
        let report = flat_report();
        let app = TuiApp::new(&report);
        assert!(!app.has_submenu());
    }

    #[test]
    fn two_instance_module_has_submenu() {
        let report = report_with_submenu();
        let app = TuiApp::new(&report);
        assert!(app.has_submenu());
        assert_eq!(app.submenu_items(), vec!["socket 0", "socket 1"]);
    }

    #[test]
    fn drill_in_only_works_when_submenu_exists() {
        let report = flat_report();
        let mut app = TuiApp::new(&report);
        app.drill_in();
        assert_eq!(app.focus, Focus::Modules, "no submenu here, drill_in should no-op");

        let report2 = report_with_submenu();
        let mut app2 = TuiApp::new(&report2);
        app2.drill_in();
        assert_eq!(app2.focus, Focus::Submenu);
        assert_eq!(app2.selected_submenu_index(), 0);
    }

    #[test]
    fn back_out_returns_false_at_top_level() {
        let report = report_with_submenu();
        let mut app = TuiApp::new(&report);
        assert!(!app.back_out(), "already at top level, nothing to back out of");
        app.drill_in();
        assert!(app.back_out(), "should back out of the submenu");
        assert_eq!(app.focus, Focus::Modules);
    }

    #[test]
    fn page_next_dispatches_to_submenu_once_drilled_in() {
        let report = report_with_submenu();
        let mut app = TuiApp::new(&report);
        app.drill_in();
        assert_eq!(app.selected_submenu_index(), 0);
        app.page_next();
        assert_eq!(app.selected_submenu_index(), 1);
        app.page_next(); // wraps
        assert_eq!(app.selected_submenu_index(), 0);
    }

    #[test]
    fn module_level_view_shows_only_global_findings_plus_hint() {
        let report = report_with_submenu();
        let mut app = TuiApp::new(&report);
        let backend = TestBackend::new(100, 30);
        let mut terminal = Terminal::new(backend).unwrap();

        terminal.draw(|f| draw(f, &mut app)).unwrap();
        let content: String = terminal
            .backend()
            .buffer()
            .content()
            .iter()
            .map(|c| c.symbol())
            .collect();

        assert!(content.contains("CPU001"));
        assert!(content.contains("2 items"));
        // Per-socket detail should NOT be visible at the module level.
        assert!(!content.contains("CPU004"));
    }

    #[test]
    fn submenu_view_shows_only_selected_instance_findings() {
        let report = report_with_submenu();
        let mut app = TuiApp::new(&report);
        app.drill_in();
        app.submenu_next(); // move to "socket 1"

        let backend = TestBackend::new(100, 30);
        let mut terminal = Terminal::new(backend).unwrap();
        terminal.draw(|f| draw(f, &mut app)).unwrap();
        let content: String = terminal
            .backend()
            .buffer()
            .content()
            .iter()
            .map(|c| c.symbol())
            .collect();

        assert!(content.contains("CPU004"));
        assert!(content.contains("socket 1"));
        assert!(content.contains("something's off"));
        // socket 0's specific content shouldn't appear on this screen.
        assert!(!content.contains("Socket 0 detail"));
        // The global overview also shouldn't repeat inside the submenu view.
        assert!(!content.contains("CPU001"));
    }
}
