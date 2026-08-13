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
//! Two independent freshness stories, deliberately not conflated:
//! - The header's CPU/memory/disk gauges (`live_stats`) refresh on their
//!   own, roughly once a second, for as long as the TUI is open — cheap
//!   `/proc` reads plus one `df` call, nothing that touches the slower
//!   per-module collectors (SMART, virsh, docker...).
//! - The findings themselves (module list, detail pane) only change when
//!   the user presses `r`, which re-runs the full module pipeline behind
//!   the same progress screen shown at startup. Re-running that on every
//!   tick would be both wasteful and far too slow to feel "live".
//!
//! `draw()` is a pure function of `(Frame, &mut TuiApp)` with no
//! dependency on a real terminal, so it's testable via ratatui's
//! `TestBackend` — see the `demo_tui_snapshot` example, which renders
//! headlessly and prints the result as text. `run()` is the thin wrapper
//! that wires it to a real terminal (crossterm, raw mode, alternate
//! screen), the initial scan, and the event loop.

use std::io;
use std::time::{Duration, Instant};

use crossterm::event::{self, Event, KeyCode, KeyEventKind};
use crossterm::execute;
use crossterm::terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen};
use ratatui::backend::{Backend, CrosstermBackend};
use ratatui::layout::{Alignment, Constraint, Direction, Layout, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Gauge, List, ListItem, ListState, Paragraph, Wrap};
use ratatui::{Frame, Terminal};

use crate::core::engine::{run_audit_with_progress, ModuleRunResult, Report};
use crate::models::{Finding, Severity};
use crate::output::live_stats::{self, CpuStatSample, LiveStats};

/// Minimum number of distinct sub-items before a module gets a real,
/// navigable submenu. Below this, everything is shown flat instead.
const MIN_ITEMS_FOR_SUBMENU: usize = 2;

/// How often the header's CPU/memory/disk gauges refresh.
const LIVE_STATS_TICK: Duration = Duration::from_millis(1000);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Focus {
    Modules,
    Submenu,
}

pub struct TuiApp {
    report: Report,
    module_state: ListState,
    submenu_state: ListState,
    focus: Focus,
    detail_scroll: u16,
    live_stats: LiveStats,
    prev_cpu_sample: Option<CpuStatSample>,
    last_scan: Instant,
}

impl TuiApp {
    pub fn new(report: Report) -> Self {
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
            live_stats: LiveStats::default(),
            prev_cpu_sample: None,
            last_scan: Instant::now(),
        }
    }

    /// Take a fresh reading of the header's CPU/memory/disk gauges. Cheap
    /// enough to call roughly once a second for as long as the TUI is
    /// open — see the module doc comment for why this is kept entirely
    /// separate from re-running the module pipeline.
    pub fn refresh_live_stats(&mut self) {
        let (stats, sample) = live_stats::refresh(self.prev_cpu_sample);
        self.live_stats = stats;
        self.prev_cpu_sample = sample;
    }

    /// Swap in a freshly re-scanned `Report` (the `r` keybinding). Keeps
    /// the same module selected across the refresh when it still exists
    /// in the new report, and otherwise falls back to the first module —
    /// re-running the same `--modules` filter means the set of modules
    /// normally won't change, but this stays correct even if it did.
    pub fn replace_report(&mut self, new_report: Report) {
        let selected_id = self.selected_module().map(|r| r.module_id);
        self.report = new_report;

        let new_index = selected_id.and_then(|id| {
            self.report.results.iter().position(|r| r.module_id == id)
        });
        if self.report.results.is_empty() {
            self.module_state.select(None);
        } else {
            self.module_state.select(Some(new_index.unwrap_or(0)));
        }
        self.submenu_state = ListState::default();
        self.focus = Focus::Modules;
        self.detail_scroll = 0;
        self.last_scan = Instant::now();
    }

    fn selected_module_index(&self) -> usize {
        self.module_state.selected().unwrap_or(0)
    }

    fn selected_module(&self) -> Option<&ModuleRunResult> {
        self.report.results.get(self.selected_module_index())
    }

    /// Distinct instance names for the currently selected module, in
    /// first-seen order, as owned `String`s. Empty if that module has no
    /// per-instance findings at all. Owned (not borrowed from `report`)
    /// specifically so callers can hold onto the result while separately
    /// taking `&mut self.submenu_state` — see ARCHITECTURE.md's note on
    /// this in the TUI section for why that matters.
    fn submenu_items(&self) -> Vec<String> {
        self.selected_module()
            .map(|r| submenu_items_for(r).into_iter().map(String::from).collect())
            .unwrap_or_default()
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

/// Green/yellow/red thresholds for the header's live gauges — a quick
/// at-a-glance signal, not a diagnostic verdict (no evidence, no
/// confidence score, no recommendation the way a real `Finding` has all
/// three). The module list's own severity-driven ✓/⚠/✗ symbols remain
/// the actual diagnostic read; this is just "does something need a
/// closer look".
fn stat_color(pct: f64) -> Color {
    if pct >= 90.0 {
        Color::Red
    } else if pct >= 70.0 {
        Color::Yellow
    } else {
        Color::Green
    }
}

fn format_age(d: Duration) -> String {
    let secs = d.as_secs();
    if secs < 60 {
        format!("{secs}s ago")
    } else {
        format!("{}m{}s ago", secs / 60, secs % 60)
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
            Constraint::Length(4),
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
            " PgUp/PgDn select module  \u{00b7}  Enter for detail  \u{00b7}  \u{2191}/\u{2193} scroll  \u{00b7}  r refresh  \u{00b7}  q quit"
        }
        Focus::Modules => {
            " PgUp/PgDn select module  \u{00b7}  \u{2191}/\u{2193} scroll  \u{00b7}  r refresh  \u{00b7}  q quit"
        }
        Focus::Submenu => {
            " PgUp/PgDn select item  \u{00b7}  Esc back  \u{00b7}  \u{2191}/\u{2193} scroll  \u{00b7}  r refresh  \u{00b7}  q quit"
        }
    }
}

fn draw_header(f: &mut Frame, app: &TuiApp, area: Rect) {
    let ctx = &app.report.context;
    let line1 = Line::from(vec![
        Span::styled("LinuxDoctor", Style::default().add_modifier(Modifier::BOLD)),
        Span::raw(format!(
            " \u{2014} {}  |  kernel {} \u{00b7} {} \u{00b7} {} CPUs \u{00b7} {} MB RAM",
            ctx.hostname,
            ctx.kernel_version,
            ctx.distro.as_deref().unwrap_or("unknown distro"),
            ctx.cpu_count,
            ctx.mem_total_kb / 1024,
        )),
    ]);

    let mut stats: Vec<Span> = Vec::new();
    match app.live_stats.cpu_percent {
        Some(pct) => {
            stats.push(Span::raw("CPU "));
            stats.push(Span::styled(
                format!("{pct:.1}%"),
                Style::default().fg(stat_color(pct)),
            ));
        }
        None => stats.push(Span::raw("CPU \u{2026}")),
    }
    stats.push(Span::raw("   "));
    match (
        app.live_stats.mem_percent,
        app.live_stats.mem_used_gb,
        app.live_stats.mem_total_gb,
    ) {
        (Some(pct), Some(used), Some(total)) => {
            stats.push(Span::raw("Mem "));
            stats.push(Span::styled(
                format!("{pct:.1}%"),
                Style::default().fg(stat_color(pct)),
            ));
            stats.push(Span::raw(format!(" ({used:.1}/{total:.1} GB)")));
        }
        _ => stats.push(Span::raw("Mem \u{2026}")),
    }
    stats.push(Span::raw("   "));
    match app.live_stats.disk_percent {
        Some(pct) => {
            stats.push(Span::raw("Disk / "));
            stats.push(Span::styled(
                format!("{pct:.1}%"),
                Style::default().fg(stat_color(pct)),
            ));
        }
        None => stats.push(Span::raw("Disk \u{2026}")),
    }
    stats.push(Span::styled(
        format!(
            "   findings from {} \u{00b7} press 'r' to refresh",
            format_age(app.last_scan.elapsed())
        ),
        Style::default().fg(Color::DarkGray),
    ));
    let line2 = Line::from(stats);

    let header =
        Paragraph::new(vec![line1, line2]).block(Block::default().borders(Borders::ALL));
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
        .into_iter()
        .map(|name| ListItem::new(Line::from(name)))
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
                    .cloned()
                    .unwrap_or_default();
                let lines = render_findings(
                    result
                        .findings
                        .iter()
                        .filter(|f| f.instance.as_deref() == Some(selected_name.as_str())),
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

/// The startup/refresh loading screen: a centered gauge that fills in as
/// each module completes, plus the name of whichever module is currently
/// running. Exists specifically so a scan with a slow module (SMART's
/// per-device `smartctl` calls, Virtualization's `virsh`/`docker` calls)
/// never looks like a frozen terminal.
pub fn draw_progress_screen(f: &mut Frame, index: usize, total: usize, current_module: &str) {
    let area = f.size();
    let vertical = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Percentage(40),
            Constraint::Length(3),
            Constraint::Percentage(40),
        ])
        .split(area);

    let title = Paragraph::new(Line::from(Span::styled(
        "LinuxDoctor",
        Style::default().add_modifier(Modifier::BOLD),
    )))
    .alignment(Alignment::Center);
    f.render_widget(title, vertical[0]);

    let ratio = if total == 0 {
        0.0
    } else {
        (index as f64 / total as f64).clamp(0.0, 1.0)
    };
    let label = if total == 0 {
        "No modules selected".to_string()
    } else if index >= total {
        "Finalizing\u{2026}".to_string()
    } else {
        format!("Scanning {current_module}\u{2026} ({}/{})", index + 1, total)
    };

    let gauge = Gauge::default()
        .block(Block::default().borders(Borders::ALL).title("Initializing"))
        .gauge_style(Style::default().fg(Color::Cyan))
        .ratio(ratio)
        .label(label);
    f.render_widget(gauge, vertical[1]);
}

/// Runs the module pipeline behind the progress screen, redrawing it as
/// each module completes. Used both for the initial scan in `run()` and
/// for the `r` refresh keybinding in the event loop — same screen either
/// time, since from the user's point of view it's the same operation.
fn run_scan_with_progress<B: Backend>(
    terminal: &mut Terminal<B>,
    selected_ids: Option<&[String]>,
) -> io::Result<Report> {
    run_audit_with_progress(selected_ids, |index, total, module_id| {
        let _ = terminal.draw(|f| draw_progress_screen(f, index, total, module_id));
    })
    .map_err(|e| io::Error::other(e.to_string()))
}

/// Wires `draw()` to a real terminal (crossterm, raw mode, alternate
/// screen), runs the initial scan behind the progress screen, then runs
/// the event loop until the user quits. Returns the final `Report`
/// (possibly refreshed since the initial scan, via `r`) so the caller can
/// compute an exit code from it the same way `audit` does. Kept separate
/// from `draw()` on purpose so the rendering logic stays testable without
/// a real TTY.
pub fn run(selected_ids: Option<&[String]>) -> io::Result<Report> {
    enable_raw_mode()?;
    let mut stdout = io::stdout();
    execute!(stdout, EnterAlternateScreen)?;
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend)?;

    let outcome = run_scan_with_progress(&mut terminal, selected_ids).and_then(|report| {
        let mut app = TuiApp::new(report);
        app.refresh_live_stats(); // populate immediately, not a full tick later
        event_loop(&mut terminal, &mut app, selected_ids).map(|()| app.report)
    });

    disable_raw_mode()?;
    execute!(terminal.backend_mut(), LeaveAlternateScreen)?;
    terminal.show_cursor()?;

    outcome
}

fn event_loop<B: Backend>(
    terminal: &mut Terminal<B>,
    app: &mut TuiApp,
    selected_ids: Option<&[String]>,
) -> io::Result<()> {
    let mut last_tick = Instant::now();

    loop {
        terminal.draw(|f| draw(f, app))?;

        let timeout = LIVE_STATS_TICK.saturating_sub(last_tick.elapsed());
        if event::poll(timeout)? {
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
                        KeyCode::Char('r') => {
                            let new_report = run_scan_with_progress(terminal, selected_ids)?;
                            app.replace_report(new_report);
                            app.refresh_live_stats();
                            last_tick = Instant::now();
                        }
                        _ => {}
                    }
                }
            }
        }

        if last_tick.elapsed() >= LIVE_STATS_TICK {
            app.refresh_live_stats();
            last_tick = Instant::now();
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

    /// A second, distinguishable report used to test `replace_report`.
    fn other_flat_report() -> Report {
        let finding = Finding::builder(
            "NET004",
            "DNS Configuration",
            Category::Network,
            Severity::Info,
            Confidence::direct_observation(),
        )
        .explanation("1 nameserver configured.")
        .build();

        Report {
            context: ctx(),
            results: vec![
                ModuleRunResult {
                    module_id: "memory",
                    findings: vec![],
                    error: None,
                    skipped: false,
                },
                ModuleRunResult {
                    module_id: "network",
                    findings: vec![finding],
                    error: None,
                    skipped: false,
                },
            ],
        }
    }

    #[test]
    fn draws_without_panicking_and_shows_module_and_finding() {
        let mut app = TuiApp::new(flat_report());
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
    fn header_shows_live_stats_placeholders_before_first_refresh() {
        let mut app = TuiApp::new(flat_report());
        let backend = TestBackend::new(100, 20);
        let mut terminal = Terminal::new(backend).unwrap();
        terminal.draw(|f| draw(f, &mut app)).unwrap();
        let content: String = terminal
            .backend()
            .buffer()
            .content()
            .iter()
            .map(|c| c.symbol())
            .collect();
        assert!(content.contains("CPU"));
        assert!(content.contains("Mem"));
        assert!(content.contains("Disk"));
        assert!(content.contains("refresh"));
    }

    #[test]
    fn header_shows_real_numbers_after_refresh() {
        let mut app = TuiApp::new(flat_report());
        app.refresh_live_stats();
        // Mem/Disk resolve on the very first call; CPU needs a second
        // sample for a delta, so only assert on the ones that don't.
        assert!(app.live_stats.mem_percent.is_some());
    }

    #[test]
    fn navigation_wraps_around() {
        let mut app = TuiApp::new(flat_report());
        assert_eq!(app.selected_module_index(), 0);
        app.next(); // only one module, should wrap back to 0
        assert_eq!(app.selected_module_index(), 0);
        app.previous();
        assert_eq!(app.selected_module_index(), 0);
    }

    #[test]
    fn single_instance_module_has_no_submenu() {
        // flat_report()'s one finding has no .instance() set at all.
        let app = TuiApp::new(flat_report());
        assert!(!app.has_submenu());
    }

    #[test]
    fn two_instance_module_has_submenu() {
        let app = TuiApp::new(report_with_submenu());
        assert!(app.has_submenu());
        assert_eq!(app.submenu_items(), vec!["socket 0".to_string(), "socket 1".to_string()]);
    }

    #[test]
    fn drill_in_only_works_when_submenu_exists() {
        let mut app = TuiApp::new(flat_report());
        app.drill_in();
        assert_eq!(app.focus, Focus::Modules, "no submenu here, drill_in should no-op");

        let mut app2 = TuiApp::new(report_with_submenu());
        app2.drill_in();
        assert_eq!(app2.focus, Focus::Submenu);
        assert_eq!(app2.selected_submenu_index(), 0);
    }

    #[test]
    fn back_out_returns_false_at_top_level() {
        let mut app = TuiApp::new(report_with_submenu());
        assert!(!app.back_out(), "already at top level, nothing to back out of");
        app.drill_in();
        assert!(app.back_out(), "should back out of the submenu");
        assert_eq!(app.focus, Focus::Modules);
    }

    #[test]
    fn page_next_dispatches_to_submenu_once_drilled_in() {
        let mut app = TuiApp::new(report_with_submenu());
        app.drill_in();
        assert_eq!(app.selected_submenu_index(), 0);
        app.page_next();
        assert_eq!(app.selected_submenu_index(), 1);
        app.page_next(); // wraps
        assert_eq!(app.selected_submenu_index(), 0);
    }

    #[test]
    fn module_level_view_shows_only_global_findings_plus_hint() {
        let mut app = TuiApp::new(report_with_submenu());
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
        let mut app = TuiApp::new(report_with_submenu());
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

    #[test]
    fn replace_report_preserves_selection_when_module_still_present() {
        let mut app = TuiApp::new(other_flat_report());
        app.next(); // move off "memory" onto "network"
        assert_eq!(app.selected_module().unwrap().module_id, "network");

        app.replace_report(other_flat_report());
        assert_eq!(app.selected_module().unwrap().module_id, "network");
    }

    #[test]
    fn replace_report_falls_back_to_first_module_when_selection_vanishes() {
        let mut app = TuiApp::new(other_flat_report());
        app.next(); // "network"
        app.replace_report(flat_report()); // only "memory" exists here
        assert_eq!(app.selected_module().unwrap().module_id, "memory");
    }

    #[test]
    fn replace_report_resets_submenu_focus() {
        let mut app = TuiApp::new(report_with_submenu());
        app.drill_in();
        assert_eq!(app.focus, Focus::Submenu);
        app.replace_report(report_with_submenu());
        assert_eq!(app.focus, Focus::Modules);
    }

    #[test]
    fn progress_screen_draws_without_panicking() {
        let backend = TestBackend::new(80, 20);
        let mut terminal = Terminal::new(backend).unwrap();
        terminal
            .draw(|f| draw_progress_screen(f, 2, 5, "storage"))
            .unwrap();
        let content: String = terminal
            .backend()
            .buffer()
            .content()
            .iter()
            .map(|c| c.symbol())
            .collect();
        assert!(content.contains("storage"));
        assert!(content.contains("3/5"));
    }

    #[test]
    fn progress_screen_handles_completion() {
        let backend = TestBackend::new(80, 20);
        let mut terminal = Terminal::new(backend).unwrap();
        terminal.draw(|f| draw_progress_screen(f, 5, 5, "")).unwrap();
        let content: String = terminal
            .backend()
            .buffer()
            .content()
            .iter()
            .map(|c| c.symbol())
            .collect();
        assert!(content.contains("Finalizing"));
    }
}
