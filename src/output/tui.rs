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
//! The screen can be narrowed without touching the report (`tui_filter`):
//! `f` cycles a minimum severity, `/` types a text looked for in the
//! findings. Both only change what is *drawn* -- the module list's status
//! symbols still describe the whole module and the exit code is still
//! computed from every finding. A module's sub-items are those of the
//! findings that pass the filter, so a filter that leaves one instance
//! shows it flat, exactly like a module that only ever had one.
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

use crossterm::event::{self, Event, KeyCode, KeyEvent, KeyEventKind, KeyModifiers};
use crossterm::execute;
use crossterm::terminal::{
    disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen,
};
use ratatui::backend::{Backend, CrosstermBackend};
use ratatui::layout::{Alignment, Constraint, Direction, Layout, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Gauge, List, ListItem, ListState, Paragraph, Wrap};
use ratatui::{Frame, Terminal};

use crate::core::engine::{run_audit_with_progress, ModuleRunResult, Report};
use crate::models::{Finding, Severity};
use crate::output::common::make_display_safe;
use crate::output::live_stats::{self, CpuStatSample, LiveStats};
use crate::output::tui_filter::ViewFilter;

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
    /// What the screen narrows the report to. Never applied to `report`.
    filter: ViewFilter,
    /// True between `/` and Enter/Esc: typed characters go to the search
    /// text instead of being commands.
    typing: bool,
}

impl TuiApp {
    pub fn new(mut report: Report) -> Self {
        // Everything the TUI draws comes from this report, and much of it was
        // chosen by the audited machine: clean it once, here.
        make_display_safe(&mut report);
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
            filter: ViewFilter::default(),
            typing: false,
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
    pub fn replace_report(&mut self, mut new_report: Report) {
        make_display_safe(&mut new_report);
        let selected_id = self.selected_module().map(|r| r.module_id);
        self.report = new_report;

        let new_index =
            selected_id.and_then(|id| self.report.results.iter().position(|r| r.module_id == id));
        if self.report.results.is_empty() {
            self.module_state.select(None);
        } else {
            self.module_state.select(Some(new_index.unwrap_or(0)));
        }
        self.submenu_state = ListState::default();
        self.focus = Focus::Modules;
        self.detail_scroll = 0;
        self.last_scan = Instant::now();
        // The filter outlives a refresh; the module it left selected may no
        // longer have anything to show.
        self.settle_selection();
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
            .map(|r| {
                instances_of(&visible_findings(r, &self.filter))
                    .into_iter()
                    .map(String::from)
                    .collect()
            })
            .unwrap_or_default()
    }

    // ----- the view filter -----------------------------------------------------------------------

    /// `f`: next minimum severity.
    pub fn cycle_severity(&mut self) {
        self.filter.cycle_severity();
        self.filter_changed();
    }

    /// `/`: from now on typed characters are the search text. Any text
    /// already there stays, to be edited.
    pub fn start_search(&mut self) {
        self.typing = true;
    }

    /// A character typed while searching.
    pub fn search_type(&mut self, c: char) {
        if self.filter.push_char(c) {
            self.filter_changed();
        }
    }

    pub fn search_backspace(&mut self) {
        if self.filter.pop_char() {
            self.filter_changed();
        }
    }

    /// Enter while searching: stop typing, keep the text as a filter.
    pub fn finish_search(&mut self) {
        self.typing = false;
    }

    /// Esc while searching: stop typing and forget the text (the severity
    /// stays).
    pub fn cancel_search(&mut self) {
        self.typing = false;
        if self.filter.clear_query() {
            self.filter_changed();
        }
    }

    /// Esc with the filter active: show everything again. Returns whether
    /// there was a filter to clear.
    pub fn clear_filter(&mut self) -> bool {
        if !self.filter.is_active() {
            return false;
        }
        self.filter.clear();
        self.filter_changed();
        true
    }

    /// The sub-items, the scroll position and possibly the selected module
    /// all depend on what passes the filter: start from the top of whatever
    /// is left.
    fn filter_changed(&mut self) {
        self.focus = Focus::Modules;
        self.submenu_state = ListState::default();
        self.detail_scroll = 0;
        self.settle_selection();
    }

    /// While a filter is active, make sure the selected module is one that
    /// has something to show -- otherwise move to the first that has. With
    /// nothing matching anywhere the selection stays put, and its page says
    /// so. Only ever called when the filter or the report changes, never
    /// while moving between modules, so the arrow keys still reach every one.
    fn settle_selection(&mut self) {
        if !self.filter.is_active() {
            return;
        }
        let filter = &self.filter;
        let shows_something = |r: &ModuleRunResult| r.findings.iter().any(|f| filter.matches(f));
        if self.selected_module().is_some_and(shows_something) {
            return;
        }
        if let Some(first) = self.report.results.iter().position(shows_something) {
            self.module_state.select(Some(first));
        }
    }

    /// How many findings pass the filter, out of how many there are.
    fn shown_and_total(&self) -> (usize, usize) {
        self.report
            .results
            .iter()
            .fold((0, 0), |(shown, total), r| {
                (
                    shown + visible_findings(r, &self.filter).len(),
                    total + r.findings.len(),
                )
            })
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

/// The findings of a module that pass the filter, in report order.
fn visible_findings<'a>(result: &'a ModuleRunResult, filter: &ViewFilter) -> Vec<&'a Finding> {
    result
        .findings
        .iter()
        .filter(|f| filter.matches(f))
        .collect()
}

/// Distinct instance names among some findings, in first-seen order. A
/// free function (not a `TuiApp` method) so `draw_module_list` can call it
/// per-row to show a submenu indicator, without going through "the
/// currently selected" module. Given the findings that pass the filter, not
/// all of them: an instance with nothing left to show is not a sub-item.
fn instances_of<'a>(findings: &[&'a Finding]) -> Vec<&'a str> {
    let mut seen: Vec<&str> = Vec::new();
    for f in findings {
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
        // A module whose commands were cut short may simply be missing
        // the finding that would have turned it red: a green check would
        // claim more than the data supports.
        _ if !result.notes.is_empty() => (
            Severity::Warning.symbol(),
            severity_color(Severity::Warning),
        ),
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
            Constraint::Length(2),
        ])
        .split(area);

    draw_header(f, app, outer[0]);

    let body = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(28), Constraint::Percentage(72)])
        .split(outer[1]);

    draw_left_pane(f, app, body[0]);
    draw_detail_pane(f, app, body[1]);

    let keys = Line::from(Span::styled(
        help_text(app),
        Style::default().fg(Color::DarkGray),
    ));
    f.render_widget(Paragraph::new(vec![status_line(app), keys]), outer[2]);
}

/// "1 finding" / "12 findings".
fn findings_count(n: usize) -> String {
    format!("{n} finding{}", if n == 1 { "" } else { "s" })
}

/// First line of the bottom bar: what the screen is showing of the report.
/// Says outright when it is not everything -- a filtered screen must never
/// pass for a complete one.
fn status_line(app: &TuiApp) -> Line<'static> {
    let (shown, total) = app.shown_and_total();
    let dim = Style::default().fg(Color::DarkGray);
    if app.typing {
        let accent = Style::default().fg(Color::Cyan);
        return Line::from(vec![
            Span::styled(" Search: ", accent.add_modifier(Modifier::BOLD)),
            Span::raw(app.filter.query().to_string()),
            Span::styled("\u{2588}", accent),
            Span::styled(format!("   {shown} of {}", findings_count(total)), dim),
        ]);
    }
    if app.filter.is_active() {
        return Line::from(Span::styled(
            format!(
                " Filter: {}  \u{00b7}  Esc clears  \u{00b7}  {shown} of {}",
                app.filter.describe(),
                findings_count(total),
            ),
            Style::default().fg(Color::Yellow),
        ));
    }
    Line::from(Span::styled(
        format!(
            " All {} shown  \u{00b7}  f filter by severity  \u{00b7}  / search",
            findings_count(total)
        ),
        dim,
    ))
}

fn help_text(app: &TuiApp) -> &'static str {
    if app.typing {
        return " type to search  \u{00b7}  Backspace delete  \u{00b7}  Enter keep  \u{00b7}  Esc clear";
    }
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
        Span::styled(
            format!("LinuxDoctor {}", crate::VERSION),
            Style::default().add_modifier(Modifier::BOLD),
        ),
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

    let header = Paragraph::new(vec![line1, line2]).block(Block::default().borders(Borders::ALL));
    f.render_widget(header, area);
}

fn draw_left_pane(f: &mut Frame, app: &mut TuiApp, area: Rect) {
    match app.focus {
        Focus::Modules => draw_module_list(f, app, area),
        Focus::Submenu => draw_submenu_list(f, app, area),
    }
}

fn draw_module_list(f: &mut Frame, app: &mut TuiApp, area: Rect) {
    let filter_on = app.filter.is_active();
    let items: Vec<ListItem> = app
        .report
        .results
        .iter()
        .map(|r| {
            // The symbol is the health of the whole module, whatever the
            // filter: it must not turn green because a finding is hidden.
            let (symbol, color) = module_status(r);
            let visible = visible_findings(r, &app.filter);
            let has_submenu = instances_of(&visible).len() >= MIN_ITEMS_FOR_SUBMENU;
            let suffix = if has_submenu { " \u{203a}" } else { "" };
            // With a filter on, say how many of this module's findings get
            // through, and grey out the modules left with none. A module
            // that failed or was skipped has no findings to count; it keeps
            // its own colour.
            let counted = filter_on && !r.skipped && r.error.is_none();
            let count = if counted {
                format!(" ({})", visible.len())
            } else {
                String::new()
            };
            let name_style = if counted && visible.is_empty() {
                Style::default().fg(Color::DarkGray)
            } else {
                Style::default()
            };
            ListItem::new(Line::from(vec![
                Span::styled(format!("{symbol} "), Style::default().fg(color)),
                Span::styled(format!("{}{suffix}{count}", r.module_id), name_style),
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
        let detail = Paragraph::new("Skipped: not applicable to this system.").block(
            Block::default()
                .borders(Borders::ALL)
                .title(result.module_id),
        );
        f.render_widget(detail, area);
        return;
    }
    if let Some(err) = &result.error {
        let detail = Paragraph::new(Line::from(Span::styled(
            format!("Error: {err}"),
            Style::default().fg(Color::Red),
        )))
        .block(
            Block::default()
                .borders(Borders::ALL)
                .title(result.module_id),
        );
        f.render_widget(detail, area);
        return;
    }

    let visible = visible_findings(result, &app.filter);
    let items = instances_of(&visible);
    let (title, lines) = if items.len() >= MIN_ITEMS_FOR_SUBMENU {
        match app.focus {
            Focus::Modules => {
                let mut lines =
                    render_findings(visible.iter().copied().filter(|f| f.instance.is_none()));
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
                    .unwrap_or_default();
                let lines = render_findings(
                    visible
                        .iter()
                        .copied()
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
            render_findings(visible.iter().copied()),
        )
    };

    // A filtered page says so, and says what is missing from it.
    let lines = if app.filter.is_active() {
        let mut page = filter_banner(&app.filter, visible.len(), result.findings.len());
        if visible.is_empty() && !result.findings.is_empty() {
            page.push(Line::from("Nothing in this module matches the filter."));
        } else {
            page.extend(lines);
        }
        page
    } else {
        lines
    };

    // Module-level incidents belong on the module's own page, not on each
    // of its sub-items.
    let inside_submenu =
        items.len() >= MIN_ITEMS_FOR_SUBMENU && matches!(app.focus, Focus::Submenu);
    let lines = if inside_submenu {
        lines
    } else {
        let mut banner = notes_banner(result);
        banner.extend(lines);
        banner
    };

    let detail = Paragraph::new(lines)
        .block(Block::default().borders(Borders::ALL).title(title))
        .wrap(Wrap { trim: false })
        .scroll((app.detail_scroll, 0));

    f.render_widget(detail, area);
}

/// First lines of a module's page while a filter is active.
fn filter_banner(filter: &ViewFilter, shown: usize, total: usize) -> Vec<Line<'static>> {
    vec![
        Line::from(Span::styled(
            format!(
                "Filter: {} \u{2014} {shown} of {total} findings of this module shown",
                filter.describe()
            ),
            Style::default().fg(Color::Yellow),
        )),
        Line::from(""),
    ]
}

/// Yellow warning block listing why a module's data may be incomplete
/// (today: external commands stopped after the time limit). Empty — and
/// therefore invisible — on a healthy run.
fn notes_banner(result: &ModuleRunResult) -> Vec<Line<'static>> {
    if result.notes.is_empty() {
        return Vec::new();
    }
    let warn = Style::default().fg(Color::Yellow);
    let mut lines = vec![Line::from(Span::styled(
        "\u{26a0} Some data may be missing from this module:",
        warn.add_modifier(Modifier::BOLD),
    ))];
    for note in &result.notes {
        lines.push(Line::from(Span::styled(format!("  \u{2022} {note}"), warn)));
    }
    lines.push(Line::from(Span::styled(
        "  Raise the limit with --timeout <seconds> if the tool is just slow.",
        Style::default().fg(Color::DarkGray),
    )));
    lines.push(Line::from(""));
    lines
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
            // Explanations may hold several paragraphs and small tables:
            // one terminal line per text line, since a newline inside a
            // single `Line` would not be drawn as a line break.
            for text_line in f.explanation.lines() {
                lines.push(Line::from(text_line.to_string()));
            }
            lines.push(Line::from(""));
        }

        if let Some(rec) = &f.recommendation {
            lines.extend(recommendation_lines(rec));
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

/// A single-line recommendation keeps the compact "Recommendation: ..."
/// form. A multi-line one (numbered steps with commands on their own
/// indented lines) gets a heading, with the commands in a distinct colour
/// so they stand out from the prose and can be copied as they are.
fn recommendation_lines(rec: &str) -> Vec<Line<'static>> {
    let dim = Style::default().fg(Color::DarkGray);
    if !rec.contains('\n') {
        return vec![Line::from(Span::styled(
            format!("Recommendation: {rec}"),
            dim,
        ))];
    }
    let mut lines = vec![Line::from(Span::styled(
        "Recommendation:",
        Style::default().add_modifier(Modifier::BOLD),
    ))];
    for text_line in rec.lines() {
        let style = if text_line.starts_with("    ") {
            Style::default().fg(Color::Cyan)
        } else {
            Style::default()
        };
        lines.push(Line::from(Span::styled(text_line.to_string(), style)));
    }
    lines
}

/// How many still-running module names the progress label spells out
/// before collapsing the rest into "+N" — at the start of a scan every
/// module is pending, and a list of eleven names would overflow the gauge.
const PENDING_NAMES_SHOWN: usize = 3;

/// "storage, virtualization" / "memory, cpu, numa +8".
fn summarize_pending(pending: &[&str]) -> String {
    if pending.len() <= PENDING_NAMES_SHOWN {
        pending.join(", ")
    } else {
        format!(
            "{} +{}",
            pending[..PENDING_NAMES_SHOWN].join(", "),
            pending.len() - PENDING_NAMES_SHOWN
        )
    }
}

/// The startup/refresh loading screen: a centered gauge that fills in as
/// each module completes, plus the names of the modules still running.
/// Modules run concurrently, so there is no single "current" module —
/// what a user waiting on a slow one wants to know is *which* ones are
/// holding things up (SMART's per-device `smartctl` calls,
/// Virtualization's `virsh`/`docker` calls). Exists specifically so a
/// slow scan never looks like a frozen terminal.
pub fn draw_progress_screen(f: &mut Frame, done: usize, total: usize, pending: &[&str]) {
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
        format!("LinuxDoctor {}", crate::VERSION),
        Style::default().add_modifier(Modifier::BOLD),
    )))
    .alignment(Alignment::Center);
    f.render_widget(title, vertical[0]);

    let ratio = if total == 0 {
        0.0
    } else {
        (done as f64 / total as f64).clamp(0.0, 1.0)
    };
    let label = if total == 0 {
        "No modules selected".to_string()
    } else if done >= total {
        "Finalizing\u{2026}".to_string()
    } else {
        format!(
            "{done}/{total} done \u{2014} waiting for {}",
            summarize_pending(pending)
        )
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
    run_audit_with_progress(selected_ids, |done, total, pending| {
        let _ = terminal.draw(|f| draw_progress_screen(f, done, total, pending));
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

/// What the event loop must do after a key press.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum KeyAction {
    Nothing,
    Quit,
    /// Run the whole pipeline again behind the progress screen (`r`).
    Rescan,
}

/// One key press, as a change to the app. Separate from the event loop so
/// the keys can be tested without a terminal.
///
/// While the search text is being typed, letters are text -- `q` and `r`
/// included -- and only the keys that cannot be text (Enter, Esc, Backspace,
/// the arrows, PgUp/PgDn) are commands.
fn handle_key(app: &mut TuiApp, key: KeyEvent) -> KeyAction {
    if app.typing {
        match key.code {
            KeyCode::Esc => app.cancel_search(),
            KeyCode::Enter => app.finish_search(),
            KeyCode::Backspace => app.search_backspace(),
            KeyCode::Char(c)
                if !key
                    .modifiers
                    .intersects(KeyModifiers::CONTROL | KeyModifiers::ALT) =>
            {
                app.search_type(c)
            }
            KeyCode::PageDown => app.page_next(),
            KeyCode::PageUp => app.page_previous(),
            KeyCode::Down => app.scroll_down(),
            KeyCode::Up => app.scroll_up(),
            _ => {}
        }
        return KeyAction::Nothing;
    }

    match key.code {
        KeyCode::Char('q') => return KeyAction::Quit,
        // Esc undoes one level at a time: the submenu, then the filter, and
        // only then leaves.
        KeyCode::Esc => {
            if !app.back_out() && !app.clear_filter() {
                return KeyAction::Quit;
            }
        }
        KeyCode::Enter => app.drill_in(),
        KeyCode::PageDown => app.page_next(),
        KeyCode::PageUp => app.page_previous(),
        KeyCode::Down | KeyCode::Char('j') => app.scroll_down(),
        KeyCode::Up | KeyCode::Char('k') => app.scroll_up(),
        KeyCode::Char('f') => app.cycle_severity(),
        KeyCode::Char('/') => app.start_search(),
        KeyCode::Char('r') => return KeyAction::Rescan,
        _ => {}
    }
    KeyAction::Nothing
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
                    match handle_key(app, key) {
                        KeyAction::Quit => break,
                        KeyAction::Rescan => {
                            let new_report = run_scan_with_progress(terminal, selected_ids)?;
                            app.replace_report(new_report);
                            app.refresh_live_stats();
                            last_tick = Instant::now();
                        }
                        KeyAction::Nothing => {}
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
                notes: Vec::new(),
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
                notes: Vec::new(),
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
                    notes: Vec::new(),
                },
                ModuleRunResult {
                    module_id: "network",
                    findings: vec![finding],
                    error: None,
                    skipped: false,
                    notes: Vec::new(),
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
    fn the_header_and_the_loading_screen_say_which_version_this_is() {
        let expected = format!("LinuxDoctor {}", crate::VERSION);
        let mut app = TuiApp::new(flat_report());
        let content = screen_text(&mut app, 100, 20);
        assert!(content.contains(&expected), "header: {content}");

        let mut terminal = Terminal::new(TestBackend::new(80, 20)).unwrap();
        terminal
            .draw(|f| draw_progress_screen(f, 1, 5, &["storage"]))
            .unwrap();
        let loading: String = terminal
            .backend()
            .buffer()
            .content()
            .iter()
            .map(|c| c.symbol())
            .collect();
        assert!(loading.contains(&expected), "loading screen: {loading}");
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

    fn plain(lines: &[Line<'_>]) -> Vec<String> {
        lines
            .iter()
            .map(|l| {
                l.spans
                    .iter()
                    .map(|s| s.content.as_ref())
                    .collect::<String>()
            })
            .collect()
    }

    #[test]
    fn multi_paragraph_explanations_become_separate_lines() {
        let f = Finding::builder(
            "MEM007",
            "Used Memory",
            Category::Memory,
            Severity::Info,
            Confidence::direct_observation(),
        )
        .explanation("First paragraph.\n\nTable:\n  Programs   5.0 GB\n  Free       4.0 GB")
        .build();
        let lines = plain(&render_findings(std::iter::once(&f)));
        assert!(lines.iter().all(|l| !l.contains('\n')), "{lines:?}");
        assert!(
            lines.contains(&"  Programs   5.0 GB".to_string()),
            "{lines:?}"
        );
        assert!(lines.contains(&"Table:".to_string()), "{lines:?}");
    }

    #[test]
    fn numbered_recommendation_gets_a_heading_and_keeps_command_indentation() {
        let lines = plain(&recommendation_lines(
            "1. Do this:\n    sudo thing\n2. Then that.",
        ));
        assert_eq!(
            lines,
            [
                "Recommendation:",
                "1. Do this:",
                "    sudo thing",
                "2. Then that."
            ]
        );
    }

    #[test]
    fn one_line_recommendation_keeps_the_compact_form() {
        let lines = plain(&recommendation_lines("Check the logs."));
        assert_eq!(lines, ["Recommendation: Check the logs."]);
    }

    #[test]
    fn commands_are_coloured_apart_from_the_prose() {
        let lines = recommendation_lines("1. Do this:\n    sudo thing");
        assert_ne!(lines[1].spans[0].style.fg, Some(Color::Cyan));
        assert_eq!(lines[2].spans[0].style.fg, Some(Color::Cyan));
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
        assert_eq!(
            app.submenu_items(),
            vec!["socket 0".to_string(), "socket 1".to_string()]
        );
    }

    #[test]
    fn drill_in_only_works_when_submenu_exists() {
        let mut app = TuiApp::new(flat_report());
        app.drill_in();
        assert_eq!(
            app.focus,
            Focus::Modules,
            "no submenu here, drill_in should no-op"
        );

        let mut app2 = TuiApp::new(report_with_submenu());
        app2.drill_in();
        assert_eq!(app2.focus, Focus::Submenu);
        assert_eq!(app2.selected_submenu_index(), 0);
    }

    #[test]
    fn back_out_returns_false_at_top_level() {
        let mut app = TuiApp::new(report_with_submenu());
        assert!(
            !app.back_out(),
            "already at top level, nothing to back out of"
        );
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
            .draw(|f| draw_progress_screen(f, 2, 5, &["storage", "virtualization", "gpu"]))
            .unwrap();
        let content: String = terminal
            .backend()
            .buffer()
            .content()
            .iter()
            .map(|c| c.symbol())
            .collect();
        assert!(content.contains("storage"));
        assert!(content.contains("2/5 done"), "{content}");
    }

    #[test]
    fn progress_screen_handles_completion() {
        let backend = TestBackend::new(80, 20);
        let mut terminal = Terminal::new(backend).unwrap();
        terminal
            .draw(|f| draw_progress_screen(f, 5, 5, &[]))
            .unwrap();
        let content: String = terminal
            .backend()
            .buffer()
            .content()
            .iter()
            .map(|c| c.symbol())
            .collect();
        assert!(content.contains("Finalizing"));
    }
    #[test]
    fn pending_names_are_listed_then_collapsed() {
        assert_eq!(summarize_pending(&[]), "");
        assert_eq!(summarize_pending(&["gpu"]), "gpu");
        assert_eq!(summarize_pending(&["a", "b", "c"]), "a, b, c");
        assert_eq!(summarize_pending(&["a", "b", "c", "d", "e"]), "a, b, c +2");
    }

    #[test]
    fn module_with_notes_is_not_shown_as_a_clean_green_check() {
        let mut clean = ModuleRunResult {
            module_id: "storage",
            findings: Vec::new(),
            error: None,
            skipped: false,
            notes: Vec::new(),
        };
        assert_eq!(module_status(&clean).0, Severity::Info.symbol());
        clean
            .notes
            .push("'smartctl' did not finish within 20s and was stopped".into());
        assert_eq!(module_status(&clean).0, Severity::Warning.symbol());
    }

    #[test]
    fn notes_banner_is_empty_when_healthy_and_explains_the_remedy_otherwise() {
        let mut result = ModuleRunResult {
            module_id: "gpu",
            findings: Vec::new(),
            error: None,
            skipped: false,
            notes: Vec::new(),
        };
        assert!(notes_banner(&result).is_empty());

        result
            .notes
            .push("'nvidia-smi' did not finish within 20s and was stopped".into());
        let text: String = notes_banner(&result)
            .iter()
            .map(|l| {
                l.spans
                    .iter()
                    .map(|s| s.content.as_ref())
                    .collect::<String>()
            })
            .collect::<Vec<_>>()
            .join("\n");
        assert!(text.contains("Some data may be missing"), "{text}");
        assert!(text.contains("'nvidia-smi' did not finish"), "{text}");
        assert!(text.contains("--timeout"), "{text}");
    }

    /// Every symbol the TUI draws for the selected module, flattened.
    fn screen_text(app: &mut TuiApp, width: u16, height: u16) -> String {
        let mut terminal = Terminal::new(TestBackend::new(width, height)).unwrap();
        terminal.draw(|f| draw(f, app)).unwrap();
        terminal
            .backend()
            .buffer()
            .content()
            .iter()
            .map(|c| c.symbol())
            .collect()
    }

    #[test]
    fn text_from_the_audited_machine_never_reaches_the_screen() {
        use crate::output::common::testkit::{hostile_report, unsafe_char};
        let mut app = TuiApp::new(hostile_report());
        let modules = app.report.results.len();
        assert!(modules >= 3);
        let mut seen_payload = false;
        for index in 0..modules {
            app.module_state.select(Some(index));
            app.submenu_state = ListState::default();
            let text = screen_text(&mut app, 200, 60);
            assert_eq!(unsafe_char(&text), None, "module {index}: {text:?}");
            seen_payload |= text.contains("EVIL");
        }
        assert!(
            seen_payload,
            "the hostile text was never drawn: the test saw nothing"
        );
    }

    #[test]
    fn a_refreshed_report_is_cleaned_too() {
        use crate::output::common::testkit::{hostile_report, unsafe_char};
        let mut app = TuiApp::new(flat_report());
        app.replace_report(hostile_report());
        let text = screen_text(&mut app, 200, 60);
        assert_eq!(unsafe_char(&text), None, "{text:?}");
        assert_eq!(unsafe_char(&app.report.context.hostname), None);
    }

    // ----- the view filter ---------------------------------------------------------------------------

    fn module(id: &'static str, findings: Vec<Finding>) -> ModuleRunResult {
        ModuleRunResult {
            module_id: id,
            findings,
            error: None,
            skipped: false,
            notes: Vec::new(),
        }
    }

    /// Five modules: two with a warning and an info each, one with only an
    /// info, one that failed, one that was skipped.
    fn mixed_report() -> Report {
        let memory = module(
            "memory",
            vec![
                Finding::builder(
                    "MEM001",
                    "Kernel Swappiness",
                    Category::Memory,
                    Severity::Info,
                    Confidence::direct_observation(),
                )
                .evidence("vm.swappiness", "60")
                .explanation("The default value.")
                .build(),
                Finding::builder(
                    "MEM002",
                    "Swap Activity",
                    Category::Memory,
                    Severity::Warning,
                    Confidence::strong_indication(85),
                )
                .explanation("Swapping while memory is tight.")
                .build(),
            ],
        );
        let security = module(
            "security",
            vec![
                Finding::builder(
                    "SEC001",
                    "Root Login Over SSH",
                    Category::Security,
                    Severity::Warning,
                    Confidence::direct_observation(),
                )
                .explanation("sshd accepts passwords for root.")
                .recommendation("Set PermitRootLogin to no.")
                .build(),
                Finding::builder(
                    "SEC002",
                    "Firewall",
                    Category::Security,
                    Severity::Info,
                    Confidence::direct_observation(),
                )
                .explanation("A firewall is active.")
                .build(),
            ],
        );
        let network = module(
            "network",
            vec![Finding::builder(
                "NET004",
                "DNS Configuration",
                Category::Network,
                Severity::Info,
                Confidence::direct_observation(),
            )
            .explanation("1 nameserver configured.")
            .build()],
        );
        let mut storage = module("storage", Vec::new());
        storage.error = Some("smartctl failed".into());
        let mut gpu = module("gpu", Vec::new());
        gpu.skipped = true;
        Report {
            context: ctx(),
            results: vec![memory, security, network, storage, gpu],
        }
    }

    fn key(code: KeyCode) -> KeyEvent {
        KeyEvent::new(code, KeyModifiers::NONE)
    }

    /// Type some text, one key press per character, as the event loop would
    /// see it. Returns what the last key asked for.
    fn press(app: &mut TuiApp, text: &str) -> KeyAction {
        let mut last = KeyAction::Nothing;
        for c in text.chars() {
            last = handle_key(app, key(KeyCode::Char(c)));
        }
        last
    }

    fn selected_id(app: &TuiApp) -> &'static str {
        app.selected_module().unwrap().module_id
    }

    fn findings_per_module(app: &TuiApp) -> Vec<usize> {
        app.report
            .results
            .iter()
            .map(|r| r.findings.len())
            .collect()
    }

    #[test]
    fn nothing_is_filtered_until_asked_and_the_bottom_bar_says_how() {
        let mut app = TuiApp::new(mixed_report());
        let screen = screen_text(&mut app, 100, 24);
        assert!(screen.contains("MEM001") && screen.contains("MEM002"));
        assert!(screen.contains("All 5 findings shown"), "{screen}");
        assert!(screen.contains("f filter by severity"), "{screen}");
        assert!(screen.contains("/ search"), "{screen}");
        assert!(!screen.contains("Filter:"), "{screen}");
        // And no counts next to the module names.
        assert!(screen.contains("memory"), "{screen}");
        assert!(!screen.contains("memory ("), "{screen}");
    }

    #[test]
    fn f_hides_what_is_below_the_severity_and_the_page_says_so() {
        let mut app = TuiApp::new(mixed_report());
        assert_eq!(press(&mut app, "f"), KeyAction::Nothing);
        let screen = screen_text(&mut app, 120, 24);
        assert!(screen.contains("MEM002"), "the warning stays: {screen}");
        assert!(!screen.contains("MEM001"), "the info is hidden: {screen}");
        assert!(
            screen.contains("1 of 2 findings of this module shown"),
            "{screen}"
        );
        assert!(
            screen.contains("Filter: severity \u{2265} warning"),
            "{screen}"
        );
        assert!(screen.contains("2 of 5 findings"), "{screen}");
        assert!(screen.contains("Esc clears"), "{screen}");
    }

    #[test]
    fn the_filter_never_changes_the_report() {
        let mut app = TuiApp::new(mixed_report());
        let before = findings_per_module(&app);
        press(&mut app, "fff");
        press(&mut app, "/");
        press(&mut app, "zzz");
        assert_eq!(findings_per_module(&app), before);
        assert_eq!(app.shown_and_total(), (0, 5));
    }

    #[test]
    fn a_module_keeps_its_health_symbol_when_the_filter_hides_its_findings() {
        let mut app = TuiApp::new(mixed_report());
        press(&mut app, "fff"); // critical only: nothing in this report
        let screen = screen_text(&mut app, 100, 24);
        assert!(
            screen.contains(&format!("{} memory (0)", Severity::Warning.symbol())),
            "memory has a warning, hidden or not: {screen}"
        );
    }

    #[test]
    fn with_a_filter_on_each_module_shows_how_many_findings_get_through() {
        let mut app = TuiApp::new(mixed_report());
        press(&mut app, "f"); // warning and above
        let screen = screen_text(&mut app, 100, 24);
        assert!(screen.contains("memory (1)"), "{screen}");
        assert!(screen.contains("security (1)"), "{screen}");
        assert!(screen.contains("network (0)"), "{screen}");
        // A module that failed or was skipped has nothing to count.
        assert!(screen.contains("storage"), "{screen}");
        assert!(!screen.contains("storage ("), "{screen}");
        assert!(!screen.contains("gpu ("), "{screen}");
    }

    /// The colour of the first cell of `word` on the screen.
    fn colour_of(app: &mut TuiApp, word: &str) -> Option<Color> {
        let mut terminal = Terminal::new(TestBackend::new(100, 24)).unwrap();
        terminal.draw(|f| draw(f, app)).unwrap();
        let buffer = terminal.backend().buffer();
        for y in 0..buffer.area.height {
            let row: String = (0..buffer.area.width)
                .map(|x| buffer.get(x, y).symbol().to_string())
                .collect();
            // Every symbol on these rows is one column wide, so a character
            // index is a column.
            if let Some(at) = row.find(word) {
                let x = row[..at].chars().count() as u16;
                return Some(buffer.get(x, y).fg);
            }
        }
        None
    }

    #[test]
    fn modules_left_with_nothing_are_greyed_out_and_the_others_are_not() {
        let mut app = TuiApp::new(mixed_report());
        press(&mut app, "f");
        assert_eq!(colour_of(&mut app, "network (0)"), Some(Color::DarkGray));
        assert_ne!(colour_of(&mut app, "security (1)"), Some(Color::DarkGray));
        // Selected rows are drawn reversed, not grey: look at an unselected one.
        assert_ne!(colour_of(&mut app, "memory (1)"), Some(Color::DarkGray));
    }

    #[test]
    fn a_search_jumps_to_the_first_module_that_has_a_match() {
        let mut app = TuiApp::new(mixed_report());
        assert_eq!(selected_id(&app), "memory");
        press(&mut app, "/");
        press(&mut app, "ssh");
        assert_eq!(selected_id(&app), "security");
        let screen = screen_text(&mut app, 120, 24);
        assert!(screen.contains("SEC001"), "{screen}");
        assert!(!screen.contains("SEC002"), "{screen}");
    }

    #[test]
    fn the_selection_stays_where_it_is_while_it_still_has_a_match() {
        let mut app = TuiApp::new(mixed_report());
        press(&mut app, "/ssh");
        assert_eq!(selected_id(&app), "security");
        handle_key(&mut app, key(KeyCode::Backspace)); // "ss": still matches
        assert_eq!(selected_id(&app), "security");
        handle_key(&mut app, key(KeyCode::Backspace)); // "s": matches memory first
        assert_eq!(selected_id(&app), "security", "no reason to move");
        handle_key(&mut app, key(KeyCode::Esc)); // clears the text
        assert_eq!(selected_id(&app), "security");
    }

    #[test]
    fn a_search_that_matches_nothing_says_so_and_stays_put() {
        let mut app = TuiApp::new(mixed_report());
        press(&mut app, "/zzzz");
        assert_eq!(selected_id(&app), "memory");
        let screen = screen_text(&mut app, 120, 24);
        assert!(
            screen.contains("Nothing in this module matches the filter"),
            "{screen}"
        );
        assert!(screen.contains("0 of 5 findings"), "{screen}");
        assert!(!screen.contains("MEM00"), "{screen}");
    }

    #[test]
    fn moving_between_modules_still_reaches_every_one_under_a_filter() {
        let mut app = TuiApp::new(mixed_report());
        press(&mut app, "f");
        let mut visited = vec![selected_id(&app)];
        for _ in 0..4 {
            handle_key(&mut app, key(KeyCode::PageDown));
            visited.push(selected_id(&app));
        }
        assert_eq!(visited, ["memory", "security", "network", "storage", "gpu"]);
    }

    #[test]
    fn a_failed_module_still_shows_its_error_under_a_filter() {
        let mut app = TuiApp::new(mixed_report());
        press(&mut app, "fff");
        app.module_state.select(Some(3));
        let screen = screen_text(&mut app, 100, 24);
        assert!(screen.contains("Error: smartctl failed"), "{screen}");
    }

    #[test]
    fn the_sub_items_are_those_of_the_findings_that_pass_the_filter() {
        let mut app = TuiApp::new(report_with_submenu());
        assert!(app.has_submenu());
        press(&mut app, "f"); // only socket 1 has a warning
        assert!(!app.has_submenu(), "one instance left: shown flat");
        let screen = screen_text(&mut app, 120, 30);
        assert!(screen.contains("CPU004"), "{screen}");
        assert!(screen.contains("something's off"), "{screen}");
        assert!(!screen.contains("Socket 0 detail"), "{screen}");
        assert!(!screen.contains("CPU001"), "the info overview is hidden");
        assert!(!screen.contains("press Enter for detail"), "{screen}");
        // Showing everything again brings the sub-items back.
        handle_key(&mut app, key(KeyCode::Esc));
        assert!(app.has_submenu());
        assert_eq!(app.submenu_items().len(), 2);
    }

    #[test]
    fn a_search_can_leave_both_instances_in_the_submenu() {
        let mut app = TuiApp::new(report_with_submenu());
        press(&mut app, "/socket");
        assert_eq!(app.submenu_items().len(), 2);
        handle_key(&mut app, key(KeyCode::Enter));
        handle_key(&mut app, key(KeyCode::Enter)); // second Enter drills in
        assert_eq!(app.focus, Focus::Submenu);
    }

    #[test]
    fn changing_the_filter_while_inside_a_submenu_goes_back_to_the_module() {
        let mut app = TuiApp::new(report_with_submenu());
        app.drill_in();
        assert_eq!(app.focus, Focus::Submenu);
        app.scroll_down();
        app.cycle_severity();
        assert_eq!(app.focus, Focus::Modules);
        assert_eq!(app.detail_scroll, 0);
    }

    #[test]
    fn esc_undoes_one_level_at_a_time_and_only_then_quits() {
        let mut app = TuiApp::new(report_with_submenu());
        press(&mut app, "/socket");
        handle_key(&mut app, key(KeyCode::Enter)); // keep the text
        handle_key(&mut app, key(KeyCode::Enter)); // drill in
        assert_eq!(app.focus, Focus::Submenu);
        assert_eq!(
            handle_key(&mut app, key(KeyCode::Esc)),
            KeyAction::Nothing,
            "leaves the submenu"
        );
        assert_eq!(app.focus, Focus::Modules);
        assert!(app.filter.is_active());
        assert_eq!(
            handle_key(&mut app, key(KeyCode::Esc)),
            KeyAction::Nothing,
            "clears the filter"
        );
        assert!(!app.filter.is_active());
        assert_eq!(handle_key(&mut app, key(KeyCode::Esc)), KeyAction::Quit);
    }

    #[test]
    fn while_typing_letters_are_text_and_not_commands() {
        let mut app = TuiApp::new(mixed_report());
        assert_eq!(press(&mut app, "/"), KeyAction::Nothing);
        assert!(app.typing);
        // q quits, r rescans, f cycles, j scrolls -- not here.
        for c in ['q', 'r', 'f', 'j', 'k', '/'] {
            assert_eq!(
                handle_key(&mut app, key(KeyCode::Char(c))),
                KeyAction::Nothing
            );
        }
        assert_eq!(app.filter.query(), "qrfjk/");
        assert_eq!(app.filter.min_severity(), Severity::Info, "f was text");
        assert!(app.typing);
        // Enter keeps the text and gives the keys back.
        handle_key(&mut app, key(KeyCode::Enter));
        assert!(!app.typing);
        assert_eq!(app.filter.query(), "qrfjk/");
        assert_eq!(press(&mut app, "q"), KeyAction::Quit);
    }

    #[test]
    fn r_still_asks_for_a_rescan_when_not_typing() {
        let mut app = TuiApp::new(mixed_report());
        assert_eq!(press(&mut app, "r"), KeyAction::Rescan);
    }

    #[test]
    fn esc_while_typing_forgets_the_text_and_does_not_quit() {
        let mut app = TuiApp::new(mixed_report());
        press(&mut app, "/ab");
        assert_eq!(handle_key(&mut app, key(KeyCode::Esc)), KeyAction::Nothing);
        assert!(!app.typing);
        assert_eq!(app.filter.query(), "");
        assert_eq!(handle_key(&mut app, key(KeyCode::Esc)), KeyAction::Quit);
    }

    #[test]
    fn esc_while_typing_keeps_the_severity() {
        let mut app = TuiApp::new(mixed_report());
        press(&mut app, "f/ab");
        handle_key(&mut app, key(KeyCode::Esc));
        assert_eq!(app.filter.min_severity(), Severity::Warning);
        assert!(app.filter.is_active());
    }

    #[test]
    fn backspace_edits_the_text_and_widens_the_view_again() {
        let mut app = TuiApp::new(mixed_report());
        press(&mut app, "/tight"); // only in the swap warning's explanation
        assert_eq!(app.shown_and_total().0, 1);
        for _ in 0..4 {
            handle_key(&mut app, key(KeyCode::Backspace));
        }
        assert_eq!(app.filter.query(), "t");
        assert!(app.shown_and_total().0 > 1, "a shorter text matches more");
        handle_key(&mut app, key(KeyCode::Backspace));
        assert_eq!(app.shown_and_total(), (5, 5));
        // Nothing left to delete is not a problem.
        handle_key(&mut app, key(KeyCode::Backspace));
        assert_eq!(app.filter.query(), "");
    }

    #[test]
    fn a_search_started_again_keeps_the_text_to_edit() {
        let mut app = TuiApp::new(mixed_report());
        press(&mut app, "/ssh");
        handle_key(&mut app, key(KeyCode::Enter));
        press(&mut app, "/");
        assert!(app.typing);
        assert_eq!(app.filter.query(), "ssh");
    }

    #[test]
    fn control_and_alt_combinations_are_not_text() {
        let mut app = TuiApp::new(mixed_report());
        press(&mut app, "/");
        for modifier in [KeyModifiers::CONTROL, KeyModifiers::ALT] {
            let action = handle_key(&mut app, KeyEvent::new(KeyCode::Char('c'), modifier));
            assert_eq!(action, KeyAction::Nothing);
        }
        assert_eq!(app.filter.query(), "");
        // A capital letter is typed with Shift held: that is text.
        handle_key(
            &mut app,
            KeyEvent::new(KeyCode::Char('S'), KeyModifiers::SHIFT),
        );
        assert_eq!(app.filter.query(), "S");
    }

    #[test]
    fn the_arrows_and_page_keys_still_work_while_typing() {
        let mut app = TuiApp::new(mixed_report());
        press(&mut app, "/");
        handle_key(&mut app, key(KeyCode::PageDown));
        assert_eq!(selected_id(&app), "security");
        handle_key(&mut app, key(KeyCode::Down));
        assert_eq!(app.detail_scroll, 1);
        handle_key(&mut app, key(KeyCode::Up));
        assert_eq!(app.detail_scroll, 0);
        assert!(app.typing, "still typing");
    }

    #[test]
    fn the_bottom_bar_shows_the_text_as_it_is_typed_and_then_the_filter() {
        let mut app = TuiApp::new(mixed_report());
        press(&mut app, "/ss");
        let typing = screen_text(&mut app, 100, 24);
        assert!(typing.contains("Search: ss\u{2588}"), "{typing}");
        assert!(typing.contains("Enter keep"), "{typing}");
        assert!(!typing.contains("q quit"), "q is text now: {typing}");

        handle_key(&mut app, key(KeyCode::Enter));
        let kept = screen_text(&mut app, 100, 24);
        assert!(kept.contains("Filter: search \u{201c}ss\u{201d}"), "{kept}");
        assert!(kept.contains("Esc clears"), "{kept}");
        assert!(kept.contains("q quit"), "{kept}");
        assert!(!kept.contains("Search: "), "{kept}");
    }

    #[test]
    fn the_bottom_bar_still_fits_in_eighty_columns() {
        let mut app = TuiApp::new(mixed_report());
        press(&mut app, "f/ssh");
        let typing = screen_text(&mut app, 80, 24);
        assert!(typing.contains("Esc clear"), "{typing}");
        handle_key(&mut app, key(KeyCode::Enter));
        let kept = screen_text(&mut app, 80, 24);
        assert!(kept.contains("Esc clears"), "{kept}");
        assert!(kept.contains("q quit"), "{kept}");
        assert!(kept.contains("1 of 5 findings"), "{kept}");
    }

    #[test]
    fn a_refresh_keeps_the_filter_and_moves_off_a_module_with_nothing_to_show() {
        let mut app = TuiApp::new(flat_report());
        press(&mut app, "/dns"); // nothing in the memory module matches
        assert_eq!(selected_id(&app), "memory");
        app.replace_report(other_flat_report());
        assert!(app.filter.is_active(), "the filter outlives a refresh");
        assert_eq!(app.filter.query(), "dns");
        assert_eq!(selected_id(&app), "network");
    }

    #[test]
    fn text_from_the_audited_machine_never_reaches_the_screen_under_a_filter() {
        use crate::output::common::testkit::{hostile_report, unsafe_char};
        let mut app = TuiApp::new(hostile_report());
        press(&mut app, "f/evil");
        let modules = app.report.results.len();
        let mut seen_payload = false;
        for index in 0..modules {
            app.module_state.select(Some(index));
            let text = screen_text(&mut app, 200, 60);
            assert_eq!(unsafe_char(&text), None, "module {index}: {text:?}");
            seen_payload |= text.contains("EVIL");
        }
        assert!(seen_payload, "the test saw none of the hostile text");
    }

    #[test]
    fn what_is_typed_cannot_put_control_characters_on_the_screen() {
        use crate::output::common::testkit::unsafe_char;
        let mut app = TuiApp::new(mixed_report());
        press(&mut app, "/");
        for c in ['\u{1b}', '\u{7}', '\u{9b}', '\r', 'a'] {
            handle_key(&mut app, key(KeyCode::Char(c)));
        }
        assert_eq!(app.filter.query(), "a");
        let text = screen_text(&mut app, 100, 24);
        assert_eq!(unsafe_char(&text), None, "{text:?}");
    }
}
