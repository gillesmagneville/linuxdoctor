// SPDX-License-Identifier: GPL-3.0-only

mod cli;
mod config;
mod manpage;

use clap::Parser;
use std::io::{ErrorKind, Write};
use std::process::ExitCode;
use std::time::Duration;

use cli::{AuditArgs, Cli, Command, DiffArgs, DiffFormat, OutputFormat};
use config::Config;
use linuxdoctor::core;
use linuxdoctor::core::gate::{self, DEFAULT_FAIL_ON};
use linuxdoctor::diff;
use linuxdoctor::models::Severity;
use linuxdoctor::output;
use linuxdoctor::output::common::{FilterInfo, RenderMeta};

/// Exit status when the configuration file cannot be used. The same as a
/// mistake on the command line, which is what a bad setting is.
const CONFIG_UNUSABLE: u8 = 2;

fn main() -> ExitCode {
    let cli = Cli::parse();
    let typed_timeout = cli.timeout;
    let choice = match (&cli.config, cli.no_config) {
        (_, true) => config::Choice::Ignore,
        (Some(path), false) => config::Choice::File(path.clone()),
        (None, false) => config::Choice::Default,
    };
    let command = cli.resolved_command();

    // The manual page and the completion scripts do not depend on any
    // setting, so a broken file must not stop them from being printed.
    let config = match command {
        Command::Man | Command::Completions(_) => Config::default(),
        _ => match config::load(&choice) {
            Ok(config) => config,
            Err(e) => {
                eprintln!("linuxdoctor: {e}");
                if choice == config::Choice::Default {
                    eprintln!("linuxdoctor: fix the file, or run with --no-config to ignore it");
                }
                return ExitCode::from(CONFIG_UNUSABLE);
            }
        },
    };
    if let Some(seconds) = typed_timeout.or(config.timeout) {
        core::command::set_default_timeout(Duration::from_secs(seconds));
    }
    match command {
        Command::Audit(args) => run_audit_command(args, &config),
        Command::Tui(args) => run_tui_command(args.modules),
        Command::Diff(args) => run_diff_command(args, &config),
        Command::Completions(args) => print_bytes(&cli::completion_script(args.shell)),
        Command::Man => run_man_command(),
    }
}

fn run_man_command() -> ExitCode {
    let modules = linuxdoctor::modules::all_modules();
    let ids: Vec<&str> = modules.iter().map(|module| module.id()).collect();
    match manpage::render(&cli::definition(), &ids) {
        Ok(page) => print_bytes(&page),
        Err(e) => {
            eprintln!("linuxdoctor: could not build the manual page: {e}");
            ExitCode::FAILURE
        }
    }
}

/// Writes `bytes` to standard output. A reader that goes away early
/// (`linuxdoctor man | head`) is not an error worth reporting.
fn print_bytes(bytes: &[u8]) -> ExitCode {
    if write_stdout(bytes) {
        ExitCode::SUCCESS
    } else {
        ExitCode::FAILURE
    }
}

/// `true` when the bytes were written or nobody is reading any more;
/// `false` (after saying why on stderr) when the write really failed.
fn write_stdout(bytes: &[u8]) -> bool {
    let mut stdout = std::io::stdout().lock();
    match stdout.write_all(bytes).and_then(|()| stdout.flush()) {
        Ok(()) => true,
        Err(e) if e.kind() == ErrorKind::BrokenPipe => true,
        Err(e) => {
            eprintln!("linuxdoctor: could not write the output: {e}");
            false
        }
    }
}

fn run_audit_command(args: AuditArgs, config: &Config) -> ExitCode {
    let settings = config.audit.resolve(
        args.output,
        args.min_severity,
        args.fail_on,
        OutputFormat::Terminal,
    );
    let mut report = match core::engine::run_audit(args.modules.as_deref()) {
        Ok(report) => report,
        Err(e) => {
            eprintln!("linuxdoctor: {e}");
            return ExitCode::FAILURE;
        }
    };

    // The pass/fail decision looks at the whole report, before any display
    // filter: hiding findings from the output must never turn a failing
    // audit into a passing one.
    let threshold = match settings.fail_on {
        Some(chosen) => chosen.level.threshold(),
        None => Some(DEFAULT_FAIL_ON),
    };
    let gate = gate::evaluate(&report, threshold);

    let filter = settings.min_severity.map(|level| {
        let min_severity = Severity::from(level);
        FilterInfo {
            min_severity,
            hidden: report.retain_at_or_above(min_severity),
        }
    });
    let meta = RenderMeta::now(filter);

    let text = match settings.output {
        OutputFormat::Terminal => output::terminal::render_with(&report, &meta),
        OutputFormat::Json => match output::json::render_with(&report, &meta) {
            Ok(json) => json + "\n",
            Err(e) => {
                eprintln!("linuxdoctor: failed to render JSON: {e}");
                return ExitCode::FAILURE;
            }
        },
        OutputFormat::Markdown => output::markdown::render(&report, &meta),
        OutputFormat::Html => output::html::render(&report, &meta),
    };
    // Not `print!`, which panics when the reader has gone away
    // (`linuxdoctor audit | head`). A reader that leaves early does not
    // change what the audit found: the verdict below is still given.
    if !write_stdout(text.as_bytes()) {
        return ExitCode::FAILURE;
    }

    // Only a level somebody chose -- with --fail-on or in the configuration
    // file -- explains itself on stderr: the default gate has always been
    // silent and stays so.
    if gate.failed() {
        if let Some(chosen) = &settings.fail_on {
            if let Some(message) = gate.message(&config.describe(chosen)) {
                eprintln!("linuxdoctor: {message}");
            }
        }
        return ExitCode::FAILURE;
    }
    ExitCode::SUCCESS
}

/// Exit status of `diff` when the reports cannot be compared (unreadable,
/// not a report, written by a newer version). Distinct from 1, which means
/// "something got worse", so a script can tell the two apart.
const DIFF_UNUSABLE: u8 = 2;

fn run_diff_command(args: DiffArgs, config: &Config) -> ExitCode {
    let settings = config.diff.resolve(
        args.output,
        args.min_severity,
        args.fail_on,
        DiffFormat::Terminal,
    );
    if args.before == "-" && args.after == "-" {
        eprintln!(
            "linuxdoctor: only one of the two reports can be read from standard input; \
             give the other as a file"
        );
        return ExitCode::from(DIFF_UNUSABLE);
    }
    let read = |source: &str| match diff::report::read(source) {
        Ok(report) => Some(report),
        Err(e) => {
            eprintln!("linuxdoctor: {e}");
            None
        }
    };
    let Some(before) = read(&args.before) else {
        return ExitCode::from(DIFF_UNUSABLE);
    };
    let Some(after) = read(&args.after) else {
        return ExitCode::from(DIFF_UNUSABLE);
    };

    let mut comparison = diff::compare::compare(&before, &after);

    // As for `audit`: the pass/fail decision looks at the whole comparison,
    // before any display filter, so hiding changes never hides a regression
    // from the exit status.
    let threshold = match settings.fail_on {
        Some(chosen) => chosen.level.threshold(),
        None => Some(DEFAULT_FAIL_ON),
    };
    let regressions = threshold.map_or(0, |t| comparison.regressions(t).len());

    if let Some(level) = settings.min_severity {
        comparison.retain_at_or_above(Severity::from(level));
    }

    let before_name = diff::report::display_name(&args.before);
    let after_name = diff::report::display_name(&args.after);
    let labels = diff::render::Labels {
        before: &before_name,
        after: &after_name,
        before_version: before.linuxdoctor_version.as_deref(),
        after_version: after.linuxdoctor_version.as_deref(),
    };
    let text = match settings.output {
        DiffFormat::Terminal => diff::render::terminal(&comparison, &labels),
        DiffFormat::Markdown => diff::render::markdown(&comparison, &labels),
        DiffFormat::Json => match diff::render::json(&comparison, &labels) {
            Ok(json) => json + "\n",
            Err(e) => {
                eprintln!("linuxdoctor: failed to render JSON: {e}");
                return ExitCode::FAILURE;
            }
        },
    };
    if !write_stdout(text.as_bytes()) {
        return ExitCode::FAILURE;
    }

    if regressions > 0 {
        // Only a level somebody chose explains itself on stderr, as for audit.
        if let (Some(chosen), Some(threshold)) = (&settings.fail_on, threshold) {
            eprintln!(
                "linuxdoctor: {regressions} finding(s) appeared or got worse, now at {threshold} \
                 or above ({}); exiting with status 1",
                config.describe(chosen)
            );
        }
        return ExitCode::FAILURE;
    }
    ExitCode::SUCCESS
}

fn run_tui_command(modules: Option<Vec<String>>) -> ExitCode {
    let report = match output::tui::run(modules.as_deref()) {
        Ok(report) => report,
        Err(e) => {
            eprintln!(
                "linuxdoctor: could not start the interactive UI ({e}). \
                 Try `linuxdoctor audit` instead — this usually means stdout \
                 isn't a real terminal (e.g. piped output or no TTY)."
            );
            return ExitCode::FAILURE;
        }
    };

    exit_code_for(&report)
}

fn exit_code_for(report: &core::engine::Report) -> ExitCode {
    if gate::evaluate(report, Some(DEFAULT_FAIL_ON)).failed() {
        ExitCode::FAILURE
    } else {
        ExitCode::SUCCESS
    }
}
