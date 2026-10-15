// SPDX-License-Identifier: GPL-3.0-only

mod cli;
mod manpage;

use clap::Parser;
use std::io::{ErrorKind, Write};
use std::process::ExitCode;
use std::time::Duration;

use cli::{AuditArgs, Cli, Command, OutputFormat};
use linuxdoctor::core;
use linuxdoctor::core::gate::{self, DEFAULT_FAIL_ON};
use linuxdoctor::models::Severity;
use linuxdoctor::output;
use linuxdoctor::output::common::{FilterInfo, RenderMeta};

fn main() -> ExitCode {
    let cli = Cli::parse();
    if let Some(seconds) = cli.timeout {
        core::command::set_default_timeout(Duration::from_secs(seconds));
    }
    match cli.resolved_command() {
        Command::Audit(args) => run_audit_command(args),
        Command::Tui(args) => run_tui_command(args.modules),
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
    let mut stdout = std::io::stdout().lock();
    match stdout.write_all(bytes).and_then(|()| stdout.flush()) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) if e.kind() == ErrorKind::BrokenPipe => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("linuxdoctor: could not write the output: {e}");
            ExitCode::FAILURE
        }
    }
}

fn run_audit_command(args: AuditArgs) -> ExitCode {
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
    let threshold = match args.fail_on {
        Some(level) => level.threshold(),
        None => Some(DEFAULT_FAIL_ON),
    };
    let gate = gate::evaluate(&report, threshold);

    let filter = args.min_severity.map(|level| {
        let min_severity = Severity::from(level);
        FilterInfo {
            min_severity,
            hidden: report.retain_at_or_above(min_severity),
        }
    });
    let meta = RenderMeta::now(filter);

    match args.output {
        OutputFormat::Terminal => print!("{}", output::terminal::render_with(&report, &meta)),
        OutputFormat::Json => match output::json::render_with(&report, &meta) {
            Ok(json) => println!("{json}"),
            Err(e) => {
                eprintln!("linuxdoctor: failed to render JSON: {e}");
                return ExitCode::FAILURE;
            }
        },
        OutputFormat::Markdown => print!("{}", output::markdown::render(&report, &meta)),
        OutputFormat::Html => print!("{}", output::html::render(&report, &meta)),
    }

    // Only an explicit --fail-on explains itself on stderr: the default
    // gate has always been silent and stays so.
    if gate.failed() {
        if args.fail_on.is_some() {
            if let Some(message) = gate.message() {
                eprintln!("linuxdoctor: {message}");
            }
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
