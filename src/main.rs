// SPDX-License-Identifier: GPL-3.0-only

mod cli;

use clap::Parser;
use std::process::ExitCode;

use cli::{Cli, Command, OutputFormat};
use linuxdoctor::core;
use linuxdoctor::models::Severity;
use linuxdoctor::output;

fn main() -> ExitCode {
    match Cli::parse().resolved_command() {
        Command::Audit(args) => run_audit_command(args.modules, args.output),
        Command::Tui(args) => run_tui_command(args.modules),
    }
}

fn run_audit_command(modules: Option<Vec<String>>, format: OutputFormat) -> ExitCode {
    let report = match core::engine::run_audit(modules.as_deref()) {
        Ok(report) => report,
        Err(e) => {
            eprintln!("linuxdoctor: {e}");
            return ExitCode::FAILURE;
        }
    };

    match format {
        OutputFormat::Terminal => print!("{}", output::terminal::render(&report)),
        OutputFormat::Json => match output::json::render(&report) {
            Ok(json) => println!("{json}"),
            Err(e) => {
                eprintln!("linuxdoctor: failed to render JSON: {e}");
                return ExitCode::FAILURE;
            }
        },
    }

    exit_code_for(&report)
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
    match report.highest_severity() {
        Some(Severity::Critical) | Some(Severity::Error) => ExitCode::FAILURE,
        _ => ExitCode::SUCCESS,
    }
}
