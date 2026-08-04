// SPDX-License-Identifier: GPL-3.0-only

use clap::{Parser, Subcommand, ValueEnum};

#[derive(Parser)]
#[command(name = "linuxdoctor", version, about = "Explainable Linux health diagnostics")]
pub struct Cli {
    #[command(subcommand)]
    pub command: Option<Command>,
}

#[derive(Subcommand)]
pub enum Command {
    /// Run a health audit (this is also what runs with no subcommand).
    Audit(AuditArgs),
    /// Interactive terminal UI over the same audit results.
    Tui(TuiArgs),
}

#[derive(Parser)]
pub struct AuditArgs {
    /// Restrict to specific modules by id (e.g. --modules memory,cpu).
    #[arg(long, value_delimiter = ',')]
    pub modules: Option<Vec<String>>,

    #[arg(long, value_enum, default_value_t = OutputFormat::Terminal)]
    pub output: OutputFormat,
}

#[derive(Parser)]
pub struct TuiArgs {
    /// Restrict to specific modules by id (e.g. --modules memory,cpu).
    #[arg(long, value_delimiter = ',')]
    pub modules: Option<Vec<String>>,
}

#[derive(Copy, Clone, ValueEnum)]
pub enum OutputFormat {
    Terminal,
    Json,
}

impl Cli {
    /// `linuxdoctor` with no subcommand behaves like `linuxdoctor audit`.
    pub fn resolved_command(self) -> Command {
        self.command.unwrap_or_else(|| {
            Command::Audit(AuditArgs {
                modules: None,
                output: OutputFormat::Terminal,
            })
        })
    }
}
