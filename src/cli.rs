// SPDX-License-Identifier: GPL-3.0-only

use std::io::IsTerminal;

use clap::{Parser, Subcommand, ValueEnum};

#[derive(Parser)]
#[command(name = "linuxdoctor", version, about = "Explainable Linux health diagnostics")]
pub struct Cli {
    #[command(subcommand)]
    pub command: Option<Command>,
}

#[derive(Subcommand)]
pub enum Command {
    /// Run a health audit and print the results (also what runs with no
    /// subcommand, when stdin/stdout aren't a real terminal).
    Audit(AuditArgs),
    /// Interactive terminal UI over the same audit results (also what
    /// runs with no subcommand, when stdin/stdout are a real terminal).
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
    /// `linuxdoctor` with no subcommand opens the interactive TUI when run
    /// in a real terminal — matching how someone launches it after
    /// installing the package. Falls back to `audit`'s plain-text output
    /// when stdin or stdout isn't actually a terminal (piped, redirected,
    /// or run from a script/cron/CI), so existing non-interactive uses
    /// like `linuxdoctor > report.txt` or `linuxdoctor | grep ...` keep
    /// working exactly as before rather than failing against a TUI that
    /// has nowhere to render or read keyboard input from. `std::io::
    /// IsTerminal` is stable in the standard library (since Rust 1.70,
    /// under this project's 1.75 pin) — no new dependency needed.
    pub fn resolved_command(self) -> Command {
        let interactive = std::io::stdout().is_terminal() && std::io::stdin().is_terminal();
        self.resolved_command_with(interactive)
    }

    /// The actual decision, taking "are we interactive" as a plain bool
    /// rather than checking real file descriptors directly — same "thin
    /// I/O wrapper around a pure, testable core" split used throughout
    /// this project's modules (see ARCHITECTURE.md "Collectors"). A test
    /// process's stdin/stdout are essentially never a real TTY, so
    /// `resolved_command()` itself can't be meaningfully unit-tested for
    /// the interactive branch — this can, deterministically, for both.
    fn resolved_command_with(self, interactive: bool) -> Command {
        self.command.unwrap_or_else(|| {
            if interactive {
                Command::Tui(TuiArgs { modules: None })
            } else {
                Command::Audit(AuditArgs {
                    modules: None,
                    output: OutputFormat::Terminal,
                })
            }
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn no_subcommand_resolves_to_tui_when_interactive() {
        let cli = Cli { command: None };
        assert!(matches!(cli.resolved_command_with(true), Command::Tui(_)));
    }

    #[test]
    fn no_subcommand_resolves_to_audit_when_not_interactive() {
        let cli = Cli { command: None };
        assert!(matches!(
            cli.resolved_command_with(false),
            Command::Audit(_)
        ));
    }

    #[test]
    fn explicit_audit_subcommand_is_never_overridden() {
        // Even when "interactive" is true, an explicit subcommand always
        // wins -- the default-guessing logic only applies when the user
        // didn't ask for anything specific.
        let cli = Cli {
            command: Some(Command::Audit(AuditArgs {
                modules: None,
                output: OutputFormat::Json,
            })),
        };
        let resolved = cli.resolved_command_with(true);
        assert!(matches!(resolved, Command::Audit(_)));
        if let Command::Audit(args) = resolved {
            assert!(matches!(args.output, OutputFormat::Json));
        }
    }

    #[test]
    fn explicit_tui_subcommand_is_never_overridden() {
        let cli = Cli {
            command: Some(Command::Tui(TuiArgs {
                modules: Some(vec!["memory".to_string()]),
            })),
        };
        let resolved = cli.resolved_command_with(false);
        assert!(matches!(resolved, Command::Tui(_)));
        if let Command::Tui(args) = resolved {
            assert_eq!(args.modules, Some(vec!["memory".to_string()]));
        }
    }
}
