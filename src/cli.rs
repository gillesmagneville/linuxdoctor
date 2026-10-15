// SPDX-License-Identifier: GPL-3.0-only

use std::io::IsTerminal;

use clap::builder::PossibleValuesParser;
use clap::{Args, CommandFactory, Parser, Subcommand, ValueEnum};
use clap_complete::Shell;

use linuxdoctor::models::Severity;

#[derive(Parser)]
#[command(
    name = "linuxdoctor",
    version,
    about = "Explainable Linux health diagnostics"
)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Option<Command>,

    /// Longest an external tool (smartctl, virsh, docker, nvidia-smi...)
    /// may run, in seconds, before LinuxDoctor stops it and reports the
    /// module's data as incomplete. Default: 10.
    #[arg(
        long,
        global = true,
        value_name = "SECONDS",
        value_parser = clap::value_parser!(u64).range(1..=3600)
    )]
    pub timeout: Option<u64>,
}

#[derive(Subcommand)]
pub enum Command {
    /// Run a health audit and print the results (also what runs with no
    /// subcommand, when stdin/stdout aren't a real terminal).
    Audit(AuditArgs),
    /// Interactive terminal UI over the same audit results (also what
    /// runs with no subcommand, when stdin/stdout are a real terminal).
    Tui(TuiArgs),
    /// Print the shell completion script for bash, zsh, fish, elvish or
    /// powershell on standard output.
    Completions(CompletionsArgs),
    /// Print the manual page (roff, for man(1)) on standard output.
    Man,
}

#[derive(Parser)]
pub struct AuditArgs {
    /// Restrict to specific modules by id (e.g. --modules memory,cpu).
    /// An unknown id is a usage error, not an empty report.
    #[arg(long, value_delimiter = ',', value_parser = module_ids())]
    pub modules: Option<Vec<String>>,

    /// Output format. `markdown` and `html` produce a complete report
    /// document (redirect it to a file); `html` is a single self-contained
    /// page.
    #[arg(long, value_enum, default_value_t = OutputFormat::Terminal)]
    pub output: OutputFormat,

    /// Only show findings at or above this severity. A display filter: it
    /// never changes the exit status (see --fail-on) and the output says
    /// how many findings it hid.
    #[arg(long, value_enum, value_name = "LEVEL")]
    pub min_severity: Option<SeverityArg>,

    /// Exit with status 1 when any finding (shown or not) is at or above
    /// this severity; `never` always exits 0 unless the audit itself
    /// fails. Default: error, i.e. Error and Critical findings fail.
    #[arg(long, value_enum, value_name = "LEVEL")]
    pub fail_on: Option<FailOnArg>,
}

#[derive(Parser)]
pub struct TuiArgs {
    /// Restrict to specific modules by id (e.g. --modules memory,cpu).
    /// An unknown id is a usage error, not an empty report.
    #[arg(long, value_delimiter = ',', value_parser = module_ids())]
    pub modules: Option<Vec<String>>,
}

#[derive(Args)]
pub struct CompletionsArgs {
    /// The shell to generate completions for.
    #[arg(value_enum)]
    pub shell: Shell,
}

/// The ids `--modules` accepts, read from the module registry so a new
/// module is accepted (and completed, and listed in the manual) the moment
/// it is registered. Before this check, a typo such as `--modules memroy`
/// selected nothing and produced an empty report that exited 0 -- a clean
/// result nobody had actually checked.
fn module_ids() -> PossibleValuesParser {
    let ids: Vec<&'static str> = linuxdoctor::modules::all_modules()
        .iter()
        .map(|module| module.id())
        .collect();
    PossibleValuesParser::new(ids)
}

/// The full command-line definition, as clap sees it. The manual page and
/// the completion scripts are generated from this, never written by hand,
/// so they cannot drift from the options the program really accepts.
pub fn definition() -> clap::Command {
    Cli::command()
}

/// The completion script for `shell`. Built in memory because
/// `clap_complete` panics if a write fails, which a closed pipe
/// (`linuxdoctor completions bash | head`) would otherwise cause.
pub fn completion_script(shell: Shell) -> Vec<u8> {
    let mut command = definition();
    let name = command.get_name().to_string();
    let mut script = Vec::new();
    clap_complete::generate(shell, &mut command, name, &mut script);
    script
}

#[derive(Copy, Clone, ValueEnum)]
pub enum OutputFormat {
    Terminal,
    Json,
    /// A Markdown report, ready for an issue, a wiki or a ticket.
    #[value(alias = "md")]
    Markdown,
    /// A single self-contained HTML page (no scripts, no external files).
    Html,
}

/// Severity as typed on the command line. Kept here, not on `Severity`,
/// so the model layer does not depend on the argument parser.
#[derive(Debug, Copy, Clone, PartialEq, Eq, ValueEnum)]
pub enum SeverityArg {
    Info,
    Warning,
    Error,
    Critical,
}

impl From<SeverityArg> for Severity {
    fn from(arg: SeverityArg) -> Self {
        match arg {
            SeverityArg::Info => Severity::Info,
            SeverityArg::Warning => Severity::Warning,
            SeverityArg::Error => Severity::Error,
            SeverityArg::Critical => Severity::Critical,
        }
    }
}

/// `--fail-on` values: the four severities, or `never`.
#[derive(Debug, Copy, Clone, PartialEq, Eq, ValueEnum)]
pub enum FailOnArg {
    Info,
    Warning,
    Error,
    Critical,
    Never,
}

impl FailOnArg {
    /// The severity from which the exit status is 1; `None` for `never`.
    pub fn threshold(self) -> Option<Severity> {
        match self {
            FailOnArg::Info => Some(Severity::Info),
            FailOnArg::Warning => Some(Severity::Warning),
            FailOnArg::Error => Some(Severity::Error),
            FailOnArg::Critical => Some(Severity::Critical),
            FailOnArg::Never => None,
        }
    }
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
        self.command.unwrap_or(if interactive {
            Command::Tui(TuiArgs { modules: None })
        } else {
            Command::Audit(AuditArgs {
                modules: None,
                output: OutputFormat::Terminal,
                min_severity: None,
                fail_on: None,
            })
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn no_subcommand_resolves_to_tui_when_interactive() {
        let cli = Cli {
            command: None,
            timeout: None,
        };
        assert!(matches!(cli.resolved_command_with(true), Command::Tui(_)));
    }

    #[test]
    fn no_subcommand_resolves_to_audit_when_not_interactive() {
        let cli = Cli {
            command: None,
            timeout: None,
        };
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
                min_severity: None,
                fail_on: None,
            })),
            timeout: None,
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
            timeout: None,
        };
        let resolved = cli.resolved_command_with(false);
        assert!(matches!(resolved, Command::Tui(_)));
        if let Command::Tui(args) = resolved {
            assert_eq!(args.modules, Some(vec!["memory".to_string()]));
        }
    }

    #[test]
    fn timeout_is_accepted_before_or_after_the_subcommand() {
        let before = Cli::try_parse_from(["linuxdoctor", "--timeout", "30", "audit"]).unwrap();
        assert_eq!(before.timeout, Some(30));
        let after = Cli::try_parse_from(["linuxdoctor", "audit", "--timeout", "30"]).unwrap();
        assert_eq!(after.timeout, Some(30));
        let bare = Cli::try_parse_from(["linuxdoctor", "--timeout", "7"]).unwrap();
        assert_eq!(bare.timeout, Some(7));
    }

    #[test]
    fn timeout_defaults_to_unset() {
        let cli = Cli::try_parse_from(["linuxdoctor", "audit"]).unwrap();
        assert_eq!(cli.timeout, None);
    }

    #[test]
    fn timeout_rejects_zero_and_non_numbers() {
        assert!(Cli::try_parse_from(["linuxdoctor", "--timeout", "0"]).is_err());
        assert!(Cli::try_parse_from(["linuxdoctor", "--timeout", "abc"]).is_err());
        assert!(Cli::try_parse_from(["linuxdoctor", "--timeout", "99999"]).is_err());
    }

    // ----- export formats and severity options ---------------------------

    fn audit_args(args: &[&str]) -> AuditArgs {
        let mut argv = vec!["linuxdoctor", "audit"];
        argv.extend_from_slice(args);
        match Cli::try_parse_from(argv).unwrap().command {
            Some(Command::Audit(a)) => a,
            _ => panic!("expected the audit subcommand"),
        }
    }

    #[test]
    fn output_accepts_markdown_html_and_the_md_alias() {
        assert!(matches!(
            audit_args(&["--output", "markdown"]).output,
            OutputFormat::Markdown
        ));
        assert!(matches!(
            audit_args(&["--output", "md"]).output,
            OutputFormat::Markdown
        ));
        assert!(matches!(
            audit_args(&["--output", "html"]).output,
            OutputFormat::Html
        ));
        assert!(matches!(
            audit_args(&["--output", "json"]).output,
            OutputFormat::Json
        ));
        assert!(Cli::try_parse_from(["linuxdoctor", "audit", "--output", "pdf"]).is_err());
    }

    #[test]
    fn severity_options_default_to_unset() {
        let a = audit_args(&[]);
        assert_eq!(a.min_severity, None);
        assert_eq!(a.fail_on, None);
    }

    #[test]
    fn min_severity_parses_every_level() {
        for (word, expected) in [
            ("info", Severity::Info),
            ("warning", Severity::Warning),
            ("error", Severity::Error),
            ("critical", Severity::Critical),
        ] {
            let a = audit_args(&["--min-severity", word]);
            assert_eq!(Severity::from(a.min_severity.unwrap()), expected, "{word}");
        }
    }

    #[test]
    fn fail_on_parses_levels_and_never() {
        assert_eq!(
            audit_args(&["--fail-on", "warning"])
                .fail_on
                .unwrap()
                .threshold(),
            Some(Severity::Warning)
        );
        assert_eq!(
            audit_args(&["--fail-on", "critical"])
                .fail_on
                .unwrap()
                .threshold(),
            Some(Severity::Critical)
        );
        assert_eq!(
            audit_args(&["--fail-on", "never"])
                .fail_on
                .unwrap()
                .threshold(),
            None
        );
    }

    #[test]
    fn severity_options_reject_unknown_words_and_are_case_sensitive() {
        assert!(Cli::try_parse_from(["linuxdoctor", "audit", "--min-severity", "high"]).is_err());
        assert!(Cli::try_parse_from(["linuxdoctor", "audit", "--fail-on", "fatal"]).is_err());
        // `never` makes sense as a threshold but not as a display filter.
        assert!(Cli::try_parse_from(["linuxdoctor", "audit", "--min-severity", "never"]).is_err());
    }

    #[test]
    fn severity_options_only_exist_on_audit() {
        assert!(Cli::try_parse_from(["linuxdoctor", "tui", "--fail-on", "error"]).is_err());
        assert!(Cli::try_parse_from(["linuxdoctor", "tui", "--min-severity", "error"]).is_err());
    }

    #[test]
    fn all_options_combine_with_modules_and_timeout() {
        let cli = Cli::try_parse_from([
            "linuxdoctor",
            "--timeout",
            "5",
            "audit",
            "--modules",
            "memory,cpu",
            "--output",
            "html",
            "--min-severity",
            "warning",
            "--fail-on",
            "never",
        ])
        .unwrap();
        assert_eq!(cli.timeout, Some(5));
        let Some(Command::Audit(a)) = cli.command else {
            panic!("expected audit");
        };
        assert_eq!(a.modules.unwrap(), ["memory", "cpu"]);
        assert!(matches!(a.output, OutputFormat::Html));
        assert_eq!(a.min_severity, Some(SeverityArg::Warning));
        assert_eq!(a.fail_on, Some(FailOnArg::Never));
    }

    // ----- completions, manual page, module ids --------------------------

    #[test]
    fn completions_takes_one_shell_and_rejects_the_others() {
        for shell in ["bash", "zsh", "fish", "elvish", "powershell"] {
            let cli = Cli::try_parse_from(["linuxdoctor", "completions", shell]).unwrap();
            assert!(
                matches!(cli.command, Some(Command::Completions(_))),
                "{shell}"
            );
        }
        assert!(Cli::try_parse_from(["linuxdoctor", "completions"]).is_err());
        assert!(Cli::try_parse_from(["linuxdoctor", "completions", "tcsh"]).is_err());
    }

    #[test]
    fn man_is_a_subcommand_without_arguments() {
        let cli = Cli::try_parse_from(["linuxdoctor", "man"]).unwrap();
        assert!(matches!(cli.command, Some(Command::Man)));
        assert!(Cli::try_parse_from(["linuxdoctor", "man", "extra"]).is_err());
    }

    #[test]
    fn modules_accepts_every_registered_id_alone_or_in_a_list() {
        for module in linuxdoctor::modules::all_modules() {
            let a = audit_args(&["--modules", module.id()]);
            assert_eq!(a.modules.unwrap(), [module.id()]);
        }
        let a = audit_args(&["--modules", "security,logs,memory"]);
        assert_eq!(a.modules.unwrap(), ["security", "logs", "memory"]);
    }

    #[test]
    fn modules_rejects_an_unknown_id_and_suggests_the_close_one() {
        // A typo used to select nothing and print an empty report, exit 0.
        let error = Cli::try_parse_from(["linuxdoctor", "audit", "--modules", "memroy"])
            .err()
            .expect("an unknown module id must not parse");
        assert_eq!(error.kind(), clap::error::ErrorKind::InvalidValue);
        let message = error.to_string();
        assert!(message.contains("memroy"), "{message}");
        assert!(message.contains("memory"), "{message}");
    }

    #[test]
    fn one_bad_id_in_a_list_rejects_the_whole_list() {
        assert!(Cli::try_parse_from(["linuxdoctor", "audit", "--modules", "memory,nope"]).is_err());
        assert!(Cli::try_parse_from(["linuxdoctor", "tui", "--modules", "nope"]).is_err());
        // Ids are exact: no silent case folding.
        assert!(Cli::try_parse_from(["linuxdoctor", "audit", "--modules", "Memory"]).is_err());
    }

    #[test]
    fn completion_scripts_know_the_commands_and_the_module_ids() {
        for (shell, marker) in [
            (Shell::Bash, "_linuxdoctor()"),
            (Shell::Zsh, "#compdef linuxdoctor"),
            (Shell::Fish, "complete -c linuxdoctor"),
        ] {
            let script = String::from_utf8(completion_script(shell)).unwrap();
            assert!(script.contains(marker), "{shell}: {marker} missing");
            for word in ["audit", "tui", "completions", "man", "fail-on", "timeout"] {
                assert!(script.contains(word), "{shell}: `{word}` missing");
            }
            for module in linuxdoctor::modules::all_modules() {
                assert!(
                    script.contains(module.id()),
                    "{shell}: module `{}` is not offered",
                    module.id()
                );
            }
        }
    }

    #[test]
    fn completion_scripts_are_deterministic() {
        for shell in [Shell::Bash, Shell::Zsh, Shell::Fish] {
            assert_eq!(completion_script(shell), completion_script(shell));
        }
    }
}
