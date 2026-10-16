// SPDX-License-Identifier: GPL-3.0-only

use std::io::IsTerminal;
use std::path::PathBuf;

use clap::builder::PossibleValuesParser;
use clap::{Args, CommandFactory, Parser, Subcommand, ValueEnum, ValueHint};
use clap_complete::Shell;

use linuxdoctor::models::Severity;
use linuxdoctor::profile::Profile;

/// Longest `--timeout` accepted, on the command line and in the
/// configuration file alike.
pub const MAX_TIMEOUT_SECONDS: u64 = 3600;

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
        value_parser = clap::value_parser!(u64).range(1..=MAX_TIMEOUT_SECONDS)
    )]
    pub timeout: Option<u64>,

    /// Read the settings from this file instead of
    /// ~/.config/linuxdoctor/config.toml. A file that is missing or
    /// invalid is an error.
    #[arg(
        long,
        global = true,
        value_name = "FILE",
        value_hint = ValueHint::FilePath,
        conflicts_with = "no_config"
    )]
    pub config: Option<PathBuf>,

    /// Ignore the configuration file: run with the built-in defaults and
    /// the options typed on the command line.
    #[arg(long, global = true)]
    pub no_config: bool,
}

#[derive(Subcommand)]
pub enum Command {
    /// Run a health audit and print the results (also what runs with no
    /// subcommand, when stdin/stdout aren't a real terminal).
    Audit(AuditArgs),
    /// Interactive terminal UI over the same audit results (also what
    /// runs with no subcommand, when stdin/stdout are a real terminal).
    Tui(TuiArgs),
    /// Compare two JSON reports (`audit --output json`) and show what
    /// changed between them: new findings, resolved ones, and findings
    /// that got worse or better. Exits 1 when something got worse.
    Diff(DiffArgs),
    /// Print the shell completion script for bash, zsh, fish, elvish or
    /// powershell on standard output.
    Completions(CompletionsArgs),
    /// Print the manual page (roff, for man(1)) on standard output.
    Man,
}

#[derive(Parser)]
pub struct AuditArgs {
    /// Restrict to specific modules by id (e.g. --modules memory,cpu).
    /// An unknown id is a usage error, not an empty report. A module that a
    /// profile adds (e.g. hpc) is accepted only together with that profile.
    #[arg(long, value_delimiter = ',', value_parser = module_ids())]
    pub modules: Option<Vec<String>>,

    /// Output format. `markdown` and `html` produce a complete report
    /// document (redirect it to a file); `html` is a single self-contained
    /// page. Default: terminal.
    #[arg(long, value_enum)]
    pub output: Option<OutputFormat>,

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

    /// The kind of machine being audited. Without it, every check judges the
    /// machine as a general-purpose one. A profile only ever lowers the
    /// severity of a reading that is normal for that kind of machine, says so
    /// in the finding, and is recorded in the report. It is chosen here or
    /// in the configuration file, never detected.
    #[arg(long, value_enum, value_name = "PROFILE")]
    pub profile: Option<ProfileArg>,
}

#[derive(Parser)]
pub struct TuiArgs {
    /// Restrict to specific modules by id (e.g. --modules memory,cpu).
    /// An unknown id is a usage error, not an empty report. A module that a
    /// profile adds (e.g. hpc) is accepted only together with that profile.
    #[arg(long, value_delimiter = ',', value_parser = module_ids())]
    pub modules: Option<Vec<String>>,

    /// The kind of machine being audited. Without it, every check judges the
    /// machine as a general-purpose one. A profile only ever lowers the
    /// severity of a reading that is normal for that kind of machine, says so
    /// in the finding, and is recorded in the report. It is chosen here or
    /// in the configuration file, never detected.
    #[arg(long, value_enum, value_name = "PROFILE")]
    pub profile: Option<ProfileArg>,
}

#[derive(Parser)]
pub struct DiffArgs {
    /// The earlier report, written with `linuxdoctor audit --output json`.
    /// `-` reads it from standard input.
    #[arg(value_name = "BEFORE")]
    pub before: String,

    /// The later report. `-` reads it from standard input (for one of the
    /// two reports only).
    #[arg(value_name = "AFTER")]
    pub after: String,

    /// Output format. `markdown` produces a complete document (redirect
    /// it to a file or paste it in a ticket). Default: terminal.
    #[arg(long, value_enum)]
    pub output: Option<DiffFormat>,

    /// Only show changes to findings that were at or above this severity
    /// in either report. A display filter: it never changes the exit
    /// status (see --fail-on) and the output says how many changes it hid.
    #[arg(long, value_enum, value_name = "LEVEL")]
    pub min_severity: Option<SeverityArg>,

    /// Exit with status 1 when a finding appeared, or got worse, and is now
    /// at or above this severity; `never` always exits 0 unless the
    /// reports cannot be compared. Default: error.
    #[arg(long, value_enum, value_name = "LEVEL")]
    pub fail_on: Option<FailOnArg>,
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
    let mut ids: Vec<&'static str> = linuxdoctor::modules::all_modules()
        .iter()
        .map(|module| module.id())
        .collect();
    // The modules a profile adds are known ids too; whether the profile was
    // chosen is checked once the command line and the configuration file are
    // both read (see `main`).
    ids.extend(linuxdoctor::profile::module_ids());
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

#[derive(Debug, Copy, Clone, PartialEq, Eq, ValueEnum)]
pub enum OutputFormat {
    Terminal,
    Json,
    /// A Markdown report, ready for an issue, a wiki or a ticket.
    #[value(alias = "md")]
    Markdown,
    /// A single self-contained HTML page (no scripts, no external files).
    Html,
}

/// `diff --output` values.
#[derive(Debug, Copy, Clone, PartialEq, Eq, ValueEnum)]
pub enum DiffFormat {
    Terminal,
    Json,
    /// A Markdown document, ready for an issue, a wiki or a ticket.
    #[value(alias = "md")]
    Markdown,
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

/// `--profile` values. Kept here, not on `Profile`, so the library does not
/// depend on the argument parser; a test checks every word here is a profile.
#[derive(Debug, Copy, Clone, PartialEq, Eq, ValueEnum)]
pub enum ProfileArg {
    /// A compute node, where fully used CPUs are the normal state:
    /// load-average findings are reported as informational.
    Hpc,
}

impl From<ProfileArg> for Profile {
    fn from(arg: ProfileArg) -> Self {
        match arg {
            ProfileArg::Hpc => Profile::Hpc,
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
            Command::Tui(TuiArgs {
                modules: None,
                profile: None,
            })
        } else {
            Command::Audit(AuditArgs {
                modules: None,
                output: None,
                min_severity: None,
                fail_on: None,
                profile: None,
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
            config: None,
            no_config: false,
        };
        assert!(matches!(cli.resolved_command_with(true), Command::Tui(_)));
    }

    #[test]
    fn no_subcommand_resolves_to_audit_when_not_interactive() {
        let cli = Cli {
            command: None,
            timeout: None,
            config: None,
            no_config: false,
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
                output: Some(OutputFormat::Json),
                min_severity: None,
                fail_on: None,
                profile: None,
            })),
            timeout: None,
            config: None,
            no_config: false,
        };
        let resolved = cli.resolved_command_with(true);
        assert!(matches!(resolved, Command::Audit(_)));
        if let Command::Audit(args) = resolved {
            assert_eq!(args.output, Some(OutputFormat::Json));
        }
    }

    #[test]
    fn explicit_tui_subcommand_is_never_overridden() {
        let cli = Cli {
            command: Some(Command::Tui(TuiArgs {
                modules: Some(vec!["memory".to_string()]),
                profile: None,
            })),
            timeout: None,
            config: None,
            no_config: false,
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
        for (word, expected) in [
            ("markdown", OutputFormat::Markdown),
            ("md", OutputFormat::Markdown),
            ("html", OutputFormat::Html),
            ("json", OutputFormat::Json),
            ("terminal", OutputFormat::Terminal),
        ] {
            assert_eq!(
                audit_args(&["--output", word]).output,
                Some(expected),
                "{word}"
            );
        }
        assert!(Cli::try_parse_from(["linuxdoctor", "audit", "--output", "pdf"]).is_err());
    }

    // ----- diff ---------------------------------------------------------------

    fn diff_args(args: &[&str]) -> DiffArgs {
        let mut argv = vec!["linuxdoctor", "diff"];
        argv.extend_from_slice(args);
        match Cli::try_parse_from(argv).unwrap().command {
            Some(Command::Diff(a)) => a,
            _ => panic!("expected the diff subcommand"),
        }
    }

    #[test]
    fn diff_takes_the_earlier_report_then_the_later_one() {
        let a = diff_args(&["before.json", "after.json"]);
        assert_eq!(a.before, "before.json");
        assert_eq!(a.after, "after.json");
        assert_eq!(
            a.output, None,
            "unset: the configuration or the default decides"
        );
        assert_eq!(a.min_severity, None);
        assert_eq!(a.fail_on, None);
    }

    #[test]
    fn diff_reads_a_lone_dash_as_standard_input() {
        let a = diff_args(&["before.json", "-"]);
        assert_eq!(a.after, "-");
    }

    #[test]
    fn diff_needs_both_reports() {
        assert!(Cli::try_parse_from(["linuxdoctor", "diff"]).is_err());
        assert!(Cli::try_parse_from(["linuxdoctor", "diff", "only-one.json"]).is_err());
        assert!(Cli::try_parse_from(["linuxdoctor", "diff", "a", "b", "c"]).is_err());
    }

    #[test]
    fn diff_has_the_severity_options_of_audit() {
        let a = diff_args(&["a", "b", "--min-severity", "warning", "--fail-on", "never"]);
        assert_eq!(a.min_severity, Some(SeverityArg::Warning));
        assert_eq!(a.fail_on, Some(FailOnArg::Never));
    }

    #[test]
    fn diff_output_has_no_html_format() {
        assert_eq!(
            diff_args(&["a", "b", "--output", "md"]).output,
            Some(DiffFormat::Markdown)
        );
        assert_eq!(
            diff_args(&["a", "b", "--output", "json"]).output,
            Some(DiffFormat::Json)
        );
        assert!(
            Cli::try_parse_from(["linuxdoctor", "diff", "a", "b", "--output", "html"]).is_err()
        );
    }

    #[test]
    fn severity_options_default_to_unset() {
        let a = audit_args(&[]);
        assert_eq!(a.min_severity, None);
        assert_eq!(a.fail_on, None);
        // Unset, not "terminal": a typed `--output terminal` must be told
        // apart from nothing typed, because the configuration file only
        // fills in what was not typed.
        assert_eq!(a.output, None);
    }

    // ----- configuration file options -----------------------------------------

    #[test]
    fn config_and_no_config_are_global_and_exclusive() {
        let cli = Cli::try_parse_from(["linuxdoctor", "audit", "--config", "/tmp/c.toml"]).unwrap();
        assert_eq!(cli.config, Some(PathBuf::from("/tmp/c.toml")));
        assert!(!cli.no_config);
        let cli = Cli::try_parse_from(["linuxdoctor", "--no-config", "diff", "a", "b"]).unwrap();
        assert!(cli.no_config);
        assert_eq!(cli.config, None);
        assert!(Cli::try_parse_from(["linuxdoctor", "--config", "x", "--no-config"]).is_err());
        assert!(Cli::try_parse_from(["linuxdoctor", "audit", "--config"]).is_err());
    }

    #[test]
    fn config_options_default_to_the_default_file() {
        let cli = Cli::try_parse_from(["linuxdoctor", "audit"]).unwrap();
        assert_eq!(cli.config, None);
        assert!(!cli.no_config);
    }

    #[test]
    fn the_timeout_limit_is_shared_with_the_configuration_file() {
        let at_limit = MAX_TIMEOUT_SECONDS.to_string();
        assert!(Cli::try_parse_from(["linuxdoctor", "--timeout", &at_limit]).is_ok());
        let over = (MAX_TIMEOUT_SECONDS + 1).to_string();
        assert!(Cli::try_parse_from(["linuxdoctor", "--timeout", &over]).is_err());
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
    fn profile_is_unset_unless_chosen() {
        assert_eq!(audit_args(&[]).profile, None);
        let cli = Cli::try_parse_from(["linuxdoctor", "tui"]).unwrap();
        let Some(Command::Tui(args)) = cli.command else {
            panic!("expected tui");
        };
        assert_eq!(args.profile, None);
    }

    #[test]
    fn profile_is_accepted_by_audit_and_tui() {
        assert_eq!(
            audit_args(&["--profile", "hpc"]).profile,
            Some(ProfileArg::Hpc)
        );
        let cli = Cli::try_parse_from(["linuxdoctor", "tui", "--profile", "hpc"]).unwrap();
        let Some(Command::Tui(args)) = cli.command else {
            panic!("expected tui");
        };
        assert_eq!(args.profile, Some(ProfileArg::Hpc));
    }

    #[test]
    fn profile_is_not_an_option_of_diff() {
        // A comparison works from the profiles the two reports record.
        assert!(Cli::try_parse_from([
            "linuxdoctor",
            "diff",
            "a.json",
            "b.json",
            "--profile",
            "hpc"
        ])
        .is_err());
    }

    #[test]
    fn profile_rejects_unknown_words_and_is_case_sensitive() {
        for word in ["desktop", "HPC", "Hpc", ""] {
            assert!(
                Cli::try_parse_from(["linuxdoctor", "audit", "--profile", word]).is_err(),
                "{word:?}"
            );
        }
    }

    #[test]
    fn every_profile_word_is_a_profile_and_every_profile_has_a_word() {
        // The library knows the profiles; the command line spells them. The
        // two lists must stay the same list.
        let words: Vec<String> = ProfileArg::value_variants()
            .iter()
            .map(|arg| arg.to_possible_value().unwrap().get_name().to_string())
            .collect();
        for word in &words {
            let profile = Profile::from_name(word).unwrap_or_else(|| panic!("{word}"));
            assert_eq!(profile.name(), word);
        }
        for profile in Profile::ALL {
            let name = profile.name().to_string();
            assert!(words.contains(&name), "{name}");
            let arg = ProfileArg::from_str(profile.name(), false).unwrap();
            assert_eq!(Profile::from(arg), profile);
        }
        assert_eq!(words.len(), Profile::ALL.len());
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
        assert_eq!(a.output, Some(OutputFormat::Html));
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
    fn modules_accepts_the_ids_a_profile_adds_and_completions_offer_them() {
        let ids = linuxdoctor::profile::module_ids();
        assert!(!ids.is_empty());
        for id in ids {
            let a = audit_args(&["--modules", id]);
            assert_eq!(a.modules.unwrap(), [id]);
            let t = Cli::try_parse_from(["linuxdoctor", "tui", "--modules", id]);
            assert!(t.is_ok(), "tui --modules {id}");
            let script = String::from_utf8(completion_script(Shell::Bash)).unwrap();
            assert!(script.contains(id), "{id} not offered by the completions");
        }
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
