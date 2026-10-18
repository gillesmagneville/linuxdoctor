// SPDX-License-Identifier: GPL-3.0-only

//! The optional configuration file, `~/.config/linuxdoctor/config.toml`:
//! the options a person types every time, written down once. [`EXAMPLE`] is
//! the file as the manual page and the README show it.
//!
//! Three rules keep it predictable:
//!
//! * **The command line always wins.** The file only fills in what was not
//!   typed ([`Settings::resolve`]).
//! * **Words are the words of the command line.** A value is read with the
//!   same parser as the option it stands for, so `"md"` works wherever
//!   `--output md` does, and the list of accepted words cannot drift.
//! * **A mistake is an error, never a guess.** An unknown key, a value that
//!   is not accepted or a file that cannot be read stops the program with
//!   status 2 and says where, instead of running with settings the person
//!   did not intend.
//!
//! `--modules` is deliberately not configurable: a file that quietly
//! narrowed every audit would produce clean-looking reports of checks that
//! were never made.
//!
//! The file is untrusted text like any other: its size is bounded, and
//! whatever of it is quoted in an error goes through [`text::printable`].

use std::ffi::OsStr;
use std::fs;
use std::io::{ErrorKind, Read};
use std::path::{Path, PathBuf};

use clap::ValueEnum;
use linuxdoctor::core::text;
use serde::de::{self, Deserializer};
use serde::Deserialize;
use thiserror::Error;

use crate::cli::{
    DiffFormat, FailOnArg, OutputFormat, ProfileArg, SeverityArg, MAX_TIMEOUT_SECONDS,
};

/// The file as the manual page and the README show it. Kept here, next to
/// the parser, and read by a test, so that what is documented is a file the
/// program really accepts.
pub const EXAMPLE: &str = r#"# ~/.config/linuxdoctor/config.toml
# Every line is optional. An option typed on the command line always wins
# over this file.

# Longest an external tool may run, in seconds (--timeout).
timeout = 20

# Exit with status 1 from this severity up, for audit and diff (--fail-on):
# info, warning, error, critical or never.
fail_on = "warning"

# Only show findings from this severity up (--min-severity).
min_severity = "warning"

# The kind of machine, for audit and tui (--profile): hpc or server. A profile
# only lowers findings that are normal for that kind of machine; without one,
# every finding keeps the severity its check gave it.
profile = "hpc"

[audit]
# terminal, json, markdown or html (--output).
output = "markdown"

[diff]
# terminal, json or markdown (--output).
output = "markdown"
# A section can change the lines above for its own command.
fail_on = "error"
"#;

/// A configuration file is a dozen short lines; anything beyond this is not
/// one, and is refused rather than read into memory.
pub const MAX_CONFIG_BYTES: u64 = 64 * 1024;

/// Which file to read, as chosen on the command line.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Choice {
    /// `~/.config/linuxdoctor/config.toml` (or under `$XDG_CONFIG_HOME`);
    /// not having one is normal.
    Default,
    /// `--config FILE`: the person named it, so it must exist.
    File(PathBuf),
    /// `--no-config`.
    Ignore,
}

#[derive(Debug, Error)]
pub enum ConfigError {
    #[error("could not read the configuration file {path}: {reason}")]
    Read { path: String, reason: String },
    #[error("{path} is not a regular file, so it cannot be a configuration file")]
    NotAFile { path: String },
    #[error(
        "the configuration file {path} is larger than {} KiB: that is not a LinuxDoctor \
         configuration",
        MAX_CONFIG_BYTES / 1024
    )]
    TooLarge { path: String },
    #[error("the configuration file {path} is not valid UTF-8 text")]
    NotUtf8 { path: String },
    #[error("the configuration file {path} is not valid:\n{reason}")]
    Invalid { path: String, reason: String },
}

/// The settings of one command, with the top-level lines of the file
/// already merged in: a section's own line wins over the top-level one.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Settings<F> {
    pub fail_on: Option<FailOnArg>,
    pub min_severity: Option<SeverityArg>,
    pub output: Option<F>,
}

impl<F> Default for Settings<F> {
    fn default() -> Self {
        Settings {
            fail_on: None,
            min_severity: None,
            output: None,
        }
    }
}

/// What the configuration file says. Everything is optional: an empty file,
/// or no file at all, is `Config::default()`.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Config {
    /// The file the settings were read from; `None` when there was none.
    pub source: Option<PathBuf>,
    pub timeout: Option<u64>,
    /// The kind of machine, for `audit` and `tui` (`diff` compares reports
    /// that already say which profile they were written with).
    pub profile: Option<ProfileArg>,
    pub audit: Settings<OutputFormat>,
    pub diff: Settings<DiffFormat>,
}

/// Where a setting that decides the exit status came from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Origin {
    CommandLine,
    ConfigFile,
}

/// A `--fail-on` level somebody chose, on the command line or in the file.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FailOn {
    pub level: FailOnArg,
    pub origin: Origin,
}

/// What a command runs with once the command line and the file are
/// combined.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Resolved<F> {
    pub output: F,
    pub min_severity: Option<SeverityArg>,
    /// `None` when nobody chose a level: the built-in default applies.
    pub fail_on: Option<FailOn>,
}

impl<F: Copy> Settings<F> {
    /// The command line first, then the file, then the built-in default.
    /// `typed_*` are what the person typed; `None` means they typed nothing,
    /// which is why the options have no default of their own.
    pub fn resolve(
        &self,
        typed_output: Option<F>,
        typed_min_severity: Option<SeverityArg>,
        typed_fail_on: Option<FailOnArg>,
        default_output: F,
    ) -> Resolved<F> {
        let fail_on = match (typed_fail_on, self.fail_on) {
            (Some(level), _) => Some(FailOn {
                level,
                origin: Origin::CommandLine,
            }),
            (None, Some(level)) => Some(FailOn {
                level,
                origin: Origin::ConfigFile,
            }),
            (None, None) => None,
        };
        Resolved {
            output: typed_output.or(self.output).unwrap_or(default_output),
            min_severity: typed_min_severity.or(self.min_severity),
            fail_on,
        }
    }
}

impl Config {
    /// How the level that decided the exit status was chosen, as it is
    /// quoted in the line that explains an exit status of 1.
    pub fn describe(&self, fail_on: &FailOn) -> String {
        let word = word_of(fail_on.level);
        match (fail_on.origin, &self.source) {
            (Origin::CommandLine, _) => format!("--fail-on {word}"),
            (Origin::ConfigFile, Some(path)) => {
                format!("fail_on = \"{word}\" in {}", shown(path))
            }
            (Origin::ConfigFile, None) => format!("fail_on = \"{word}\" in the configuration file"),
        }
    }
}

// ----- the shape of the file --------------------------------------------------------------------

/// A word read with the parser of the command-line option it stands for.
#[derive(Debug, Clone, Copy)]
struct Word<T>(T);

impl<'de, T: ValueEnum> Deserialize<'de> for Word<T> {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let given = String::deserialize(deserializer)?;
        match T::from_str(&given, false) {
            Ok(value) => Ok(Word(value)),
            Err(_) => Err(de::Error::custom(format!(
                "`{}` is not one of: {}",
                text::clean(&given, 40),
                accepted_words::<T>()
            ))),
        }
    }
}

/// A number of seconds in the range `--timeout` accepts.
#[derive(Debug, Clone, Copy)]
struct Seconds(u64);

impl<'de> Deserialize<'de> for Seconds {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let seconds = u64::deserialize(deserializer)?;
        if (1..=MAX_TIMEOUT_SECONDS).contains(&seconds) {
            Ok(Seconds(seconds))
        } else {
            Err(de::Error::custom(format!(
                "{seconds} is not a number of seconds between 1 and {MAX_TIMEOUT_SECONDS}"
            )))
        }
    }
}

/// `output` at the top of the file. It is declared only so that it can be
/// refused with an explanation rather than as an unknown key.
struct Misplaced;

impl<'de> Deserialize<'de> for Misplaced {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        de::IgnoredAny::deserialize(deserializer)?;
        Err(de::Error::custom(
            "`output` cannot be set at the top of the file, because audit and diff do not \
             accept the same formats; set it under [audit] or [diff]",
        ))
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields, bound(deserialize = "F: ValueEnum"))]
struct Section<F> {
    fail_on: Option<Word<FailOnArg>>,
    min_severity: Option<Word<SeverityArg>>,
    output: Option<Word<F>>,
}

impl<F> Default for Section<F> {
    fn default() -> Self {
        Section {
            fail_on: None,
            min_severity: None,
            output: None,
        }
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct FileShape {
    timeout: Option<Seconds>,
    profile: Option<Word<ProfileArg>>,
    fail_on: Option<Word<FailOnArg>>,
    min_severity: Option<Word<SeverityArg>>,
    /// Never present: deserializing it is an error (see `Misplaced`).
    #[serde(rename = "output")]
    _output: Option<Misplaced>,
    audit: Option<Section<OutputFormat>>,
    diff: Option<Section<DiffFormat>>,
}

/// Reads the text of a configuration file. Pure: no file is touched. The
/// error says what is wrong and where, in a form that is safe to print.
pub fn parse(source: &str) -> Result<Config, String> {
    let file: FileShape = toml::from_str(source).map_err(|e| describe_error(source, &e))?;
    let top_fail_on = file.fail_on.map(|word| word.0);
    let top_min_severity = file.min_severity.map(|word| word.0);
    let audit = file.audit.unwrap_or_default();
    let diff = file.diff.unwrap_or_default();
    Ok(Config {
        source: None,
        timeout: file.timeout.map(|seconds| seconds.0),
        profile: file.profile.map(|word| word.0),
        audit: Settings {
            fail_on: audit.fail_on.map(|word| word.0).or(top_fail_on),
            min_severity: audit.min_severity.map(|word| word.0).or(top_min_severity),
            output: audit.output.map(|word| word.0),
        },
        diff: Settings {
            fail_on: diff.fail_on.map(|word| word.0).or(top_fail_on),
            min_severity: diff.min_severity.map(|word| word.0).or(top_min_severity),
            output: diff.output.map(|word| word.0),
        },
    })
}

/// Longest piece of the offending line that is quoted in an error.
const MAX_QUOTED_LINE: usize = 100;

/// What is wrong, on which line, and that line. Built here rather than
/// taken from the parser's own rendering, which quotes the whole line: a
/// single line of the file may be 64 KiB long, and it is untrusted text.
fn describe_error(source: &str, error: &toml::de::Error) -> String {
    let message = text::clean(error.message(), 400);
    let Some(start) = error.span().map(|span| span.start) else {
        return message;
    };
    let Some(before) = source.get(..start) else {
        return message;
    };
    let line_number = before.matches('\n').count() + 1;
    let column = before.rsplit('\n').next().unwrap_or("").chars().count() + 1;
    let line = source.lines().nth(line_number - 1).unwrap_or("");
    format!(
        "line {line_number}, column {column}: {message}\n  {line_number} | {}",
        text::clean(line, MAX_QUOTED_LINE)
    )
}

// ----- finding and reading the file -----------------------------------------------------------------

/// Where the default configuration file is: `$XDG_CONFIG_HOME` when it is
/// set to an absolute path (the XDG rule: a relative one is ignored), else
/// `~/.config`. `None` when neither is usable, as in a bare cron job.
pub fn default_path(xdg_config_home: Option<&OsStr>, home: Option<&OsStr>) -> Option<PathBuf> {
    let base = match xdg_config_home
        .map(Path::new)
        .filter(|dir| dir.is_absolute())
    {
        Some(dir) => dir.to_path_buf(),
        None => {
            let home = Path::new(home?);
            if !home.is_absolute() {
                return None;
            }
            home.join(".config")
        }
    };
    Some(base.join("linuxdoctor").join("config.toml"))
}

/// Loads the settings the person asked for. Reads `$XDG_CONFIG_HOME` and
/// `$HOME` to find the default file.
pub fn load(choice: &Choice) -> Result<Config, ConfigError> {
    let xdg = std::env::var_os("XDG_CONFIG_HOME");
    let home = std::env::var_os("HOME");
    load_with(choice, xdg.as_deref(), home.as_deref())
}

fn load_with(
    choice: &Choice,
    xdg_config_home: Option<&OsStr>,
    home: Option<&OsStr>,
) -> Result<Config, ConfigError> {
    let (path, must_exist) = match choice {
        Choice::Ignore => return Ok(Config::default()),
        Choice::File(path) => (path.clone(), true),
        Choice::Default => match default_path(xdg_config_home, home) {
            Some(path) => (path, false),
            None => return Ok(Config::default()),
        },
    };
    let Some(source) = read_file(&path, must_exist)? else {
        return Ok(Config::default());
    };
    let mut config = parse(&source).map_err(|reason| ConfigError::Invalid {
        path: shown(&path),
        reason,
    })?;
    config.source = Some(path);
    Ok(config)
}

/// The text of the file; `None` when there is no such file and that is
/// allowed.
fn read_file(path: &Path, must_exist: bool) -> Result<Option<String>, ConfigError> {
    let read_error = |e: std::io::Error| ConfigError::Read {
        path: shown(path),
        reason: e.to_string(),
    };
    // Looked at before it is opened: opening a named pipe waits for a
    // writer that may never come.
    let metadata = match fs::metadata(path) {
        Ok(metadata) => metadata,
        Err(e) if e.kind() == ErrorKind::NotFound && !must_exist => return Ok(None),
        Err(e) => return Err(read_error(e)),
    };
    if !metadata.is_file() {
        return Err(ConfigError::NotAFile { path: shown(path) });
    }
    let mut bytes = Vec::new();
    fs::File::open(path)
        .and_then(|file| file.take(MAX_CONFIG_BYTES + 1).read_to_end(&mut bytes))
        .map_err(read_error)?;
    if bytes.len() as u64 > MAX_CONFIG_BYTES {
        return Err(ConfigError::TooLarge { path: shown(path) });
    }
    match String::from_utf8(bytes) {
        Ok(source) => Ok(Some(source)),
        Err(_) => Err(ConfigError::NotUtf8 { path: shown(path) }),
    }
}

/// A path as it is quoted in a message: one line, nothing that could act on
/// a terminal. The path may come from the environment.
fn shown(path: &Path) -> String {
    text::clean(&path.to_string_lossy(), 200)
}

fn word_of<T: ValueEnum>(value: T) -> String {
    value
        .to_possible_value()
        .map(|possible| possible.get_name().to_string())
        .unwrap_or_default()
}

fn accepted_words<T: ValueEnum>() -> String {
    T::value_variants()
        .iter()
        .filter_map(|variant| variant.to_possible_value())
        .map(|possible| possible.get_name().to_string())
        .collect::<Vec<_>>()
        .join(", ")
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::ffi::OsStrExt;

    fn parsed(source: &str) -> Config {
        parse(source).unwrap_or_else(|e| panic!("should parse:\n{source}\n{e}"))
    }

    fn error_of(source: &str) -> String {
        match parse(source) {
            Ok(config) => panic!("should be refused:\n{source}\n{config:?}"),
            Err(message) => message,
        }
    }

    const FULL: &str = r#"
timeout = 20
fail_on = "warning"
min_severity = "warning"

[audit]
output = "markdown"

[diff]
output = "json"
fail_on = "never"
"#;

    // ----- what the file can say -----------------------------------------------------

    #[test]
    fn an_empty_file_changes_nothing() {
        assert_eq!(parsed(""), Config::default());
        assert_eq!(parsed("# only a comment\n\n"), Config::default());
    }

    #[test]
    fn the_documented_example_means_what_it_says() {
        let config = parsed(FULL);
        assert_eq!(config.timeout, Some(20));
        assert_eq!(config.audit.output, Some(OutputFormat::Markdown));
        assert_eq!(config.audit.fail_on, Some(FailOnArg::Warning));
        assert_eq!(config.audit.min_severity, Some(SeverityArg::Warning));
        assert_eq!(config.diff.output, Some(DiffFormat::Json));
        // The section's own line wins over the top-level one...
        assert_eq!(config.diff.fail_on, Some(FailOnArg::Never));
        // ...and the top-level line is the default of both.
        assert_eq!(config.diff.min_severity, Some(SeverityArg::Warning));
    }

    #[test]
    fn the_example_in_the_manual_and_the_readme_is_a_file_the_program_accepts() {
        let config = parsed(EXAMPLE);
        assert_eq!(config.timeout, Some(20));
        assert_eq!(config.audit.fail_on, Some(FailOnArg::Warning));
        assert_eq!(config.audit.min_severity, Some(SeverityArg::Warning));
        assert_eq!(config.audit.output, Some(OutputFormat::Markdown));
        assert_eq!(
            config.diff.fail_on,
            Some(FailOnArg::Error),
            "the section wins"
        );
        assert_eq!(config.diff.output, Some(DiffFormat::Markdown));
        assert_eq!(config.profile, Some(ProfileArg::Hpc));
    }

    #[test]
    fn the_readme_shows_the_example_verbatim() {
        let readme = include_str!("../README.md");
        assert!(
            readme.contains(EXAMPLE),
            "README.md must contain config::EXAMPLE exactly (the section \
             \"The configuration file\")"
        );
    }

    #[test]
    fn top_level_lines_apply_to_audit_and_diff_alike() {
        let config = parsed("fail_on = \"critical\"\nmin_severity = \"error\"\n");
        for fail_on in [config.audit.fail_on, config.diff.fail_on] {
            assert_eq!(fail_on, Some(FailOnArg::Critical));
        }
        for min in [config.audit.min_severity, config.diff.min_severity] {
            assert_eq!(min, Some(SeverityArg::Error));
        }
        assert_eq!(config.audit.output, None);
        assert_eq!(config.diff.output, None);
    }

    #[test]
    fn a_section_does_not_leak_into_the_other_one() {
        let config = parsed("[audit]\nfail_on = \"never\"\nmin_severity = \"warning\"\n");
        assert_eq!(config.audit.fail_on, Some(FailOnArg::Never));
        assert_eq!(config.diff.fail_on, None);
        assert_eq!(config.diff.min_severity, None);
    }

    #[test]
    fn every_word_the_command_line_accepts_is_accepted_in_the_file() {
        // The file reads its words with the parser of the options, so a new
        // value (or alias) is available in both places at once. This is the
        // test that fails if the two ever stop sharing a parser.
        for variant in FailOnArg::value_variants() {
            let word = word_of(*variant);
            let config = parsed(&format!("fail_on = \"{word}\""));
            assert_eq!(config.audit.fail_on, Some(*variant), "fail_on = {word}");
        }
        for variant in SeverityArg::value_variants() {
            let word = word_of(*variant);
            let config = parsed(&format!("min_severity = \"{word}\""));
            assert_eq!(config.diff.min_severity, Some(*variant), "{word}");
        }
        for variant in OutputFormat::value_variants() {
            let word = word_of(*variant);
            let config = parsed(&format!("[audit]\noutput = \"{word}\""));
            assert_eq!(config.audit.output, Some(*variant), "{word}");
        }
        for variant in DiffFormat::value_variants() {
            let word = word_of(*variant);
            let config = parsed(&format!("[diff]\noutput = \"{word}\""));
            assert_eq!(config.diff.output, Some(*variant), "{word}");
        }
        for variant in ProfileArg::value_variants() {
            let word = word_of(*variant);
            let config = parsed(&format!("profile = \"{word}\""));
            assert_eq!(config.profile, Some(*variant), "profile = {word}");
        }
        // Aliases too, as on the command line.
        assert_eq!(
            parsed("[audit]\noutput = \"md\"").audit.output,
            Some(OutputFormat::Markdown)
        );
        assert_eq!(
            parsed("[diff]\noutput = \"md\"").diff.output,
            Some(DiffFormat::Markdown)
        );
    }

    #[test]
    fn no_profile_line_means_no_profile() {
        assert_eq!(parsed("").profile, None);
        assert_eq!(parsed("timeout = 5\nfail_on = \"never\"\n").profile, None);
    }

    #[test]
    fn the_server_profile_can_be_chosen_in_the_file() {
        assert_eq!(
            parsed("profile = \"server\"\n").profile,
            Some(ProfileArg::Server)
        );
    }

    #[test]
    fn the_profile_is_a_top_level_line_only() {
        // It is the kind of machine, not a setting of one command: the same
        // for every audit, in the terminal or the interactive UI.
        let message = error_of("[audit]\nprofile = \"hpc\"\n");
        assert!(message.contains("unknown field `profile`"), "{message}");
        let message = error_of("[diff]\nprofile = \"hpc\"\n");
        assert!(message.contains("unknown field `profile`"), "{message}");
    }

    #[test]
    fn an_unknown_profile_lists_the_ones_that_exist() {
        let message = error_of("profile = \"desktop\"\n");
        assert!(message.contains("line 1"), "{message}");
        assert!(message.contains("`desktop` is not one of"), "{message}");
        assert!(message.contains("hpc"), "{message}");
        assert!(message.contains("server"), "{message}");
        // Exact, like every other word.
        assert!(parse("profile = \"HPC\"").is_err());
        assert!(parse("profile = 3").is_err());
    }

    #[test]
    fn the_formats_of_each_command_are_its_own() {
        // html is a report format, not a comparison format.
        let message = error_of("[diff]\noutput = \"html\"");
        assert!(message.contains("`html` is not one of"), "{message}");
        assert!(message.contains("terminal, json, markdown"), "{message}");
        assert_eq!(
            parsed("[audit]\noutput = \"html\"").audit.output,
            Some(OutputFormat::Html)
        );
    }

    // ----- what it refuses ---------------------------------------------------------------

    #[test]
    fn an_unknown_key_is_an_error_that_names_it_and_the_line() {
        let message = error_of("timeout = 5\ncolours = true\n");
        assert!(message.contains("unknown field `colours`"), "{message}");
        assert!(message.contains("line 2"), "{message}");
        assert!(
            message.contains("timeout"),
            "the choices are listed: {message}"
        );
        // Also inside a section.
        let message = error_of("[audit]\nmodules = [\"cpu\"]\n");
        assert!(message.contains("unknown field `modules`"), "{message}");
        // And an unknown section.
        let message = error_of("[tui]\nfail_on = \"never\"\n");
        assert!(message.contains("unknown field `tui`"), "{message}");
    }

    #[test]
    fn a_word_that_is_not_accepted_lists_the_ones_that_are() {
        let message = error_of("fail_on = \"fatal\"\n");
        assert!(message.contains("line 1"), "{message}");
        assert!(message.contains("`fatal` is not one of"), "{message}");
        assert!(
            message.contains("info, warning, error, critical, never"),
            "{message}"
        );
        // `never` is a threshold, not a display filter.
        let message = error_of("min_severity = \"never\"\n");
        assert!(
            message.contains("info, warning, error, critical"),
            "{message}"
        );
        assert!(!message.contains("critical, never"), "{message}");
    }

    #[test]
    fn words_are_exact_like_on_the_command_line() {
        assert!(parse("fail_on = \"Warning\"").is_err());
        assert!(parse("fail_on = \" warning\"").is_err());
        assert!(parse("[audit]\noutput = \"MD\"").is_err());
    }

    #[test]
    fn a_value_of_the_wrong_type_is_an_error() {
        for source in [
            "fail_on = 3",
            "fail_on = true",
            "timeout = \"20\"",
            "timeout = 2.5",
            "[audit]\noutput = [\"json\"]",
            "audit = 5",
            "diff = \"markdown\"",
        ] {
            assert!(parse(source).is_err(), "{source}");
        }
    }

    #[test]
    fn the_timeout_range_is_the_one_of_the_command_line() {
        assert_eq!(parsed("timeout = 1").timeout, Some(1));
        assert_eq!(
            parsed(&format!("timeout = {MAX_TIMEOUT_SECONDS}")).timeout,
            Some(MAX_TIMEOUT_SECONDS)
        );
        for source in [
            "timeout = 0".to_string(),
            "timeout = -5".to_string(),
            format!("timeout = {}", MAX_TIMEOUT_SECONDS + 1),
        ] {
            assert!(parse(&source).is_err(), "{source}");
        }
        let message = error_of("timeout = 0");
        assert!(message.contains("between 1 and 3600"), "{message}");
    }

    #[test]
    fn output_at_the_top_is_explained_not_just_rejected() {
        let message = error_of("output = \"json\"\n");
        assert!(message.contains("[audit] or [diff]"), "{message}");
        assert!(message.contains("line 1"), "{message}");
    }

    #[test]
    fn a_repeated_key_is_an_error_not_a_silent_last_wins() {
        assert!(parse("fail_on = \"never\"\nfail_on = \"error\"\n").is_err());
        assert!(parse("[audit]\n[audit]\n").is_err());
    }

    #[test]
    fn text_that_is_not_toml_is_an_error() {
        assert!(parse("fail_on warning").is_err());
        assert!(parse("{").is_err());
        assert!(parse("\u{0}").is_err());
    }

    // ----- the command line wins ------------------------------------------------------------

    fn audit_settings() -> Settings<OutputFormat> {
        parsed(FULL).audit
    }

    #[test]
    fn nothing_typed_means_the_file_then_the_default() {
        let from_file = audit_settings().resolve(None, None, None, OutputFormat::Terminal);
        assert_eq!(from_file.output, OutputFormat::Markdown);
        assert_eq!(from_file.min_severity, Some(SeverityArg::Warning));
        assert_eq!(
            from_file.fail_on,
            Some(FailOn {
                level: FailOnArg::Warning,
                origin: Origin::ConfigFile
            })
        );

        let nothing =
            Settings::<OutputFormat>::default().resolve(None, None, None, OutputFormat::Terminal);
        assert_eq!(nothing.output, OutputFormat::Terminal);
        assert_eq!(nothing.min_severity, None);
        assert_eq!(nothing.fail_on, None, "no level chosen: the default gate");
    }

    #[test]
    fn what_is_typed_always_beats_the_file() {
        let resolved = audit_settings().resolve(
            Some(OutputFormat::Json),
            Some(SeverityArg::Critical),
            Some(FailOnArg::Info),
            OutputFormat::Terminal,
        );
        assert_eq!(resolved.output, OutputFormat::Json);
        assert_eq!(resolved.min_severity, Some(SeverityArg::Critical));
        assert_eq!(
            resolved.fail_on,
            Some(FailOn {
                level: FailOnArg::Info,
                origin: Origin::CommandLine
            })
        );
    }

    #[test]
    fn typing_the_default_value_still_beats_the_file() {
        // `--output terminal` is a choice: the file says markdown, and the
        // person has just said otherwise.
        let resolved = audit_settings().resolve(
            Some(OutputFormat::Terminal),
            None,
            None,
            OutputFormat::Terminal,
        );
        assert_eq!(resolved.output, OutputFormat::Terminal);
    }

    #[test]
    fn each_option_is_resolved_on_its_own() {
        let resolved =
            audit_settings().resolve(None, None, Some(FailOnArg::Never), OutputFormat::Terminal);
        assert_eq!(resolved.output, OutputFormat::Markdown, "from the file");
        assert_eq!(
            resolved.min_severity,
            Some(SeverityArg::Warning),
            "the file"
        );
        assert_eq!(resolved.fail_on.unwrap().level, FailOnArg::Never, "typed");
    }

    #[test]
    fn the_exit_status_explanation_says_where_the_level_came_from() {
        let mut config = parsed(FULL);
        config.source = Some(PathBuf::from("/home/me/.config/linuxdoctor/config.toml"));
        let typed = FailOn {
            level: FailOnArg::Warning,
            origin: Origin::CommandLine,
        };
        let configured = FailOn {
            level: FailOnArg::Critical,
            origin: Origin::ConfigFile,
        };
        assert_eq!(config.describe(&typed), "--fail-on warning");
        assert_eq!(
            config.describe(&configured),
            "fail_on = \"critical\" in /home/me/.config/linuxdoctor/config.toml"
        );
    }

    // ----- where the file is -------------------------------------------------------------------

    #[test]
    fn the_default_file_is_under_xdg_config_home_then_under_home() {
        let os = |s: &'static str| Some(OsStr::new(s));
        assert_eq!(
            default_path(os("/xdg"), os("/home/me")),
            Some(PathBuf::from("/xdg/linuxdoctor/config.toml"))
        );
        assert_eq!(
            default_path(None, os("/home/me")),
            Some(PathBuf::from("/home/me/.config/linuxdoctor/config.toml"))
        );
    }

    #[test]
    fn an_unusable_xdg_config_home_is_ignored_as_the_xdg_rule_says() {
        let os = |s: &'static str| Some(OsStr::new(s));
        for unusable in ["", "relative/dir", "."] {
            assert_eq!(
                default_path(os(unusable), os("/home/me")),
                Some(PathBuf::from("/home/me/.config/linuxdoctor/config.toml")),
                "{unusable:?}"
            );
        }
    }

    #[test]
    fn without_a_usable_home_there_is_no_default_file() {
        let os = |s: &'static str| Some(OsStr::new(s));
        assert_eq!(default_path(None, None), None);
        assert_eq!(default_path(None, os("")), None);
        assert_eq!(default_path(os("relative"), os("relative/home")), None);
    }

    // ----- reading it ------------------------------------------------------------------------

    struct Dir(PathBuf);

    impl Dir {
        fn new(name: &str) -> Dir {
            let dir = std::env::temp_dir()
                .join(format!("linuxdoctor-config-{name}-{}", std::process::id()));
            let _ = fs::remove_dir_all(&dir);
            fs::create_dir_all(&dir).unwrap();
            Dir(dir)
        }

        fn file(&self, name: &str, content: impl AsRef<[u8]>) -> PathBuf {
            let path = self.0.join(name);
            fs::write(&path, content).unwrap();
            path
        }
    }

    impl Drop for Dir {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    #[test]
    fn a_file_is_read_and_remembers_where_it_came_from() {
        let dir = Dir::new("read");
        let path = dir.file("c.toml", FULL);
        let config = load_with(&Choice::File(path.clone()), None, None).unwrap();
        assert_eq!(config.source, Some(path));
        assert_eq!(config.timeout, Some(20));
    }

    #[test]
    fn no_default_file_is_normal_but_a_named_one_must_exist() {
        let dir = Dir::new("missing");
        let xdg = dir.0.clone();
        // The default file does not exist: nothing is configured, no error.
        assert_eq!(
            load_with(&Choice::Default, Some(xdg.as_os_str()), None).unwrap(),
            Config::default()
        );
        // A file named with --config does: the person meant it.
        let error = load_with(&Choice::File(dir.0.join("nope.toml")), None, None).unwrap_err();
        assert!(matches!(error, ConfigError::Read { .. }), "{error}");
        assert!(error.to_string().contains("nope.toml"), "{error}");
    }

    #[test]
    fn the_default_file_is_found_under_xdg_config_home() {
        let dir = Dir::new("xdg");
        fs::create_dir_all(dir.0.join("linuxdoctor")).unwrap();
        fs::write(dir.0.join("linuxdoctor/config.toml"), "timeout = 7\n").unwrap();
        let config = load_with(&Choice::Default, Some(dir.0.as_os_str()), None).unwrap();
        assert_eq!(config.timeout, Some(7));
        assert_eq!(
            config.source,
            Some(dir.0.join("linuxdoctor").join("config.toml"))
        );
    }

    #[test]
    fn no_config_reads_nothing_even_if_the_file_is_broken() {
        let dir = Dir::new("ignore");
        fs::create_dir_all(dir.0.join("linuxdoctor")).unwrap();
        fs::write(dir.0.join("linuxdoctor/config.toml"), "this is not toml").unwrap();
        let config = load_with(&Choice::Ignore, Some(dir.0.as_os_str()), None).unwrap();
        assert_eq!(config, Config::default());
        // While the same file, read, is an error.
        assert!(load_with(&Choice::Default, Some(dir.0.as_os_str()), None).is_err());
    }

    #[test]
    fn a_broken_file_is_an_error_that_names_the_file_and_the_line() {
        let dir = Dir::new("broken");
        let path = dir.file("c.toml", "timeout = 5\nfail_on = \"fatal\"\n");
        let error = load_with(&Choice::File(path), None, None).unwrap_err();
        let message = error.to_string();
        assert!(matches!(error, ConfigError::Invalid { .. }), "{message}");
        assert!(message.contains("c.toml"), "{message}");
        assert!(message.contains("line 2"), "{message}");
        assert!(message.contains("`fatal` is not one of"), "{message}");
    }

    #[test]
    fn something_that_is_not_a_regular_file_is_refused_without_being_opened() {
        let dir = Dir::new("not-a-file");
        let error = load_with(&Choice::File(dir.0.clone()), None, None).unwrap_err();
        assert!(matches!(error, ConfigError::NotAFile { .. }), "{error}");
        // A named pipe would make open() wait for a writer forever.
        let fifo = dir.0.join("pipe");
        let made = std::process::Command::new("mkfifo").arg(&fifo).status();
        if made.map(|status| status.success()).unwrap_or(false) {
            let error = load_with(&Choice::File(fifo), None, None).unwrap_err();
            assert!(matches!(error, ConfigError::NotAFile { .. }), "{error}");
        }
    }

    #[test]
    fn a_huge_file_is_refused_and_a_big_one_is_not() {
        let dir = Dir::new("size");
        let max = MAX_CONFIG_BYTES as usize;
        let comment = |bytes: usize| format!("#{}\n", "x".repeat(bytes - 2));
        let fits = dir.file("fits.toml", comment(max));
        assert!(load_with(&Choice::File(fits), None, None).is_ok());
        let over = dir.file("over.toml", comment(max + 1));
        let error = load_with(&Choice::File(over), None, None).unwrap_err();
        assert!(matches!(error, ConfigError::TooLarge { .. }), "{error}");
        assert!(error.to_string().contains("64 KiB"), "{error}");
    }

    #[test]
    fn a_file_that_is_not_text_is_refused() {
        let dir = Dir::new("utf8");
        let path = dir.file("c.toml", b"timeout = 5\n# \xff\xfe\n");
        let error = load_with(&Choice::File(path), None, None).unwrap_err();
        assert!(matches!(error, ConfigError::NotUtf8 { .. }), "{error}");
    }

    #[test]
    fn the_error_message_cannot_act_on_the_terminal() {
        // Control characters are not allowed in a TOML comment, so the
        // parser refuses this file and quotes the line it choked on --
        // escape sequence included.
        let dir = Dir::new("hostile");
        let path = dir.file("c.toml", "# \u{1b}[2J\u{1b}]0;pwned\u{7}\ntimeout = 5\n");
        let error = load_with(&Choice::File(path), None, None).unwrap_err();
        let message = error.to_string();
        assert!(!message.contains('\u{1b}'), "{message:?}");
        assert!(!message.contains('\u{7}'), "{message:?}");
        assert!(
            message.contains("?[2J"),
            "neutralised, not removed: {message}"
        );

        // The path is quoted on one line, too.
        let weird = Path::new(OsStr::from_bytes(b"/tmp/\x1b[2Jnope\n.toml"));
        let error = load_with(&Choice::File(weird.to_path_buf()), None, None).unwrap_err();
        let message = error.to_string();
        assert!(
            !message.contains('\u{1b}') && !message.contains('\n'),
            "{message:?}"
        );
    }

    #[test]
    fn the_word_in_an_error_is_cleaned_and_bounded() {
        let long = "x".repeat(500);
        let message = error_of(&format!("fail_on = \"{long}\""));
        assert!(!message.contains(&long), "{message}");
        assert!(message.len() < 400, "{} bytes: {message}", message.len());
        let message = error_of("fail_on = \"\\u001b[2J\"");
        assert!(!message.contains('\u{1b}'), "{message:?}");
    }
}
