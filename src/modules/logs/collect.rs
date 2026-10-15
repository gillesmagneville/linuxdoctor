// SPDX-License-Identifier: GPL-3.0-only

//! The I/O side of the logs module: ask `journalctl`, read `auth.log` or
//! `secure`, run `dmesg`, look at the journal's directory and walk
//! `/var/log`. The decisions about what to use when a source is missing
//! are in [`assemble`], a pure function, so they are tested without a
//! journal.
//!
//! Strictly read-only. Nothing here needs root, but without it the journal
//! shows only the user's own entries and the classic log files are usually
//! unreadable; the module says so (see [`Gap`]) instead of reporting a
//! clean bill of health it could not verify.

use std::fs::{self, File};
use std::io::{self, Read, Seek, SeekFrom};
use std::path::Path;
use std::time::{Duration, Instant};

use crate::core::command::command;
use crate::core::context::effective_uid;
use crate::core::error::ModuleError;
use crate::core::parallel::parallel_map;

use super::auth::WINDOW_HOURS;
use super::health::{
    parse_journald_conf, read_journald_messages, JournalInfo, JournaldConfig, LogFile, LogFiles,
    Storage,
};
use super::journal::{parse_dmesg, parse_journal_json, parse_syslog, Entry};
use super::text::clean;

const AUTH_LIMIT: usize = 50_000;
const ERRORS_LIMIT: usize = 5_000;
const KERNEL_LIMIT: usize = 20_000;
const JOURNALD_LIMIT: usize = 2_000;

/// Classic authentication logs, in the order they are tried.
pub const AUTH_FILES: [&str; 2] = ["/var/log/auth.log", "/var/log/secure"];
/// How much of the end of a log file is read.
const TAIL_BYTES: u64 = 8 * 1024 * 1024;
/// Files of at least this size are listed.
const LISTED_FROM: u64 = 1024 * 1024;
const WALK_BUDGET: Duration = Duration::from_secs(2);
const WALK_MAX_ENTRIES: usize = 50_000;
const WALK_MAX_DEPTH: usize = 3;

// ---------------------------------------------------------------------------
// What was read
// ---------------------------------------------------------------------------

/// A stream of log lines and where it came from.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Source {
    /// `systemd journal`, `/var/log/auth.log`, `dmesg`...
    pub name: String,
    pub entries: Vec<Entry>,
    /// More lines exist than were read; the oldest were left out.
    pub truncated: bool,
}

/// Something that could not be read, and why.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Gap {
    pub what: String,
    pub why: String,
    /// Membership of the `adm` / `systemd-journal` group would fix it.
    pub group_fixes_it: bool,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct LogsRawData {
    pub is_root: bool,
    pub auth: Option<Source>,
    pub errors: Option<Source>,
    pub kernel: Option<Source>,
    pub journal: JournalInfo,
    pub files: LogFiles,
    pub gaps: Vec<Gap>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Problem {
    /// The journal exists but this user may not read it.
    NoAccess,
    /// `journalctl` failed or did not answer.
    Failed(String),
}

/// The answer of one `journalctl` query.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct JournalAnswer {
    pub entries: Vec<Entry>,
    pub truncated: bool,
    pub problem: Option<Problem>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FileProblem {
    NotFound,
    Denied,
    Other(String),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FileRead {
    pub path: String,
    pub result: Result<(Vec<Entry>, bool), FileProblem>,
}

/// Everything read from the system, before deciding what to use.
#[derive(Debug, Clone, Default)]
pub struct Inputs {
    pub is_root: bool,
    pub journalctl_present: bool,
    pub auth: Option<JournalAnswer>,
    pub errors: Option<JournalAnswer>,
    pub kernel: Option<JournalAnswer>,
    pub journald: Option<JournalAnswer>,
    pub auth_files: Vec<FileRead>,
    /// `dmesg`: its entries, or why it failed.
    pub dmesg: Option<Result<Vec<Entry>, String>>,
    pub journal: JournalInfo,
    pub files: LogFiles,
}

// ---------------------------------------------------------------------------
// Deciding what to use (pure)
// ---------------------------------------------------------------------------

fn journal_worked(answer: &Option<JournalAnswer>) -> bool {
    answer.as_ref().is_some_and(|a| a.problem.is_none())
}

fn describe(problem: &Problem) -> String {
    match problem {
        Problem::NoAccess => {
            "the journal exists but this user may not read it, so only the user's own \
             entries are visible"
                .to_string()
        }
        Problem::Failed(why) => why.clone(),
    }
}

/// A journal that answers every query with nothing is not a quiet journal:
/// a running journald always holds at least the kernel's boot messages and
/// its own. It means journald is not running here (a container, a system
/// without systemd) or the files are out of reach.
fn mark_empty_journal(inputs: &mut Inputs) {
    let answers: Vec<&JournalAnswer> = [
        &inputs.auth,
        &inputs.errors,
        &inputs.kernel,
        &inputs.journald,
    ]
    .into_iter()
    .filter_map(|a| a.as_ref())
    .collect();
    let asked = answers.len();
    let any_problem = answers.iter().any(|a| a.problem.is_some());
    let any_entries = answers.iter().any(|a| !a.entries.is_empty());
    if inputs.journalctl_present && asked > 0 && !any_problem && !any_entries {
        let empty = Problem::Failed(
            "the journal is empty: journald is not running here (a container, for example) \
             or the logs are kept elsewhere"
                .to_string(),
        );
        for answer in [
            &mut inputs.auth,
            &mut inputs.errors,
            &mut inputs.kernel,
            &mut inputs.journald,
        ]
        .into_iter()
        .flatten()
        {
            answer.problem = Some(empty.clone());
        }
    }
}

pub fn assemble(mut inputs: Inputs) -> LogsRawData {
    mark_empty_journal(&mut inputs);
    let mut gaps: Vec<Gap> = Vec::new();
    let mut journal_gap_added = false;
    let mut note_journal = |gaps: &mut Vec<Gap>, answers: &[&Option<JournalAnswer>]| {
        if journal_gap_added {
            return;
        }
        let problem = answers
            .iter()
            .filter_map(|a| a.as_ref().and_then(|a| a.problem.as_ref()))
            .next();
        if let Some(problem) = problem {
            journal_gap_added = true;
            gaps.push(Gap {
                what: "systemd journal".to_string(),
                why: describe(problem),
                group_fixes_it: *problem == Problem::NoAccess,
            });
        }
    };

    // Authentication: the journal first, then the classic files.
    let journal_auth = inputs
        .auth
        .as_ref()
        .filter(|a| a.problem.is_none() && !a.entries.is_empty());
    let mut auth: Option<Source> = journal_auth.map(|a| Source {
        name: "systemd journal".to_string(),
        entries: a.entries.clone(),
        truncated: a.truncated,
    });
    if auth.is_none() {
        for file in &inputs.auth_files {
            if let Ok((entries, truncated)) = &file.result {
                auth = Some(Source {
                    name: file.path.clone(),
                    entries: entries.clone(),
                    truncated: *truncated,
                });
                break;
            }
        }
    }
    if auth.is_none() && journal_worked(&inputs.auth) {
        // The journal answered and simply has nothing from SSH or sudo.
        auth = Some(Source {
            name: "systemd journal".to_string(),
            ..Default::default()
        });
    }
    if auth.is_none() {
        note_journal(&mut gaps, &[&inputs.auth]);
        let mut tried: Vec<String> = Vec::new();
        let mut denied = false;
        for file in &inputs.auth_files {
            match &file.result {
                Err(FileProblem::Denied) => {
                    denied = true;
                    tried.push(format!("{} (permission denied)", file.path));
                }
                Err(FileProblem::Other(why)) => tried.push(format!("{} ({why})", file.path)),
                _ => {}
            }
        }
        let mut why = if inputs.journalctl_present {
            "the journal had nothing readable".to_string()
        } else {
            "journalctl is not installed".to_string()
        };
        if tried.is_empty() {
            why.push_str(
                " and no classic authentication log exists (/var/log/auth.log, /var/log/secure)",
            );
        } else {
            why.push_str(&format!(", and {}", tried.join(", ")));
        }
        gaps.push(Gap {
            what: "authentication log".to_string(),
            why,
            group_fixes_it: denied
                || inputs
                    .auth
                    .as_ref()
                    .is_some_and(|a| a.problem == Some(Problem::NoAccess)),
        });
    }

    // System errors: only the journal can filter by priority.
    let errors = match &inputs.errors {
        Some(a) if a.problem.is_none() => Some(Source {
            name: "systemd journal".to_string(),
            entries: a.entries.clone(),
            truncated: a.truncated,
        }),
        _ => {
            note_journal(&mut gaps, &[&inputs.errors]);
            if inputs.errors.is_none() {
                gaps.push(Gap {
                    what: "system errors".to_string(),
                    why: "they are read from the systemd journal, which is not available here"
                        .to_string(),
                    group_fixes_it: false,
                });
            }
            None
        }
    };

    // Kernel messages: the journal, or dmesg.
    let journal_kernel = inputs
        .kernel
        .as_ref()
        .filter(|a| a.problem.is_none() && !a.entries.is_empty());
    let mut kernel: Option<Source> = journal_kernel.map(|a| Source {
        name: "systemd journal".to_string(),
        entries: a.entries.clone(),
        truncated: a.truncated,
    });
    if kernel.is_none() {
        if let Some(Ok(entries)) = &inputs.dmesg {
            if !entries.is_empty() {
                kernel = Some(Source {
                    name: "dmesg".to_string(),
                    entries: entries.clone(),
                    truncated: false,
                });
            }
        }
    }
    if kernel.is_none() && journal_worked(&inputs.kernel) {
        kernel = Some(Source {
            name: "systemd journal".to_string(),
            ..Default::default()
        });
    }
    if kernel.is_none() {
        note_journal(&mut gaps, &[&inputs.kernel]);
        let why = match &inputs.dmesg {
            Some(Err(why)) => format!("dmesg: {why}"),
            Some(Ok(_)) => "dmesg printed nothing".to_string(),
            None => "dmesg is not installed".to_string(),
        };
        gaps.push(Gap {
            what: "kernel messages".to_string(),
            why,
            group_fixes_it: false,
        });
    }

    // The journal's own state.
    let mut journal = inputs.journal.clone();
    if journal_worked(&inputs.journald) {
        let entries = inputs
            .journald
            .as_ref()
            .map(|a| &a.entries[..])
            .unwrap_or(&[]);
        let (suppressed, replaced) = read_journald_messages(entries);
        journal.suppressed = suppressed;
        journal.replaced_files = replaced;
    }

    LogsRawData {
        is_root: inputs.is_root,
        auth,
        errors,
        kernel,
        journal,
        files: inputs.files,
        gaps,
    }
}

// ---------------------------------------------------------------------------
// Reading the system
// ---------------------------------------------------------------------------

pub fn collect() -> Result<LogsRawData, ModuleError> {
    let is_root = effective_uid() == Some(0);
    let journalctl_present = in_path("journalctl");

    let (auth, errors, kernel, journald) = if journalctl_present {
        let queries = [Query::Auth, Query::Errors, Query::Kernel, Query::Journald];
        let mut answers = parallel_map(&queries, 4, |q| ask_journal(*q)).into_iter();
        (
            answers.next(),
            answers.next(),
            answers.next(),
            answers.next(),
        )
    } else {
        (None, None, None, None)
    };

    // The classic files and dmesg only matter when the journal did not
    // already answer; reading them costs little but there is no point.
    let auth_wanted = !auth
        .as_ref()
        .is_some_and(|a| a.problem.is_none() && !a.entries.is_empty());
    let auth_files = if auth_wanted {
        AUTH_FILES.iter().map(|p| read_auth_file(p)).collect()
    } else {
        Vec::new()
    };
    let kernel_wanted = !kernel
        .as_ref()
        .is_some_and(|a| a.problem.is_none() && !a.entries.is_empty());
    let dmesg = if kernel_wanted { read_dmesg() } else { None };

    Ok(assemble(Inputs {
        is_root,
        journalctl_present,
        auth,
        errors,
        kernel,
        journald,
        auth_files,
        dmesg,
        journal: read_journal_info(),
        files: scan_log_dir(Path::new("/var/log"), &["journal"]),
    }))
}

/// `true` when a program of that name is in one of the `PATH` directories.
fn in_path(program: &str) -> bool {
    std::env::var_os("PATH")
        .is_some_and(|paths| std::env::split_paths(&paths).any(|dir| dir.join(program).is_file()))
}

#[derive(Clone, Copy)]
enum Query {
    Auth,
    Errors,
    Kernel,
    Journald,
}

fn journal_arguments(query: Query) -> (Vec<String>, usize) {
    let mut args: Vec<String> = [
        "--no-pager",
        "-o",
        "json",
        "--output-fields=MESSAGE,PRIORITY,SYSLOG_IDENTIFIER,_COMM,_SYSTEMD_UNIT",
    ]
    .iter()
    .map(|s| s.to_string())
    .collect();
    let (extra, limit): (Vec<String>, usize) = match query {
        Query::Auth => (
            vec![
                "--since".into(),
                format!("{WINDOW_HOURS} hours ago"),
                "-t".into(),
                "sshd".into(),
                "-t".into(),
                "sshd-session".into(),
                "-t".into(),
                "sudo".into(),
                "-t".into(),
                "su".into(),
                "-t".into(),
                "login".into(),
            ],
            AUTH_LIMIT,
        ),
        Query::Errors => (vec!["-b".into(), "-p".into(), "err".into()], ERRORS_LIMIT),
        Query::Kernel => (vec!["-k".into(), "-b".into()], KERNEL_LIMIT),
        Query::Journald => (
            vec!["-b".into(), "-u".into(), "systemd-journald.service".into()],
            JOURNALD_LIMIT,
        ),
    };
    args.extend(extra);
    args.push("-n".into());
    args.push(limit.to_string());
    (args, limit)
}

fn ask_journal(query: Query) -> JournalAnswer {
    let (args, limit) = journal_arguments(query);
    let output = match command("journalctl").args(&args).output() {
        Ok(o) => o,
        Err(e) if e.kind() == io::ErrorKind::TimedOut => {
            return JournalAnswer {
                problem: Some(Problem::Failed(
                    "journalctl did not answer in time and was stopped".to_string(),
                )),
                ..Default::default()
            }
        }
        Err(e) => {
            return JournalAnswer {
                problem: Some(Problem::Failed(format!(
                    "journalctl could not be run ({e})"
                ))),
                ..Default::default()
            }
        }
    };
    let stderr = String::from_utf8_lossy(&output.stderr);
    let entries = parse_journal_json(&String::from_utf8_lossy(&output.stdout));
    let no_access = stderr.contains("not seeing messages from other users")
        || stderr.contains("No journal files were found")
        || stderr.contains("Permission denied");
    let problem = if no_access {
        Some(Problem::NoAccess)
    } else if !output.status.success() && entries.is_empty() {
        let first = stderr.lines().find(|l| !l.trim().is_empty()).unwrap_or("");
        Some(Problem::Failed(format!(
            "journalctl failed ({})",
            clean(first.trim(), 120)
        )))
    } else {
        None
    };
    let truncated = entries.len() >= limit;
    JournalAnswer {
        entries,
        truncated,
        problem,
    }
}

/// Reads the end of a file: at most `max` bytes, starting at a line
/// boundary. The flag says whether the beginning was left out.
fn read_tail(path: &Path, max: u64) -> io::Result<(String, bool)> {
    let mut file = File::open(path)?;
    let len = file.metadata()?.len();
    let cut = len > max;
    if cut {
        file.seek(SeekFrom::Start(len - max))?;
    }
    let mut bytes = Vec::new();
    file.take(max).read_to_end(&mut bytes)?;
    let mut text = String::from_utf8_lossy(&bytes).into_owned();
    if cut {
        // The first line is probably cut in half.
        if let Some(at) = text.find('\n') {
            text.drain(..=at);
        }
    }
    Ok((text, cut))
}

fn read_auth_file(path: &str) -> FileRead {
    let result = match read_tail(Path::new(path), TAIL_BYTES) {
        Ok((text, cut)) => Ok((parse_syslog(&text), cut)),
        Err(e) if e.kind() == io::ErrorKind::NotFound => Err(FileProblem::NotFound),
        Err(e) if e.kind() == io::ErrorKind::PermissionDenied => Err(FileProblem::Denied),
        Err(e) => Err(FileProblem::Other(e.to_string())),
    };
    FileRead {
        path: path.to_string(),
        result,
    }
}

fn read_dmesg() -> Option<Result<Vec<Entry>, String>> {
    if !in_path("dmesg") {
        return None;
    }
    match command("dmesg").output() {
        Ok(o) if o.status.success() => {
            let mut entries = parse_dmesg(&String::from_utf8_lossy(&o.stdout));
            if entries.len() > KERNEL_LIMIT {
                entries.drain(..entries.len() - KERNEL_LIMIT);
            }
            Some(Ok(entries))
        }
        Ok(o) => {
            let stderr = String::from_utf8_lossy(&o.stderr);
            let first = stderr
                .lines()
                .find(|l| !l.trim().is_empty())
                .unwrap_or("failed");
            Some(Err(clean(
                first.trim().strip_prefix("dmesg: ").unwrap_or(first.trim()),
                100,
            )))
        }
        Err(e) => Some(Err(format!("could not be run ({e})"))),
    }
}

// ---------------------------------------------------------------------------
// The journal's directory and /var/log
// ---------------------------------------------------------------------------

fn read_journal_info() -> JournalInfo {
    let (storage, dir) = if Path::new("/var/log/journal").is_dir() {
        (Storage::Persistent, Some("/var/log/journal"))
    } else if Path::new("/run/log/journal").is_dir() {
        (Storage::Volatile, Some("/run/log/journal"))
    } else {
        (Storage::Absent, None)
    };
    let size_bytes = dir.map(|d| dir_size(Path::new(d), 2));

    let mut config = fs::read_to_string("/etc/systemd/journald.conf")
        .map(|t| parse_journald_conf(&t))
        .unwrap_or_default();
    for dir in [
        "/usr/lib/systemd/journald.conf.d",
        "/run/systemd/journald.conf.d",
        "/etc/systemd/journald.conf.d",
    ] {
        if let Ok(entries) = fs::read_dir(dir) {
            for entry in entries.flatten() {
                let path = entry.path();
                if path.extension().is_some_and(|e| e == "conf") {
                    if let Ok(text) = fs::read_to_string(&path) {
                        config = JournaldConfig::merge(config, parse_journald_conf(&text));
                    }
                }
            }
        }
    }
    JournalInfo {
        storage,
        size_bytes,
        size_limit_configured: config.size_limit_configured,
        ..Default::default()
    }
}

/// Total size of the regular files under `dir`, `depth` levels down.
fn dir_size(dir: &Path, depth: usize) -> u64 {
    let Ok(entries) = fs::read_dir(dir) else {
        return 0;
    };
    entries
        .flatten()
        .map(|e| match e.file_type() {
            Ok(t) if t.is_file() => e.metadata().map(|m| m.len()).unwrap_or(0),
            Ok(t) if t.is_dir() && depth > 0 => dir_size(&e.path(), depth - 1),
            _ => 0,
        })
        .sum()
}

/// Walks `root` (not following symlinks, skipping the top-level directories
/// in `skip`), adding up sizes and keeping the largest files.
pub fn scan_log_dir(root: &Path, skip: &[&str]) -> LogFiles {
    let mut out = LogFiles {
        logrotate_installed: [
            "/usr/sbin/logrotate",
            "/sbin/logrotate",
            "/usr/bin/logrotate",
            "/etc/logrotate.conf",
        ]
        .iter()
        .any(|p| Path::new(p).exists()),
        ..Default::default()
    };
    if fs::read_dir(root).is_err() {
        return out;
    }
    out.scanned = true;

    let started = Instant::now();
    let mut visited = 0usize;
    let mut stack: Vec<(std::path::PathBuf, usize)> = vec![(root.to_path_buf(), 0)];
    let mut files: Vec<LogFile> = Vec::new();
    while let Some((dir, depth)) = stack.pop() {
        let entries = match fs::read_dir(&dir) {
            Ok(e) => e,
            Err(e) => {
                if e.kind() != io::ErrorKind::NotFound {
                    out.unreadable_dirs += 1;
                }
                continue;
            }
        };
        for entry in entries.flatten() {
            visited += 1;
            if visited > WALK_MAX_ENTRIES || started.elapsed() > WALK_BUDGET {
                stack.clear();
                break;
            }
            let Ok(kind) = entry.file_type() else {
                continue;
            };
            let path = entry.path();
            if kind.is_dir() {
                let name = entry.file_name();
                let skipped = depth == 0 && skip.iter().any(|s| name == *s);
                if !skipped && depth < WALK_MAX_DEPTH {
                    stack.push((path, depth + 1));
                }
            } else if kind.is_file() {
                let size = entry.metadata().map(|m| m.len()).unwrap_or(0);
                out.total_bytes += size;
                if size >= LISTED_FROM {
                    files.push(LogFile {
                        path: clean(&path.to_string_lossy(), 120),
                        size,
                    });
                }
            }
        }
    }
    files.sort_by(|a, b| b.size.cmp(&a.size).then_with(|| a.path.cmp(&b.path)));
    files.truncate(10);
    out.largest = files;
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::modules::logs::health::Storage;

    fn answer(messages: &[(&str, &str)]) -> JournalAnswer {
        JournalAnswer {
            entries: messages.iter().map(|(i, m)| Entry::new(i, m)).collect(),
            ..Default::default()
        }
    }

    fn no_access() -> JournalAnswer {
        JournalAnswer {
            problem: Some(Problem::NoAccess),
            ..Default::default()
        }
    }

    fn file(path: &str, result: Result<(Vec<Entry>, bool), FileProblem>) -> FileRead {
        FileRead {
            path: path.into(),
            result,
        }
    }

    fn healthy() -> Inputs {
        Inputs {
            is_root: true,
            journalctl_present: true,
            auth: Some(answer(&[(
                "sshd",
                "Failed password for root from 1.2.3.4 port 1 ssh2",
            )])),
            errors: Some(answer(&[("x", "boom")])),
            kernel: Some(answer(&[("kernel", "Linux version 6.8")])),
            journald: Some(answer(&[])),
            ..Default::default()
        }
    }

    #[test]
    fn a_readable_journal_provides_everything() {
        let data = assemble(healthy());
        assert_eq!(data.auth.as_ref().unwrap().name, "systemd journal");
        assert_eq!(data.errors.as_ref().unwrap().entries.len(), 1);
        assert_eq!(data.kernel.as_ref().unwrap().name, "systemd journal");
        assert!(data.gaps.is_empty());
        assert!(data.is_root);
    }

    #[test]
    fn auth_log_file_is_used_when_the_journal_has_no_ssh_entries() {
        let mut inputs = healthy();
        inputs.auth = Some(answer(&[]));
        inputs.auth_files = vec![
            file(
                "/var/log/auth.log",
                Ok((vec![Entry::new("sshd", "x")], false)),
            ),
            file("/var/log/secure", Err(FileProblem::NotFound)),
        ];
        let data = assemble(inputs);
        assert_eq!(data.auth.unwrap().name, "/var/log/auth.log");
    }

    #[test]
    fn a_journal_that_answers_nothing_to_anything_is_not_a_quiet_one() {
        let inputs = Inputs {
            is_root: true,
            journalctl_present: true,
            auth: Some(answer(&[])),
            errors: Some(answer(&[])),
            kernel: Some(answer(&[])),
            journald: Some(answer(&[])),
            dmesg: Some(Ok(vec![Entry::new("kernel", "Linux version 6.8")])),
            ..Default::default()
        };
        let data = assemble(inputs);
        assert!(data.auth.is_none() && data.errors.is_none());
        assert_eq!(data.kernel.unwrap().name, "dmesg", "dmesg still works");
        let gap = data
            .gaps
            .iter()
            .find(|g| g.what == "systemd journal")
            .unwrap();
        assert!(gap.why.contains("the journal is empty"));
        assert!(!gap.group_fixes_it);
    }

    #[test]
    fn a_quiet_journal_without_files_is_a_quiet_day_not_a_gap() {
        let mut inputs = healthy();
        inputs.auth = Some(answer(&[]));
        inputs.auth_files = vec![
            file("/var/log/auth.log", Err(FileProblem::NotFound)),
            file("/var/log/secure", Err(FileProblem::NotFound)),
        ];
        let data = assemble(inputs);
        let auth = data.auth.unwrap();
        assert_eq!(auth.name, "systemd journal");
        assert!(auth.entries.is_empty());
        assert!(data.gaps.is_empty());
    }

    #[test]
    fn without_access_the_gap_says_what_would_fix_it() {
        let mut inputs = healthy();
        inputs.is_root = false;
        inputs.auth = Some(no_access());
        inputs.errors = Some(no_access());
        inputs.kernel = Some(no_access());
        inputs.journald = Some(no_access());
        inputs.auth_files = vec![
            file("/var/log/auth.log", Err(FileProblem::Denied)),
            file("/var/log/secure", Err(FileProblem::NotFound)),
        ];
        inputs.dmesg = Some(Err(
            "read kernel buffer failed: Operation not permitted".into()
        ));
        let data = assemble(inputs);
        assert!(data.auth.is_none() && data.errors.is_none() && data.kernel.is_none());
        let whats: Vec<&str> = data.gaps.iter().map(|g| g.what.as_str()).collect();
        assert_eq!(
            whats.iter().filter(|w| **w == "systemd journal").count(),
            1,
            "the journal is reported once, not once per query: {whats:?}"
        );
        assert!(whats.contains(&"authentication log") && whats.contains(&"kernel messages"));
        let auth_gap = data
            .gaps
            .iter()
            .find(|g| g.what == "authentication log")
            .unwrap();
        assert!(auth_gap
            .why
            .contains("/var/log/auth.log (permission denied)"));
        assert!(auth_gap.group_fixes_it);
        assert!(data
            .gaps
            .iter()
            .any(|g| g.what == "systemd journal" && g.group_fixes_it));
    }

    #[test]
    fn no_journalctl_means_files_and_dmesg() {
        let inputs = Inputs {
            is_root: true,
            journalctl_present: false,
            auth_files: vec![file(
                "/var/log/secure",
                Ok((vec![Entry::new("sshd", "x")], true)),
            )],
            dmesg: Some(Ok(vec![Entry::new("kernel", "hello")])),
            ..Default::default()
        };
        let data = assemble(inputs);
        let auth = data.auth.unwrap();
        assert_eq!(auth.name, "/var/log/secure");
        assert!(auth.truncated);
        assert_eq!(data.kernel.unwrap().name, "dmesg");
        assert!(data.errors.is_none());
        assert!(data.gaps.iter().any(|g| g.what == "system errors"));
    }

    #[test]
    fn nothing_at_all_is_three_gaps_not_a_clean_report() {
        let data = assemble(Inputs::default());
        assert!(data.auth.is_none() && data.errors.is_none() && data.kernel.is_none());
        let auth_gap = data
            .gaps
            .iter()
            .find(|g| g.what == "authentication log")
            .unwrap();
        assert!(auth_gap.why.contains("journalctl is not installed"));
        assert!(auth_gap
            .why
            .contains("no classic authentication log exists"));
        assert!(data
            .gaps
            .iter()
            .any(|g| g.what == "kernel messages" && g.why.contains("dmesg is not installed")));
    }

    #[test]
    fn a_failing_journalctl_is_reported_with_its_reason() {
        let mut inputs = healthy();
        inputs.errors = Some(JournalAnswer {
            problem: Some(Problem::Failed(
                "journalctl did not answer in time and was stopped".into(),
            )),
            ..Default::default()
        });
        let data = assemble(inputs);
        assert!(data.errors.is_none());
        let gap = data
            .gaps
            .iter()
            .find(|g| g.what == "systemd journal")
            .unwrap();
        assert!(gap.why.contains("did not answer in time"));
        assert!(!gap.group_fixes_it);
    }

    #[test]
    fn journald_complaints_fill_the_journal_info() {
        let mut inputs = healthy();
        inputs.journal = JournalInfo {
            storage: Storage::Persistent,
            ..Default::default()
        };
        inputs.journald = Some(answer(&[(
            "systemd-journald",
            "Suppressed 500 messages from app.service",
        )]));
        let data = assemble(inputs);
        assert_eq!(
            data.journal.suppressed,
            vec![("app.service".to_string(), 500)]
        );
        assert_eq!(data.journal.storage, Storage::Persistent);
    }

    // ----- real I/O, against temporary files -----

    fn temp_dir(name: &str) -> std::path::PathBuf {
        let dir =
            std::env::temp_dir().join(format!("linuxdoctor-logs-{name}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn tail_reads_the_end_from_a_line_boundary() {
        let dir = temp_dir("tail");
        let path = dir.join("log");
        let mut text = String::new();
        for i in 0..1000 {
            text.push_str(&format!("line {i:04} xxxxxxxxxx\n"));
        }
        fs::write(&path, &text).unwrap();
        let (tail, cut) = read_tail(&path, 200).unwrap();
        assert!(cut);
        assert!(
            tail.starts_with("line "),
            "starts on a whole line: {tail:?}"
        );
        assert!(tail.ends_with("line 0999 xxxxxxxxxx\n"));
        let (all, cut) = read_tail(&path, 1 << 20).unwrap();
        assert!(!cut);
        assert_eq!(all, text);
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn missing_and_unreadable_files_are_told_apart() {
        let r = read_auth_file("/nonexistent/linuxdoctor/auth.log");
        assert_eq!(r.result, Err(FileProblem::NotFound));
    }

    #[test]
    fn the_log_directory_walk_totals_sizes_and_lists_the_big_files() {
        let dir = temp_dir("walk");
        fs::create_dir_all(dir.join("app/sub")).unwrap();
        fs::create_dir_all(dir.join("journal/abc")).unwrap();
        fs::write(dir.join("small.log"), vec![b'x'; 1000]).unwrap();
        fs::write(dir.join("app/big.log"), vec![b'x'; 3 * 1024 * 1024]).unwrap();
        fs::write(dir.join("app/sub/bigger.log"), vec![b'x'; 5 * 1024 * 1024]).unwrap();
        fs::write(
            dir.join("journal/abc/system.journal"),
            vec![b'x'; 9 * 1024 * 1024],
        )
        .unwrap();
        let files = scan_log_dir(&dir, &["journal"]);
        assert!(files.scanned);
        assert_eq!(
            files.total_bytes,
            1000 + 8 * 1024 * 1024,
            "the journal is not counted"
        );
        assert_eq!(files.largest.len(), 2);
        assert!(files.largest[0].path.ends_with("bigger.log"));
        assert!(files.largest[1].path.ends_with("big.log"));
        assert_eq!(files.unreadable_dirs, 0);
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_missing_log_directory_is_not_scanned() {
        let files = scan_log_dir(Path::new("/nonexistent/linuxdoctor"), &[]);
        assert!(!files.scanned);
        assert_eq!(files.total_bytes, 0);
    }

    #[test]
    fn the_walk_does_not_follow_symlinks() {
        let dir = temp_dir("links");
        let outside = temp_dir("outside");
        fs::write(outside.join("huge.log"), vec![b'x'; 2 * 1024 * 1024]).unwrap();
        std::os::unix::fs::symlink(&outside, dir.join("link")).unwrap();
        let files = scan_log_dir(&dir, &[]);
        assert_eq!(files.total_bytes, 0);
        let _ = fs::remove_dir_all(&dir);
        let _ = fs::remove_dir_all(&outside);
    }

    #[test]
    fn the_journal_queries_have_the_expected_shape() {
        let (auth, limit) = journal_arguments(Query::Auth);
        assert_eq!(limit, AUTH_LIMIT);
        assert!(auth.windows(2).any(|w| w == ["--since", "24 hours ago"]));
        assert!(auth.windows(2).any(|w| w == ["-t", "sshd-session"]));
        assert_eq!(
            auth[auth.len() - 2..],
            ["-n".to_string(), AUTH_LIMIT.to_string()]
        );
        let (errors, _) = journal_arguments(Query::Errors);
        assert!(
            errors.windows(2).any(|w| w == ["-p", "err"]) && errors.contains(&"-b".to_string())
        );
        let (kernel, _) = journal_arguments(Query::Kernel);
        assert!(kernel.contains(&"-k".to_string()));
        // Never ask journalctl to do anything but read.
        for q in [Query::Auth, Query::Errors, Query::Kernel, Query::Journald] {
            let (args, _) = journal_arguments(q);
            assert!(!args
                .iter()
                .any(|a| a.contains("vacuum") || a.contains("rotate") || a.contains("flush")));
        }
    }

    #[test]
    fn collecting_on_this_machine_never_fails() {
        let data = collect().expect("no log source is required");
        // Whatever the host has, the module's two always-present parts exist.
        let _ = data.journal;
        let _ = data.files;
    }
}
