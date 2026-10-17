// SPDX-License-Identifier: GPL-3.0-only

//! KERN007 and KERN008 -- the kernel's tables of open files and of processes.
//!
//! Both are system-wide and have a fixed size. While they have room nothing
//! shows; when one is full the next program that asks for an entry is
//! refused, and what fails (a login, a service that restarts itself, a
//! database) rarely says why. The rule for "getting full" is the one in
//! [`crate::modules::saturation`]. Everything is read from `/proc`, under a
//! root, without a tool.
//!
//! What this does not look at: a single program that meets its own limit
//! (`ulimit -n`, a systemd service's `TasksMax`). Those are per-process or
//! per-service, and are not visible without walking every process.

use std::path::Path;

use crate::models::{Category, Finding};
use crate::modules::recommend::{sysctl_commands, Steps};
use crate::modules::saturation::{doubled, parse_number, read_small, Fill, Level};

const FILE_NR: &str = "proc/sys/fs/file-nr";
const LOADAVG: &str = "proc/loadavg";
const PID_MAX: &str = "proc/sys/kernel/pid_max";
const THREADS_MAX: &str = "proc/sys/kernel/threads-max";

/// The handles each program holds, the largest first: one line per process.
const COUNT_HANDLES: &str = "sudo sh -c 'for p in /proc/[0-9]*; do echo \"$(ls $p/fd \
2>/dev/null | wc -l) $(cat $p/comm 2>/dev/null)\"; done | sort -rn | head'";

/// The most `kernel.pid_max` can be on a 64-bit system (2^22).
pub const PID_MAX_LIMIT: u64 = 4_194_304;

/// Which of the two limits a new process meets first.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Limit {
    PidMax,
    ThreadsMax,
}

impl Limit {
    fn name(self) -> &'static str {
        match self {
            Limit::PidMax => "kernel.pid_max",
            Limit::ThreadsMax => "kernel.threads-max",
        }
    }
}

/// The processes and threads that exist, and the two limits on their number.
/// Each thread has its own identifier, so both count threads.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Tasks {
    pub count: u64,
    pub pid_max: Option<u64>,
    pub threads_max: Option<u64>,
}

impl Tasks {
    /// The lower of the limits that are known and not zero, and which it is;
    /// `pid_max` when they are equal. `None` when neither is known.
    pub fn binding(&self) -> Option<(Limit, u64)> {
        let pid = self.pid_max.filter(|&limit| limit > 0);
        let threads = self.threads_max.filter(|&limit| limit > 0);
        match (pid, threads) {
            (Some(pid), Some(threads)) if threads < pid => Some((Limit::ThreadsMax, threads)),
            (Some(pid), _) => Some((Limit::PidMax, pid)),
            (None, Some(threads)) => Some((Limit::ThreadsMax, threads)),
            (None, None) => None,
        }
    }
}

/// What KERN007 and KERN008 judge.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Limits {
    pub files: Option<Fill>,
    pub tasks: Option<Tasks>,
}

/// `/proc/sys/fs/file-nr`: the handles allocated, the handles allocated and
/// unused (always zero since Linux 2.6), and the maximum, separated by tabs.
pub fn parse_file_nr(text: &str) -> Option<Fill> {
    let mut fields = text.split_whitespace();
    let used = parse_number(fields.next()?)?;
    fields.next()?;
    let limit = parse_number(fields.next()?)?;
    Some(Fill { used, limit })
}

/// The number of processes and threads in `/proc/loadavg`, the second number
/// of its fourth field: `0.21 0.91 0.75 1/93 22501`.
pub fn parse_task_count(text: &str) -> Option<u64> {
    let field = text.split_whitespace().nth(3)?;
    let (running, total) = field.split_once('/')?;
    parse_number(running)?;
    parse_number(total)
}

/// The tables under `root` (`/` on a real machine).
pub fn read(root: &Path) -> Limits {
    let file = |path: &str| read_small(&root.join(path));
    let number = |path: &str| file(path).and_then(|text| parse_number(&text));
    Limits {
        files: file(FILE_NR).and_then(|text| parse_file_nr(&text)),
        tasks: file(LOADAVG)
            .and_then(|text| parse_task_count(&text))
            .map(|count| Tasks {
                count,
                pid_max: number(PID_MAX),
                threads_max: number(THREADS_MAX),
            }),
    }
}

/// KERN007 and KERN008, in that order, for what could be read.
pub fn findings(limits: &Limits) -> Vec<Finding> {
    let mut findings = Vec::new();
    findings.extend(limits.files.and_then(|fill| files_finding(&fill)));
    findings.extend(limits.tasks.and_then(|tasks| tasks_finding(&tasks)));
    findings
}

fn how_full(level: Level) -> &'static str {
    match level {
        Level::Ample => "",
        Level::Near => " That is getting full.",
        Level::Full => " That is almost full.",
    }
}

/// KERN007: the handles for open files, sockets and pipes, system-wide.
/// `None` when the limit is zero, which is no limit to compare with.
pub fn files_finding(fill: &Fill) -> Option<Finding> {
    let level = fill.level()?;
    let percent = fill.percent()?;
    let mut text = format!(
        "The system has {} file handles open out of the {} it allows (`fs.file-max`), {}%.{}",
        fill.used,
        fill.limit,
        percent,
        how_full(level)
    );
    if level != Level::Ample {
        text.push_str(
            " When the table is full, every program that opens a file or a socket is refused \
             with `Too many open files in system`: services stop answering and nobody can log \
             in. This is the table of the whole system; a single program that runs out of its \
             own descriptors (`ulimit -n`) is a different limit, which this does not look at.",
        );
    }
    let mut builder = Finding::builder(
        "KERN007",
        "File Handle Table",
        Category::Kernel,
        level.severity(),
        level.confidence(),
    )
    .evidence("open_file_handles", fill.used.to_string())
    .evidence("file_max", fill.limit.to_string())
    .evidence("usage_percent", percent.to_string())
    .explanation(text);
    if level != Level::Ample {
        builder = builder.recommendation(
            Steps::new()
                .step(
                    "Find the programs that hold the most file handles (a program that leaks \
                     them holds far more than the others):",
                    &[COUNT_HANDLES],
                )
                .step_owned(
                    "If one program holds most of them it is leaking: restart it, then look for \
                     the cause in its configuration or its latest update. If the load is \
                     legitimate, raise the limit to twice what it is now:",
                    sysctl_commands(
                        &format!("fs.file-max={}", doubled(fill.limit)),
                        "90-file-max.conf",
                    ),
                )
                .step(
                    "Check the count again (the first number is the handles in use, the last \
                     is the limit):",
                    &["cat /proc/sys/fs/file-nr"],
                )
                .build(),
        );
    }
    Some(builder.build())
}

/// KERN008: the processes and threads, against the lower of `pid_max` and
/// `threads-max`. `None` when neither limit is known.
pub fn tasks_finding(tasks: &Tasks) -> Option<Finding> {
    let (limit_in_force, limit) = tasks.binding()?;
    let fill = Fill {
        used: tasks.count,
        limit,
    };
    let level = fill.level()?;
    let percent = fill.percent()?;
    let other = match limit_in_force {
        Limit::PidMax => tasks.threads_max.map(|n| (Limit::ThreadsMax, n)),
        Limit::ThreadsMax => tasks.pid_max.map(|n| (Limit::PidMax, n)),
    };
    let mut text = format!(
        "{} processes and threads exist, {}% of the {} the kernel allows (`{}`",
        tasks.count,
        percent,
        limit,
        limit_in_force.name()
    );
    match other {
        Some((name, value)) => text.push_str(&format!(
            "; the other limit, `{}`, is {})",
            name.name(),
            value
        )),
        None => text.push(')'),
    }
    text.push('.');
    text.push_str(how_full(level));
    if level != Level::Ample {
        text.push_str(
            " When the table is full, no program can start another process or thread: `fork` \
             fails with `Resource temporarily unavailable`, new SSH sessions and scheduled \
             jobs fail, and a service cannot restart itself. A service can also meet its own \
             limit (`TasksMax` in systemd), which this does not look at.",
        );
    }
    let mut builder = Finding::builder(
        "KERN008",
        "Process and Thread Table",
        Category::Kernel,
        level.severity(),
        level.confidence(),
    )
    .evidence("processes_and_threads", tasks.count.to_string());
    if let Some(pid_max) = tasks.pid_max {
        builder = builder.evidence("pid_max", pid_max.to_string());
    }
    if let Some(threads_max) = tasks.threads_max {
        builder = builder.evidence("threads_max", threads_max.to_string());
    }
    builder = builder
        .evidence("limit_in_force", limit_in_force.name())
        .evidence("usage_percent", percent.to_string())
        .explanation(text);
    if level != Level::Ample {
        builder = builder.recommendation(tasks_steps(limit_in_force, limit).build());
    }
    Some(builder.build())
}

fn tasks_steps(limit_in_force: Limit, limit: u64) -> Steps {
    let mut steps = Steps::new().step(
        "Find the programs with the most threads (a leak shows as one program with thousands):",
        &["ps -eo nlwp,pid,comm --sort=-nlwp | head"],
    );
    let can_raise_pids = cfg!(target_pointer_width = "64") && limit < PID_MAX_LIMIT;
    steps = match limit_in_force {
        Limit::PidMax if can_raise_pids => steps.step_owned(
            "If the load is legitimate, raise the number of process identifiers to the most \
             the kernel accepts:",
            sysctl_commands(
                &format!("kernel.pid_max={PID_MAX_LIMIT}"),
                "90-pid-max.conf",
            ),
        ),
        Limit::PidMax => steps.step(
            "`kernel.pid_max` is already at the most the kernel accepts: only fewer processes \
             and threads will help, so restart the program that has too many.",
            &[],
        ),
        Limit::ThreadsMax => steps.step_owned(
            "If the load is legitimate, raise the number of threads to twice what it is now:",
            sysctl_commands(
                &format!("kernel.threads-max={}", doubled(limit)),
                "90-threads-max.conf",
            ),
        ),
    };
    steps.step(
        "Check the count again (the number after the slash is the processes and threads that \
         exist):",
        &["cut -d' ' -f4 /proc/loadavg"],
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::Severity;
    use std::fs;
    use std::path::PathBuf;

    fn evidence<'a>(finding: &'a Finding, key: &str) -> Option<&'a str> {
        finding
            .evidence
            .iter()
            .find(|(k, _)| k == key)
            .map(|(_, v)| v.as_str())
    }

    fn fill(used: u64, limit: u64) -> Fill {
        Fill { used, limit }
    }

    fn tasks(count: u64, pid_max: Option<u64>, threads_max: Option<u64>) -> Tasks {
        Tasks {
            count,
            pid_max,
            threads_max,
        }
    }

    // --- the files -----------------------------------------------------

    #[test]
    fn file_nr_is_the_handles_in_use_and_the_maximum() {
        assert_eq!(parse_file_nr("119\t0\t819675\n"), Some(fill(119, 819_675)));
        assert_eq!(parse_file_nr("1 0 2"), Some(fill(1, 2)));
        assert_eq!(parse_file_nr("  5   0   10  \n"), Some(fill(5, 10)));
        // The middle number is not read, but has to be there.
        assert_eq!(parse_file_nr("5 x 10"), Some(fill(5, 10)));
        assert_eq!(
            parse_file_nr("12\t0\t9223372036854775807\n"),
            Some(fill(12, i64::MAX as u64))
        );
        // A field added later does not hide the three first.
        assert_eq!(parse_file_nr("5 0 10 99"), Some(fill(5, 10)));
        for bad in [
            "", "\n", "5", "5 0", "x 0 10", "5 0 x", "-5 0 10", "5 0 -10", "5 0 1.5",
        ] {
            assert_eq!(parse_file_nr(bad), None, "{bad:?}");
        }
    }

    // --- the processes -------------------------------------------------

    #[test]
    fn the_task_count_is_after_the_slash_of_the_fourth_field_of_loadavg() {
        for (text, count) in [
            ("0.21 0.91 0.75 1/93 22501\n", Some(93)),
            ("0.00 0.00 0.00 0/1 1", Some(1)),
            ("12.50 8.00 4.25 31/4096 99999", Some(4096)),
            ("0.21 0.91 0.75 1/93", Some(93)),
            ("0.21 0.91 0.75 1/x 5", None),
            ("0.21 0.91 0.75 193 5", None),
            ("0.21 0.91 0.75 /93 5", None),
            ("0.21 0.91 0.75 x/93 5", None),
            ("0.21 0.91 0.75", None),
            ("0.21 0.91", None),
            ("", None),
            ("0.21 0.91 0.75 1/-93 5", None),
        ] {
            assert_eq!(parse_task_count(text), count, "{text:?}");
        }
    }

    #[test]
    fn the_limit_in_force_is_the_lower_one_and_pid_max_when_equal() {
        for (pid, threads, expected) in [
            (Some(32_768), Some(64_088), Some((Limit::PidMax, 32_768))),
            (
                Some(4_194_304),
                Some(64_088),
                Some((Limit::ThreadsMax, 64_088)),
            ),
            (Some(100), Some(100), Some((Limit::PidMax, 100))),
            (Some(100), Some(101), Some((Limit::PidMax, 100))),
            (Some(101), Some(100), Some((Limit::ThreadsMax, 100))),
            (Some(100), None, Some((Limit::PidMax, 100))),
            (None, Some(100), Some((Limit::ThreadsMax, 100))),
            (None, None, None),
            // A limit of zero is not a limit to compare with.
            (Some(0), Some(100), Some((Limit::ThreadsMax, 100))),
            (Some(100), Some(0), Some((Limit::PidMax, 100))),
            (Some(0), Some(0), None),
            (Some(0), None, None),
            // The smallest limit there is, one, is a limit.
            (Some(1), None, Some((Limit::PidMax, 1))),
            (None, Some(1), Some((Limit::ThreadsMax, 1))),
            (Some(1), Some(1), Some((Limit::PidMax, 1))),
            (Some(5), Some(1), Some((Limit::ThreadsMax, 1))),
            (Some(1), Some(5), Some((Limit::PidMax, 1))),
        ] {
            assert_eq!(
                tasks(1, pid, threads).binding(),
                expected,
                "{pid:?} {threads:?}"
            );
        }
    }

    // --- reading -------------------------------------------------------

    fn tree(name: &str) -> PathBuf {
        let root = std::env::temp_dir().join(format!(
            "linuxdoctor-kernel-limits-{name}-{}",
            std::process::id()
        ));
        let _ = fs::remove_dir_all(&root);
        fs::create_dir_all(root.join("proc/sys/fs")).unwrap();
        fs::create_dir_all(root.join("proc/sys/kernel")).unwrap();
        root
    }

    fn put(root: &Path, path: &str, text: &str) {
        fs::write(root.join(path), text).unwrap();
    }

    #[test]
    fn the_tables_are_read_under_the_root() {
        let root = tree("read");
        put(&root, FILE_NR, "119\t0\t819675\n");
        put(&root, LOADAVG, "0.21 0.91 0.75 1/93 22501\n");
        put(&root, PID_MAX, "32768\n");
        put(&root, THREADS_MAX, "64088\n");
        assert_eq!(
            read(&root),
            Limits {
                files: Some(fill(119, 819_675)),
                tasks: Some(tasks(93, Some(32_768), Some(64_088))),
            }
        );
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn what_cannot_be_read_is_left_out_and_nothing_else() {
        let root = tree("partial");
        assert_eq!(read(&root), Limits::default());
        put(&root, LOADAVG, "0.00 0.00 0.00 1/50 7\n");
        // Processes without either limit are counted but cannot be judged.
        assert_eq!(read(&root).tasks, Some(tasks(50, None, None)));
        assert_eq!(read(&root).files, None);
        put(&root, THREADS_MAX, "1000\n");
        assert_eq!(read(&root).tasks, Some(tasks(50, None, Some(1000))));
        put(&root, PID_MAX, "not a number\n");
        assert_eq!(read(&root).tasks, Some(tasks(50, None, Some(1000))));
        put(&root, FILE_NR, "garbage\n");
        assert_eq!(read(&root).files, None);
        // Limits without a count: nothing to judge.
        fs::remove_file(root.join(LOADAVG)).unwrap();
        assert_eq!(read(&root).tasks, None);
        let _ = fs::remove_dir_all(&root);
    }

    // --- KERN007 -------------------------------------------------------

    #[test]
    fn plenty_of_room_is_information_with_the_figures() {
        let f = files_finding(&fill(119, 819_675)).unwrap();
        assert_eq!(f.id, "KERN007");
        assert_eq!(f.title, "File Handle Table");
        assert_eq!(f.category, Category::Kernel);
        assert_eq!(f.severity, Severity::Info);
        assert_eq!(f.confidence.percent, 100);
        assert_eq!(f.recommendation, None);
        assert_eq!(
            f.explanation,
            "The system has 119 file handles open out of the 819675 it allows (`fs.file-max`), \
             0%."
        );
        assert_eq!(evidence(&f, "open_file_handles"), Some("119"));
        assert_eq!(evidence(&f, "file_max"), Some("819675"));
        assert_eq!(evidence(&f, "usage_percent"), Some("0"));
    }

    #[test]
    fn a_table_that_is_getting_full_is_a_warning_with_steps() {
        let f = files_finding(&fill(80_000, 100_000)).unwrap();
        assert_eq!(f.severity, Severity::Warning);
        assert_eq!(f.confidence.percent, 85);
        assert!(
            f.explanation.starts_with(
                "The system has 80000 file handles open out of the 100000 it allows \
                 (`fs.file-max`), 80%. That is getting full. When the table is full, every \
                 program that opens a file or a socket is refused with `Too many open files \
                 in system`"
            ),
            "{}",
            f.explanation
        );
        assert!(f.explanation.contains("`ulimit -n`"), "{}", f.explanation);
        let rec = f.recommendation.unwrap();
        assert!(
            rec.starts_with("1. Find the programs that hold the most file handles"),
            "{rec}"
        );
        for command in [
            "\n    sudo sh -c 'for p in /proc/[0-9]*; do echo \"$(ls $p/fd 2>/dev/null | wc -l) $(cat $p/comm 2>/dev/null)\"; done | sort -rn | head'",
            "\n    sudo sysctl fs.file-max=200000",
            "\n    echo 'fs.file-max = 200000' | sudo tee /etc/sysctl.d/90-file-max.conf",
            "\n    cat /proc/sys/fs/file-nr",
        ] {
            assert!(rec.contains(command), "{command}\n{rec}");
        }
    }

    #[test]
    fn an_almost_full_table_is_an_error() {
        let f = files_finding(&fill(95_000, 100_000)).unwrap();
        assert_eq!(f.severity, Severity::Error);
        assert_eq!(f.confidence.percent, 85);
        assert!(
            f.explanation.contains("95%. That is almost full."),
            "{}",
            f.explanation
        );
        assert!(f.recommendation.is_some());
        let at = |used: u64| files_finding(&fill(used, 100_000)).unwrap().severity;
        assert_eq!(at(79_999), Severity::Info);
        assert_eq!(at(80_000), Severity::Warning);
        assert_eq!(at(94_999), Severity::Warning);
        assert_eq!(at(95_000), Severity::Error);
    }

    #[test]
    fn the_limit_proposed_is_twice_the_current_one_and_never_too_large() {
        let rec = |used: u64, limit: u64| {
            files_finding(&fill(used, limit))
                .unwrap()
                .recommendation
                .unwrap()
        };
        assert!(
            rec(90, 100).contains("sudo sysctl fs.file-max=200\n"),
            "{}",
            rec(90, 100)
        );
        let max = i64::MAX as u64;
        let huge = rec(max, max);
        assert!(
            huge.contains(&format!("sudo sysctl fs.file-max={max}\n")),
            "{huge}"
        );
        let wrapped = rec(u64::MAX, u64::MAX);
        assert!(
            wrapped.contains(&format!("sudo sysctl fs.file-max={max}\n")),
            "{wrapped}"
        );
    }

    #[test]
    fn a_limit_of_zero_says_nothing() {
        assert!(files_finding(&fill(5, 0)).is_none());
        assert!(files_finding(&fill(0, 0)).is_none());
    }

    #[test]
    fn the_largest_limit_is_read_without_overflow() {
        let max = i64::MAX as u64;
        let f = files_finding(&fill(1_000, max)).unwrap();
        assert_eq!(f.severity, Severity::Info);
        assert_eq!(evidence(&f, "file_max"), Some("9223372036854775807"));
        assert_eq!(evidence(&f, "usage_percent"), Some("0"));
    }

    // --- KERN008 -------------------------------------------------------

    #[test]
    fn few_processes_are_information_with_both_limits_named() {
        let f = tasks_finding(&tasks(93, Some(32_768), Some(64_088))).unwrap();
        assert_eq!(f.id, "KERN008");
        assert_eq!(f.title, "Process and Thread Table");
        assert_eq!(f.category, Category::Kernel);
        assert_eq!(f.severity, Severity::Info);
        assert_eq!(f.confidence.percent, 100);
        assert_eq!(f.recommendation, None);
        assert_eq!(
            f.explanation,
            "93 processes and threads exist, 0% of the 32768 the kernel allows \
             (`kernel.pid_max`; the other limit, `kernel.threads-max`, is 64088)."
        );
        assert_eq!(evidence(&f, "processes_and_threads"), Some("93"));
        assert_eq!(evidence(&f, "pid_max"), Some("32768"));
        assert_eq!(evidence(&f, "threads_max"), Some("64088"));
        assert_eq!(evidence(&f, "limit_in_force"), Some("kernel.pid_max"));
        assert_eq!(evidence(&f, "usage_percent"), Some("0"));
    }

    #[test]
    fn the_lower_limit_is_the_one_the_figure_is_against() {
        let f = tasks_finding(&tasks(1_000, Some(4_194_304), Some(10_000))).unwrap();
        assert_eq!(evidence(&f, "limit_in_force"), Some("kernel.threads-max"));
        assert_eq!(evidence(&f, "usage_percent"), Some("10"));
        assert!(
            f.explanation.starts_with(
                "1000 processes and threads exist, 10% of the 10000 the kernel allows \
                 (`kernel.threads-max`; the other limit, `kernel.pid_max`, is 4194304)."
            ),
            "{}",
            f.explanation
        );
    }

    #[test]
    fn one_limit_known_is_named_alone() {
        let f = tasks_finding(&tasks(10, None, Some(1_000))).unwrap();
        assert_eq!(
            f.explanation,
            "10 processes and threads exist, 1% of the 1000 the kernel allows \
             (`kernel.threads-max`)."
        );
        assert_eq!(evidence(&f, "pid_max"), None);
        assert_eq!(evidence(&f, "threads_max"), Some("1000"));
        let f = tasks_finding(&tasks(10, Some(1_000), None)).unwrap();
        assert!(
            f.explanation.ends_with("(`kernel.pid_max`)."),
            "{}",
            f.explanation
        );
        assert_eq!(evidence(&f, "threads_max"), None);
    }

    #[test]
    fn no_known_limit_says_nothing() {
        assert!(tasks_finding(&tasks(10, None, None)).is_none());
        assert!(tasks_finding(&tasks(10, Some(0), Some(0))).is_none());
    }

    #[test]
    fn a_full_pid_space_is_judged_at_the_same_thresholds() {
        let at = |count: u64| {
            tasks_finding(&tasks(count, Some(1_000), None))
                .unwrap()
                .severity
        };
        assert_eq!(at(799), Severity::Info);
        assert_eq!(at(800), Severity::Warning);
        assert_eq!(at(949), Severity::Warning);
        assert_eq!(at(950), Severity::Error);
        assert_eq!(at(1_000), Severity::Error);
    }

    #[test]
    fn a_full_table_names_what_fails_and_what_it_does_not_see() {
        let f = tasks_finding(&tasks(900, Some(1_000), Some(5_000))).unwrap();
        assert_eq!(f.severity, Severity::Warning);
        assert_eq!(f.confidence.percent, 85);
        assert!(
            f.explanation.contains(
                "900 processes and threads exist, 90% of the 1000 the kernel allows \
                 (`kernel.pid_max`; the other limit, `kernel.threads-max`, is 5000). That is \
                 getting full. When the table is full, no program can start another process \
                 or thread: `fork` fails with `Resource temporarily unavailable`"
            ),
            "{}",
            f.explanation
        );
        assert!(f.explanation.contains("`TasksMax`"), "{}", f.explanation);
        let almost = tasks_finding(&tasks(990, Some(1_000), None)).unwrap();
        assert!(
            almost.explanation.contains("That is almost full."),
            "{}",
            almost.explanation
        );
        assert_eq!(almost.severity, Severity::Error);
    }

    #[test]
    fn when_pid_max_is_the_limit_the_steps_raise_it_to_the_most_the_kernel_takes() {
        let rec = tasks_finding(&tasks(900, Some(1_000), None))
            .unwrap()
            .recommendation
            .unwrap();
        assert!(
            rec.starts_with("1. Find the programs with the most threads"),
            "{rec}"
        );
        for command in [
            "\n    ps -eo nlwp,pid,comm --sort=-nlwp | head",
            "\n    sudo sysctl kernel.pid_max=4194304",
            "\n    echo 'kernel.pid_max = 4194304' | sudo tee /etc/sysctl.d/90-pid-max.conf",
            "\n    cut -d' ' -f4 /proc/loadavg",
        ] {
            assert!(rec.contains(command), "{command}\n{rec}");
        }
        assert!(!rec.contains("threads-max"), "{rec}");
    }

    #[test]
    fn a_pid_max_already_at_the_most_cannot_be_raised() {
        let f = tasks_finding(&tasks(4_000_000, Some(PID_MAX_LIMIT), None)).unwrap();
        assert_eq!(f.severity, Severity::Error);
        let rec = f.recommendation.unwrap();
        assert!(!rec.contains("sysctl"), "{rec}");
        assert!(
            rec.contains("already at the most the kernel accepts"),
            "{rec}"
        );
        // One less than the most can still be raised.
        let rec = tasks_finding(&tasks(4_000_000, Some(PID_MAX_LIMIT - 1), None))
            .unwrap()
            .recommendation
            .unwrap();
        assert!(
            rec.contains("sudo sysctl kernel.pid_max=4194304\n"),
            "{rec}"
        );
    }

    #[test]
    fn when_threads_max_is_the_limit_the_steps_double_it() {
        let rec = tasks_finding(&tasks(9_000, Some(4_194_304), Some(10_000)))
            .unwrap()
            .recommendation
            .unwrap();
        for command in [
            "\n    sudo sysctl kernel.threads-max=20000",
            "\n    echo 'kernel.threads-max = 20000' | sudo tee /etc/sysctl.d/90-threads-max.conf",
        ] {
            assert!(rec.contains(command), "{command}\n{rec}");
        }
        assert!(!rec.contains("pid_max"), "{rec}");
    }

    // --- both ----------------------------------------------------------

    #[test]
    fn the_findings_come_in_order_and_only_for_what_was_read() {
        let both = Limits {
            files: Some(fill(1, 100)),
            tasks: Some(tasks(1, Some(100), None)),
        };
        let ids: Vec<String> = findings(&both).into_iter().map(|f| f.id).collect();
        assert_eq!(ids, ["KERN007", "KERN008"]);
        let only_tasks = Limits {
            files: None,
            ..both
        };
        let ids: Vec<String> = findings(&only_tasks).into_iter().map(|f| f.id).collect();
        assert_eq!(ids, ["KERN008"]);
        let only_files = Limits {
            tasks: None,
            ..both
        };
        let ids: Vec<String> = findings(&only_files).into_iter().map(|f| f.id).collect();
        assert_eq!(ids, ["KERN007"]);
        assert!(findings(&Limits::default()).is_empty());
    }

    #[test]
    fn no_command_is_hidden_in_the_prose_of_the_steps() {
        let mut texts = vec![
            files_finding(&fill(90, 100))
                .unwrap()
                .recommendation
                .unwrap(),
            tasks_finding(&tasks(900, Some(1_000), None))
                .unwrap()
                .recommendation
                .unwrap(),
            tasks_finding(&tasks(900, Some(PID_MAX_LIMIT), Some(1_000)))
                .unwrap()
                .recommendation
                .unwrap(),
        ];
        texts.push(
            tasks_finding(&tasks(PID_MAX_LIMIT, Some(PID_MAX_LIMIT), None))
                .unwrap()
                .recommendation
                .unwrap(),
        );
        for text in texts {
            for line in text.lines().filter(|line| !line.starts_with("    ")) {
                for word in ["sudo", "sysctl", " tee ", "ps -", "cat /", "cut -d"] {
                    assert!(!line.contains(word), "{word}: {line}");
                }
            }
        }
    }
}
