// SPDX-License-Identifier: GPL-3.0-only

//! The state of the logging itself: does the systemd journal survive a
//! reboot, how big has it grown, is journald dropping messages from a
//! chatty service, and is a plain log file in `/var/log` growing without
//! being rotated.
//!
//! Pure functions; the directory walk and the file reads are `collect.rs`.

use crate::models::{Category, Confidence, Finding, Severity};
use crate::modules::recommend::{Family, Steps};

use super::journal::Entry;
use super::text::{clean, human_size, is_safe_word, table, word_or};

const GIB: u64 = 1024 * 1024 * 1024;
/// systemd's own ceiling for the journal when nothing is configured:
/// 10% of the filesystem, but never more than 4 GiB.
pub const JOURNAL_DEFAULT_CAP: u64 = 4 * GIB;
/// Messages journald dropped for one service that make it a flood.
pub const SUPPRESSED_FLOOD: u64 = 1000;
/// A single log file this big has not been rotated, or is being flooded.
pub const BIG_LOG_FILE: u64 = GIB;
pub const HUGE_LOG_FILE: u64 = 10 * GIB;
/// All of `/var/log` (the journal aside) this big is worth a look.
pub const BIG_LOG_DIR: u64 = 5 * GIB;

// ---------------------------------------------------------------------------
// The journal
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum Storage {
    /// `/var/log/journal` exists: logs survive a reboot.
    Persistent,
    /// Only `/run/log/journal`: logs are in memory and vanish at reboot.
    Volatile,
    /// No journal directory at all.
    #[default]
    Absent,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct JournalInfo {
    pub storage: Storage,
    pub size_bytes: Option<u64>,
    /// `SystemMaxUse=` or `RuntimeMaxUse=` is set in journald's configuration.
    pub size_limit_configured: bool,
    /// Services journald dropped messages from, with how many: the most
    /// affected first.
    pub suppressed: Vec<(String, u64)>,
    /// Journal files journald had to replace after an unclean shutdown.
    pub replaced_files: u32,
}

/// What `journald.conf` and its drop-in files say, in the two respects
/// this module cares about.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct JournaldConfig {
    pub size_limit_configured: bool,
}

/// Reads one `journald.conf`-style file. Later files may add to what
/// earlier ones set; call it on each and combine with
/// [`JournaldConfig::merge`].
pub fn parse_journald_conf(text: &str) -> JournaldConfig {
    let mut in_journal = false;
    let mut config = JournaldConfig::default();
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') || line.starts_with(';') {
            continue;
        }
        if let Some(section) = line.strip_prefix('[').and_then(|l| l.strip_suffix(']')) {
            in_journal = section.eq_ignore_ascii_case("Journal");
            continue;
        }
        if !in_journal {
            continue;
        }
        if let Some((key, value)) = line.split_once('=') {
            let key = key.trim();
            if (key == "SystemMaxUse" || key == "RuntimeMaxUse") && !value.trim().is_empty() {
                config.size_limit_configured = true;
            }
        }
    }
    config
}

impl JournaldConfig {
    pub fn merge(self, other: JournaldConfig) -> JournaldConfig {
        JournaldConfig {
            size_limit_configured: self.size_limit_configured || other.size_limit_configured,
        }
    }
}

/// Finds journald's own complaints in its messages: `Suppressed N messages
/// from UNIT` (rate limiting kicked in) and files replaced after an unclean
/// shutdown. Returns the suppressed totals per service, most affected
/// first, and the number of replaced files.
pub fn read_journald_messages(entries: &[Entry]) -> (Vec<(String, u64)>, u32) {
    let mut suppressed: Vec<(String, u64)> = Vec::new();
    let mut replaced = 0;
    for e in entries {
        if let Some(rest) = e.message.strip_prefix("Suppressed ") {
            if let Some((count, from)) = rest.split_once(" messages from ") {
                if let Ok(count) = count.trim().parse::<u64>() {
                    let name = clean(from.trim(), 64);
                    match suppressed.iter_mut().find(|(n, _)| *n == name) {
                        Some((_, total)) => *total += count,
                        None => suppressed.push((name, count)),
                    }
                }
            }
        } else if e.message.contains("corrupted or uncleanly shut down") {
            replaced += 1;
        }
    }
    suppressed.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));
    (suppressed, replaced)
}

/// LOG008 — the journal's own state.
pub fn journal_finding(info: &JournalInfo) -> Finding {
    let flooded = info
        .suppressed
        .first()
        .filter(|(_, n)| *n >= SUPPRESSED_FLOOD);
    let too_big = info
        .size_bytes
        .is_some_and(|b| b > JOURNAL_DEFAULT_CAP && !info.size_limit_configured);
    let severity = if flooded.is_some() || too_big {
        Severity::Warning
    } else {
        Severity::Info
    };

    let mut text = String::new();
    text.push_str(match info.storage {
        Storage::Persistent => {
            "The journal is stored on disk (/var/log/journal): logs survive a reboot."
        }
        Storage::Volatile => {
            "The journal is kept in memory only (/run/log/journal) and disappears at every \
             reboot. After a crash or a power cut there is nothing left to investigate, and \
             the authentication history only goes back to the last boot."
        }
        Storage::Absent => {
            "No systemd journal directory was found. This machine either does not use \
             journald or keeps its logs elsewhere (rsyslog files in /var/log)."
        }
    });
    if let Some(size) = info.size_bytes {
        text.push_str(&format!("\n\nThe journal takes {}", human_size(size)));
        if too_big {
            text.push_str(&format!(
                ", more than the {} journald allows itself when nothing is configured. A \
                 limit was probably removed or raised by hand, so it will keep growing.",
                human_size(JOURNAL_DEFAULT_CAP)
            ));
        } else if info.size_limit_configured {
            text.push_str(", within a limit set in journald's configuration.");
        } else {
            text.push('.');
        }
    }
    if !info.suppressed.is_empty() {
        let rows: Vec<Vec<String>> = info
            .suppressed
            .iter()
            .take(6)
            .map(|(name, n)| vec![n.to_string(), name.clone()])
            .collect();
        text.push_str(
            "\n\njournald dropped messages because these services wrote faster than its rate \
             limit allows. Whatever they said in those moments is lost:\n",
        );
        text.push_str(&table(&["Dropped", "Service"], &rows));
    }
    if info.replaced_files > 0 {
        text.push_str(&format!(
            "\n\n{} journal file(s) were replaced because they were corrupted or had not been \
             closed properly. That is what an unclean shutdown (a power cut, a crash, a reset) \
             leaves behind.",
            info.replaced_files
        ));
    }

    let storage_label = match info.storage {
        Storage::Persistent => "persistent",
        Storage::Volatile => "volatile",
        Storage::Absent => "absent",
    };
    let mut builder = Finding::builder(
        "LOG008",
        "Journal",
        Category::Logs,
        severity,
        Confidence::direct_observation(),
    )
    .evidence("storage", storage_label);
    if let Some(size) = info.size_bytes {
        builder = builder.evidence("size", human_size(size));
        builder = builder.evidence(
            "size_limit",
            if info.size_limit_configured {
                "configured"
            } else {
                "default"
            },
        );
    }
    if !info.suppressed.is_empty() {
        builder = builder.evidence(
            "dropped_messages",
            info.suppressed
                .iter()
                .map(|(_, n)| n)
                .sum::<u64>()
                .to_string(),
        );
    }
    if info.replaced_files > 0 {
        builder = builder.evidence("replaced_files", info.replaced_files.to_string());
    }
    builder = builder.explanation(text);

    let mut steps = Steps::new();
    if info.storage == Storage::Volatile {
        steps = steps.step(
            "Keep the journal across reboots. Creating the directory is enough on most \
             systems; if journald is set to `Storage=volatile`, change that line in \
             /etc/systemd/journald.conf instead:",
            &[
                "sudo mkdir -p /var/log/journal",
                "sudo systemctl restart systemd-journald",
                "journalctl --disk-usage",
            ],
        );
    }
    if too_big {
        steps = steps
            .step(
                "Shrink the journal now:",
                &["journalctl --disk-usage", "sudo journalctl --vacuum-size=1G"],
            )
            .step(
                "Cap it for good, in a drop-in file so the distribution's own file stays \
                 untouched:",
                &[
                    "sudo mkdir -p /etc/systemd/journald.conf.d",
                    "printf '[Journal]\\nSystemMaxUse=1G\\n' | sudo tee /etc/systemd/journald.conf.d/50-size.conf",
                    "sudo systemctl restart systemd-journald",
                ],
            );
    }
    if let Some((name, _)) = flooded {
        let command = if is_safe_word(name) {
            format!("sudo journalctl -b -u {name} --no-pager | tail -30")
        } else {
            "sudo journalctl -b --no-pager | tail -60".to_string()
        };
        steps = steps
            .step(
                format!(
                    "Find out why {} writes so much (debug logging left on, an error \
                     repeating in a loop):",
                    word_or(name, "the noisiest service")
                ),
                &[&command],
            )
            .step(
                "Fix the cause rather than raising the limit. If the volume is legitimate, \
                 `RateLimitBurst=` in /etc/systemd/journald.conf raises it for everyone.",
                &[],
            );
    }
    if !steps.is_empty() {
        builder = builder.recommendation(steps.build());
    }
    builder.build()
}

// ---------------------------------------------------------------------------
// Log files
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LogFile {
    pub path: String,
    pub size: u64,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct LogFiles {
    /// `/var/log` was readable and walked.
    pub scanned: bool,
    /// Everything under `/var/log` except the journal.
    pub total_bytes: u64,
    /// The largest files (1 MiB and up), biggest first.
    pub largest: Vec<LogFile>,
    /// Directories that could not be listed.
    pub unreadable_dirs: u32,
    pub logrotate_installed: bool,
}

/// Compressed archives of old logs are meant to be kept for a while;
/// they are not what "never rotated" means.
fn is_compressed(path: &str) -> bool {
    [".gz", ".xz", ".zst", ".bz2", ".lz4"]
        .iter()
        .any(|ext| path.ends_with(ext))
}

impl LogFiles {
    fn worst_file(&self) -> Option<&LogFile> {
        self.largest.iter().find(|f| !is_compressed(&f.path))
    }

    pub fn severity(&self) -> Severity {
        match self.worst_file() {
            Some(f) if f.size >= HUGE_LOG_FILE => Severity::Error,
            Some(f) if f.size >= BIG_LOG_FILE => Severity::Warning,
            _ if self.total_bytes >= BIG_LOG_DIR => Severity::Warning,
            _ => Severity::Info,
        }
    }
}

/// LOG009 — log files in `/var/log`.
pub fn files_finding(files: &LogFiles, family: Family) -> Finding {
    let severity = files.severity();
    let mut text = String::new();
    if !files.scanned {
        text.push_str("/var/log could not be read, so the size of the log files is unknown.");
    } else {
        text.push_str(&format!(
            "The log files in /var/log (the journal aside) take {}.",
            human_size(files.total_bytes)
        ));
        match files.worst_file() {
            Some(f) if f.size >= BIG_LOG_FILE => text.push_str(&format!(
                " {} alone is {}: a log that size has usually never been rotated, or a \
                 program is writing to it in a loop. It can fill the disk, and a full disk \
                 stops databases, mail and logins.",
                f.path,
                human_size(f.size)
            )),
            _ if files.total_bytes >= BIG_LOG_DIR => text.push_str(
                " That is a lot of logs: rotation is probably missing or keeps too many copies.",
            ),
            _ => text.push_str(" Nothing is unusually large."),
        }
    }
    if !files.largest.is_empty() {
        let rows: Vec<Vec<String>> = files
            .largest
            .iter()
            .take(6)
            .map(|f| vec![human_size(f.size), f.path.clone()])
            .collect();
        text.push_str("\n\nLargest files:\n");
        text.push_str(&table(&["Size", "File"], &rows));
    }
    if files.unreadable_dirs > 0 {
        text.push_str(&format!(
            "\n\n{} director{} could not be listed (run with sudo to include {}).",
            files.unreadable_dirs,
            if files.unreadable_dirs == 1 {
                "y"
            } else {
                "ies"
            },
            if files.unreadable_dirs == 1 {
                "it"
            } else {
                "them"
            }
        ));
    }

    let mut builder = Finding::builder(
        "LOG009",
        "Log Files",
        Category::Logs,
        severity,
        Confidence::direct_observation(),
    )
    .evidence("scanned", if files.scanned { "yes" } else { "no" })
    .evidence("size", human_size(files.total_bytes))
    .evidence(
        "logrotate",
        if files.logrotate_installed {
            "installed"
        } else {
            "not found"
        },
    );
    if let Some(f) = files.largest.first() {
        builder = builder.evidence(
            "largest_file",
            format!("{} ({})", f.path, human_size(f.size)),
        );
    }
    builder = builder.explanation(text);

    if severity >= Severity::Warning {
        let file = files.worst_file().map(|f| f.path.as_str());
        let path = file.filter(|p| is_safe_word(p)).unwrap_or("<file>");
        let mut steps = Steps::new().step(
            "See what takes the space:",
            &["sudo du -ah /var/log 2>/dev/null | sort -rh | head -15"],
        );
        if file.is_some() {
            steps = steps.step(
                "Find which program writes to the largest file, and what it keeps saying:",
                &[
                    &format!("sudo lsof {path}"),
                    &format!("sudo tail -50 {path}"),
                ],
            );
        }
        if files.logrotate_installed {
            steps = steps.step(
                "Check why it is not rotated — a rule in /etc/logrotate.d should name it. A \
                 dry run shows what logrotate would do:",
                &[
                    &format!("grep -rn '{path}' /etc/logrotate.conf /etc/logrotate.d/"),
                    "sudo logrotate -d /etc/logrotate.conf",
                ],
            );
        } else {
            let install = match family {
                Family::DebianLike => vec!["sudo apt install logrotate".to_string()],
                Family::RedHatLike => vec!["sudo dnf install logrotate".to_string()],
                Family::Unknown => Vec::new(),
            };
            if install.is_empty() {
                steps = steps.step(
                    "logrotate was not found: install it with your package manager and give \
                     the log a rule in /etc/logrotate.d.",
                    &[],
                );
            } else {
                steps = steps.step_owned(
                    "logrotate was not found. Install it, then give the log a rule in \
                     /etc/logrotate.d:",
                    install,
                );
            }
        }
        if file.is_some() {
            steps = steps.step(
                "Free the space now. Empty the file rather than deleting it, so the program \
                 that has it open keeps writing into a file that exists — and only after \
                 checking you do not need the content:",
                &[&format!("sudo truncate -s 0 {path}")],
            );
        }
        builder = builder.recommendation(steps.build());
    }
    builder.build()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn journal(storage: Storage, size: Option<u64>) -> JournalInfo {
        JournalInfo {
            storage,
            size_bytes: size,
            ..Default::default()
        }
    }

    #[test]
    fn a_persistent_modest_journal_is_fine() {
        let f = journal_finding(&journal(Storage::Persistent, Some(300 * 1024 * 1024)));
        assert_eq!(f.severity, Severity::Info);
        assert!(f.explanation.contains("survive a reboot"));
        assert!(f.explanation.contains("300 MiB"));
        assert!(f.recommendation.is_none());
    }

    #[test]
    fn a_volatile_journal_is_information_with_the_way_to_keep_it() {
        let f = journal_finding(&journal(Storage::Volatile, None));
        assert_eq!(f.severity, Severity::Info);
        let rec = f.recommendation.unwrap();
        assert!(rec.contains("sudo mkdir -p /var/log/journal"));
        assert!(f.explanation.contains("disappears at every reboot"));
    }

    #[test]
    fn no_journal_at_all_is_not_an_error() {
        let f = journal_finding(&journal(Storage::Absent, None));
        assert_eq!(f.severity, Severity::Info);
        assert!(f.explanation.contains("rsyslog"));
    }

    #[test]
    fn an_unbounded_journal_is_a_warning_with_a_drop_in_cap() {
        let f = journal_finding(&journal(Storage::Persistent, Some(9 * GIB)));
        assert_eq!(f.severity, Severity::Warning);
        let rec = f.recommendation.unwrap();
        assert!(rec.contains("--vacuum-size=1G"));
        assert!(rec.contains("/etc/systemd/journald.conf.d/50-size.conf"));
        assert!(rec.find("vacuum").unwrap() < rec.find("journald.conf.d").unwrap());
    }

    #[test]
    fn a_big_journal_with_a_configured_limit_is_the_admins_choice() {
        let mut info = journal(Storage::Persistent, Some(9 * GIB));
        info.size_limit_configured = true;
        assert_eq!(journal_finding(&info).severity, Severity::Info);
    }

    #[test]
    fn a_flooding_service_is_a_warning() {
        let mut info = journal(Storage::Persistent, Some(GIB));
        info.suppressed = vec![("chatty.service".into(), 5000), ("other.service".into(), 3)];
        let f = journal_finding(&info);
        assert_eq!(f.severity, Severity::Warning);
        assert!(f.explanation.contains("chatty.service"));
        assert!(f
            .recommendation
            .unwrap()
            .contains("journalctl -b -u chatty.service"));
        let small = JournalInfo {
            suppressed: vec![("x.service".into(), 10)],
            ..Default::default()
        };
        assert_eq!(journal_finding(&small).severity, Severity::Info);
    }

    #[test]
    fn replaced_files_tell_of_an_unclean_shutdown() {
        let mut info = journal(Storage::Persistent, None);
        info.replaced_files = 2;
        let f = journal_finding(&info);
        assert_eq!(f.severity, Severity::Info);
        assert!(f.explanation.contains("unclean shutdown"));
    }

    #[test]
    fn journald_complaints_are_read_from_its_messages() {
        let entries = vec![
            Entry::new("systemd-journald", "Suppressed 120 messages from nginx.service"),
            Entry::new("systemd-journald", "Suppressed 30 messages from nginx.service"),
            Entry::new("systemd-journald", "Suppressed 9000 messages from app.service"),
            Entry::new("systemd-journald", "Suppressed lots of messages from x.service"),
            Entry::new(
                "systemd-journald",
                "Journal file /var/log/journal/abc/system.journal is corrupted or uncleanly shut down, renaming and replacing.",
            ),
            Entry::new("systemd-journald", "Journal started"),
        ];
        let (suppressed, replaced) = read_journald_messages(&entries);
        assert_eq!(
            suppressed,
            vec![
                ("app.service".to_string(), 9000),
                ("nginx.service".to_string(), 150)
            ]
        );
        assert_eq!(replaced, 1);
    }

    #[test]
    fn journald_conf_limits_are_found_in_the_journal_section_only() {
        let conf = "# comment\n[Journal]\n#SystemMaxUse=\nSystemMaxUse=500M\n";
        assert!(parse_journald_conf(conf).size_limit_configured);
        assert!(parse_journald_conf("[Journal]\nRuntimeMaxUse = 50M\n").size_limit_configured);
        assert!(
            !parse_journald_conf("[Journal]\n#SystemMaxUse=500M\nStorage=auto\n")
                .size_limit_configured
        );
        assert!(!parse_journald_conf("[Other]\nSystemMaxUse=500M\n").size_limit_configured);
        assert!(!parse_journald_conf("[Journal]\nSystemMaxUse=\n").size_limit_configured);
        assert!(!parse_journald_conf("").size_limit_configured);
        let merged =
            parse_journald_conf("").merge(parse_journald_conf("[Journal]\nSystemMaxUse=1G\n"));
        assert!(merged.size_limit_configured);
    }

    fn files(sizes: &[(&str, u64)], total: u64, rotate: bool) -> LogFiles {
        LogFiles {
            scanned: true,
            total_bytes: total,
            largest: sizes
                .iter()
                .map(|(p, s)| LogFile {
                    path: (*p).into(),
                    size: *s,
                })
                .collect(),
            unreadable_dirs: 0,
            logrotate_installed: rotate,
        }
    }

    #[test]
    fn ordinary_log_files_are_fine() {
        let f = files_finding(
            &files(
                &[("/var/log/syslog", 40 * 1024 * 1024)],
                200 * 1024 * 1024,
                true,
            ),
            Family::DebianLike,
        );
        assert_eq!(f.severity, Severity::Info);
        assert!(f.explanation.contains("Nothing is unusually large"));
        assert!(f.recommendation.is_none());
    }

    #[test]
    fn a_gigabyte_log_is_a_warning_and_ten_are_an_error() {
        let big = files(&[("/var/log/app.log", 2 * GIB)], 2 * GIB, true);
        assert_eq!(
            files_finding(&big, Family::DebianLike).severity,
            Severity::Warning
        );
        let huge = files(&[("/var/log/app.log", 12 * GIB)], 12 * GIB, true);
        assert_eq!(
            files_finding(&huge, Family::DebianLike).severity,
            Severity::Error
        );
    }

    #[test]
    fn compressed_archives_are_not_a_runaway_log() {
        let f = files(
            &[
                ("/var/log/old.log.1.gz", 3 * GIB),
                ("/var/log/syslog", 10 * 1024 * 1024),
            ],
            3 * GIB,
            true,
        );
        assert_eq!(f.severity(), Severity::Info);
        let sum = LogFiles {
            total_bytes: 6 * GIB,
            ..f
        };
        assert_eq!(
            sum.severity(),
            Severity::Warning,
            "but a lot of logs overall is"
        );
    }

    #[test]
    fn steps_find_the_writer_check_rotation_and_empty_the_file_last() {
        let f = files_finding(
            &files(&[("/var/log/app.log", 2 * GIB)], 2 * GIB, true),
            Family::DebianLike,
        );
        let rec = f.recommendation.unwrap();
        assert!(rec.contains("sudo lsof /var/log/app.log"));
        assert!(rec.contains("grep -rn '/var/log/app.log' /etc/logrotate.conf /etc/logrotate.d/"));
        assert!(rec.contains("sudo truncate -s 0 /var/log/app.log"));
        assert!(rec.find("lsof").unwrap() < rec.find("logrotate -d").unwrap());
        assert!(rec.find("logrotate -d").unwrap() < rec.find("truncate").unwrap());
    }

    #[test]
    fn a_missing_logrotate_is_installed_the_distribution_way() {
        let base = files(&[("/var/log/app.log", 2 * GIB)], 2 * GIB, false);
        assert!(files_finding(&base, Family::DebianLike)
            .recommendation
            .unwrap()
            .contains("sudo apt install logrotate"));
        assert!(files_finding(&base, Family::RedHatLike)
            .recommendation
            .unwrap()
            .contains("sudo dnf install logrotate"));
        let neutral = files_finding(&base, Family::Unknown)
            .recommendation
            .unwrap();
        assert!(!neutral.contains("apt install") && neutral.contains("logrotate was not found"));
    }

    #[test]
    fn a_path_with_odd_characters_stays_out_of_commands() {
        let f = files_finding(
            &files(&[("/var/log/a b;rm.log", 2 * GIB)], 2 * GIB, true),
            Family::DebianLike,
        );
        let rec = f.recommendation.unwrap();
        assert!(!rec.contains("rm.log"));
        assert!(rec.contains("sudo truncate -s 0 <file>"));
    }

    #[test]
    fn unreadable_places_are_disclosed() {
        let mut f = files(&[], 0, true);
        f.unreadable_dirs = 2;
        let text = files_finding(&f, Family::DebianLike).explanation;
        assert!(text.contains("2 directories could not be listed"));
        let nothing = LogFiles::default();
        let t = files_finding(&nothing, Family::DebianLike);
        assert!(t.explanation.contains("could not be read"));
        assert_eq!(t.severity, Severity::Info);
    }
}
