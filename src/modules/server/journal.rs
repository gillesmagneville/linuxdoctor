// SPDX-License-Identifier: GPL-3.0-only

//! SRV002 -- do the logs survive a reboot?
//!
//! After a crash, a power cut or a reboot nobody asked for, the logs are what
//! says what happened. On a server nobody was watching, they are the only
//! witness, so they have to be on disk. systemd's journal is on disk only when
//! `Storage=` says so -- `persistent`, or `auto` (the default) with a
//! `/var/log/journal` directory --; otherwise it lives in `/run/log/journal`,
//! in memory, and goes with the reboot. Classic log files (rsyslog's
//! `/var/log/syslog` or `/var/log/messages`) are on disk too, and many systems
//! keep both.
//!
//! This reads the settings and the files, not the journal: no tool is run. The
//! logs module (LOG008) already says whether the journal is on disk, from its
//! directory only; this check adds what a server needs to know -- `Storage=`
//! can say `volatile` or `none` whatever the directory holds, and the classic
//! files can make up for a journal in memory -- and says it louder, because
//! on a server it matters more.

use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};

use crate::core::text::clean;
use crate::models::finding::FindingBuilder;
use crate::models::{Category, Confidence, Finding, Severity};
use crate::modules::logs::text::is_safe_word;
use crate::modules::recommend::Steps;

use super::age::{age_text, DAY};
use super::collect::{modified_unix, read_config};

/// Where systemd looks for `journald.conf` and its `journald.conf.d`, from the
/// highest priority to the lowest (`journald.conf(5)`).
const CONFIG_DIRS: [&str; 4] = [
    "etc/systemd",
    "run/systemd",
    "usr/local/lib/systemd",
    "usr/lib/systemd",
];

/// More drop-in files than this in one directory are not read: nobody has
/// them, and a directory stuffed with files is not a configuration.
const MAX_DROP_INS: usize = 256;

/// Longest file name or path quoted back.
const MAX_PATH: usize = 200;

/// The classic log files, which hold the whole system log.
const SYSLOG_FILES: [&str; 2] = ["var/log/syslog", "var/log/messages"];

/// A classic log file counts as written if it was written this lately. A
/// machine writes to its system log all the time; a file untouched for a
/// week is a relic of a logger that is gone.
pub const SYSLOG_FRESH_SECS: u64 = 7 * DAY;

/// What `Storage=` can be set to (`journald.conf(5)`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Storage {
    /// On disk (`/var/log/journal`) if that directory exists, otherwise in
    /// memory. The default.
    Auto,
    /// On disk; journald creates the directory.
    Persistent,
    /// In memory only (`/run/log/journal`), whatever `/var/log/journal` holds.
    Volatile,
    /// Nothing is stored. Forwarding to a syslog socket still works.
    None,
}

impl Storage {
    /// systemd's own spelling. It compares the words as they are written: a
    /// differently spelt value is invalid, and journald ignores it.
    fn from_word(word: &str) -> Option<Storage> {
        match word {
            "auto" => Some(Storage::Auto),
            "persistent" => Some(Storage::Persistent),
            "volatile" => Some(Storage::Volatile),
            "none" => Some(Storage::None),
            _ => None,
        }
    }

    pub fn word(self) -> &'static str {
        match self {
            Storage::Auto => "auto",
            Storage::Persistent => "persistent",
            Storage::Volatile => "volatile",
            Storage::None => "none",
        }
    }
}

/// The `Storage=` that counts, and the file it is in.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StorageSetting {
    pub value: Storage,
    /// As an absolute path, cleaned of anything that is not text.
    pub file: String,
}

/// A classic log file that has been written lately.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SyslogFile {
    pub path: &'static str,
    /// Seconds since it was last written.
    pub age_secs: u64,
}

/// Where this machine keeps its logs.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct JournalSetup {
    /// systemd-journald is this machine's logger: its runtime directory or
    /// one of its journal directories is there.
    pub journald: bool,
    /// `None` when no file sets `Storage=`.
    pub setting: Option<StorageSetting>,
    /// `/var/log/journal` exists.
    pub directory: bool,
    pub syslog: Vec<SyslogFile>,
}

// ---------------------------------------------------------------------------
// Reading
// ---------------------------------------------------------------------------

/// The last valid `Storage=` of the `[Journal]` section of a file. The value
/// has to be exactly one of the four words, with nothing after it: journald
/// takes an assignment it cannot read for a mistake and ignores it, so what
/// was set before still counts. A comment (`#` or `;`) needs no case of its
/// own: it is no section, and the name before its `=` starts with the mark.
pub fn parse_storage(text: &str) -> Option<Storage> {
    let mut in_journal = false;
    let mut found = None;
    for line in text.lines() {
        let line = line.trim();
        if let Some(section) = line.strip_prefix('[').and_then(|s| s.strip_suffix(']')) {
            in_journal = section == "Journal";
            continue;
        }
        if !in_journal {
            continue;
        }
        let Some((name, value)) = line.split_once('=') else {
            continue;
        };
        if name.trim() == "Storage" {
            if let Some(storage) = Storage::from_word(value.trim()) {
                found = Some(storage);
            }
        }
    }
    found
}

/// A file that sets `Storage=`, ready to be read.
struct ConfigFile {
    /// What the files are sorted by.
    name: String,
    /// Where it is shown to be.
    shown: String,
    path: PathBuf,
}

/// The `journald.conf.d` files that apply, in the order they apply: the files
/// of every directory sorted together by name, and a name that is in a
/// directory of higher priority hides the same name in the ones below it --
/// a link to `/dev/null` is how a drop-in is hidden: it hides the name and
/// says nothing.
fn drop_ins(root: &Path) -> Vec<ConfigFile> {
    let mut seen = BTreeSet::new();
    let mut files = Vec::new();
    for dir in CONFIG_DIRS {
        let relative = format!("{dir}/journald.conf.d");
        let Ok(entries) = fs::read_dir(root.join(&relative)) else {
            continue;
        };
        for entry in entries.flatten().take(MAX_DROP_INS) {
            let name = entry.file_name().to_string_lossy().into_owned();
            if !name.ends_with(".conf") || !seen.insert(name.clone()) {
                continue;
            }
            files.push(ConfigFile {
                shown: clean(&format!("/{relative}/{name}"), MAX_PATH),
                path: entry.path(),
                name,
            });
        }
    }
    files.sort_by(|a, b| a.name.cmp(&b.name));
    files
}

/// `Storage=` as journald has it: the main file -- the first of
/// `/etc/systemd/journald.conf` and its fellows that exists --, then the
/// drop-ins, each over the last.
fn read_setting(root: &Path) -> Option<StorageSetting> {
    let mut setting = None;
    let mut take = |text: &str, file: String| {
        if let Some(value) = parse_storage(text) {
            setting = Some(StorageSetting { value, file });
        }
    };
    for dir in CONFIG_DIRS {
        let relative = format!("{dir}/journald.conf");
        if let Some(text) = read_config(&root.join(&relative)) {
            take(&text, format!("/{relative}"));
            break;
        }
    }
    for file in drop_ins(root) {
        if let Some(text) = read_config(&file.path) {
            take(&text, file.shown);
        }
    }
    setting
}

/// The classic log files written within [`SYSLOG_FRESH_SECS`] of `now_unix`.
fn read_syslog(root: &Path, now_unix: u64) -> Vec<SyslogFile> {
    SYSLOG_FILES
        .iter()
        .filter_map(|&relative| {
            let metadata = fs::metadata(root.join(relative)).ok()?;
            if !metadata.is_file() || metadata.len() == 0 {
                return None;
            }
            // A clock that is behind the file's date reads as "just now".
            let age_secs = now_unix.saturating_sub(modified_unix(&metadata)?);
            (age_secs <= SYSLOG_FRESH_SECS).then_some(SyslogFile {
                path: syslog_path(relative),
                age_secs,
            })
        })
        .collect()
}

/// The absolute path of one of [`SYSLOG_FILES`].
fn syslog_path(relative: &str) -> &'static str {
    match relative {
        "var/log/syslog" => "/var/log/syslog",
        _ => "/var/log/messages",
    }
}

/// Reads the settings and the files under `root` (`/` on a real machine).
pub fn read(root: &Path, now_unix: u64) -> JournalSetup {
    let directory = root.join("var/log/journal").is_dir();
    let journald = directory
        || root.join("run/log/journal").is_dir()
        || root.join("run/systemd/journal").is_dir();
    JournalSetup {
        journald,
        setting: read_setting(root),
        directory,
        syslog: read_syslog(root, now_unix),
    }
}

// ---------------------------------------------------------------------------
// The finding
// ---------------------------------------------------------------------------

/// What every warning about lost logs says it cannot see.
const FORWARDING: &str = "This looks only at this machine. If the logs are sent to another one \
     as they are written (a syslog or journal-remote collector, an agent such as Promtail or \
     Filebeat), they survive there and this can be ignored.";

/// Whether journald keeps the journal on disk, from `Storage=` and the
/// directory: `persistent` always, `volatile` and `none` never, `auto` (or
/// nothing set) when `/var/log/journal` exists.
fn journal_on_disk(setup: &JournalSetup) -> bool {
    match setup.setting.as_ref().map(|s| s.value) {
        Some(Storage::Persistent) => true,
        Some(Storage::Volatile | Storage::None) => false,
        Some(Storage::Auto) | None => setup.directory,
    }
}

/// Why the journal is where it is: what decides it, as a clause.
fn reason(setup: &JournalSetup) -> String {
    let directory = if setup.directory {
        "`/var/log/journal` exists"
    } else {
        "`/var/log/journal` does not exist"
    };
    match &setup.setting {
        Some(StorageSetting { value, file }) if *value != Storage::Auto => {
            format!("`Storage={}` in `{file}`", value.word())
        }
        Some(StorageSetting { file, .. }) => {
            format!("`Storage=auto` in `{file}`, and {directory}")
        }
        None => format!("`Storage=` is not set, which is `auto`, and {directory}"),
    }
}

/// The journal is not kept on disk, in words.
fn not_kept(setup: &JournalSetup) -> &'static str {
    match setup.setting.as_ref().map(|s| s.value) {
        Some(Storage::None) => "journald is told to keep no log at all",
        _ => "the journal is in memory only",
    }
}

/// `/var/log/syslog` (last written 3 hours ago), for each file.
fn syslog_text(files: &[SyslogFile]) -> String {
    files
        .iter()
        .map(|f| format!("`{}` (last written {} ago)", f.path, age_text(f.age_secs)))
        .collect::<Vec<_>>()
        .join(", ")
}

fn builder(severity: Severity, confidence: Confidence) -> FindingBuilder {
    Finding::builder(
        "SRV002",
        "Logs Kept Across Reboots",
        Category::Logs,
        severity,
        confidence,
    )
}

/// The facts the finding rests on.
fn with_evidence(builder: FindingBuilder, setup: &JournalSetup) -> FindingBuilder {
    let mut builder = builder.evidence(
        "journal_storage",
        setup.setting.as_ref().map_or("not set", |s| s.value.word()),
    );
    if let Some(setting) = &setup.setting {
        builder = builder.evidence("journal_storage_file", setting.file.as_str());
    }
    builder
        .evidence(
            "var_log_journal",
            if setup.directory { "present" } else { "absent" },
        )
        .evidence(
            "syslog_files",
            if setup.syslog.is_empty() {
                "none written lately".to_string()
            } else {
                setup
                    .syslog
                    .iter()
                    .map(|f| f.path)
                    .collect::<Vec<_>>()
                    .join(",")
            },
        )
}

pub fn journal_finding(setup: &JournalSetup) -> Finding {
    if !setup.journald {
        return builder(Severity::Info, Confidence::direct_observation())
            .evidence("journald", "not found")
            .explanation(
                "Whether the logs survive a reboot was not checked: no systemd journal was \
                 found (no runtime directory of journald, no `/var/log/journal`). That is not \
                 the same as the logs being kept.",
            )
            .build();
    }

    if journal_on_disk(setup) {
        let created = if setup.directory {
            ""
        } else {
            " `/var/log/journal` does not exist yet: journald creates it."
        };
        return with_evidence(builder(Severity::Info, Confidence::correlated(90)), setup)
            .explanation(format!(
                "The journal is kept on disk, so the logs of what happened before a reboot or \
                 a crash are still there afterwards: {}.{created} How long they are kept \
                 depends on the size limit of the journal (`SystemMaxUse=`) and on the free \
                 space; LOG008, in the logs module, shows its size and limit.",
                reason(setup)
            ))
            .build();
    }

    if !setup.syslog.is_empty() {
        return with_evidence(builder(Severity::Info, Confidence::correlated(90)), setup)
            .explanation(format!(
                "On its own the journal would not survive a reboot: {} ({}). The classic log \
                 files are written, though: {}. They are on disk, so they are what to read \
                 after a crash.",
                not_kept(setup),
                reason(setup),
                syslog_text(&setup.syslog)
            ))
            .build();
    }

    with_evidence(
        builder(Severity::Warning, Confidence::strong_indication(80)),
        setup,
    )
    .explanation(format!(
        "The logs do not survive a reboot: {} ({}), and neither `/var/log/syslog` nor \
         `/var/log/messages` has been written in the last {}. After a crash, a power cut or a \
         reboot nobody asked for, nothing is left to say what happened before it. {FORWARDING}",
        not_kept(setup),
        reason(setup),
        age_text(SYSLOG_FRESH_SECS)
    ))
    .recommendation(steps(setup).build())
    .build()
}

fn steps(setup: &JournalSetup) -> Steps {
    let mut steps = Steps::new();
    let to_change = setup
        .setting
        .as_ref()
        .filter(|s| matches!(s.value, Storage::Volatile | Storage::None));
    if let Some(setting) = to_change {
        // The path comes from a directory listing: it is put in a command only
        // if it is made of characters a shell takes literally.
        let commands = if is_safe_word(&setting.file) {
            vec![format!("sudoedit {}", setting.file)]
        } else {
            Vec::new()
        };
        steps = steps.step_owned(
            format!(
                "Set `Storage=persistent` (or delete the line) in `{}`, which keeps the journal \
                 off the disk:",
                setting.file
            ),
            commands,
        );
    }
    steps
        .step(
            if to_change.is_some() {
                "Then give the journal its directory and restart journald:"
            } else {
                "Keep the journal on disk. Its directory is all `Storage=auto` needs:"
            },
            &[
                "sudo mkdir -p /var/log/journal",
                "sudo systemd-tmpfiles --create --prefix /var/log/journal",
                "sudo systemctl restart systemd-journald",
            ],
        )
        .step(
            "Check that it is on disk now, and, after the next reboot, that the boots before it \
             are listed:",
            &["journalctl --disk-usage", "journalctl --list-boots"],
        )
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs::File;
    use std::os::unix::fs::symlink;
    use std::time::{Duration, UNIX_EPOCH};

    const NOW: u64 = 1_000_000_000;

    fn tree(name: &str) -> PathBuf {
        let root = std::env::temp_dir().join(format!(
            "linuxdoctor-server-journal-{name}-{}",
            std::process::id()
        ));
        let _ = fs::remove_dir_all(&root);
        fs::create_dir_all(&root).unwrap();
        root
    }

    fn write(root: &Path, relative: &str, text: &str) {
        let path = root.join(relative);
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(path, text).unwrap();
    }

    /// A file that was last written `ago` seconds before [`NOW`].
    fn written(root: &Path, relative: &str, text: &str, ago: u64) {
        write(root, relative, text);
        let time = UNIX_EPOCH + Duration::from_secs(NOW) - Duration::from_secs(ago);
        File::options()
            .write(true)
            .open(root.join(relative))
            .unwrap()
            .set_modified(time)
            .unwrap();
    }

    fn storage(root: &Path) -> Option<(Storage, String)> {
        read(root, NOW).setting.map(|s| (s.value, s.file))
    }

    fn setting(value: Storage, file: &str) -> Option<StorageSetting> {
        Some(StorageSetting {
            value,
            file: file.into(),
        })
    }

    // ----- Storage= ----------------------------------------------------------

    #[test]
    fn each_word_of_storage_is_read() {
        for (word, storage) in [
            ("auto", Storage::Auto),
            ("persistent", Storage::Persistent),
            ("volatile", Storage::Volatile),
            ("none", Storage::None),
        ] {
            let text = format!("[Journal]\nStorage={word}\n");
            assert_eq!(parse_storage(&text), Some(storage), "{word}");
            assert_eq!(storage.word(), word);
        }
        assert_eq!(parse_storage(""), None);
        assert_eq!(parse_storage("[Journal]\n"), None);
    }

    #[test]
    fn the_last_valid_assignment_counts() {
        let text = "[Journal]\nStorage=volatile\nStorage=persistent\n";
        assert_eq!(parse_storage(text), Some(Storage::Persistent));
        // An invalid one is ignored, as journald ignores it: what was set before stays.
        let text = "[Journal]\nStorage=volatile\nStorage=forever\n";
        assert_eq!(parse_storage(text), Some(Storage::Volatile));
        // And the section may come back.
        let text = "[Journal]\nStorage=volatile\n[Other]\nStorage=none\n[Journal]\nStorage=auto\n";
        assert_eq!(parse_storage(text), Some(Storage::Auto));
    }

    #[test]
    fn only_a_storage_of_the_journal_section_counts() {
        for text in [
            "Storage=persistent\n",
            "[Other]\nStorage=persistent\n",
            "[journal]\nStorage=persistent\n",
            "[Journal ]\nStorage=persistent\n",
            "[Journal]\nstorage=persistent\n",
            "[Journal]\nStorageX=persistent\n",
            "[Journal]\nSystemMaxUse=persistent\n",
        ] {
            assert_eq!(parse_storage(text), None, "{text:?}");
        }
    }

    #[test]
    fn a_value_is_the_word_alone() {
        for text in [
            "[Journal]\nStorage=Persistent\n",
            "[Journal]\nStorage=persistent # for the post-mortem\n",
            "[Journal]\nStorage=\n",
            "[Journal]\nStorage\n",
            "[Journal]\nStorage=persistent persistent\n",
            "[Journal]\nStorage=\"persistent\"\n",
        ] {
            assert_eq!(parse_storage(text), None, "{text:?}");
        }
        // Spacing around the name, the sign and the value is not part of them.
        let text = "[Journal]\n  Storage  =  persistent  \n";
        assert_eq!(parse_storage(text), Some(Storage::Persistent));
        let text = "  [Journal]  \nStorage=volatile\r\n";
        assert_eq!(parse_storage(text), Some(Storage::Volatile));
    }

    #[test]
    fn a_commented_assignment_is_not_one() {
        let text = "[Journal]\n#Storage=volatile\n;Storage=none\n  # Storage=none\nStorage=auto\n";
        assert_eq!(parse_storage(text), Some(Storage::Auto));
        // Commented out, it leaves what an earlier line set.
        let text = "[Journal]\nStorage=persistent\n#Storage=volatile\n;Storage=none\n";
        assert_eq!(parse_storage(text), Some(Storage::Persistent));
        // A commented section header does not change the section.
        let text = "[Journal]\n#[Other]\nStorage=persistent\n";
        assert_eq!(parse_storage(text), Some(Storage::Persistent));
    }

    // ----- the files ---------------------------------------------------------------

    #[test]
    fn a_machine_without_any_of_it_says_so() {
        let root = tree("none");
        let setup = read(&root, NOW);
        assert_eq!(setup, JournalSetup::default());
        assert!(!setup.journald);
    }

    #[test]
    fn journald_is_found_by_any_of_its_directories() {
        for (relative, on_disk) in [
            ("var/log/journal", true),
            ("run/log/journal", false),
            ("run/systemd/journal", false),
        ] {
            let root = tree("journald");
            fs::create_dir_all(root.join(relative)).unwrap();
            let setup = read(&root, NOW);
            assert!(setup.journald, "{relative}");
            assert_eq!(setup.directory, on_disk, "{relative}");
        }
        // A file of that name is not the directory.
        let root = tree("journald-file");
        write(&root, "var/log/journal", "");
        let setup = read(&root, NOW);
        assert!(!setup.journald && !setup.directory);
    }

    #[test]
    fn the_main_file_is_the_first_one_that_exists() {
        let root = tree("main");
        write(
            &root,
            "usr/lib/systemd/journald.conf",
            "[Journal]\nStorage=none\n",
        );
        assert_eq!(
            storage(&root),
            Some((Storage::None, "/usr/lib/systemd/journald.conf".into()))
        );
        write(
            &root,
            "usr/local/lib/systemd/journald.conf",
            "[Journal]\nStorage=volatile\n",
        );
        assert_eq!(
            storage(&root),
            Some((
                Storage::Volatile,
                "/usr/local/lib/systemd/journald.conf".into()
            ))
        );
        write(
            &root,
            "run/systemd/journald.conf",
            "[Journal]\nStorage=auto\n",
        );
        assert_eq!(
            storage(&root),
            Some((Storage::Auto, "/run/systemd/journald.conf".into()))
        );
        write(
            &root,
            "etc/systemd/journald.conf",
            "[Journal]\nStorage=persistent\n",
        );
        assert_eq!(
            storage(&root),
            Some((Storage::Persistent, "/etc/systemd/journald.conf".into()))
        );
        // The first one that exists is the only one, even if it sets nothing:
        // the commented-out file of the distribution hides the vendor's.
        write(
            &root,
            "etc/systemd/journald.conf",
            "[Journal]\n#Storage=auto\n",
        );
        assert_eq!(storage(&root), None);
    }

    #[test]
    fn drop_ins_come_after_the_main_file_and_the_last_name_wins() {
        let root = tree("dropins");
        write(
            &root,
            "etc/systemd/journald.conf",
            "[Journal]\nStorage=volatile\n",
        );
        write(
            &root,
            "etc/systemd/journald.conf.d/10-a.conf",
            "[Journal]\nStorage=none\n",
        );
        assert_eq!(
            storage(&root),
            Some((
                Storage::None,
                "/etc/systemd/journald.conf.d/10-a.conf".into()
            ))
        );
        // Sorted by name, whatever the directory: this one is in a directory of
        // lower priority and sorts later.
        write(
            &root,
            "usr/lib/systemd/journald.conf.d/20-b.conf",
            "[Journal]\nStorage=persistent\n",
        );
        assert_eq!(
            storage(&root),
            Some((
                Storage::Persistent,
                "/usr/lib/systemd/journald.conf.d/20-b.conf".into()
            ))
        );
        // A drop-in that sets nothing leaves what came before.
        write(
            &root,
            "run/systemd/journald.conf.d/30-c.conf",
            "[Journal]\nSystemMaxUse=1G\n",
        );
        assert_eq!(
            storage(&root),
            Some((
                Storage::Persistent,
                "/usr/lib/systemd/journald.conf.d/20-b.conf".into()
            ))
        );
        // Names that are not `.conf` are not drop-ins.
        write(
            &root,
            "etc/systemd/journald.conf.d/99-z.conf.bak",
            "[Journal]\nStorage=none\n",
        );
        write(
            &root,
            "etc/systemd/journald.conf.d/99-y",
            "[Journal]\nStorage=none\n",
        );
        fs::create_dir_all(root.join("etc/systemd/journald.conf.d/99-x.conf")).unwrap();
        assert_eq!(
            storage(&root),
            Some((
                Storage::Persistent,
                "/usr/lib/systemd/journald.conf.d/20-b.conf".into()
            ))
        );
    }

    #[test]
    fn a_name_in_a_higher_directory_hides_the_same_name_below() {
        let root = tree("masking");
        write(
            &root,
            "usr/lib/systemd/journald.conf.d/50-x.conf",
            "[Journal]\nStorage=volatile\n",
        );
        write(
            &root,
            "etc/systemd/journald.conf.d/50-x.conf",
            "[Journal]\nStorage=persistent\n",
        );
        assert_eq!(
            storage(&root),
            Some((
                Storage::Persistent,
                "/etc/systemd/journald.conf.d/50-x.conf".into()
            ))
        );
        // A link to /dev/null is how a drop-in is hidden.
        let root = tree("masking-null");
        write(
            &root,
            "usr/lib/systemd/journald.conf.d/50-x.conf",
            "[Journal]\nStorage=volatile\n",
        );
        fs::create_dir_all(root.join("etc/systemd/journald.conf.d")).unwrap();
        symlink(
            "/dev/null",
            root.join("etc/systemd/journald.conf.d/50-x.conf"),
        )
        .unwrap();
        assert_eq!(storage(&root), None);
    }

    #[test]
    fn a_huge_file_is_not_read_to_the_end() {
        let root = tree("huge");
        let mut text = "[Journal]\n".to_string();
        text.push_str(&"#".repeat(2 * 1024 * 1024));
        text.push_str("\nStorage=volatile\n");
        write(&root, "etc/systemd/journald.conf", &text);
        assert_eq!(storage(&root), None);
        // What is before the limit is read.
        let mut text = "[Journal]\nStorage=none\n".to_string();
        text.push_str(&"#".repeat(2 * 1024 * 1024));
        write(&root, "etc/systemd/journald.conf", &text);
        assert_eq!(storage(&root).unwrap().0, Storage::None);
    }

    #[test]
    fn the_name_of_the_file_is_cleaned() {
        let root = tree("hostile");
        write(
            &root,
            "etc/systemd/journald.conf.d/\u{1b}[31mred.conf",
            "[Journal]\nStorage=none\n",
        );
        let (_, file) = storage(&root).unwrap();
        assert!(!file.contains('\u{1b}'), "{file:?}");
        assert!(file.ends_with("?[31mred.conf"), "{file:?}");
        // A file name can be 255 bytes: the path shown is cut at 200 characters.
        let long = format!("etc/systemd/journald.conf.d/{}.conf", "x".repeat(240));
        write(&root, &long, "[Journal]\nStorage=none\n");
        let (_, file) = storage(&root).unwrap();
        assert_eq!(file.chars().count(), 201, "{file}");
        assert!(file.ends_with('…'), "{file}");
    }

    #[test]
    fn the_classic_logs_are_those_written_this_week() {
        let root = tree("syslog");
        written(&root, "var/log/syslog", "line\n", 3 * 3600);
        written(&root, "var/log/messages", "line\n", 2 * DAY);
        assert_eq!(
            read(&root, NOW).syslog,
            [
                SyslogFile {
                    path: "/var/log/syslog",
                    age_secs: 3 * 3600
                },
                SyslogFile {
                    path: "/var/log/messages",
                    age_secs: 2 * DAY
                }
            ]
        );
    }

    #[test]
    fn a_classic_log_that_is_old_empty_or_not_a_file_does_not_count() {
        let root = tree("syslog-no");
        // Exactly a week (604800 seconds) is still this week; a second more is not.
        written(&root, "var/log/syslog", "line\n", 604_800);
        assert_eq!(read(&root, NOW).syslog.len(), 1);
        written(&root, "var/log/syslog", "line\n", 604_801);
        assert!(read(&root, NOW).syslog.is_empty());
        // Empty.
        written(&root, "var/log/syslog", "", 60);
        assert!(read(&root, NOW).syslog.is_empty());
        // A directory, and a link to a device.
        let root = tree("syslog-not-file");
        fs::create_dir_all(root.join("var/log/syslog")).unwrap();
        fs::create_dir_all(root.join("var/log")).unwrap();
        symlink("/dev/null", root.join("var/log/messages")).unwrap();
        assert!(read(&root, NOW).syslog.is_empty());
    }

    #[test]
    fn a_clock_behind_the_file_reads_as_just_written() {
        let root = tree("syslog-future");
        write(&root, "var/log/syslog", "line\n");
        let future = UNIX_EPOCH + Duration::from_secs(NOW + 3600);
        File::options()
            .write(true)
            .open(root.join("var/log/syslog"))
            .unwrap()
            .set_modified(future)
            .unwrap();
        assert_eq!(
            read(&root, NOW).syslog,
            [SyslogFile {
                path: "/var/log/syslog",
                age_secs: 0
            }]
        );
    }

    // ----- the verdict -----------------------------------------------------------

    fn setup(
        setting: Option<StorageSetting>,
        directory: bool,
        syslog: &[SyslogFile],
    ) -> JournalSetup {
        JournalSetup {
            journald: true,
            setting,
            directory,
            syslog: syslog.to_vec(),
        }
    }

    fn syslog_file() -> SyslogFile {
        SyslogFile {
            path: "/var/log/syslog",
            age_secs: 3 * 3600,
        }
    }

    fn evidence<'a>(finding: &'a Finding, key: &str) -> Option<&'a str> {
        finding
            .evidence
            .iter()
            .find(|(k, _)| k == key)
            .map(|(_, v)| v.as_str())
    }

    #[test]
    fn the_journal_is_on_disk_the_way_journald_decides() {
        let file = "/etc/systemd/journald.conf";
        for (value, directory, on_disk) in [
            (None, true, true),
            (None, false, false),
            (Some(Storage::Auto), true, true),
            (Some(Storage::Auto), false, false),
            // `persistent` makes the directory; `volatile` and `none` ignore it.
            (Some(Storage::Persistent), true, true),
            (Some(Storage::Persistent), false, true),
            (Some(Storage::Volatile), true, false),
            (Some(Storage::Volatile), false, false),
            (Some(Storage::None), true, false),
            (Some(Storage::None), false, false),
        ] {
            let s = setup(value.and_then(|v| setting(v, file)), directory, &[]);
            assert_eq!(journal_on_disk(&s), on_disk, "{value:?} {directory}");
        }
    }

    #[test]
    fn a_machine_without_a_journal_is_not_checked() {
        let f = journal_finding(&JournalSetup::default());
        assert_eq!(f.id, "SRV002");
        assert_eq!(f.title, "Logs Kept Across Reboots");
        assert_eq!(f.category, Category::Logs);
        assert_eq!(f.severity, Severity::Info);
        assert_eq!(f.confidence.percent, 100);
        assert!(f.recommendation.is_none());
        assert!(
            f.explanation.contains("was not checked"),
            "{}",
            f.explanation
        );
        assert!(
            f.explanation
                .contains("not the same as the logs being kept"),
            "{}",
            f.explanation
        );
        assert_eq!(evidence(&f, "journald"), Some("not found"));
        // Whatever else is in the setup, nothing is said about it.
        let mut s = setup(setting(Storage::None, "/x"), false, &[]);
        s.journald = false;
        let f = journal_finding(&s);
        assert_eq!(f.severity, Severity::Info);
        assert_eq!(evidence(&f, "journal_storage"), None);
    }

    #[test]
    fn a_journal_on_disk_is_information_that_says_why() {
        let f = journal_finding(&setup(None, true, &[]));
        assert_eq!(f.severity, Severity::Info);
        assert_eq!(f.confidence.percent, 90);
        assert!(f.recommendation.is_none());
        assert!(f.explanation.contains("kept on disk"), "{}", f.explanation);
        assert!(
            f.explanation
                .contains("`Storage=` is not set, which is `auto`, and `/var/log/journal` exists"),
            "{}",
            f.explanation
        );
        assert!(f.explanation.contains("LOG008"), "{}", f.explanation);
        assert_eq!(evidence(&f, "journal_storage"), Some("not set"));
        assert_eq!(evidence(&f, "journal_storage_file"), None);
        assert_eq!(evidence(&f, "var_log_journal"), Some("present"));
        assert_eq!(evidence(&f, "syslog_files"), Some("none written lately"));

        let f = journal_finding(&setup(
            setting(Storage::Auto, "/etc/systemd/journald.conf"),
            true,
            &[],
        ));
        assert!(
            f.explanation.contains(
                "`Storage=auto` in `/etc/systemd/journald.conf`, and `/var/log/journal` exists"
            ),
            "{}",
            f.explanation
        );
        assert_eq!(evidence(&f, "journal_storage"), Some("auto"));
        assert_eq!(
            evidence(&f, "journal_storage_file"),
            Some("/etc/systemd/journald.conf")
        );
    }

    #[test]
    fn persistent_makes_its_own_directory() {
        let f = journal_finding(&setup(
            setting(
                Storage::Persistent,
                "/etc/systemd/journald.conf.d/10-p.conf",
            ),
            false,
            &[],
        ));
        assert_eq!(f.severity, Severity::Info);
        assert!(
            f.explanation
                .contains("`Storage=persistent` in `/etc/systemd/journald.conf.d/10-p.conf`"),
            "{}",
            f.explanation
        );
        assert!(
            f.explanation
                .contains("does not exist yet: journald creates it"),
            "{}",
            f.explanation
        );
        assert_eq!(evidence(&f, "var_log_journal"), Some("absent"));
        // With the directory there, there is nothing to add.
        let f = journal_finding(&setup(setting(Storage::Persistent, "/x.conf"), true, &[]));
        assert!(!f.explanation.contains("creates it"), "{}", f.explanation);
    }

    #[test]
    fn a_journal_in_memory_is_a_warning_that_says_why_and_what_to_do() {
        // `volatile` wins over a directory that is there.
        let f = journal_finding(&setup(
            setting(Storage::Volatile, "/etc/systemd/journald.conf"),
            true,
            &[],
        ));
        assert_eq!(f.severity, Severity::Warning);
        assert_eq!(f.confidence.percent, 80);
        assert!(
            f.explanation.contains("The logs do not survive a reboot"),
            "{}",
            f.explanation
        );
        assert!(
            f.explanation
                .contains("the journal is in memory only (`Storage=volatile` in `/etc/systemd/journald.conf`)"),
            "{}",
            f.explanation
        );
        assert!(f.explanation.contains("last 7 days"), "{}", f.explanation);
        assert!(
            f.explanation.contains("sent to another one"),
            "{}",
            f.explanation
        );
        assert_eq!(evidence(&f, "journal_storage"), Some("volatile"));
        assert_eq!(evidence(&f, "var_log_journal"), Some("present"));
        let steps = f.recommendation.unwrap();
        assert!(
            steps.starts_with(
                "1. Set `Storage=persistent` (or delete the line) in `/etc/systemd/journald.conf`, which keeps the journal off the disk:\n    sudoedit /etc/systemd/journald.conf\n"
            ),
            "{steps}"
        );
        assert!(
            steps.contains(
                "2. Then give the journal its directory and restart journald:\n    sudo mkdir -p /var/log/journal\n    sudo systemd-tmpfiles --create --prefix /var/log/journal\n    sudo systemctl restart systemd-journald\n"
            ),
            "{steps}"
        );
        assert!(
            steps.trim_end().ends_with(
                "3. Check that it is on disk now, and, after the next reboot, that the boots before it are listed:\n    journalctl --disk-usage\n    journalctl --list-boots"
            ),
            "{steps}"
        );
    }

    #[test]
    fn no_log_at_all_is_said_in_its_own_words() {
        let f = journal_finding(&setup(setting(Storage::None, "/x.conf"), true, &[]));
        assert_eq!(f.severity, Severity::Warning);
        assert!(
            f.explanation
                .contains("journald is told to keep no log at all (`Storage=none` in `/x.conf`)"),
            "{}",
            f.explanation
        );
        assert!(
            !f.explanation.contains("in memory only"),
            "{}",
            f.explanation
        );
        assert!(f.recommendation.unwrap().contains("sudoedit /x.conf"));
    }

    #[test]
    fn without_a_directory_the_directory_is_the_first_step() {
        for value in [None, Some(Storage::Auto)] {
            let f = journal_finding(&setup(
                value.and_then(|v| setting(v, "/etc/systemd/journald.conf")),
                false,
                &[],
            ));
            assert_eq!(f.severity, Severity::Warning, "{value:?}");
            assert!(
                f.explanation.contains("`/var/log/journal` does not exist"),
                "{}",
                f.explanation
            );
            let steps = f.recommendation.unwrap();
            assert!(
                steps.starts_with(
                    "1. Keep the journal on disk. Its directory is all `Storage=auto` needs:\n    sudo mkdir -p /var/log/journal\n"
                ),
                "{steps}"
            );
            assert!(!steps.contains("sudoedit"), "{steps}");
            assert!(!steps.contains("Set `Storage=persistent`"), "{steps}");
        }
    }

    #[test]
    fn a_classic_log_makes_up_for_a_journal_in_memory() {
        let f = journal_finding(&setup(None, false, &[syslog_file()]));
        assert_eq!(f.severity, Severity::Info);
        assert_eq!(f.confidence.percent, 90);
        assert!(f.recommendation.is_none());
        assert!(
            f.explanation
                .contains("On its own the journal would not survive a reboot"),
            "{}",
            f.explanation
        );
        assert!(
            f.explanation
                .contains("`/var/log/syslog` (last written 3 hours ago)"),
            "{}",
            f.explanation
        );
        assert_eq!(evidence(&f, "syslog_files"), Some("/var/log/syslog"));

        let both = [
            syslog_file(),
            SyslogFile {
                path: "/var/log/messages",
                age_secs: 2 * DAY,
            },
        ];
        let f = journal_finding(&setup(setting(Storage::None, "/x.conf"), true, &both));
        assert_eq!(f.severity, Severity::Info);
        assert!(
            f.explanation.contains(
                "`/var/log/syslog` (last written 3 hours ago), `/var/log/messages` (last written 2 days ago)"
            ),
            "{}",
            f.explanation
        );
        assert!(
            f.explanation
                .contains("journald is told to keep no log at all"),
            "{}",
            f.explanation
        );
        assert_eq!(
            evidence(&f, "syslog_files"),
            Some("/var/log/syslog,/var/log/messages")
        );
        // A journal on disk does not need them.
        let f = journal_finding(&setup(None, true, &both));
        assert!(f.explanation.contains("kept on disk"), "{}", f.explanation);
        assert!(!f.explanation.contains("classic"), "{}", f.explanation);
    }

    #[test]
    fn a_path_that_is_not_safe_in_a_command_is_not_put_in_one() {
        let f = journal_finding(&setup(
            setting(Storage::Volatile, "/etc/systemd/journald.conf.d/a b;c.conf"),
            true,
            &[],
        ));
        let steps = f.recommendation.unwrap();
        assert!(!steps.contains("sudoedit"), "{steps}");
        assert!(
            steps.contains("in `/etc/systemd/journald.conf.d/a b;c.conf`"),
            "{steps}"
        );
        assert!(steps.contains("sudo mkdir -p /var/log/journal"), "{steps}");
    }

    #[test]
    fn no_recommendation_hides_a_command_in_its_prose() {
        for s in [
            setup(None, false, &[]),
            setup(setting(Storage::Volatile, "/etc/x.conf"), true, &[]),
            setup(setting(Storage::None, "/etc/x.conf"), true, &[]),
        ] {
            let steps = journal_finding(&s).recommendation.unwrap();
            for line in steps.lines().filter(|l| !l.starts_with("    ")) {
                for word in ["sudo ", "systemctl ", "journalctl ", "mkdir "] {
                    assert!(!line.contains(word), "{line}");
                }
            }
        }
    }
}
