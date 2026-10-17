// SPDX-License-Identifier: GPL-3.0-only

//! SRV004 -- package updates that are waiting, on a Debian-like system.
//!
//! SRV001 says whether the machine has a way to patch itself. This says what
//! that way has not done yet: how many updates are waiting, how many of them
//! come from a security repository, and whether the machine has been looking
//! and upgrading lately. Both are judged by time, not by the bare number: on
//! a machine that upgrades every night, a security update published this
//! morning is normal; the same update on a machine where nothing has been
//! installed for a week is not.
//!
//! The count is `apt list --upgradable`, which reads the lists apt already
//! has and needs no network and no root. It is as fresh as those lists, which
//! is why the age of the lists is part of the verdict. Red Hat-like systems
//! are not looked at: `dnf` would have to refresh its metadata to answer.

use std::fs;
use std::path::Path;

use crate::models::{Category, Confidence, Finding, Severity};
use crate::modules::recommend::Steps;

use super::age::{age_text, DAY};
use super::collect::modified_unix;

/// Package lists older than this have missed whatever was published since:
/// the daily refresh is not running.
pub const LISTS_STALE_SECS: u64 = 7 * DAY;

/// Security updates that have waited while nothing was upgraded for this long
/// are not waiting for the night job: it is not doing its work.
pub const RUN_STALE_SECS: u64 = 3 * DAY;

/// Touched by every successful `apt update`, by hand or by the daily job.
const UPDATE_STAMP: &str = "var/lib/apt/periodic/update-success-stamp";
/// Touched each time `unattended-upgrade` runs, whether it installs or not.
const UPGRADE_STAMP: &str = "var/lib/apt/periodic/unattended-upgrades-stamp";
/// Written to by every action of dpkg, so its date is the last time a package
/// was installed, upgraded or removed (by hand or by a job).
const DPKG_LOG: &str = "var/log/dpkg.log";

/// Lines of the listing looked at; a real one has a few hundred at most.
const MAX_LINES: usize = 100_000;

/// What `apt list --upgradable` lists.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Upgradable {
    pub total: usize,
    /// How many of them come from a repository whose name ends in
    /// `-security` (`noble-security`, `stable-security`...).
    pub security: usize,
}

/// The facts SRV004 judges.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PendingUpdates {
    /// `None` when `apt list --upgradable` did not answer.
    pub upgradable: Option<Upgradable>,
    /// The last successful `apt update`; `None` if there is no stamp.
    pub lists_unix: Option<u64>,
    /// The last upgrade job, or the last thing dpkg did, whichever is later.
    pub last_run_unix: Option<u64>,
}

/// The output of `apt list --upgradable`: a `Listing...` line, then one per
/// package, `name/suites version arch [upgradable from: version]`. The suites
/// are those the new version is in, separated by commas.
pub fn parse_upgradable(text: &str) -> Upgradable {
    let mut upgradable = Upgradable {
        total: 0,
        security: 0,
    };
    for line in text.lines().take(MAX_LINES) {
        let Some((name, suites)) = line
            .split_whitespace()
            .next()
            .and_then(|word| word.split_once('/'))
        else {
            continue;
        };
        if name.is_empty() {
            continue;
        }
        upgradable.total += 1;
        if suites
            .split(',')
            .any(|suite| suite.to_ascii_lowercase().ends_with("-security"))
        {
            upgradable.security += 1;
        }
    }
    upgradable
}

/// The stamps under `root` (`/` on a real machine), with the listing the
/// caller got from `apt`.
pub fn read(root: &Path, listing: Option<&str>) -> PendingUpdates {
    let modified = |path: &str| {
        fs::metadata(root.join(path))
            .ok()
            .and_then(|metadata| modified_unix(&metadata))
    };
    PendingUpdates {
        upgradable: listing.map(parse_upgradable),
        lists_unix: modified(UPDATE_STAMP),
        last_run_unix: modified(UPGRADE_STAMP).max(modified(DPKG_LOG)),
    }
}

fn plural(count: usize, word: &str) -> String {
    if count == 1 {
        format!("{count} {word}")
    } else {
        format!("{count} {word}s")
    }
}

/// The finding. Pure.
pub fn pending_finding(pending: &PendingUpdates, now_unix: u64) -> Finding {
    // A clock behind a file's date reads as "just now".
    let age = |unix: Option<u64>| unix.map(|t| now_unix.saturating_sub(t));
    let lists_age = age(pending.lists_unix);
    let run_age = age(pending.last_run_unix);
    let security = pending.upgradable.map_or(0, |u| u.security);
    let lists_stale = lists_age.is_some_and(|age| age >= LISTS_STALE_SECS);
    let nothing_upgrading = security > 0 && !run_age.is_some_and(|age| age < RUN_STALE_SECS);

    let counted = match pending.upgradable {
        None => {
            "The updates that are waiting could not be counted (`apt list --upgradable` did not \
             answer)"
                .to_string()
        }
        Some(Upgradable { total: 0, .. }) => "No package update is waiting".to_string(),
        Some(Upgradable { total, security: 0 }) => {
            format!(
                "{} waiting, none of them security updates",
                plural(total, "package update")
            )
        }
        Some(Upgradable { total, security }) => format!(
            "{} waiting, {} of them from a security repository",
            plural(total, "package update"),
            security
        ),
    };
    let lists = match lists_age {
        Some(age) => format!("as of the package lists, refreshed {} ago", age_text(age)),
        None => "when the package lists were last refreshed is not known".to_string(),
    };
    let mut text = format!("{counted} ({lists}).");
    if lists_stale {
        text.push_str(
            " That is over a week: `apt` cannot know about what has been published since, so \
             the real number may be higher, and the daily refresh is not working.",
        );
    }
    if nothing_upgrading {
        match run_age {
            Some(age) => text.push_str(&format!(
                " Nothing has been upgraded or installed here for {}, though `unattended-upgrades` \
                 would normally have taken security updates within a day.",
                age_text(age)
            )),
            None => text.push_str(
                " Nothing is known to have been upgraded or installed here, though \
                 `unattended-upgrades` would normally have taken security updates within a day.",
            ),
        }
        text.push_str(" SRV001 says whether it is set up.");
    } else if let Some(age) = run_age.filter(|_| security > 0) {
        text.push_str(&format!(
            " Packages were last installed or upgraded here {} ago, and these are still waiting: \
             they may have been published since, or be held back (a held package, a repository \
             the automatic job is not allowed to take from).",
            age_text(age)
        ));
    }

    let warning = lists_stale || nothing_upgrading;
    let (severity, confidence) = if warning {
        (Severity::Warning, Confidence::strong_indication(80))
    } else {
        (Severity::Info, Confidence::direct_observation())
    };
    let mut builder = Finding::builder(
        "SRV004",
        "Updates Waiting",
        Category::Security,
        severity,
        confidence,
    );
    if let Some(upgradable) = pending.upgradable {
        builder = builder
            .evidence("updates_waiting", upgradable.total.to_string())
            .evidence("security_updates_waiting", upgradable.security.to_string());
    }
    if let Some(age) = lists_age {
        builder = builder.evidence("package_lists_age_days", (age / DAY).to_string());
    }
    if let Some(age) = run_age {
        builder = builder.evidence("last_upgrade_age_days", (age / DAY).to_string());
    }
    builder = builder.explanation(text);
    if warning {
        builder = builder.recommendation(steps(lists_stale, nothing_upgrading).build());
    }
    builder.build()
}

fn steps(lists_stale: bool, nothing_upgrading: bool) -> Steps {
    let mut steps = Steps::new();
    if lists_stale {
        steps = steps
            .step(
                "Refresh the lists and see what is waiting:",
                &["sudo apt update", "apt list --upgradable"],
            )
            .step(
                "Find out why the daily refresh does not happen:",
                &[
                    "systemctl status apt-daily.timer",
                    "journalctl -u apt-daily.service -n 20 --no-pager",
                ],
            );
    } else {
        steps = steps.step(
            "See the security updates that are waiting:",
            &["apt list --upgradable 2>/dev/null | grep -i security"],
        );
    }
    if nothing_upgrading {
        steps = steps
            .step(
                "Install them. A new kernel or library only takes effect after a reboot; SRV003 \
                 and SRV005 say whether one is waiting:",
                &["sudo apt upgrade"],
            )
            .step(
                "Find out why the automatic job has not done it:",
                &[
                    "systemctl status apt-daily-upgrade.timer",
                    "sudo tail -n 30 /var/log/unattended-upgrades/unattended-upgrades.log",
                ],
            );
    }
    steps
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs::File;
    use std::path::PathBuf;
    use std::time::{Duration, UNIX_EPOCH};

    const NOW: u64 = 1_000_000_000;

    const UBUNTU: &str = "\
Listing...
curl/noble-security 8.5.0-2ubuntu10.16 amd64 [upgradable from: 8.5.0-2ubuntu10.15]
fonts-opensymbol/noble-updates,noble-security 4:102.12+LibO24.2.7-0ubuntu0.24.04.7 all [upgradable from: 4:102.12+LibO24.2.7-0ubuntu0.24.04.6]
libapparmor1/noble-updates 4.0.1really4.0.1-0ubuntu0.24.04.9 amd64 [upgradable from: 4.0.1really4.0.1-0ubuntu0.24.04.8]
";

    fn evidence<'a>(finding: &'a Finding, key: &str) -> Option<&'a str> {
        finding
            .evidence
            .iter()
            .find(|(k, _)| k == key)
            .map(|(_, v)| v.as_str())
    }

    fn pending(
        total: usize,
        security: usize,
        lists_ago: Option<u64>,
        run_ago: Option<u64>,
    ) -> PendingUpdates {
        PendingUpdates {
            upgradable: Some(Upgradable { total, security }),
            lists_unix: lists_ago.map(|a| NOW - a),
            last_run_unix: run_ago.map(|a| NOW - a),
        }
    }

    // --- the listing -------------------------------------------------------

    #[test]
    fn the_listing_is_counted_with_its_security_updates() {
        assert_eq!(
            parse_upgradable(UBUNTU),
            Upgradable {
                total: 3,
                security: 2
            }
        );
    }

    #[test]
    fn a_security_repository_is_told_by_its_suffix_whatever_the_distribution() {
        for (suites, security) in [
            ("noble-security", 1),
            ("jammy-security", 1),
            ("stable-security", 1),
            ("bookworm-security,bookworm-updates", 1),
            ("bookworm-updates,bookworm-security", 1),
            ("noble-infra-security", 1),
            ("noble-apps-security", 1),
            ("Stable-Security", 1),
            ("noble-updates", 0),
            ("noble", 0),
            ("stable", 0),
            ("security", 0),
            ("noble-security-extra", 0),
            ("noble-securityx", 0),
            ("", 0),
        ] {
            let text = format!("Listing...\npkg/{suites} 1.0 amd64 [upgradable from: 0.9]\n");
            assert_eq!(parse_upgradable(&text).security, security, "{suites:?}");
            assert_eq!(parse_upgradable(&text).total, 1, "{suites:?}");
        }
    }

    #[test]
    fn lines_that_are_not_packages_are_not_counted() {
        for text in [
            "",
            "Listing...\n",
            "Listing... Done\n",
            "\n\n",
            "WARNING: apt does not have a stable CLI interface.\n",
            "/usr/bin/thing 1.0 amd64\n",
            "   \n",
            "N: Unable to locate package\n",
        ] {
            assert_eq!(parse_upgradable(text).total, 0, "{text:?}");
        }
    }

    #[test]
    fn a_listing_cannot_be_counted_past_the_bound() {
        let text: String = (0..100_100)
            .map(|i| format!("p{i}/noble-security 1 amd64 [upgradable from: 0]\n"))
            .collect();
        let counted = parse_upgradable(&text);
        assert_eq!(counted.total, 100_000);
        assert_eq!(counted.security, 100_000);
    }

    // --- the stamps --------------------------------------------------------

    fn tree(name: &str) -> PathBuf {
        let root = std::env::temp_dir().join(format!(
            "linuxdoctor-server-pending-{name}-{}",
            std::process::id()
        ));
        let _ = fs::remove_dir_all(&root);
        fs::create_dir_all(root.join("var/lib/apt/periodic")).unwrap();
        fs::create_dir_all(root.join("var/log")).unwrap();
        root
    }

    fn stamp(root: &Path, path: &str, ago: u64) {
        let path = root.join(path);
        fs::write(&path, "").unwrap();
        File::options()
            .write(true)
            .open(path)
            .unwrap()
            .set_modified(UNIX_EPOCH + Duration::from_secs(NOW - ago))
            .unwrap();
    }

    #[test]
    fn the_stamps_are_read_under_the_root() {
        let root = tree("stamps");
        stamp(&root, UPDATE_STAMP, 3600);
        stamp(&root, UPGRADE_STAMP, 2 * 86_400);
        stamp(&root, DPKG_LOG, 5 * 86_400);
        let read = read(&root, Some(UBUNTU));
        assert_eq!(read.lists_unix, Some(NOW - 3600));
        assert_eq!(read.last_run_unix, Some(NOW - 2 * 86_400));
        assert_eq!(read.upgradable.unwrap().total, 3);
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn the_later_of_the_job_and_dpkg_is_the_last_run() {
        let root = tree("later");
        stamp(&root, UPGRADE_STAMP, 5 * 86_400);
        stamp(&root, DPKG_LOG, 86_400);
        assert_eq!(read(&root, None).last_run_unix, Some(NOW - 86_400));
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn a_stamp_alone_is_enough_and_none_is_none() {
        let root = tree("alone");
        assert_eq!(
            read(&root, None),
            PendingUpdates {
                upgradable: None,
                lists_unix: None,
                last_run_unix: None
            }
        );
        stamp(&root, DPKG_LOG, 100);
        assert_eq!(read(&root, None).last_run_unix, Some(NOW - 100));
        assert_eq!(read(&root, None).lists_unix, None);
        let _ = fs::remove_dir_all(&root);
        let bare = std::env::temp_dir().join(format!(
            "linuxdoctor-server-pending-bare-{}",
            std::process::id()
        ));
        let _ = fs::remove_dir_all(&bare);
        assert_eq!(read(&bare, Some("")).lists_unix, None);
    }

    // --- the verdict -------------------------------------------------------

    #[test]
    fn a_machine_with_nothing_waiting_is_information() {
        let f = pending_finding(&pending(0, 0, Some(3600), Some(86_400)), NOW);
        assert_eq!(f.id, "SRV004");
        assert_eq!(f.title, "Updates Waiting");
        assert_eq!(f.severity, Severity::Info);
        assert_eq!(f.confidence.percent, 100);
        assert_eq!(f.recommendation, None);
        assert_eq!(
            f.explanation,
            "No package update is waiting (as of the package lists, refreshed 1 hour ago)."
        );
        assert_eq!(evidence(&f, "updates_waiting"), Some("0"));
        assert_eq!(evidence(&f, "security_updates_waiting"), Some("0"));
        assert_eq!(evidence(&f, "package_lists_age_days"), Some("0"));
        assert_eq!(evidence(&f, "last_upgrade_age_days"), Some("1"));
    }

    #[test]
    fn updates_that_are_not_security_ones_never_make_a_warning() {
        let f = pending_finding(&pending(1, 0, Some(3600), Some(30 * 86_400)), NOW);
        assert_eq!(f.severity, Severity::Info);
        assert_eq!(
            f.explanation,
            "1 package update waiting, none of them security updates (as of the package \
             lists, refreshed 1 hour ago)."
        );
        let f = pending_finding(&pending(40, 0, Some(3600), None), NOW);
        assert_eq!(f.severity, Severity::Info);
        assert!(
            f.explanation
                .starts_with("40 package updates waiting, none"),
            "{}",
            f.explanation
        );
    }

    #[test]
    fn security_updates_with_a_recent_upgrade_are_information_with_a_reason() {
        let f = pending_finding(&pending(5, 2, Some(3600), Some(86_400)), NOW);
        assert_eq!(f.severity, Severity::Info);
        assert_eq!(f.recommendation, None);
        assert_eq!(
            f.explanation,
            "5 package updates waiting, 2 of them from a security repository (as of the \
             package lists, refreshed 1 hour ago). Packages were last installed or upgraded \
             here 1 day ago, and these are still waiting: they may have been published since, \
             or be held back (a held package, a repository the automatic job is not allowed to \
             take from)."
        );
    }

    #[test]
    fn security_updates_with_nothing_upgrading_are_a_warning() {
        let f = pending_finding(&pending(5, 1, Some(3600), Some(4 * 86_400)), NOW);
        assert_eq!(f.severity, Severity::Warning);
        assert_eq!(f.confidence.percent, 80);
        assert_eq!(
            f.explanation,
            "5 package updates waiting, 1 of them from a security repository (as of the \
             package lists, refreshed 1 hour ago). Nothing has been upgraded or installed here \
             for 4 days, though `unattended-upgrades` would normally have taken security \
             updates within a day. SRV001 says whether it is set up."
        );
        let rec = f.recommendation.unwrap();
        assert!(
            rec.starts_with("1. See the security updates that are waiting:"),
            "{rec}"
        );
        for command in [
            "\n    apt list --upgradable 2>/dev/null | grep -i security",
            "\n    sudo apt upgrade",
            "\n    systemctl status apt-daily-upgrade.timer",
            "\n    sudo tail -n 30 /var/log/unattended-upgrades/unattended-upgrades.log",
        ] {
            assert!(rec.contains(command), "{command}\n{rec}");
        }
        assert!(!rec.contains("sudo apt update"), "{rec}");
    }

    #[test]
    fn nothing_known_to_have_run_is_the_same_warning() {
        let f = pending_finding(&pending(1, 1, Some(3600), None), NOW);
        assert_eq!(f.severity, Severity::Warning);
        assert!(
            f.explanation
                .contains("Nothing is known to have been upgraded or installed here, though"),
            "{}",
            f.explanation
        );
        assert_eq!(evidence(&f, "last_upgrade_age_days"), None);
    }

    #[test]
    fn three_days_without_an_upgrade_is_where_the_warning_starts() {
        let at = |run: u64| pending_finding(&pending(1, 1, Some(3600), Some(run)), NOW).severity;
        assert_eq!(at(3 * 86_400 - 1), Severity::Info);
        assert_eq!(at(3 * 86_400), Severity::Warning);
        assert_eq!(at(0), Severity::Info);
    }

    #[test]
    fn a_week_without_a_refresh_is_where_the_lists_turn_stale() {
        let at = |lists: u64| pending_finding(&pending(0, 0, Some(lists), Some(0)), NOW).severity;
        assert_eq!(at(7 * 86_400 - 1), Severity::Info);
        assert_eq!(at(7 * 86_400), Severity::Warning);
    }

    #[test]
    fn stale_lists_say_the_number_may_be_low_and_how_to_refresh() {
        let f = pending_finding(&pending(0, 0, Some(12 * 86_400), Some(0)), NOW);
        assert_eq!(f.severity, Severity::Warning);
        assert_eq!(f.confidence.percent, 80);
        assert_eq!(
            f.explanation,
            "No package update is waiting (as of the package lists, refreshed 12 days ago). \
             That is over a week: `apt` cannot know about what has been published since, so \
             the real number may be higher, and the daily refresh is not working."
        );
        assert_eq!(evidence(&f, "package_lists_age_days"), Some("12"));
        let rec = f.recommendation.unwrap();
        assert!(rec.starts_with("1. Refresh the lists"), "{rec}");
        for command in [
            "\n    sudo apt update",
            "\n    apt list --upgradable\n",
            "\n    systemctl status apt-daily.timer",
            "\n    journalctl -u apt-daily.service -n 20 --no-pager",
        ] {
            assert!(rec.contains(command), "{command}\n{rec}");
        }
        for absent in ["sudo apt upgrade", "grep -i security", "apt-daily-upgrade"] {
            assert!(!rec.contains(absent), "{absent}\n{rec}");
        }
    }

    #[test]
    fn stale_lists_and_idle_security_updates_get_all_the_steps() {
        let f = pending_finding(&pending(9, 4, Some(20 * 86_400), Some(20 * 86_400)), NOW);
        assert_eq!(f.severity, Severity::Warning);
        let rec = f.recommendation.unwrap();
        let at = |needle: &str| rec.find(needle).unwrap();
        assert!(at("sudo apt update") < at("apt-daily.timer"));
        assert!(at("apt-daily.timer") < at("sudo apt upgrade"));
        assert!(at("sudo apt upgrade") < at("apt-daily-upgrade.timer"));
        // The security listing is for when the lists are not the problem.
        assert!(!rec.contains("grep -i security"), "{rec}");
        assert!(f.explanation.contains("over a week"), "{}", f.explanation);
        assert!(
            f.explanation
                .contains("Nothing has been upgraded or installed here for 20 days"),
            "{}",
            f.explanation
        );
    }

    #[test]
    fn a_count_that_could_not_be_made_is_said_and_not_invented() {
        let none = PendingUpdates {
            upgradable: None,
            lists_unix: Some(NOW - 60),
            last_run_unix: Some(NOW - 60),
        };
        let f = pending_finding(&none, NOW);
        assert_eq!(f.severity, Severity::Info);
        assert_eq!(
            f.explanation,
            "The updates that are waiting could not be counted (`apt list --upgradable` did \
             not answer) (as of the package lists, refreshed 1 minute ago)."
        );
        assert_eq!(evidence(&f, "updates_waiting"), None);
        assert_eq!(evidence(&f, "security_updates_waiting"), None);
        // Stale lists are a finding by themselves, with or without a count.
        let stale = PendingUpdates {
            lists_unix: Some(NOW - 9 * 86_400),
            ..none
        };
        assert_eq!(pending_finding(&stale, NOW).severity, Severity::Warning);
    }

    #[test]
    fn lists_with_no_stamp_are_not_judged_stale() {
        let f = pending_finding(&pending(2, 0, None, Some(0)), NOW);
        assert_eq!(f.severity, Severity::Info);
        assert_eq!(
            f.explanation,
            "2 package updates waiting, none of them security updates (when the package lists \
             were last refreshed is not known)."
        );
        assert_eq!(evidence(&f, "package_lists_age_days"), None);
    }

    #[test]
    fn a_clock_behind_the_stamps_reads_as_just_now() {
        let ahead = PendingUpdates {
            upgradable: Some(Upgradable {
                total: 1,
                security: 1,
            }),
            lists_unix: Some(NOW + 10 * 86_400),
            last_run_unix: Some(NOW + 10 * 86_400),
        };
        let f = pending_finding(&ahead, NOW);
        assert_eq!(f.severity, Severity::Info);
        assert_eq!(evidence(&f, "package_lists_age_days"), Some("0"));
        assert_eq!(evidence(&f, "last_upgrade_age_days"), Some("0"));
    }

    #[test]
    fn no_command_is_hidden_in_the_prose_of_the_steps() {
        // A command is on its own indented line; every other line is prose,
        // and prose has no `sudo`, no `apt` and no `systemctl`.
        for (stale, idle) in [(true, false), (false, true), (true, true)] {
            let text = steps(stale, idle).build();
            let mut commands = 0;
            for line in text.lines() {
                if line.starts_with("    ") {
                    commands += 1;
                    continue;
                }
                for word in ["sudo", "apt ", "systemctl", "journalctl", "tail "] {
                    assert!(!line.contains(word), "{word}: {line}");
                }
            }
            assert!(commands >= 2, "{text}");
        }
    }

    #[test]
    fn one_security_update_is_said_in_the_singular() {
        let f = pending_finding(&pending(1, 1, Some(0), Some(0)), NOW);
        assert!(
            f.explanation
                .starts_with("1 package update waiting, 1 of them from a security"),
            "{}",
            f.explanation
        );
        // One is enough for the reason to be given.
        assert!(
            f.explanation
                .contains("Packages were last installed or upgraded here less than a minute ago"),
            "{}",
            f.explanation
        );
    }
}
