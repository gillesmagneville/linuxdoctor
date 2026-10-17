// SPDX-License-Identifier: GPL-3.0-only

//! SRV003 -- a reboot that has been waiting for days.
//!
//! On a Debian-like system, an update that only takes effect after a reboot (a
//! new kernel, glibc, systemd...) writes `/var/run/reboot-required`, and the
//! names of the packages in `/var/run/reboot-required.pkgs`. Until the reboot
//! the machine runs the old code, so the fixes in the update are not active.
//! The kernel module (KERN004) reports that the marker is there. On a server,
//! what matters is for how long: a reboot that is a few days away is a
//! maintenance window, one that has been waiting for weeks is a machine
//! running known vulnerabilities.
//!
//! The marker is a file in `/run`, which is emptied at every boot, so its date
//! is not older than the boot. It is written again by every update that needs
//! a reboot, so the date is that of the *last* one: the reboot has been
//! waiting for at least that long, and perhaps longer.
//!
//! Other families have no such file (KERN004 says as much), so nothing is
//! reported there; this does not mean that nothing is waiting.

use std::collections::BTreeSet;
use std::fs;
use std::path::Path;

use crate::core::text::clean;
use crate::models::{Category, Confidence, Finding, Severity};
use crate::modules::recommend::Steps;

use super::age::{age_text, DAY};
use super::collect::{modified_unix, read_config};

const MARKER: &str = "var/run/reboot-required";
const PACKAGES: &str = "var/run/reboot-required.pkgs";

/// A reboot that has been waiting for less than this is a maintenance window
/// to come, not a problem; nothing is reported.
pub const STALE_AFTER_SECS: u64 = 7 * DAY;

/// Packages named in a finding; the others are counted.
const MAX_PACKAGES: usize = 10;

/// Longest package name quoted back.
const MAX_NAME: usize = 100;

/// A reboot that is waiting.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PendingReboot {
    /// When the marker was last written, in seconds since 1970; `None` if the
    /// file system would not say.
    pub modified_unix: Option<u64>,
    /// The packages that asked for the reboot, each once, in the order the
    /// file has them; at most [`MAX_PACKAGES`].
    pub packages: Vec<String>,
    /// How many more were named.
    pub more_packages: usize,
}

/// The package names in `reboot-required.pkgs`: one per line, blanks skipped,
/// each name once (every update appends its own).
pub fn parse_packages(text: &str) -> (Vec<String>, usize) {
    let mut seen = BTreeSet::new();
    let mut named = Vec::new();
    for line in text.lines() {
        let name = line.trim();
        if !name.is_empty() && seen.insert(name) {
            named.push(clean(name, MAX_NAME));
        }
    }
    let more = named.len().saturating_sub(MAX_PACKAGES);
    named.truncate(MAX_PACKAGES);
    (named, more)
}

/// Reads the marker under `root` (`/` on a real machine); `None` when there
/// is no reboot waiting.
pub fn read(root: &Path) -> Option<PendingReboot> {
    let metadata = fs::metadata(root.join(MARKER)).ok()?;
    let (packages, more_packages) = read_config(&root.join(PACKAGES))
        .map(|text| parse_packages(&text))
        .unwrap_or_default();
    Some(PendingReboot {
        modified_unix: modified_unix(&metadata),
        packages,
        more_packages,
    })
}

/// The finding, when the reboot has been waiting long enough; `None` before
/// that, and when the age is unknown.
pub fn reboot_finding(pending: &PendingReboot, now_unix: u64) -> Option<Finding> {
    // A clock that is behind the file's date reads as "just written".
    let age = now_unix.saturating_sub(pending.modified_unix?);
    if age < STALE_AFTER_SECS {
        return None;
    }

    let mut text = format!(
        "A reboot has been waiting for at least {}: `/var/run/reboot-required` was last written \
         that long ago, and every update that needs a reboot writes it again, so it may have \
         been waiting for longer. Until the reboot, the machine runs the old kernel or \
         libraries, so the security fixes in those updates are not active yet.",
        age_text(age)
    );
    if !pending.packages.is_empty() {
        text.push_str(&format!(
            " Packages that asked for it: {}",
            pending.packages.join(", ")
        ));
        if pending.more_packages > 0 {
            text.push_str(&format!(" (and {} more)", pending.more_packages));
        }
        text.push('.');
    }
    text.push_str(
        " If the kernel is live-patched, its fixes are already active; the other packages still \
         need the reboot. KERN004 reports the same marker, without its age.",
    );

    let mut builder = Finding::builder(
        "SRV003",
        "Reboot Left Pending",
        Category::Kernel,
        Severity::Warning,
        Confidence::correlated(90),
    )
    .evidence("reboot_required_age_days", (age / DAY).to_string());
    if !pending.packages.is_empty() {
        builder = builder.evidence("packages", pending.packages.join(","));
    }
    Some(
        builder
            .explanation(text)
            .recommendation(
                Steps::new()
                    .step(
                        "See what is waiting for the reboot:",
                        &["cat /var/run/reboot-required.pkgs"],
                    )
                    .step(
                        "Plan the reboot for a maintenance window, once the services the machine \
                         has to serve start by themselves, then reboot:",
                        &["sudo reboot"],
                    )
                    .step(
                        "After it, check that the marker is gone (the first command should say \
                         there is no such file) and which kernel runs:",
                        &["ls /var/run/reboot-required", "uname -r"],
                    )
                    .build(),
            )
            .build(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs::File;
    use std::path::PathBuf;
    use std::time::{Duration, UNIX_EPOCH};

    const NOW: u64 = 1_000_000_000;

    fn tree(name: &str) -> PathBuf {
        let root = std::env::temp_dir().join(format!(
            "linuxdoctor-server-reboot-{name}-{}",
            std::process::id()
        ));
        let _ = fs::remove_dir_all(&root);
        fs::create_dir_all(root.join("var/run")).unwrap();
        root
    }

    fn marker(root: &Path, ago: u64) {
        let path = root.join(MARKER);
        fs::write(&path, "*** System restart required ***\n").unwrap();
        let time = UNIX_EPOCH + Duration::from_secs(NOW - ago);
        File::options()
            .write(true)
            .open(path)
            .unwrap()
            .set_modified(time)
            .unwrap();
    }

    fn pending(ago: Option<u64>, packages: &[&str], more: usize) -> PendingReboot {
        PendingReboot {
            modified_unix: ago.map(|a| NOW - a),
            packages: packages.iter().map(|p| p.to_string()).collect(),
            more_packages: more,
        }
    }

    fn evidence<'a>(finding: &'a Finding, key: &str) -> Option<&'a str> {
        finding
            .evidence
            .iter()
            .find(|(k, _)| k == key)
            .map(|(_, v)| v.as_str())
    }

    // ----- the package list --------------------------------------------------------

    #[test]
    fn the_packages_are_each_named_once_in_the_order_of_the_file() {
        let (names, more) =
            parse_packages("linux-base\n\n  libc6  \nlinux-base\nsystemd\nlibc6\r\nlinux-base\n");
        assert_eq!(names, ["linux-base", "libc6", "systemd"]);
        assert_eq!(more, 0);
        assert_eq!(parse_packages(""), (Vec::new(), 0));
        assert_eq!(parse_packages("\n  \n\n"), (Vec::new(), 0));
    }

    #[test]
    fn only_so_many_packages_are_named_and_the_others_are_counted() {
        // Ten are named.
        let text: String = (0..13).map(|i| format!("pkg{i}\n")).collect();
        let (names, more) = parse_packages(&text);
        assert_eq!(names.len(), 10);
        assert_eq!(names[0], "pkg0");
        assert_eq!(names[9], "pkg9");
        assert_eq!(more, 3);
        // Exactly the limit is all of them.
        let text: String = (0..10).map(|i| format!("pkg{i}\n")).collect();
        assert_eq!(parse_packages(&text).1, 0);
        assert_eq!(parse_packages(&text).0.len(), 10);
        // One more is one more.
        let text: String = (0..11).map(|i| format!("pkg{i}\n")).collect();
        assert_eq!(parse_packages(&text).1, 1);
        // Repeats are not counted as more.
        let text: String = (0..30).map(|_| "same\n").collect();
        assert_eq!(parse_packages(&text), (vec!["same".to_string()], 0));
    }

    #[test]
    fn a_package_name_is_cleaned_and_shortened() {
        let (names, _) = parse_packages(&format!("evil\u{1b}[2J\n{}\n", "x".repeat(300)));
        assert_eq!(names[0], "evil?[2J");
        assert_eq!(names[1].chars().count(), 101, "{}", names[1]);
        assert!(names[1].ends_with('…'));
    }

    // ----- the marker ---------------------------------------------------------------

    #[test]
    fn no_marker_is_no_reboot_waiting() {
        let root = tree("none");
        assert_eq!(read(&root), None);
        // The packages alone are not a marker.
        fs::write(root.join(PACKAGES), "linux-base\n").unwrap();
        assert_eq!(read(&root), None);
    }

    #[test]
    fn the_marker_gives_its_date_and_the_packages() {
        let root = tree("marker");
        marker(&root, 9 * DAY);
        fs::write(root.join(PACKAGES), "linux-image-6.8.0-45-generic\nlibc6\n").unwrap();
        let reboot = read(&root).unwrap();
        assert_eq!(reboot.modified_unix, Some(NOW - 9 * DAY));
        assert_eq!(reboot.packages, ["linux-image-6.8.0-45-generic", "libc6"]);
        assert_eq!(reboot.more_packages, 0);
    }

    #[test]
    fn the_packages_beyond_the_limit_are_counted_when_read() {
        let root = tree("many");
        marker(&root, 60);
        let list: String = (0..12).map(|i| format!("pkg{i}\n")).collect();
        fs::write(root.join(PACKAGES), list).unwrap();
        let reboot = read(&root).unwrap();
        assert_eq!(reboot.packages.len(), 10);
        assert_eq!(reboot.more_packages, 2);
    }

    #[test]
    fn a_marker_without_the_list_is_still_a_reboot_waiting() {
        let root = tree("no-list");
        marker(&root, 60);
        let reboot = read(&root).unwrap();
        assert!(reboot.packages.is_empty());
        assert_eq!(reboot.more_packages, 0);
        assert_eq!(reboot.modified_unix, Some(NOW - 60));
    }

    // ----- the finding ------------------------------------------------------------------

    #[test]
    fn a_reboot_that_has_not_waited_a_week_is_not_reported() {
        // A week is 604800 seconds.
        for ago in [0, 60, 86_400, 6 * 86_400 + 86_399, 604_799] {
            assert!(
                reboot_finding(&pending(Some(ago), &["libc6"], 0), NOW).is_none(),
                "{ago}"
            );
        }
        // Exactly a week is a week.
        assert!(reboot_finding(&pending(Some(604_800), &[], 0), NOW).is_some());
    }

    #[test]
    fn nothing_is_said_when_the_age_is_not_known_or_is_in_the_future() {
        assert!(reboot_finding(&pending(None, &["libc6"], 0), NOW).is_none());
        let future = PendingReboot {
            modified_unix: Some(NOW + 30 * DAY),
            packages: Vec::new(),
            more_packages: 0,
        };
        assert!(reboot_finding(&future, NOW).is_none());
    }

    #[test]
    fn a_reboot_left_for_weeks_is_a_warning_that_says_how_long_and_what_for() {
        let f = reboot_finding(
            &pending(
                Some(40 * DAY + 5),
                &["linux-image-6.8.0-45-generic", "libc6"],
                0,
            ),
            NOW,
        )
        .unwrap();
        assert_eq!(f.id, "SRV003");
        assert_eq!(f.title, "Reboot Left Pending");
        assert_eq!(f.category, Category::Kernel);
        assert_eq!(f.severity, Severity::Warning);
        assert_eq!(f.confidence.percent, 90);
        assert!(
            f.explanation.contains("waiting for at least 40 days"),
            "{}",
            f.explanation
        );
        assert!(
            f.explanation.contains("may have been waiting for longer"),
            "{}",
            f.explanation
        );
        assert!(
            f.explanation
                .contains("Packages that asked for it: linux-image-6.8.0-45-generic, libc6."),
            "{}",
            f.explanation
        );
        assert!(f.explanation.contains("live-patched"), "{}", f.explanation);
        assert!(f.explanation.contains("KERN004"), "{}", f.explanation);
        assert_eq!(evidence(&f, "reboot_required_age_days"), Some("40"));
        assert_eq!(
            evidence(&f, "packages"),
            Some("linux-image-6.8.0-45-generic,libc6")
        );
    }

    #[test]
    fn the_age_is_in_days_rounded_down() {
        let f = reboot_finding(&pending(Some(7 * DAY + DAY - 1), &[], 0), NOW).unwrap();
        assert_eq!(evidence(&f, "reboot_required_age_days"), Some("7"));
        assert!(
            f.explanation.contains("at least 7 days"),
            "{}",
            f.explanation
        );
        let f = reboot_finding(&pending(Some(8 * DAY), &[], 0), NOW).unwrap();
        assert_eq!(evidence(&f, "reboot_required_age_days"), Some("8"));
    }

    #[test]
    fn the_packages_are_left_out_when_the_list_is_missing_and_the_others_counted() {
        let f = reboot_finding(&pending(Some(10 * DAY), &[], 0), NOW).unwrap();
        assert!(
            !f.explanation.contains("Packages that asked"),
            "{}",
            f.explanation
        );
        assert_eq!(evidence(&f, "packages"), None);

        let f = reboot_finding(&pending(Some(10 * DAY), &["a", "b"], 3), NOW).unwrap();
        assert!(
            f.explanation.contains("asked for it: a, b (and 3 more)."),
            "{}",
            f.explanation
        );
        let f = reboot_finding(&pending(Some(10 * DAY), &["a", "b"], 1), NOW).unwrap();
        assert!(
            f.explanation.contains("asked for it: a, b (and 1 more)."),
            "{}",
            f.explanation
        );
        // The evidence names those that are named.
        assert_eq!(evidence(&f, "packages"), Some("a,b"));
    }

    #[test]
    fn the_steps_are_the_same_for_every_reboot() {
        let f = reboot_finding(&pending(Some(10 * DAY), &["libc6"], 0), NOW).unwrap();
        let steps = f.recommendation.unwrap();
        assert_eq!(
            steps,
            "1. See what is waiting for the reboot:\n    cat /var/run/reboot-required.pkgs\n\
             2. Plan the reboot for a maintenance window, once the services the machine has to serve start by themselves, then reboot:\n    sudo reboot\n\
             3. After it, check that the marker is gone (the first command should say there is no such file) and which kernel runs:\n    ls /var/run/reboot-required\n    uname -r"
        );
        for line in steps.lines().filter(|l| !l.starts_with("    ")) {
            assert!(!line.contains("sudo "), "{line}");
        }
    }
}
