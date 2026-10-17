// SPDX-License-Identifier: GPL-3.0-only

//! SRV005 -- a newer kernel is installed than the one that runs.
//!
//! A kernel update takes effect at the next boot, not before. On a Debian-like
//! system the reboot marker says so (SRV003 and KERN004); the other families
//! have no marker, and the only way to know is to compare the running kernel
//! with the ones that are installed. This does it on every family, and says
//! nothing where the marker already speaks.
//!
//! Versions are compared as numbers, the way a person reads them: `6.8.0-45`
//! is older than `6.8.0-50`, and `6.8.9` older than `6.8.10`. Only a kernel of
//! the same flavor counts (`generic` against `generic`, `amd64` against
//! `amd64`): a machine that has a low-latency kernel installed beside the one
//! it runs has not forgotten to reboot.

use std::cmp::Ordering;
use std::collections::BTreeSet;
use std::fs;
use std::path::Path;

use crate::core::text::clean;
use crate::models::{Category, Confidence, Finding, Severity};
use crate::modules::recommend::Steps;

use super::age::{age_text, DAY};
use super::collect::modified_unix;

/// A kernel that was installed less than this long ago is a reboot to come,
/// not a reboot forgotten.
pub const STALE_AFTER_SECS: u64 = 7 * DAY;

const OSRELEASE: &str = "proc/sys/kernel/osrelease";
const BOOT: &str = "boot";
const MODULES: &str = "usr/lib/modules";
const LIVEPATCH: &str = "sys/kernel/livepatch";

/// Entries looked at in a directory, and characters kept of a version.
const MAX_ENTRIES: usize = 256;
const MAX_VERSION: usize = 100;

/// A kernel newer than the running one.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NewerKernel {
    pub running: String,
    /// The newest installed kernel of the same flavor.
    pub installed: String,
    /// When its initial RAM disk was written, which is when it was installed;
    /// `None` when the system has none by that name or would not say.
    pub installed_unix: Option<u64>,
    /// A live patch is loaded: the worst kernel flaws are already fixed in
    /// memory.
    pub livepatch: bool,
}

/// The numbers a kernel version starts with, and the rest of it.
#[derive(Debug, PartialEq, Eq)]
struct Version {
    numbers: Vec<u64>,
    flavor: String,
}

/// `6.8.0-45-generic` as `[6, 8, 0, 45]` and `generic`; `5.14.0-427.13.1.el9_4.x86_64`
/// as `[5, 14, 0, 427, 13, 1]` and `x86_64`. Two numbers at least, or it is not a
/// kernel version. The flavor leaves out the distribution tag (`el9_4`, `fc40`),
/// which changes with the minor release and says nothing about the kernel.
fn parse_version(text: &str) -> Option<Version> {
    let mut numbers = Vec::new();
    let mut tokens = text.split(['.', '-']).peekable();
    while let Some(token) = tokens.peek() {
        if token.is_empty() || !token.bytes().all(|b| b.is_ascii_digit()) {
            break;
        }
        numbers.push(token.parse::<u64>().ok()?);
        tokens.next();
    }
    if numbers.len() < 2 {
        return None;
    }
    let flavor: Vec<&str> = tokens.filter(|token| !is_distribution_tag(token)).collect();
    Some(Version {
        numbers,
        flavor: flavor.join("."),
    })
}

/// `el9`, `el9_4`, `fc40`: the release of a Red Hat-like distribution.
fn is_distribution_tag(token: &str) -> bool {
    let Some(rest) = token
        .strip_prefix("el")
        .or_else(|| token.strip_prefix("fc"))
    else {
        return false;
    };
    let number = |part: &str| !part.is_empty() && part.bytes().all(|b| b.is_ascii_digit());
    let mut parts = rest.split('_');
    let release = parts.next().is_some_and(number);
    let minor = match parts.next() {
        None => true,
        Some(minor) => number(minor),
    };
    release && minor && parts.next().is_none()
}

/// Numbers compared one by one, a missing one being zero.
fn compare(a: &[u64], b: &[u64]) -> Ordering {
    for i in 0..a.len().max(b.len()) {
        let order = a.get(i).unwrap_or(&0).cmp(b.get(i).unwrap_or(&0));
        if order != Ordering::Equal {
            return order;
        }
    }
    Ordering::Equal
}

/// The newest of `installed` that is newer than `running` and of its flavor.
/// Names that are not kernel versions are ignored; so is a `running` that is
/// not one.
pub fn newest_newer<'a>(running: &str, installed: &'a [String]) -> Option<&'a String> {
    let running = parse_version(running)?;
    installed
        .iter()
        .filter_map(|name| Some((name, parse_version(name)?)))
        .filter(|(_, version)| {
            version.flavor == running.flavor
                && compare(&version.numbers, &running.numbers) == Ordering::Greater
        })
        .max_by(|(_, a), (_, b)| compare(&a.numbers, &b.numbers))
        .map(|(name, _)| name)
}

/// The versions of the kernels that are installed: `/boot/vmlinuz-<version>`
/// (Debian-like and Red Hat-like systems), and the `vmlinuz` inside each
/// `/usr/lib/modules/<version>` (Arch, and Fedora's newer layout). Each once.
fn installed_versions(root: &Path) -> Vec<String> {
    let mut found = BTreeSet::new();
    if let Ok(entries) = fs::read_dir(root.join(BOOT)) {
        for entry in entries.flatten().take(MAX_ENTRIES) {
            let name = entry.file_name().to_string_lossy().into_owned();
            if let Some(version) = name.strip_prefix("vmlinuz-") {
                found.insert(version.to_string());
            }
        }
    }
    if let Ok(entries) = fs::read_dir(root.join(MODULES)) {
        for entry in entries.flatten().take(MAX_ENTRIES) {
            if entry.path().join("vmlinuz").is_file() {
                found.insert(entry.file_name().to_string_lossy().into_owned());
            }
        }
    }
    found.into_iter().collect()
}

/// When `version` was installed: the date of its initial RAM disk, written
/// when the package is configured. The kernel image itself carries the date
/// the package was built, which can be a month before it was installed.
fn installed_at(root: &Path, version: &str) -> Option<u64> {
    [
        format!("initrd.img-{version}"),
        format!("initramfs-{version}.img"),
    ]
    .iter()
    .find_map(|name| fs::metadata(root.join(BOOT).join(name)).ok())
    .and_then(|metadata| modified_unix(&metadata))
}

/// A live patch is loaded when `/sys/kernel/livepatch` has anything in it.
fn livepatch_loaded(root: &Path) -> bool {
    fs::read_dir(root.join(LIVEPATCH)).is_ok_and(|mut entries| entries.next().is_some())
}

/// The newer kernel installed under `root` (`/` on a real machine); `None`
/// when the running kernel is the newest of its flavor, or cannot be told.
pub fn read(root: &Path) -> Option<NewerKernel> {
    let running = fs::read_to_string(root.join(OSRELEASE)).ok()?;
    let running = running.trim();
    let installed = installed_versions(root);
    let newer = newest_newer(running, &installed)?;
    Some(NewerKernel {
        running: clean(running, MAX_VERSION),
        installed: clean(newer, MAX_VERSION),
        installed_unix: installed_at(root, newer),
        livepatch: livepatch_loaded(root),
    })
}

/// The finding, when the kernel has been waiting long enough; `None` before
/// that. When the age is not known there is nothing to judge it by, so it is
/// information and no more.
pub fn kernel_finding(kernel: &NewerKernel, now_unix: u64) -> Option<Finding> {
    // A clock that is behind the file's date reads as "just installed".
    let age = kernel
        .installed_unix
        .map(|installed| now_unix.saturating_sub(installed));
    if age.is_some_and(|age| age < STALE_AFTER_SECS) {
        return None;
    }

    let mut text = format!("The machine runs kernel {}, but kernel ", kernel.running);
    match age {
        Some(age) => text.push_str(&format!(
            "{} was installed {} ago",
            kernel.installed,
            age_text(age)
        )),
        None => text.push_str(&format!(
            "{} is installed (when it was installed could not be told, so it is not judged \
             by its age)",
            kernel.installed
        )),
    }
    text.push_str(
        ". A kernel is replaced at the next boot only, so the fixes in the new one are not \
         active yet.",
    );
    if kernel.livepatch {
        text.push_str(
            " A live patch is loaded, which fixes the most serious kernel flaws in memory: this \
             is less urgent, but the rest of the update still waits for the reboot.",
        );
    }
    text.push_str(
        " Debian-like systems also say so with `/var/run/reboot-required` (SRV003, KERN004); \
         this one is for those that do not.",
    );

    let (severity, confidence) = match age {
        Some(_) if !kernel.livepatch => (Severity::Warning, Confidence::correlated(90)),
        Some(_) => (Severity::Info, Confidence::correlated(90)),
        None => (Severity::Info, Confidence::strong_indication(80)),
    };
    let mut builder = Finding::builder(
        "SRV005",
        "Newer Kernel Installed",
        Category::Kernel,
        severity,
        confidence,
    )
    .evidence("running_kernel", kernel.running.clone())
    .evidence("installed_kernel", kernel.installed.clone());
    if let Some(age) = age {
        builder = builder.evidence("installed_age_days", (age / DAY).to_string());
    }
    if kernel.livepatch {
        builder = builder.evidence("livepatch", "loaded");
    }
    builder = builder.explanation(text);
    if severity >= Severity::Warning {
        builder = builder.recommendation(
            Steps::new()
                .step(
                    "See which kernel runs and which ones are installed:",
                    &["uname -r", "ls /boot"],
                )
                .step(
                    "Plan the reboot for a maintenance window, once the services the machine \
                     has to serve start by themselves, then reboot:",
                    &["sudo reboot"],
                )
                .step("After it, check that the new kernel runs:", &["uname -r"])
                .build(),
        );
    }
    Some(builder.build())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs::File;
    use std::path::PathBuf;
    use std::time::{Duration, UNIX_EPOCH};

    const NOW: u64 = 1_000_000_000;

    fn evidence<'a>(finding: &'a Finding, key: &str) -> Option<&'a str> {
        finding
            .evidence
            .iter()
            .find(|(k, _)| k == key)
            .map(|(_, v)| v.as_str())
    }

    fn names(list: &[&str]) -> Vec<String> {
        list.iter().map(|n| n.to_string()).collect()
    }

    // --- versions ----------------------------------------------------------

    #[test]
    fn a_version_is_its_numbers_and_its_flavor() {
        for (text, numbers, flavor) in [
            ("6.8.0-45-generic", vec![6, 8, 0, 45], "generic"),
            ("6.1.0-25-amd64", vec![6, 1, 0, 25], "amd64"),
            ("6.1.0-25-cloud-amd64", vec![6, 1, 0, 25], "cloud.amd64"),
            ("5.14.0-427.el9.x86_64", vec![5, 14, 0, 427], "x86_64"),
            (
                "5.14.0-427.13.1.el9_4.x86_64",
                vec![5, 14, 0, 427, 13, 1],
                "x86_64",
            ),
            (
                "5.14.0-503.11.1.el9_5.x86_64+debug",
                vec![5, 14, 0, 503, 11, 1],
                "x86_64+debug",
            ),
            ("6.10.11-200.fc40.x86_64", vec![6, 10, 11, 200], "x86_64"),
            (
                "6.4.0-150600.23.14-default",
                vec![6, 4, 0, 150600, 23, 14],
                "default",
            ),
            ("6.10.3-arch1-1", vec![6, 10, 3], "arch1.1"),
            ("6.18.44-fc-v139", vec![6, 18, 44], "fc.v139"),
            ("6.8", vec![6, 8], ""),
            ("6.8.0", vec![6, 8, 0], ""),
        ] {
            let version = parse_version(text).unwrap_or_else(|| panic!("{text}"));
            assert_eq!(version.numbers, numbers, "{text}");
            assert_eq!(version.flavor, flavor, "{text}");
        }
    }

    #[test]
    fn what_is_not_a_kernel_version_is_none() {
        for text in [
            "",
            "6",
            "6-generic",
            "linux",
            "0-rescue-abc",
            "a.b.c",
            ".6.8",
            "-6.8",
            "+6.8.0",
            "6..8",
            "99999999999999999999.1",
        ] {
            assert_eq!(parse_version(text), None, "{text:?}");
        }
    }

    #[test]
    fn a_distribution_tag_is_told_from_a_flavor() {
        for tag in ["el9", "el9_4", "el10", "fc40", "fc9", "el0"] {
            assert!(is_distribution_tag(tag), "{tag}");
        }
        for word in [
            "", "el", "fc", "e9", "el9_", "el_9", "el9_4_1", "elx", "el9x", "fcx40", "generic",
            "amd64", "default", "debug", "EL9",
        ] {
            assert!(!is_distribution_tag(word), "{word:?}");
        }
    }

    #[test]
    fn numbers_are_compared_one_by_one_and_a_missing_one_is_zero() {
        use Ordering::*;
        for (a, b, order) in [
            (vec![6, 8, 0, 45], vec![6, 8, 0, 50], Less),
            (vec![6, 8, 0, 50], vec![6, 8, 0, 45], Greater),
            (vec![6, 8, 9], vec![6, 8, 10], Less),
            (vec![6, 8, 0], vec![6, 8], Equal),
            (vec![6, 8], vec![6, 8, 0], Equal),
            (vec![6, 8, 1], vec![6, 8], Greater),
            (vec![6, 8], vec![6, 8, 1], Less),
            (vec![5, 14, 0, 427], vec![5, 14, 0, 427, 13, 1], Less),
            (vec![7, 0], vec![6, 99, 99], Greater),
            (vec![], vec![], Equal),
        ] {
            assert_eq!(compare(&a, &b), order, "{a:?} {b:?}");
        }
    }

    #[test]
    fn the_newest_kernel_of_the_same_flavor_is_the_one_that_counts() {
        let installed = names(&[
            "6.8.0-40-generic",
            "6.8.0-45-generic",
            "6.8.0-50-generic",
            "6.8.0-60-lowlatency",
            "6.11.0-9-generic",
            "6.11.0-17-generic",
            "vmlinuz",
            "garbage",
        ]);
        assert_eq!(
            newest_newer("6.8.0-45-generic", &installed).map(String::as_str),
            Some("6.11.0-17-generic")
        );
        // Not the lowlatency one, even though its number is the highest of its kind.
        let installed = names(&["6.8.0-45-generic", "6.8.0-60-lowlatency"]);
        assert_eq!(newest_newer("6.8.0-45-generic", &installed), None);
    }

    #[test]
    fn nothing_is_newer_when_the_running_kernel_is_the_newest() {
        let installed = names(&["6.8.0-40-generic", "6.8.0-45-generic"]);
        assert_eq!(newest_newer("6.8.0-45-generic", &installed), None);
        assert_eq!(newest_newer("6.8.0-50-generic", &installed), None);
        assert_eq!(newest_newer("6.8.0-45-generic", &[]), None);
        assert_eq!(newest_newer("not a kernel", &installed), None);
    }

    #[test]
    fn a_red_hat_minor_release_does_not_hide_a_newer_kernel() {
        let installed = names(&[
            "5.14.0-427.13.1.el9_4.x86_64",
            "5.14.0-503.11.1.el9_5.x86_64",
        ]);
        assert_eq!(
            newest_newer("5.14.0-427.13.1.el9_4.x86_64", &installed).map(String::as_str),
            Some("5.14.0-503.11.1.el9_5.x86_64")
        );
        // A debug kernel is another flavor.
        let installed = names(&["5.14.0-503.11.1.el9_5.x86_64+debug"]);
        assert_eq!(
            newest_newer("5.14.0-427.13.1.el9_4.x86_64", &installed),
            None
        );
    }

    // --- reading -----------------------------------------------------------

    fn tree(name: &str) -> PathBuf {
        let root = std::env::temp_dir().join(format!(
            "linuxdoctor-server-kernel-{name}-{}",
            std::process::id()
        ));
        let _ = fs::remove_dir_all(&root);
        fs::create_dir_all(root.join("proc/sys/kernel")).unwrap();
        fs::create_dir_all(root.join("boot")).unwrap();
        root
    }

    fn running(root: &Path, version: &str) {
        fs::write(root.join(OSRELEASE), format!("{version}\n")).unwrap();
    }

    fn set_age(path: &Path, ago: u64) {
        File::options()
            .write(true)
            .open(path)
            .unwrap()
            .set_modified(UNIX_EPOCH + Duration::from_secs(NOW - ago))
            .unwrap();
    }

    #[test]
    fn a_newer_kernel_in_boot_is_found_with_the_age_of_its_ram_disk() {
        let root = tree("boot");
        running(&root, "6.8.0-45-generic");
        for version in ["6.8.0-45-generic", "6.8.0-50-generic"] {
            fs::write(root.join(format!("boot/vmlinuz-{version}")), "").unwrap();
        }
        fs::write(root.join("boot/vmlinuz.old"), "").unwrap();
        let initrd = root.join("boot/initrd.img-6.8.0-50-generic");
        fs::write(&initrd, "").unwrap();
        set_age(&initrd, 9 * 86_400);
        // The image carries the date it was built, long before.
        set_age(&root.join("boot/vmlinuz-6.8.0-50-generic"), 90 * 86_400);

        let kernel = read(&root).unwrap();
        assert_eq!(kernel.running, "6.8.0-45-generic");
        assert_eq!(kernel.installed, "6.8.0-50-generic");
        assert_eq!(kernel.installed_unix, Some(NOW - 9 * 86_400));
        assert!(!kernel.livepatch);
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn a_red_hat_ram_disk_gives_the_age_too() {
        let root = tree("redhat");
        running(&root, "5.14.0-427.13.1.el9_4.x86_64");
        for version in [
            "5.14.0-427.13.1.el9_4.x86_64",
            "5.14.0-503.11.1.el9_5.x86_64",
        ] {
            fs::write(root.join(format!("boot/vmlinuz-{version}")), "").unwrap();
        }
        fs::write(root.join("boot/vmlinuz-0-rescue-0123456789abcdef"), "").unwrap();
        let initramfs = root.join("boot/initramfs-5.14.0-503.11.1.el9_5.x86_64.img");
        fs::write(&initramfs, "").unwrap();
        set_age(&initramfs, 3 * 86_400);

        let kernel = read(&root).unwrap();
        assert_eq!(kernel.installed, "5.14.0-503.11.1.el9_5.x86_64");
        assert_eq!(kernel.installed_unix, Some(NOW - 3 * 86_400));
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn a_kernel_in_usr_lib_modules_counts_when_it_has_an_image() {
        let root = tree("arch");
        running(&root, "6.10.2-arch1-1");
        fs::create_dir_all(root.join("usr/lib/modules/6.10.3-arch1-1")).unwrap();
        fs::write(root.join("usr/lib/modules/6.10.3-arch1-1/vmlinuz"), "").unwrap();
        // Modules left behind by a removed kernel, with no image.
        fs::create_dir_all(root.join("usr/lib/modules/6.11.0-arch1-1")).unwrap();
        // A file that is not a directory.
        fs::write(root.join("usr/lib/modules/6.12.0-arch1-1"), "").unwrap();

        let kernel = read(&root).unwrap();
        assert_eq!(kernel.installed, "6.10.3-arch1-1");
        assert_eq!(kernel.installed_unix, None);
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn a_kernel_in_both_places_is_one() {
        let root = tree("both");
        running(&root, "6.8.0-45-generic");
        fs::write(root.join("boot/vmlinuz-6.8.0-50-generic"), "").unwrap();
        fs::create_dir_all(root.join("usr/lib/modules/6.8.0-50-generic")).unwrap();
        fs::write(root.join("usr/lib/modules/6.8.0-50-generic/vmlinuz"), "").unwrap();
        assert_eq!(
            installed_versions(&root),
            vec!["6.8.0-50-generic".to_string()]
        );
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn nothing_newer_means_nothing() {
        let root = tree("none");
        running(&root, "6.8.0-50-generic");
        fs::write(root.join("boot/vmlinuz-6.8.0-45-generic"), "").unwrap();
        fs::write(root.join("boot/vmlinuz-6.8.0-50-generic"), "").unwrap();
        assert_eq!(read(&root), None);
        // No running kernel to compare with, or no boot directory at all.
        fs::remove_file(root.join(OSRELEASE)).unwrap();
        assert_eq!(read(&root), None);
        let bare = std::env::temp_dir().join(format!(
            "linuxdoctor-server-kernel-bare-{}",
            std::process::id()
        ));
        let _ = fs::remove_dir_all(&bare);
        assert_eq!(read(&bare), None);
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn a_loaded_live_patch_is_seen() {
        let root = tree("livepatch");
        running(&root, "6.8.0-45-generic");
        fs::write(root.join("boot/vmlinuz-6.8.0-50-generic"), "").unwrap();
        fs::create_dir_all(root.join("sys/kernel/livepatch")).unwrap();
        assert!(
            !read(&root).unwrap().livepatch,
            "an empty directory is none"
        );
        fs::create_dir_all(root.join("sys/kernel/livepatch/livepatch_61_1")).unwrap();
        assert!(read(&root).unwrap().livepatch);
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn terminal_escapes_in_versions_are_replaced() {
        let root = tree("hostile");
        running(&root, "6.8.0-45-gen\u{1b}eric");
        fs::write(root.join("boot/vmlinuz-6.8.0-50-gen\u{1b}eric"), "").unwrap();
        let kernel = read(&root).unwrap();
        assert_eq!(kernel.running, "6.8.0-45-gen?eric");
        assert_eq!(kernel.installed, "6.8.0-50-gen?eric");
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn long_versions_are_cut() {
        let root = tree("long");
        let flavor = "x".repeat(150);
        running(&root, &format!("6.8.0-45-{flavor}"));
        fs::write(root.join(format!("boot/vmlinuz-6.8.0-50-{flavor}")), "").unwrap();
        let kernel = read(&root).unwrap();
        assert_eq!(kernel.running.chars().count(), 101);
        assert_eq!(kernel.installed.chars().count(), 101);
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn a_directory_cannot_make_the_search_longer_than_the_bound() {
        let root = tree("many");
        running(&root, "6.8.0-45-generic");
        for i in 0..300 {
            fs::write(root.join(format!("boot/vmlinuz-5.0.{i}-generic")), "").unwrap();
        }
        assert_eq!(installed_versions(&root).len(), 256);
        let _ = fs::remove_dir_all(&root);
    }

    // --- the finding -------------------------------------------------------

    fn kernel(ago: Option<u64>, livepatch: bool) -> NewerKernel {
        NewerKernel {
            running: "6.8.0-45-generic".to_string(),
            installed: "6.8.0-50-generic".to_string(),
            installed_unix: ago.map(|a| NOW - a),
            livepatch,
        }
    }

    #[test]
    fn a_kernel_installed_for_less_than_a_week_is_not_reported() {
        assert!(kernel_finding(&kernel(Some(0), false), NOW).is_none());
        assert!(kernel_finding(&kernel(Some(7 * 86_400 - 1), false), NOW).is_none());
        // A clock behind the file's date reads as just installed.
        let ahead = NewerKernel {
            installed_unix: Some(NOW + 1000),
            ..kernel(None, false)
        };
        assert!(kernel_finding(&ahead, NOW).is_none());
    }

    #[test]
    fn a_week_is_enough_to_be_a_warning() {
        let f = kernel_finding(&kernel(Some(7 * 86_400), false), NOW).unwrap();
        assert_eq!(f.id, "SRV005");
        assert_eq!(f.title, "Newer Kernel Installed");
        assert_eq!(f.severity, Severity::Warning);
        assert_eq!(f.confidence.percent, 90);
        assert_eq!(evidence(&f, "running_kernel"), Some("6.8.0-45-generic"));
        assert_eq!(evidence(&f, "installed_kernel"), Some("6.8.0-50-generic"));
        assert_eq!(evidence(&f, "installed_age_days"), Some("7"));
        assert_eq!(evidence(&f, "livepatch"), None);
        let f = kernel_finding(&kernel(Some(40 * 86_400 + 5), false), NOW).unwrap();
        assert_eq!(evidence(&f, "installed_age_days"), Some("40"));
        assert!(
            f.explanation.contains("was installed 40 days ago"),
            "{}",
            f.explanation
        );
    }

    #[test]
    fn the_explanation_names_both_kernels_and_says_what_it_means() {
        let f = kernel_finding(&kernel(Some(12 * 86_400), false), NOW).unwrap();
        assert_eq!(
            f.explanation,
            "The machine runs kernel 6.8.0-45-generic, but kernel 6.8.0-50-generic was \
             installed 12 days ago. A kernel is replaced at the next boot only, so the \
             fixes in the new one are not active yet. Debian-like systems also say so with \
             `/var/run/reboot-required` (SRV003, KERN004); this one is for those that do not."
        );
    }

    #[test]
    fn a_warning_comes_with_the_steps_to_reboot() {
        let rec = kernel_finding(&kernel(Some(12 * 86_400), false), NOW)
            .unwrap()
            .recommendation
            .unwrap();
        assert!(rec.starts_with("1. See which kernel runs"), "{rec}");
        for command in ["\n    uname -r", "\n    ls /boot", "\n    sudo reboot"] {
            assert!(rec.contains(command), "{command}\n{rec}");
        }
        assert_eq!(rec.matches("uname -r").count(), 2, "{rec}");
        assert!(rec.contains("check that the new kernel runs"), "{rec}");
    }

    #[test]
    fn a_live_patch_makes_it_information_and_says_so() {
        let f = kernel_finding(&kernel(Some(30 * 86_400), true), NOW).unwrap();
        assert_eq!(f.severity, Severity::Info);
        assert_eq!(f.confidence.percent, 90);
        assert_eq!(f.recommendation, None);
        assert_eq!(evidence(&f, "livepatch"), Some("loaded"));
        assert!(
            f.explanation.contains("A live patch is loaded"),
            "{}",
            f.explanation
        );
        let without = kernel_finding(&kernel(Some(30 * 86_400), false), NOW).unwrap();
        assert!(
            !without.explanation.contains("live patch"),
            "{}",
            without.explanation
        );
    }

    #[test]
    fn an_unknown_age_is_information_without_a_judgement() {
        let f = kernel_finding(&kernel(None, false), NOW).unwrap();
        assert_eq!(f.severity, Severity::Info);
        assert_eq!(f.confidence.percent, 80);
        assert_eq!(f.recommendation, None);
        assert_eq!(evidence(&f, "installed_age_days"), None);
        assert!(
            f.explanation
                .contains("is installed (when it was installed could not be told"),
            "{}",
            f.explanation
        );
        let patched = kernel_finding(&kernel(None, true), NOW).unwrap();
        assert_eq!(patched.severity, Severity::Info);
        assert_eq!(patched.confidence.percent, 80);
    }
}
