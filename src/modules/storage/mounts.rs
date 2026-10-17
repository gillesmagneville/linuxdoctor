// SPDX-License-Identifier: GPL-3.0-only

//! STOR006: a filesystem the kernel has mounted read-only although
//! `/etc/fstab` asks for read-write.
//!
//! A filesystem on a local disk that finds damage is remounted read-only (`errors=remount-ro`
//! is the default on most distributions), and from then on every program that
//! writes to it fails in its own way. The kernel log says so once, at the
//! moment it happens, and only while that boot's journal is still there; the
//! mount table says so for as long as it lasts. Only filesystems that fstab
//! says should be writable are looked at: a mount someone wrote as `ro` is
//! what they asked for.

use std::collections::{BTreeMap, HashMap};
use std::fs;
use std::path::Path;

use crate::core::text::clean;
use crate::models::{Category, Confidence, Finding, Severity};
use crate::modules::logs::text::is_safe_word;
use crate::modules::recommend::Steps;

use super::device::disk_of;

/// The kernel's table of mounts and the administrator's, under the root
/// being read.
const MOUNTS: &str = "proc/mounts";
const FSTAB: &str = "etc/fstab";
/// Lines read from either file, and characters kept of each field.
const MAX_LINES: usize = 4096;
const MAX_FIELD: usize = 200;
/// Filesystems that are read-only by nature: it is the medium, not a
/// reaction to an error.
const READ_ONLY_BY_NATURE: [&str; 5] = ["iso9660", "udf", "squashfs", "erofs", "cramfs"];

/// A mount that fstab wants writable and the kernel serves read-only.
#[derive(Debug, Clone, PartialEq)]
pub struct ReadOnlyMount {
    pub mount_point: String,
    pub device: String,
    pub fstype: String,
    /// The options the kernel shows for it, `ro,relatime,...`.
    pub mounted_options: String,
    /// The options fstab asks for.
    pub fstab_options: String,
}

/// One line of `/proc/mounts` or `/etc/fstab`, spaces and the like decoded.
struct Entry {
    device: String,
    mount_point: String,
    fstype: String,
    options: String,
}

/// `\040` is a space in these files, `\011` a tab, `\012` a newline,
/// `\134` a backslash: three octal digits for any byte.
fn unescape(field: &str) -> String {
    let bytes = field.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        let octal = match bytes.get(i..i + 4) {
            Some([b'\\', a @ b'0'..=b'7', b @ b'0'..=b'7', c @ b'0'..=b'7']) => u8::try_from(
                u32::from(a - b'0') * 64 + u32::from(b - b'0') * 8 + u32::from(c - b'0'),
            )
            .ok(),
            _ => None,
        };
        match octal {
            Some(byte) => {
                out.push(byte);
                i += 4;
            }
            None => {
                out.push(bytes[i]);
                i += 1;
            }
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// The entries of a table, in order. Comments, blank lines and lines too
/// short to name a mount are skipped; a missing options field is `defaults`.
fn parse_table(text: &str) -> Vec<Entry> {
    text.lines()
        .take(MAX_LINES)
        .filter_map(|line| {
            let line = line.trim();
            if line.starts_with('#') {
                return None;
            }
            let mut fields = line.split_whitespace();
            let device = unescape(fields.next()?);
            let mount_point = unescape(fields.next()?);
            let fstype = unescape(fields.next()?);
            let options = fields.next().map_or("defaults".to_string(), unescape);
            Some(Entry {
                device,
                mount_point,
                fstype,
                options,
            })
        })
        .collect()
}

fn has_option(options: &str, name: &str) -> bool {
    options.split(',').any(|option| option == name)
}

/// `/data/` and `/data` are the same mount point; `/` stays `/`.
fn normalized(mount_point: &str) -> String {
    match mount_point.trim_end_matches('/') {
        "" => "/".to_string(),
        trimmed => trimmed.to_string(),
    }
}

/// Pure: the mounts that fstab wants writable and the kernel has read-only.
/// Several lines for one mount point mean stacked mounts; the last is the
/// one in use. Sorted by mount point.
pub fn read_only_against_fstab(mounts: &str, fstab: &str) -> Vec<ReadOnlyMount> {
    let mut mounted: HashMap<String, Entry> = HashMap::new();
    for entry in parse_table(mounts) {
        mounted.insert(normalized(&entry.mount_point), entry);
    }
    let mut wanted: BTreeMap<String, Entry> = BTreeMap::new();
    for entry in parse_table(fstab) {
        if entry.mount_point.starts_with('/') {
            wanted.insert(normalized(&entry.mount_point), entry);
        }
    }
    let mut found = Vec::new();
    for (mount_point, want) in wanted {
        // Read-only on purpose, not mounted at boot, or a view of another
        // mount whose own flags decide.
        let not_asked = ["ro", "noauto", "bind", "rbind"]
            .into_iter()
            .any(|option| has_option(&want.options, option));
        if not_asked {
            continue;
        }
        let Some(now) = mounted.get(&mount_point) else {
            continue;
        };
        let by_nature = READ_ONLY_BY_NATURE.contains(&now.fstype.as_str())
            || READ_ONLY_BY_NATURE.contains(&want.fstype.as_str());
        // Only a filesystem on a local block device goes read-only because
        // the disk is failing; memory, network and virtual ones do not.
        let on_a_disk = now.device.starts_with("/dev/");
        if by_nature || !on_a_disk || !has_option(&now.options, "ro") {
            continue;
        }
        found.push(ReadOnlyMount {
            mount_point: clean(&mount_point, MAX_FIELD),
            device: clean(&now.device, MAX_FIELD),
            fstype: clean(&now.fstype, MAX_FIELD),
            mounted_options: clean(&now.options, MAX_FIELD),
            fstab_options: clean(&want.options, MAX_FIELD),
        });
    }
    found
}

/// The read-only mounts of the machine under `root` (`/` for the real
/// one). Without fstab there is nothing to compare with, and a file that
/// cannot be read gives none.
pub fn read(root: &Path) -> Vec<ReadOnlyMount> {
    let (Ok(mounts), Ok(fstab)) = (
        fs::read_to_string(root.join(MOUNTS)),
        fs::read_to_string(root.join(FSTAB)),
    ) else {
        return Vec::new();
    };
    read_only_against_fstab(&mounts, &fstab)
}

fn steps(mount: &ReadOnlyMount) -> Steps {
    let is_root = mount.mount_point == "/";
    let point = if is_safe_word(&mount.mount_point) {
        mount.mount_point.clone()
    } else {
        "<mount-point>".to_string()
    };
    let device = if is_safe_word(&mount.device) {
        mount.device.clone()
    } else {
        "/dev/<partition>".to_string()
    };
    let disk = mount
        .device
        .strip_prefix("/dev/")
        .and_then(disk_of)
        .filter(|disk| is_safe_word(disk));
    let smart = match disk {
        Some(disk) => format!("sudo smartctl -a /dev/{disk}"),
        None => "sudo smartctl --scan".to_string(),
    };
    let steps = Steps::new()
        .step(
            "If it went read-only because of errors, copy what matters somewhere else before \
             anything else: the disk may be failing.",
            &[],
        )
        .step(
            "See whether the kernel remounted it after an error, and when:",
            &["sudo journalctl -k -b | grep -i -E 'remount|read-only|i/o error'"],
        )
        .step_owned(
            "Ask the disk about its own health (install smartmontools if the command is \
             missing). Reallocated, pending or uncorrectable sectors mean it is dying:",
            vec![smart],
        )
        .step_owned(
            "If nothing is wrong and it was only remounted on purpose (a backup, \
             maintenance), put it back:",
            vec![format!("sudo mount -o remount,rw {point}")],
        );
    let check = "(ext4 shown; use xfs_repair for XFS, btrfs check for Btrfs):";
    if is_root {
        steps.step_owned(
            format!(
                "If the disk reported errors, check and repair the filesystem. The root \
                 filesystem cannot be checked while it is mounted: boot a rescue system or \
                 the installer's live mode, then {check}"
            ),
            vec![format!("sudo fsck -f {device}")],
        )
    } else {
        steps.step_owned(
            format!(
                "If the disk reported errors, check and repair the filesystem. Never do it \
                 while it is mounted: unmount it first, then {check}"
            ),
            vec![
                format!("sudo umount {point}"),
                format!("sudo fsck -f {device}"),
            ],
        )
    }
}

/// The finding for one read-only mount. Pure.
pub fn mount_finding(mount: &ReadOnlyMount) -> Finding {
    let is_root = mount.mount_point == "/";
    let severity = if is_root {
        Severity::Critical
    } else {
        Severity::Error
    };
    let mut text = format!(
        "{} is mounted read-only ({}, {}), but /etc/fstab asks for read-write. Either someone \
         remounted it on purpose (a backup, maintenance), or the kernel did it after finding \
         errors on the disk; in that case nothing can be written to it until it is repaired.",
        mount.mount_point, mount.device, mount.fstype
    );
    if is_root {
        text.push_str(
            " This is the root filesystem: the system cannot write its logs, its state or \
             its temporary files, and services will start to fail.",
        );
    }
    Finding::builder(
        "STOR006",
        format!("Read-Only Filesystem \u{2014} {}", mount.mount_point),
        Category::Storage,
        severity,
        Confidence::correlated(90),
    )
    .instance(mount.mount_point.clone())
    .evidence("mount_point", mount.mount_point.clone())
    .evidence("device", mount.device.clone())
    .evidence("fstype", mount.fstype.clone())
    .evidence("mounted_options", mount.mounted_options.clone())
    .evidence("fstab_options", mount.fstab_options.clone())
    .explanation(text)
    .recommendation(steps(mount).build())
    .build()
}

#[cfg(test)]
mod tests {
    use super::*;

    const FSTAB_TEXT: &str = "\
# <file system> <mount point> <type> <options> <dump> <pass>
UUID=aaaa-bbbb  /      ext4  errors=remount-ro  0  1
UUID=cccc-dddd  /data  xfs   defaults            0  2
UUID=eeee-ffff  none   swap  sw                  0  0
";

    fn mount(point: &str) -> ReadOnlyMount {
        ReadOnlyMount {
            mount_point: point.to_string(),
            device: "/dev/sdb1".to_string(),
            fstype: "xfs".to_string(),
            mounted_options: "ro,relatime".to_string(),
            fstab_options: "defaults".to_string(),
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
    fn octal_escapes_are_decoded() {
        for (raw, decoded) in [
            ("/plain", "/plain"),
            ("/my\\040disk", "/my disk"),
            ("/a\\011b", "/a\tb"),
            ("/a\\012b", "/a\nb"),
            ("/a\\134b", "/a\\b"),
            ("\\040", " "),
            ("/a\\040", "/a "),
            ("/a\\04", "/a\\04"),
            ("/a\\0", "/a\\0"),
            ("/a\\", "/a\\"),
            ("/a\\089", "/a\\089"),
            ("/a\\777", "/a\\777"),
            ("/a\\400", "/a\\400"),
            ("/a\\377", "/a\u{fffd}"),
            ("", ""),
        ] {
            assert_eq!(unescape(raw), decoded, "{raw}");
        }
    }

    #[test]
    fn a_table_is_read_line_by_line() {
        let entries = parse_table(FSTAB_TEXT);
        let seen: Vec<(&str, &str, &str, &str)> = entries
            .iter()
            .map(|e| {
                (
                    e.device.as_str(),
                    e.mount_point.as_str(),
                    e.fstype.as_str(),
                    e.options.as_str(),
                )
            })
            .collect();
        assert_eq!(
            seen,
            vec![
                ("UUID=aaaa-bbbb", "/", "ext4", "errors=remount-ro"),
                ("UUID=cccc-dddd", "/data", "xfs", "defaults"),
                ("UUID=eeee-ffff", "none", "swap", "sw"),
            ]
        );
    }

    #[test]
    fn short_lines_and_comments_are_skipped_and_options_default() {
        let entries = parse_table(
            "  # indented comment\n\nonly two\n/dev/sda1 /x ext4\n  /dev/sdb1 /y ext4 ro 0 0\n",
        );
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].options, "defaults");
        assert_eq!(entries[0].mount_point, "/x");
        assert_eq!(entries[1].options, "ro");
    }

    #[test]
    fn a_file_cannot_make_the_table_longer_than_the_bound() {
        let text: String = (0..4106)
            .map(|i| format!("/dev/sda1 /m{i} ext4 rw 0 0\n"))
            .collect();
        assert_eq!(parse_table(&text).len(), 4096);
    }

    #[test]
    fn options_are_matched_whole() {
        assert!(has_option("ro,relatime", "ro"));
        assert!(has_option("rw,ro", "ro"));
        assert!(has_option("ro", "ro"));
        assert!(!has_option("rw,relatime", "ro"));
        assert!(!has_option("errors=remount-ro", "ro"));
        assert!(!has_option("rootcontext=x,nodev", "ro"));
        assert!(!has_option("", "ro"));
    }

    #[test]
    fn a_mount_point_is_the_same_with_or_without_a_slash_at_the_end() {
        assert_eq!(normalized("/data/"), "/data");
        assert_eq!(normalized("/data//"), "/data");
        assert_eq!(normalized("/data"), "/data");
        assert_eq!(normalized("/"), "/");
        assert_eq!(normalized("//"), "/");
    }

    #[test]
    fn a_data_disk_that_went_read_only_is_found() {
        let mounts = "\
/dev/nvme0n1p2 / ext4 rw,relatime,errors=remount-ro 0 0
/dev/sdb1 /data xfs ro,relatime,attr2 0 0
tmpfs /run tmpfs rw,nosuid 0 0
";
        let found = read_only_against_fstab(mounts, FSTAB_TEXT);
        assert_eq!(
            found,
            vec![ReadOnlyMount {
                mount_point: "/data".to_string(),
                device: "/dev/sdb1".to_string(),
                fstype: "xfs".to_string(),
                mounted_options: "ro,relatime,attr2".to_string(),
                fstab_options: "defaults".to_string(),
            }]
        );
    }

    #[test]
    fn nothing_is_found_when_everything_is_as_fstab_asks() {
        let mounts = "/dev/sda2 / ext4 rw,relatime 0 0\n/dev/sdb1 /data xfs rw 0 0\n";
        assert_eq!(read_only_against_fstab(mounts, FSTAB_TEXT), vec![]);
    }

    #[test]
    fn a_mount_fstab_wants_read_only_is_not_a_finding() {
        let fstab = "/dev/sdb1 /data xfs defaults,ro 0 0\n/dev/sdc1 /boot ext4 ro 0 0\n";
        let mounts = "/dev/sdb1 /data xfs ro 0 0\n/dev/sdc1 /boot ext4 ro 0 0\n";
        assert_eq!(read_only_against_fstab(mounts, fstab), vec![]);
    }

    #[test]
    fn a_mount_that_is_not_asked_for_at_boot_or_is_a_view_is_left_alone() {
        for options in ["noauto,user", "defaults,bind", "rbind", "defaults,noauto"] {
            let fstab = format!("/dev/sdb1 /data xfs {options} 0 0\n");
            let mounts = "/dev/sdb1 /data xfs ro 0 0\n";
            assert_eq!(read_only_against_fstab(mounts, &fstab), vec![], "{options}");
        }
    }

    #[test]
    fn a_medium_that_is_read_only_by_nature_is_left_alone() {
        for fstype in ["iso9660", "udf", "squashfs", "erofs", "cramfs"] {
            let fstab = format!(
                "/dev/sr0 /media/cd auto defaults 0 0\n/dev/x /img {fstype} defaults 0 0\n"
            );
            let mounts =
                format!("/dev/sr0 /media/cd {fstype} ro 0 0\n/dev/loop1 /img {fstype} ro 0 0\n");
            assert_eq!(read_only_against_fstab(&mounts, &fstab), vec![], "{fstype}");
        }
        // The type fstab names counts too, when the kernel says something else.
        let fstab = "/dev/sr0 /media/cd iso9660 defaults 0 0\n";
        let mounts = "/dev/sr0 /media/cd auto ro 0 0\n";
        assert_eq!(read_only_against_fstab(mounts, fstab), vec![]);
    }

    #[test]
    fn a_filesystem_that_is_not_on_a_local_disk_is_left_alone() {
        let fstab = "tmpfs /tmp tmpfs defaults 0 0\nserver:/export /srv nfs defaults 0 0\n\
                     overlay /merged overlay defaults 0 0\n/dev/sdb1 /data xfs defaults 0 0\n";
        let mounts = "tmpfs /tmp tmpfs ro 0 0\nserver:/export /srv nfs ro 0 0\n\
                      overlay /merged overlay ro 0 0\ndev/sdb1 /data xfs ro 0 0\n";
        assert_eq!(read_only_against_fstab(mounts, fstab), vec![]);
        // The same data disk, with its device where the kernel puts it.
        let mounts = "/dev/sdb1 /data xfs ro 0 0\n";
        assert_eq!(read_only_against_fstab(mounts, fstab).len(), 1);
    }

    #[test]
    fn a_mount_fstab_lists_but_the_kernel_does_not_is_not_a_finding() {
        let mounts = "/dev/sda2 / ext4 rw 0 0\n";
        assert_eq!(read_only_against_fstab(mounts, FSTAB_TEXT), vec![]);
    }

    #[test]
    fn a_mount_the_kernel_has_without_fstab_asking_is_not_a_finding() {
        let mounts = "/dev/sdz9 /elsewhere ext4 ro 0 0\n";
        assert_eq!(read_only_against_fstab(mounts, FSTAB_TEXT), vec![]);
        assert_eq!(read_only_against_fstab(mounts, ""), vec![]);
    }

    #[test]
    fn an_entry_that_is_not_a_path_is_not_a_mount_point() {
        // `swap` and `none` are not places; they must not match a kernel line
        // that happens to be called the same.
        let fstab = "/dev/sda3 swap swap sw 0 0\n/dev/sda4 none swap sw 0 0\n";
        let mounts = "/dev/x swap x ro 0 0\n/dev/x none x ro 0 0\n";
        assert_eq!(read_only_against_fstab(mounts, fstab), vec![]);
    }

    #[test]
    fn the_last_line_for_a_mount_point_is_the_one_in_use() {
        let mounts = "/dev/sdb1 /data xfs rw 0 0\n/dev/sdc1 /data xfs ro 0 0\n";
        let found = read_only_against_fstab(mounts, FSTAB_TEXT);
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].device, "/dev/sdc1");
        let mounts = "/dev/sdc1 /data xfs ro 0 0\n/dev/sdb1 /data xfs rw 0 0\n";
        assert_eq!(read_only_against_fstab(mounts, FSTAB_TEXT), vec![]);
        // And in fstab: the last wants read-only, so there is nothing to say.
        let fstab = "/dev/a /data xfs defaults 0 0\n/dev/b /data xfs ro 0 0\n";
        let mounts = "/dev/b /data xfs ro 0 0\n";
        assert_eq!(read_only_against_fstab(mounts, fstab), vec![]);
        let fstab = "/dev/a /data xfs ro 0 0\n/dev/b /data xfs defaults 0 0\n";
        assert_eq!(read_only_against_fstab(mounts, fstab).len(), 1);
    }

    #[test]
    fn a_trailing_slash_does_not_hide_a_mount() {
        let fstab = "/dev/sdb1 /data/ xfs defaults 0 0\n";
        let mounts = "/dev/sdb1 /data xfs ro 0 0\n";
        let found = read_only_against_fstab(mounts, fstab);
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].mount_point, "/data");
        let fstab = "/dev/sdb1 /data xfs defaults 0 0\n";
        let mounts = "/dev/sdb1 /data/ xfs ro 0 0\n";
        assert_eq!(read_only_against_fstab(mounts, fstab).len(), 1);
    }

    #[test]
    fn a_mount_point_with_a_space_is_matched_after_decoding() {
        let fstab = "/dev/sdb1 /my\\040disk xfs defaults 0 0\n";
        let mounts = "/dev/sdb1 /my\\040disk xfs ro 0 0\n";
        let found = read_only_against_fstab(mounts, fstab);
        assert_eq!(found[0].mount_point, "/my disk");
    }

    #[test]
    fn the_findings_come_in_the_order_of_the_mount_points() {
        let fstab = "/dev/c /zeta xfs defaults 0 0\n/dev/a /alpha xfs defaults 0 0\n/dev/b / ext4 defaults 0 0\n";
        let mounts = "/dev/c /zeta xfs ro 0 0\n/dev/a /alpha xfs ro 0 0\n/dev/b / ext4 ro 0 0\n";
        let points: Vec<String> = read_only_against_fstab(mounts, fstab)
            .into_iter()
            .map(|m| m.mount_point)
            .collect();
        assert_eq!(points, vec!["/", "/alpha", "/zeta"]);
    }

    #[test]
    fn terminal_escapes_in_a_mount_are_replaced() {
        let fstab = "/dev/sdb1 /da\\033ta xfs defaults 0 0\n";
        let mounts = "/dev/sdb\\033 /da\\033ta x\\033fs ro,\\033 0 0\n";
        let found = read_only_against_fstab(mounts, fstab);
        assert_eq!(found.len(), 1);
        let m = &found[0];
        for field in [&m.mount_point, &m.device, &m.fstype, &m.mounted_options] {
            assert!(!field.contains('\u{1b}'), "{field}");
        }
        assert_eq!(m.mount_point, "/da?ta");
        assert_eq!(m.device, "/dev/sdb?");
    }

    #[test]
    fn long_fields_are_cut() {
        let long = "a".repeat(300);
        let fstab = format!("/dev/sdb1 /{long} xfs defaults 0 0\n");
        let mounts = format!("/dev/sdb1 /{long} xfs ro,{long} 0 0\n");
        let m = &read_only_against_fstab(&mounts, &fstab)[0];
        assert_eq!(m.mount_point.chars().count(), 201);
        assert_eq!(m.mounted_options.chars().count(), 201);
        let fstab = format!("/dev/sdb1 /data xfs defaults,{long} 0 0\n");
        let mounts = "/dev/sdb1 /data xfs ro 0 0\n";
        let m = &read_only_against_fstab(mounts, &fstab)[0];
        assert_eq!(m.fstab_options.chars().count(), 201);
        let mounts = format!("/dev/{long} /data xfs ro 0 0\n");
        let m = &read_only_against_fstab(&mounts, "/dev/x /data xfs defaults 0 0\n")[0];
        assert_eq!(m.device.chars().count(), 201);
        let mounts = format!("/dev/sdb1 /data {long} ro 0 0\n");
        let m = &read_only_against_fstab(&mounts, "/dev/x /data auto defaults 0 0\n")[0];
        assert_eq!(m.fstype.chars().count(), 201);
    }

    #[test]
    fn the_mounts_are_read_under_the_root_and_both_files_are_needed() {
        let root = std::env::temp_dir().join(format!("ld-mounts-{}", std::process::id()));
        let _ = fs::remove_dir_all(&root);
        assert_eq!(read(&root), vec![]);
        fs::create_dir_all(root.join("proc")).unwrap();
        fs::create_dir_all(root.join("etc")).unwrap();
        let mounts = "/dev/sdb1 /data xfs ro 0 0\n";
        fs::write(root.join("proc/mounts"), mounts).unwrap();
        assert_eq!(read(&root), vec![], "no fstab");
        fs::remove_file(root.join("proc/mounts")).unwrap();
        fs::write(root.join("etc/fstab"), FSTAB_TEXT).unwrap();
        assert_eq!(read(&root), vec![], "no mounts");
        fs::write(root.join("proc/mounts"), mounts).unwrap();
        let found = read(&root);
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].mount_point, "/data");
        let _ = fs::remove_dir_all(&root);
    }

    // --- the finding -----------------------------------------------------

    #[test]
    fn a_data_disk_is_an_error_with_what_is_known() {
        let f = mount_finding(&mount("/data"));
        assert_eq!(f.id, "STOR006");
        assert_eq!(f.title, "Read-Only Filesystem \u{2014} /data");
        assert_eq!(f.instance.as_deref(), Some("/data"));
        assert_eq!(f.severity, Severity::Error);
        assert_eq!(f.confidence.percent, 90);
        assert_eq!(evidence(&f, "mount_point"), Some("/data"));
        assert_eq!(evidence(&f, "device"), Some("/dev/sdb1"));
        assert_eq!(evidence(&f, "fstype"), Some("xfs"));
        assert_eq!(evidence(&f, "mounted_options"), Some("ro,relatime"));
        assert_eq!(evidence(&f, "fstab_options"), Some("defaults"));
        assert_eq!(
            f.explanation,
            "/data is mounted read-only (/dev/sdb1, xfs), but /etc/fstab asks for \
             read-write. Either someone remounted it on purpose (a backup, maintenance), or \
             the kernel did it after finding errors on the disk; in that case nothing can \
             be written to it until it is repaired."
        );
    }

    #[test]
    fn the_root_filesystem_is_critical_and_says_why() {
        let f = mount_finding(&mount("/"));
        assert_eq!(f.severity, Severity::Critical);
        assert!(
            f.explanation.starts_with("/ is mounted read-only"),
            "{}",
            f.explanation
        );
        assert!(
            f.explanation.ends_with(
                "This is the root filesystem: the system cannot write its logs, its state or \
                 its temporary files, and services will start to fail."
            ),
            "{}",
            f.explanation
        );
        let other = mount_finding(&mount("/data"));
        assert!(!other.explanation.contains("root filesystem"));
    }

    #[test]
    fn a_data_disk_is_checked_after_unmounting_it() {
        let rec = mount_finding(&mount("/data")).recommendation.unwrap();
        assert!(
            rec.starts_with("1. If it went read-only because of errors, copy what matters"),
            "{rec}"
        );
        for command in [
            "\n    sudo journalctl -k -b | grep -i -E 'remount|read-only|i/o error'",
            "\n    sudo smartctl -a /dev/sdb",
            "\n    sudo mount -o remount,rw /data",
            "\n    sudo umount /data",
            "\n    sudo fsck -f /dev/sdb1",
        ] {
            assert!(rec.contains(command), "{command}\n{rec}");
        }
        assert!(rec.contains("unmount it first"), "{rec}");
        assert!(!rec.contains("rescue"), "{rec}");
        let at = |needle: &str| rec.find(needle).unwrap();
        assert!(at("journalctl") < at("smartctl"));
        assert!(at("smartctl") < at("remount,rw"));
        assert!(at("remount,rw") < at("umount"));
        assert!(at("umount") < at("fsck"));
    }

    #[test]
    fn the_root_filesystem_is_checked_from_a_rescue_system() {
        let mut root = mount("/");
        root.device = "/dev/nvme0n1p2".to_string();
        let rec = mount_finding(&root).recommendation.unwrap();
        assert!(rec.contains("boot a rescue system"), "{rec}");
        assert!(
            rec.contains("\n    sudo smartctl -a /dev/nvme0n1\n"),
            "{rec}"
        );
        assert!(rec.contains("\n    sudo fsck -f /dev/nvme0n1p2"), "{rec}");
        assert!(rec.contains("\n    sudo mount -o remount,rw /\n"), "{rec}");
        assert!(!rec.contains("umount"), "{rec}");
    }

    #[test]
    fn a_device_that_is_not_a_disk_is_scanned_for_not_named() {
        for device in [
            "/dev/mapper/vg-data",
            "/dev/dm-0",
            "/dev/md0",
            "/dev/root",
            "UUID=abcd",
        ] {
            let mut m = mount("/data");
            m.device = device.to_string();
            let rec = mount_finding(&m).recommendation.unwrap();
            assert!(
                rec.contains("\n    sudo smartctl --scan"),
                "{device}\n{rec}"
            );
            assert!(!rec.contains("smartctl -a"), "{device}\n{rec}");
        }
    }

    #[test]
    fn names_that_are_not_safe_in_a_command_are_not_put_in_one() {
        let mut m = mount("/my data;halt");
        m.device = "/dev/sdb1;reboot".to_string();
        let rec = mount_finding(&m).recommendation.unwrap();
        assert!(!rec.contains("reboot") && !rec.contains("halt"), "{rec}");
        assert!(
            rec.contains("\n    sudo mount -o remount,rw <mount-point>"),
            "{rec}"
        );
        assert!(rec.contains("\n    sudo umount <mount-point>"), "{rec}");
        assert!(rec.contains("\n    sudo fsck -f /dev/<partition>"), "{rec}");
        assert!(rec.contains("\n    sudo smartctl --scan"), "{rec}");
    }
}
