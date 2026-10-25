// SPDX-License-Identifier: GPL-3.0-only

use std::path::Path;

use crate::core::context::Context;
use crate::models::{Category, Confidence, Finding, Severity};

use super::collect::{DiskHealth, FilesystemUsage, InodeUsage, StorageRawData};
use super::{mounts, raid};

/// Pseudo/virtual filesystems that don't represent real, manageable disk
/// space — excluded so findings only cover storage an administrator can
/// actually act on. `overlay` is excluded too: on a typical host it's a
/// container's own ephemeral layer, not persistent storage this tool's
/// target audience (PROJECT_CONTEXT.md: sysadmins auditing a single
/// machine) manages directly.
///
/// `df` hides the ones that have no size at all (`proc`, `sysfs`,
/// `cgroup2`, ...), but not those that report a small one: `efivarfs`, the
/// UEFI variable store, is a few hundred KiB that are nearly all in use,
/// which would read as a Critical "nearly full" disk.
///
/// The filesystems that are full by construction (`iso9660`, `squashfs`,
/// ...) are excluded too, through `mounts::READ_ONLY_BY_NATURE`.
const EXCLUDED_FSTYPES: &[&str] = &[
    "tmpfs",
    "devtmpfs",
    "proc",
    "sysfs",
    "cgroup",
    "cgroup2",
    "overlay",
    "efivarfs",
    "selinuxfs",
    "resctrl",
    "nfsd",
    "devpts",
    "mqueue",
    "debugfs",
    "tracefs",
    "configfs",
    "fusectl",
    "binfmt_misc",
    "autofs",
    "nsfs",
    "ramfs",
    "rpc_pipefs",
    "securityfs",
    "pstore",
    "bpf",
    "hugetlbfs",
];

/// Where the kernel mounts what it provides itself. Whatever is mounted
/// under these is a view of the kernel, however its type is named — which
/// also covers the next pseudo-filesystem before the list above knows it.
/// Compared by whole path components: `/sysroot` is a real mount.
const KERNEL_MOUNT_ROOTS: [&str; 2] = ["/proc", "/sys"];

fn is_real_filesystem(fstype: &str, mount_point: &str) -> bool {
    if EXCLUDED_FSTYPES.contains(&fstype) || mounts::READ_ONLY_BY_NATURE.contains(&fstype) {
        return false;
    }
    let mount_point = Path::new(mount_point);
    if KERNEL_MOUNT_ROOTS
        .iter()
        .any(|root| mount_point.starts_with(root))
    {
        return false;
    }
    // AppImage runtimes mount themselves via FUSE with a type string that
    // embeds the app's own name (e.g. "fuse.MyApp-x86_64.AppImage"), so it
    // can't be matched by an exact name like the entries above — match the
    // pattern instead.
    if fstype.to_lowercase().contains("appimage") {
        return false;
    }
    true
}

/// Pure function: RawData -> Findings. No I/O — see ARCHITECTURE.md
/// "Testing Strategy". `_ctx` is unused today but kept for consistency
/// with the other modules and in case future thresholds ever vary by
/// profile (see ARCHITECTURE.md "Future Vision").
pub fn analyze(data: &StorageRawData, _ctx: &Context) -> Vec<Finding> {
    let mut findings = Vec::new();

    for fs in data
        .filesystems
        .iter()
        .filter(|f| is_real_filesystem(&f.fstype, &f.mount_point))
    {
        findings.push(space_usage_finding(fs));
    }
    for fs in data
        .inodes
        .iter()
        .filter(|f| is_real_filesystem(&f.fstype, &f.mount_point))
    {
        findings.push(inode_usage_finding(fs));
    }

    findings.push(smart_summary_finding(data));
    for disk in &data.disk_health {
        findings.push(smart_health_finding(disk));
    }

    findings.extend(raid::findings(&data.raid));
    findings.extend(data.read_only_mounts.iter().map(mounts::mount_finding));

    findings
}

/// Same threshold shape as MEM002/CPU002, applied to a usage percentage.
/// Below 80% we're simply confident it's fine (direct observation); above
/// that, each tier is a single strong signal — not "correlated" evidence,
/// since there's only one measurement here, not multiple agreeing ones.
fn severity_tier(pct: f64) -> (Severity, Confidence) {
    if pct < 80.0 {
        (Severity::Info, Confidence::direct_observation())
    } else if pct < 90.0 {
        (Severity::Warning, Confidence::strong_indication(78))
    } else if pct < 95.0 {
        (Severity::Error, Confidence::strong_indication(85))
    } else {
        (Severity::Critical, Confidence::strong_indication(89))
    }
}

/// STOR001 — one finding per real filesystem, evaluating block usage.
fn space_usage_finding(fs: &FilesystemUsage) -> Finding {
    let (severity, confidence) = severity_tier(fs.use_percent);
    let explanation = match severity {
        Severity::Info => "This filesystem has comfortable headroom.".to_string(),
        Severity::Warning => "This filesystem is filling up. Not necessarily \
             urgent, but worth monitoring — especially if usage has been \
             trending upward."
            .to_string(),
        Severity::Error => "Very little space remains. Applications and \
             services writing to this filesystem may start failing soon."
            .to_string(),
        Severity::Critical => "This filesystem is nearly full. Writes may \
             already be failing, and if this is the root filesystem, overall \
             system stability can be affected."
            .to_string(),
    };

    let mut builder = Finding::builder(
        "STOR001",
        format!("Filesystem Usage \u{2014} {}", fs.mount_point),
        Category::Storage,
        severity,
        confidence,
    )
    .instance(fs.mount_point.clone())
    .evidence("mount_point", fs.mount_point.clone())
    .evidence("fstype", fs.fstype.clone())
    .evidence("used_kb", fs.used_kb.to_string())
    .evidence("total_kb", fs.total_kb.to_string())
    .evidence("use_percent", format!("{:.1}", fs.use_percent))
    .explanation(explanation);

    if severity > Severity::Info {
        builder = builder.recommendation(
            "Identify large files or directories (du, ncdu) and consider \
             removing unneeded data, rotating logs, or expanding the \
             filesystem.",
        );
    }
    builder.build()
}

/// STOR002 — one finding per real filesystem, evaluating inode usage. A
/// distinct failure mode from space usage: a filesystem can run out of
/// inodes with plenty of bytes still free.
fn inode_usage_finding(fs: &InodeUsage) -> Finding {
    let (severity, confidence) = severity_tier(fs.use_percent);
    let explanation = if severity == Severity::Info {
        "Plenty of inodes available on this filesystem.".to_string()
    } else {
        "A filesystem can run out of inodes before running out of disk \
         space — this commonly happens with directories holding very large \
         numbers of small files (mail spools, session caches, log rotation \
         directories). Once inodes are exhausted, new files can't be \
         created even if space remains free."
            .to_string()
    };

    let mut builder = Finding::builder(
        "STOR002",
        format!("Inode Usage \u{2014} {}", fs.mount_point),
        Category::Storage,
        severity,
        confidence,
    )
    .instance(fs.mount_point.clone())
    .evidence("mount_point", fs.mount_point.clone())
    .evidence("fstype", fs.fstype.clone())
    .evidence("inodes_used", fs.inodes_used.to_string())
    .evidence("inodes_total", fs.inodes_total.to_string())
    .evidence("use_percent", format!("{:.1}", fs.use_percent))
    .explanation(explanation);

    if severity > Severity::Info {
        builder = builder.recommendation(
            "Identify directories with very large file counts (e.g. `find \
             <path> | wc -l` per subdirectory) and clean up or consolidate \
             small files.",
        );
    }
    builder.build()
}

/// STOR003 — always reported. Same reasoning as CPU005: absence of
/// per-device STOR004 findings should never be ambiguous between "all
/// devices are healthy" and "SMART couldn't be checked at all".
fn smart_summary_finding(data: &StorageRawData) -> Finding {
    let checked = data.disks_checked;
    let capable = data.disk_health.len();

    let explanation = if !data.smartctl_available {
        "smartctl (from smartmontools) isn't installed, so disk health \
         (SMART) couldn't be checked for any device."
            .to_string()
    } else if checked == 0 {
        "No candidate storage devices were found under /sys/block to check.".to_string()
    } else if capable == 0 {
        let priv_note = if !data.running_as_root {
            " This may also be a permissions issue — SMART queries \
             typically require root; try re-running as root or with sudo."
        } else {
            ""
        };
        format!(
            "Checked {checked} device{s}; none support SMART or reported \
             usable health data (common for virtual/paravirtualized \
             disks).{priv_note}",
            s = if checked == 1 { "" } else { "s" },
        )
    } else {
        format!(
            "{capable} of {checked} device{s} support SMART — see below for \
             per-device health.",
            s = if checked == 1 { "" } else { "s" },
        )
    };

    Finding::builder(
        "STOR003",
        "SMART Summary",
        Category::Storage,
        Severity::Info,
        Confidence::direct_observation(),
    )
    .evidence("smartctl_available", data.smartctl_available.to_string())
    .evidence("devices_checked", checked.to_string())
    .evidence("smart_capable_devices", capable.to_string())
    .explanation(explanation)
    .build()
}

/// STOR004 — one finding per device with usable SMART data. Severity
/// escalates on the strongest signal found: a failed overall
/// self-assessment is the clearest possible warning, but early-warning
/// attribute counts (reallocated/pending/uncorrectable sectors, NVMe
/// critical-warning flags, wear level) are tracked too, since SMART's own
/// pass/fail threshold is often more lenient than these individual
/// attributes climbing from zero.
fn smart_health_finding(disk: &DiskHealth) -> Finding {
    let model = disk.model.as_deref().unwrap_or("unknown model");
    let mut concerns: Vec<String> = Vec::new();
    let mut severity = Severity::Info;

    if disk.smart_passed == Some(false) {
        severity = Severity::Critical;
        concerns.push("the drive's own SMART self-assessment reports FAILED".to_string());
    }

    if let Some(n) = disk.reallocated_sectors {
        if n > 0 {
            severity = severity.max(if n >= 10 {
                Severity::Error
            } else {
                Severity::Warning
            });
            concerns.push(format!(
                "{n} reallocated sector{s}",
                s = if n == 1 { "" } else { "s" }
            ));
        }
    }
    if let Some(n) = disk.pending_sectors {
        if n > 0 {
            severity = severity.max(if n >= 10 {
                Severity::Error
            } else {
                Severity::Warning
            });
            concerns.push(format!(
                "{n} pending sector{s} awaiting reallocation",
                s = if n == 1 { "" } else { "s" }
            ));
        }
    }
    if let Some(n) = disk.uncorrectable_sectors {
        if n > 0 {
            severity = severity.max(Severity::Error);
            concerns.push(format!(
                "{n} uncorrectable sector{s}",
                s = if n == 1 { "" } else { "s" }
            ));
        }
    }
    if let Some(cw) = disk.nvme_critical_warning {
        if cw != 0 {
            severity = severity.max(Severity::Error);
            concerns.push(format!("NVMe critical warning flags set (0x{cw:x})"));
        }
    }
    if let Some(used) = disk.nvme_percentage_used {
        if used >= 100 {
            severity = severity.max(Severity::Error);
            concerns.push(format!("{used}% of rated endurance used"));
        } else if used >= 80 {
            severity = severity.max(Severity::Warning);
            concerns.push(format!("{used}% of rated endurance used"));
        }
    }
    if let Some(n) = disk.nvme_media_errors {
        if n > 0 {
            severity = severity.max(Severity::Warning);
            concerns.push(format!(
                "{n} media error{s} logged",
                s = if n == 1 { "" } else { "s" }
            ));
        }
    }

    let confidence = if concerns.is_empty() {
        Confidence::direct_observation()
    } else {
        Confidence::strong_indication(82)
    };

    let explanation = if concerns.is_empty() {
        format!(
            "{model}: SMART overall-health self-assessment: {}.",
            match disk.smart_passed {
                Some(true) => "PASSED",
                Some(false) => "FAILED",
                None => "unknown",
            }
        )
    } else {
        format!("{model}: {}.", concerns.join("; "))
    };

    let mut builder = Finding::builder(
        "STOR004",
        format!("SMART Health \u{2014} {}", disk.device),
        Category::Storage,
        severity,
        confidence,
    )
    .instance(disk.device.clone())
    .evidence("device", disk.device.clone())
    .evidence("model", model.to_string());

    if let Some(passed) = disk.smart_passed {
        builder = builder.evidence("smart_passed", passed.to_string());
    }
    if let Some(t) = disk.temperature_celsius {
        builder = builder.evidence("temperature_celsius", t.to_string());
    }
    if let Some(h) = disk.power_on_hours {
        builder = builder.evidence("power_on_hours", h.to_string());
    }
    if let Some(n) = disk.reallocated_sectors {
        builder = builder.evidence("reallocated_sectors", n.to_string());
    }
    if let Some(n) = disk.pending_sectors {
        builder = builder.evidence("pending_sectors", n.to_string());
    }
    if let Some(n) = disk.uncorrectable_sectors {
        builder = builder.evidence("uncorrectable_sectors", n.to_string());
    }
    if let Some(n) = disk.nvme_percentage_used {
        builder = builder.evidence("nvme_percentage_used", n.to_string());
    }
    if let Some(n) = disk.nvme_media_errors {
        builder = builder.evidence("nvme_media_errors", n.to_string());
    }

    builder = builder.explanation(explanation);

    if severity == Severity::Critical {
        builder = builder.recommendation(
            "Back up this drive's data immediately and plan to replace it \
             soon — a failed SMART self-assessment is a strong indicator of \
             imminent failure.",
        );
    } else if severity > Severity::Info {
        builder = builder.recommendation(
            "Back up this drive's data if you haven't recently, and watch \
             these figures over time with `smartctl -a <device>` — SMART \
             attribute trends matter more than a single snapshot. Early \
             reallocated/pending sectors don't always mean imminent \
             failure, but rising counts are a strong signal to plan a \
             replacement.",
        );
    }

    builder.build()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ctx() -> Context {
        Context {
            hostname: "test".into(),
            kernel_version: "test".into(),
            distro: None,
            architecture: "x86_64".into(),
            cpu_count: 4,
            mem_total_kb: 16_384_000,
            boot_time_unix: 0,
        }
    }

    fn fs(mount_point: &str, fstype: &str, use_percent: f64) -> FilesystemUsage {
        let total = 100_000_000u64;
        let used = (use_percent / 100.0 * total as f64) as u64;
        FilesystemUsage {
            mount_point: mount_point.to_string(),
            fstype: fstype.to_string(),
            total_kb: total,
            used_kb: used,
            available_kb: total - used,
            use_percent,
        }
    }

    fn inode(mount_point: &str, fstype: &str, use_percent: f64) -> InodeUsage {
        let total = 1_000_000u64;
        let used = (use_percent / 100.0 * total as f64) as u64;
        InodeUsage {
            mount_point: mount_point.to_string(),
            fstype: fstype.to_string(),
            inodes_total: total,
            inodes_used: used,
            inodes_free: total - used,
            use_percent,
        }
    }

    fn healthy_disk(device: &str) -> DiskHealth {
        DiskHealth {
            device: device.to_string(),
            model: Some("Test Drive".to_string()),
            device_type: Some("sat".to_string()),
            smart_passed: Some(true),
            temperature_celsius: Some(35),
            power_on_hours: Some(1000),
            reallocated_sectors: Some(0),
            pending_sectors: Some(0),
            uncorrectable_sectors: Some(0),
            nvme_critical_warning: None,
            nvme_percentage_used: None,
            nvme_media_errors: None,
        }
    }

    #[test]
    fn excludes_pseudo_filesystems() {
        let data = StorageRawData {
            filesystems: vec![fs("/dev/shm", "tmpfs", 50.0), fs("/", "ext4", 50.0)],
            inodes: vec![],
            smartctl_available: false,
            disks_checked: 0,
            disk_health: vec![],
            running_as_root: false,
            ..Default::default()
        };
        let findings = analyze(&data, &ctx());
        // 1 real filesystem finding (STOR001 for "/") + always-present STOR003.
        assert_eq!(findings.len(), 2);
        let stor001 = findings.iter().find(|f| f.id == "STOR001").unwrap();
        assert!(stor001
            .evidence
            .iter()
            .any(|(k, v)| k == "mount_point" && v == "/"));
    }

    #[test]
    fn excludes_appimage_fuse_mounts_regardless_of_app_name() {
        let data = StorageRawData {
            filesystems: vec![
                fs("/tmp/.mount_MyApp123", "fuse.MyApp-x86_64.AppImage", 50.0),
                fs("/", "ext4", 50.0),
            ],
            inodes: vec![],
            smartctl_available: false,
            disks_checked: 0,
            disk_health: vec![],
            running_as_root: false,
            ..Default::default()
        };
        let findings = analyze(&data, &ctx());
        assert_eq!(findings.len(), 2); // STOR001 for "/" + always-present STOR003
        let stor001 = findings.iter().find(|f| f.id == "STOR001").unwrap();
        assert!(stor001
            .evidence
            .iter()
            .any(|(k, v)| k == "mount_point" && v == "/"));
    }

    /// STOR001 and STOR002 findings the analysis produced for `data`, as
    /// `(id, mount point)` pairs.
    fn usage_findings(data: &StorageRawData) -> Vec<(String, String)> {
        analyze(data, &ctx())
            .into_iter()
            .filter(|f| f.id == "STOR001" || f.id == "STOR002")
            .map(|f| (f.id, f.instance.unwrap_or_default()))
            .collect()
    }

    /// One mount, full on blocks and on inodes, of the given type and place.
    fn full_mount(mount_point: &str, fstype: &str) -> StorageRawData {
        StorageRawData {
            filesystems: vec![fs(mount_point, fstype, 100.0)],
            inodes: vec![inode(mount_point, fstype, 100.0)],
            ..Default::default()
        }
    }

    #[test]
    fn excludes_every_kernel_pseudo_filesystem() {
        // Mounted outside /sys and /proc on purpose: only the type decides here.
        // `efivarfs` is the one a real machine showed as a Critical "full disk":
        // `df` lists it because it has a small size, nearly all of it used.
        for fstype in [
            "efivarfs",
            "selinuxfs",
            "resctrl",
            "nfsd",
            "sysfs",
            "proc",
            "tmpfs",
            "devtmpfs",
            "cgroup",
            "cgroup2",
            "securityfs",
            "debugfs",
            "tracefs",
            "configfs",
            "fusectl",
            "binfmt_misc",
            "pstore",
            "bpf",
            "devpts",
            "mqueue",
            "hugetlbfs",
            "ramfs",
            "rpc_pipefs",
            "autofs",
            "nsfs",
            "overlay",
        ] {
            assert_eq!(
                usage_findings(&full_mount("/mnt/x", fstype)),
                vec![],
                "{fstype} must not be reported as a disk"
            );
        }
    }

    #[test]
    fn excludes_images_that_are_full_by_construction() {
        // A mounted ISO, a snap, an EROFS image: 100% used because that is
        // what the medium is, not because anything filled up.
        for fstype in ["iso9660", "udf", "squashfs", "erofs", "cramfs"] {
            assert_eq!(
                usage_findings(&full_mount("/mnt/x", fstype)),
                vec![],
                "{fstype} must not be reported as a full disk"
            );
        }
    }

    #[test]
    fn excludes_whatever_is_mounted_under_sys_and_proc() {
        // A kernel filesystem this list has never heard of still lives there.
        for mount_point in [
            "/sys",
            "/proc",
            "/sys/fs/futurefs",
            "/sys/firmware/efi/efivars",
            "/proc/fs/nfsd",
            "/proc/sys/fs/binfmt_misc",
        ] {
            assert_eq!(
                usage_findings(&full_mount(mount_point, "futurefs")),
                vec![],
                "{mount_point} is kernel-provided"
            );
        }
    }

    #[test]
    fn keeps_real_filesystems_with_a_name_like_sys_or_proc() {
        // `/sysroot` is a real mount on ostree systems; the match is on whole
        // path components, not on the start of the text.
        for mount_point in [
            "/sysroot",
            "/system",
            "/proc-backup",
            "/mnt/sys",
            "/data/proc",
        ] {
            assert_eq!(
                usage_findings(&full_mount(mount_point, "ext4")),
                vec![
                    ("STOR001".to_string(), mount_point.to_string()),
                    ("STOR002".to_string(), mount_point.to_string()),
                ],
                "{mount_point} is a real disk"
            );
        }
    }

    #[test]
    fn keeps_every_kind_of_real_filesystem() {
        // Local, network, userspace and shared-folder filesystems all hold
        // data an administrator can fill up.
        for fstype in [
            "ext4",
            "xfs",
            "btrfs",
            "zfs",
            "f2fs",
            "vfat",
            "exfat",
            "ntfs3",
            "fuseblk",
            "nfs4",
            "cifs",
            "9p",
            "virtiofs",
            "lustre",
            "fuse.sshfs",
        ] {
            assert_eq!(
                usage_findings(&full_mount("/mnt/x", fstype)),
                vec![
                    ("STOR001".to_string(), "/mnt/x".to_string()),
                    ("STOR002".to_string(), "/mnt/x".to_string()),
                ],
                "{fstype} is a real filesystem"
            );
        }
    }

    #[test]
    fn info_level_below_80_percent() {
        let data = StorageRawData {
            filesystems: vec![fs("/", "ext4", 73.0)],
            inodes: vec![],
            smartctl_available: false,
            disks_checked: 0,
            disk_health: vec![],
            running_as_root: false,
            ..Default::default()
        };
        assert_eq!(analyze(&data, &ctx())[0].severity, Severity::Info);
    }

    #[test]
    fn warning_level_between_80_and_90() {
        let data = StorageRawData {
            filesystems: vec![fs("/", "ext4", 85.0)],
            inodes: vec![],
            smartctl_available: false,
            disks_checked: 0,
            disk_health: vec![],
            running_as_root: false,
            ..Default::default()
        };
        assert_eq!(analyze(&data, &ctx())[0].severity, Severity::Warning);
    }

    #[test]
    fn error_level_between_90_and_95() {
        let data = StorageRawData {
            filesystems: vec![fs("/", "ext4", 92.0)],
            inodes: vec![],
            smartctl_available: false,
            disks_checked: 0,
            disk_health: vec![],
            running_as_root: false,
            ..Default::default()
        };
        assert_eq!(analyze(&data, &ctx())[0].severity, Severity::Error);
    }

    #[test]
    fn critical_level_at_or_above_95() {
        let data = StorageRawData {
            filesystems: vec![fs("/", "ext4", 97.0)],
            inodes: vec![],
            smartctl_available: false,
            disks_checked: 0,
            disk_health: vec![],
            running_as_root: false,
            ..Default::default()
        };
        assert_eq!(analyze(&data, &ctx())[0].severity, Severity::Critical);
    }

    #[test]
    fn inode_findings_use_stor002_id() {
        let data = StorageRawData {
            filesystems: vec![],
            inodes: vec![inode("/", "ext4", 92.0)],
            smartctl_available: false,
            disks_checked: 0,
            disk_health: vec![],
            running_as_root: false,
            ..Default::default()
        };
        let findings = analyze(&data, &ctx());
        assert_eq!(findings[0].id, "STOR002");
        assert_eq!(findings[0].severity, Severity::Error);
    }

    #[test]
    fn multiple_real_filesystems_each_get_a_finding() {
        let data = StorageRawData {
            filesystems: vec![fs("/", "ext4", 50.0), fs("/data", "xfs", 92.0)],
            inodes: vec![],
            smartctl_available: false,
            disks_checked: 0,
            disk_health: vec![],
            running_as_root: false,
            ..Default::default()
        };
        assert_eq!(analyze(&data, &ctx()).len(), 3); // 2 filesystems + STOR003
    }

    #[test]
    fn confidence_never_reported_below_60() {
        let data = StorageRawData {
            filesystems: vec![fs("/", "ext4", 10.0), fs("/data", "xfs", 99.0)],
            inodes: vec![inode("/", "ext4", 99.0)],
            smartctl_available: false,
            disks_checked: 0,
            disk_health: vec![],
            running_as_root: false,
            ..Default::default()
        };
        for f in analyze(&data, &ctx()) {
            assert!(f.confidence.percent >= 60);
        }
    }

    #[test]
    fn smart_summary_always_present() {
        let data = StorageRawData {
            filesystems: vec![],
            inodes: vec![],
            smartctl_available: false,
            disks_checked: 0,
            disk_health: vec![],
            running_as_root: false,
            ..Default::default()
        };
        let findings = analyze(&data, &ctx());
        assert!(findings.iter().any(|f| f.id == "STOR003"));
    }

    #[test]
    fn smart_summary_notes_missing_smartctl() {
        let data = StorageRawData {
            filesystems: vec![],
            inodes: vec![],
            smartctl_available: false,
            disks_checked: 0,
            disk_health: vec![],
            running_as_root: true,
            ..Default::default()
        };
        let findings = analyze(&data, &ctx());
        let stor003 = findings.iter().find(|f| f.id == "STOR003").unwrap();
        assert!(stor003.explanation.contains("isn't installed"));
    }

    #[test]
    fn smart_summary_notes_permission_hint_when_not_root() {
        let data = StorageRawData {
            filesystems: vec![],
            inodes: vec![],
            smartctl_available: true,
            disks_checked: 2,
            disk_health: vec![],
            running_as_root: false,
            ..Default::default()
        };
        let findings = analyze(&data, &ctx());
        let stor003 = findings.iter().find(|f| f.id == "STOR003").unwrap();
        assert!(stor003.explanation.contains("permissions"));
    }

    #[test]
    fn smart_summary_no_permission_hint_when_root() {
        let data = StorageRawData {
            filesystems: vec![],
            inodes: vec![],
            smartctl_available: true,
            disks_checked: 2,
            disk_health: vec![],
            running_as_root: true,
            ..Default::default()
        };
        let findings = analyze(&data, &ctx());
        let stor003 = findings.iter().find(|f| f.id == "STOR003").unwrap();
        assert!(!stor003.explanation.contains("permissions"));
    }

    #[test]
    fn healthy_disk_produces_info_and_instance() {
        let data = StorageRawData {
            filesystems: vec![],
            inodes: vec![],
            smartctl_available: true,
            disks_checked: 1,
            disk_health: vec![healthy_disk("/dev/sda")],
            running_as_root: true,
            ..Default::default()
        };
        let findings = analyze(&data, &ctx());
        let stor004 = findings.iter().find(|f| f.id == "STOR004").unwrap();
        assert_eq!(stor004.severity, Severity::Info);
        assert_eq!(stor004.instance.as_deref(), Some("/dev/sda"));
    }

    #[test]
    fn failed_smart_status_is_critical() {
        let mut disk = healthy_disk("/dev/sda");
        disk.smart_passed = Some(false);
        let data = StorageRawData {
            filesystems: vec![],
            inodes: vec![],
            smartctl_available: true,
            disks_checked: 1,
            disk_health: vec![disk],
            running_as_root: true,
            ..Default::default()
        };
        let findings = analyze(&data, &ctx());
        let stor004 = findings.iter().find(|f| f.id == "STOR004").unwrap();
        assert_eq!(stor004.severity, Severity::Critical);
        assert!(stor004.recommendation.is_some());
    }

    #[test]
    fn small_reallocated_count_is_warning() {
        let mut disk = healthy_disk("/dev/sda");
        disk.reallocated_sectors = Some(3);
        let data = StorageRawData {
            filesystems: vec![],
            inodes: vec![],
            smartctl_available: true,
            disks_checked: 1,
            disk_health: vec![disk],
            running_as_root: true,
            ..Default::default()
        };
        let findings = analyze(&data, &ctx());
        let stor004 = findings.iter().find(|f| f.id == "STOR004").unwrap();
        assert_eq!(stor004.severity, Severity::Warning);
    }

    #[test]
    fn large_reallocated_count_is_error() {
        let mut disk = healthy_disk("/dev/sda");
        disk.reallocated_sectors = Some(50);
        let data = StorageRawData {
            filesystems: vec![],
            inodes: vec![],
            smartctl_available: true,
            disks_checked: 1,
            disk_health: vec![disk],
            running_as_root: true,
            ..Default::default()
        };
        let findings = analyze(&data, &ctx());
        let stor004 = findings.iter().find(|f| f.id == "STOR004").unwrap();
        assert_eq!(stor004.severity, Severity::Error);
    }

    #[test]
    fn nvme_high_wear_is_warning() {
        let mut disk = healthy_disk("/dev/nvme0");
        disk.reallocated_sectors = None;
        disk.pending_sectors = None;
        disk.uncorrectable_sectors = None;
        disk.nvme_percentage_used = Some(85);
        let data = StorageRawData {
            filesystems: vec![],
            inodes: vec![],
            smartctl_available: true,
            disks_checked: 1,
            disk_health: vec![disk],
            running_as_root: true,
            ..Default::default()
        };
        let findings = analyze(&data, &ctx());
        let stor004 = findings.iter().find(|f| f.id == "STOR004").unwrap();
        assert_eq!(stor004.severity, Severity::Warning);
    }

    #[test]
    fn nvme_critical_warning_flags_are_error() {
        let mut disk = healthy_disk("/dev/nvme0");
        disk.reallocated_sectors = None;
        disk.pending_sectors = None;
        disk.uncorrectable_sectors = None;
        disk.nvme_critical_warning = Some(1);
        let data = StorageRawData {
            filesystems: vec![],
            inodes: vec![],
            smartctl_available: true,
            disks_checked: 1,
            disk_health: vec![disk],
            running_as_root: true,
            ..Default::default()
        };
        let findings = analyze(&data, &ctx());
        let stor004 = findings.iter().find(|f| f.id == "STOR004").unwrap();
        assert_eq!(stor004.severity, Severity::Error);
    }

    #[test]
    fn multiple_disks_each_get_their_own_instance() {
        let data = StorageRawData {
            filesystems: vec![],
            inodes: vec![],
            smartctl_available: true,
            disks_checked: 2,
            disk_health: vec![healthy_disk("/dev/sda"), healthy_disk("/dev/sdb")],
            running_as_root: true,
            ..Default::default()
        };
        let findings = analyze(&data, &ctx());
        let instances: Vec<_> = findings
            .iter()
            .filter(|f| f.id == "STOR004")
            .filter_map(|f| f.instance.as_deref())
            .collect();
        assert_eq!(instances, vec!["/dev/sda", "/dev/sdb"]);
    }

    #[test]
    fn arrays_and_read_only_mounts_come_after_the_disks_in_that_order() {
        let data = StorageRawData {
            smartctl_available: true,
            disks_checked: 1,
            disk_health: vec![healthy_disk("/dev/sda")],
            raid: raid::parse_mdstat(
                "md0 : active raid1 sdb1[1] sda1[0]\n  1 blocks [2/2] [UU]\n\
                 md1 : active raid1 sdd1[1](F) sdc1[0]\n  1 blocks [2/1] [U_]\n",
            ),
            read_only_mounts: mounts::read_only_against_fstab(
                "/dev/sdb1 /data xfs ro 0 0\n/dev/sdc1 /srv xfs ro 0 0\n",
                "/dev/sdb1 /data xfs defaults 0 0\n/dev/sdc1 /srv xfs defaults 0 0\n",
            ),
            ..Default::default()
        };
        let findings = analyze(&data, &ctx());
        let seen: Vec<(String, Option<String>)> = findings
            .iter()
            .map(|f| (f.id.clone(), f.instance.clone()))
            .collect();
        let expected: Vec<(String, Option<String>)> = [
            ("STOR003", None),
            ("STOR004", Some("/dev/sda")),
            ("STOR005", Some("md0")),
            ("STOR005", Some("md1")),
            ("STOR006", Some("/data")),
            ("STOR006", Some("/srv")),
        ]
        .into_iter()
        .map(|(id, instance)| (id.to_string(), instance.map(str::to_string)))
        .collect();
        assert_eq!(seen, expected);
    }

    #[test]
    fn a_machine_without_arrays_or_read_only_mounts_has_neither_finding() {
        let findings = analyze(&StorageRawData::default(), &ctx());
        assert!(findings
            .iter()
            .all(|f| f.id != "STOR005" && f.id != "STOR006"));
    }
}
