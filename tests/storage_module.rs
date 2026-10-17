// SPDX-License-Identifier: GPL-3.0-only

use linuxdoctor::core::context::Context;
use linuxdoctor::models::Severity;
use linuxdoctor::modules::storage::analyze::analyze;
use linuxdoctor::modules::storage::collect::{
    parse_inode_usage, parse_space_usage, StorageRawData,
};
use linuxdoctor::modules::storage::{mounts, raid};

fn test_context() -> Context {
    Context {
        hostname: "test-host".into(),
        kernel_version: "6.8.0-test".into(),
        distro: Some("Test Linux".into()),
        architecture: "x86_64".into(),
        cpu_count: 4,
        mem_total_kb: 16_384_000,
        boot_time_unix: 0,
    }
}

#[test]
fn healthy_disk_fixture_produces_only_info_findings() {
    let space = "\
Filesystem     Type  1024-blocks     Used Available Capacity Mounted on
tmpfs          tmpfs     4093748        0   4093748       0% /dev/shm
/dev/vda       ext4    264212084 14177364   5255172      73% /
";
    let inodes = "\
Filesystem     Type    Inodes  IUsed    IFree IUse% Mounted on
tmpfs          tmpfs   511718     20   511698    1% /dev/shm
/dev/vda       ext4  16777216 206913 16570303    2% /
";

    let data = StorageRawData {
        filesystems: parse_space_usage(space).unwrap(),
        inodes: parse_inode_usage(inodes).unwrap(),
        smartctl_available: false,
        disks_checked: 0,
        disk_health: vec![],
        running_as_root: false,
        ..Default::default()
    };

    let findings = analyze(&data, &test_context());

    // tmpfs excluded, only "/" remains -> one STOR001 + one STOR002
    assert_eq!(findings.len(), 3);
    assert!(findings.iter().all(|f| f.severity == Severity::Info));
    assert!(findings.iter().any(|f| f.id == "STOR001"));
    assert!(findings.iter().any(|f| f.id == "STOR002"));
    assert!(findings.iter().any(|f| f.id == "STOR003"));
}

#[test]
fn nearly_full_disk_fixture_produces_critical_finding() {
    let space = "\
Filesystem     Type  1024-blocks     Used Available Capacity Mounted on
/dev/sda1      ext4   100000000 97000000   3000000      97% /
";
    let inodes = "\
Filesystem     Type    Inodes  IUsed    IFree IUse% Mounted on
/dev/sda1      ext4     1000000    2000    998000    0% /
";

    let data = StorageRawData {
        filesystems: parse_space_usage(space).unwrap(),
        inodes: parse_inode_usage(inodes).unwrap(),
        smartctl_available: false,
        disks_checked: 0,
        disk_health: vec![],
        running_as_root: false,
        ..Default::default()
    };

    let findings = analyze(&data, &test_context());
    let stor001 = findings.iter().find(|f| f.id == "STOR001").unwrap();
    let stor002 = findings.iter().find(|f| f.id == "STOR002").unwrap();

    assert_eq!(stor001.severity, Severity::Critical);
    assert_eq!(stor002.severity, Severity::Info); // inodes are fine even though space isn't
}

#[test]
fn a_degraded_array_fixture_is_an_error_naming_the_array() {
    let data = StorageRawData {
        raid: raid::parse_mdstat(
            "\
Personalities : [raid1]
md2 : active raid1 sdb1[1](F) sda1[0]
      976630336 blocks super 1.2 [2/1] [U_]

unused devices: <none>
",
        ),
        ..Default::default()
    };

    let findings = analyze(&data, &test_context());
    let md2 = findings.iter().find(|f| f.id == "STOR005").unwrap();

    assert_eq!(md2.severity, Severity::Error);
    assert_eq!(md2.instance.as_deref(), Some("md2"));
    assert!(md2
        .recommendation
        .as_deref()
        .unwrap()
        .contains("sudo mdadm /dev/md2 --remove failed"));
}

#[test]
fn a_root_filesystem_that_went_read_only_fixture_is_critical() {
    let data = StorageRawData {
        read_only_mounts: mounts::read_only_against_fstab(
            "/dev/nvme0n1p2 / ext4 ro,relatime,errors=remount-ro 0 0\n",
            "UUID=aaaa-bbbb / ext4 errors=remount-ro 0 1\n",
        ),
        ..Default::default()
    };

    let findings = analyze(&data, &test_context());
    let root = findings.iter().find(|f| f.id == "STOR006").unwrap();

    assert_eq!(root.severity, Severity::Critical);
    assert_eq!(root.instance.as_deref(), Some("/"));
}
