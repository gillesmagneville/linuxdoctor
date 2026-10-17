// SPDX-License-Identifier: GPL-3.0-only

//! Block device names, as the kernel prints them in `/proc/mdstat` and
//! `/proc/mounts`.

/// The whole disk behind a partition name: `sda1` is on `sda`,
/// `nvme0n1p2` on `nvme0n1`, `mmcblk0p1` on `mmcblk0`. A name that is
/// already a whole disk comes back as it is. Anything that is not a plain
/// disk or partition (`dm-0`, `md1`, `loop3`, `root`) has no disk to ask
/// about, so it is `None`.
pub fn disk_of(name: &str) -> Option<&str> {
    let without_digits = name.trim_end_matches(|c: char| c.is_ascii_digit());
    if name.starts_with("nvme") || name.starts_with("mmcblk") {
        // The digits at the end of `nvme0n1` belong to the disk's name; only
        // `p` and digits after a digit are a partition.
        return match without_digits.strip_suffix('p') {
            Some(disk)
                if disk.ends_with(|c: char| c.is_ascii_digit())
                    && without_digits.len() < name.len() =>
            {
                Some(disk)
            }
            _ => Some(name),
        };
    }
    let prefix = ["xvd", "sd", "vd", "hd"]
        .into_iter()
        .find(|prefix| name.starts_with(prefix))?;
    // `sd1` and `xvd` have no letter that names a disk.
    (without_digits.len() > prefix.len()).then_some(without_digits)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_partition_name_gives_its_disk() {
        for (name, disk) in [
            ("sda1", Some("sda")),
            ("sda", Some("sda")),
            ("sdaa12", Some("sdaa")),
            ("vdb3", Some("vdb")),
            ("hdc2", Some("hdc")),
            ("xvda1", Some("xvda")),
            ("nvme0n1p2", Some("nvme0n1")),
            ("nvme0n1", Some("nvme0n1")),
            ("nvme0n1p", Some("nvme0n1p")),
            ("nvmep1", Some("nvmep1")),
            ("nvme12n3p10", Some("nvme12n3")),
            ("mmcblk0p1", Some("mmcblk0")),
            ("mmcblk0", Some("mmcblk0")),
            ("dm-0", None),
            ("md1", None),
            ("loop3", None),
            ("root", None),
            ("sd", None),
            ("sd1", None),
            ("xvd", None),
            ("xvd7", None),
            ("", None),
        ] {
            assert_eq!(disk_of(name), disk, "{name}");
        }
    }
}
