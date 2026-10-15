// SPDX-License-Identifier: GPL-3.0-only

//! What the kernel reported since boot that points at failing hardware or
//! a crashing system: disk and filesystem errors, memory and bus errors,
//! tasks stuck on I/O, overheating, and programs or kernel code that
//! crashed.
//!
//! Out-of-memory kills are the Kernel module's (`KERN` findings); they are
//! deliberately not repeated here.
//!
//! Pure functions over [`Entry`] values.

use std::collections::{BTreeMap, BTreeSet};

use crate::models::{Category, Confidence, Finding, Severity};
use crate::modules::recommend::Steps;

use super::journal::Entry;
use super::text::{clean, is_safe_word, table};

/// Corrected PCIe errors are routine on many desktops; this many in one
/// boot suggest a marginal link.
const PCIE_FLOOD: u32 = 100;
/// Segfaults of the same program that make it worth a warning.
const REPEATED_CRASH: u32 = 3;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Kind {
    // Storage and hardware (LOG006)
    FsReadOnly,
    HardwareUncorrected,
    FsError,
    IoError,
    HardwareCorrected,
    HungTask,
    Throttle,
    NetWatchdog,
    PcieCorrected,
    // Crashes (LOG007)
    Oops,
    Lockup,
    Segfault,
}

impl Kind {
    pub fn is_crash(self) -> bool {
        matches!(self, Kind::Oops | Kind::Lockup | Kind::Segfault)
    }

    pub fn label(self) -> &'static str {
        match self {
            Kind::FsReadOnly => "Filesystem switched to read-only",
            Kind::HardwareUncorrected => "Uncorrected hardware errors",
            Kind::FsError => "Filesystem errors",
            Kind::IoError => "Disk I/O errors",
            Kind::HardwareCorrected => "Corrected hardware errors",
            Kind::HungTask => "Tasks stuck for minutes",
            Kind::Throttle => "CPU thermal throttling",
            Kind::NetWatchdog => "Network adapter timeouts",
            Kind::PcieCorrected => "Corrected PCIe errors",
            Kind::Oops => "Kernel faults (Oops, BUG)",
            Kind::Lockup => "CPU lockups and stalls",
            Kind::Segfault => "Program crashes",
        }
    }

    fn why(self) -> &'static str {
        match self {
            Kind::FsReadOnly => {
                "The kernel remounted a filesystem read-only after finding damage or I/O \
                 failures, to stop making it worse. Everything that writes there now fails."
            }
            Kind::HardwareUncorrected => {
                "The CPU, memory controller or a PCIe device reported an error the hardware \
                 could not correct: data may have been corrupted."
            }
            Kind::FsError => {
                "A filesystem found inconsistent data. It may be the disk, a power cut, or a \
                 bug; either way the filesystem needs a check."
            }
            Kind::IoError => {
                "A disk, SSD or controller failed to read or write. This is the usual first \
                 sign of a failing drive or a loose cable. It is also logged when a USB drive \
                 is unplugged without being unmounted."
            }
            Kind::HardwareCorrected => {
                "The hardware corrected an error by itself (memory or CPU cache). A few are \
                 normal; a steady stream from the same module means it is wearing out."
            }
            Kind::HungTask => {
                "A task waited more than a couple of minutes for the disk or network. The \
                 storage is stalling, or a remote filesystem stopped answering."
            }
            Kind::Throttle => {
                "The CPU slowed itself down to avoid overheating: cooling is inadequate or \
                 blocked."
            }
            Kind::NetWatchdog => {
                "The kernel's watchdog found a network adapter that stopped sending. Often a \
                 driver, firmware or cable problem."
            }
            Kind::PcieCorrected => {
                "A PCIe link corrected transmission errors. Occasional ones are routine; a \
                 flood points to a marginal slot, riser or power-saving setting."
            }
            Kind::Oops => {
                "The kernel itself hit a bug or an impossible state. After one, the system \
                 may be unstable until it is rebooted."
            }
            Kind::Lockup => {
                "A CPU stopped responding for seconds, or the kernel detected a stall. \
                 Usually a driver bug or failing hardware."
            }
            Kind::Segfault => {
                "Programs were killed by the kernel for touching memory they should not. \
                 One program crashing is a bug in it; several unrelated ones point to \
                 failing memory or overheating."
            }
        }
    }

    fn severity(self, count: u32) -> Severity {
        match self {
            Kind::FsReadOnly | Kind::HardwareUncorrected => Severity::Critical,
            Kind::FsError | Kind::IoError | Kind::Oops => Severity::Error,
            Kind::HardwareCorrected
            | Kind::HungTask
            | Kind::Throttle
            | Kind::NetWatchdog
            | Kind::Lockup => Severity::Warning,
            Kind::PcieCorrected if count >= PCIE_FLOOD => Severity::Warning,
            Kind::PcieCorrected => Severity::Info,
            Kind::Segfault => Severity::Info, // decided from the whole picture, see crash_severity
        }
    }
}

/// The kind of problem a kernel message reports, if any.
pub fn classify(message: &str) -> Option<Kind> {
    let m = message.to_lowercase();
    let has = |s: &str| m.contains(s);

    if has(": segfault at ") || m.starts_with("traps: ") {
        return Some(Kind::Segfault);
    }
    if has("soft lockup") || has("hard lockup") || has("detected stall") {
        return Some(Kind::Lockup);
    }
    if has("unable to handle kernel")
        || has("kernel bug at")
        || m.starts_with("bug: ")
        || has("oops: ")
        || has("kernel panic")
    {
        return Some(Kind::Oops);
    }
    if has("remounting filesystem read-only")
        || has("forced readonly")
        || (has("xfs") && (has("filesystem has been shut down") || has("force_shutdown")))
    {
        return Some(Kind::FsReadOnly);
    }
    if (has("mce:") && (has("uncorrected") || has("fatal")))
        || has("machine check exception")
        || (has("edac") && (has(" ue ") || has("uncorrected")))
        || (has("aer:") && has("uncorrected"))
    {
        return Some(Kind::HardwareUncorrected);
    }
    if has("ext4-fs error")
        || (has("xfs") && (has("metadata i/o error") || has("corruption detected")))
        || (has("btrfs")
            && (has("csum failed") || has("checksum error") || has("parent transid verify failed")))
    {
        return Some(Kind::FsError);
    }
    if has("i/o error, dev ")
        || has("blk_update_request: i/o error")
        || has("buffer i/o error")
        || has("end_request: i/o error")
        || has("failed command: read")
        || has("failed command: write")
        || has("medium error, dev ")
        || (has("ata") && has("exception emask"))
        || (has("nvme") && (has("timeout") || has("controller is down")))
    {
        return Some(Kind::IoError);
    }
    if (has("mce:") && (has("hardware error") || has("machine check events logged")))
        || (has("edac") && has(" ce "))
    {
        return Some(Kind::HardwareCorrected);
    }
    if has("aer:") && has("corrected") {
        return Some(Kind::PcieCorrected);
    }
    if has("blocked for more than") && has("seconds") {
        return Some(Kind::HungTask);
    }
    if has("cpu clock throttled")
        || has("package temperature above threshold")
        || has("core temperature above threshold")
    {
        return Some(Kind::Throttle);
    }
    if has("netdev watchdog") && has("timed out") {
        return Some(Kind::NetWatchdog);
    }
    None
}

/// The program named in a crash message:
/// `firefox[1234]: segfault at ...` or `traps: foo[12] general protection ...`.
fn crashed_program(message: &str) -> Option<String> {
    let head = match message.find(": segfault at ") {
        Some(at) => &message[..at],
        None => message.strip_prefix("traps: ")?.split(']').next()?,
    };
    let name = head.rsplit_once('[').map_or(head, |(name, _)| name);
    let name = name.trim();
    (!name.is_empty()).then(|| clean(name, 40))
}

/// The disk named in a storage message, reduced to the whole device
/// (`sda1` becomes `sda`, `nvme0n1p2` becomes `nvme0n1`). Only real disks
/// are returned: loop devices, device-mapper and RAID volumes have no SMART
/// data of their own.
fn device_of(message: &str) -> Option<String> {
    let alnum = |text: &str| -> String {
        text.chars()
            .take_while(|c| c.is_ascii_alphanumeric())
            .collect()
    };
    let raw = if let Some(at) = message.find("dev ") {
        alnum(&message[at + 4..])
    } else {
        // "EXT4-fs (sda1): ..." and "EXT4-fs error (device sda1): ..."
        let open = message.find('(')?;
        let inner = &message[open + 1..];
        alnum(inner.strip_prefix("device ").unwrap_or(inner))
    };
    let disk = if raw.starts_with("nvme") || raw.starts_with("mmcblk") {
        match raw.rfind('p') {
            Some(p)
                if p > 0
                    && p + 1 < raw.len()
                    && raw[p + 1..].chars().all(|c| c.is_ascii_digit()) =>
            {
                raw[..p].to_string()
            }
            _ => raw,
        }
    } else if ["sd", "hd", "vd", "xvd"].iter().any(|p| raw.starts_with(p)) {
        raw.trim_end_matches(|c: char| c.is_ascii_digit())
            .to_string()
    } else {
        return None;
    };
    (is_safe_word(&disk) && !disk.is_empty()).then_some(disk)
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct KindStats {
    pub count: u32,
    /// The first message of this kind, as the kernel wrote it.
    pub example: String,
    /// Disks involved (at most four).
    pub devices: Vec<String>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct KernelSummary {
    /// Kernel messages examined.
    pub examined: usize,
    pub kinds: BTreeMap<Kind, KindStats>,
    /// Crashed programs and how often each crashed.
    pub programs: BTreeMap<String, u32>,
}

pub fn summarize(entries: &[Entry]) -> KernelSummary {
    let mut s = KernelSummary {
        examined: entries.len(),
        ..Default::default()
    };
    for e in entries {
        let Some(kind) = classify(&e.message) else {
            continue;
        };
        let stats = s.kinds.entry(kind).or_default();
        stats.count += 1;
        if stats.example.is_empty() {
            stats.example = clean(&e.message, 110);
        }
        if matches!(kind, Kind::IoError | Kind::FsError | Kind::FsReadOnly) {
            if let Some(device) = device_of(&e.message) {
                if !stats.devices.contains(&device) && stats.devices.len() < 4 {
                    stats.devices.push(device);
                }
            }
        }
        if kind == Kind::Segfault {
            if let Some(program) = crashed_program(&e.message) {
                *s.programs.entry(program).or_insert(0) += 1;
            }
        }
    }
    s
}

impl KernelSummary {
    fn present(&self, crash: bool) -> Vec<(Kind, &KindStats)> {
        let mut v: Vec<(Kind, &KindStats)> = self
            .kinds
            .iter()
            .filter(|(k, _)| k.is_crash() == crash)
            .map(|(k, s)| (*k, s))
            .collect();
        v.sort_by_key(|(k, s)| (std::cmp::Reverse(k.severity(s.count)), *k));
        v
    }

    fn devices(&self) -> BTreeSet<&str> {
        self.kinds
            .values()
            .flat_map(|s| s.devices.iter().map(String::as_str))
            .collect()
    }
}

fn plural(n: u32) -> &'static str {
    if n == 1 {
        "time"
    } else {
        "times"
    }
}

/// LOG006 — storage and hardware errors.
pub fn hardware_finding(summary: &KernelSummary, source: &str) -> Finding {
    let present = summary.present(false);
    let severity = present
        .iter()
        .map(|(k, s)| k.severity(s.count))
        .max()
        .unwrap_or(Severity::Info);

    let mut text = String::new();
    if present.is_empty() {
        text.push_str(&format!(
            "No disk, filesystem, memory, bus or cooling error appears in the {} kernel \
             messages since boot. Out-of-memory kills are reported by the Kernel module.",
            summary.examined
        ));
    } else {
        text.push_str(
            "The kernel logged hardware or storage problems since the last boot, most \
             serious first.",
        );
        let rows: Vec<Vec<String>> = present
            .iter()
            .map(|(k, s)| {
                vec![
                    s.count.to_string(),
                    k.label().to_string(),
                    s.example.clone(),
                ]
            })
            .collect();
        text.push_str("\n\n");
        text.push_str(&table(&["Count", "Problem", "First message"], &rows));
        for (k, s) in &present {
            if k.severity(s.count) >= Severity::Warning || *k == Kind::IoError {
                text.push_str(&format!("\n\n{}: {}", k.label(), k.why()));
            }
        }
    }

    let mut builder = Finding::builder(
        "LOG006",
        "Storage & Hardware Errors",
        Category::Logs,
        severity,
        Confidence::direct_observation(),
    )
    .evidence("source", source)
    .evidence("kernel_messages_examined", summary.examined.to_string());
    for (k, s) in &present {
        builder = builder.evidence(
            k.label()
                .to_lowercase()
                .replace(['(', ')', ','], "")
                .replace(' ', "_"),
            s.count.to_string(),
        );
    }
    builder = builder.explanation(text);

    if severity >= Severity::Warning {
        builder = builder.recommendation(hardware_steps(summary, &present).build());
    }
    builder.build()
}

fn smart_commands(summary: &KernelSummary) -> Vec<String> {
    let devices = summary.devices();
    if devices.is_empty() {
        return vec!["sudo smartctl --scan".to_string()];
    }
    devices
        .iter()
        .map(|d| format!("sudo smartctl -a /dev/{d}"))
        .collect()
}

fn hardware_steps(summary: &KernelSummary, present: &[(Kind, &KindStats)]) -> Steps {
    let has = |k: Kind| present.iter().any(|(p, _)| *p == k);
    let mut steps = Steps::new();

    if has(Kind::FsReadOnly) {
        steps = steps.step(
            "Copy what matters somewhere else right now: the filesystem is read-only to \
             protect what is left. See which one:",
            &["mount | grep -E '[(,]ro[,)]' | grep -v -E 'squashfs|iso9660|tmpfs'"],
        );
    }
    if has(Kind::FsReadOnly) || has(Kind::FsError) || has(Kind::IoError) {
        steps = steps.step_owned(
            "Ask the disk about its own health (install smartmontools if the command is \
             missing). Reallocated, pending or uncorrectable sectors mean it is dying:",
            smart_commands(summary),
        );
    }
    if has(Kind::IoError) {
        steps = steps.step(
            "Rule out the cheap causes: reseat the data and power cables, try another port, \
             and look at the full error history:",
            &["sudo journalctl -k -b | grep -i -E 'i/o error|ata[0-9]|nvme'"],
        );
    }
    if has(Kind::FsReadOnly) || has(Kind::FsError) {
        steps = steps.step(
            "Check and repair the filesystem. Never do it while it is mounted: boot a rescue \
             system or the installer's live mode, then (ext4 shown; use xfs_repair for XFS, \
             btrfs check for Btrfs):",
            &["sudo fsck -f /dev/<partition>"],
        );
    }
    if has(Kind::HardwareUncorrected) || has(Kind::HardwareCorrected) {
        steps = steps.step(
            "See which component reports the errors (rasdaemon gives the DIMM slot):",
            &[
                "sudo journalctl -k -b | grep -i -E 'mce|edac|hardware error'",
                "sudo ras-mc-ctl --errors",
            ],
        );
        steps = steps.step(
            "Test the memory from the boot menu (memtest86+) for several passes, and replace \
             the module that keeps reporting. Do not trust data written since the first \
             uncorrected error.",
            &[],
        );
    }
    if has(Kind::HungTask) {
        steps = steps.step(
            "Find which device is stalling:",
            &[
                "iostat -x 1 5",
                "sudo journalctl -k -b | grep -i 'blocked for more than'",
            ],
        );
    }
    if has(Kind::Throttle) {
        steps = steps.step(
            "Check temperatures and cooling (fans, dust, thermal paste, airflow):",
            &["sensors"],
        );
    }
    if has(Kind::NetWatchdog) {
        steps = steps.step(
            "Identify the adapter and its driver, then update the firmware and driver:",
            &[
                "ip -br link",
                "sudo journalctl -k -b | grep -i 'netdev watchdog'",
            ],
        );
    }
    if has(Kind::PcieCorrected) {
        steps = steps.step(
            "Find the device behind the corrected errors:",
            &["sudo journalctl -k -b | grep -i 'AER:' | tail -20"],
        );
    }
    steps
}

fn crash_severity(summary: &KernelSummary) -> Severity {
    let oops = summary.kinds.contains_key(&Kind::Oops);
    let lockup = summary.kinds.contains_key(&Kind::Lockup);
    let repeated = summary.programs.values().any(|n| *n >= REPEATED_CRASH);
    let several = summary.programs.len() >= 3;
    if oops {
        Severity::Error
    } else if lockup || repeated || several {
        Severity::Warning
    } else {
        Severity::Info
    }
}

/// LOG007 — crashed programs and kernel faults.
pub fn crash_finding(summary: &KernelSummary, source: &str) -> Finding {
    let severity = crash_severity(summary);
    let present = summary.present(true);

    let mut text = String::new();
    if present.is_empty() {
        text.push_str(&format!(
            "No program crash, kernel fault or CPU lockup appears in the {} kernel messages \
             since boot.",
            summary.examined
        ));
    } else {
        let rows: Vec<Vec<String>> = present
            .iter()
            .map(|(k, s)| {
                vec![
                    s.count.to_string(),
                    k.label().to_string(),
                    s.example.clone(),
                ]
            })
            .collect();
        text.push_str(&table(&["Count", "What happened", "First message"], &rows));
        if !summary.programs.is_empty() {
            let mut programs: Vec<(&String, &u32)> = summary.programs.iter().collect();
            programs.sort_by(|a, b| b.1.cmp(a.1).then_with(|| a.0.cmp(b.0)));
            let listed: Vec<String> = programs
                .iter()
                .take(8)
                .map(|(name, n)| format!("{name} ({n} {})", plural(**n)))
                .collect();
            text.push_str(&format!(
                "\n\nPrograms that crashed: {}.",
                listed.join(", ")
            ));
        }
        for (k, _) in &present {
            text.push_str(&format!("\n\n{}: {}", k.label(), k.why()));
        }
        if summary.programs.len() >= 3 {
            text.push_str(
                "\n\nSeveral unrelated programs crashed. When that happens the cause is \
                 rarely in the programs: test the memory and check the temperatures.",
            );
        }
    }

    let mut builder = Finding::builder(
        "LOG007",
        "Crashes & Lockups",
        Category::Logs,
        severity,
        Confidence::direct_observation(),
    )
    .evidence("source", source)
    .evidence("kernel_messages_examined", summary.examined.to_string());
    for (k, s) in &present {
        builder = builder.evidence(
            k.label()
                .to_lowercase()
                .replace(['(', ')', ','], "")
                .replace(' ', "_"),
            s.count.to_string(),
        );
    }
    builder = builder.explanation(text);

    if severity >= Severity::Warning {
        let mut steps = Steps::new();
        if summary.kinds.contains_key(&Kind::Oops) || summary.kinds.contains_key(&Kind::Lockup) {
            steps = steps
                .step(
                    "Read the kernel's own report, with the lines around it:",
                    &["sudo journalctl -k -b | grep -B3 -A25 -E 'BUG:|Oops|lockup|stall'"],
                )
                .step(
                    "Update the kernel and the firmware (BIOS/UEFI), then reboot: most faults \
                     of this kind are fixed in a later release. If it comes back, report it \
                     with the full report above.",
                    &[],
                );
        }
        if !summary.programs.is_empty() {
            let top = summary
                .programs
                .iter()
                .max_by(|a, b| a.1.cmp(b.1).then_with(|| b.0.cmp(a.0)))
                .map(|(name, _)| name.as_str())
                .unwrap_or("");
            let list = "coredumpctl list --since today".to_string();
            let info = if is_safe_word(top) {
                format!("coredumpctl info {top}")
            } else {
                "coredumpctl info".to_string()
            };
            steps = steps.step_owned(
                "See the crashes systemd recorded (install systemd-coredump if the command \
                 reports nothing), and the details of the most frequent one:",
                vec![list, info],
            );
            steps = steps.step(
                "Update the program, and check whether anything it loads changed recently:",
                &["sudo journalctl -k -b | grep -i segfault | tail -20"],
            );
        }
        if summary.programs.len() >= 3 {
            steps = steps.step(
                "Test the memory from the boot menu (memtest86+) for several passes, and \
                 watch the temperatures:",
                &["sensors"],
            );
        }
        builder = builder.recommendation(steps.build());
    }
    builder.build()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn k(message: &str) -> Entry {
        Entry::new("kernel", message)
    }

    #[test]
    fn classifies_real_kernel_messages() {
        let cases: &[(&str, Kind)] = &[
            ("EXT4-fs (sda1): Remounting filesystem read-only", Kind::FsReadOnly),
            ("BTRFS: error (device sda2) in btrfs_commit_transaction: errno=-5 IO failure (Error while writing out transaction) forced readonly", Kind::FsReadOnly),
            ("XFS (sdb1): Filesystem has been shut down due to log error (0x2).", Kind::FsReadOnly),
            ("EXT4-fs error (device sda1): ext4_find_entry:1455: inode #2: comm ls: reading directory lblock 0", Kind::FsError),
            ("XFS (sdb1): Metadata corruption detected at xfs_inode_buf_verify", Kind::FsError),
            ("BTRFS warning (device sda2): csum failed root 5 ino 257 off 0", Kind::FsError),
            ("blk_update_request: I/O error, dev sda, sector 123456 op 0x0:(READ) flags 0x0 phys_seg 1 prio class 0", Kind::IoError),
            ("Buffer I/O error on dev sdb1, logical block 0, async page read", Kind::IoError),
            ("ata1.00: exception Emask 0x0 SAct 0x0 SErr 0x0 action 0x0", Kind::IoError),
            ("ata1.00: failed command: READ FPDMA QUEUED", Kind::IoError),
            ("nvme nvme0: I/O 12 QID 3 timeout, aborting", Kind::IoError),
            ("critical medium error, dev sda, sector 5 op 0x0:(READ)", Kind::IoError),
            ("mce: [Hardware Error]: Machine check events logged", Kind::HardwareCorrected),
            ("EDAC MC0: 1 CE memory read error on CPU_SrcID#0_Ha#0_Chan#1_DIMM#0", Kind::HardwareCorrected),
            ("EDAC MC0: 1 UE memory read error on CPU_SrcID#0_Chan#1_DIMM#0", Kind::HardwareUncorrected),
            ("mce: [Hardware Error]: CPU 3: Machine Check: 0 Bank 5: be00000000800400 uncorrected", Kind::HardwareUncorrected),
            ("pcieport 0000:00:1c.0: AER: Corrected error received: 0000:03:00.0", Kind::PcieCorrected),
            ("pcieport 0000:00:1c.0: AER: Uncorrected (Fatal) error received: 0000:03:00.0", Kind::HardwareUncorrected),
            ("INFO: task jbd2/sda1-8:312 blocked for more than 120 seconds.", Kind::HungTask),
            ("CPU0: Core temperature above threshold, cpu clock throttled (total events = 5)", Kind::Throttle),
            ("NETDEV WATCHDOG: enp3s0 (e1000e): transmit queue 0 timed out", Kind::NetWatchdog),
            ("firefox[4321]: segfault at 0 ip 00007f sp 00007ffd error 4 in libxul.so[7f+1000]", Kind::Segfault),
            ("traps: foo[99] general protection fault ip:7f sp:7ffc error:0 in libc.so.6", Kind::Segfault),
            ("BUG: kernel NULL pointer dereference, address: 0000000000000008", Kind::Oops),
            ("BUG: unable to handle page fault for address: ffffffffc0a00000", Kind::Oops),
            ("Oops: 0002 [#1] SMP NOPTI", Kind::Oops),
            ("watchdog: BUG: soft lockup - CPU#2 stuck for 22s! [kworker:123]", Kind::Lockup),
            ("rcu: INFO: rcu_sched self-detected stall on CPU", Kind::Lockup),
        ];
        for (message, expected) in cases {
            assert_eq!(classify(message), Some(*expected), "{message}");
        }
    }

    #[test]
    fn ordinary_kernel_messages_are_not_problems() {
        for message in [
            "Linux version 6.8.0 (buildd@lcy02) (gcc 13.2)",
            "ata1: SATA link up 6.0 Gbps (SStatus 133 SControl 300)",
            "ata1: hard resetting link",
            "EXT4-fs (sda1): mounted filesystem with ordered data mode",
            "nvme nvme0: 8/0/0 default/read/poll queues",
            "Out of memory: Killed process 123 (java)",
            "usb 1-1: new high-speed USB device number 2",
            "XFS (sdb1): Mounting V5 Filesystem",
            "pcieport 0000:00:1c.0: AER: enabled with IRQ 122",
        ] {
            assert_eq!(classify(message), None, "{message}");
        }
    }

    #[test]
    fn programs_and_disks_are_extracted() {
        assert_eq!(
            crashed_program("firefox[4321]: segfault at 0 ip 00007f"),
            Some("firefox".into())
        );
        assert_eq!(
            crashed_program("Web Content[77]: segfault at 8 ip 0"),
            Some("Web Content".into())
        );
        assert_eq!(
            crashed_program("traps: foo[99] general protection fault ip:7f"),
            Some("foo".into())
        );
        assert_eq!(
            device_of("blk_update_request: I/O error, dev sda, sector 1"),
            Some("sda".into())
        );
        assert_eq!(
            device_of("Buffer I/O error on dev sdb1, logical block 0"),
            Some("sdb".into())
        );
        assert_eq!(
            device_of("EXT4-fs error (device nvme0n1p2): x"),
            Some("nvme0n1".into())
        );
        assert_eq!(
            device_of("Buffer I/O error on dev loop0, logical block 0"),
            None,
            "not a real disk"
        );
        assert_eq!(
            device_of("EXT4-fs (nvme0n1p2): Remounting filesystem read-only"),
            Some("nvme0n1".into())
        );
        assert_eq!(
            device_of("EXT4-fs (sda1): Remounting filesystem read-only"),
            Some("sda".into())
        );
        assert_eq!(
            device_of("I/O error, dev mmcblk0p1, sector 3"),
            Some("mmcblk0".into())
        );
        assert_eq!(
            device_of("I/O error, dev dm-0, sector 3"),
            None,
            "not a plain disk name"
        );
    }

    #[test]
    fn a_quiet_boot_has_nothing_to_report() {
        let s = summarize(&[k("Linux version 6.8"), k("ata1: SATA link up")]);
        let hw = hardware_finding(&s, "journal");
        let crash = crash_finding(&s, "journal");
        assert_eq!(hw.severity, Severity::Info);
        assert_eq!(crash.severity, Severity::Info);
        assert!(hw.explanation.contains("No disk, filesystem"));
        assert!(hw.explanation.contains("Kernel module"));
        assert!(hw.recommendation.is_none() && crash.recommendation.is_none());
    }

    #[test]
    fn a_read_only_filesystem_is_critical_and_starts_with_the_backup() {
        let s = summarize(&[
            k("blk_update_request: I/O error, dev sda, sector 1 op 0x0:(READ)"),
            k("EXT4-fs (sda1): Remounting filesystem read-only"),
        ]);
        let f = hardware_finding(&s, "journal");
        assert_eq!(f.severity, Severity::Critical);
        let rec = f.recommendation.unwrap();
        assert!(rec.starts_with("1. Copy what matters"));
        assert!(rec.contains("sudo smartctl -a /dev/sda"));
        assert!(rec.contains("sudo fsck -f /dev/<partition>"));
        assert!(rec.find("smartctl").unwrap() < rec.find("fsck").unwrap());
        // Most serious first in the table.
        assert!(
            f.explanation.find("read-only").unwrap()
                < f.explanation.find("Disk I/O errors").unwrap()
        );
    }

    #[test]
    fn io_errors_alone_are_an_error_with_a_scan_when_the_disk_is_unknown() {
        let s = summarize(&[k("Buffer I/O error on dev loop0, logical block 0")]);
        let f = hardware_finding(&s, "journal");
        assert_eq!(f.severity, Severity::Error);
        assert!(f.recommendation.unwrap().contains("sudo smartctl --scan"));
    }

    #[test]
    fn corrected_memory_errors_are_a_warning_and_uncorrected_critical() {
        let ce = summarize(&[k("EDAC MC0: 1 CE memory read error on DIMM#0")]);
        assert_eq!(hardware_finding(&ce, "journal").severity, Severity::Warning);
        let ue = summarize(&[k("EDAC MC0: 1 UE memory read error on DIMM#0")]);
        let f = hardware_finding(&ue, "journal");
        assert_eq!(f.severity, Severity::Critical);
        assert!(f.recommendation.unwrap().contains("memtest86+"));
    }

    #[test]
    fn corrected_pcie_errors_matter_only_in_a_flood() {
        let few = summarize(&vec![
            k(
                "pcieport 0000:00:1c.0: AER: Corrected error received: x"
            );
            10
        ]);
        assert_eq!(hardware_finding(&few, "journal").severity, Severity::Info);
        let many = summarize(&vec![
            k(
                "pcieport 0000:00:1c.0: AER: Corrected error received: x"
            );
            150
        ]);
        assert_eq!(
            hardware_finding(&many, "journal").severity,
            Severity::Warning
        );
    }

    #[test]
    fn one_crash_is_information_repeated_or_widespread_ones_a_warning() {
        let one = summarize(&[k(
            "firefox[1]: segfault at 0 ip 0 sp 0 error 4 in libxul.so[0+1]",
        )]);
        assert_eq!(crash_finding(&one, "journal").severity, Severity::Info);

        let repeated = summarize(&vec![
            k(
                "foo[1]: segfault at 0 ip 0 sp 0 error 4 in libc.so[0+1]"
            );
            3
        ]);
        let f = crash_finding(&repeated, "journal");
        assert_eq!(f.severity, Severity::Warning);
        assert!(f.recommendation.unwrap().contains("coredumpctl info foo"));

        let widespread = summarize(&[
            k("a[1]: segfault at 0 ip 0"),
            k("b[1]: segfault at 0 ip 0"),
            k("c[1]: segfault at 0 ip 0"),
        ]);
        let f = crash_finding(&widespread, "journal");
        assert_eq!(f.severity, Severity::Warning);
        assert!(f.explanation.contains("Several unrelated programs"));
        assert!(f.recommendation.unwrap().contains("memtest86+"));
    }

    #[test]
    fn kernel_oops_is_an_error_and_lockups_a_warning() {
        let oops = summarize(&[k("BUG: unable to handle page fault for address: ffff")]);
        assert_eq!(crash_finding(&oops, "journal").severity, Severity::Error);
        let lock = summarize(&[k("watchdog: BUG: soft lockup - CPU#2 stuck for 22s!")]);
        let f = crash_finding(&lock, "journal");
        assert_eq!(f.severity, Severity::Warning);
        assert!(f.recommendation.unwrap().contains("Update the kernel"));
    }

    #[test]
    fn a_program_name_with_shell_characters_stays_out_of_commands() {
        let s = summarize(&vec![k("x;reboot[1]: segfault at 0 ip 0"); 3]);
        let rec = crash_finding(&s, "journal").recommendation.unwrap();
        assert!(!rec.contains("reboot"));
        assert!(
            rec.contains("coredumpctl info\n")
                || rec.ends_with("coredumpctl info")
                || rec.contains("coredumpctl info ")
        );
    }

    #[test]
    fn examples_keep_the_first_message_and_stay_short() {
        let long = format!(
            "blk_update_request: I/O error, dev sda, sector 1 {}",
            "x".repeat(300)
        );
        let s = summarize(&[k(&long), k("Buffer I/O error on dev sdb, logical block 1")]);
        let stats = &s.kinds[&Kind::IoError];
        assert_eq!(stats.count, 2);
        assert!(stats.example.starts_with("blk_update_request"));
        assert!(stats.example.chars().count() <= 111);
        assert_eq!(stats.devices, vec!["sda", "sdb"]);
    }
}
