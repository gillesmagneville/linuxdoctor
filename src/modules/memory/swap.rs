// SPDX-License-Identifier: GPL-3.0-only

//! Swap: what vm.swappiness should be for the kind of swap this machine
//! has (MEM001), what is sitting in swap and whether it hurts (MEM002),
//! and whether swap itself is set up sensibly — present, compressed,
//! prioritised (MEM010).

use crate::models::{Category, Confidence, Finding, Severity};

use super::collect::{percent, MemoryRawData, SwapDevice, SwapKind};
use super::format::{
    group_label, kb, pct, suggested_swap_gb, swapfile_commands, sysctl_commands, top_by_anon,
    top_by_swap, Steps,
};

pub const DEFAULT_SWAPPINESS: u8 = 60;

/// Swap used above this share of its size leaves no room for the next spike.
const SWAP_NEARLY_FULL_PERCENT: f64 = 80.0;

/// Swapped-out memory below this is not worth a "bring it back" hint.
const BRING_BACK_MIN_KB: u64 = 256 * 1024;

/// A machine this small really needs swap.
const SMALL_RAM_KB: u64 = 2 * 1024 * 1024;

/// zram holding more than this share of RAM is competing with programs.
const ZRAM_RAM_SHARE_WARNING: f64 = 25.0;

/// Below this, zram is not buying much.
const POOR_COMPRESSION_RATIO: f64 = 1.5;
const POOR_COMPRESSION_MIN_KB: u64 = 256 * 1024;

const DATABASE_PROGRAMS: [&str; 9] = [
    "mysqld",
    "mariadbd",
    "postgres",
    "mongod",
    "redis-server",
    "valkey-server",
    "clickhouse-serv",
    "oracle",
    "influxd",
];

// ---------------------------------------------------------------------------
// What kind of swap does this machine have?
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SwapProfile {
    None,
    /// Only compressed RAM.
    Zram,
    /// A disk (partition or file), possibly spinning.
    Disk {
        rotational: bool,
    },
    /// zram in front of a disk.
    Mixed {
        rotational: bool,
    },
}

impl SwapProfile {
    fn of(data: &MemoryRawData) -> Self {
        if data.swap_total_kb == 0 {
            return SwapProfile::None;
        }
        let zram = data.swap_devices.iter().any(|d| d.kind == SwapKind::Zram);
        let disks: Vec<&SwapDevice> = data
            .swap_devices
            .iter()
            .filter(|d| d.kind != SwapKind::Zram)
            .collect();
        let rotational = disks.iter().any(|d| d.rotational == Some(true));
        match (zram, disks.is_empty()) {
            (true, true) => SwapProfile::Zram,
            (true, false) => SwapProfile::Mixed { rotational },
            // /proc/swaps unreadable but meminfo says there is swap:
            // assume an ordinary disk, not a spinning one.
            _ => SwapProfile::Disk { rotational },
        }
    }

    fn label(self) -> &'static str {
        match self {
            SwapProfile::None => "none",
            SwapProfile::Zram => "zram",
            SwapProfile::Disk { rotational: false } => "disk",
            SwapProfile::Disk { rotational: true } => "disk (rotational)",
            SwapProfile::Mixed { rotational: false } => "zram + disk",
            SwapProfile::Mixed { rotational: true } => "zram + disk (rotational)",
        }
    }
}

/// zram-generator setup, persistent across reboots. Text only — never run.
pub fn zram_setup_commands() -> Vec<String> {
    vec![
        "sudo apt install systemd-zram-generator     # Fedora, Arch, openSUSE: zram-generator".to_string(),
        "printf '[zram0]\\nzram-size = ram / 2\\ncompression-algorithm = zstd\\n' | sudo tee /etc/systemd/zram-generator.conf"
            .to_string(),
        "sudo systemctl daemon-reload".to_string(),
        "sudo systemctl start systemd-zram-setup@zram0.service".to_string(),
    ]
}

fn database_in_charge(data: &MemoryRawData) -> Option<String> {
    let top = top_by_anon(&data.processes, 1);
    let g = top.first()?;
    DATABASE_PROGRAMS
        .iter()
        .any(|d| g.name == *d)
        .then(|| g.name.clone())
}

// ---------------------------------------------------------------------------
// MEM001 — swappiness
// ---------------------------------------------------------------------------

/// MEM001 — always reported. What a given swappiness *means* depends on the
/// swap behind it: 60 is fine for an SSD, too low for zram (where swapping
/// is cheap) and too high for a spinning disk.
pub fn swappiness(data: &MemoryRawData) -> Finding {
    let sw = data.swappiness;
    let profile = SwapProfile::of(data);

    let mut severity = Severity::Info;
    let mut confidence = Confidence::direct_observation();
    let mut paragraphs = vec![format!(
        "vm.swappiness is {sw} (kernel default {DEFAULT_SWAPPINESS}). It decides how eagerly the \
         kernel moves idle program memory to swap instead of dropping file cache: low values \
         protect programs' memory, high values protect the file cache. The scale runs from 0 to 200."
    )];
    let mut steps = Steps::new();

    match profile {
        SwapProfile::None => paragraphs.push(
            "No swap is configured, so there is nowhere to move program memory and this \
             setting has no effect on it. See Swap configuration."
                .to_string(),
        ),
        SwapProfile::Zram | SwapProfile::Mixed { rotational: false } => {
            if sw < 100 {
                paragraphs.push(format!(
                    "Swap here is compressed RAM (zram). Moving an idle page into it costs a \
                     little CPU time, while dropping file cache costs a disk read later. With \
                     swap this cheap, the kernel documentation suggests values around 100 or \
                     more, so that idle program memory is compressed before useful file cache is \
                     thrown away. At {sw} the kernel leans towards dropping cache first."
                ));
                steps = steps.step_owned(
                    "Optional: raise it (100 is a safe start; setups tuned for zram go up to 180):",
                    sysctl_commands("vm.swappiness=100", "99-swappiness.conf"),
                );
            } else {
                paragraphs.push(format!(
                    "{sw} suits compressed swap: idle program memory is compressed rather than \
                     file cache dropped, which is the cheaper trade when swap lives in RAM."
                ));
            }
        }
        SwapProfile::Disk { rotational } | SwapProfile::Mixed { rotational } => {
            let db = database_in_charge(data);
            if rotational && sw >= 100 {
                severity = Severity::Warning;
                confidence = Confidence::strong_indication(80);
                paragraphs.push(format!(
                    "Swap is on a spinning disk and swappiness is {sw}. Values above 100 are \
                     meant for compressed RAM swap; on a hard disk they push program memory onto \
                     the slowest storage in the machine and make everything crawl whenever memory \
                     fills up."
                ));
                steps = steps.step_owned(
                    "Lower it so programs stay in RAM and only truly idle memory is swapped out:",
                    sysctl_commands("vm.swappiness=10", "99-swappiness.conf"),
                );
            } else if rotational && sw > DEFAULT_SWAPPINESS {
                paragraphs.push(format!(
                    "Swap is on a spinning disk, where every page swapped back in costs a seek. \
                     At {sw} the kernel swaps eagerly; a low value keeps programs responsive."
                ));
                steps = steps.step_owned(
                    "Lower it:",
                    sysctl_commands("vm.swappiness=10", "99-swappiness.conf"),
                );
            } else if sw >= 100 {
                paragraphs.push(format!(
                    "Values above 100 are meant for compressed RAM swap. With swap on a disk, {sw} \
                     makes the kernel push program memory out in preference to dropping cache, \
                     which adds disk traffic and latency."
                ));
                steps = steps.step_owned(
                    "Return it to the default:",
                    sysctl_commands("vm.swappiness=60", "99-swappiness.conf"),
                );
            } else if sw == 0 {
                paragraphs.push(
                    "0 tells the kernel not to swap until memory is almost exhausted (it only \
                     swaps to avoid the OOM killer). Programs stay fast, but swap no longer acts \
                     as an early cushion. 1 is the lowest value that still lets idle pages move \
                     out under moderate pressure."
                        .to_string(),
                );
                steps = steps.step_owned(
                    "Optional: use 1 so swap keeps working as a safety net:",
                    sysctl_commands("vm.swappiness=1", "99-swappiness.conf"),
                );
            } else if sw <= 10 {
                paragraphs.push(format!(
                    "{sw} is low: the kernel keeps program memory in RAM and drops file cache \
                     first, swapping only under real pressure. That favours responsiveness on \
                     desktops and latency-sensitive servers; the price is that file cache shrinks \
                     before idle programs are swapped out."
                ));
            } else if sw < DEFAULT_SWAPPINESS {
                paragraphs.push(format!(
                    "Lower than the kernel default of {DEFAULT_SWAPPINESS}. The kernel prefers keeping \
                     data in RAM over swapping it out, which usually favours responsiveness on \
                     systems with plenty of memory."
                ));
            } else if sw == DEFAULT_SWAPPINESS {
                paragraphs.push(
                    "This is the default kernel value. For a desktop with large amounts of RAM, a \
                     lower value is often preferred. No action required unless swap activity is \
                     high."
                        .to_string(),
                );
            } else {
                paragraphs.push(format!(
                    "Higher than the kernel default of {DEFAULT_SWAPPINESS}. The kernel swaps out \
                     memory more eagerly. Reasonable on systems tuned for throughput over \
                     latency; worth a second look otherwise."
                ));
            }
            if let (Some(db), true) = (db, sw > 10 && sw < 100) {
                paragraphs.push(format!(
                    "{db} is the biggest memory user. Database servers are usually run with a \
                     low swappiness (1 to 10) so that their buffer pool is never swapped out in \
                     favour of file cache they manage themselves."
                ));
                steps = steps.step_owned(
                    "Optional, for a database host: keep its memory in RAM:",
                    sysctl_commands("vm.swappiness=10", "99-swappiness.conf"),
                );
            }
        }
    }

    let mut builder = Finding::builder(
        "MEM001",
        "Kernel Swappiness Setting",
        Category::Memory,
        severity,
        confidence,
    )
    .evidence("vm.swappiness", sw.to_string())
    .evidence("kernel_default", DEFAULT_SWAPPINESS.to_string())
    .evidence("swap_type", profile.label());
    if let Some(v) = data.vm.page_cluster {
        builder = builder.evidence("vm.page-cluster", v.to_string());
    }
    builder = builder.explanation(paragraphs.join("\n\n"));
    if !steps.is_empty() {
        builder = builder.recommendation(steps.build());
    }
    builder.build()
}

// ---------------------------------------------------------------------------
// MEM002 — swap activity
// ---------------------------------------------------------------------------

/// MEM002 — only reported when something is in swap. Severity scales with
/// how little RAM remains alongside it, and with how full swap is.
/// Cross-references the configured swappiness: swapping at a low value is
/// a stronger signal than the same swapping at the default.
pub fn swap_activity(data: &MemoryRawData) -> Option<Finding> {
    if data.swap_total_kb == 0 {
        return None;
    }
    let used = data.swap_used_kb();
    if used == 0 {
        return None;
    }
    let used_pct = percent(used, data.swap_total_kb);
    let avail_pct = if data.mem_total_kb > 0 {
        data.available_percent()
    } else {
        100.0
    };
    let nearly_full = used_pct >= SWAP_NEARLY_FULL_PERCENT;

    let (mut severity, mut confidence, lead) = if avail_pct < 3.0 {
        (
            Severity::Error,
            Confidence::correlated(95),
            "The system is actively swapping while almost no RAM remains free. This commonly \
             causes visible slowdowns. Investigation is recommended.",
        )
    } else if avail_pct < 10.0 {
        (
            Severity::Warning,
            Confidence::strong_indication(85),
            "The system is actively swapping while relatively little RAM remains free. This \
             commonly indicates memory pressure, though it is not necessarily a problem on its \
             own — worth investigating if performance feels degraded.",
        )
    } else {
        (
            Severity::Info,
            Confidence::weak_indication(70),
            "Swap is in use, but plenty of RAM is still free. This is not necessarily a problem \
             — some swap usage is normal even on systems with ample memory.",
        )
    };
    if nearly_full && severity < Severity::Warning {
        severity = Severity::Warning;
        confidence = Confidence::strong_indication(80);
    }

    let mut paragraphs = vec![lead.to_string()];
    paragraphs.push(format!(
        "{} of {} of swap is in use ({}).",
        kb(used),
        kb(data.swap_total_kb),
        pct(used_pct)
    ));
    if nearly_full {
        paragraphs.push(
            "Swap is nearly full: the next memory spike has nowhere to go, and the kernel will \
             have to start killing processes."
                .to_string(),
        );
    }
    if let Some(p) = &data.pressure {
        paragraphs.push(if p.some.avg60 >= 1.0 {
            format!(
                "Programs spent {} of the last minute stalled waiting for memory, so the swapping \
                 is costing real time.",
                pct(p.some.avg60)
            )
        } else {
            "Programs have not been stalled waiting for memory in the last minute, so what is in \
             swap is probably idle memory that has been parked there."
                .to_string()
        });
    }

    if data.swappiness <= 10 {
        paragraphs.push(format!(
            "Notably, vm.swappiness is set low ({}), meaning the kernel normally avoids swapping \
             unless under real pressure — this activity is a stronger signal than the same swap \
             usage would be at the default swappiness ({DEFAULT_SWAPPINESS}).",
            data.swappiness,
        ));
    }

    let swapped = top_by_swap(&data.processes, 3);
    let mut builder = Finding::builder(
        "MEM002",
        "Swap Activity",
        Category::Memory,
        severity,
        confidence,
    )
    .evidence("swap_used_kb", used.to_string())
    .evidence("swap_total_kb", data.swap_total_kb.to_string())
    .evidence("swap_used_percent", format!("{used_pct:.1}"))
    .evidence("mem_available_kb", data.mem_available_kb.to_string())
    .evidence("mem_available_pct", format!("{avail_pct:.1}"))
    .evidence("vm.swappiness", data.swappiness.to_string());
    if let Some(c) = data.vmstat {
        let page_kb = data.page_size_kb_or_default();
        builder = builder
            .evidence(
                "swapped_out_since_boot_kb",
                (c.pswpout * page_kb).to_string(),
            )
            .evidence("swapped_in_since_boot_kb", (c.pswpin * page_kb).to_string());
    }
    if !swapped.is_empty() {
        let mut list = String::from("Programs with the most memory in swap:");
        for (i, g) in swapped.iter().enumerate() {
            let who = if g.count == 1 {
                format!("{} (PID {})", g.name, g.largest_pid)
            } else {
                group_label(g)
            };
            list.push_str(&format!("\n  {}. {} — {}", i + 1, who, kb(g.swap_kb)));
            builder = builder.evidence(
                format!("swapped_program_{}", i + 1),
                format!("{who}: {}", kb(g.swap_kb)),
            );
        }
        paragraphs.push(list);
    }
    builder = builder.explanation(paragraphs.join("\n\n"));

    if severity > Severity::Info {
        builder = builder.recommendation(activity_steps(data, &swapped, nearly_full).build());
    } else if used >= BRING_BACK_MIN_KB && data.mem_available_kb >= used.saturating_mul(2) {
        builder = builder.recommendation(
            Steps::new()
                .step(
                    format!(
                        "Optional: if programs feel sluggish when they wake up, bring the parked \
                         memory back into RAM. This is safe now because {} of RAM is available, \
                         more than twice what is in swap:",
                        kb(data.mem_available_kb)
                    ),
                    &["sudo swapoff -a && sudo swapon -a"],
                )
                .build(),
        );
    }
    Some(builder.build())
}

fn activity_steps(
    data: &MemoryRawData,
    swapped: &[super::format::ProcessGroup],
    nearly_full: bool,
) -> Steps {
    let who = swapped
        .first()
        .map(|g| format!(" ({} has the most)", group_label(g)))
        .unwrap_or_default();
    let mut steps = Steps::new()
        .step(
            format!("See which programs are in swap{who}:"),
            &["grep -H VmSwap /proc/[0-9]*/status 2>/dev/null | sort -k2 -n -r | head"],
        )
        .step(
            "Check whether the machine is swapping right now: non-zero 'si' (read back from \
             swap) and 'so' (written to swap) columns for several seconds in a row mean it is:",
            &["vmstat 1 5"],
        );

    let top = top_by_anon(&data.processes, 1);
    steps = steps.step(
        match top.first() {
            Some(g) => format!(
                "Reduce the demand for memory: {} holds the most ({}). The Used memory page \
                 shows the full list and what to do about the biggest consumer.",
                group_label(g),
                kb(g.anon_kb)
            ),
            None => {
                "Reduce the demand for memory: the Used memory page shows what to do about the \
                     biggest consumer."
                    .to_string()
            }
        },
        &[],
    );

    if nearly_full {
        let size = suggested_swap_gb(data.mem_total_kb);
        steps = steps.step_owned(
            format!(
                "Give the kernel more room. A {size} GB swap file is a reasonable addition (it \
                 is used after existing swap, at a lower priority):"
            ),
            swapfile_commands(size),
        );
    }

    let profile = SwapProfile::of(data);
    if matches!(profile, SwapProfile::Disk { .. }) {
        steps = steps.step(
            "Swap on a disk is slow. Compressed RAM swap (zram) is far faster and spares the \
             disk; the Swap configuration finding has the commands.",
            &[],
        );
    }
    steps
}

// ---------------------------------------------------------------------------
// MEM010 — swap configuration
// ---------------------------------------------------------------------------

struct Issue {
    severity: Severity,
    confidence: Confidence,
    text: String,
    steps: Vec<(String, Vec<String>)>,
}

fn describe_device(d: &SwapDevice) -> String {
    let kind = match d.kind {
        SwapKind::Partition => "partition",
        SwapKind::File => "file",
        SwapKind::Zram => "zram",
        SwapKind::Other => "other",
    };
    let mut s = format!(
        "{} — {}, {}, {} used, priority {}",
        d.path,
        kind,
        kb(d.size_kb),
        kb(d.used_kb),
        d.priority
    );
    if d.rotational == Some(true) {
        s.push_str(", spinning disk");
    }
    if let Some(z) = &d.zram {
        if z.compressed_kb > 0 && z.original_kb > 0 {
            s.push_str(&format!(
                " ({:.1}:1 compression{})",
                z.original_kb as f64 / z.compressed_kb as f64,
                z.algorithm
                    .as_deref()
                    .map(|a| format!(" with {a}"))
                    .unwrap_or_default()
            ));
        } else if let Some(a) = &z.algorithm {
            s.push_str(&format!(" ({a})"));
        }
    }
    s
}

fn configuration_issues(data: &MemoryRawData) -> Vec<Issue> {
    let mut issues = Vec::new();
    let profile = SwapProfile::of(data);
    let avail_pct = data.available_percent();

    // --- no swap -------------------------------------------------------
    if profile == SwapProfile::None {
        let urgent = (data.mem_total_kb > 0 && avail_pct < 10.0)
            || (data.mem_total_kb > 0 && data.mem_total_kb <= SMALL_RAM_KB);
        let (severity, confidence) = if urgent {
            (Severity::Warning, Confidence::strong_indication(78))
        } else {
            (Severity::Info, Confidence::direct_observation())
        };
        let size = suggested_swap_gb(data.mem_total_kb);
        issues.push(Issue {
            severity,
            confidence,
            text: "No swap is configured. Without it the kernel can only reclaim file cache; once \
                   that is gone, the only option left is the OOM killer. Even a small swap lets \
                   idle program memory move out of the way and gives a memory spike somewhere to \
                   go. (Exceptions: Kubernetes nodes, where the kubelet expects swap off by \
                   default, and appliances that deliberately prefer an OOM kill to slowness.)"
                .to_string(),
            steps: vec![
                (
                    "Preferred: compressed RAM swap (zram). It needs no disk space, causes no \
                     disk wear and is much faster than swap on a disk. This sets it to half of \
                     RAM, kept after reboot:"
                        .to_string(),
                    zram_setup_commands(),
                ),
                (
                    format!(
                        "Or a swap file of {size} GB on disk (ext4 or xfs; on Btrfs use \
                         'btrfs filesystem mkswapfile' instead of fallocate):"
                    ),
                    swapfile_commands(size),
                ),
            ],
        });
        return issues;
    }

    let zram_devs: Vec<&SwapDevice> = data
        .swap_devices
        .iter()
        .filter(|d| d.kind == SwapKind::Zram)
        .collect();
    let disk_devs: Vec<&SwapDevice> = data
        .swap_devices
        .iter()
        .filter(|d| d.kind != SwapKind::Zram)
        .collect();

    // --- zram in front of a disk with the wrong priority ----------------
    if let Some(best_zram) = zram_devs.iter().map(|d| d.priority).max() {
        if let Some(disk) = disk_devs.iter().find(|d| d.priority >= best_zram) {
            issues.push(Issue {
                severity: Severity::Warning,
                confidence: Confidence::strong_indication(85),
                text: format!(
                    "{} has priority {}, not lower than zram's {}. The kernel fills the \
                     highest-priority swap first, so slow disk swap is used before the fast \
                     compressed swap in RAM.",
                    disk.path, disk.priority, best_zram
                ),
                steps: vec![(
                    "Give zram the higher priority (100 is what zram-generator uses). Re-enable \
                     the zram device with it, and list the result:"
                        .to_string(),
                    vec![
                        format!("sudo swapoff {}", zram_devs[0].path),
                        format!("sudo swapon --priority 100 {}", zram_devs[0].path),
                        "swapon --show".to_string(),
                    ],
                )],
            });
        }
    }

    // --- zram health ---------------------------------------------------
    for z in &zram_devs {
        let Some(stats) = &z.zram else { continue };
        if stats.memory_used_kb > 0
            && percent(stats.memory_used_kb, data.mem_total_kb) >= ZRAM_RAM_SHARE_WARNING
        {
            issues.push(Issue {
                severity: Severity::Warning,
                confidence: Confidence::strong_indication(82),
                text: format!(
                    "{} occupies {} of RAM ({}) to hold {} of swapped data. Compressed swap \
                     competes with programs for the very memory it is meant to relieve.",
                    z.path,
                    kb(stats.memory_used_kb),
                    pct(percent(stats.memory_used_kb, data.mem_total_kb)),
                    kb(stats.original_kb),
                ),
                steps: vec![
                    (
                        "Find out why so much is swapped (see Swap Activity and Used memory), \
                         then reduce the demand for memory."
                            .to_string(),
                        vec![],
                    ),
                    (
                        "Cap the zram size so it cannot grow past a safe share of RAM \
                         ('zram-size = min(ram / 2, 4096)' in /etc/systemd/zram-generator.conf, \
                         in MB), then restart the unit:"
                            .to_string(),
                        vec![
                            "sudo systemctl daemon-reload".to_string(),
                            "sudo systemctl restart systemd-zram-setup@zram0.service".to_string(),
                        ],
                    ),
                ],
            });
        }
        if stats.compressed_kb > 0 && stats.original_kb >= POOR_COMPRESSION_MIN_KB {
            let ratio = stats.original_kb as f64 / stats.compressed_kb as f64;
            if ratio < POOR_COMPRESSION_RATIO {
                issues.push(Issue {
                    severity: Severity::Info,
                    confidence: Confidence::direct_observation(),
                    text: format!(
                        "{} compresses only {:.1}:1: the data in it (already-compressed media, \
                         encrypted or random data) barely shrinks, so zram saves little RAM \
                         here.",
                        z.path, ratio
                    ),
                    steps: vec![],
                });
            }
        }
        if matches!(stats.algorithm.as_deref(), Some("lzo") | Some("lzo-rle")) {
            issues.push(Issue {
                severity: Severity::Info,
                confidence: Confidence::direct_observation(),
                text: format!(
                    "{} uses {}. zstd compresses noticeably better (more data fits in the same \
                     RAM) at a small CPU cost; lz4 is the fastest choice.",
                    z.path,
                    stats.algorithm.as_deref().unwrap_or("lzo")
                ),
                steps: vec![(
                    "Optional: switch to zstd in /etc/systemd/zram-generator.conf, then restart \
                     the unit (whatever is in zram is moved back to RAM first, so only do this \
                     with free memory to spare):"
                        .to_string(),
                    vec![
                        "printf '[zram0]\\nzram-size = ram / 2\\ncompression-algorithm = zstd\\n' | sudo tee /etc/systemd/zram-generator.conf".to_string(),
                        "sudo systemctl daemon-reload".to_string(),
                        "sudo systemctl restart systemd-zram-setup@zram0.service".to_string(),
                    ],
                )],
            });
        }
        if z.size_kb > data.mem_total_kb && data.mem_total_kb > 0 {
            issues.push(Issue {
                severity: Severity::Info,
                confidence: Confidence::direct_observation(),
                text: format!(
                    "{} is larger than RAM ({} vs {}). It only uses RAM for what it actually \
                     holds, but a full device of poorly-compressing data could consume most of \
                     memory. Half of RAM is the usual size.",
                    z.path,
                    kb(z.size_kb),
                    kb(data.mem_total_kb)
                ),
                steps: vec![],
            });
        }
    }

    // --- zswap on top of zram -----------------------------------------
    if data.vm.zswap_enabled == Some(true) && !zram_devs.is_empty() {
        issues.push(Issue {
            severity: Severity::Info,
            confidence: Confidence::direct_observation(),
            text: "Both zswap (a compressed cache in front of swap) and zram swap are active. \
                   Pages are compressed twice for no benefit; use one or the other."
                .to_string(),
            steps: vec![(
                "Turn zswap off now, and at every boot by adding zswap.enabled=0 to the kernel \
                 command line (GRUB_CMDLINE_LINUX in /etc/default/grub, then regenerate the \
                 GRUB configuration):"
                    .to_string(),
                vec!["echo 0 | sudo tee /sys/module/zswap/parameters/enabled".to_string()],
            )],
        });
    }

    // --- swap on a spinning disk ---------------------------------------
    let rotational: Vec<&&SwapDevice> = disk_devs
        .iter()
        .filter(|d| d.rotational == Some(true))
        .collect();
    if !rotational.is_empty() {
        let names: Vec<&str> = rotational.iter().map(|d| d.path.as_str()).collect();
        issues.push(Issue {
            severity: Severity::Info,
            confidence: Confidence::direct_observation(),
            text: format!(
                "{} {} on a spinning disk. Any real swapping will be very slow there; compressed \
                 RAM swap in front of it absorbs most of the traffic.",
                names.join(", "),
                if names.len() == 1 { "is" } else { "are" }
            ),
            steps: if zram_devs.is_empty() {
                vec![(
                    "Add zram in front of it (priority 100, above the disk):".to_string(),
                    zram_setup_commands(),
                )]
            } else {
                vec![]
            },
        });
    }

    // --- read-ahead for swap that has no seek cost ----------------------
    let cheap_swap = !zram_devs.is_empty() || data.vm.zswap_enabled == Some(true);
    if cheap_swap {
        if let Some(pc) = data.vm.page_cluster {
            if pc > 0 {
                issues.push(Issue {
                    severity: Severity::Info,
                    confidence: Confidence::strong_indication(80),
                    text: format!(
                        "vm.page-cluster is {pc}, so each swap-in also reads {} neighbouring \
                         pages. That read-ahead pays off on spinning disks only; with \
                         compressed swap it just decompresses pages nobody asked for.",
                        (1u64 << pc.min(16)) - 1
                    ),
                    steps: vec![(
                        "Disable the read-ahead:".to_string(),
                        sysctl_commands("vm.page-cluster=0", "99-page-cluster.conf"),
                    )],
                });
            }
        }
    }

    issues
}

/// MEM010 — always reported. Lists the swap devices and what is wrong, if
/// anything, with how swap is set up: none at all, wrong priority, zram
/// that eats RAM or compresses badly, redundant zswap, swap on a spinning
/// disk, pointless read-ahead.
pub fn swap_config(data: &MemoryRawData) -> Finding {
    let profile = SwapProfile::of(data);
    let issues = configuration_issues(data);

    let (severity, confidence) = issues
        .iter()
        .map(|i| (i.severity, i.confidence.clone()))
        .max_by_key(|(s, c)| (*s, c.percent))
        .unwrap_or((Severity::Info, Confidence::direct_observation()));

    let mut paragraphs: Vec<String> = Vec::new();
    if profile == SwapProfile::None {
        paragraphs.push("Swap: none configured.".to_string());
    } else if data.swap_devices.is_empty() {
        paragraphs.push(format!(
            "Swap: {} in total, {} used. The individual swap devices could not be listed.",
            kb(data.swap_total_kb),
            kb(data.swap_used_kb())
        ));
    } else {
        let mut list = format!(
            "Swap: {} in total, {} used, on {} device{}:",
            kb(data.swap_total_kb),
            kb(data.swap_used_kb()),
            data.swap_devices.len(),
            if data.swap_devices.len() == 1 {
                ""
            } else {
                "s"
            }
        );
        for d in &data.swap_devices {
            list.push_str(&format!("\n  - {}", describe_device(d)));
        }
        paragraphs.push(list);
    }
    if data.vm.zswap_enabled == Some(true) {
        paragraphs.push(format!(
            "zswap is enabled: swapped pages are compressed in a RAM pool first{}.",
            if data.detail.zswap_kb > 0 {
                format!(
                    " (currently {} of RAM holding {} of data)",
                    kb(data.detail.zswap_kb),
                    kb(data.detail.zswapped_kb)
                )
            } else {
                String::new()
            }
        ));
    }
    if issues.is_empty() {
        paragraphs.push("Nothing to change: this is a sound swap setup.".to_string());
    }
    for issue in &issues {
        paragraphs.push(issue.text.clone());
    }

    let mut builder = Finding::builder(
        "MEM010",
        "Swap Configuration",
        Category::Memory,
        severity,
        confidence,
    )
    .evidence("swap_type", profile.label())
    .evidence("swap_total_kb", data.swap_total_kb.to_string())
    .evidence("swap_devices", data.swap_devices.len().to_string());
    for (i, d) in data.swap_devices.iter().enumerate() {
        builder = builder.evidence(format!("swap_device_{}", i + 1), describe_device(d));
    }
    if let Some(on) = data.vm.zswap_enabled {
        builder = builder.evidence("zswap_enabled", on.to_string());
    }
    builder = builder.explanation(paragraphs.join("\n\n"));

    let mut steps = Steps::new();
    for issue in &issues {
        for (text, commands) in &issue.steps {
            steps = steps.step_owned(text.clone(), commands.clone());
        }
    }
    if !steps.is_empty() {
        builder = builder.recommendation(steps.build());
    }
    builder.build()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::modules::memory::collect::{
        MemoryPressure, PsiLine, VmTunables, VmstatCounters, ZramStats,
    };
    use crate::modules::memory::test_support::{evidence, healthy, proc};

    fn disk(
        path: &str,
        kind: SwapKind,
        size_mb: u64,
        used_mb: u64,
        prio: i64,
        rotational: Option<bool>,
    ) -> SwapDevice {
        SwapDevice {
            path: path.into(),
            kind,
            size_kb: size_mb * 1024,
            used_kb: used_mb * 1024,
            priority: prio,
            zram: None,
            rotational,
        }
    }

    fn zram(
        size_mb: u64,
        used_mb: u64,
        prio: i64,
        orig_mb: u64,
        comp_mb: u64,
        algo: &str,
    ) -> SwapDevice {
        SwapDevice {
            path: "/dev/zram0".into(),
            kind: SwapKind::Zram,
            size_kb: size_mb * 1024,
            used_kb: used_mb * 1024,
            priority: prio,
            zram: Some(ZramStats {
                original_kb: orig_mb * 1024,
                compressed_kb: comp_mb * 1024,
                memory_used_kb: comp_mb * 1024,
                algorithm: Some(algo.into()),
            }),
            rotational: None,
        }
    }

    fn with_zram_only(mut d: MemoryRawData) -> MemoryRawData {
        d.swap_total_kb = 8 * 1024 * 1024;
        d.swap_free_kb = d.swap_total_kb;
        d.swap_devices = vec![zram(8192, 0, 100, 0, 0, "zstd")];
        d
    }

    fn with_hdd_swap(mut d: MemoryRawData) -> MemoryRawData {
        d.swap_devices = vec![disk(
            "/dev/sda2",
            SwapKind::Partition,
            4096,
            0,
            -2,
            Some(true),
        )];
        d
    }

    fn no_swap(mut d: MemoryRawData) -> MemoryRawData {
        d.swap_total_kb = 0;
        d.swap_free_kb = 0;
        d.swap_devices.clear();
        d
    }

    // ---- MEM001 --------------------------------------------------------

    #[test]
    fn default_swappiness_on_ssd_swap_needs_nothing() {
        let f = swappiness(&healthy());
        assert_eq!(f.id, "MEM001");
        assert_eq!(f.severity, Severity::Info);
        assert!(f.recommendation.is_none());
        assert!(f.explanation.contains("default kernel value"));
        assert_eq!(evidence(&f, "swap_type"), Some("disk"));
    }

    #[test]
    fn no_swap_means_swappiness_has_no_effect() {
        let f = swappiness(&no_swap(healthy()));
        assert!(f.explanation.contains("no effect"));
        assert!(f.recommendation.is_none());
        assert_eq!(evidence(&f, "swap_type"), Some("none"));
    }

    #[test]
    fn zram_with_default_swappiness_suggests_raising_it() {
        let f = swappiness(&with_zram_only(healthy()));
        assert_eq!(f.severity, Severity::Info);
        assert!(f.explanation.contains("compressed RAM"));
        let rec = f.recommendation.unwrap();
        assert!(rec.contains("sudo sysctl vm.swappiness=100"));
        assert!(
            rec.contains("echo 'vm.swappiness = 100' | sudo tee /etc/sysctl.d/99-swappiness.conf")
        );
    }

    #[test]
    fn zram_with_high_swappiness_is_fine() {
        let mut d = with_zram_only(healthy());
        d.swappiness = 150;
        let f = swappiness(&d);
        assert!(f.recommendation.is_none());
        assert!(f.explanation.contains("suits compressed swap"));
    }

    #[test]
    fn high_swappiness_on_a_spinning_disk_warns() {
        let mut d = with_hdd_swap(healthy());
        d.swappiness = 150;
        let f = swappiness(&d);
        assert_eq!(f.severity, Severity::Warning);
        assert!(f.recommendation.unwrap().contains("vm.swappiness=10"));
    }

    #[test]
    fn moderately_high_swappiness_on_hdd_is_info_with_a_fix() {
        let mut d = with_hdd_swap(healthy());
        d.swappiness = 80;
        let f = swappiness(&d);
        assert_eq!(f.severity, Severity::Info);
        assert!(f.recommendation.is_some());
    }

    #[test]
    fn over_100_on_an_ssd_is_explained_and_reverted_to_default() {
        let mut d = healthy();
        d.swappiness = 150;
        let f = swappiness(&d);
        assert_eq!(f.severity, Severity::Info);
        assert!(f.explanation.contains("meant for compressed RAM swap"));
        assert!(f.recommendation.unwrap().contains("vm.swappiness=60"));
    }

    #[test]
    fn swappiness_zero_gets_the_semantics_explained() {
        let mut d = healthy();
        d.swappiness = 0;
        let f = swappiness(&d);
        assert!(f.explanation.contains("almost exhausted"));
        assert!(f.recommendation.unwrap().contains("vm.swappiness=1"));
    }

    #[test]
    fn low_and_high_values_keep_their_historic_wording() {
        let mut d = healthy();
        d.swappiness = 30;
        assert!(swappiness(&d)
            .explanation
            .contains("Lower than the kernel default"));
        d.swappiness = 80;
        assert!(swappiness(&d)
            .explanation
            .contains("Higher than the kernel default"));
        d.swappiness = 5;
        assert!(swappiness(&d).explanation.contains("is low"));
    }

    #[test]
    fn database_host_is_told_to_keep_swappiness_low() {
        let mut d = healthy();
        d.processes = vec![proc(1, "mysqld", 4_000_000), proc(2, "sshd", 1000)];
        let f = swappiness(&d);
        assert!(f.explanation.contains("mysqld is the biggest memory user"));
        assert!(f.recommendation.unwrap().contains("database host"));
    }

    #[test]
    fn database_advice_not_given_when_already_low_or_not_a_database() {
        let mut d = healthy();
        d.swappiness = 10;
        d.processes = vec![proc(1, "mysqld", 4_000_000)];
        assert!(swappiness(&d).recommendation.is_none());
        let mut d = healthy();
        d.processes = vec![proc(1, "firefox", 4_000_000)];
        assert!(swappiness(&d).recommendation.is_none());
    }

    #[test]
    fn page_cluster_is_exposed_as_evidence() {
        let mut d = healthy();
        d.vm.page_cluster = Some(3);
        assert_eq!(evidence(&swappiness(&d), "vm.page-cluster"), Some("3"));
    }

    // ---- MEM002 --------------------------------------------------------

    fn swapping(mut d: MemoryRawData) -> MemoryRawData {
        d.swap_free_kb = d.swap_total_kb - 100_000;
        d
    }

    #[test]
    fn no_activity_finding_without_swap_or_when_unused() {
        assert!(swap_activity(&no_swap(healthy())).is_none());
        assert!(swap_activity(&healthy()).is_none());
    }

    #[test]
    fn activity_severity_follows_available_memory() {
        let mut d = swapping(healthy());
        assert_eq!(swap_activity(&d).unwrap().severity, Severity::Info);
        d.mem_available_kb = 1_000_000;
        assert_eq!(swap_activity(&d).unwrap().severity, Severity::Warning);
        d.mem_available_kb = 300_000;
        assert_eq!(swap_activity(&d).unwrap().severity, Severity::Error);
    }

    #[test]
    fn nearly_full_swap_warns_even_when_ram_is_plentiful() {
        let mut d = healthy();
        d.swap_free_kb = 600_000; // 85% used
        let f = swap_activity(&d).unwrap();
        assert_eq!(f.severity, Severity::Warning);
        assert!(f.explanation.contains("nearly full"));
        let rec = f.recommendation.unwrap();
        assert!(rec.contains("mkswap"), "more swap is offered: {rec}");
    }

    #[test]
    fn low_swappiness_note_only_when_low() {
        let mut d = swapping(healthy());
        d.swappiness = 1;
        assert!(swap_activity(&d)
            .unwrap()
            .explanation
            .contains("stronger signal"));
        d.swappiness = 60;
        assert!(!swap_activity(&d)
            .unwrap()
            .explanation
            .contains("stronger signal"));
    }

    #[test]
    fn swapped_programs_are_named() {
        let mut d = swapping(healthy());
        d.mem_available_kb = 1_000_000;
        let mut p = proc(321, "mysqld", 100);
        p.swap_kb = 900_000;
        let mut q = proc(1, "idle", 100);
        q.swap_kb = 0;
        d.processes = vec![p, q];
        let f = swap_activity(&d).unwrap();
        assert_eq!(
            evidence(&f, "swapped_program_1"),
            Some("mysqld (PID 321): 879 MB")
        );
        assert!(
            evidence(&f, "swapped_program_2").is_none(),
            "nothing swapped, not listed"
        );
        assert!(f.recommendation.unwrap().contains("mysqld has the most"));
    }

    #[test]
    fn pressure_tells_idle_swap_from_painful_swap() {
        let mut d = swapping(healthy());
        d.pressure = Some(MemoryPressure {
            some: PsiLine {
                avg10: 0.0,
                avg60: 0.0,
                avg300: 0.0,
                total_us: 0,
            },
            full: None,
        });
        assert!(swap_activity(&d).unwrap().explanation.contains("parked"));
        d.pressure = Some(MemoryPressure {
            some: PsiLine {
                avg10: 20.0,
                avg60: 18.5,
                avg300: 5.0,
                total_us: 1,
            },
            full: None,
        });
        let text = swap_activity(&d).unwrap().explanation;
        assert!(text.contains("18.5% of the last minute"), "{text}");
    }

    #[test]
    fn swap_traffic_since_boot_is_converted_with_the_page_size() {
        let mut d = swapping(healthy());
        d.page_size_kb = 4;
        d.vmstat = Some(VmstatCounters {
            pswpin: 1000,
            pswpout: 2500,
            ..Default::default()
        });
        let f = swap_activity(&d).unwrap();
        assert_eq!(evidence(&f, "swapped_in_since_boot_kb"), Some("4000"));
        assert_eq!(evidence(&f, "swapped_out_since_boot_kb"), Some("10000"));
    }

    #[test]
    fn idle_swap_with_lots_of_ram_offers_the_safe_bring_back_hint() {
        let mut d = healthy();
        d.swap_free_kb = d.swap_total_kb - 1_000_000; // 1 GB parked, 9 GB available
        let f = swap_activity(&d).unwrap();
        assert_eq!(f.severity, Severity::Info);
        let rec = f.recommendation.unwrap();
        assert!(rec.contains("swapoff -a && sudo swapon -a"));
        assert!(rec.contains("more than twice"));
    }

    #[test]
    fn bring_back_hint_is_withheld_when_ram_could_not_hold_it() {
        let mut d = healthy();
        d.swap_free_kb = d.swap_total_kb - 3_000_000;
        d.mem_available_kb = 5_000_000; // < 2 x 3 GB, still above 10% of RAM
        let f = swap_activity(&d).unwrap();
        assert!(f.recommendation.is_none());
        d = healthy();
        d.swap_free_kb = d.swap_total_kb - 100_000; // tiny amount, pointless
        assert!(swap_activity(&d).unwrap().recommendation.is_none());
    }

    #[test]
    fn disk_swap_under_pressure_points_to_zram() {
        let mut d = swapping(healthy());
        d.mem_available_kb = 1_000_000;
        d.swap_devices = vec![disk("/swapfile", SwapKind::File, 4096, 100, -2, None)];
        assert!(swap_activity(&d)
            .unwrap()
            .recommendation
            .unwrap()
            .contains("zram"));
        d.swap_devices = vec![zram(4096, 100, 100, 100, 30, "zstd")];
        assert!(!swap_activity(&d)
            .unwrap()
            .recommendation
            .unwrap()
            .contains("Swap on a disk is slow"));
    }

    // ---- MEM010 --------------------------------------------------------

    #[test]
    fn sound_disk_swap_has_nothing_to_change() {
        let mut d = healthy();
        d.swap_devices = vec![disk("/swapfile", SwapKind::File, 4096, 0, -2, None)];
        let f = swap_config(&d);
        assert_eq!(f.id, "MEM010");
        assert_eq!(f.severity, Severity::Info);
        assert!(f.recommendation.is_none());
        assert!(f.explanation.contains("sound swap setup"));
        assert!(f.explanation.contains("/swapfile — file"));
    }

    #[test]
    fn no_swap_on_a_comfortable_machine_is_info_with_both_remedies() {
        let f = swap_config(&no_swap(healthy()));
        assert_eq!(f.severity, Severity::Info);
        let rec = f.recommendation.unwrap();
        assert!(rec.contains("systemd-zram-generator"));
        assert!(rec.contains("zram-size = ram / 2"));
        assert!(rec.contains("fallocate -l 7G /swapfile"));
        assert!(rec.contains("btrfs filesystem mkswapfile"));
    }

    #[test]
    fn no_swap_with_little_memory_or_a_tiny_machine_warns() {
        let mut d = no_swap(healthy());
        d.mem_available_kb = 1_200_000; // 7.5%
        assert_eq!(swap_config(&d).severity, Severity::Warning);
        let mut d = no_swap(healthy());
        d.mem_total_kb = 1_500_000;
        d.mem_available_kb = 1_000_000;
        assert_eq!(swap_config(&d).severity, Severity::Warning);
    }

    #[test]
    fn disk_swap_outranking_zram_is_a_warning_with_the_fix() {
        let mut d = healthy();
        d.swap_devices = vec![
            zram(4096, 0, 50, 0, 0, "zstd"),
            disk("/swapfile", SwapKind::File, 4096, 0, 100, None),
        ];
        let f = swap_config(&d);
        assert_eq!(f.severity, Severity::Warning);
        assert!(f.explanation.contains("/swapfile has priority 100"));
        let rec = f.recommendation.unwrap();
        assert!(rec.contains("sudo swapoff /dev/zram0"));
        assert!(rec.contains("sudo swapon --priority 100 /dev/zram0"));
    }

    #[test]
    fn zram_ahead_of_disk_is_correct() {
        let mut d = healthy();
        d.swap_devices = vec![
            zram(4096, 0, 100, 0, 0, "zstd"),
            disk("/swapfile", SwapKind::File, 4096, 0, -2, None),
        ];
        assert_eq!(swap_config(&d).severity, Severity::Info);
    }

    #[test]
    fn zram_eating_a_quarter_of_ram_warns() {
        let mut d = healthy();
        d.swap_devices = vec![zram(8192, 6000, 100, 6000, 4500, "zstd")]; // 4.4 GB of 16 GB
        let f = swap_config(&d);
        assert_eq!(f.severity, Severity::Warning);
        assert!(f.explanation.contains("competes with programs"));
        assert!(f
            .recommendation
            .unwrap()
            .contains("zram-size = min(ram / 2, 4096)"));
    }

    #[test]
    fn poor_compression_is_noted_but_not_alarming() {
        let mut d = healthy();
        d.swap_devices = vec![zram(8192, 1000, 100, 1000, 900, "zstd")];
        let f = swap_config(&d);
        assert_eq!(f.severity, Severity::Info);
        assert!(f.explanation.contains("compresses only 1.1:1"));
    }

    #[test]
    fn lzo_gets_an_optional_zstd_suggestion() {
        let mut d = healthy();
        d.swap_devices = vec![zram(4096, 100, 100, 100, 40, "lzo-rle")];
        let f = swap_config(&d);
        assert!(f.explanation.contains("uses lzo-rle"));
        assert!(f
            .recommendation
            .unwrap()
            .contains("compression-algorithm = zstd"));
        d.swap_devices = vec![zram(4096, 100, 100, 100, 40, "zstd")];
        assert!(swap_config(&d).recommendation.is_none());
    }

    #[test]
    fn oversized_zram_is_flagged_as_info() {
        let mut d = healthy();
        d.swap_devices = vec![zram(32_000, 0, 100, 0, 0, "zstd")];
        assert!(swap_config(&d).explanation.contains("larger than RAM"));
    }

    #[test]
    fn zswap_together_with_zram_is_redundant() {
        let mut d = healthy();
        d.swap_devices = vec![zram(4096, 0, 100, 0, 0, "zstd")];
        d.vm = VmTunables {
            zswap_enabled: Some(true),
            ..Default::default()
        };
        let f = swap_config(&d);
        assert!(f.explanation.contains("compressed twice"));
        assert!(f
            .recommendation
            .unwrap()
            .contains("/sys/module/zswap/parameters/enabled"));
    }

    #[test]
    fn zswap_on_disk_swap_is_good_not_redundant() {
        let mut d = healthy();
        d.swap_devices = vec![disk("/swapfile", SwapKind::File, 4096, 0, -2, None)];
        d.vm = VmTunables {
            zswap_enabled: Some(true),
            ..Default::default()
        };
        let f = swap_config(&d);
        assert!(f.explanation.contains("zswap is enabled"));
        assert!(!f.explanation.contains("compressed twice"));
    }

    #[test]
    fn hdd_swap_without_zram_is_offered_zram() {
        let f = swap_config(&with_hdd_swap(healthy()));
        assert!(f.explanation.contains("/dev/sda2 is on a spinning disk"));
        assert!(f.recommendation.unwrap().contains("systemd-zram-generator"));
    }

    #[test]
    fn page_cluster_is_cleared_only_for_cheap_swap() {
        let mut d = healthy();
        d.swap_devices = vec![zram(4096, 0, 100, 0, 0, "zstd")];
        d.vm.page_cluster = Some(3);
        let f = swap_config(&d);
        assert!(f.explanation.contains("reads 7 neighbouring pages"));
        assert!(f.recommendation.unwrap().contains("vm.page-cluster=0"));

        d.vm.page_cluster = Some(0);
        assert!(swap_config(&d).recommendation.is_none());

        let mut hdd = with_hdd_swap(healthy());
        hdd.vm.page_cluster = Some(3);
        assert!(!swap_config(&hdd).explanation.contains("neighbouring"));
    }

    #[test]
    fn worst_issue_sets_the_severity() {
        let mut d = healthy();
        d.swap_devices = vec![
            zram(4096, 0, 50, 0, 0, "lzo-rle"),
            disk("/swapfile", SwapKind::File, 4096, 0, 100, None),
        ];
        // info (lzo) + warning (priority) -> warning
        assert_eq!(swap_config(&d).severity, Severity::Warning);
    }

    #[test]
    fn missing_device_list_is_reported_honestly() {
        let f = swap_config(&healthy());
        assert!(f.explanation.contains("could not be listed"));
        assert!(f.severity == Severity::Info);
    }

    #[test]
    fn steps_from_several_issues_are_numbered_continuously() {
        let mut d = healthy();
        d.swap_devices = vec![
            zram(4096, 0, 50, 0, 0, "lzo-rle"),
            disk("/swapfile", SwapKind::File, 4096, 0, 100, None),
        ];
        d.vm.page_cluster = Some(3);
        let rec = swap_config(&d).recommendation.unwrap();
        assert!(rec.starts_with("1. "));
        assert!(rec.contains("\n2. "));
        assert!(rec.contains("\n3. "));
    }
}
