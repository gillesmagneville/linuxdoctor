// SPDX-License-Identifier: GPL-3.0-only

//! Presentation helpers shared by the memory findings: human-readable
//! sizes and the per-program grouping behind "top consumers". No I/O, no
//! thresholds. The numbered recommendation layout ([`Steps`]) and the
//! sysctl commands are shared with the other modules and live in
//! `modules::recommend`; they are re-exported here so the memory topics
//! keep importing everything from one place.

use std::collections::HashMap;

pub use crate::modules::recommend::{sysctl_commands, Steps};

use super::collect::ProcessMemory;

/// kB -> "812 kB", "640 MB", "7.8 GB", "1.50 TB". Binary units (1 GB =
/// 1024 MB), matching `free -h` and the rest of this tool's output.
pub fn kb(value: u64) -> String {
    const MB: f64 = 1024.0;
    const GB: f64 = 1024.0 * 1024.0;
    const TB: f64 = 1024.0 * 1024.0 * 1024.0;
    let v = value as f64;
    if v >= TB {
        format!("{:.2} TB", v / TB)
    } else if v >= GB {
        format!("{:.1} GB", v / GB)
    } else if v >= MB {
        format!("{:.0} MB", v / MB)
    } else {
        format!("{value} kB")
    }
}

/// "12.3%" with one decimal.
pub fn pct(value: f64) -> String {
    format!("{value:.1}%")
}

/// A reasonable size for a new swap area: half of RAM, but at least 2 GB
/// and at most 8 GB. A starting point, not a rule — the point of swap on a
/// modern machine is a cushion for spikes and a home for idle pages, not
/// extra capacity.
pub fn suggested_swap_gb(total_kb: u64) -> u64 {
    let ram_gb = total_kb / (1024 * 1024);
    (ram_gb / 2).clamp(2, 8)
}

/// Commands that create and enable a swap file (for ext4/xfs; Btrfs needs
/// `btrfs filesystem mkswapfile` instead, which the callers mention).
pub fn swapfile_commands(size_gb: u64) -> Vec<String> {
    vec![
        format!("sudo fallocate -l {size_gb}G /swapfile"),
        "sudo chmod 600 /swapfile".to_string(),
        "sudo mkswap /swapfile".to_string(),
        "sudo swapon /swapfile".to_string(),
        "echo '/swapfile none swap sw 0 0' | sudo tee -a /etc/fstab   # keep it after reboot"
            .to_string(),
    ]
}

/// All processes sharing one command name, added together.
#[derive(Debug, Clone, PartialEq)]
pub struct ProcessGroup {
    pub name: String,
    pub count: usize,
    pub anon_kb: u64,
    pub file_kb: u64,
    pub shmem_kb: u64,
    pub swap_kb: u64,
    /// The single biggest member (by private memory) — the one to inspect.
    pub largest_pid: u32,
    pub largest_anon_kb: u64,
}

/// Groups by command name. Private anonymous memory adds up honestly
/// across processes (each page belongs to one process); the file-backed
/// and shared figures overlap between processes, so they are carried
/// separately and never folded into one "total".
pub fn group_by_name(processes: &[ProcessMemory]) -> Vec<ProcessGroup> {
    let mut groups: HashMap<&str, ProcessGroup> = HashMap::new();
    for p in processes {
        let g = groups
            .entry(p.name.as_str())
            .or_insert_with(|| ProcessGroup {
                name: p.name.clone(),
                count: 0,
                anon_kb: 0,
                file_kb: 0,
                shmem_kb: 0,
                swap_kb: 0,
                largest_pid: p.pid,
                largest_anon_kb: 0,
            });
        g.count += 1;
        g.anon_kb += p.rss_anon_kb;
        g.file_kb += p.rss_file_kb;
        g.shmem_kb += p.rss_shmem_kb;
        g.swap_kb += p.swap_kb;
        if p.rss_anon_kb >= g.largest_anon_kb {
            g.largest_anon_kb = p.rss_anon_kb;
            g.largest_pid = p.pid;
        }
    }
    groups.into_values().collect()
}

/// Largest private-memory consumers first; ties broken by name so the
/// output is stable.
pub fn top_by_anon(processes: &[ProcessMemory], n: usize) -> Vec<ProcessGroup> {
    let mut groups = group_by_name(processes);
    groups.sort_by(|a, b| b.anon_kb.cmp(&a.anon_kb).then_with(|| a.name.cmp(&b.name)));
    groups.truncate(n);
    groups
}

/// Programs with the most memory currently swapped out; only those with
/// something in swap.
pub fn top_by_swap(processes: &[ProcessMemory], n: usize) -> Vec<ProcessGroup> {
    let mut groups: Vec<_> = group_by_name(processes)
        .into_iter()
        .filter(|g| g.swap_kb > 0)
        .collect();
    groups.sort_by(|a, b| b.swap_kb.cmp(&a.swap_kb).then_with(|| a.name.cmp(&b.name)));
    groups.truncate(n);
    groups
}

/// "firefox (14 processes)" / "sshd".
pub fn group_label(g: &ProcessGroup) -> String {
    if g.count > 1 {
        format!("{} ({} processes)", g.name, g.count)
    } else {
        g.name.clone()
    }
}

/// One evidence line: "2.1 GB private, 310 MB file-backed, 220 MB shared, 64 MB swapped".
///
/// Private and swapped memory belong to one process each, so they add up
/// honestly across a group. File-backed and shared pages (libraries, shared
/// mappings) are counted again in every process that maps them — summing
/// them for fifty processes would report the same library fifty times — so
/// they are shown only for a program that runs as a single process.
pub fn group_detail(g: &ProcessGroup) -> String {
    let mut parts = vec![format!("{} private", kb(g.anon_kb))];
    if g.count == 1 {
        if g.file_kb > 0 {
            parts.push(format!("{} file-backed", kb(g.file_kb)));
        }
        if g.shmem_kb > 0 {
            parts.push(format!("{} shared", kb(g.shmem_kb)));
        }
    }
    if g.swap_kb > 0 {
        parts.push(format!("{} swapped out", kb(g.swap_kb)));
    }
    parts.join(", ")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn proc(pid: u32, name: &str, anon: u64, file: u64, shmem: u64, swap: u64) -> ProcessMemory {
        ProcessMemory {
            pid,
            name: name.into(),
            rss_anon_kb: anon,
            rss_file_kb: file,
            rss_shmem_kb: shmem,
            swap_kb: swap,
        }
    }

    #[test]
    fn sizes_use_binary_units_and_sensible_precision() {
        assert_eq!(kb(0), "0 kB");
        assert_eq!(kb(812), "812 kB");
        assert_eq!(kb(1024), "1 MB");
        assert_eq!(kb(655_360), "640 MB");
        assert_eq!(kb(8_222_320), "7.8 GB");
        assert_eq!(kb(1_610_612_736), "1.50 TB");
    }

    #[test]
    fn swap_size_suggestion_is_half_of_ram_within_2_to_8_gb() {
        assert_eq!(suggested_swap_gb(1024 * 1024), 2); // 1 GB RAM
        assert_eq!(suggested_swap_gb(8 * 1024 * 1024), 4);
        assert_eq!(suggested_swap_gb(16 * 1024 * 1024), 8);
        assert_eq!(suggested_swap_gb(256 * 1024 * 1024), 8);
        assert_eq!(suggested_swap_gb(0), 2);
    }

    #[test]
    fn swapfile_commands_use_the_requested_size_and_persist_in_fstab() {
        let cmds = swapfile_commands(4);
        assert_eq!(cmds[0], "sudo fallocate -l 4G /swapfile");
        assert!(cmds.iter().any(|c| c.contains("mkswap")));
        assert!(cmds.iter().any(|c| c.contains("/etc/fstab")));
    }

    #[test]
    fn grouping_adds_private_memory_and_tracks_the_largest_member() {
        let procs = vec![
            proc(10, "chrome", 500, 100, 50, 0),
            proc(11, "chrome", 900, 100, 50, 10),
            proc(12, "chrome", 100, 100, 50, 0),
            proc(20, "sshd", 20, 5, 0, 0),
        ];
        let top = top_by_anon(&procs, 5);
        assert_eq!(top.len(), 2);
        assert_eq!(top[0].name, "chrome");
        assert_eq!(top[0].count, 3);
        assert_eq!(top[0].anon_kb, 1500);
        assert_eq!(top[0].file_kb, 300);
        assert_eq!(top[0].swap_kb, 10);
        assert_eq!(top[0].largest_pid, 11);
        assert_eq!(top[0].largest_anon_kb, 900);
        assert_eq!(top[1].name, "sshd");
    }

    #[test]
    fn top_n_truncates_and_ties_are_stable() {
        let procs = vec![
            proc(1, "b", 10, 0, 0, 0),
            proc(2, "a", 10, 0, 0, 0),
            proc(3, "c", 10, 0, 0, 0),
        ];
        let top = top_by_anon(&procs, 2);
        assert_eq!(
            top.iter().map(|g| g.name.as_str()).collect::<Vec<_>>(),
            ["a", "b"]
        );
    }

    #[test]
    fn swap_ranking_ignores_programs_with_nothing_swapped() {
        let procs = vec![
            proc(1, "idle", 10, 0, 0, 0),
            proc(2, "db", 10, 0, 0, 5000),
            proc(3, "cache", 10, 0, 0, 800),
        ];
        let top = top_by_swap(&procs, 5);
        assert_eq!(top.len(), 2);
        assert_eq!(top[0].name, "db");
    }

    #[test]
    fn labels_and_details_read_naturally() {
        let g = ProcessGroup {
            name: "firefox".into(),
            count: 14,
            anon_kb: 2_202_009,
            file_kb: 317_440,
            shmem_kb: 0,
            swap_kb: 65_536,
            largest_pid: 1,
            largest_anon_kb: 1,
        };
        assert_eq!(group_label(&g), "firefox (14 processes)");
        // Libraries are mapped by every process: not summed for a group.
        assert_eq!(group_detail(&g), "2.1 GB private, 64 MB swapped out");
        let single = ProcessGroup { count: 1, ..g };
        assert_eq!(group_label(&single), "firefox");
        assert_eq!(
            group_detail(&single),
            "2.1 GB private, 310 MB file-backed, 64 MB swapped out"
        );
    }
}
