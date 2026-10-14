// SPDX-License-Identifier: GPL-3.0-only

use std::collections::HashMap;
use std::fs;

use crate::core::command::command;
use crate::core::error::ModuleError;

/// Raw facts read from the system, before any interpretation. Collectors
/// never interpret — see ARCHITECTURE.md "Collectors".
///
/// The first group of fields is what the module has always read and is
/// **required**: if `/proc/meminfo` or the basic `vm` sysctls cannot be
/// read, the module reports an error. Everything in the second group
/// (`detail` and below) is **best-effort**: an older kernel, a container
/// or a restricted `/proc` simply leaves those fields empty, and the
/// findings that need them are skipped or say plainly what could not be
/// checked. A missing optional source never turns the whole module red.
#[derive(Debug, Clone, PartialEq, Default)]
pub struct MemoryRawData {
    pub mem_total_kb: u64,
    pub mem_free_kb: u64,
    pub mem_available_kb: u64,
    /// Buffers + Cached from /proc/meminfo. **Includes shared memory**:
    /// the kernel counts tmpfs/shm pages inside `Cached`, so this figure
    /// is larger than the memory that can actually be dropped on demand.
    /// Use [`MemoryRawData::reclaimable_cache_kb`] for the latter.
    pub cached_kb: u64,
    /// Shmem from /proc/meminfo — tmpfs, /dev/shm, SysV/POSIX shared
    /// memory segments, memfd. Unlike page cache, not reclaimable on
    /// demand (it can only be swapped out).
    pub shmem_kb: u64,
    /// Dirty from /proc/meminfo — modified pages not yet written to disk.
    pub dirty_kb: u64,
    pub swap_total_kb: u64,
    pub swap_free_kb: u64,
    pub swappiness: u8,
    /// vm.dirty_ratio (%) — processes block on writes at/above this.
    pub dirty_ratio: u8,
    /// vm.dirty_background_ratio (%) — kernel starts background writeback
    /// at/above this, before the harder `dirty_ratio` limit above.
    pub dirty_background_ratio: u8,

    // ---- best-effort sources -------------------------------------------
    /// The rest of /proc/meminfo (LRU lists, slab, page tables, commit
    /// accounting, huge pages...).
    pub detail: MeminfoDetail,
    pub vm: VmTunables,
    /// Active swap areas from /proc/swaps.
    pub swap_devices: Vec<SwapDevice>,
    /// /proc/pressure/memory; `None` when the kernel has no PSI (older
    /// than 4.20, built without CONFIG_PSI, or booted with `psi=0`).
    pub pressure: Option<MemoryPressure>,
    /// Selected cumulative counters from /proc/vmstat (since boot).
    pub vmstat: Option<VmstatCounters>,
    /// Per-process memory from /proc/<pid>/status, kernel threads excluded.
    pub processes: Vec<ProcessMemory>,
    /// tmpfs mounts with their usage (`df -t tmpfs`).
    pub tmpfs_mounts: Vec<TmpfsMount>,
    /// SysV shared memory segments; `None` when /proc/sysvipc/shm is not
    /// readable at all (distinct from "readable and empty").
    pub sysv_shm: Option<Vec<SysvSegment>>,
    /// ZFS ARC, when OpenZFS is loaded.
    pub zfs_arc: Option<ZfsArc>,
    /// Kernel page size in kB (4 on x86-64, 4 or 64 on arm64). 0 = unknown.
    pub page_size_kb: u64,
}

impl MemoryRawData {
    /// The part of the data that comes from `/proc/meminfo`: the headline
    /// figures and the extended [`MeminfoDetail`]. Everything else keeps
    /// its default, so callers (and tests) fill in only the sources they
    /// care about with struct-update syntax.
    pub fn from_meminfo(text: &str) -> Result<Self, ModuleError> {
        let fields = parse_meminfo(text)?;
        let get = |name: &str| *fields.get(name).unwrap_or(&0);
        Ok(MemoryRawData {
            mem_total_kb: get("MemTotal"),
            mem_free_kb: get("MemFree"),
            mem_available_kb: get("MemAvailable"),
            cached_kb: get("Buffers") + get("Cached"),
            shmem_kb: get("Shmem"),
            dirty_kb: get("Dirty"),
            swap_total_kb: get("SwapTotal"),
            swap_free_kb: get("SwapFree"),
            detail: MeminfoDetail::from_fields(&fields),
            ..Default::default()
        })
    }

    /// Memory in use by programs and the kernel: total minus available.
    /// This is the definition `free(1)` uses for its "used" column
    /// (procps-ng 4.x) and what the Overview has always reported.
    pub fn used_kb(&self) -> u64 {
        self.mem_total_kb.saturating_sub(self.mem_available_kb)
    }

    pub fn swap_used_kb(&self) -> u64 {
        self.swap_total_kb.saturating_sub(self.swap_free_kb)
    }

    /// Ordinary file-backed page cache, i.e. `Cached` **without** the
    /// shared memory the kernel also counts there, and without buffers.
    pub fn file_cache_kb(&self) -> u64 {
        self.cached_kb
            .saturating_sub(self.detail.buffers_kb)
            .saturating_sub(self.shmem_kb)
    }

    /// Memory the kernel can hand back without swapping: buffers, plain
    /// page cache and reclaimable slab (dentry/inode caches). Shared
    /// memory is deliberately excluded.
    pub fn reclaimable_cache_kb(&self) -> u64 {
        self.detail.buffers_kb + self.file_cache_kb() + self.detail.sreclaimable_kb
    }

    /// What `free(1)` prints under "buff/cache": Buffers + Cached +
    /// SReclaimable. Includes shared memory, which is why it must not be
    /// read as "droppable".
    pub fn free_style_buff_cache_kb(&self) -> u64 {
        self.cached_kb + self.detail.sreclaimable_kb
    }

    pub fn available_percent(&self) -> f64 {
        percent(self.mem_available_kb, self.mem_total_kb)
    }

    pub fn page_size_kb_or_default(&self) -> u64 {
        if self.page_size_kb == 0 {
            4
        } else {
            self.page_size_kb
        }
    }

    pub fn has_swap(&self) -> bool {
        self.swap_total_kb > 0
    }
}

/// `part` as a percentage of `whole`; 0 when `whole` is 0.
pub fn percent(part: u64, whole: u64) -> f64 {
    if whole == 0 {
        0.0
    } else {
        part as f64 / whole as f64 * 100.0
    }
}

// ---------------------------------------------------------------------------
// /proc/meminfo, in full
// ---------------------------------------------------------------------------

/// Every /proc/meminfo field the analysis uses beyond the headline ones,
/// in kB (huge-page counts are pages). A field the kernel does not
/// provide stays 0.
#[derive(Debug, Clone, PartialEq, Default)]
pub struct MeminfoDetail {
    pub buffers_kb: u64,
    /// The `Cached` line. Includes Shmem and SwapCached.
    pub cached_incl_shmem_kb: u64,
    pub swap_cached_kb: u64,
    pub active_anon_kb: u64,
    pub inactive_anon_kb: u64,
    pub active_file_kb: u64,
    pub inactive_file_kb: u64,
    pub unevictable_kb: u64,
    pub mlocked_kb: u64,
    /// Private anonymous memory: heaps, stacks, malloc arenas.
    pub anon_pages_kb: u64,
    /// File pages currently mapped into running programs.
    pub mapped_kb: u64,
    pub writeback_kb: u64,
    pub slab_kb: u64,
    pub sreclaimable_kb: u64,
    pub sunreclaim_kb: u64,
    pub kernel_stack_kb: u64,
    pub page_tables_kb: u64,
    pub percpu_kb: u64,
    pub commit_limit_kb: u64,
    pub committed_as_kb: u64,
    pub anon_huge_pages_kb: u64,
    pub shmem_huge_pages_kb: u64,
    pub hugepages_total: u64,
    pub hugepages_free: u64,
    pub hugepages_rsvd: u64,
    pub hugepage_size_kb: u64,
    pub hugetlb_kb: u64,
    pub zswap_kb: u64,
    pub zswapped_kb: u64,
    pub balloon_kb: u64,
}

impl MeminfoDetail {
    pub fn from_fields(fields: &HashMap<String, u64>) -> Self {
        let get = |name: &str| *fields.get(name).unwrap_or(&0);
        MeminfoDetail {
            buffers_kb: get("Buffers"),
            cached_incl_shmem_kb: get("Cached"),
            swap_cached_kb: get("SwapCached"),
            active_anon_kb: get("Active(anon)"),
            inactive_anon_kb: get("Inactive(anon)"),
            active_file_kb: get("Active(file)"),
            inactive_file_kb: get("Inactive(file)"),
            unevictable_kb: get("Unevictable"),
            mlocked_kb: get("Mlocked"),
            anon_pages_kb: get("AnonPages"),
            mapped_kb: get("Mapped"),
            writeback_kb: get("Writeback"),
            slab_kb: get("Slab"),
            sreclaimable_kb: get("SReclaimable"),
            sunreclaim_kb: get("SUnreclaim"),
            kernel_stack_kb: get("KernelStack"),
            page_tables_kb: get("PageTables"),
            percpu_kb: get("Percpu"),
            commit_limit_kb: get("CommitLimit"),
            committed_as_kb: get("Committed_AS"),
            anon_huge_pages_kb: get("AnonHugePages"),
            shmem_huge_pages_kb: get("ShmemHugePages"),
            hugepages_total: get("HugePages_Total"),
            hugepages_free: get("HugePages_Free"),
            hugepages_rsvd: get("HugePages_Rsvd"),
            hugepage_size_kb: get("Hugepagesize"),
            hugetlb_kb: get("Hugetlb"),
            zswap_kb: get("Zswap"),
            zswapped_kb: get("Zswapped"),
            balloon_kb: get("Balloon"),
        }
    }
}

// ---------------------------------------------------------------------------
// Tunables
// ---------------------------------------------------------------------------

/// `/proc/sys/vm/*` and `/sys/kernel/mm/*` settings the analysis reasons
/// about. `None` means the file does not exist or could not be read.
#[derive(Debug, Clone, PartialEq, Default)]
pub struct VmTunables {
    pub vfs_cache_pressure: Option<u64>,
    pub min_free_kbytes: Option<u64>,
    pub overcommit_memory: Option<u64>,
    pub overcommit_ratio: Option<u64>,
    /// Non-zero means it overrides `overcommit_ratio`.
    pub overcommit_kbytes: Option<u64>,
    /// Non-zero means byte-based dirty limits override the ratios.
    pub dirty_bytes: Option<u64>,
    pub dirty_background_bytes: Option<u64>,
    pub dirty_expire_centisecs: Option<u64>,
    pub dirty_writeback_centisecs: Option<u64>,
    /// `vm.page-cluster`: swap read-ahead is 2^N pages (default 3).
    pub page_cluster: Option<u64>,
    /// Selected word of `transparent_hugepage/enabled`: always, madvise, never.
    pub thp_enabled: Option<String>,
    /// Selected word of `transparent_hugepage/defrag`.
    pub thp_defrag: Option<String>,
    /// `/sys/module/zswap/parameters/enabled`.
    pub zswap_enabled: Option<bool>,
}

// ---------------------------------------------------------------------------
// Swap
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SwapKind {
    Partition,
    File,
    /// Compressed RAM block device (`/dev/zramN`).
    Zram,
    Other,
}

/// What the kernel reports for a zram device, converted to kB.
#[derive(Debug, Clone, PartialEq, Default)]
pub struct ZramStats {
    /// Uncompressed size of the data currently stored.
    pub original_kb: u64,
    pub compressed_kb: u64,
    /// RAM actually consumed, including allocator overhead.
    pub memory_used_kb: u64,
    pub algorithm: Option<String>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct SwapDevice {
    pub path: String,
    pub kind: SwapKind,
    pub size_kb: u64,
    pub used_kb: u64,
    pub priority: i64,
    pub zram: Option<ZramStats>,
    /// Whether the backing disk is a spinning disk. `None` when it cannot
    /// be told (swap files, zram, exotic device-mapper stacks).
    pub rotational: Option<bool>,
}

// ---------------------------------------------------------------------------
// Pressure & counters
// ---------------------------------------------------------------------------

/// One line of a PSI file: the share of the last 10/60/300 seconds (in %)
/// during which tasks were stalled, plus the cumulative stall time.
#[derive(Debug, Clone, Copy, PartialEq, Default)]
pub struct PsiLine {
    pub avg10: f64,
    pub avg60: f64,
    pub avg300: f64,
    pub total_us: u64,
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub struct MemoryPressure {
    /// At least one task was stalled waiting for memory.
    pub some: PsiLine,
    /// *All* non-idle tasks were stalled at once.
    pub full: Option<PsiLine>,
}

/// Cumulative since boot. Counted in pages (convert with the page size).
#[derive(Debug, Clone, Copy, PartialEq, Default)]
pub struct VmstatCounters {
    pub pswpin: u64,
    pub pswpout: u64,
    pub pgmajfault: u64,
    pub pgscan_kswapd: u64,
    pub pgscan_direct: u64,
    pub pgsteal_kswapd: u64,
    pub pgsteal_direct: u64,
    /// Times a process had to reclaim memory itself before its allocation
    /// could proceed (sum of every `allocstall_*` zone counter).
    pub allocstall: u64,
    /// Processes killed by the kernel's OOM killer since boot.
    pub oom_kill: u64,
    /// File pages evicted and then needed again.
    pub workingset_refault: u64,
}

// ---------------------------------------------------------------------------
// Processes
// ---------------------------------------------------------------------------

/// One user-space process's memory, from `/proc/<pid>/status`.
#[derive(Debug, Clone, PartialEq)]
pub struct ProcessMemory {
    pub pid: u32,
    /// Command name (`comm`), at most 15 characters.
    pub name: String,
    /// Private anonymous memory (heap, stacks) — the process's own,
    /// unshared footprint.
    pub rss_anon_kb: u64,
    /// File-backed pages mapped by the process (executables, libraries).
    pub rss_file_kb: u64,
    pub rss_shmem_kb: u64,
    /// This process's memory currently sitting in swap.
    pub swap_kb: u64,
}

// ---------------------------------------------------------------------------
// Shared memory sources
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq)]
pub struct TmpfsMount {
    pub mount_point: String,
    pub size_kb: u64,
    pub used_kb: u64,
}

/// One row of /proc/sysvipc/shm.
#[derive(Debug, Clone, PartialEq)]
pub struct SysvSegment {
    pub shmid: u64,
    pub size_kb: u64,
    /// Processes currently attached. 0 = orphaned: nobody uses it, yet its
    /// memory stays allocated until it is explicitly removed.
    pub nattch: u64,
    /// Part of the segment actually resident in RAM.
    pub rss_kb: u64,
    pub swap_kb: u64,
    pub uid: u32,
}

#[derive(Debug, Clone, PartialEq)]
pub struct ZfsArc {
    pub size_kb: u64,
    pub max_kb: u64,
}

// ---------------------------------------------------------------------------
// I/O
// ---------------------------------------------------------------------------

fn read_opt(path: &str) -> Option<String> {
    fs::read_to_string(path).ok()
}

/// Thin I/O wrapper: reads the source files and delegates all
/// interpretation to the pure parse functions below.
pub fn collect() -> Result<MemoryRawData, ModuleError> {
    let meminfo_text = fs::read_to_string("/proc/meminfo").map_err(|source| ModuleError::Io {
        path: "/proc/meminfo".to_string(),
        source,
    })?;
    let swappiness_text =
        fs::read_to_string("/proc/sys/vm/swappiness").map_err(|source| ModuleError::Io {
            path: "/proc/sys/vm/swappiness".to_string(),
            source,
        })?;
    let dirty_ratio_text =
        fs::read_to_string("/proc/sys/vm/dirty_ratio").map_err(|source| ModuleError::Io {
            path: "/proc/sys/vm/dirty_ratio".to_string(),
            source,
        })?;
    let dirty_background_ratio_text = fs::read_to_string("/proc/sys/vm/dirty_background_ratio")
        .map_err(|source| ModuleError::Io {
            path: "/proc/sys/vm/dirty_background_ratio".to_string(),
            source,
        })?;

    let swappiness = parse_swappiness(&swappiness_text)?;
    let dirty_ratio = parse_small_uint_file(&dirty_ratio_text, "/proc/sys/vm/dirty_ratio")?;
    let dirty_background_ratio = parse_small_uint_file(
        &dirty_background_ratio_text,
        "/proc/sys/vm/dirty_background_ratio",
    )?;

    Ok(MemoryRawData {
        swappiness,
        dirty_ratio,
        dirty_background_ratio,

        vm: collect_vm_tunables(),
        swap_devices: collect_swap_devices(),
        pressure: read_opt("/proc/pressure/memory").and_then(|t| parse_psi(&t)),
        vmstat: read_opt("/proc/vmstat").and_then(|t| parse_vmstat(&t)),
        processes: collect_processes(),
        tmpfs_mounts: collect_tmpfs_mounts(),
        sysv_shm: read_opt("/proc/sysvipc/shm").map(|t| parse_sysv_shm(&t)),
        zfs_arc: read_opt("/proc/spl/kstat/zfs/arcstats").and_then(|t| parse_zfs_arcstats(&t)),
        page_size_kb: read_opt("/proc/self/smaps")
            .and_then(|t| parse_kernel_page_size_kb(&t))
            .unwrap_or(0),
        ..MemoryRawData::from_meminfo(&meminfo_text)?
    })
}

fn collect_vm_tunables() -> VmTunables {
    let sysctl =
        |name: &str| read_opt(&format!("/proc/sys/vm/{name}")).and_then(|t| parse_u64_file(&t));
    VmTunables {
        vfs_cache_pressure: sysctl("vfs_cache_pressure"),
        min_free_kbytes: sysctl("min_free_kbytes"),
        overcommit_memory: sysctl("overcommit_memory"),
        overcommit_ratio: sysctl("overcommit_ratio"),
        overcommit_kbytes: sysctl("overcommit_kbytes"),
        dirty_bytes: sysctl("dirty_bytes"),
        dirty_background_bytes: sysctl("dirty_background_bytes"),
        dirty_expire_centisecs: sysctl("dirty_expire_centisecs"),
        dirty_writeback_centisecs: sysctl("dirty_writeback_centisecs"),
        page_cluster: sysctl("page-cluster"),
        thp_enabled: read_opt("/sys/kernel/mm/transparent_hugepage/enabled")
            .and_then(|t| parse_bracketed_choice(&t)),
        thp_defrag: read_opt("/sys/kernel/mm/transparent_hugepage/defrag")
            .and_then(|t| parse_bracketed_choice(&t)),
        zswap_enabled: read_opt("/sys/module/zswap/parameters/enabled")
            .map(|t| matches!(t.trim(), "Y" | "y" | "1")),
    }
}

fn collect_swap_devices() -> Vec<SwapDevice> {
    let Some(text) = read_opt("/proc/swaps") else {
        return Vec::new();
    };
    let mut devices = parse_proc_swaps(&text);
    for device in &mut devices {
        if device.kind == SwapKind::Partition {
            device.rotational = swap_partition_is_rotational(&device.path);
        }
        if device.kind != SwapKind::Zram {
            continue;
        }
        let Some(name) = device.path.strip_prefix("/dev/") else {
            continue;
        };
        let stats =
            read_opt(&format!("/sys/block/{name}/mm_stat")).and_then(|t| parse_zram_mm_stat(&t));
        if let Some(mut stats) = stats {
            stats.algorithm = read_opt(&format!("/sys/block/{name}/comp_algorithm"))
                .and_then(|t| parse_bracketed_choice(&t));
            device.zram = Some(stats);
        }
    }
    devices
}

/// Resolves `/dev/sda3`, `/dev/mapper/vg-swap`, `/dev/disk/by-uuid/...` to
/// the kernel block device and reads `queue/rotational` — from the device
/// itself when it has one (whole disks, device-mapper) or from its parent
/// disk (partitions).
fn swap_partition_is_rotational(path: &str) -> Option<bool> {
    let resolved = fs::canonicalize(path).ok()?;
    let name = resolved.file_name()?.to_str()?.to_string();
    let sys = fs::canonicalize(format!("/sys/class/block/{name}")).ok()?;
    let flag = |dir: &std::path::Path| {
        fs::read_to_string(dir.join("queue/rotational"))
            .ok()
            .map(|t| t.trim() == "1")
    };
    flag(&sys).or_else(|| flag(sys.parent()?))
}

fn collect_processes() -> Vec<ProcessMemory> {
    let Ok(entries) = fs::read_dir("/proc") else {
        return Vec::new();
    };
    let mut processes = Vec::new();
    for entry in entries.flatten() {
        let file_name = entry.file_name();
        let Some(pid) = file_name.to_str().and_then(|s| s.parse::<u32>().ok()) else {
            continue;
        };
        // A process can exit between listing and reading; that is normal.
        let Ok(text) = fs::read_to_string(entry.path().join("status")) else {
            continue;
        };
        if let Some(process) = parse_proc_status(pid, &text) {
            processes.push(process);
        }
    }
    processes
}

/// `df` is the portable way to get tmpfs usage without a libc call. Its
/// exit status is ignored on purpose: a single unreadable mount makes it
/// exit non-zero while every other line is still valid.
fn collect_tmpfs_mounts() -> Vec<TmpfsMount> {
    match command("df").args(["-kP", "-t", "tmpfs"]).output() {
        Ok(output) => parse_df_tmpfs(&String::from_utf8_lossy(&output.stdout)),
        Err(_) => Vec::new(),
    }
}

// ---------------------------------------------------------------------------
// Pure parsers
// ---------------------------------------------------------------------------

/// Parse `/proc/meminfo` text into a key -> kB map. Pure function, tested
/// directly against fixture strings (no filesystem access needed).
pub fn parse_meminfo(text: &str) -> Result<HashMap<String, u64>, ModuleError> {
    let mut fields = HashMap::new();
    for line in text.lines() {
        let Some((key, rest)) = line.split_once(':') else {
            continue;
        };
        let Some(value_str) = rest.split_whitespace().next() else {
            continue;
        };
        if let Ok(value) = value_str.parse::<u64>() {
            fields.insert(key.trim().to_string(), value);
        }
    }
    if fields.is_empty() {
        return Err(ModuleError::Parse {
            what: "/proc/meminfo".to_string(),
            reason: "no recognizable key: value lines".to_string(),
        });
    }
    Ok(fields)
}

/// Parse the single-integer contents of `/proc/sys/vm/swappiness`.
pub fn parse_swappiness(text: &str) -> Result<u8, ModuleError> {
    parse_small_uint_file(text, "/proc/sys/vm/swappiness")
}

/// Shared parser for small single-integer `/proc/sys/vm/*` files
/// (swappiness, dirty_ratio, dirty_background_ratio all share this shape).
fn parse_small_uint_file(text: &str, what: &str) -> Result<u8, ModuleError> {
    text.trim().parse::<u8>().map_err(|e| ModuleError::Parse {
        what: what.to_string(),
        reason: e.to_string(),
    })
}

/// A single unsigned integer, as most `/proc/sys/vm/*` files hold.
pub fn parse_u64_file(text: &str) -> Option<u64> {
    text.trim().parse().ok()
}

/// "always [madvise] never" -> `Some("madvise")`: the kernel brackets the
/// currently selected choice in these files (also zram's `comp_algorithm`).
pub fn parse_bracketed_choice(text: &str) -> Option<String> {
    let start = text.find('[')?;
    let end = text[start..].find(']')? + start;
    let choice = text[start + 1..end].trim();
    if choice.is_empty() {
        None
    } else {
        Some(choice.to_string())
    }
}

/// `/proc/swaps`: `Filename Type Size Used Priority`, sizes in kB. The
/// kernel escapes spaces in file names as `\040`.
pub fn parse_proc_swaps(text: &str) -> Vec<SwapDevice> {
    text.lines()
        .skip(1) // header
        .filter_map(|line| {
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() < 5 {
                return None;
            }
            let path = parts[0].replace("\\040", " ");
            let kind = if path.starts_with("/dev/zram") {
                SwapKind::Zram
            } else {
                match parts[1] {
                    "partition" => SwapKind::Partition,
                    "file" => SwapKind::File,
                    _ => SwapKind::Other,
                }
            };
            Some(SwapDevice {
                path,
                kind,
                size_kb: parts[2].parse().ok()?,
                used_kb: parts[3].parse().ok()?,
                priority: parts[4].parse().ok()?,
                zram: None,
                rotational: None,
            })
        })
        .collect()
}

/// `/sys/block/zramN/mm_stat`: bytes — `orig_data_size compr_data_size
/// mem_used_total mem_limit mem_used_max same_pages pages_compacted ...`.
pub fn parse_zram_mm_stat(text: &str) -> Option<ZramStats> {
    let mut numbers = text.split_whitespace().map(|w| w.parse::<u64>());
    let original = numbers.next()?.ok()?;
    let compressed = numbers.next()?.ok()?;
    let used = numbers.next()?.ok()?;
    Some(ZramStats {
        original_kb: original / 1024,
        compressed_kb: compressed / 1024,
        memory_used_kb: used / 1024,
        algorithm: None,
    })
}

/// `/proc/pressure/memory`:
/// `some avg10=0.00 avg60=0.00 avg300=0.00 total=0` (+ a `full` line).
pub fn parse_psi(text: &str) -> Option<MemoryPressure> {
    let mut some = None;
    let mut full = None;
    for line in text.lines() {
        let mut words = line.split_whitespace();
        let kind = words.next()?;
        let mut parsed = PsiLine::default();
        for word in words {
            let Some((key, value)) = word.split_once('=') else {
                continue;
            };
            match key {
                "avg10" => parsed.avg10 = value.parse().ok()?,
                "avg60" => parsed.avg60 = value.parse().ok()?,
                "avg300" => parsed.avg300 = value.parse().ok()?,
                "total" => parsed.total_us = value.parse().ok()?,
                _ => {}
            }
        }
        match kind {
            "some" => some = Some(parsed),
            "full" => full = Some(parsed),
            _ => {}
        }
    }
    Some(MemoryPressure { some: some?, full })
}

/// `/proc/vmstat`: `name value` per line. `None` when it does not look
/// like vmstat at all (no recognizable counter).
pub fn parse_vmstat(text: &str) -> Option<VmstatCounters> {
    let mut counters = VmstatCounters::default();
    let mut recognised = false;
    let mut refault_file = None;
    let mut refault_legacy = None;
    for line in text.lines() {
        let mut words = line.split_whitespace();
        let (Some(name), Some(value)) = (words.next(), words.next()) else {
            continue;
        };
        let Ok(value) = value.parse::<u64>() else {
            continue;
        };
        match name {
            "pswpin" => counters.pswpin = value,
            "pswpout" => counters.pswpout = value,
            "pgmajfault" => counters.pgmajfault = value,
            "pgscan_kswapd" => counters.pgscan_kswapd = value,
            "pgscan_direct" => counters.pgscan_direct = value,
            "pgsteal_kswapd" => counters.pgsteal_kswapd = value,
            "pgsteal_direct" => counters.pgsteal_direct = value,
            "oom_kill" => counters.oom_kill = value,
            // Linux 5.9+ splits the counter; earlier kernels have one.
            "workingset_refault_file" => refault_file = Some(value),
            "workingset_refault" => refault_legacy = Some(value),
            n if n.starts_with("allocstall_") => counters.allocstall += value,
            _ => continue,
        }
        recognised = true;
    }
    counters.workingset_refault = refault_file.or(refault_legacy).unwrap_or(0);
    recognised.then_some(counters)
}

/// `/proc/<pid>/status`. Returns `None` for kernel threads (they have no
/// `RssAnon`) and for kernels older than 4.5 that lack the split fields.
pub fn parse_proc_status(pid: u32, text: &str) -> Option<ProcessMemory> {
    let mut name = None;
    let mut rss_anon = None;
    let mut rss_file = 0;
    let mut rss_shmem = 0;
    let mut swap = 0;
    for line in text.lines() {
        let Some((key, rest)) = line.split_once(':') else {
            continue;
        };
        let value = rest.trim();
        let kb = || value.split_whitespace().next()?.parse::<u64>().ok();
        match key {
            "Name" => name = Some(value.to_string()),
            "RssAnon" => rss_anon = kb(),
            "RssFile" => rss_file = kb().unwrap_or(0),
            "RssShmem" => rss_shmem = kb().unwrap_or(0),
            "VmSwap" => swap = kb().unwrap_or(0),
            _ => {}
        }
    }
    Some(ProcessMemory {
        pid,
        name: name?,
        rss_anon_kb: rss_anon?,
        rss_file_kb: rss_file,
        rss_shmem_kb: rss_shmem,
        swap_kb: swap,
    })
}

/// `df -kP -t tmpfs`: `Filesystem 1024-blocks Used Available Capacity
/// Mounted on`. The mount point is the rest of the line, so a path with
/// spaces survives.
pub fn parse_df_tmpfs(text: &str) -> Vec<TmpfsMount> {
    text.lines()
        .skip(1) // header
        .filter_map(|line| {
            let mut words = line.split_whitespace();
            let _filesystem = words.next()?;
            let size_kb = words.next()?.parse().ok()?;
            let used_kb = words.next()?.parse().ok()?;
            let _available = words.next()?;
            let _capacity = words.next()?;
            let mount_point = words.collect::<Vec<_>>().join(" ");
            if mount_point.is_empty() {
                return None;
            }
            Some(TmpfsMount {
                mount_point,
                size_kb,
                used_kb,
            })
        })
        .collect()
}

/// `/proc/sysvipc/shm`. Columns are located through the header line, so a
/// kernel that adds or reorders a column does not shift the values.
pub fn parse_sysv_shm(text: &str) -> Vec<SysvSegment> {
    let mut lines = text.lines();
    let Some(header) = lines.next() else {
        return Vec::new();
    };
    let columns: Vec<&str> = header.split_whitespace().collect();
    let index = |name: &str| columns.iter().position(|c| *c == name);
    let (Some(i_shmid), Some(i_size), Some(i_nattch)) =
        (index("shmid"), index("size"), index("nattch"))
    else {
        return Vec::new();
    };
    let (i_rss, i_swap, i_uid) = (index("rss"), index("swap"), index("uid"));

    lines
        .filter_map(|line| {
            let words: Vec<&str> = line.split_whitespace().collect();
            if words.len() < columns.len() {
                return None;
            }
            let number = |i: usize| words.get(i)?.parse::<u64>().ok();
            Some(SysvSegment {
                shmid: number(i_shmid)?,
                size_kb: number(i_size)? / 1024,
                nattch: number(i_nattch)?,
                rss_kb: i_rss.and_then(number).unwrap_or(0) / 1024,
                swap_kb: i_swap.and_then(number).unwrap_or(0) / 1024,
                uid: i_uid.and_then(number).unwrap_or(0) as u32,
            })
        })
        .collect()
}

/// `/proc/spl/kstat/zfs/arcstats`: `name type data` rows, bytes.
pub fn parse_zfs_arcstats(text: &str) -> Option<ZfsArc> {
    let mut size = None;
    let mut max = None;
    for line in text.lines() {
        let words: Vec<&str> = line.split_whitespace().collect();
        if words.len() != 3 {
            continue;
        }
        match words[0] {
            "size" => size = words[2].parse::<u64>().ok(),
            "c_max" => max = words[2].parse::<u64>().ok(),
            _ => {}
        }
    }
    Some(ZfsArc {
        size_kb: size? / 1024,
        max_kb: max.unwrap_or(0) / 1024,
    })
}

/// First `KernelPageSize:` line of a smaps file, in kB.
pub fn parse_kernel_page_size_kb(smaps: &str) -> Option<u64> {
    smaps
        .lines()
        .find_map(|l| l.strip_prefix("KernelPageSize:"))
        .and_then(|rest| rest.split_whitespace().next())
        .and_then(|n| n.parse().ok())
}

#[cfg(test)]
mod tests {
    use super::*;

    const FIXTURE_MEMINFO: &str = "\
MemTotal:       16384000 kB
MemFree:         1200000 kB
MemAvailable:    2000000 kB
Buffers:          300000 kB
Cached:          4000000 kB
Shmem:            250000 kB
Dirty:              1200 kB
SwapTotal:       4194300 kB
SwapFree:         100000 kB
";

    /// A realistic full /proc/meminfo (kernel 6.x, 8 GiB VM).
    const FULL_MEMINFO: &str = "\
MemTotal:        8222320 kB
MemFree:         7724092 kB
MemAvailable:    7766580 kB
Buffers:            9304 kB
Cached:           248540 kB
SwapCached:         1000 kB
Active:            27884 kB
Inactive:         415204 kB
Active(anon):         28 kB
Inactive(anon):   199604 kB
Active(file):      27856 kB
Inactive(file):   215600 kB
Unevictable:        8516 kB
Mlocked:            8564 kB
SwapTotal:       2097148 kB
SwapFree:        2097148 kB
Zswap:                 0 kB
Zswapped:              0 kB
Dirty:              1720 kB
Writeback:            64 kB
AnonPages:        193944 kB
Mapped:           182236 kB
Shmem:             14392 kB
KReclaimable:       4404 kB
Slab:              21244 kB
SReclaimable:       4404 kB
SUnreclaim:        16840 kB
KernelStack:        1516 kB
PageTables:         2184 kB
CommitLimit:     4111160 kB
Committed_AS:     531396 kB
Percpu:              496 kB
AnonHugePages:      2048 kB
ShmemHugePages:        0 kB
HugePages_Total:       4
HugePages_Free:        3
HugePages_Rsvd:        1
HugePages_Surp:        0
Hugepagesize:       2048 kB
Hugetlb:            8192 kB
";

    #[test]
    fn parses_known_fields() {
        let fields = parse_meminfo(FIXTURE_MEMINFO).unwrap();
        assert_eq!(fields.get("MemTotal"), Some(&16384000));
        assert_eq!(fields.get("MemAvailable"), Some(&2000000));
        assert_eq!(fields.get("Shmem"), Some(&250000));
        assert_eq!(fields.get("Dirty"), Some(&1200));
        assert_eq!(fields.get("SwapTotal"), Some(&4194300));
        assert_eq!(fields.get("SwapFree"), Some(&100000));
    }

    #[test]
    fn ignores_unparseable_lines() {
        let text = "MemTotal:       16384000 kB\nNotAField without a colon value\n";
        let fields = parse_meminfo(text).unwrap();
        assert_eq!(fields.len(), 1);
    }

    #[test]
    fn errors_on_empty_input() {
        assert!(parse_meminfo("").is_err());
    }

    #[test]
    fn parses_swappiness() {
        assert_eq!(parse_swappiness("60\n").unwrap(), 60);
    }

    #[test]
    fn errors_on_malformed_swappiness() {
        assert!(parse_swappiness("not-a-number").is_err());
    }

    #[test]
    fn parses_dirty_ratio_style_files() {
        assert_eq!(parse_small_uint_file("20\n", "vm.dirty_ratio").unwrap(), 20);
        assert_eq!(
            parse_small_uint_file("10\n", "vm.dirty_background_ratio").unwrap(),
            10
        );
    }

    #[test]
    fn swappiness_above_100_is_valid_on_modern_kernels() {
        // Linux 5.8 widened the range to 0-200.
        assert_eq!(parse_swappiness("180\n").unwrap(), 180);
    }

    #[test]
    fn meminfo_detail_maps_every_field() {
        let fields = parse_meminfo(FULL_MEMINFO).unwrap();
        let d = MeminfoDetail::from_fields(&fields);
        assert_eq!(d.buffers_kb, 9304);
        assert_eq!(d.cached_incl_shmem_kb, 248540);
        assert_eq!(d.swap_cached_kb, 1000);
        assert_eq!(d.active_file_kb, 27856);
        assert_eq!(d.inactive_file_kb, 215600);
        assert_eq!(d.inactive_anon_kb, 199604);
        assert_eq!(d.anon_pages_kb, 193944);
        assert_eq!(d.mapped_kb, 182236);
        assert_eq!(d.writeback_kb, 64);
        assert_eq!(d.sreclaimable_kb, 4404);
        assert_eq!(d.sunreclaim_kb, 16840);
        assert_eq!(d.kernel_stack_kb, 1516);
        assert_eq!(d.page_tables_kb, 2184);
        assert_eq!(d.percpu_kb, 496);
        assert_eq!(d.commit_limit_kb, 4111160);
        assert_eq!(d.committed_as_kb, 531396);
        assert_eq!(d.anon_huge_pages_kb, 2048);
        assert_eq!(d.hugepages_total, 4);
        assert_eq!(d.hugepages_free, 3);
        assert_eq!(d.hugepages_rsvd, 1);
        assert_eq!(d.hugepage_size_kb, 2048);
        assert_eq!(d.hugetlb_kb, 8192);
        assert_eq!(d.unevictable_kb, 8516);
        assert_eq!(d.mlocked_kb, 8564);
    }

    #[test]
    fn from_meminfo_fills_headline_fields_and_detail() {
        let data = MemoryRawData::from_meminfo(FULL_MEMINFO).unwrap();
        assert_eq!(data.mem_total_kb, 8_222_320);
        assert_eq!(data.mem_free_kb, 7_724_092);
        assert_eq!(data.mem_available_kb, 7_766_580);
        // The legacy `cached_kb` is Buffers + Cached: 9_304 + 248_540.
        assert_eq!(data.cached_kb, 257_844);
        assert_eq!(data.shmem_kb, 14_392);
        assert_eq!(data.dirty_kb, 1_720);
        assert_eq!(data.swap_total_kb, 2_097_148);
        assert_eq!(data.swap_free_kb, 2_097_148);
        assert_eq!(data.detail.sunreclaim_kb, 16_840);
        assert_eq!(data.detail.hugepages_total, 4);
    }

    #[test]
    fn from_meminfo_leaves_best_effort_sources_empty() {
        let data = MemoryRawData::from_meminfo(FIXTURE_MEMINFO).unwrap();
        assert!(data.processes.is_empty());
        assert!(data.swap_devices.is_empty());
        assert!(data.tmpfs_mounts.is_empty());
        assert!(data.sysv_shm.is_none());
        assert!(data.pressure.is_none());
        assert!(data.zfs_arc.is_none());
        // Derived figures still work on the minimal fixture.
        assert_eq!(data.used_kb(), 16_384_000 - 2_000_000);
        assert_eq!(data.swap_used_kb(), 4_194_300 - 100_000);
    }

    #[test]
    fn from_meminfo_rejects_empty_input() {
        assert!(MemoryRawData::from_meminfo("").is_err());
    }

    #[test]
    fn meminfo_detail_missing_fields_are_zero() {
        // The old, minimal fixture has none of the extended fields.
        let fields = parse_meminfo(FIXTURE_MEMINFO).unwrap();
        let d = MeminfoDetail::from_fields(&fields);
        assert_eq!(d.sreclaimable_kb, 0);
        assert_eq!(d.balloon_kb, 0);
    }

    #[test]
    fn derived_cache_figures_exclude_shared_memory() {
        let data = MemoryRawData {
            mem_total_kb: 16_384_000,
            cached_kb: 4_300_000, // Buffers 300_000 + Cached 4_000_000
            shmem_kb: 250_000,
            detail: MeminfoDetail {
                buffers_kb: 300_000,
                sreclaimable_kb: 100_000,
                ..Default::default()
            },
            ..Default::default()
        };
        // 4_300_000 - 300_000 buffers - 250_000 shmem
        assert_eq!(data.file_cache_kb(), 3_750_000);
        assert_eq!(data.reclaimable_cache_kb(), 300_000 + 3_750_000 + 100_000);
        // free(1)'s buff/cache keeps the shared memory in.
        assert_eq!(data.free_style_buff_cache_kb(), 4_400_000);
    }

    #[test]
    fn derived_figures_never_underflow() {
        let data = MemoryRawData {
            cached_kb: 10,
            shmem_kb: 500,
            mem_available_kb: 900,
            mem_total_kb: 100,
            ..Default::default()
        };
        assert_eq!(data.file_cache_kb(), 0);
        assert_eq!(data.used_kb(), 0);
    }

    #[test]
    fn percent_handles_zero_whole() {
        assert_eq!(percent(5, 0), 0.0);
        assert_eq!(percent(1, 4), 25.0);
    }

    #[test]
    fn bracketed_choice_picks_the_selected_word() {
        assert_eq!(
            parse_bracketed_choice("always [madvise] never\n").as_deref(),
            Some("madvise")
        );
        assert_eq!(
            parse_bracketed_choice("[always] madvise never").as_deref(),
            Some("always")
        );
        assert_eq!(
            parse_bracketed_choice("lzo lzo-rle lz4 [zstd]").as_deref(),
            Some("zstd")
        );
        assert_eq!(parse_bracketed_choice("always madvise never"), None);
        assert_eq!(parse_bracketed_choice("[]"), None);
    }

    #[test]
    fn u64_file_parses_or_is_none() {
        assert_eq!(parse_u64_file("67584\n"), Some(67584));
        assert_eq!(parse_u64_file("abc"), None);
        assert_eq!(parse_u64_file(""), None);
    }

    const SWAPS: &str = "\
Filename\t\t\t\tType\t\tSize\t\tUsed\t\tPriority
/dev/zram0                              partition\t4194300\t\t1048576\t\t100
/swapfile                               file\t\t2097148\t\t0\t\t-2
/dev/sda3                               partition\t8388604\t\t512\t\t-3
/my\\040swap                             file\t\t1024\t\t0\t\t-4
";

    #[test]
    fn parses_swap_areas_with_kinds_and_priorities() {
        let swaps = parse_proc_swaps(SWAPS);
        assert_eq!(swaps.len(), 4);
        assert_eq!(swaps[0].path, "/dev/zram0");
        assert_eq!(swaps[0].kind, SwapKind::Zram, "zram reports as 'partition'");
        assert_eq!(swaps[0].size_kb, 4194300);
        assert_eq!(swaps[0].used_kb, 1048576);
        assert_eq!(swaps[0].priority, 100);
        assert_eq!(swaps[1].kind, SwapKind::File);
        assert_eq!(swaps[1].priority, -2);
        assert_eq!(swaps[2].kind, SwapKind::Partition);
        assert_eq!(swaps[3].path, "/my swap", "kernel escapes spaces as \\040");
    }

    #[test]
    fn header_only_swaps_file_means_no_swap() {
        assert!(parse_proc_swaps("Filename\t\tType\t\tSize\tUsed\tPriority\n").is_empty());
        assert!(parse_proc_swaps("").is_empty());
    }

    #[test]
    fn zram_mm_stat_is_converted_to_kb() {
        // orig 3 GiB, compressed 1 GiB, used 1.1 GiB (+ the other columns).
        let text = "3221225472 1073741824 1181116006 0 1200000000 5000 0 0 0\n";
        let stats = parse_zram_mm_stat(text).unwrap();
        assert_eq!(stats.original_kb, 3_145_728);
        assert_eq!(stats.compressed_kb, 1_048_576);
        assert_eq!(stats.memory_used_kb, 1_153_433);
        assert!(parse_zram_mm_stat("").is_none());
        assert!(parse_zram_mm_stat("1 2").is_none());
    }

    #[test]
    fn parses_psi() {
        let text = "\
some avg10=1.50 avg60=12.25 avg300=3.00 total=987654
full avg10=0.00 avg60=2.10 avg300=0.50 total=12345
";
        let psi = parse_psi(text).unwrap();
        assert_eq!(psi.some.avg10, 1.5);
        assert_eq!(psi.some.avg60, 12.25);
        assert_eq!(psi.some.avg300, 3.0);
        assert_eq!(psi.some.total_us, 987_654);
        let full = psi.full.unwrap();
        assert_eq!(full.avg60, 2.1);
    }

    #[test]
    fn psi_without_a_some_line_is_unusable() {
        assert!(parse_psi("").is_none());
        assert!(parse_psi("full avg10=0.00 avg60=0.00 avg300=0.00 total=0").is_none());
        assert!(parse_psi("some avg10=oops avg60=0 avg300=0 total=0").is_none());
    }

    #[test]
    fn parses_vmstat_counters_and_sums_allocstall_zones() {
        let text = "\
nr_free_pages 1931023
pswpin 100
pswpout 250
pgmajfault 2298
allocstall_dma 1
allocstall_dma32 2
allocstall_normal 4
allocstall_movable 0
pgscan_kswapd 1000
pgscan_direct 300
pgsteal_kswapd 900
pgsteal_direct 250
workingset_refault_anon 7
workingset_refault_file 42
oom_kill 3
";
        let c = parse_vmstat(text).unwrap();
        assert_eq!(c.pswpin, 100);
        assert_eq!(c.pswpout, 250);
        assert_eq!(c.pgmajfault, 2298);
        assert_eq!(c.allocstall, 7);
        assert_eq!(c.pgscan_kswapd, 1000);
        assert_eq!(c.pgscan_direct, 300);
        assert_eq!(c.pgsteal_kswapd, 900);
        assert_eq!(c.pgsteal_direct, 250);
        assert_eq!(
            c.workingset_refault, 42,
            "the file counter is the one that matters"
        );
        assert_eq!(c.oom_kill, 3);
    }

    #[test]
    fn vmstat_on_an_older_kernel_uses_the_single_refault_counter() {
        let c = parse_vmstat("pswpin 1\nworkingset_refault 99\n").unwrap();
        assert_eq!(c.workingset_refault, 99);
    }

    #[test]
    fn unrelated_text_is_not_vmstat() {
        assert!(parse_vmstat("").is_none());
        assert!(parse_vmstat("hello world\nfoo bar\n").is_none());
    }

    const STATUS: &str = "\
Name:\tfirefox
Umask:\t0022
State:\tS (sleeping)
Pid:\t4242
VmPeak:\t 9000000 kB
VmRSS:\t 2500000 kB
RssAnon:\t 2100000 kB
RssFile:\t  300000 kB
RssShmem:\t  100000 kB
VmSwap:\t   64000 kB
Threads:\t68
";

    #[test]
    fn parses_process_status() {
        let p = parse_proc_status(4242, STATUS).unwrap();
        assert_eq!(p.pid, 4242);
        assert_eq!(p.name, "firefox");
        assert_eq!(p.rss_anon_kb, 2_100_000);
        assert_eq!(p.rss_file_kb, 300_000);
        assert_eq!(p.rss_shmem_kb, 100_000);
        assert_eq!(p.swap_kb, 64_000);
    }

    #[test]
    fn kernel_threads_and_pre_4_5_kernels_are_skipped() {
        // Kernel threads have no Vm*/Rss* lines at all.
        assert!(parse_proc_status(2, "Name:\tkthreadd\nState:\tS (sleeping)\n").is_none());
        // Old kernels have VmRSS but not the split.
        assert!(parse_proc_status(1, "Name:\tinit\nVmRSS:\t 100 kB\n").is_none());
        assert!(parse_proc_status(1, "").is_none());
    }

    #[test]
    fn process_names_with_spaces_survive() {
        let p = parse_proc_status(7, "Name:\tTab Process\nRssAnon:\t 10 kB\n").unwrap();
        assert_eq!(p.name, "Tab Process");
    }

    const DF_TMPFS: &str = "\
Filesystem     1024-blocks    Used Available Capacity Mounted on
tmpfs              8222320 3145728   5076592      39% /dev/shm
tmpfs              1644464    2048   1642416       1% /run
tmpfs              4096000       0   4096000       0% /tmp/my build
shm                  65536       4     65532       1% /var/lib/docker/containers/abc/mounts/shm
";

    #[test]
    fn parses_df_tmpfs_including_mount_points_with_spaces() {
        let mounts = parse_df_tmpfs(DF_TMPFS);
        assert_eq!(mounts.len(), 4);
        assert_eq!(mounts[0].mount_point, "/dev/shm");
        assert_eq!(mounts[0].size_kb, 8_222_320);
        assert_eq!(mounts[0].used_kb, 3_145_728);
        assert_eq!(mounts[2].mount_point, "/tmp/my build");
        assert_eq!(
            mounts[3].mount_point,
            "/var/lib/docker/containers/abc/mounts/shm"
        );
    }

    #[test]
    fn df_with_only_a_header_is_empty() {
        assert!(
            parse_df_tmpfs("Filesystem 1024-blocks Used Available Capacity Mounted on\n")
                .is_empty()
        );
        assert!(parse_df_tmpfs("").is_empty());
    }

    const SYSV: &str = "\
       key      shmid perms                  size  cpid  lpid nattch   uid   gid  cuid  cgid      atime      dtime      ctime                   rss                  swap
         0          0 600               134217728  1200  1200      0  1000  1000  1000  1000          0          0 1700000000             134217728                     0
  12345678          3 666                 4194304  1300  1301      2     0     0     0     0 1700000100          0 1700000000               2097152               2097152
";

    #[test]
    fn parses_sysv_segments_by_header_name() {
        let segs = parse_sysv_shm(SYSV);
        assert_eq!(segs.len(), 2);
        assert_eq!(segs[0].shmid, 0);
        assert_eq!(segs[0].size_kb, 131_072);
        assert_eq!(segs[0].nattch, 0, "orphan: nobody attached");
        assert_eq!(segs[0].rss_kb, 131_072);
        assert_eq!(segs[0].uid, 1000);
        assert_eq!(segs[1].shmid, 3);
        assert_eq!(segs[1].nattch, 2);
        assert_eq!(segs[1].rss_kb, 2048);
        assert_eq!(segs[1].swap_kb, 2048);
    }

    #[test]
    fn sysv_header_only_or_garbage_is_empty() {
        assert!(parse_sysv_shm("").is_empty());
        let header_only = SYSV.lines().next().unwrap();
        assert!(parse_sysv_shm(header_only).is_empty());
        assert!(parse_sysv_shm("not a table\n1 2 3\n").is_empty());
    }

    #[test]
    fn sysv_survives_a_kernel_with_an_extra_column() {
        let text = "\
 key shmid newcol perms size cpid lpid nattch uid rss swap
 0 9 x 600 8192 1 1 0 1000 4096 0
";
        let segs = parse_sysv_shm(text);
        assert_eq!(segs.len(), 1);
        assert_eq!(segs[0].shmid, 9);
        assert_eq!(segs[0].size_kb, 8);
        assert_eq!(segs[0].rss_kb, 4);
    }

    #[test]
    fn parses_zfs_arc_size_and_limit() {
        let text = "\
13 1 0x01 123 33456 1000 2000
name                            type data
hits                            4    1000
size                            4    21474836480
c_max                           4    34359738368
c_min                           4    2147483648
";
        let arc = parse_zfs_arcstats(text).unwrap();
        assert_eq!(arc.size_kb, 20_971_520);
        assert_eq!(arc.max_kb, 33_554_432);
        assert!(parse_zfs_arcstats("nothing useful").is_none());
    }

    #[test]
    fn reads_kernel_page_size_from_smaps() {
        let smaps = "\
00400000-00452000 r-xp 00000000 08:01 1234 /usr/bin/foo
Size:                328 kB
KernelPageSize:       64 kB
MMUPageSize:          64 kB
";
        assert_eq!(parse_kernel_page_size_kb(smaps), Some(64));
        assert_eq!(parse_kernel_page_size_kb("Size: 4 kB\n"), None);
    }

    #[test]
    fn collect_runs_on_this_system_without_error() {
        // The sandbox's own /proc: every best-effort source must degrade
        // quietly, and the required ones exist on any Linux.
        let data = collect().expect("memory collection should work on any Linux");
        assert!(data.mem_total_kb > 0);
        assert!(data.detail.anon_pages_kb <= data.mem_total_kb);
        assert!(
            data.processes.iter().any(|p| p.pid == std::process::id()),
            "the test process itself should be listed"
        );
    }
}
