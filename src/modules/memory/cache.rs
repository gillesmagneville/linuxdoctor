// SPDX-License-Identifier: GPL-3.0-only

//! Cached memory: the page cache and kernel file-name caches (MEM008) and
//! the pages waiting to be written back to disk (MEM005).

use crate::models::{Category, Confidence, Finding, Severity};

use super::collect::{percent, MemoryRawData};
use super::format::{kb, pct, Steps};

/// Below this share of RAM the file cache is considered squeezed — but
/// only when memory is also tight (a small cache on an idle machine just
/// means nothing has been read lately).
const SQUEEZED_FILE_LRU_PERCENT: f64 = 5.0;
const SQUEEZED_AVAILABLE_PERCENT: f64 = 10.0;

/// A cache this big starts to worry people reading `free`; that is when
/// the drop_caches myth is worth addressing.
const BIG_CACHE_PERCENT: f64 = 20.0;

/// Kernel default.
const DEFAULT_VFS_CACHE_PRESSURE: u64 = 100;

/// Slab caches this large (share of RAM) are worth explaining when the
/// administrator asked the kernel to hold on to them.
const BIG_SLAB_PERCENT: f64 = 10.0;

/// MEM008 — always reported. Explains what "cached" really contains, how
/// much of it is hot, and why emptying it is not an optimisation. Warns
/// only when the cache has been squeezed out by programs while memory is
/// tight, since that is when files get re-read from disk.
pub fn page_cache(data: &MemoryRawData) -> Finding {
    let d = &data.detail;
    let total = data.mem_total_kb;
    let cache = data.file_cache_kb();
    let cache_pct = percent(cache, total);
    let file_lru = d.active_file_kb + d.inactive_file_kb;
    let lru_known = file_lru > 0;
    let avail_pct = data.available_percent();
    let squeezed = lru_known
        && percent(file_lru, total) < SQUEEZED_FILE_LRU_PERCENT
        && avail_pct < SQUEEZED_AVAILABLE_PERCENT;
    let vfs = data.vm.vfs_cache_pressure;

    let (severity, confidence) = if squeezed {
        (Severity::Warning, Confidence::strong_indication(78))
    } else {
        (Severity::Info, Confidence::direct_observation())
    };

    let mut paragraphs = vec![format!(
        "The page cache holds {} ({} of RAM): copies of files recently read or written, \
         kept so the next access is served from memory instead of the disk. Disk-block \
         buffers add {}.",
        kb(cache),
        pct(cache_pct),
        kb(d.buffers_kb),
    )];

    if lru_known {
        paragraphs.push(format!(
            "{} of the file cache has not been touched recently (the kernel drops that \
             first) and {} is in active use. Running programs map {} of it.",
            kb(d.inactive_file_kb),
            kb(d.active_file_kb),
            kb(d.mapped_kb),
        ));
    }

    if d.sreclaimable_kb > 0 {
        paragraphs.push(format!(
            "Reclaimable kernel caches (the dentry and inode caches that remember file \
             names and metadata) add {}.",
            kb(d.sreclaimable_kb)
        ));
    }

    if squeezed {
        paragraphs.push(format!(
            "The file cache has shrunk to {} of RAM while only {} of memory is available. \
             Programs' private memory is crowding it out, so files that were cached are \
             now read from the disk again and again. This is what makes a busy machine \
             feel slow even when the disk itself is healthy.",
            pct(percent(file_lru, total)),
            pct(avail_pct),
        ));
    } else {
        paragraphs.push(
            "This memory is not wasted: it makes file access fast and is handed back to \
             programs the moment they ask for it."
                .to_string(),
        );
        if cache_pct >= BIG_CACHE_PERCENT {
            paragraphs.push(
                "A large cache is therefore a sign of a healthy machine, not a leak. \
                 Emptying it (echo 3 > /proc/sys/vm/drop_caches) frees nothing of lasting \
                 value: it only forces files to be read from the disk again and slows \
                 everything down until the cache is rebuilt. It is a benchmarking tool, \
                 not an optimisation."
                    .to_string(),
            );
        }
    }

    // vfs_cache_pressure: only worth a word when it departs from the
    // default in a way that has a visible effect.
    let slab_pct = percent(d.sreclaimable_kb, total);
    let mut restore_vfs = false;
    if let Some(v) = vfs {
        if v > DEFAULT_VFS_CACHE_PRESSURE {
            restore_vfs = true;
            paragraphs.push(format!(
                "vm.vfs_cache_pressure is {v} (default {DEFAULT_VFS_CACHE_PRESSURE}): the kernel \
                 drops file-name and metadata caches more eagerly than file contents. That \
                 saves a little memory but makes directory listings, find, git and backups \
                 slower."
            ));
        } else if v < DEFAULT_VFS_CACHE_PRESSURE && slab_pct >= BIG_SLAB_PERCENT {
            restore_vfs = true;
            paragraphs.push(format!(
                "vm.vfs_cache_pressure is {v} (default {DEFAULT_VFS_CACHE_PRESSURE}), so the kernel \
                 clings to its file-name caches, which now take {} ({} of RAM). They are \
                 still reclaimable, but they are released later than usual.",
                kb(d.sreclaimable_kb),
                pct(slab_pct),
            ));
        }
    }

    if data.zfs_arc.is_some() {
        paragraphs.push(
            "ZFS keeps its own cache (the ARC) outside the page cache; it is described \
             under Kernel memory."
                .to_string(),
        );
    }

    let mut builder = Finding::builder(
        "MEM008",
        "Page Cache",
        Category::Memory,
        severity,
        confidence,
    )
    .evidence("page_cache_kb", cache.to_string())
    .evidence("page_cache_percent", format!("{cache_pct:.1}"))
    .evidence("buffers_kb", d.buffers_kb.to_string())
    .evidence("slab_reclaimable_kb", d.sreclaimable_kb.to_string());
    if lru_known {
        builder = builder
            .evidence("active_file_kb", d.active_file_kb.to_string())
            .evidence("inactive_file_kb", d.inactive_file_kb.to_string())
            .evidence("mapped_kb", d.mapped_kb.to_string());
    }
    if let Some(v) = vfs {
        builder = builder.evidence("vm.vfs_cache_pressure", v.to_string());
    }
    builder = builder.explanation(paragraphs.join("\n\n"));

    if squeezed || restore_vfs {
        let mut steps = Steps::new();
        if squeezed {
            steps = steps
                .step(
                    "Give the cache its memory back by reducing what programs hold: every GB \
                     freed in private memory becomes cache again. The Used memory page lists \
                     the largest consumers.",
                    &[],
                )
                .step(
                    "Check that files really are being re-read from the disk (high 'bi' with \
                     little free memory, and I/O pressure above a few percent):",
                    &["vmstat 1 5", "cat /proc/pressure/io"],
                )
                .step(
                    "If the machine serves files or runs a database whose working set is \
                     larger than RAM, no tuning will fix it: add RAM, or spread the data \
                     over more machines.",
                    &[],
                );
        }
        if restore_vfs {
            steps = steps.step_owned(
                format!(
                    "Return vm.vfs_cache_pressure to its default of {DEFAULT_VFS_CACHE_PRESSURE}:"
                ),
                super::format::sysctl_commands(
                    &format!("vm.vfs_cache_pressure={DEFAULT_VFS_CACHE_PRESSURE}"),
                    "99-vfs-cache-pressure.conf",
                ),
            );
            steps = steps.step(
                "If it was set deliberately (for example by a tuning profile), check what applies it:",
                &["grep -r vfs_cache_pressure /etc/sysctl.conf /etc/sysctl.d /usr/lib/sysctl.d"],
            );
        }
        builder = builder.recommendation(steps.build());
    }
    builder.build()
}

/// What the dirty-page thresholds are measured against: memory the kernel
/// is willing to fill with dirty data — free memory plus file cache — not
/// total RAM. Falls back to total RAM when the file LRU sizes are not
/// known. The bool is true when that fallback was used.
fn dirtyable_kb(data: &MemoryRawData) -> (u64, bool) {
    let lru = data.detail.active_file_kb + data.detail.inactive_file_kb;
    if lru > 0 {
        (data.mem_free_kb + lru, false)
    } else {
        (data.mem_total_kb, true)
    }
}

/// One of the two thresholds, in kB: bytes override ratio.
fn threshold_kb(bytes: Option<u64>, ratio: u8, dirtyable: u64) -> u64 {
    match bytes {
        Some(b) if b > 0 => b / 1024,
        _ => dirtyable * u64::from(ratio) / 100,
    }
}

/// MEM005 — always reported. Compares the dirty and in-writeback pages
/// with this system's *own* thresholds, computed the way the kernel does
/// (a share of dirtyable memory, or fixed bytes when vm.dirty_bytes is
/// set) — not with assumed defaults, since these are commonly tuned.
///
/// Three zones, as in the kernel: below the background threshold nothing
/// happens; above it the flusher threads write in the background (normal
/// under load); from the midpoint to the hard limit writers are throttled
/// and slowed down; at the hard limit they block.
pub fn dirty_pages(data: &MemoryRawData) -> Finding {
    let total = data.mem_total_kb;
    let (dirtyable, estimated) = dirtyable_kb(data);
    let current = data.dirty_kb + data.detail.writeback_kb;
    let dirty_pct = percent(data.dirty_kb, total);

    let bytes_mode = data.vm.dirty_bytes.unwrap_or(0) > 0;
    let bg_bytes_mode = data.vm.dirty_background_bytes.unwrap_or(0) > 0;
    let limit = threshold_kb(data.vm.dirty_bytes, data.dirty_ratio, dirtyable);
    let background = threshold_kb(
        data.vm.dirty_background_bytes,
        data.dirty_background_ratio,
        dirtyable,
    );

    let base = |severity, confidence| {
        Finding::builder(
            "MEM005",
            "Dirty Page / Writeback Pressure",
            Category::Memory,
            severity,
            confidence,
        )
        .evidence("dirty_kb", data.dirty_kb.to_string())
        .evidence("dirty_percent", format!("{dirty_pct:.2}"))
        .evidence("writeback_kb", data.detail.writeback_kb.to_string())
        .evidence(
            "dirty_background_ratio",
            data.dirty_background_ratio.to_string(),
        )
        .evidence("dirty_ratio", data.dirty_ratio.to_string())
    };

    // Neither a ratio nor a byte value to compare with: say so instead of
    // comparing with zero, which would flag any non-zero amount.
    if limit == 0 || background == 0 {
        return base(Severity::Info, Confidence::direct_observation())
            .explanation(format!(
                "{} of memory is currently dirty (modified, not yet written to disk). This \
                 system's vm.dirty_ratio or vm.dirty_background_ratio is 0, which normally \
                 means the byte-based settings (vm.dirty_bytes / vm.dirty_background_bytes) \
                 are in effect, but their values could not be read, so no comparison is made.",
                pct(dirty_pct)
            ))
            .build();
    }

    let throttle_start = (background + limit) / 2;
    let (severity, confidence, zone) = if current >= limit {
        (
            Severity::Error,
            Confidence::strong_indication(87),
            Zone::Blocking,
        )
    } else if current >= throttle_start {
        (
            Severity::Warning,
            Confidence::strong_indication(78),
            Zone::Throttled,
        )
    } else if current >= background {
        (
            Severity::Info,
            Confidence::direct_observation(),
            Zone::Flushing,
        )
    } else {
        (
            Severity::Info,
            Confidence::direct_observation(),
            Zone::Quiet,
        )
    };

    let current_pct_of_dirtyable = percent(current, dirtyable);
    let basis = if estimated {
        format!(
            "{} (total RAM; the file cache sizes were not available)",
            kb(dirtyable)
        )
    } else {
        format!("{} (free memory plus file cache)", kb(dirtyable))
    };
    let limits = format!(
        "Background writeback starts at {} and writers are slowed from {}; the hard limit is {}. \
         These are measured against {}.",
        kb(background),
        kb(throttle_start),
        kb(limit),
        basis,
    );

    let explanation = match zone {
        Zone::Blocking => format!(
            "{} is waiting to be written to disk ({} of what can be dirtied) — at or above \
             the hard limit of {}. Programs that write now block until the disk catches up, \
             which shows up as freezes and I/O stalls.\n\n{limits}",
            kb(current),
            pct(current_pct_of_dirtyable),
            kb(limit),
        ),
        Zone::Throttled => format!(
            "{} is waiting to be written to disk ({} of what can be dirtied). That is past \
             the point where the kernel starts deliberately slowing the programs that \
             write, so they are already being held back by the disk's speed.\n\n{limits}",
            kb(current),
            pct(current_pct_of_dirtyable),
        ),
        Zone::Flushing => format!(
            "{} is waiting to be written to disk ({} of what can be dirtied). That is above \
             the background threshold, so the kernel is writing it out right now. This is \
             normal during a large copy, download or database checkpoint.\n\n{limits}",
            kb(current),
            pct(current_pct_of_dirtyable),
        ),
        Zone::Quiet => format!(
            "{} is waiting to be written to disk ({} of what can be dirtied), comfortably \
             below the background threshold of {}.\n\n{limits}",
            kb(current),
            pct(current_pct_of_dirtyable),
            kb(background),
        ),
    };

    let mut builder = base(severity, confidence)
        .evidence("dirtyable_kb", dirtyable.to_string())
        .evidence("background_threshold_kb", background.to_string())
        .evidence("hard_limit_kb", limit.to_string());
    if let Some(v) = data.vm.dirty_expire_centisecs {
        builder = builder.evidence("vm.dirty_expire_centisecs", v.to_string());
    }
    if let Some(v) = data.vm.dirty_writeback_centisecs {
        builder = builder.evidence("vm.dirty_writeback_centisecs", v.to_string());
    }
    if bytes_mode {
        builder = builder.evidence(
            "vm.dirty_bytes",
            data.vm.dirty_bytes.unwrap_or(0).to_string(),
        );
    }
    if bg_bytes_mode {
        builder = builder.evidence(
            "vm.dirty_background_bytes",
            data.vm.dirty_background_bytes.unwrap_or(0).to_string(),
        );
    }

    let mut explanation = explanation;
    let oversized = !bytes_mode && limit >= OVERSIZED_LIMIT_KB;
    if oversized {
        explanation.push_str(&format!(
            "\n\nOn this machine the ratio settings allow up to {} of dirty data to pile up \
             before writers are blocked. Flushing that much at once can freeze programs for \
             many seconds on a slow disk; many administrators cap it with fixed byte limits \
             instead.",
            kb(limit)
        ));
    }
    builder = builder.explanation(explanation);

    if severity > Severity::Info {
        builder = builder.recommendation(dirty_steps(data, limit).build());
    } else if oversized {
        builder = builder.recommendation(
            Steps::new()
                .step_owned(
                    "Optional: cap the amount of dirty data with fixed limits (256 MB to start \
                     background writeback, 1 GB before writers block). Setting the byte values \
                     replaces the ratios:",
                    byte_limit_commands(),
                )
                .build(),
        );
    }
    builder.build()
}

/// Hard limit above which the ratio settings are considered oversized: 4 GiB.
const OVERSIZED_LIMIT_KB: u64 = 4 * 1024 * 1024;

enum Zone {
    Quiet,
    Flushing,
    Throttled,
    Blocking,
}

fn byte_limit_commands() -> Vec<String> {
    vec![
        "sudo sysctl vm.dirty_background_bytes=268435456 vm.dirty_bytes=1073741824".to_string(),
        "printf 'vm.dirty_background_bytes = 268435456\\nvm.dirty_bytes = 1073741824\\n' | sudo tee /etc/sysctl.d/99-dirty.conf"
            .to_string(),
    ]
}

fn dirty_steps(data: &MemoryRawData, limit_kb: u64) -> Steps {
    let mut steps = Steps::new()
        .step(
            "See what is writing, and whether the disk keeps up (watch the Dirty and \
             Writeback lines, and the %util / await columns of iostat):",
            &[
                "watch -n1 \"grep -E 'Dirty|Writeback:' /proc/meminfo\"",
                "iostat -x 1 5     # needs the 'sysstat' package",
            ],
        )
        .step(
            "If Writeback stays high and Dirty never shrinks, the storage is not completing \
             writes (failing disk, stalled network share, USB device). Check the kernel log \
             and the Storage findings of this report:",
            &["sudo dmesg -T | grep -i -E 'blocked for more than|I/O error|timeout'"],
        )
        .step(
            "Force everything out to disk and see how long it takes; if this hangs, the \
             problem is the storage, not the settings:",
            &["time sync"],
        );
    if data.vm.dirty_bytes.unwrap_or(0) == 0 && limit_kb >= 1024 * 1024 {
        steps = steps.step_owned(
            "On a machine with lots of RAM, flush earlier and cap the backlog with fixed \
             limits so a burst of writes cannot freeze programs (256 MB to start background \
             writeback, 1 GB before writers block):",
            byte_limit_commands(),
        );
    }
    steps
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::modules::memory::collect::VmTunables;
    use crate::modules::memory::test_support::{evidence, healthy};

    // ---- MEM008 page cache ------------------------------------------

    fn with_file_lru(mut d: MemoryRawData) -> MemoryRawData {
        d.detail.active_file_kb = 1_500_000;
        d.detail.inactive_file_kb = 3_000_000;
        d.detail.mapped_kb = 700_000;
        d
    }

    #[test]
    fn page_cache_excludes_shared_memory_and_reports_hot_and_cold() {
        let f = page_cache(&with_file_lru(healthy()));
        assert_eq!(f.id, "MEM008");
        assert_eq!(f.severity, Severity::Info);
        assert!(f.recommendation.is_none());
        // 5.0M cached+buffers - 200k buffers - 300k shmem
        assert_eq!(evidence(&f, "page_cache_kb"), Some("4500000"));
        assert_eq!(evidence(&f, "inactive_file_kb"), Some("3000000"));
        assert!(f.explanation.contains("has not been touched recently"));
        assert!(f.explanation.contains("not wasted"));
    }

    #[test]
    fn big_cache_gets_the_drop_caches_explanation() {
        let mut d = with_file_lru(healthy());
        d.cached_kb = 8_000_000; // 7.5M file cache = 47% of RAM
        let f = page_cache(&d);
        assert!(f.explanation.contains("drop_caches"));
        assert!(f.explanation.contains("not an optimisation"));
    }

    #[test]
    fn small_cache_does_not_lecture_about_drop_caches() {
        let mut d = with_file_lru(healthy());
        d.cached_kb = 1_000_000;
        assert!(!page_cache(&d).explanation.contains("drop_caches"));
    }

    #[test]
    fn squeezed_cache_under_memory_pressure_warns_with_steps() {
        let mut d = healthy();
        d.mem_available_kb = 1_000_000; // 6%
        d.detail.active_file_kb = 200_000;
        d.detail.inactive_file_kb = 300_000; // 3% of RAM
        let f = page_cache(&d);
        assert_eq!(f.severity, Severity::Warning);
        assert!(f.explanation.contains("crowding it out"));
        let rec = f.recommendation.unwrap();
        assert!(rec.starts_with("1. "));
        assert!(rec.contains("vmstat 1 5"));
        assert!(rec.contains("/proc/pressure/io"));
    }

    #[test]
    fn small_cache_with_plenty_of_memory_is_not_a_problem() {
        let mut d = healthy();
        d.detail.active_file_kb = 100_000;
        d.detail.inactive_file_kb = 100_000; // 1.25% of RAM, but 56% available
        assert_eq!(page_cache(&d).severity, Severity::Info);
    }

    #[test]
    fn unknown_file_lru_never_claims_squeeze() {
        let mut d = healthy();
        d.mem_available_kb = 500_000;
        assert_eq!(page_cache(&d).severity, Severity::Info);
    }

    #[test]
    fn aggressive_vfs_cache_pressure_is_explained_and_reverted() {
        let mut d = with_file_lru(healthy());
        d.vm.vfs_cache_pressure = Some(500);
        let f = page_cache(&d);
        assert!(f.explanation.contains("vfs_cache_pressure is 500"));
        let rec = f.recommendation.unwrap();
        assert!(rec.contains("sudo sysctl vm.vfs_cache_pressure=100"));
        assert!(rec.contains("/etc/sysctl.d/99-vfs-cache-pressure.conf"));
        assert_eq!(f.severity, Severity::Info, "a setting is not a fault");
    }

    #[test]
    fn low_vfs_cache_pressure_matters_only_when_slab_is_big() {
        let mut d = with_file_lru(healthy());
        d.vm.vfs_cache_pressure = Some(50);
        assert!(page_cache(&d).recommendation.is_none(), "slab is only 2.5%");
        d.detail.sreclaimable_kb = 3_000_000; // 18.75%
        let f = page_cache(&d);
        assert!(f.explanation.contains("clings"));
        assert!(f.recommendation.is_some());
    }

    #[test]
    fn default_vfs_cache_pressure_is_silent() {
        let mut d = with_file_lru(healthy());
        d.vm.vfs_cache_pressure = Some(100);
        let f = page_cache(&d);
        assert!(!f.explanation.contains("vfs_cache_pressure"));
        assert_eq!(evidence(&f, "vm.vfs_cache_pressure"), Some("100"));
    }

    #[test]
    fn zfs_users_are_pointed_to_the_arc() {
        let mut d = with_file_lru(healthy());
        d.zfs_arc = Some(crate::modules::memory::collect::ZfsArc {
            size_kb: 1,
            max_kb: 2,
        });
        assert!(page_cache(&d).explanation.contains("ARC"));
    }

    // ---- MEM005 dirty pages -----------------------------------------

    #[test]
    fn dirty_pages_quiet_by_default() {
        let f = dirty_pages(&healthy());
        assert_eq!(f.id, "MEM005");
        assert_eq!(f.severity, Severity::Info);
        assert!(f.explanation.contains("comfortably below"));
        assert!(f.recommendation.is_none());
    }

    #[test]
    fn thresholds_are_measured_against_dirtyable_memory_not_total_ram() {
        let mut d = healthy();
        d.detail.active_file_kb = 1_000_000;
        d.detail.inactive_file_kb = 1_000_000;
        // dirtyable = free 4.0M + 2.0M = 6.0M -> 10% background = 600k
        let f = dirty_pages(&d);
        assert_eq!(evidence(&f, "dirtyable_kb"), Some("6000000"));
        assert_eq!(evidence(&f, "background_threshold_kb"), Some("600000"));
        assert_eq!(evidence(&f, "hard_limit_kb"), Some("1200000"));
    }

    #[test]
    fn falls_back_to_total_ram_when_file_lru_is_unknown() {
        let f = dirty_pages(&healthy());
        assert_eq!(evidence(&f, "dirtyable_kb"), Some("16000000"));
        assert!(f
            .explanation
            .contains("file cache sizes were not available"));
    }

    #[test]
    fn background_zone_is_info_and_says_it_is_normal() {
        let mut d = healthy();
        d.dirty_kb = 2_000_000; // bg 1.6M, throttle 2.4M, limit 3.2M
        let f = dirty_pages(&d);
        assert_eq!(f.severity, Severity::Info);
        assert!(f.explanation.contains("normal during a large copy"));
    }

    #[test]
    fn throttled_zone_warns() {
        let mut d = healthy();
        d.dirty_kb = 2_600_000;
        let f = dirty_pages(&d);
        assert_eq!(f.severity, Severity::Warning);
        assert!(f.explanation.contains("slowing the programs"));
        assert!(f.recommendation.unwrap().contains("iostat -x 1 5"));
    }

    #[test]
    fn blocking_zone_is_an_error() {
        let mut d = healthy();
        d.dirty_kb = 3_400_000;
        let f = dirty_pages(&d);
        assert_eq!(f.severity, Severity::Error);
        assert!(f.explanation.contains("block"));
    }

    #[test]
    fn writeback_counts_toward_the_limit() {
        let mut d = healthy();
        d.dirty_kb = 1_000_000;
        d.detail.writeback_kb = 2_300_000; // 3.3M >= 3.2M limit
        assert_eq!(dirty_pages(&d).severity, Severity::Error);
    }

    #[test]
    fn byte_limits_replace_ratios() {
        let mut d = healthy();
        d.dirty_ratio = 0;
        d.dirty_background_ratio = 0;
        d.vm = VmTunables {
            dirty_bytes: Some(1_073_741_824),          // 1 GiB = 1_048_576 kB
            dirty_background_bytes: Some(268_435_456), // 256 MiB = 262_144 kB
            ..Default::default()
        };
        d.dirty_kb = 400_000; // above the 262_144 kB background, below the 655_360 midpoint
        let f = dirty_pages(&d);
        assert_eq!(evidence(&f, "hard_limit_kb"), Some("1048576"));
        assert_eq!(evidence(&f, "background_threshold_kb"), Some("262144"));
        assert_eq!(f.severity, Severity::Info);
        d.dirty_kb = 700_000;
        assert_eq!(dirty_pages(&d).severity, Severity::Warning);
    }

    #[test]
    fn unreadable_byte_settings_are_reported_honestly() {
        let mut d = healthy();
        d.dirty_ratio = 0; // bytes mode, but the byte values are unknown
        d.dirty_kb = 5_000_000;
        let f = dirty_pages(&d);
        assert_eq!(f.severity, Severity::Info);
        assert!(f.explanation.contains("dirty_bytes"));
        assert!(f.explanation.contains("no comparison"));
    }

    #[test]
    fn huge_ratio_based_limit_gets_an_optional_cap_suggestion() {
        let mut d = healthy();
        d.mem_total_kb = 64 * 1024 * 1024;
        d.mem_free_kb = 20 * 1024 * 1024;
        d.mem_available_kb = 40 * 1024 * 1024;
        d.detail.active_file_kb = 10 * 1024 * 1024;
        d.detail.inactive_file_kb = 20 * 1024 * 1024;
        // dirtyable = 50 GiB -> 20% limit = 10 GiB
        let f = dirty_pages(&d);
        assert_eq!(f.severity, Severity::Info);
        assert!(f.explanation.contains("fixed byte limits"));
        let rec = f.recommendation.unwrap();
        assert!(rec.contains("vm.dirty_background_bytes=268435456"));
        assert!(rec.contains("/etc/sysctl.d/99-dirty.conf"));
    }

    #[test]
    fn no_cap_suggestion_once_bytes_are_already_in_use() {
        let mut d = healthy();
        d.mem_total_kb = 64 * 1024 * 1024;
        d.mem_free_kb = 20 * 1024 * 1024;
        d.dirty_ratio = 0;
        d.dirty_background_ratio = 0;
        d.vm.dirty_bytes = Some(1_073_741_824);
        d.vm.dirty_background_bytes = Some(268_435_456);
        assert!(dirty_pages(&d).recommendation.is_none());
    }

    #[test]
    fn warning_includes_cap_step_only_on_big_machines() {
        let mut d = healthy();
        d.dirty_kb = 2_600_000; // small machine, 3.2M limit ≈ 3 GiB
        let small = dirty_pages(&d).recommendation.unwrap();
        assert!(
            small.contains("vm.dirty_bytes=1073741824"),
            "3 GiB limit is worth capping"
        );
        d.mem_total_kb = 2_000_000;
        d.mem_free_kb = 500_000;
        d.mem_available_kb = 800_000;
        d.dirty_kb = 330_000; // limit 400k kB -> below 1 GiB
        let tiny = dirty_pages(&d).recommendation.unwrap();
        assert!(!tiny.contains("vm.dirty_bytes"), "{tiny}");
    }
}
