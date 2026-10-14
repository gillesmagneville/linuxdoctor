// SPDX-License-Identifier: GPL-3.0-only

//! "Used memory": the overview every report starts with (MEM004), the
//! breakdown of where RAM actually goes and who is using it (MEM007), and
//! the emergency finding for a machine that is out of options (MEM003).

use crate::models::{Category, Confidence, Finding, Severity};

use super::collect::{percent, MemoryRawData};
use super::format::{
    group_detail, group_label, kb, pct, suggested_swap_gb, swapfile_commands, top_by_anon, Steps,
};

/// How many consumers MEM007 lists.
const TOP_CONSUMERS: usize = 5;

/// A row below this share of RAM is left out of the printed breakdown
/// (it is still in the evidence).
const MIN_ROW_PERCENT: f64 = 0.5;

/// The "not attributed" remainder is explained once it is this large.
const UNATTRIBUTED_NOTE_PERCENT: f64 = 5.0;
const UNATTRIBUTED_NOTE_MIN_KB: u64 = 512 * 1024;

/// A program holding less than this share of RAM is not listed as a
/// consumer (except when it is the largest).
const MIN_CONSUMER_PERCENT: f64 = 0.1;

/// Plain-language reading of "available" as a share of RAM.
pub fn availability_band(available_percent: f64) -> &'static str {
    if available_percent >= 25.0 {
        "comfortable"
    } else if available_percent >= 10.0 {
        "adequate"
    } else if available_percent >= 5.0 {
        "tight"
    } else {
        "very tight"
    }
}

/// MEM004 — always reported, always at the top. This is the "why is my
/// free RAM low" answer: it separates memory that is really in use from
/// cache the kernel will give back, and spells out that the `buff/cache`
/// figure of `free(1)` also contains shared memory, which it will not.
pub fn overview(data: &MemoryRawData) -> Finding {
    let used = data.used_kb();
    let used_pct = percent(used, data.mem_total_kb);
    let avail_pct = data.available_percent();
    let buff_cache = data.free_style_buff_cache_kb();
    let reclaimable = data.reclaimable_cache_kb();

    let explanation = format!(
        "Of {total} of RAM, {used} ({used_pct}) is in use by programs and the kernel, \
         and {available} ({avail_pct}) is available for new allocations without swapping \
         — {band}. These are the 'used' and 'available' columns of free(1).\n\n\
         Only {free} is completely unused, and that is normal: Linux fills spare RAM with \
         cache and hands it back the moment a program asks. free(1) shows {buff_cache} as \
         'buff/cache', but that figure includes {shmem} of shared memory (tmpfs, /dev/shm, \
         graphics buffers) which stays in RAM; the part the kernel can genuinely give back \
         is {reclaimable}.\n\n\
         What matters is 'available', not 'free'. The Used memory, Page cache, Shared \
         memory, Swap, Pressure and Kernel tuning pages break this number down.",
        total = kb(data.mem_total_kb),
        used = kb(used),
        used_pct = pct(used_pct),
        available = kb(data.mem_available_kb),
        avail_pct = pct(avail_pct),
        band = availability_band(avail_pct),
        free = kb(data.mem_free_kb),
        buff_cache = kb(buff_cache),
        shmem = kb(data.shmem_kb),
        reclaimable = kb(reclaimable),
    );

    Finding::builder(
        "MEM004",
        "Memory Usage Overview",
        Category::Memory,
        Severity::Info,
        Confidence::direct_observation(),
    )
    .evidence("total_kb", data.mem_total_kb.to_string())
    .evidence("used_kb", used.to_string())
    .evidence("used_percent", format!("{used_pct:.1}"))
    .evidence("free_kb", data.mem_free_kb.to_string())
    .evidence("shared_kb", data.shmem_kb.to_string())
    .evidence("buff_cache_kb", buff_cache.to_string())
    .evidence("reclaimable_cache_kb", reclaimable.to_string())
    .evidence("available_kb", data.mem_available_kb.to_string())
    .evidence("available_percent", format!("{avail_pct:.1}"))
    // Historic key: Buffers + Cached, shared memory included.
    .evidence("cached_kb", data.cached_kb.to_string())
    .explanation(explanation)
    .build()
}

/// One line of the "where the RAM goes" table.
struct Row {
    label: &'static str,
    kb: u64,
}

/// Where every kB of RAM is, from /proc/meminfo's own accounting. `None`
/// when the extended meminfo fields are missing (then the table would be
/// all "not attributed", which would be a lie rather than a breakdown).
fn breakdown(data: &MemoryRawData) -> Option<Vec<Row>> {
    let d = &data.detail;
    if d.anon_pages_kb == 0 {
        return None;
    }
    let hugetlb = d.hugetlb_kb.max(d.hugepages_total * d.hugepage_size_kb);
    let kernel_misc = d.kernel_stack_kb + d.page_tables_kb + d.percpu_kb;

    let mut rows = vec![
        Row {
            label: "Programs (private memory)",
            kb: d.anon_pages_kb,
        },
        Row {
            label: "Page cache (files)",
            kb: data.file_cache_kb(),
        },
        Row {
            label: "Shared memory (tmpfs, shm)",
            kb: data.shmem_kb,
        },
        Row {
            label: "Buffers",
            kb: d.buffers_kb,
        },
        Row {
            label: "Reclaimable kernel caches",
            kb: d.sreclaimable_kb,
        },
        Row {
            label: "Kernel memory (not reclaimable)",
            kb: d.sunreclaim_kb,
        },
        Row {
            label: "Kernel stacks, page tables",
            kb: kernel_misc,
        },
        Row {
            label: "Reserved huge pages",
            kb: hugetlb,
        },
        Row {
            label: "Free",
            kb: data.mem_free_kb,
        },
    ];
    let accounted: u64 = rows.iter().map(|r| r.kb).sum();
    let remainder = data.mem_total_kb.saturating_sub(accounted);
    if let Some(arc) = &data.zfs_arc {
        let arc_kb = arc.size_kb.min(remainder);
        rows.push(Row {
            label: "ZFS ARC cache",
            kb: arc_kb,
        });
        rows.push(Row {
            label: "Not attributed",
            kb: remainder - arc_kb,
        });
    } else {
        rows.push(Row {
            label: "Not attributed",
            kb: remainder,
        });
    }
    Some(rows)
}

/// Memory that cannot be dropped like cache: programs' private memory
/// (it can only be swapped), shared memory, non-reclaimable kernel memory
/// and reserved huge pages.
fn pinned_kb(data: &MemoryRawData) -> u64 {
    let d = &data.detail;
    let hugetlb = d.hugetlb_kb.max(d.hugepages_total * d.hugepage_size_kb);
    d.anon_pages_kb
        + data.shmem_kb
        + d.sunreclaim_kb
        + d.kernel_stack_kb
        + d.page_tables_kb
        + d.percpu_kb
        + hugetlb
}

/// MEM007 — always reported. Answers "what is my RAM actually used for,
/// and by whom?": a full breakdown from /proc/meminfo's own accounting,
/// plus the biggest consumers by private memory (counted once, so a
/// browser's forty processes are not inflated by shared libraries).
/// Severity follows how little memory is left available.
pub fn used_memory(data: &MemoryRawData) -> Finding {
    let used = data.used_kb();
    let used_pct = percent(used, data.mem_total_kb);
    let avail_pct = data.available_percent();
    let top = top_by_anon(&data.processes, TOP_CONSUMERS);
    let rows = breakdown(data);

    let (severity, confidence) = if avail_pct < 5.0 {
        (Severity::Error, Confidence::correlated(90))
    } else if avail_pct < 10.0 {
        (Severity::Warning, Confidence::strong_indication(82))
    } else {
        (Severity::Info, Confidence::direct_observation())
    };

    let mut paragraphs: Vec<String> = Vec::new();

    paragraphs.push(match severity {
        Severity::Error => format!(
            "Only {} of RAM ({}) is still available while {} ({}) is in use. At this \
             level the kernel is {}, programs stall, and the OOM killer is close.",
            kb(data.mem_available_kb),
            pct(avail_pct),
            kb(used),
            pct(used_pct),
            if data.has_swap() {
                "reclaiming cache and swapping constantly"
            } else {
                "reclaiming cache constantly with no swap to fall back on"
            },
        ),
        Severity::Warning => format!(
            "Only {} of RAM ({}) is still available while {} ({}) is in use. That is \
             little headroom: a new workload or a memory spike will push the system \
             into reclaiming and swapping.",
            kb(data.mem_available_kb),
            pct(avail_pct),
            kb(used),
            pct(used_pct),
        ),
        _ => format!(
            "{} of RAM ({}) is in use and {} ({}) is available — {}.",
            kb(used),
            pct(used_pct),
            kb(data.mem_available_kb),
            pct(avail_pct),
            availability_band(avail_pct),
        ),
    });

    let mut builder = Finding::builder(
        "MEM007",
        "Used Memory and Top Consumers",
        Category::Memory,
        severity,
        confidence,
    )
    .evidence("used_kb", used.to_string())
    .evidence("used_percent", format!("{used_pct:.1}"))
    .evidence("available_percent", format!("{avail_pct:.1}"));

    if let Some(rows) = &rows {
        let mut table = format!("Where the {} of RAM goes right now:", kb(data.mem_total_kb));
        let mut smaller_kb = 0;
        let mut smaller_rows = 0;
        for row in rows {
            let share = percent(row.kb, data.mem_total_kb);
            if share >= MIN_ROW_PERCENT || row.label == "Free" {
                table.push_str(&format!(
                    "\n  {:<33}{:>9}  {:>6}",
                    row.label,
                    kb(row.kb),
                    pct(share)
                ));
            } else {
                smaller_kb += row.kb;
                smaller_rows += 1;
            }
        }
        // Keep the table adding up to the whole: what was left out of the
        // printout is summed into one line.
        if smaller_rows > 0 && smaller_kb > 0 {
            table.push_str(&format!(
                "\n  {:<33}{:>9}  {:>6}",
                "Smaller items (each under 0.5%)",
                kb(smaller_kb),
                pct(percent(smaller_kb, data.mem_total_kb))
            ));
        }
        paragraphs.push(table);

        if let Some(row) = rows.iter().find(|r| r.label == "Not attributed") {
            let share = percent(row.kb, data.mem_total_kb);
            if share >= UNATTRIBUTED_NOTE_PERCENT && row.kb >= UNATTRIBUTED_NOTE_MIN_KB {
                paragraphs.push(format!(
                    "{} ({}) of RAM is not itemised by the kernel's own accounting: typically \
                     graphics memory and other driver buffers (vmalloc) and, in a virtual \
                     machine, memory the hypervisor has taken back or not yet handed over.",
                    kb(row.kb),
                    pct(share)
                ));
            }
        }

        let pinned = pinned_kb(data);
        paragraphs.push(format!(
            "About {} ({}) of RAM is memory that cannot simply be dropped: programs' \
             private memory (it can only be swapped out), shared memory, non-reclaimable \
             kernel memory and reserved huge pages. The rest is cache the kernel can take \
             back on demand.",
            kb(pinned),
            pct(percent(pinned, data.mem_total_kb)),
        ));

        for row in rows {
            let key = match row.label {
                "Programs (private memory)" => "anon_kb",
                "Page cache (files)" => "page_cache_kb",
                "Shared memory (tmpfs, shm)" => "shmem_kb",
                "Buffers" => "buffers_kb",
                "Reclaimable kernel caches" => "slab_reclaimable_kb",
                "Kernel memory (not reclaimable)" => "slab_unreclaimable_kb",
                "Kernel stacks, page tables" => "kernel_stack_and_page_tables_kb",
                "Reserved huge pages" => "hugetlb_kb",
                "ZFS ARC cache" => "zfs_arc_kb",
                "Not attributed" => "unattributed_kb",
                _ => continue,
            };
            builder = builder.evidence(key, row.kb.to_string());
        }
        builder = builder
            .evidence("non_reclaimable_kb", pinned.to_string())
            .evidence(
                "non_reclaimable_percent",
                format!("{:.1}", percent(pinned, data.mem_total_kb)),
            );
        if data.detail.unevictable_kb > 0 {
            builder = builder.evidence("unevictable_kb", data.detail.unevictable_kb.to_string());
        }
    } else {
        paragraphs.push(
            "The detailed breakdown is unavailable: this kernel does not expose the \
             extended /proc/meminfo fields."
                .to_string(),
        );
    }

    if top.is_empty() {
        if rows.is_some() {
            paragraphs.push(
                "Per-program figures are unavailable (/proc/<pid>/status could not be read)."
                    .to_string(),
            );
        }
    } else {
        let mut list = String::from(
            "Largest consumers by private memory (each page is counted once, so programs that \
             share libraries are not inflated):",
        );
        let mut shown = 0;
        for (i, g) in top.iter().enumerate() {
            let share = percent(g.anon_kb, data.mem_total_kb);
            // A program using a rounding error of RAM is not a consumer
            // worth listing (it stays in the evidence).
            if i == 0 || share >= MIN_CONSUMER_PERCENT {
                shown += 1;
                list.push_str(&format!(
                    "\n  {}. {} — {} ({} of RAM)",
                    shown,
                    group_label(g),
                    group_detail(g),
                    pct(share)
                ));
            }
            builder = builder.evidence(
                format!("top_consumer_{}", i + 1),
                format!(
                    "{} — {} (largest process: PID {})",
                    group_label(g),
                    group_detail(g),
                    g.largest_pid
                ),
            );
        }
        paragraphs.push(list);
        builder = builder.evidence("processes_scanned", data.processes.len().to_string());
    }

    builder = builder.explanation(paragraphs.join("\n\n"));

    if severity > Severity::Info {
        builder = builder.recommendation(used_memory_steps(data, &top).build());
    }
    builder.build()
}

fn used_memory_steps(data: &MemoryRawData, top: &[super::format::ProcessGroup]) -> Steps {
    let mut steps = Steps::new().step(
        "Find who is using the memory. ps shows each process's resident size; smem splits \
         shared pages fairly between the processes that share them:",
        &[
            "ps -eo pid,user,rss,comm --sort=-rss | head -15",
            "systemd-cgtop -m            # per service, ordered by memory",
            "smem -tkr -s pss | head -15   # needs the 'smem' package",
        ],
    );

    if let Some(biggest) = top.first() {
        let share = percent(biggest.anon_kb, data.mem_total_kb);
        let pid = biggest.largest_pid.to_string();
        let growth = format!("watch -n 5 'grep -E \"RssAnon|VmSwap\" /proc/{pid}/status'");
        steps = steps
            .step_owned(
                format!(
                    "{} holds {} of private memory ({} of RAM). If that number keeps climbing \
                     while the workload stays the same, it is a leak: restart it to recover \
                     the memory, update it, and report it upstream. Watch its private memory \
                     (RssAnon) and swap use over a few minutes:",
                    group_label(biggest),
                    kb(biggest.anon_kb),
                    pct(share)
                ),
                vec![growth],
            )
            .step_owned(
                "Find which service owns it (systemctl accepts a process ID), to restart \
                 or limit it by name:",
                vec![format!("systemctl status {pid}")],
            );
        steps = steps.step(
            "Stop one program from taking the whole machine: give its service a ceiling \
             (MemoryHigh makes it slow down first, MemoryMax is the hard limit). Pick \
             values above its normal peak:",
            &["sudo systemctl set-property <service> MemoryHigh=<N>G MemoryMax=<M>G"],
        );
        if biggest.count >= 4 {
            steps = steps.step(
                format!(
                    "{} runs as {} separate processes: reducing the worker, connection or \
                     tab count in its configuration is usually the quickest saving.",
                    biggest.name, biggest.count
                ),
                &[],
            );
        }
    }

    if !data.has_swap() || data.swap_free_kb == 0 {
        let size = suggested_swap_gb(data.mem_total_kb);
        steps = steps.step_owned(
            "Give the kernel a cushion so a spike slows the system down instead of killing \
             a process: compressed-RAM swap (zram) or a swap file. The Swap page has the \
             zram setup; a swap file:",
            swapfile_commands(size),
        );
    }

    steps.step(
        "If the memory that cannot be dropped stays above roughly 80% of RAM even in \
         normal use, the machine is undersized for its workload: add RAM or move part \
         of the workload elsewhere.",
        &[],
    )
}

/// MEM003 — memory is critically low AND there's no swap left to absorb it
/// (either no swap configured, or swap itself is exhausted).
pub fn critical(data: &MemoryRawData) -> Option<Finding> {
    if data.mem_total_kb == 0 {
        return None;
    }
    let mem_available_pct = data.available_percent();
    let swap_exhausted = data.swap_total_kb == 0 || data.swap_free_kb == 0;

    if !(mem_available_pct < 5.0 && swap_exhausted) {
        return None;
    }

    let top = top_by_anon(&data.processes, 1);
    let mut explanation = String::from(
        "Available memory is critically low and there is no swap left to absorb further \
         pressure. New allocations may soon fail or the kernel's OOM killer may start \
         terminating processes.",
    );
    if let Some(g) = top.first() {
        explanation.push_str(&format!(
            " The largest consumer is {} with {} of private memory ({} of RAM).",
            group_label(g),
            kb(g.anon_kb),
            pct(percent(g.anon_kb, data.mem_total_kb)),
        ));
    }

    let mut steps = Steps::new();
    steps = match top.first() {
        Some(g) => steps.step_owned(
            format!(
                "Free memory right now by stopping or restarting the biggest consumer: {}, \
                 whose largest process is PID {}. Find its service, then restart it:",
                group_label(g),
                g.largest_pid
            ),
            vec![
                format!("systemctl status {}", g.largest_pid),
                "sudo systemctl restart <service>".to_string(),
            ],
        ),
        None => steps.step(
            "Free memory right now by stopping or restarting the biggest consumer:",
            &["ps -eo pid,user,rss,comm --sort=-rss | head -5"],
        ),
    };
    let size = suggested_swap_gb(data.mem_total_kb);
    steps = steps.step_owned(
        if data.swap_total_kb == 0 {
            "No swap exists at all. Add some immediately so the kernel has somewhere to \
             put idle pages (this is the quickest relief; make it permanent via the \
             fstab line):"
        } else {
            "Swap is completely full. Add more so the kernel has room again:"
        },
        swapfile_commands(size),
    );
    steps = steps.step(
        "Protect the services that must survive from the OOM killer (-1000 exempts a \
         process entirely; use sparingly), in the unit's [Service] section:",
        &["OOMScoreAdjust=-900"],
    );
    steps = steps.step(
        "Then find the cause: the Used memory page lists the top consumers, and the \
         Pressure page shows whether the OOM killer has already acted.",
        &[],
    );

    Some(
        Finding::builder(
            "MEM003",
            "Critically Low Available Memory",
            Category::Memory,
            Severity::Critical,
            Confidence::correlated(90),
        )
        .evidence("mem_available_pct", format!("{mem_available_pct:.1}"))
        .evidence("swap_total_kb", data.swap_total_kb.to_string())
        .evidence("swap_free_kb", data.swap_free_kb.to_string())
        .explanation(explanation)
        .recommendation(steps.build())
        .build(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::modules::memory::collect::ZfsArc;
    use crate::modules::memory::test_support::{evidence, healthy, proc};

    #[test]
    fn overview_separates_shared_memory_from_reclaimable_cache() {
        let f = overview(&healthy());
        assert_eq!(f.id, "MEM004");
        assert_eq!(f.severity, Severity::Info);
        // free(1) style: 5_000_000 + 400_000
        assert_eq!(evidence(&f, "buff_cache_kb"), Some("5400000"));
        // reclaimable: buffers 200k + (5.0M - 200k - 300k) + 400k slab
        assert_eq!(evidence(&f, "reclaimable_cache_kb"), Some("5100000"));
        assert_eq!(evidence(&f, "shared_kb"), Some("300000"));
        assert!(f.explanation.contains("includes"));
        assert!(f.explanation.contains("shared memory"));
        // Used = total - available
        assert_eq!(evidence(&f, "used_kb"), Some("7000000"));
    }

    #[test]
    fn overview_keeps_the_historic_cached_key() {
        let f = overview(&healthy());
        assert_eq!(evidence(&f, "cached_kb"), Some("5000000"));
    }

    #[test]
    fn overview_names_the_availability_band() {
        let mut d = healthy();
        assert!(overview(&d).explanation.contains("comfortable"));
        d.mem_available_kb = 2_400_000; // 15%
        assert!(overview(&d).explanation.contains("adequate"));
        d.mem_available_kb = 1_200_000; // 7.5%
        assert!(overview(&d).explanation.contains("tight"));
        d.mem_available_kb = 400_000; // 2.5%
        assert!(overview(&d).explanation.contains("very tight"));
    }

    #[test]
    fn bands_cover_the_boundaries() {
        assert_eq!(availability_band(25.0), "comfortable");
        assert_eq!(availability_band(24.9), "adequate");
        assert_eq!(availability_band(10.0), "adequate");
        assert_eq!(availability_band(9.9), "tight");
        assert_eq!(availability_band(5.0), "tight");
        assert_eq!(availability_band(4.9), "very tight");
    }

    #[test]
    fn healthy_machine_is_info_with_a_breakdown_and_no_recommendation() {
        let f = used_memory(&healthy());
        assert_eq!(f.id, "MEM007");
        assert_eq!(f.severity, Severity::Info);
        assert!(f.recommendation.is_none());
        assert!(f.explanation.contains("Where the"));
        assert!(f.explanation.contains("Programs (private memory)"));
        assert!(f.explanation.contains("Free"));
        assert_eq!(evidence(&f, "anon_kb"), Some("5000000"));
        // 16_000_000 - (5.0M + 4.5M + 0.3M + 0.2M + 0.4M + 0.2M + 0.1M + 0 + 4.0M)
        // = 16.0M - 14.7M = 1.3M
        assert_eq!(evidence(&f, "unattributed_kb"), Some("1300000"));
    }

    #[test]
    fn low_available_memory_escalates_and_brings_numbered_steps() {
        let mut d = healthy();
        d.mem_available_kb = 1_200_000; // 7.5%
        let f = used_memory(&d);
        assert_eq!(f.severity, Severity::Warning);
        let rec = f.recommendation.expect("a warning must come with a fix");
        assert!(rec.starts_with("1. "));
        assert!(rec.contains("ps -eo pid,user,rss,comm --sort=-rss"));
        assert!(rec.contains("systemd-cgtop -m"));

        d.mem_available_kb = 500_000; // 3.1%
        assert_eq!(used_memory(&d).severity, Severity::Error);
    }

    #[test]
    fn top_consumers_are_listed_with_pids_and_drive_the_advice() {
        let mut d = healthy();
        d.mem_available_kb = 1_200_000;
        d.processes = vec![
            proc(100, "postgres", 1_500_000),
            proc(101, "postgres", 1_400_000),
            proc(102, "postgres", 1_300_000),
            proc(103, "postgres", 1_200_000),
            proc(200, "sshd", 10_000),
        ];
        let f = used_memory(&d);
        assert!(evidence(&f, "top_consumer_1")
            .unwrap()
            .starts_with("postgres (4 processes)"));
        assert!(evidence(&f, "top_consumer_1").unwrap().contains("PID 100"));
        assert!(f.explanation.contains("postgres (4 processes)"));
        let rec = f.recommendation.unwrap();
        assert!(rec.contains("systemctl status 100"));
        assert!(rec.contains("Watch its private memory"));
        assert!(rec.contains("MemoryHigh"));
        assert!(
            rec.contains("4 separate processes"),
            "many workers get the worker-count advice"
        );
    }

    #[test]
    fn single_process_consumer_gets_no_worker_count_advice() {
        let mut d = healthy();
        d.mem_available_kb = 1_200_000;
        d.processes = vec![proc(100, "java", 6_000_000)];
        let rec = used_memory(&d).recommendation.unwrap();
        assert!(!rec.contains("separate processes"));
        assert!(rec.contains("java"));
    }

    #[test]
    fn swap_cushion_advice_only_when_there_is_no_usable_swap() {
        let mut d = healthy();
        d.mem_available_kb = 1_200_000;
        let with_swap = used_memory(&d).recommendation.unwrap();
        assert!(!with_swap.contains("mkswap"));

        d.swap_total_kb = 0;
        d.swap_free_kb = 0;
        let without = used_memory(&d).recommendation.unwrap();
        assert!(without.contains("mkswap"));
        // 16_000_000 kB is 15.3 GiB -> 15 GiB / 2 -> 7 GB swap file.
        assert!(without.contains("fallocate -l 7G"), "{without}");
    }

    #[test]
    fn without_extended_meminfo_the_breakdown_is_honestly_absent() {
        let d = MemoryRawData {
            mem_total_kb: 1_000_000,
            mem_available_kb: 500_000,
            ..Default::default()
        };
        let f = used_memory(&d);
        assert!(f.explanation.contains("breakdown is unavailable"));
        assert!(
            evidence(&f, "unattributed_kb").is_none(),
            "no fake 100% unattributed"
        );
    }

    #[test]
    fn tiny_rows_are_summed_into_one_line_and_kept_in_evidence() {
        let mut d = healthy();
        d.detail.percpu_kb = 1;
        d.detail.kernel_stack_kb = 1;
        d.detail.page_tables_kb = 1; // together far below 0.5%
        d.detail.sunreclaim_kb = 1;
        d.detail.buffers_kb = 1;
        let f = used_memory(&d);
        assert!(!f.explanation.contains("Kernel stacks, page tables"));
        assert!(f.explanation.contains("Smaller items (each under 0.5%)"));
        assert_eq!(evidence(&f, "kernel_stack_and_page_tables_kb"), Some("3"));
    }

    #[test]
    fn no_smaller_items_line_when_nothing_was_left_out() {
        // Only the empty "Reserved huge pages" row is omitted: nothing to sum.
        assert!(!used_memory(&healthy())
            .explanation
            .contains("Smaller items"));
    }

    #[test]
    fn a_rounding_error_of_ram_is_not_listed_as_a_consumer() {
        let mut d = healthy();
        d.processes = vec![proc(1, "big", 3_000_000), proc(2, "tiny", 1_000)]; // tiny = 0.006%
        let f = used_memory(&d);
        assert!(f.explanation.contains("1. big"));
        assert!(!f.explanation.contains("tiny"));
        assert!(
            evidence(&f, "top_consumer_2").unwrap().starts_with("tiny"),
            "still in the evidence"
        );
    }

    #[test]
    fn the_largest_consumer_is_always_listed_even_on_a_nearly_idle_machine() {
        let mut d = healthy();
        d.processes = vec![proc(1, "only", 500)];
        assert!(used_memory(&d).explanation.contains("1. only"));
    }

    #[test]
    fn a_large_unattributed_remainder_is_explained() {
        // healthy(): 1.3M unattributed of 16M = 8.1%
        assert!(used_memory(&healthy())
            .explanation
            .contains("not itemised by the kernel"));
        let mut d = healthy();
        d.mem_free_kb = 5_200_000; // leaves only 0.1M unattributed
        assert!(!used_memory(&d).explanation.contains("not itemised"));
    }

    #[test]
    fn zfs_arc_is_carved_out_of_the_unattributed_remainder() {
        let mut d = healthy();
        d.zfs_arc = Some(ZfsArc {
            size_kb: 1_000_000,
            max_kb: 8_000_000,
        });
        let f = used_memory(&d);
        assert_eq!(evidence(&f, "zfs_arc_kb"), Some("1000000"));
        assert_eq!(evidence(&f, "unattributed_kb"), Some("300000"));
        assert!(f.explanation.contains("ZFS ARC cache"));
    }

    #[test]
    fn zfs_arc_larger_than_the_remainder_does_not_underflow() {
        let mut d = healthy();
        d.zfs_arc = Some(ZfsArc {
            size_kb: 9_000_000,
            max_kb: 0,
        });
        let f = used_memory(&d);
        assert_eq!(evidence(&f, "zfs_arc_kb"), Some("1300000"));
        assert_eq!(evidence(&f, "unattributed_kb"), Some("0"));
    }

    #[test]
    fn hugetlb_is_counted_as_pinned_memory() {
        let mut d = healthy();
        d.detail.hugepages_total = 1000;
        d.detail.hugepage_size_kb = 2048; // 2_048_000 kB reserved
        let f = used_memory(&d);
        assert_eq!(evidence(&f, "hugetlb_kb"), Some("2048000"));
        // pinned = anon 5.0M + shmem 0.3M + sunreclaim 0.2M + 0.1M + hugetlb 2.048M
        assert_eq!(evidence(&f, "non_reclaimable_kb"), Some("7648000"));
    }

    #[test]
    fn critical_requires_low_memory_and_no_swap_room() {
        let mut d = healthy();
        d.mem_available_kb = 400_000; // 2.5%
        assert!(critical(&d).is_none(), "swap still has room");

        d.swap_total_kb = 0;
        d.swap_free_kb = 0;
        let f = critical(&d).unwrap();
        assert_eq!(f.id, "MEM003");
        assert_eq!(f.severity, Severity::Critical);

        d.swap_total_kb = 4_000_000;
        d.swap_free_kb = 0; // exhausted
        assert!(critical(&d).is_some());

        d.mem_available_kb = 2_000_000; // 12.5%: not low
        assert!(critical(&d).is_none());
    }

    #[test]
    fn critical_names_the_culprit_and_gives_emergency_steps() {
        let mut d = healthy();
        d.mem_available_kb = 400_000;
        d.swap_total_kb = 0;
        d.swap_free_kb = 0;
        d.processes = vec![proc(4242, "mysqld", 9_000_000)];
        let f = critical(&d).unwrap();
        assert!(f.explanation.contains("mysqld"));
        let rec = f.recommendation.unwrap();
        assert!(rec.contains("largest process is PID 4242"));
        assert!(rec.contains("systemctl status 4242"));
        assert!(rec.contains("No swap exists at all"));
        assert!(rec.contains("OOMScoreAdjust=-900"));
    }

    #[test]
    fn critical_with_exhausted_swap_says_so_instead_of_claiming_none_exists() {
        let mut d = healthy();
        d.mem_available_kb = 400_000;
        d.swap_free_kb = 0;
        let rec = critical(&d).unwrap().recommendation.unwrap();
        assert!(rec.contains("completely full"));
        assert!(!rec.contains("No swap exists"));
    }

    #[test]
    fn critical_works_without_per_process_data() {
        let mut d = healthy();
        d.mem_available_kb = 400_000;
        d.swap_total_kb = 0;
        d.swap_free_kb = 0;
        let rec = critical(&d).unwrap().recommendation.unwrap();
        assert!(rec.contains("ps -eo pid,user,rss,comm --sort=-rss | head -5"));
    }
}
