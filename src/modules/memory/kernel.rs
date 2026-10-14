// SPDX-License-Identifier: GPL-3.0-only

//! Memory held by the kernel itself (MEM013): slab caches, page tables,
//! stacks, the ZFS ARC, the reserve behind vm.min_free_kbytes, memory a
//! hypervisor has taken back, and memory locked into RAM.

use crate::models::{Category, Confidence, Finding, Severity};

use super::collect::{percent, MemoryRawData};
use super::format::{kb, pct, Steps};

/// Kernel memory that cannot be reclaimed (SUnreclaim) becomes a problem
/// when it is this large: a driver or kernel leak is the usual cause.
const UNRECLAIM_WARNING_PERCENT: f64 = 10.0;
const UNRECLAIM_ERROR_PERCENT: f64 = 25.0;
const UNRECLAIM_MIN_KB: u64 = 1024 * 1024;

/// Page tables this large mean many processes map the same big memory
/// area with small pages (typically a database with many connections).
const PAGE_TABLES_WARNING_PERCENT: f64 = 5.0;
const PAGE_TABLES_MIN_KB: u64 = 512 * 1024;

/// A ZFS cache this large, on a machine short of memory, is worth a word.
const ARC_LARGE_PERCENT: f64 = 50.0;
const ARC_TIGHT_AVAILABLE_PERCENT: f64 = 10.0;

/// vm.min_free_kbytes is a reserve the kernel never hands to programs.
const MIN_FREE_WARNING_PERCENT: f64 = 5.0;

/// Locked memory worth mentioning.
const UNEVICTABLE_NOTE_PERCENT: f64 = 25.0;

pub fn kernel_memory(data: &MemoryRawData) -> Option<Finding> {
    let d = &data.detail;
    let total = data.mem_total_kb;
    if d.slab_kb == 0 && d.page_tables_kb == 0 && d.kernel_stack_kb == 0 {
        return None; // the extended /proc/meminfo fields are missing
    }

    let kernel_kb = d.slab_kb + d.kernel_stack_kb + d.page_tables_kb + d.percpu_kb;
    let kernel_pct = percent(kernel_kb, total);
    let unreclaim_pct = percent(d.sunreclaim_kb, total);
    let page_tables_pct = percent(d.page_tables_kb, total);
    let avail_pct = data.available_percent();

    let mut severity = Severity::Info;
    let mut confidence = Confidence::direct_observation();
    let mut raise = |s: Severity, c: Confidence| {
        if s > severity {
            severity = s;
            confidence = c;
        }
    };

    let mut paragraphs: Vec<String> = vec![format!(
        "The kernel itself holds {} of RAM ({}): {} of slab caches ({} reclaimable, {} not), {} \
         of page tables, {} of kernel stacks and {} of per-CPU data. This memory belongs to no \
         program; it is the cost of running the system.",
        kb(kernel_kb),
        pct(kernel_pct),
        kb(d.slab_kb),
        kb(d.sreclaimable_kb),
        kb(d.sunreclaim_kb),
        kb(d.page_tables_kb),
        kb(d.kernel_stack_kb),
        kb(d.percpu_kb),
    )];
    let mut steps = Steps::new();

    // --- non-reclaimable slab -------------------------------------------
    if d.sunreclaim_kb >= UNRECLAIM_MIN_KB && unreclaim_pct >= UNRECLAIM_WARNING_PERCENT {
        if unreclaim_pct >= UNRECLAIM_ERROR_PERCENT {
            raise(Severity::Error, Confidence::strong_indication(80));
        } else {
            raise(Severity::Warning, Confidence::strong_indication(80));
        }
        paragraphs.push(format!(
            "{} of kernel memory ({} of RAM) cannot be reclaimed. That is far more than a \
             healthy system needs, and it only grows when something in the kernel allocates \
             and never releases: a driver, a firewall connection-tracking table, or a kernel \
             bug.",
            kb(d.sunreclaim_kb),
            pct(unreclaim_pct)
        ));
        steps = steps
            .step(
                "See which kernel object is growing (the top entries by size are the suspects):",
                &["sudo slabtop -o -s c | head -15"],
            )
            .step(
                "Match the name to its source: nf_conntrack* is the firewall's connection table \
                 (raise net.netfilter.nf_conntrack_max only if full, or lower the timeouts); \
                 anything with a driver name points at that driver. Update the kernel and \
                 drivers; a reboot is the only way to give the memory back.",
                &["sudo lsmod | head -30"],
            );
    }

    // --- page tables -----------------------------------------------------
    if d.page_tables_kb >= PAGE_TABLES_MIN_KB && page_tables_pct >= PAGE_TABLES_WARNING_PERCENT {
        raise(Severity::Warning, Confidence::strong_indication(78));
        paragraphs.push(format!(
            "Page tables take {} ({} of RAM). That happens when many processes each map the \
             same large memory area with ordinary 4 KB pages — typically a database with hundreds \
             of connections and a big shared buffer. Huge pages shrink the bookkeeping \
             dramatically.",
            kb(d.page_tables_kb),
            pct(page_tables_pct)
        ));
        steps = steps
            .step(
                "Find the programs with the most memory mapped (a large 'VmPTE' means many page \
                 table pages):",
                &["grep -H VmPTE /proc/[0-9]*/status 2>/dev/null | sort -k2 -n -r | head -5"],
            )
            .step(
                "Use huge pages for that program's shared memory (huge_pages = on in PostgreSQL, \
                 for example), or reduce the number of connections with a pooler such as \
                 PgBouncer. See the Huge Pages finding for how to reserve them.",
                &[],
            );
    }

    // --- ZFS ARC ---------------------------------------------------------
    if let Some(arc) = &data.zfs_arc {
        let arc_pct = percent(arc.size_kb, total);
        paragraphs.push(format!(
            "ZFS is loaded. Its cache (the ARC) holds {} ({} of RAM, limit {}). ZFS allocates it \
             itself, outside the page cache, and /proc/meminfo's 'available' figure does not \
             count it — so a ZFS machine always looks fuller than it is. ZFS does give the \
             memory back when programs ask, but more slowly than the page cache does.",
            kb(arc.size_kb),
            pct(arc_pct),
            if arc.max_kb > 0 {
                kb(arc.max_kb)
            } else {
                "unknown".to_string()
            },
        ));
        if arc_pct >= ARC_LARGE_PERCENT && avail_pct < ARC_TIGHT_AVAILABLE_PERCENT {
            raise(Severity::Warning, Confidence::strong_indication(80));
            let cap = total / 4 * 1024; // bytes
            paragraphs.push(
                "The ARC holds more than half of RAM while little memory is available. If \
                 programs are being starved or killed while ZFS holds on to its cache, cap it."
                    .to_string(),
            );
            steps = steps
                .step_owned(
                    format!(
                        "Cap the ARC now (here at a quarter of RAM, {}; pick what suits the \
                         workload — databases and virtual machines want more room, file \
                         servers less):",
                        kb(total / 4)
                    ),
                    vec![format!(
                        "echo {cap} | sudo tee /sys/module/zfs/parameters/zfs_arc_max"
                    )],
                )
                .step_owned(
                    "Keep the cap after reboot:",
                    vec![format!(
                        "echo 'options zfs zfs_arc_max={cap}' | sudo tee /etc/modprobe.d/zfs.conf"
                    )],
                );
        }
    }

    // --- reserve ----------------------------------------------------------
    if let Some(min_free) = data.vm.min_free_kbytes {
        let min_free_pct = percent(min_free, total);
        if min_free_pct >= MIN_FREE_WARNING_PERCENT {
            raise(Severity::Warning, Confidence::strong_indication(80));
            paragraphs.push(format!(
                "vm.min_free_kbytes is {} ({} of RAM). That much memory is kept permanently \
                 free and never handed to programs, and the kernel starts reclaiming earlier \
                 because of it. Tuning guides sometimes raise it far beyond need; the kernel's \
                 own default is a few tens of MB.",
                kb(min_free),
                pct(min_free_pct)
            ));
            steps = steps
                .step(
                    "Check where the value comes from, and lower it unless a vendor (for \
                     example for a network card driver) requires it:",
                    &["grep -r min_free_kbytes /etc/sysctl.conf /etc/sysctl.d /usr/lib/sysctl.d"],
                )
                .step_owned(
                    "Set a moderate value (65536 kB = 64 MB is plenty for most machines):",
                    super::format::sysctl_commands("vm.min_free_kbytes=65536", "99-min-free.conf"),
                );
        } else {
            paragraphs.push(format!(
                "vm.min_free_kbytes is {}: the reserve the kernel keeps free so it can always \
                 satisfy urgent allocations.",
                kb(min_free)
            ));
        }
    }

    // --- virtual machines --------------------------------------------------
    if d.balloon_kb > 0 {
        paragraphs.push(format!(
            "The hypervisor has taken {} of this virtual machine's memory back through the \
             balloon driver. That is why the total shown here may be smaller than what the VM \
             was assigned; the memory returns when the host gives it back.",
            kb(d.balloon_kb)
        ));
    }

    // --- locked memory -----------------------------------------------------
    let unevictable_pct = percent(d.unevictable_kb, total);
    if d.unevictable_kb > 0 && unevictable_pct >= UNEVICTABLE_NOTE_PERCENT {
        paragraphs.push(format!(
            "{} of RAM ({}) is locked and can never be swapped or reclaimed (mlock, ramfs, \
             memory held by some drivers). {} of it is locked by programs with mlock.",
            kb(d.unevictable_kb),
            pct(unevictable_pct),
            kb(d.mlocked_kb)
        ));
    }

    let mut builder = Finding::builder(
        "MEM013",
        "Kernel Memory",
        Category::Memory,
        severity,
        confidence,
    )
    .evidence("kernel_memory_kb", kernel_kb.to_string())
    .evidence("kernel_memory_percent", format!("{kernel_pct:.1}"))
    .evidence("slab_kb", d.slab_kb.to_string())
    .evidence("slab_reclaimable_kb", d.sreclaimable_kb.to_string())
    .evidence("slab_unreclaimable_kb", d.sunreclaim_kb.to_string())
    .evidence("page_tables_kb", d.page_tables_kb.to_string())
    .evidence("kernel_stack_kb", d.kernel_stack_kb.to_string())
    .evidence("percpu_kb", d.percpu_kb.to_string());
    if let Some(v) = data.vm.min_free_kbytes {
        builder = builder.evidence("vm.min_free_kbytes", v.to_string());
    }
    if let Some(arc) = &data.zfs_arc {
        builder = builder
            .evidence("zfs_arc_kb", arc.size_kb.to_string())
            .evidence("zfs_arc_max_kb", arc.max_kb.to_string());
    }
    if d.balloon_kb > 0 {
        builder = builder.evidence("balloon_kb", d.balloon_kb.to_string());
    }
    if d.unevictable_kb > 0 {
        builder = builder.evidence("unevictable_kb", d.unevictable_kb.to_string());
    }
    builder = builder.explanation(paragraphs.join("\n\n"));
    if !steps.is_empty() {
        builder = builder.recommendation(steps.build());
    }
    Some(builder.build())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::modules::memory::collect::{VmTunables, ZfsArc};
    use crate::modules::memory::test_support::{evidence, healthy};

    #[test]
    fn missing_extended_meminfo_means_no_finding() {
        let d = MemoryRawData {
            mem_total_kb: 1_000_000,
            ..Default::default()
        };
        assert!(kernel_memory(&d).is_none());
    }

    #[test]
    fn ordinary_kernel_memory_is_a_quiet_breakdown() {
        let f = kernel_memory(&healthy()).unwrap();
        assert_eq!(f.id, "MEM013");
        assert_eq!(f.severity, Severity::Info);
        assert!(f.recommendation.is_none());
        // slab 0 in healthy() -> kernel = 0 + 30k + 60k + 10k
        assert_eq!(evidence(&f, "kernel_memory_kb"), Some("100000"));
        assert!(f.explanation.contains("belongs to no program"));
    }

    fn leaky() -> MemoryRawData {
        let mut d = healthy();
        d.detail.slab_kb = 3_000_000;
        d.detail.sreclaimable_kb = 300_000;
        d.detail.sunreclaim_kb = 2_700_000; // 16.9%
        d
    }

    #[test]
    fn large_unreclaimable_slab_warns_and_names_the_tools() {
        let f = kernel_memory(&leaky()).unwrap();
        assert_eq!(f.severity, Severity::Warning);
        assert!(f.explanation.contains("cannot be reclaimed"));
        let rec = f.recommendation.unwrap();
        assert!(rec.contains("slabtop -o -s c"));
        assert!(rec.contains("nf_conntrack"));
    }

    #[test]
    fn huge_unreclaimable_slab_is_an_error() {
        let mut d = leaky();
        d.detail.sunreclaim_kb = 4_500_000; // 28%
        assert_eq!(kernel_memory(&d).unwrap().severity, Severity::Error);
    }

    #[test]
    fn small_unreclaimable_slab_is_normal() {
        let mut d = healthy();
        d.detail.slab_kb = 800_000;
        d.detail.sunreclaim_kb = 400_000;
        assert_eq!(kernel_memory(&d).unwrap().severity, Severity::Info);
    }

    #[test]
    fn big_page_tables_point_to_huge_pages() {
        let mut d = healthy();
        d.detail.page_tables_kb = 1_200_000; // 7.5%
        let f = kernel_memory(&d).unwrap();
        assert_eq!(f.severity, Severity::Warning);
        let rec = f.recommendation.unwrap();
        assert!(rec.contains("VmPTE"));
        assert!(rec.contains("PgBouncer"));
    }

    #[test]
    fn zfs_arc_is_explained_and_not_a_problem_when_memory_is_fine() {
        let mut d = healthy();
        d.zfs_arc = Some(ZfsArc {
            size_kb: 6_000_000,
            max_kb: 8_000_000,
        });
        let f = kernel_memory(&d).unwrap();
        assert_eq!(f.severity, Severity::Info);
        assert!(f.explanation.contains("does not count it"));
        assert_eq!(evidence(&f, "zfs_arc_kb"), Some("6000000"));
    }

    #[test]
    fn oversized_arc_on_a_tight_machine_warns_with_a_cap() {
        let mut d = healthy();
        d.mem_available_kb = 1_000_000;
        d.zfs_arc = Some(ZfsArc {
            size_kb: 9_000_000,
            max_kb: 12_000_000,
        });
        let f = kernel_memory(&d).unwrap();
        assert_eq!(f.severity, Severity::Warning);
        let rec = f.recommendation.unwrap();
        // quarter of 16_000_000 kB, in bytes
        assert!(
            rec.contains("echo 4096000000 | sudo tee /sys/module/zfs/parameters/zfs_arc_max"),
            "{rec}"
        );
        assert!(rec.contains("options zfs zfs_arc_max=4096000000"));
    }

    #[test]
    fn excessive_min_free_kbytes_warns() {
        let mut d = healthy();
        d.vm = VmTunables {
            min_free_kbytes: Some(1_600_000),
            ..Default::default()
        }; // 10%
        let f = kernel_memory(&d).unwrap();
        assert_eq!(f.severity, Severity::Warning);
        let rec = f.recommendation.unwrap();
        assert!(rec.contains("grep -r min_free_kbytes"));
        assert!(rec.contains("vm.min_free_kbytes=65536"));
    }

    #[test]
    fn normal_min_free_kbytes_is_only_described() {
        let mut d = healthy();
        d.vm = VmTunables {
            min_free_kbytes: Some(67_584),
            ..Default::default()
        };
        let f = kernel_memory(&d).unwrap();
        assert_eq!(f.severity, Severity::Info);
        assert!(f.explanation.contains("urgent allocations"));
        assert_eq!(evidence(&f, "vm.min_free_kbytes"), Some("67584"));
    }

    #[test]
    fn ballooned_memory_in_a_vm_is_explained() {
        let mut d = healthy();
        d.detail.balloon_kb = 2_000_000;
        let f = kernel_memory(&d).unwrap();
        assert!(f.explanation.contains("balloon driver"));
        assert_eq!(f.severity, Severity::Info);
    }

    #[test]
    fn locked_memory_is_mentioned_only_when_substantial() {
        let mut d = healthy();
        d.detail.unevictable_kb = 100_000;
        assert!(!kernel_memory(&d).unwrap().explanation.contains("locked"));
        d.detail.unevictable_kb = 5_000_000;
        d.detail.mlocked_kb = 4_000_000;
        assert!(kernel_memory(&d)
            .unwrap()
            .explanation
            .contains("locked and can never be swapped"));
    }

    #[test]
    fn worst_issue_wins() {
        let mut d = leaky();
        d.detail.sunreclaim_kb = 4_500_000;
        d.detail.page_tables_kb = 1_200_000;
        let f = kernel_memory(&d).unwrap();
        assert_eq!(f.severity, Severity::Error);
        let rec = f.recommendation.unwrap();
        assert!(rec.contains("slabtop"));
        assert!(rec.contains("VmPTE"), "both sets of advice are kept");
    }
}
