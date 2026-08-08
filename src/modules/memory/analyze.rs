// SPDX-License-Identifier: GPL-3.0-only

use crate::core::context::Context;
use crate::models::{Category, Confidence, Finding, Severity};

use super::collect::MemoryRawData;

const DEFAULT_SWAPPINESS: u8 = 60;

/// Pure function: RawData -> Findings. No I/O, no filesystem access, fully
/// unit-testable — this is the whole point of separating collect() from
/// analyze(). See ARCHITECTURE.md "Testing Strategy".
pub fn analyze(data: &MemoryRawData, _ctx: &Context) -> Vec<Finding> {
    let mut findings = Vec::new();

    findings.push(memory_overview_finding(data));
    findings.push(swappiness_finding(data));

    if let Some(f) = swap_pressure_finding(data) {
        findings.push(f);
    }
    if let Some(f) = critical_memory_finding(data) {
        findings.push(f);
    }

    findings.push(dirty_pages_finding(data));
    findings.push(shared_memory_finding(data));

    findings
}

/// MEM004 — always reported. This is the "why is my free RAM low" answer:
/// distinguishes actually-used memory from reclaimable cache, since the
/// two are easy to confuse and only one of them is worth worrying about.
fn memory_overview_finding(data: &MemoryRawData) -> Finding {
    let used_kb = data.mem_total_kb.saturating_sub(data.mem_available_kb);
    let used_pct = if data.mem_total_kb > 0 {
        used_kb as f64 / data.mem_total_kb as f64 * 100.0
    } else {
        0.0
    };

    let to_gb = |kb: u64| kb as f64 / 1024.0 / 1024.0;

    Finding::builder(
        "MEM004",
        "Memory Usage Overview",
        Category::Memory,
        Severity::Info,
        Confidence::direct_observation(),
    )
    .evidence("total_kb", data.mem_total_kb.to_string())
    .evidence("used_kb", used_kb.to_string())
    .evidence("free_kb", data.mem_free_kb.to_string())
    .evidence("available_kb", data.mem_available_kb.to_string())
    .evidence("cached_kb", data.cached_kb.to_string())
    .evidence("used_percent", format!("{used_pct:.1}"))
    .explanation(format!(
        "Of {:.1} GB total memory, {:.1} GB ({used_pct:.1}%) is actually in \
         use. Only {:.1} GB shows as strictly free, but {:.1} GB is \
         reclaimable page cache — Linux uses spare RAM to cache disk data \
         for speed, and hands it back automatically the moment an \
         application needs it. A low 'free' number by itself is not a sign \
         of a problem: {:.1} GB is genuinely available for new allocations.",
        to_gb(data.mem_total_kb),
        to_gb(used_kb),
        to_gb(data.mem_free_kb),
        to_gb(data.cached_kb),
        to_gb(data.mem_available_kb),
    ))
    .build()
}

/// MEM001 — always reported. Directly mirrors the worked example in
/// PROJECT_CONTEXT.md's "Explain instead of dumping data" section.
fn swappiness_finding(data: &MemoryRawData) -> Finding {
    let is_default = data.swappiness == DEFAULT_SWAPPINESS;
    let explanation = if is_default {
        "This is the default kernel value. For a desktop with large amounts \
         of RAM, a lower value is often preferred. No action required \
         unless swap activity is high."
            .to_string()
    } else if data.swappiness < DEFAULT_SWAPPINESS {
        format!(
            "Lower than the kernel default of {DEFAULT_SWAPPINESS}. The kernel \
             will prefer keeping data in RAM over swapping it out, which usually \
             favors responsiveness on systems with plenty of memory."
        )
    } else {
        format!(
            "Higher than the kernel default of {DEFAULT_SWAPPINESS}. The kernel \
             will swap out memory more eagerly. Reasonable on systems tuned for \
             throughput over latency; worth a second look otherwise."
        )
    };

    Finding::builder(
        "MEM001",
        "Kernel Swappiness Setting",
        Category::Memory,
        Severity::Info,
        Confidence::direct_observation(),
    )
    .evidence("vm.swappiness", data.swappiness.to_string())
    .evidence("kernel_default", DEFAULT_SWAPPINESS.to_string())
    .explanation(explanation)
    .build()
}

/// MEM002 — only reported when swap is actually in use. Severity and
/// confidence scale with how little free memory remains alongside it.
/// Cross-references the configured swappiness: swap activity at a low
/// configured swappiness is a stronger signal than the same activity
/// would be at the default, since the kernel is normally reluctant to
/// swap at all in that case.
fn swap_pressure_finding(data: &MemoryRawData) -> Option<Finding> {
    if data.swap_total_kb == 0 {
        return None; // no swap configured, nothing to say here
    }
    let swap_used_kb = data.swap_total_kb.saturating_sub(data.swap_free_kb);
    if swap_used_kb == 0 {
        return None; // swap configured but unused
    }

    let mem_available_pct = if data.mem_total_kb > 0 {
        (data.mem_available_kb as f64 / data.mem_total_kb as f64) * 100.0
    } else {
        100.0
    };

    let (severity, confidence, mut explanation) = if mem_available_pct < 3.0 {
        (
            Severity::Error,
            Confidence::correlated(95),
            "The system is actively swapping while almost no RAM remains free. \
             This commonly causes visible slowdowns. Investigation is recommended."
                .to_string(),
        )
    } else if mem_available_pct < 10.0 {
        (
            Severity::Warning,
            Confidence::strong_indication(85),
            "The system is actively swapping while relatively little RAM remains \
             free. This commonly indicates memory pressure, though it is not \
             necessarily a problem on its own — worth investigating if \
             performance feels degraded."
                .to_string(),
        )
    } else {
        (
            Severity::Info,
            Confidence::weak_indication(70),
            "Swap is in use, but plenty of RAM is still free. This is not \
             necessarily a problem — some swap usage is normal even on systems \
             with ample memory."
                .to_string(),
        )
    };

    if data.swappiness <= 10 {
        explanation.push_str(&format!(
            " Notably, vm.swappiness is set low ({}), meaning the kernel \
             normally avoids swapping unless under real pressure — this \
             activity is a stronger signal than the same swap usage would be \
             at the default swappiness ({DEFAULT_SWAPPINESS}).",
            data.swappiness,
        ));
    }

    Some(
        Finding::builder(
            "MEM002",
            "Swap Activity",
            Category::Memory,
            severity,
            confidence,
        )
        .evidence("swap_used_kb", swap_used_kb.to_string())
        .evidence("mem_available_kb", data.mem_available_kb.to_string())
        .evidence(
            "mem_available_pct",
            format!("{mem_available_pct:.1}"),
        )
        .evidence("vm.swappiness", data.swappiness.to_string())
        .explanation(explanation)
        .recommendation(
            "Identify high-memory processes (ps, smem) and consider whether \
             more RAM or lower memory usage is needed.",
        )
        .build(),
    )
}

/// MEM003 — memory is critically low AND there's no swap left to absorb it
/// (either no swap configured, or swap itself is exhausted).
fn critical_memory_finding(data: &MemoryRawData) -> Option<Finding> {
    if data.mem_total_kb == 0 {
        return None;
    }
    let mem_available_pct = (data.mem_available_kb as f64 / data.mem_total_kb as f64) * 100.0;
    let swap_exhausted = data.swap_total_kb == 0 || data.swap_free_kb == 0;

    if mem_available_pct < 5.0 && swap_exhausted {
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
            .explanation(
                "Available memory is critically low and there is no swap left to \
                 absorb further pressure. New allocations may soon fail or the \
                 kernel's OOM killer may start terminating processes."
                    .to_string(),
            )
            .recommendation(
                "Free memory immediately (stop or restart high-memory processes) \
                 or add swap/RAM before the situation worsens.",
            )
            .build(),
        )
    } else {
        None
    }
}

/// MEM005 — always reported. Compares actual dirty-page level against
/// this system's *own configured* thresholds (not assumed Linux defaults)
/// — evidence-based rather than guessed, since these are commonly tuned
/// away from their defaults on real servers.
fn dirty_pages_finding(data: &MemoryRawData) -> Finding {
    let dirty_pct = if data.mem_total_kb > 0 {
        data.dirty_kb as f64 / data.mem_total_kb as f64 * 100.0
    } else {
        0.0
    };

    // Ratio-based dirty-page tuning can be turned off in favor of the
    // *_bytes equivalents (vm.dirty_bytes / vm.dirty_background_bytes),
    // which reads as 0 here. Comparing against a zero threshold would be
    // meaningless (and falsely trigger on any nonzero dirty amount), so
    // this is reported as a distinct, honest case rather than guessed at.
    if data.dirty_ratio == 0 || data.dirty_background_ratio == 0 {
        return Finding::builder(
            "MEM005",
            "Dirty Page / Writeback Pressure",
            Category::Memory,
            Severity::Info,
            Confidence::direct_observation(),
        )
        .evidence("dirty_kb", data.dirty_kb.to_string())
        .evidence("dirty_percent", format!("{dirty_pct:.2}"))
        .evidence("dirty_background_ratio", data.dirty_background_ratio.to_string())
        .evidence("dirty_ratio", data.dirty_ratio.to_string())
        .explanation(format!(
            "{dirty_pct:.1}% of memory is currently dirty (modified, not yet \
             written to disk). This system's vm.dirty_ratio or \
             vm.dirty_background_ratio is set to 0, which usually means the \
             byte-based equivalents (vm.dirty_bytes / \
             vm.dirty_background_bytes) are in effect instead — this tool \
             doesn't currently compare against those."
        ))
        .build();
    }

    let (severity, confidence, explanation) = if dirty_pct >= data.dirty_ratio as f64 {
        (
            Severity::Error,
            Confidence::strong_indication(87),
            format!(
                "{dirty_pct:.1}% of memory is dirty — at or above this \
                 system's configured vm.dirty_ratio of {}%. Past this point \
                 processes writing to disk can block synchronously until the \
                 kernel catches up, which shows up as I/O stalls.",
                data.dirty_ratio,
            ),
        )
    } else if dirty_pct >= data.dirty_background_ratio as f64 {
        (
            Severity::Warning,
            Confidence::strong_indication(78),
            format!(
                "{dirty_pct:.1}% of memory is dirty — at or above this \
                 system's configured vm.dirty_background_ratio of {}%, so the \
                 kernel should already be actively flushing pages to disk in \
                 the background. Not necessarily a problem on its own, but \
                 worth watching if it stays elevated.",
                data.dirty_background_ratio,
            ),
        )
    } else {
        (
            Severity::Info,
            Confidence::direct_observation(),
            format!(
                "{dirty_pct:.1}% of memory is dirty, comfortably below this \
                 system's configured background writeback threshold of {}%.",
                data.dirty_background_ratio,
            ),
        )
    };

    let mut builder = Finding::builder(
        "MEM005",
        "Dirty Page / Writeback Pressure",
        Category::Memory,
        severity,
        confidence,
    )
    .evidence("dirty_kb", data.dirty_kb.to_string())
    .evidence("dirty_percent", format!("{dirty_pct:.2}"))
    .evidence("dirty_background_ratio", data.dirty_background_ratio.to_string())
    .evidence("dirty_ratio", data.dirty_ratio.to_string())
    .explanation(explanation);

    if severity > Severity::Info {
        builder = builder.recommendation(
            "Check what's generating the writes with `iostat -x 1` or \
             `vmstat 1`. If this is expected under sustained write load, \
             consider tuning vm.dirty_background_ratio / vm.dirty_ratio (or \
             the *_bytes equivalents) to flush more gradually, and confirm \
             the underlying storage can keep up.",
        );
    }
    builder.build()
}

/// MEM006 — always reported. Shared memory (tmpfs/shm) isn't reclaimable
/// the way page cache is, so unlike MEM004's cached figure, a large value
/// here directly competes with applications for RAM.
fn shared_memory_finding(data: &MemoryRawData) -> Finding {
    let shmem_pct = if data.mem_total_kb > 0 {
        data.shmem_kb as f64 / data.mem_total_kb as f64 * 100.0
    } else {
        0.0
    };

    let (severity, confidence, explanation) = if shmem_pct >= 25.0 {
        (
            Severity::Error,
            Confidence::strong_indication(85),
            format!(
                "Shared memory (tmpfs, /dev/shm, SysV/POSIX shm segments) \
                 accounts for {shmem_pct:.1}% of total RAM. Unlike page \
                 cache, this memory isn't automatically reclaimable — it \
                 stays allocated until something explicitly frees it (or it \
                 gets swapped out), so it competes directly with \
                 applications for RAM."
            ),
        )
    } else if shmem_pct >= 10.0 {
        (
            Severity::Warning,
            Confidence::strong_indication(76),
            format!(
                "Shared memory accounts for {shmem_pct:.1}% of total RAM — \
                 worth knowing what's using it, since it isn't reclaimable \
                 the way page cache is."
            ),
        )
    } else {
        (
            Severity::Info,
            Confidence::direct_observation(),
            format!(
                "Shared memory accounts for {shmem_pct:.1}% of total RAM, a \
                 normal level."
            ),
        )
    };

    let mut builder = Finding::builder(
        "MEM006",
        "Shared Memory Usage",
        Category::Memory,
        severity,
        confidence,
    )
    .evidence("shmem_kb", data.shmem_kb.to_string())
    .evidence("shmem_percent", format!("{shmem_pct:.1}"))
    .explanation(explanation);

    if severity > Severity::Info {
        builder = builder.recommendation(
            "Find what's using it: `du -sh /dev/shm`, `ipcs -m` for SysV \
             shared segments, and `df -h -t tmpfs` for tmpfs mounts sized \
             larger than expected. Large temp files or caches an \
             application places in /dev/shm are common culprits.",
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

    fn base_data() -> MemoryRawData {
        MemoryRawData {
            mem_total_kb: 16_384_000,
            mem_free_kb: 7_500_000,
            mem_available_kb: 8_000_000, // plenty free
            cached_kb: 4_300_000,
            shmem_kb: 200_000, // ~1.2%, normal
            dirty_kb: 16_000,  // ~0.1%, well below defaults
            swap_total_kb: 4_194_300,
            swap_free_kb: 4_194_300, // swap fully unused
            swappiness: 60,
            dirty_ratio: 20,
            dirty_background_ratio: 10,
        }
    }

    #[test]
    fn always_reports_overview_and_swappiness() {
        let findings = analyze(&base_data(), &ctx());
        assert!(findings.iter().any(|f| f.id == "MEM004"));
        assert!(findings.iter().any(|f| f.id == "MEM001"));
    }

    #[test]
    fn overview_reports_used_as_total_minus_available() {
        let findings = analyze(&base_data(), &ctx());
        let overview = findings.iter().find(|f| f.id == "MEM004").unwrap();
        // 16_384_000 - 8_000_000 = 8_384_000
        assert!(overview
            .evidence
            .iter()
            .any(|(k, v)| k == "used_kb" && v == "8384000"));
    }

    #[test]
    fn no_swap_pressure_finding_when_swap_unused() {
        let findings = analyze(&base_data(), &ctx());
        assert!(!findings.iter().any(|f| f.id == "MEM002"));
    }

    #[test]
    fn info_level_swap_pressure_when_memory_is_ample() {
        let mut data = base_data();
        data.swap_free_kb = 100_000; // swap in use
        let findings = analyze(&data, &ctx());
        let mem002 = findings.iter().find(|f| f.id == "MEM002").unwrap();
        assert_eq!(mem002.severity, Severity::Info);
    }

    #[test]
    fn warning_level_swap_pressure_when_memory_is_tight() {
        let mut data = base_data();
        data.swap_free_kb = 100_000;
        data.mem_available_kb = 1_000_000; // ~6.1% available
        let findings = analyze(&data, &ctx());
        let mem002 = findings.iter().find(|f| f.id == "MEM002").unwrap();
        assert_eq!(mem002.severity, Severity::Warning);
    }

    #[test]
    fn error_level_swap_pressure_when_memory_is_nearly_gone() {
        let mut data = base_data();
        data.swap_free_kb = 100_000;
        data.mem_available_kb = 300_000; // ~1.8% available
        let findings = analyze(&data, &ctx());
        let mem002 = findings.iter().find(|f| f.id == "MEM002").unwrap();
        assert_eq!(mem002.severity, Severity::Error);
    }

    #[test]
    fn low_swappiness_note_appears_when_swapping_anyway() {
        let mut data = base_data();
        data.swap_free_kb = 100_000; // swap in use
        data.swappiness = 1;
        let findings = analyze(&data, &ctx());
        let mem002 = findings.iter().find(|f| f.id == "MEM002").unwrap();
        assert!(mem002.explanation.contains("stronger signal"));
    }

    #[test]
    fn high_swappiness_gets_no_low_swappiness_note() {
        let mut data = base_data();
        data.swap_free_kb = 100_000;
        data.swappiness = 60;
        let findings = analyze(&data, &ctx());
        let mem002 = findings.iter().find(|f| f.id == "MEM002").unwrap();
        assert!(!mem002.explanation.contains("stronger signal"));
    }

    #[test]
    fn critical_finding_when_memory_low_and_swap_exhausted() {
        let mut data = base_data();
        data.mem_available_kb = 200_000; // ~1.2% available
        data.swap_free_kb = 0; // swap exhausted
        let findings = analyze(&data, &ctx());
        let mem003 = findings.iter().find(|f| f.id == "MEM003");
        assert!(mem003.is_some());
        assert_eq!(mem003.unwrap().severity, Severity::Critical);
    }

    #[test]
    fn no_critical_finding_when_swap_still_has_room() {
        let mut data = base_data();
        data.mem_available_kb = 200_000; // low, but swap still has room
        let findings = analyze(&data, &ctx());
        assert!(!findings.iter().any(|f| f.id == "MEM003"));
    }

    #[test]
    fn dirty_pages_info_when_below_background_threshold() {
        let findings = analyze(&base_data(), &ctx());
        let mem005 = findings.iter().find(|f| f.id == "MEM005").unwrap();
        assert_eq!(mem005.severity, Severity::Info);
    }

    #[test]
    fn dirty_pages_warning_at_background_ratio() {
        let mut data = base_data();
        // 10% of 16_384_000 = 1_638_400
        data.dirty_kb = 1_700_000;
        let findings = analyze(&data, &ctx());
        let mem005 = findings.iter().find(|f| f.id == "MEM005").unwrap();
        assert_eq!(mem005.severity, Severity::Warning);
        assert!(mem005.recommendation.is_some());
    }

    #[test]
    fn dirty_pages_error_at_dirty_ratio() {
        let mut data = base_data();
        // 20% of 16_384_000 = 3_276_800
        data.dirty_kb = 3_400_000;
        let findings = analyze(&data, &ctx());
        let mem005 = findings.iter().find(|f| f.id == "MEM005").unwrap();
        assert_eq!(mem005.severity, Severity::Error);
    }

    #[test]
    fn dirty_pages_handles_bytes_based_tuning_gracefully() {
        let mut data = base_data();
        data.dirty_ratio = 0; // ratio tuning disabled in favor of *_bytes
        data.dirty_kb = 5_000_000; // would be well above 20% if compared naively
        let findings = analyze(&data, &ctx());
        let mem005 = findings.iter().find(|f| f.id == "MEM005").unwrap();
        assert_eq!(mem005.severity, Severity::Info);
        assert!(mem005.explanation.contains("dirty_bytes"));
    }

    #[test]
    fn shared_memory_info_when_normal() {
        let findings = analyze(&base_data(), &ctx());
        let mem006 = findings.iter().find(|f| f.id == "MEM006").unwrap();
        assert_eq!(mem006.severity, Severity::Info);
    }

    #[test]
    fn shared_memory_warning_tier() {
        let mut data = base_data();
        data.shmem_kb = 2_000_000; // ~12.2%
        let findings = analyze(&data, &ctx());
        let mem006 = findings.iter().find(|f| f.id == "MEM006").unwrap();
        assert_eq!(mem006.severity, Severity::Warning);
        assert!(mem006.recommendation.is_some());
    }

    #[test]
    fn shared_memory_error_tier() {
        let mut data = base_data();
        data.shmem_kb = 5_000_000; // ~30.5%
        let findings = analyze(&data, &ctx());
        let mem006 = findings.iter().find(|f| f.id == "MEM006").unwrap();
        assert_eq!(mem006.severity, Severity::Error);
    }

    #[test]
    fn confidence_never_reported_below_60() {
        for data in [base_data()] {
            for f in analyze(&data, &ctx()) {
                assert!(f.confidence.percent >= 60);
            }
        }
    }
}
