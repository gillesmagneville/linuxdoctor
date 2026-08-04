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

    findings.push(swappiness_finding(data));

    if let Some(f) = swap_pressure_finding(data) {
        findings.push(f);
    }

    if let Some(f) = critical_memory_finding(data) {
        findings.push(f);
    }

    findings
}

/// MEM001 — always reported. Directly mirrors the worked example in
/// PROJECT_CONTEXT.md's "Explain instead of dumping data" section.
fn swappiness_finding(data: &MemoryRawData) -> Finding {
    let is_default = data.swappiness == DEFAULT_SWAPPINESS;
    let explanation = if is_default {
        format!(
            "This is the default kernel value. For a desktop with large amounts \
             of RAM, a lower value is often preferred. No action required unless \
             swap activity is high."
        )
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

    let (severity, confidence, explanation) = if mem_available_pct < 3.0 {
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
            mem_available_kb: 8_000_000, // plenty free
            swap_total_kb: 4_194_300,
            swap_free_kb: 4_194_300, // swap fully unused
            swappiness: 60,
        }
    }

    #[test]
    fn always_reports_swappiness() {
        let findings = analyze(&base_data(), &ctx());
        assert!(findings.iter().any(|f| f.id == "MEM001"));
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
    fn confidence_never_reported_below_60() {
        for data in [base_data()] {
            for f in analyze(&data, &ctx()) {
                assert!(f.confidence.percent >= 60);
            }
        }
    }
}
