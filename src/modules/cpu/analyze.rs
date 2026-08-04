// SPDX-License-Identifier: GPL-3.0-only

use crate::core::context::Context;
use crate::models::{Category, Confidence, Finding, Severity};

use super::collect::CpuRawData;

/// Pure function: RawData -> Findings. No I/O — see ARCHITECTURE.md
/// "Testing Strategy".
pub fn analyze(data: &CpuRawData, ctx: &Context) -> Vec<Finding> {
    let mut findings = vec![cpu_info_finding(data, ctx)];

    if let Some(f) = load_pressure_finding(data, ctx) {
        findings.push(f);
    }
    if let Some(f) = sustained_overload_finding(data, ctx) {
        findings.push(f);
    }

    findings
}

/// CPU001 — always reported, purely informational.
fn cpu_info_finding(data: &CpuRawData, ctx: &Context) -> Finding {
    let plural = if ctx.cpu_count == 1 { "" } else { "s" };
    let model_sentence = data
        .model_name
        .as_deref()
        .map(|m| format!(" Detected model: {m}."))
        .unwrap_or_default();

    let mut builder = Finding::builder(
        "CPU001",
        "CPU Information",
        Category::Cpu,
        Severity::Info,
        Confidence::direct_observation(),
    )
    .evidence("cpu_count", ctx.cpu_count.to_string());

    if let Some(model) = &data.model_name {
        builder = builder.evidence("model", model.clone());
    }

    builder
        .explanation(format!(
            "This system has {} logical CPU{plural}.{model_sentence}",
            ctx.cpu_count
        ))
        .build()
}

/// CPU002 — 1-minute load relative to available CPUs. Severity and
/// confidence scale with the ratio, mirroring MEM002's shape.
fn load_pressure_finding(data: &CpuRawData, ctx: &Context) -> Option<Finding> {
    if ctx.cpu_count == 0 {
        return None;
    }
    let ratio_1m = data.load_1m / ctx.cpu_count as f64;

    let (severity, confidence, explanation) = if ratio_1m < 1.0 {
        (
            Severity::Info,
            Confidence::weak_indication(70),
            "The 1-minute load average is within the number of available CPUs. \
             This is not necessarily worth investigating."
                .to_string(),
        )
    } else if ratio_1m < 2.0 {
        (
            Severity::Warning,
            Confidence::strong_indication(80),
            "The 1-minute load average exceeds the number of available CPUs. \
             Some processes are likely queueing for CPU time — not necessarily \
             a problem on its own if this is a brief spike."
                .to_string(),
        )
    } else {
        (
            Severity::Error,
            Confidence::strong_indication(88),
            "The 1-minute load average is more than twice the number of \
             available CPUs. This commonly indicates CPU contention affecting \
             responsiveness."
                .to_string(),
        )
    };

    Some(
        Finding::builder(
            "CPU002",
            "Load Average Pressure",
            Category::Cpu,
            severity,
            confidence,
        )
        .evidence("load_1m", format!("{:.2}", data.load_1m))
        .evidence("cpu_count", ctx.cpu_count.to_string())
        .evidence("ratio", format!("{ratio_1m:.2}"))
        .explanation(explanation)
        .recommendation(
            "Identify high-CPU processes (top, htop, pidstat) and consider \
             whether more cores or lower CPU usage is needed.",
        )
        .build(),
    )
}

/// CPU003 — only fires when the 1, 5, AND 15-minute windows all exceed
/// available CPUs: a sustained bottleneck rather than a brief spike.
fn sustained_overload_finding(data: &CpuRawData, ctx: &Context) -> Option<Finding> {
    if ctx.cpu_count == 0 {
        return None;
    }
    let n = ctx.cpu_count as f64;
    let sustained = data.load_1m >= n && data.load_5m >= n && data.load_15m >= n;
    if !sustained {
        return None;
    }

    Some(
        Finding::builder(
            "CPU003",
            "Sustained CPU Overload",
            Category::Cpu,
            Severity::Critical,
            Confidence::correlated(93),
        )
        .evidence("load_1m", format!("{:.2}", data.load_1m))
        .evidence("load_5m", format!("{:.2}", data.load_5m))
        .evidence("load_15m", format!("{:.2}", data.load_15m))
        .evidence("cpu_count", ctx.cpu_count.to_string())
        .explanation(
            "Load average exceeds the number of available CPUs across the 1, \
             5, and 15-minute windows. This indicates a persistent bottleneck \
             rather than a brief spike."
                .to_string(),
        )
        .recommendation(
            "Investigate sustained high-CPU processes, or consider scaling to \
             more cores.",
        )
        .build(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ctx(cpu_count: usize) -> Context {
        Context {
            hostname: "test".into(),
            kernel_version: "test".into(),
            distro: None,
            architecture: "x86_64".into(),
            cpu_count,
            mem_total_kb: 16_384_000,
            boot_time_unix: 0,
        }
    }

    fn data(load_1m: f64, load_5m: f64, load_15m: f64) -> CpuRawData {
        CpuRawData {
            load_1m,
            load_5m,
            load_15m,
            model_name: Some("Test CPU".to_string()),
        }
    }

    #[test]
    fn always_reports_cpu_info() {
        let findings = analyze(&data(0.1, 0.1, 0.1), &ctx(4));
        assert!(findings.iter().any(|f| f.id == "CPU001"));
    }

    #[test]
    fn info_level_when_load_below_capacity() {
        let findings = analyze(&data(1.5, 0.5, 0.5), &ctx(4));
        let cpu002 = findings.iter().find(|f| f.id == "CPU002").unwrap();
        assert_eq!(cpu002.severity, Severity::Info);
    }

    #[test]
    fn warning_level_when_load_exceeds_capacity() {
        let findings = analyze(&data(6.0, 1.0, 1.0), &ctx(4));
        let cpu002 = findings.iter().find(|f| f.id == "CPU002").unwrap();
        assert_eq!(cpu002.severity, Severity::Warning);
    }

    #[test]
    fn error_level_when_load_more_than_double_capacity() {
        let findings = analyze(&data(9.0, 1.0, 1.0), &ctx(4));
        let cpu002 = findings.iter().find(|f| f.id == "CPU002").unwrap();
        assert_eq!(cpu002.severity, Severity::Error);
    }

    #[test]
    fn no_critical_finding_on_transient_spike() {
        // 1-minute is elevated but 5/15-minute have not caught up yet.
        let findings = analyze(&data(9.0, 2.0, 1.0), &ctx(4));
        assert!(!findings.iter().any(|f| f.id == "CPU003"));
    }

    #[test]
    fn critical_finding_when_overload_is_sustained() {
        let findings = analyze(&data(9.0, 8.0, 7.0), &ctx(4));
        let cpu003 = findings.iter().find(|f| f.id == "CPU003");
        assert!(cpu003.is_some());
        assert_eq!(cpu003.unwrap().severity, Severity::Critical);
    }

    #[test]
    fn confidence_never_reported_below_60() {
        for d in [data(0.1, 0.1, 0.1), data(9.0, 8.0, 7.0)] {
            for f in analyze(&d, &ctx(4)) {
                assert!(f.confidence.percent >= 60);
            }
        }
    }
}
