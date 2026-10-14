// SPDX-License-Identifier: GPL-3.0-only

use crate::core::context::Context;
use crate::models::{Category, Confidence, Finding, Severity};

use super::collect::{GpuInfo, GpuProcess, GpuRawData, GpuVendor};

/// Pure function: RawData -> Findings. No I/O — see ARCHITECTURE.md
/// "Testing Strategy".
pub fn analyze(data: &GpuRawData, _ctx: &Context) -> Vec<Finding> {
    let mut findings = vec![summary_finding(data)];
    for gpu in &data.gpus {
        findings.push(detail_finding(gpu));
    }
    findings
}

fn vendor_label(vendor: GpuVendor) -> &'static str {
    match vendor {
        GpuVendor::Nvidia => "NVIDIA",
        GpuVendor::Amd => "AMD",
        GpuVendor::Intel => "Intel",
        GpuVendor::Other => "unknown vendor",
    }
}

/// GPU001 — always reported, same "always present" reasoning as
/// STOR003/CPU005/KERN002: a missing per-GPU finding should never be
/// ambiguous between "no GPU" and "didn't check".
fn summary_finding(data: &GpuRawData) -> Finding {
    let count = data.gpus.len();

    let mut explanation = if count == 0 {
        "No GPU detected under /sys/class/drm. This is expected on a \
         headless server or minimal VM with no graphics hardware exposed \
         — not itself a problem."
            .to_string()
    } else {
        let mut vendor_counts: Vec<(&str, usize)> = Vec::new();
        for gpu in &data.gpus {
            let label = vendor_label(gpu.vendor);
            if let Some(entry) = vendor_counts.iter_mut().find(|(v, _)| *v == label) {
                entry.1 += 1;
            } else {
                vendor_counts.push((label, 1));
            }
        }
        let breakdown: Vec<String> = vendor_counts
            .iter()
            .map(|(label, n)| format!("{n} {label}"))
            .collect();
        format!(
            "{count} GPU{s} detected: {}.",
            breakdown.join(", "),
            s = if count == 1 { "" } else { "s" },
        )
    };

    let mut builder = Finding::builder(
        "GPU001",
        "GPU Inventory Summary",
        Category::Gpu,
        Severity::Info,
        Confidence::direct_observation(),
    )
    .evidence("gpu_count", count.to_string());

    if let Some(v) = &data.nvidia_max_cuda_version {
        explanation.push_str(&format!(
            " Maximum CUDA version supported by the installed NVIDIA \
             driver: {v} — this is the driver's own capability ceiling, \
             *not* the CUDA Toolkit version an application actually \
             uses (check `nvcc --version` for that, if a toolkit is \
             installed at all); the two commonly differ and are easy to \
             conflate."
        ));
        builder = builder.evidence("nvidia_max_cuda_version", v.clone());
    }

    builder.explanation(explanation).build()
}

/// Format VRAM as "13456 MB used of 49152 MB (27.4%)" when both figures
/// are known, degrading gracefully when only one is.
fn format_vram(used_mb: Option<u64>, total_mb: Option<u64>) -> Option<String> {
    match (used_mb, total_mb) {
        (Some(used), Some(total)) if total > 0 => {
            let pct = used as f64 / total as f64 * 100.0;
            Some(format!("{used} MB used of {total} MB ({pct:.1}%)"))
        }
        (None, Some(total)) => Some(format!("{total} MB total")),
        (Some(used), None) => Some(format!("{used} MB used")),
        _ => None,
    }
}

fn format_processes(processes: &[GpuProcess]) -> Option<String> {
    if processes.is_empty() {
        return None;
    }
    let parts: Vec<String> = processes
        .iter()
        .map(|p| match p.memory_mb {
            Some(mb) => format!("{} (pid {}, {mb} MB)", p.name, p.pid),
            None => format!("{} (pid {})", p.name, p.pid),
        })
        .collect();
    Some(parts.join(", "))
}

/// GPU002 — one finding per GPU. Temperature is the one metric this
/// escalates severity on: utilization, VRAM usage, and power draw near
/// the card's limit are often *intentional* (a card doing real work),
/// not a problem, so they stay Info-level context rather than alerts —
/// same reasoning Virtualization's resource-usage findings use.
fn detail_finding(gpu: &GpuInfo) -> Finding {
    let vendor = vendor_label(gpu.vendor);
    let model = gpu.description.as_deref().unwrap_or("model unknown");
    // Avoid "NVIDIA NVIDIA GeForce RTX 4090": nvidia-smi's own reported
    // name (used as `description` when lspci found nothing better)
    // commonly already starts with the vendor name.
    let model_prefix = if model.to_uppercase().starts_with(&vendor.to_uppercase()) {
        String::new()
    } else {
        format!("{vendor} ")
    };

    let driver_note = match &gpu.driver {
        Some(d) if d == "nouveau" => ", using the open-source \"nouveau\" driver — a deliberate \
             choice for some, but with known performance/feature gaps \
             versus NVIDIA's proprietary driver on modern cards"
            .to_string(),
        Some(d) => format!(", driver {d}"),
        None => String::new(),
    };
    let driver_version_note = gpu
        .driver_version
        .as_deref()
        .map(|v| format!(" (driver version {v})"))
        .unwrap_or_default();

    let (severity, confidence, temp_note) = match (gpu.temperature_c, gpu.temperature_crit_c) {
        (Some(t), Some(crit)) if crit > 0.0 => {
            let ratio = t / crit;
            let (sev, conf) = if ratio >= 0.98 {
                (Severity::Error, Confidence::strong_indication(85))
            } else if ratio >= 0.90 {
                (Severity::Warning, Confidence::strong_indication(78))
            } else {
                (Severity::Info, Confidence::direct_observation())
            };
            (
                sev,
                conf,
                format!(
                    " Temperature: {t:.0}\u{b0}C (this card's own critical \
                     threshold is {crit:.0}\u{b0}C — currently at {:.0}% of it).",
                    ratio * 100.0,
                ),
            )
        }
        (Some(t), None) => {
            // No card-specific critical value available (NVIDIA) -- a
            // more conservative, generic threshold, clearly labeled as
            // such rather than presented as precisely as the AMD case.
            let (sev, conf) = if t >= 95.0 {
                (Severity::Warning, Confidence::weak_indication(65))
            } else {
                (Severity::Info, Confidence::direct_observation())
            };
            (
                sev,
                conf,
                format!(
                    " Temperature: {t:.0}\u{b0}C (no card-specific critical \
                     threshold available for this vendor — {} is a \
                     generic caution point, not this card's own limit).",
                    "95\u{b0}C+",
                ),
            )
        }
        _ => (
            Severity::Info,
            Confidence::direct_observation(),
            String::new(),
        ),
    };

    let util_note = match (gpu.utilization_percent, gpu.memory_utilization_percent) {
        (Some(u), Some(mu)) => format!(" Utilization: {u:.0}% GPU, {mu:.0}% memory controller."),
        (Some(u), None) => format!(" Utilization: {u:.0}% GPU."),
        _ => String::new(),
    };

    let vram_note = format_vram(gpu.vram_used_mb, gpu.vram_total_mb)
        .map(|v| format!(" VRAM: {v}."))
        .unwrap_or_default();

    let power_note = match (gpu.power_draw_w, gpu.power_limit_w) {
        (Some(draw), Some(limit)) if limit > 0.0 => {
            format!(
                " Power: {draw:.1} W of {limit:.1} W limit ({:.0}%).",
                draw / limit * 100.0
            )
        }
        (Some(draw), None) => format!(" Power: {draw:.1} W."),
        _ => String::new(),
    };

    let fan_note = match (gpu.fan_percent, gpu.fan_rpm) {
        (Some(pct), _) => format!(" Fan: {pct:.0}%."),
        (None, Some(rpm)) => format!(" Fan: {rpm} RPM."),
        (None, None) => String::new(),
    };

    let clock_note = match (gpu.clock_core_mhz, gpu.clock_memory_mhz) {
        (Some(core), Some(mem)) => format!(" Clocks: {core} MHz core, {mem} MHz memory."),
        (Some(core), None) => format!(" Clock: {core} MHz core."),
        (None, Some(mem)) => format!(" Clock: {mem} MHz memory."),
        (None, None) => String::new(),
    };

    let pcie_note = match (
        &gpu.pcie_link_speed_current,
        &gpu.pcie_link_speed_max,
        gpu.pcie_link_width_current,
        gpu.pcie_link_width_max,
    ) {
        (Some(cur_speed), Some(max_speed), Some(cur_width), Some(max_width)) => {
            if cur_speed != max_speed || cur_width != max_width {
                format!(
                    " PCIe: currently {cur_speed} x{cur_width}, below this \
                     card's maximum of {max_speed} x{max_width} — worth \
                     checking the physical slot/cable if unexpected (could \
                     also just be a normal idle power-saving state)."
                )
            } else {
                format!(
                    " PCIe: {cur_speed} x{cur_width} (matches this card's \
                     maximum — though some systems report the maximum \
                     here even during idle/power-saving states rather \
                     than a true live reading, a known kernel/driver \
                     quirk, not confirmed either way for this system)."
                )
            }
        }
        _ => String::new(),
    };

    let no_driver_note = if gpu.driver.is_none() {
        " No kernel driver is bound to this GPU — if this is unexpected, \
         a proprietary driver (NVIDIA) may need installing, or the \
         open-source driver failed to bind (check `dmesg`)."
    } else {
        ""
    };

    let processes_note = format_processes(&gpu.processes)
        .map(|p| format!(" Processes using this GPU: {p}."))
        .unwrap_or_default();

    let explanation = format!(
        "{model_prefix}{model}{driver_note}{driver_version_note}.{temp_note}{util_note}{vram_note}{power_note}{fan_note}{clock_note}{pcie_note}{no_driver_note}{processes_note}"
    );

    // A missing driver is a distinct, always-worth-flagging concern,
    // layered on top of (not overriding) whatever the temperature check
    // already decided — e.g. a hot card with no driver bound stays at
    // whichever severity is higher.
    let severity = if gpu.driver.is_none() {
        severity.max(Severity::Warning)
    } else {
        severity
    };

    let mut builder = Finding::builder(
        "GPU002",
        format!("GPU \u{2014} {} ({model})", gpu.name),
        Category::Gpu,
        severity,
        confidence,
    )
    .instance(gpu.name.clone())
    .evidence("vendor", vendor.to_string())
    .evidence("pci_address", gpu.pci_address.clone());

    if let Some(d) = &gpu.driver {
        builder = builder.evidence("driver", d.clone());
    }
    if let Some(v) = &gpu.driver_version {
        builder = builder.evidence("driver_version", v.clone());
    }
    if let Some(t) = gpu.temperature_c {
        builder = builder.evidence("temperature_c", format!("{t:.1}"));
    }
    if let Some(c) = gpu.temperature_crit_c {
        builder = builder.evidence("temperature_crit_c", format!("{c:.1}"));
    }
    if let Some(u) = gpu.utilization_percent {
        builder = builder.evidence("utilization_percent", format!("{u:.1}"));
    }
    if let Some(mu) = gpu.memory_utilization_percent {
        builder = builder.evidence("memory_utilization_percent", format!("{mu:.1}"));
    }
    if let Some(v) = gpu.vram_total_mb {
        builder = builder.evidence("vram_total_mb", v.to_string());
    }
    if let Some(v) = gpu.vram_used_mb {
        builder = builder.evidence("vram_used_mb", v.to_string());
    }
    if let Some(p) = gpu.power_draw_w {
        builder = builder.evidence("power_draw_w", format!("{p:.1}"));
    }
    if let Some(p) = gpu.power_limit_w {
        builder = builder.evidence("power_limit_w", format!("{p:.1}"));
    }
    if let Some(f) = gpu.fan_percent {
        builder = builder.evidence("fan_percent", format!("{f:.1}"));
    }
    if let Some(f) = gpu.fan_rpm {
        builder = builder.evidence("fan_rpm", f.to_string());
    }
    if let Some(c) = gpu.clock_core_mhz {
        builder = builder.evidence("clock_core_mhz", c.to_string());
    }
    if let Some(c) = gpu.clock_memory_mhz {
        builder = builder.evidence("clock_memory_mhz", c.to_string());
    }
    if let Some(s) = &gpu.pcie_link_speed_current {
        builder = builder.evidence("pcie_link_speed_current", s.clone());
    }
    if let Some(s) = &gpu.pcie_link_speed_max {
        builder = builder.evidence("pcie_link_speed_max", s.clone());
    }
    if let Some(w) = gpu.pcie_link_width_current {
        builder = builder.evidence("pcie_link_width_current", w.to_string());
    }
    if let Some(w) = gpu.pcie_link_width_max {
        builder = builder.evidence("pcie_link_width_max", w.to_string());
    }
    if !gpu.processes.is_empty() {
        builder = builder.evidence("process_count", gpu.processes.len().to_string());
    }

    builder = builder.explanation(explanation);

    if severity > Severity::Info {
        let recommendation = if gpu.driver.is_none() {
            "Check `dmesg` and `lspci -k` for why no driver bound to this \
             device. For NVIDIA cards, install the proprietary driver \
             package for your distro; for AMD/Intel, the in-tree \
             amdgpu/i915 driver should bind automatically unless \
             blacklisted."
        } else {
            "Check airflow/dust and case cooling. Sustained high \
             temperature accelerates hardware wear and can trigger \
             thermal throttling (reduced clocks) even before an outright \
             shutdown."
        };
        builder = builder.recommendation(recommendation);
    }

    builder.build()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::modules::gpu::collect::GpuVendor;

    fn ctx() -> Context {
        Context {
            hostname: "test".into(),
            kernel_version: "test".into(),
            distro: None,
            architecture: "x86_64".into(),
            cpu_count: 8,
            mem_total_kb: 16_000_000,
            boot_time_unix: 0,
        }
    }

    fn base_gpu() -> GpuInfo {
        GpuInfo {
            name: "card0".to_string(),
            pci_address: "0000:01:00.0".to_string(),
            vendor: GpuVendor::Amd,
            description: Some("Radeon RX 6800".to_string()),
            driver: Some("amdgpu".to_string()),
            driver_version: None,
            vram_total_mb: Some(16384),
            vram_used_mb: Some(4096),
            utilization_percent: Some(45.0),
            memory_utilization_percent: Some(20.0),
            temperature_c: Some(65.0),
            temperature_crit_c: Some(110.0),
            power_draw_w: Some(150.0),
            power_limit_w: Some(250.0),
            fan_percent: None,
            fan_rpm: Some(1800),
            clock_core_mhz: None,
            clock_memory_mhz: None,
            pcie_link_speed_current: None,
            pcie_link_speed_max: None,
            pcie_link_width_current: None,
            pcie_link_width_max: None,
            processes: vec![],
        }
    }

    #[test]
    fn no_gpu_summary_is_info() {
        let data = GpuRawData {
            gpus: vec![],
            nvidia_max_cuda_version: None,
        };
        let findings = analyze(&data, &ctx());
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].severity, Severity::Info);
        assert!(findings[0].explanation.contains("No GPU detected"));
    }

    #[test]
    fn summary_breaks_down_by_vendor() {
        let mut nvidia_gpu = base_gpu();
        nvidia_gpu.name = "card1".to_string();
        nvidia_gpu.vendor = GpuVendor::Nvidia;
        let data = GpuRawData {
            gpus: vec![base_gpu(), nvidia_gpu],
            nvidia_max_cuda_version: None,
        };
        let findings = analyze(&data, &ctx());
        let gpu001 = findings.iter().find(|f| f.id == "GPU001").unwrap();
        assert!(gpu001.explanation.contains("1 AMD"));
        assert!(gpu001.explanation.contains("1 NVIDIA"));
    }

    #[test]
    fn healthy_amd_gpu_is_info() {
        let data = GpuRawData {
            gpus: vec![base_gpu()],
            nvidia_max_cuda_version: None,
        };
        let findings = analyze(&data, &ctx());
        let gpu002 = findings.iter().find(|f| f.id == "GPU002").unwrap();
        assert_eq!(gpu002.severity, Severity::Info);
        assert_eq!(gpu002.instance.as_deref(), Some("card0"));
        assert!(gpu002.explanation.contains("AMD Radeon RX 6800"));
        assert!(gpu002.explanation.contains("65\u{b0}C"));
        assert!(gpu002
            .explanation
            .contains("4096 MB used of 16384 MB (25.0%)"));
    }

    #[test]
    fn amd_gpu_near_own_critical_temp_is_warning() {
        let mut gpu = base_gpu();
        gpu.temperature_c = Some(100.0); // 100/110 ~= 90.9%
        let data = GpuRawData {
            gpus: vec![gpu],
            nvidia_max_cuda_version: None,
        };
        let findings = analyze(&data, &ctx());
        let gpu002 = findings.iter().find(|f| f.id == "GPU002").unwrap();
        assert_eq!(gpu002.severity, Severity::Warning);
        assert!(gpu002.explanation.contains("critical threshold is 110"));
    }

    #[test]
    fn amd_gpu_essentially_at_critical_temp_is_error() {
        let mut gpu = base_gpu();
        gpu.temperature_c = Some(109.0); // 109/110 ~= 99.1%
        let data = GpuRawData {
            gpus: vec![gpu],
            nvidia_max_cuda_version: None,
        };
        let findings = analyze(&data, &ctx());
        let gpu002 = findings.iter().find(|f| f.id == "GPU002").unwrap();
        assert_eq!(gpu002.severity, Severity::Error);
    }

    #[test]
    fn nvidia_gpu_uses_generic_threshold_when_no_crit_value() {
        let mut gpu = base_gpu();
        gpu.vendor = GpuVendor::Nvidia;
        gpu.temperature_crit_c = None; // NVIDIA doesn't expose this the same way
        gpu.temperature_c = Some(96.0);
        let data = GpuRawData {
            gpus: vec![gpu],
            nvidia_max_cuda_version: None,
        };
        let findings = analyze(&data, &ctx());
        let gpu002 = findings.iter().find(|f| f.id == "GPU002").unwrap();
        assert_eq!(gpu002.severity, Severity::Warning);
        assert!(gpu002
            .explanation
            .contains("no card-specific critical threshold"));
        // Generic-threshold confidence must read lower than the
        // evidence-based AMD case above.
        assert!(gpu002.confidence.percent < 78);
    }

    #[test]
    fn high_utilization_alone_is_not_elevated_severity() {
        // Deliberately mirrors a card doing real, successful work --
        // not a problem on its own.
        let mut gpu = base_gpu();
        gpu.utilization_percent = Some(100.0);
        gpu.vram_used_mb = gpu.vram_total_mb;
        gpu.power_draw_w = gpu.power_limit_w;
        let data = GpuRawData {
            gpus: vec![gpu],
            nvidia_max_cuda_version: None,
        };
        let findings = analyze(&data, &ctx());
        let gpu002 = findings.iter().find(|f| f.id == "GPU002").unwrap();
        assert_eq!(gpu002.severity, Severity::Info);
    }

    #[test]
    fn missing_driver_is_warning_with_recommendation() {
        let mut gpu = base_gpu();
        gpu.driver = None;
        let data = GpuRawData {
            gpus: vec![gpu],
            nvidia_max_cuda_version: None,
        };
        let findings = analyze(&data, &ctx());
        let gpu002 = findings.iter().find(|f| f.id == "GPU002").unwrap();
        assert_eq!(gpu002.severity, Severity::Warning);
        assert!(gpu002.explanation.contains("No kernel driver is bound"));
        assert!(gpu002.recommendation.is_some());
    }

    #[test]
    fn missing_driver_severity_does_not_downgrade_hot_card() {
        let mut gpu = base_gpu();
        gpu.driver = None;
        gpu.temperature_c = Some(109.0); // would already be Error alone
        let data = GpuRawData {
            gpus: vec![gpu],
            nvidia_max_cuda_version: None,
        };
        let findings = analyze(&data, &ctx());
        let gpu002 = findings.iter().find(|f| f.id == "GPU002").unwrap();
        assert_eq!(gpu002.severity, Severity::Error);
    }

    #[test]
    fn nouveau_driver_gets_a_note() {
        let mut gpu = base_gpu();
        gpu.vendor = GpuVendor::Nvidia;
        gpu.driver = Some("nouveau".to_string());
        let data = GpuRawData {
            gpus: vec![gpu],
            nvidia_max_cuda_version: None,
        };
        let findings = analyze(&data, &ctx());
        let gpu002 = findings.iter().find(|f| f.id == "GPU002").unwrap();
        assert!(gpu002
            .explanation
            .contains("open-source \"nouveau\" driver"));
    }

    #[test]
    fn processes_surfaced_when_present() {
        let mut gpu = base_gpu();
        gpu.vendor = GpuVendor::Nvidia;
        gpu.processes = vec![GpuProcess {
            pid: 4051,
            name: "python3".to_string(),
            memory_mb: Some(1234),
        }];
        let data = GpuRawData {
            gpus: vec![gpu],
            nvidia_max_cuda_version: None,
        };
        let findings = analyze(&data, &ctx());
        let gpu002 = findings.iter().find(|f| f.id == "GPU002").unwrap();
        assert!(gpu002.explanation.contains("python3 (pid 4051, 1234 MB)"));
        assert!(gpu002
            .evidence
            .iter()
            .any(|(k, v)| k == "process_count" && v == "1"));
    }

    #[test]
    fn clocks_and_pcie_shown_when_present() {
        let mut gpu = base_gpu();
        gpu.clock_core_mhz = Some(2100);
        gpu.clock_memory_mhz = Some(1750);
        gpu.pcie_link_speed_current = Some("8.0 GT/s PCIe".to_string());
        gpu.pcie_link_speed_max = Some("16.0 GT/s PCIe".to_string());
        gpu.pcie_link_width_current = Some(8);
        gpu.pcie_link_width_max = Some(16);
        let data = GpuRawData {
            gpus: vec![gpu],
            nvidia_max_cuda_version: None,
        };
        let findings = analyze(&data, &ctx());
        let gpu002 = findings.iter().find(|f| f.id == "GPU002").unwrap();
        assert!(gpu002
            .explanation
            .contains("2100 MHz core, 1750 MHz memory"));
        assert!(gpu002.explanation.contains(
            "currently 8.0 GT/s PCIe x8, below this card's maximum of 16.0 GT/s PCIe x16"
        ));
        assert!(gpu002
            .explanation
            .contains("checking the physical slot/cable"));
        assert!(gpu002
            .evidence
            .iter()
            .any(|(k, v)| k == "pcie_link_width_current" && v == "8"));
    }

    #[test]
    fn pcie_at_max_gets_the_reliability_caveat_not_a_concern_note() {
        let mut gpu = base_gpu();
        gpu.pcie_link_speed_current = Some("16.0 GT/s PCIe".to_string());
        gpu.pcie_link_speed_max = Some("16.0 GT/s PCIe".to_string());
        gpu.pcie_link_width_current = Some(16);
        gpu.pcie_link_width_max = Some(16);
        let data = GpuRawData {
            gpus: vec![gpu],
            nvidia_max_cuda_version: None,
        };
        let findings = analyze(&data, &ctx());
        let gpu002 = findings.iter().find(|f| f.id == "GPU002").unwrap();
        assert!(gpu002.explanation.contains("known kernel/driver quirk"));
        // A PCIe reading at its own max, alone, must never raise severity.
        assert_eq!(gpu002.severity, Severity::Info);
    }

    #[test]
    fn summary_mentions_max_cuda_version_with_the_toolkit_distinction() {
        let mut gpu = base_gpu();
        gpu.vendor = GpuVendor::Nvidia;
        let data = GpuRawData {
            gpus: vec![gpu],
            nvidia_max_cuda_version: Some("12.4".to_string()),
        };
        let findings = analyze(&data, &ctx());
        let gpu001 = findings.iter().find(|f| f.id == "GPU001").unwrap();
        assert!(gpu001.explanation.contains("12.4"));
        assert!(gpu001.explanation.contains("not*"));
        assert!(gpu001.explanation.contains("nvcc --version"));
        assert!(gpu001
            .evidence
            .iter()
            .any(|(k, v)| k == "nvidia_max_cuda_version" && v == "12.4"));
    }

    #[test]
    fn no_cuda_version_evidence_without_nvidia_data() {
        let data = GpuRawData {
            gpus: vec![],
            nvidia_max_cuda_version: None,
        };
        let findings = analyze(&data, &ctx());
        let gpu001 = findings.iter().find(|f| f.id == "GPU001").unwrap();
        assert!(!gpu001.explanation.contains("CUDA"));
    }

    #[test]
    fn vendor_name_not_repeated_when_description_already_includes_it() {
        let mut gpu = base_gpu();
        gpu.vendor = GpuVendor::Nvidia;
        gpu.description = Some("NVIDIA GeForce RTX 4090".to_string());
        let data = GpuRawData {
            gpus: vec![gpu],
            nvidia_max_cuda_version: None,
        };
        let findings = analyze(&data, &ctx());
        let gpu002 = findings.iter().find(|f| f.id == "GPU002").unwrap();
        assert!(gpu002.explanation.starts_with("NVIDIA GeForce RTX 4090"));
        assert!(!gpu002.explanation.contains("NVIDIA NVIDIA"));
    }

    #[test]
    fn vendor_name_still_prefixed_when_description_omits_it() {
        // AMD's lspci-style descriptions typically don't repeat "AMD".
        let data = GpuRawData {
            gpus: vec![base_gpu()],
            nvidia_max_cuda_version: None,
        };
        let findings = analyze(&data, &ctx());
        let gpu002 = findings.iter().find(|f| f.id == "GPU002").unwrap();
        assert!(gpu002.explanation.starts_with("AMD Radeon RX 6800"));
    }

    #[test]
    fn confidence_never_reported_below_60() {
        for gpu in [base_gpu(), {
            let mut g = base_gpu();
            g.driver = None;
            g.temperature_c = None;
            g.temperature_crit_c = None;
            g
        }] {
            let data = GpuRawData {
                gpus: vec![gpu],
                nvidia_max_cuda_version: None,
            };
            for f in analyze(&data, &ctx()) {
                assert!(f.confidence.percent >= 60);
            }
        }
    }
}
