// SPDX-License-Identifier: GPL-3.0-only

use crate::core::context::Context;
use crate::models::{Category, Confidence, Finding, Severity};

use super::collect::{active_taint_bits, KernelRawData};

/// Pure function: RawData -> Findings. No I/O — see ARCHITECTURE.md
/// "Testing Strategy".
pub fn analyze(data: &KernelRawData, _ctx: &Context) -> Vec<Finding> {
    vec![
        taint_status_finding(data),
        oom_kill_finding(data),
        build_info_finding(data),
        reboot_required_finding(data),
        aslr_finding(data),
        boot_parameters_finding(data),
    ]
}

/// KERN001 — always reported, a single finding covering every active
/// taint bit (not per-bit findings: these are heterogeneous conditions,
/// not a list of similar sub-items the way sockets or filesystems are).
fn taint_status_finding(data: &KernelRawData) -> Finding {
    let active = active_taint_bits(data.tainted_raw);
    let severity = active
        .iter()
        .map(|b| b.severity)
        .max()
        .unwrap_or(Severity::Info);

    let explanation = if active.is_empty() {
        "The kernel is not tainted — a clean state with no recorded anomalies.".to_string()
    } else {
        let reasons: Vec<String> = active.iter().map(|b| b.description.to_string()).collect();
        format!(
            "The kernel is tainted: {}. Note the kernel stays tainted even \
             after the underlying cause is resolved (e.g. a module is \
             unloaded) — it's a historical record, not a live status.",
            reasons.join("; ")
        )
    };

    let codes: Vec<&str> = active.iter().map(|b| b.code).collect();

    let mut builder = Finding::builder(
        "KERN001",
        "Kernel Taint Status",
        Category::Kernel,
        severity,
        Confidence::direct_observation(),
    )
    .evidence("tainted_raw", data.tainted_raw.to_string())
    .evidence(
        "active_flags",
        if codes.is_empty() {
            "none".to_string()
        } else {
            codes.join(",")
        },
    )
    .explanation(explanation);

    if severity > Severity::Info {
        builder = builder.recommendation(
            "Check `dmesg` or `journalctl -k` around the time tainting occurred \
             for the specific event. A Machine Check Exception (M) or bad page \
             (B) can indicate failing hardware; an OOPS/BUG (D) or soft lockup \
             (L) is worth investigating, or reporting upstream if reproducible \
             on a current mainline kernel.",
        );
    }

    builder.build()
}

/// KERN002 — always reported. When the check itself couldn't run (no
/// permission to read dmesg — common, since kernel.dmesg_restrict often
/// limits it to root), says so explicitly rather than silently reporting
/// nothing, same reasoning as CPU005/NUMA002/STOR003.
fn oom_kill_finding(data: &KernelRawData) -> Finding {
    let Some(count) = data.oom_kill_count else {
        return Finding::builder(
            "KERN002",
            "OOM Kill History",
            Category::Kernel,
            Severity::Info,
            Confidence::direct_observation(),
        )
        .explanation(format!(
            "Could not check the kernel log for OOM killer activity: {}. \
             This commonly requires root (kernel.dmesg_restrict often \
             limits dmesg to root) — re-run as root/sudo for this check.",
            data.dmesg_error.as_deref().unwrap_or("dmesg unavailable"),
        ))
        .build();
    };

    let severity = if count == 0 {
        Severity::Info
    } else if count <= 2 {
        Severity::Warning
    } else {
        Severity::Error
    };

    let explanation = if count == 0 {
        "No OOM killer activity found in the kernel log. Note this only \
         covers what's still in the kernel ring buffer (dmesg), not \
         necessarily the whole uptime if the buffer has wrapped."
            .to_string()
    } else {
        format!(
            "{count} OOM kill event{s} found in the kernel log — the kernel \
             had to forcibly terminate process(es) to free memory. This is \
             a strong sign that memory sizing, or a specific process's \
             usage, needs attention.",
            s = if count == 1 { "" } else { "s" },
        )
    };

    let mut builder = Finding::builder(
        "KERN002",
        "OOM Kill History",
        Category::Kernel,
        severity,
        Confidence::direct_observation(),
    )
    .evidence("oom_kill_count", count.to_string())
    .explanation(explanation);

    if severity > Severity::Info {
        builder = builder.recommendation(
            "Check `dmesg | grep -i 'out of memory'` for which process(es) were \
             killed, and see the Memory module's findings for current \
             pressure. Consider adding RAM/swap, or investigating what's \
             consuming memory if one process keeps getting killed.",
        );
    }

    builder.build()
}

/// KERN003 — always reported. Purely informational context: what built
/// this kernel and when, useful to know whether it's a stock distro
/// kernel or something custom.
fn build_info_finding(data: &KernelRawData) -> Finding {
    let info = &data.build_info;
    let mut builder = Finding::builder(
        "KERN003",
        "Kernel Build Info",
        Category::Kernel,
        Severity::Info,
        Confidence::direct_observation(),
    );

    if let Some(v) = &info.build_user_host {
        builder = builder.evidence("build_user_host", v.clone());
    }
    if let Some(v) = &info.compiler {
        builder = builder.evidence("compiler", v.clone());
    }
    if let Some(v) = &info.build_tag {
        builder = builder.evidence("build_tag", v.clone());
    }

    let explanation = match (&info.build_user_host, &info.compiler) {
        (Some(host), Some(compiler)) => format!(
            "Built by {host} using {compiler}. Useful context when comparing \
             against a distro's official kernel build, or confirming this \
             is a custom-built kernel."
        ),
        _ => "Could not parse build details from /proc/version.".to_string(),
    };

    builder.explanation(explanation).build()
}

/// KERN004 — always reported. The Debian/Ubuntu `reboot-required`
/// convention is the only reliable, dependency-free signal of this kind
/// available across distros — other families don't have an equivalent
/// marker file, so absence there is reported honestly as "not confirmed
/// either way", not as "no reboot needed".
fn reboot_required_finding(data: &KernelRawData) -> Finding {
    let info = &data.reboot_required;

    let (severity, explanation) = if info.marker_present {
        let pkgs = if info.packages.is_empty() {
            String::new()
        } else {
            format!(" Packages that triggered it: {}.", info.packages.join(", "))
        };
        (
            Severity::Warning,
            format!(
                "/var/run/reboot-required is present — a package update \
                 (commonly a kernel or glibc update) needs a reboot to take \
                 effect. Until then, this system keeps running the old \
                 kernel/libraries, so any security fixes in the update \
                 aren't active yet.{pkgs}"
            ),
        )
    } else {
        (
            Severity::Info,
            "No /var/run/reboot-required marker present. This is a \
             Debian/Ubuntu-specific convention — its absence confirms \
             nothing on other distributions, which don't use this file at \
             all."
                .to_string(),
        )
    };

    let mut builder = Finding::builder(
        "KERN004",
        "Reboot Required",
        Category::Kernel,
        severity,
        Confidence::direct_observation(),
    )
    .evidence("marker_present", info.marker_present.to_string());

    if !info.packages.is_empty() {
        builder = builder.evidence("packages", info.packages.join(","));
    }

    builder = builder.explanation(explanation);

    if severity > Severity::Info {
        builder = builder.recommendation(
            "Reboot at the next convenient maintenance window to apply the \
             pending update(s). `cat /var/run/reboot-required.pkgs` lists \
             what triggered it, if you need to confirm before scheduling \
             downtime.",
        );
    }

    builder.build()
}

/// KERN005 — always reported. ASLR is a basic, well-understood exploit
/// mitigation; disabling it is occasionally deliberate (some debugging
/// workflows) but usually not intentional.
fn aslr_finding(data: &KernelRawData) -> Finding {
    let (severity, explanation) = match data.aslr_mode {
        Some(0) => (
            Severity::Warning,
            "Address Space Layout Randomization (ASLR) is fully disabled \
             (kernel.randomize_va_space=0). This makes memory-corruption \
             exploits meaningfully easier, since process memory layout is \
             predictable. Sometimes disabled deliberately for debugging — \
             worth confirming that's the reason here."
                .to_string(),
        ),
        Some(1) => (
            Severity::Info,
            "ASLR is partially enabled (kernel.randomize_va_space=1): \
             stack, mmap base, and VDSO are randomized, but not the heap."
                .to_string(),
        ),
        Some(2) => (
            Severity::Info,
            "ASLR is fully enabled (kernel.randomize_va_space=2), including \
             heap randomization — the default and recommended setting on \
             modern kernels."
                .to_string(),
        ),
        Some(other) => (
            Severity::Info,
            format!("kernel.randomize_va_space reports an unrecognized value ({other})."),
        ),
        None => (
            Severity::Info,
            "Could not read kernel.randomize_va_space.".to_string(),
        ),
    };

    let mut builder = Finding::builder(
        "KERN005",
        "ASLR Status",
        Category::Kernel,
        severity,
        Confidence::direct_observation(),
    );

    if let Some(mode) = data.aslr_mode {
        builder = builder.evidence("randomize_va_space", mode.to_string());
    }

    builder = builder.explanation(explanation);

    if severity > Severity::Info {
        builder = builder.recommendation(
            "If this wasn't intentional, re-enable it: `sysctl -w \
             kernel.randomize_va_space=2` (add to /etc/sysctl.d/ to persist \
             across reboots).",
        );
    }

    builder.build()
}

/// KERN006 — always reported. A small, curated set of boot parameters
/// worth surfacing on their own, not an exhaustive cmdline linter.
fn boot_parameters_finding(data: &KernelRawData) -> Finding {
    let flags = &data.notable_cmdline_flags;

    let (severity, explanation) = if flags.is_empty() {
        (
            Severity::Info,
            "No notable boot parameters found (checked for mitigations=off, \
             nomodeset, single/emergency boot targets)."
                .to_string(),
        )
    } else {
        let severity = if flags.contains(&"mitigations=off") {
            Severity::Warning
        } else {
            Severity::Info
        };
        (
            severity,
            format!(
                "Notable boot parameter{s} present: {}.",
                flags.join(", "),
                s = if flags.len() == 1 { "" } else { "s" },
            ),
        )
    };

    let mut builder = Finding::builder(
        "KERN006",
        "Notable Boot Parameters",
        Category::Kernel,
        severity,
        Confidence::direct_observation(),
    )
    .evidence(
        "flags",
        if flags.is_empty() {
            "none".to_string()
        } else {
            flags.join(",")
        },
    );

    builder = builder.explanation(explanation);

    if flags.contains(&"mitigations=off") {
        builder = builder.recommendation(
            "mitigations=off disables CPU vulnerability mitigations \
             (Spectre, Meltdown, and similar) in exchange for performance. \
             Confirm this trade-off was deliberate for this system's \
             workload and threat model.",
        );
    }

    builder.build()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::modules::kernel::collect::{KernelBuildInfo, RebootRequiredInfo};

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

    fn data(tainted: u64, oom_count: Option<usize>) -> KernelRawData {
        KernelRawData {
            tainted_raw: tainted,
            oom_kill_count: oom_count,
            dmesg_error: if oom_count.is_none() {
                Some("permission denied".to_string())
            } else {
                None
            },
            build_info: KernelBuildInfo::default(),
            reboot_required: RebootRequiredInfo::default(),
            aslr_mode: Some(2),
            notable_cmdline_flags: vec![],
        }
    }

    #[test]
    fn clean_system_is_all_info() {
        let findings = analyze(&data(0, Some(0)), &ctx());
        assert!(findings.iter().all(|f| f.severity == Severity::Info));
    }

    #[test]
    fn always_reports_both_checks() {
        let findings = analyze(&data(0, Some(0)), &ctx());
        assert!(findings.iter().any(|f| f.id == "KERN001"));
        assert!(findings.iter().any(|f| f.id == "KERN002"));
        assert!(findings.iter().any(|f| f.id == "KERN003"));
        assert!(findings.iter().any(|f| f.id == "KERN004"));
        assert!(findings.iter().any(|f| f.id == "KERN005"));
        assert!(findings.iter().any(|f| f.id == "KERN006"));
    }

    #[test]
    fn benign_taint_bits_stay_info() {
        // bit 0 (proprietary module) + bit 12 (out-of-tree module): both
        // Info-level, common and not inherently concerning.
        let findings = analyze(&data(1 | 4096, Some(0)), &ctx());
        let kern001 = findings.iter().find(|f| f.id == "KERN001").unwrap();
        assert_eq!(kern001.severity, Severity::Info);
    }

    #[test]
    fn mce_taint_bit_is_error() {
        let findings = analyze(&data(16, Some(0)), &ctx()); // bit 4 = MCE
        let kern001 = findings.iter().find(|f| f.id == "KERN001").unwrap();
        assert_eq!(kern001.severity, Severity::Error);
        assert!(kern001.recommendation.is_some());
    }

    #[test]
    fn worst_of_multiple_bits_wins() {
        // bit 0 (P, Info) + bit 14 (L, soft lockup, Error)
        let findings = analyze(&data(1 | 16384, Some(0)), &ctx());
        let kern001 = findings.iter().find(|f| f.id == "KERN001").unwrap();
        assert_eq!(kern001.severity, Severity::Error);
    }

    #[test]
    fn oom_check_unavailable_is_info_not_silent() {
        let findings = analyze(&data(0, None), &ctx());
        let kern002 = findings.iter().find(|f| f.id == "KERN002").unwrap();
        assert_eq!(kern002.severity, Severity::Info);
        assert!(kern002.explanation.contains("Could not check"));
        assert!(kern002.explanation.contains("permission denied"));
    }

    #[test]
    fn few_oom_kills_is_warning() {
        let findings = analyze(&data(0, Some(1)), &ctx());
        let kern002 = findings.iter().find(|f| f.id == "KERN002").unwrap();
        assert_eq!(kern002.severity, Severity::Warning);
    }

    #[test]
    fn many_oom_kills_is_error() {
        let findings = analyze(&data(0, Some(5)), &ctx());
        let kern002 = findings.iter().find(|f| f.id == "KERN002").unwrap();
        assert_eq!(kern002.severity, Severity::Error);
        assert!(kern002.recommendation.is_some());
    }

    #[test]
    fn build_info_present_when_parsed() {
        let mut d = data(0, Some(0));
        d.build_info = KernelBuildInfo {
            build_user_host: Some("buildd@host".to_string()),
            compiler: Some("gcc (Ubuntu 13.2.0) 13.2.0".to_string()),
            build_tag: Some("#31-Ubuntu SMP".to_string()),
        };
        let findings = analyze(&d, &ctx());
        let kern003 = findings.iter().find(|f| f.id == "KERN003").unwrap();
        assert_eq!(kern003.severity, Severity::Info);
        assert!(kern003
            .evidence
            .iter()
            .any(|(k, v)| k == "build_user_host" && v == "buildd@host"));
    }

    #[test]
    fn reboot_required_marker_present_is_warning() {
        let mut d = data(0, Some(0));
        d.reboot_required = RebootRequiredInfo {
            marker_present: true,
            packages: vec!["linux-image-6.8.0-32-generic".to_string()],
        };
        let findings = analyze(&d, &ctx());
        let kern004 = findings.iter().find(|f| f.id == "KERN004").unwrap();
        assert_eq!(kern004.severity, Severity::Warning);
        assert!(kern004.explanation.contains("linux-image-6.8.0-32-generic"));
        assert!(kern004.recommendation.is_some());
    }

    #[test]
    fn reboot_required_marker_absent_is_info_not_a_confirmed_all_clear() {
        let findings = analyze(&data(0, Some(0)), &ctx()); // default: marker absent
        let kern004 = findings.iter().find(|f| f.id == "KERN004").unwrap();
        assert_eq!(kern004.severity, Severity::Info);
        assert!(kern004.explanation.contains("confirms nothing"));
    }

    #[test]
    fn aslr_disabled_is_warning() {
        let mut d = data(0, Some(0));
        d.aslr_mode = Some(0);
        let findings = analyze(&d, &ctx());
        let kern005 = findings.iter().find(|f| f.id == "KERN005").unwrap();
        assert_eq!(kern005.severity, Severity::Warning);
        assert!(kern005.recommendation.is_some());
    }

    #[test]
    fn aslr_full_is_info() {
        let findings = analyze(&data(0, Some(0)), &ctx()); // default: Some(2)
        let kern005 = findings.iter().find(|f| f.id == "KERN005").unwrap();
        assert_eq!(kern005.severity, Severity::Info);
    }

    #[test]
    fn mitigations_off_flagged_as_warning() {
        let mut d = data(0, Some(0));
        d.notable_cmdline_flags = vec!["mitigations=off"];
        let findings = analyze(&d, &ctx());
        let kern006 = findings.iter().find(|f| f.id == "KERN006").unwrap();
        assert_eq!(kern006.severity, Severity::Warning);
        assert!(kern006.recommendation.is_some());
    }

    #[test]
    fn nomodeset_flagged_as_info_not_warning() {
        let mut d = data(0, Some(0));
        d.notable_cmdline_flags = vec!["nomodeset"];
        let findings = analyze(&d, &ctx());
        let kern006 = findings.iter().find(|f| f.id == "KERN006").unwrap();
        assert_eq!(kern006.severity, Severity::Info);
    }

    #[test]
    fn no_notable_flags_is_clean_info() {
        let findings = analyze(&data(0, Some(0)), &ctx());
        let kern006 = findings.iter().find(|f| f.id == "KERN006").unwrap();
        assert_eq!(kern006.severity, Severity::Info);
        assert!(kern006.explanation.contains("No notable"));
    }

    #[test]
    fn confidence_never_reported_below_60() {
        for d in [data(4609, Some(0)), data(0, None), data(0, Some(5))] {
            for f in analyze(&d, &ctx()) {
                assert!(f.confidence.percent >= 60);
            }
        }
    }
}
