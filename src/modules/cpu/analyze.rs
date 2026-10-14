// SPDX-License-Identifier: GPL-3.0-only

use crate::core::context::Context;
use crate::models::{Category, Confidence, Finding, Severity};

use super::collect::{CpuRawData, CpuSocket};

/// Pure function: RawData -> Findings. No I/O — see ARCHITECTURE.md
/// "Testing Strategy".
pub fn analyze(data: &CpuRawData, _ctx: &Context) -> Vec<Finding> {
    let all_isolated = data.all_isolated_cpus();

    let mut findings = vec![overview_finding(data)];

    for socket in &data.sockets {
        findings.push(socket_detail_finding(socket, &all_isolated));
    }

    if let Some(f) = load_pressure_finding(data) {
        findings.push(f);
    }
    if let Some(f) = sustained_overload_finding(data) {
        findings.push(f);
    }

    // Always present, unlike the other conditional findings -- see
    // isolated_cpus_finding's doc comment for why.
    findings.push(isolated_cpus_finding(data, &all_isolated));

    if let Some(f) = offline_cpus_finding(data) {
        findings.push(f);
    }

    findings
}

/// CPU001 — always reported: the machine-wide totals across every socket.
fn overview_finding(data: &CpuRawData) -> Finding {
    let sockets = data.sockets.len();
    let cores = data.total_cores();
    let threads = data.total_logical_cpus();
    let smt_note = if threads > cores {
        " Hyper-Threading/SMT appears active (more logical CPUs than physical cores)."
    } else {
        ""
    };

    Finding::builder(
        "CPU001",
        "CPU Overview",
        Category::Cpu,
        Severity::Info,
        Confidence::direct_observation(),
    )
    .evidence("sockets", sockets.to_string())
    .evidence("total_cores", cores.to_string())
    .evidence("total_logical_cpus", threads.to_string())
    .explanation(format!(
        "This machine has {sockets} socket{s}, totaling {cores} physical \
         core{cs} and {threads} logical CPU{ls}.{smt_note}",
        s = if sockets == 1 { "" } else { "s" },
        cs = if cores == 1 { "" } else { "s" },
        ls = if threads == 1 { "" } else { "s" },
    ))
    .build()
}

/// CPU004 — one finding per socket, always reported. Shows that socket's
/// own core/thread counts, and — this is the point of a per-socket
/// breakdown rather than one machine-wide count — how many of its logical
/// CPUs are actually available to the scheduler versus isolated by any of
/// the mechanisms CPU005 checks.
fn socket_detail_finding(socket: &CpuSocket, all_isolated: &[u32]) -> Finding {
    let isolated_in_socket: Vec<u32> = socket
        .logical_cpus
        .iter()
        .filter(|c| all_isolated.contains(c))
        .copied()
        .collect();
    let available = socket.threads - isolated_in_socket.len();

    let model = socket.model_name.as_deref().unwrap_or("unknown model");
    let smt_note = if socket.threads > socket.cores {
        " (SMT/Hyper-Threading active on this socket)"
    } else {
        ""
    };
    let isolation_note = if isolated_in_socket.is_empty() {
        String::new()
    } else {
        format!(
            " {} of these are isolated from the general scheduler ({}), \
             leaving {available} available.",
            isolated_in_socket.len(),
            format_cpu_list(&isolated_in_socket),
        )
    };

    Finding::builder(
        "CPU004",
        format!("Socket Detail \u{2014} socket {}", socket.physical_id),
        Category::Cpu,
        Severity::Info,
        Confidence::direct_observation(),
    )
    .instance(format!("socket {}", socket.physical_id))
    .evidence("physical_id", socket.physical_id.to_string())
    .evidence("model", model.to_string())
    .evidence("cores", socket.cores.to_string())
    .evidence("threads", socket.threads.to_string())
    .evidence("available_threads", available.to_string())
    .evidence("isolated_threads", isolated_in_socket.len().to_string())
    .explanation(format!(
        "Socket {}: {model}, {} physical core{cs}, {} logical CPU{ls}{smt_note}.{isolation_note}",
        socket.physical_id,
        socket.cores,
        socket.threads,
        cs = if socket.cores == 1 { "" } else { "s" },
        ls = if socket.threads == 1 { "" } else { "s" },
    ))
    .build()
}

/// CPU002 — 1-minute load relative to total logical CPUs across all
/// sockets. Severity and confidence scale with the ratio.
fn load_pressure_finding(data: &CpuRawData) -> Option<Finding> {
    let total = data.total_logical_cpus();
    if total == 0 {
        return None;
    }
    let ratio_1m = data.load_1m / total as f64;

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
        .evidence("cpu_count", total.to_string())
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
/// total logical CPUs: a sustained bottleneck rather than a brief spike.
fn sustained_overload_finding(data: &CpuRawData) -> Option<Finding> {
    let total = data.total_logical_cpus();
    if total == 0 {
        return None;
    }
    let n = total as f64;
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
        .evidence("cpu_count", total.to_string())
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

/// CPU005 — machine-wide summary of every isolation mechanism checked.
/// Unlike the other conditional findings in this module, this one is
/// *always* reported, even when nothing is isolated: silently omitting it
/// when empty is indistinguishable from "the tool didn't check" versus
/// "the tool checked three sources and found nothing" -- and if cores are
/// genuinely reserved but not showing up here, that's important
/// information in itself (see the explanation below).
fn isolated_cpus_finding(data: &CpuRawData, all_isolated: &[u32]) -> Finding {
    let explanation = if all_isolated.is_empty() {
        "No isolated CPUs detected via any kernel-visible mechanism this \
         tool checks: the isolcpus= and nohz_full= boot parameters, cgroup \
         v2 isolated cpuset partitions (searched under /sys/fs/cgroup), and \
         system.slice being restricted via AllowedCPUs=. If cores are \
         expected to be reserved on this system, that reservation is most \
         likely happening at the hypervisor/host level (e.g. vCPU pinning \
         via virsh vcpupin or similar) -- which has no kernel interface \
         exposing it to a guest, and so cannot be detected from inside the \
         system being audited, by this or any other in-guest tool."
            .to_string()
    } else {
        let mut sources = Vec::new();
        if !data.isolcpus.is_empty() {
            sources.push(format!("isolcpus=: {}", format_cpu_list(&data.isolcpus)));
        }
        if !data.nohz_full.is_empty() {
            sources.push(format!("nohz_full=: {}", format_cpu_list(&data.nohz_full)));
        }
        if !data.cgroup_isolated.is_empty() {
            sources.push(format!(
                "cgroup isolated partition: {}",
                format_cpu_list(&data.cgroup_isolated)
            ));
        }
        if !data.system_slice_excluded.is_empty() {
            sources.push(format!(
                "excluded from system.slice (AllowedCPUs=): {}",
                format_cpu_list(&data.system_slice_excluded)
            ));
        }
        format!(
            "{} logical CPU{} excluded from the general scheduler ({}) — {}. \
             This is commonly used for real-time or dedicated workloads. In \
             virtualized environments it's often paired with host-level vCPU \
             pinning, which — unlike these kernel-level mechanisms — isn't \
             visible from inside the guest at all.",
            all_isolated.len(),
            if all_isolated.len() == 1 { "" } else { "s" },
            format_cpu_list(all_isolated),
            sources.join("; "),
        )
    };

    Finding::builder(
        "CPU005",
        "Isolated CPUs",
        Category::Cpu,
        Severity::Info,
        Confidence::direct_observation(),
    )
    .evidence("isolcpus", format_cpu_list(&data.isolcpus))
    .evidence("nohz_full", format_cpu_list(&data.nohz_full))
    .evidence(
        "cgroup_isolated_partitions",
        format_cpu_list(&data.cgroup_isolated),
    )
    .evidence(
        "system_slice_excluded",
        format_cpu_list(&data.system_slice_excluded),
    )
    .evidence("total_isolated", all_isolated.len().to_string())
    .explanation(explanation)
    .build()
}

/// CPU006 — only fires when at least one possible CPU isn't online.
/// Distinct from CPU005: isolated CPUs are online but scheduler-excluded;
/// offline CPUs aren't running at all.
fn offline_cpus_finding(data: &CpuRawData) -> Option<Finding> {
    if data.offline_cpus.is_empty() {
        return None;
    }

    let list = format_cpu_list(&data.offline_cpus);

    Some(
        Finding::builder(
            "CPU006",
            "Offline CPUs",
            Category::Cpu,
            Severity::Info,
            Confidence::direct_observation(),
        )
        .evidence("offline_cpus", list.clone())
        .evidence("count", data.offline_cpus.len().to_string())
        .explanation(format!(
            "{} logical CPU{} ({list}) {} present but not currently online. \
             Common causes: CPU hotplug (deliberately offlined), a boot \
             parameter limiting active CPUs (maxcpus=/nr_cpus=), or — \
             relevant on a VM — a hypervisor provisioning more possible \
             vCPUs than it currently activates, so they can be hot-added \
             later without a reboot.",
            data.offline_cpus.len(),
            if data.offline_cpus.len() == 1 {
                ""
            } else {
                "s"
            },
            if data.offline_cpus.len() == 1 {
                "is"
            } else {
                "are"
            },
        ))
        .build(),
    )
}

/// Render a sorted list of CPU indices back into compact range notation,
/// e.g. [0,1,2,3,8] -> "0-3,8" — the inverse of collect::parse_cpu_list,
/// used only for display. Returns "none" for an empty list so evidence
/// values are never blank.
fn format_cpu_list(cpus: &[u32]) -> String {
    if cpus.is_empty() {
        return "none".to_string();
    }
    let mut sorted = cpus.to_vec();
    sorted.sort_unstable();
    sorted.dedup();

    let mut ranges: Vec<String> = Vec::new();
    let mut i = 0;
    while i < sorted.len() {
        let start = sorted[i];
        let mut end = start;
        while i + 1 < sorted.len() && sorted[i + 1] == end + 1 {
            end = sorted[i + 1];
            i += 1;
        }
        if start == end {
            ranges.push(start.to_string());
        } else {
            ranges.push(format!("{start}-{end}"));
        }
        i += 1;
    }
    ranges.join(",")
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

    fn single_socket(load_1m: f64, load_5m: f64, load_15m: f64) -> CpuRawData {
        CpuRawData {
            load_1m,
            load_5m,
            load_15m,
            sockets: vec![CpuSocket {
                physical_id: 0,
                model_name: Some("Test CPU".to_string()),
                cores: 4,
                threads: 4,
                logical_cpus: vec![0, 1, 2, 3],
            }],
            isolcpus: vec![],
            nohz_full: vec![],
            cgroup_isolated: vec![],
            system_slice_excluded: vec![],
            offline_cpus: vec![],
        }
    }

    fn dual_socket(load_1m: f64, load_5m: f64, load_15m: f64) -> CpuRawData {
        CpuRawData {
            load_1m,
            load_5m,
            load_15m,
            sockets: vec![
                CpuSocket {
                    physical_id: 0,
                    model_name: Some("Test CPU".to_string()),
                    cores: 2,
                    threads: 4,
                    logical_cpus: vec![0, 1, 2, 3],
                },
                CpuSocket {
                    physical_id: 1,
                    model_name: Some("Test CPU".to_string()),
                    cores: 2,
                    threads: 4,
                    logical_cpus: vec![4, 5, 6, 7],
                },
            ],
            isolcpus: vec![],
            nohz_full: vec![],
            cgroup_isolated: vec![],
            system_slice_excluded: vec![],
            offline_cpus: vec![],
        }
    }

    #[test]
    fn always_reports_overview() {
        let findings = analyze(&single_socket(0.1, 0.1, 0.1), &ctx());
        assert!(findings.iter().any(|f| f.id == "CPU001"));
    }

    #[test]
    fn one_socket_detail_finding_per_socket() {
        let findings = analyze(&dual_socket(0.1, 0.1, 0.1), &ctx());
        let socket_findings: Vec<_> = findings.iter().filter(|f| f.id == "CPU004").collect();
        assert_eq!(socket_findings.len(), 2);
    }

    #[test]
    fn overview_totals_sum_across_sockets() {
        let findings = analyze(&dual_socket(0.1, 0.1, 0.1), &ctx());
        let overview = findings.iter().find(|f| f.id == "CPU001").unwrap();
        assert!(overview
            .evidence
            .iter()
            .any(|(k, v)| k == "total_cores" && v == "4"));
        assert!(overview
            .evidence
            .iter()
            .any(|(k, v)| k == "total_logical_cpus" && v == "8"));
    }

    #[test]
    fn socket_detail_reports_all_available_when_nothing_isolated() {
        let findings = analyze(&single_socket(0.1, 0.1, 0.1), &ctx());
        let cpu004 = findings.iter().find(|f| f.id == "CPU004").unwrap();
        assert!(cpu004
            .evidence
            .iter()
            .any(|(k, v)| k == "available_threads" && v == "4"));
        assert!(cpu004
            .evidence
            .iter()
            .any(|(k, v)| k == "isolated_threads" && v == "0"));
    }

    #[test]
    fn socket_detail_splits_available_vs_isolated_for_that_socket_only() {
        let mut data = dual_socket(0.1, 0.1, 0.1);
        data.isolcpus = vec![4, 5]; // belong to socket 1, not socket 0

        let findings = analyze(&data, &ctx());
        let socket0 = findings
            .iter()
            .find(|f| f.title.contains("socket 0"))
            .unwrap();
        let socket1 = findings
            .iter()
            .find(|f| f.title.contains("socket 1"))
            .unwrap();

        assert!(socket0
            .evidence
            .iter()
            .any(|(k, v)| k == "available_threads" && v == "4"));
        assert!(socket1
            .evidence
            .iter()
            .any(|(k, v)| k == "available_threads" && v == "2"));
        assert!(socket1
            .evidence
            .iter()
            .any(|(k, v)| k == "isolated_threads" && v == "2"));
    }

    #[test]
    fn socket_detail_counts_isolation_from_any_of_the_three_sources() {
        // nohz_full and cgroup_isolated should attribute to sockets exactly
        // like isolcpus does -- not just the first-checked source.
        let mut data = dual_socket(0.1, 0.1, 0.1);
        data.nohz_full = vec![2, 3];
        data.cgroup_isolated = vec![6];

        let findings = analyze(&data, &ctx());
        let socket0 = findings
            .iter()
            .find(|f| f.title.contains("socket 0"))
            .unwrap();
        let socket1 = findings
            .iter()
            .find(|f| f.title.contains("socket 1"))
            .unwrap();

        assert!(socket0
            .evidence
            .iter()
            .any(|(k, v)| k == "isolated_threads" && v == "2"));
        assert!(socket1
            .evidence
            .iter()
            .any(|(k, v)| k == "isolated_threads" && v == "1"));
    }

    #[test]
    fn info_level_when_load_below_capacity() {
        let findings = analyze(&single_socket(1.5, 0.5, 0.5), &ctx());
        let cpu002 = findings.iter().find(|f| f.id == "CPU002").unwrap();
        assert_eq!(cpu002.severity, Severity::Info);
    }

    #[test]
    fn warning_level_when_load_exceeds_capacity() {
        let findings = analyze(&single_socket(6.0, 1.0, 1.0), &ctx());
        let cpu002 = findings.iter().find(|f| f.id == "CPU002").unwrap();
        assert_eq!(cpu002.severity, Severity::Warning);
    }

    #[test]
    fn error_level_when_load_more_than_double_capacity() {
        let findings = analyze(&single_socket(9.0, 1.0, 1.0), &ctx());
        let cpu002 = findings.iter().find(|f| f.id == "CPU002").unwrap();
        assert_eq!(cpu002.severity, Severity::Error);
    }

    #[test]
    fn load_pressure_uses_total_across_sockets_not_just_one() {
        let findings = analyze(&dual_socket(9.0, 1.0, 1.0), &ctx());
        let cpu002 = findings.iter().find(|f| f.id == "CPU002").unwrap();
        assert_eq!(cpu002.severity, Severity::Warning);
    }

    #[test]
    fn no_critical_finding_on_transient_spike() {
        let findings = analyze(&single_socket(9.0, 2.0, 1.0), &ctx());
        assert!(!findings.iter().any(|f| f.id == "CPU003"));
    }

    #[test]
    fn critical_finding_when_overload_is_sustained() {
        let findings = analyze(&single_socket(9.0, 8.0, 7.0), &ctx());
        let cpu003 = findings.iter().find(|f| f.id == "CPU003");
        assert!(cpu003.is_some());
        assert_eq!(cpu003.unwrap().severity, Severity::Critical);
    }

    #[test]
    fn cpu005_always_present_even_with_nothing_isolated() {
        let findings = analyze(&single_socket(0.1, 0.1, 0.1), &ctx());
        let cpu005 = findings.iter().find(|f| f.id == "CPU005");
        assert!(
            cpu005.is_some(),
            "CPU005 must always be reported, not skipped"
        );
        assert!(cpu005
            .unwrap()
            .explanation
            .contains("hypervisor/host level"));
    }

    #[test]
    fn cpu005_reports_compact_range_and_mechanism() {
        let mut data = single_socket(0.1, 0.1, 0.1);
        data.isolcpus = vec![2, 3];
        let findings = analyze(&data, &ctx());
        let cpu005 = findings.iter().find(|f| f.id == "CPU005").unwrap();
        assert!(cpu005
            .evidence
            .iter()
            .any(|(k, v)| k == "isolcpus" && v == "2-3"));
        assert!(cpu005.explanation.contains("isolcpus="));
        assert_eq!(cpu005.severity, Severity::Info);
    }

    #[test]
    fn cpu005_attributes_nohz_full_separately_from_isolcpus() {
        let mut data = single_socket(0.1, 0.1, 0.1);
        data.nohz_full = vec![1];
        let findings = analyze(&data, &ctx());
        let cpu005 = findings.iter().find(|f| f.id == "CPU005").unwrap();
        assert!(cpu005
            .evidence
            .iter()
            .any(|(k, v)| k == "nohz_full" && v == "1"));
        assert!(cpu005
            .evidence
            .iter()
            .any(|(k, v)| k == "isolcpus" && v == "none"));
    }

    #[test]
    fn cpu005_attributes_system_slice_exclusion_and_folds_into_per_socket_isolation() {
        // The exact scenario reported: a libvirt hook restricts
        // system.slice's AllowedCPUs when a VM starts, freeing the
        // complement for the VM. CPUs 4-7 belong to socket 1.
        let mut data = dual_socket(0.1, 0.1, 0.1);
        data.system_slice_excluded = vec![4, 5, 6, 7];

        let findings = analyze(&data, &ctx());

        let cpu005 = findings.iter().find(|f| f.id == "CPU005").unwrap();
        assert!(cpu005
            .evidence
            .iter()
            .any(|(k, v)| k == "system_slice_excluded" && v == "4-7"));
        assert!(cpu005.explanation.contains("AllowedCPUs="));

        let socket1 = findings
            .iter()
            .find(|f| f.title.contains("socket 1"))
            .unwrap();
        assert!(socket1
            .evidence
            .iter()
            .any(|(k, v)| k == "isolated_threads" && v == "4"));
        assert!(socket1
            .evidence
            .iter()
            .any(|(k, v)| k == "available_threads" && v == "0"));
    }

    #[test]
    fn no_offline_finding_when_none_offline() {
        let findings = analyze(&single_socket(0.1, 0.1, 0.1), &ctx());
        assert!(!findings.iter().any(|f| f.id == "CPU006"));
    }

    #[test]
    fn offline_finding_reports_compact_range() {
        let mut data = single_socket(0.1, 0.1, 0.1);
        data.offline_cpus = vec![8, 9, 10];
        let findings = analyze(&data, &ctx());
        let cpu006 = findings.iter().find(|f| f.id == "CPU006").unwrap();
        assert!(cpu006
            .evidence
            .iter()
            .any(|(k, v)| k == "offline_cpus" && v == "8-10"));
        assert_eq!(cpu006.severity, Severity::Info);
    }

    #[test]
    fn confidence_never_reported_below_60() {
        for d in [single_socket(0.1, 0.1, 0.1), single_socket(9.0, 8.0, 7.0)] {
            for f in analyze(&d, &ctx()) {
                assert!(f.confidence.percent >= 60);
            }
        }
    }
}
