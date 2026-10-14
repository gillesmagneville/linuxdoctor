// SPDX-License-Identifier: GPL-3.0-only

use crate::core::context::Context;
use crate::models::{Category, Confidence, Finding, Severity};

use super::collect::{NumaNode, NumaRawData};

/// Pure function: RawData -> Findings. No I/O — see ARCHITECTURE.md
/// "Testing Strategy".
pub fn analyze(data: &NumaRawData, _ctx: &Context) -> Vec<Finding> {
    let mut findings = Vec::new();

    for node in &data.nodes {
        findings.push(node_finding(node, data.nodes.len()));
    }

    if let Some(f) = memory_balance_finding(data) {
        findings.push(f);
    }
    if let Some(f) = topology_comparison_finding(data) {
        findings.push(f);
    }

    findings
}

/// NUMA001 — always reported, one per node.
fn node_finding(node: &NumaNode, total_nodes: usize) -> Finding {
    let used_pct = node.mem_used_percent();
    let cpu_list = format_id_list(&node.cpus);

    let explanation = if total_nodes == 1 {
        "This system has a single NUMA node — NUMA placement is not a \
         concern here; every CPU has equal-cost access to all memory."
            .to_string()
    } else {
        format!(
            "Node {} owns {} logical CPU{} and {:.1} GB of memory ({:.1}% in \
             use). Processes and their memory should ideally stay on the \
             same node — cross-node memory access carries a latency penalty.",
            node.id,
            node.cpus.len(),
            if node.cpus.len() == 1 { "" } else { "s" },
            node.mem_total_kb as f64 / 1024.0 / 1024.0,
            used_pct,
        )
    };

    Finding::builder(
        "NUMA001",
        format!("NUMA Node \u{2014} node{}", node.id),
        Category::Numa,
        Severity::Info,
        Confidence::direct_observation(),
    )
    .instance(format!("node{}", node.id))
    .evidence("node_id", node.id.to_string())
    .evidence("cpus", cpu_list)
    .evidence("mem_total_kb", node.mem_total_kb.to_string())
    .evidence("mem_free_kb", node.mem_free_kb.to_string())
    .evidence("mem_used_percent", format!("{used_pct:.1}"))
    .explanation(explanation)
    .build()
}

/// NUMA002 — memory *usage* balance across nodes. Always reported on
/// systems with 2+ nodes (not just when imbalanced), so its absence is
/// never ambiguous with "the comparison didn't run" — the same lesson
/// learned from CPU005. Silently skipped on single-node systems, since
/// NUMA001 already explains why there's nothing to compare there.
fn memory_balance_finding(data: &NumaRawData) -> Option<Finding> {
    if data.nodes.len() < 2 {
        return None;
    }

    let busiest = data
        .nodes
        .iter()
        .max_by(|a, b| a.mem_used_percent().total_cmp(&b.mem_used_percent()))?;
    let idlest = data
        .nodes
        .iter()
        .min_by(|a, b| a.mem_used_percent().total_cmp(&b.mem_used_percent()))?;

    let busiest_pct = busiest.mem_used_percent();
    let idlest_pct = idlest.mem_used_percent();

    // A genuine cross-node *imbalance* needs one node under real pressure
    // while another has real headroom -- both nodes being busy together is
    // just system-wide memory pressure, which is the Memory module's job,
    // not a NUMA placement problem.
    let imbalanced = busiest_pct >= 90.0 && idlest_pct < 50.0;

    let (severity, explanation, recommendation) = if !imbalanced {
        (
            Severity::Info,
            format!(
                "Memory usage is reasonably balanced across the {} nodes \
                 (busiest: node {} at {busiest_pct:.1}%, idlest: node {} at \
                 {idlest_pct:.1}%).",
                data.nodes.len(),
                busiest.id,
                idlest.id,
            ),
            None,
        )
    } else {
        let sev = if busiest_pct >= 95.0 {
            Severity::Error
        } else {
            Severity::Warning
        };
        (
            sev,
            format!(
                "Node {} is at {busiest_pct:.1}% memory usage while node {} \
                 sits at only {idlest_pct:.1}%. This commonly means processes \
                 aren't NUMA-aware or aren't pinned to the node their memory \
                 was allocated on, causing both wasted capacity on the idle \
                 node and cross-node access penalties for the busy one.",
                busiest.id, idlest.id,
            ),
            Some(
                "Check process/memory placement with `numastat -p <pid>` for \
                 memory-heavy processes, and consider NUMA-aware placement \
                 (numactl --membind / --cpunodebind) for workloads that \
                 support it."
                    .to_string(),
            ),
        )
    };

    let mut builder = Finding::builder(
        "NUMA002",
        "Memory Balance Across Nodes",
        Category::Numa,
        severity,
        Confidence::correlated(90),
    )
    .evidence("busiest_node", busiest.id.to_string())
    .evidence("busiest_used_percent", format!("{busiest_pct:.1}"))
    .evidence("idlest_node", idlest.id.to_string())
    .evidence("idlest_used_percent", format!("{idlest_pct:.1}"))
    .explanation(explanation);

    if let Some(rec) = recommendation {
        builder = builder.recommendation(rec);
    }

    Some(builder.build())
}

/// NUMA003 — *structural* topology comparison: CPU count and memory
/// capacity per node, as opposed to NUMA002's usage comparison. A node
/// with far fewer CPUs or far less memory than its siblings isn't a
/// problem on its own (asymmetric NUMA topologies are normal on some real
/// hardware — e.g. a compute-only node associated with an accelerator),
/// but it means nodes can't be assumed interchangeable when placing
/// workloads, which is worth surfacing explicitly. Always reported on
/// systems with 2+ nodes, same reasoning as NUMA002.
fn topology_comparison_finding(data: &NumaRawData) -> Option<Finding> {
    if data.nodes.len() < 2 {
        return None;
    }

    let cpu_counts: Vec<usize> = data.nodes.iter().map(|n| n.cpus.len()).collect();
    let mem_totals: Vec<u64> = data.nodes.iter().map(|n| n.mem_total_kb).collect();

    let max_cpus = *cpu_counts.iter().max().unwrap_or(&0);
    let min_cpus = *cpu_counts.iter().min().unwrap_or(&0);
    let max_mem = *mem_totals.iter().max().unwrap_or(&0);
    let min_mem = *mem_totals.iter().min().unwrap_or(&0);

    let memoryless: Vec<u32> = data
        .nodes
        .iter()
        .filter(|n| n.mem_total_kb == 0)
        .map(|n| n.id)
        .collect();
    let cpuless: Vec<u32> = data
        .nodes
        .iter()
        .filter(|n| n.cpus.is_empty())
        .map(|n| n.id)
        .collect();

    // Ratio checks only make sense when the smaller side is non-zero;
    // zero-CPU/zero-memory nodes are already called out separately above.
    let cpu_asymmetric = min_cpus > 0 && max_cpus as f64 / min_cpus as f64 >= 2.0;
    let mem_asymmetric = min_mem > 0 && max_mem as f64 / min_mem as f64 >= 2.0;

    let mut notes = Vec::new();
    if !memoryless.is_empty() {
        notes.push(format!(
            "node{} {} {} no local memory (compute-only)",
            if memoryless.len() == 1 { "" } else { "s" },
            format_id_list(&memoryless),
            if memoryless.len() == 1 { "has" } else { "have" },
        ));
    }
    if !cpuless.is_empty() {
        notes.push(format!(
            "node{} {} {} no CPUs (memory-only)",
            if cpuless.len() == 1 { "" } else { "s" },
            format_id_list(&cpuless),
            if cpuless.len() == 1 { "has" } else { "have" },
        ));
    }
    if cpu_asymmetric {
        notes.push(format!(
            "CPU counts range from {min_cpus} to {max_cpus} across nodes"
        ));
    }
    if mem_asymmetric {
        notes.push(format!(
            "memory capacity ranges from {:.1} GB to {:.1} GB across nodes",
            min_mem as f64 / 1024.0 / 1024.0,
            max_mem as f64 / 1024.0 / 1024.0,
        ));
    }

    let symmetric = notes.is_empty();

    let (explanation, recommendation) = if symmetric {
        (
            format!(
                "All {} nodes have comparable CPU counts and memory capacity \
                 — a roughly symmetric topology. Evenly spreading a workload \
                 across nodes is a reasonable default here.",
                data.nodes.len(),
            ),
            None,
        )
    } else {
        (
            format!(
                "This system's NUMA topology is not symmetric: {}. Nodes \
                 shouldn't be assumed interchangeable when placing workloads.",
                notes.join("; "),
            ),
            Some(
                "Use `numactl --hardware` to inspect the exact topology, and \
                 size or pin workloads (numactl --cpunodebind=N --membind=N) \
                 according to each node's actual capacity rather than \
                 spreading evenly by default."
                    .to_string(),
            ),
        )
    };

    let mut builder = Finding::builder(
        "NUMA003",
        "Topology Comparison",
        Category::Numa,
        Severity::Info,
        Confidence::direct_observation(),
    )
    .evidence("nodes", data.nodes.len().to_string())
    .evidence("min_cpus_per_node", min_cpus.to_string())
    .evidence("max_cpus_per_node", max_cpus.to_string())
    .evidence("min_mem_kb_per_node", min_mem.to_string())
    .evidence("max_mem_kb_per_node", max_mem.to_string())
    .explanation(explanation);

    if let Some(rec) = recommendation {
        builder = builder.recommendation(rec);
    }

    Some(builder.build())
}

/// Simple comma-joined id list (node/CPU indices are few enough in
/// practice — typically 2-8 — that range-compaction like the CPU
/// module's `format_cpu_list` isn't worth the extra complexity here).
fn format_id_list(ids: &[u32]) -> String {
    if ids.is_empty() {
        return "none".to_string();
    }
    let mut sorted = ids.to_vec();
    sorted.sort_unstable();
    sorted
        .iter()
        .map(|id| id.to_string())
        .collect::<Vec<_>>()
        .join(",")
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

    fn node(id: u32, cpus: Vec<u32>, total_kb: u64, free_kb: u64) -> NumaNode {
        NumaNode {
            id,
            cpus,
            mem_total_kb: total_kb,
            mem_free_kb: free_kb,
        }
    }

    #[test]
    fn single_node_reports_no_numa_concern() {
        let data = NumaRawData {
            nodes: vec![node(0, vec![0, 1, 2, 3], 16_000_000, 8_000_000)],
        };
        let findings = analyze(&data, &ctx());
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].id, "NUMA001");
        assert_eq!(findings[0].severity, Severity::Info);
        assert!(!findings.iter().any(|f| f.id == "NUMA002"));
        assert!(!findings.iter().any(|f| f.id == "NUMA003"));
    }

    #[test]
    fn one_node_finding_per_node() {
        let data = NumaRawData {
            nodes: vec![
                node(0, vec![0, 1], 8_000_000, 4_000_000),
                node(1, vec![2, 3], 8_000_000, 4_000_000),
            ],
        };
        let findings = analyze(&data, &ctx());
        assert_eq!(findings.iter().filter(|f| f.id == "NUMA001").count(), 2);
    }

    #[test]
    fn numa002_always_present_with_two_nodes_even_when_balanced() {
        let data = NumaRawData {
            nodes: vec![
                node(0, vec![0, 1], 8_000_000, 4_000_000), // 50%
                node(1, vec![2, 3], 8_000_000, 4_000_000), // 50%
            ],
        };
        let findings = analyze(&data, &ctx());
        let numa002 = findings.iter().find(|f| f.id == "NUMA002");
        assert!(
            numa002.is_some(),
            "NUMA002 must always be reported, not skipped"
        );
        assert_eq!(numa002.unwrap().severity, Severity::Info);
    }

    #[test]
    fn no_imbalance_when_both_nodes_busy() {
        // Both nodes under pressure isn't a NUMA *imbalance* -- it's
        // system-wide memory pressure, which is Memory's job to flag.
        let data = NumaRawData {
            nodes: vec![
                node(0, vec![0, 1], 8_000_000, 400_000), // 95%
                node(1, vec![2, 3], 8_000_000, 800_000), // 90%
            ],
        };
        let findings = analyze(&data, &ctx());
        let numa002 = findings.iter().find(|f| f.id == "NUMA002").unwrap();
        assert_eq!(numa002.severity, Severity::Info);
    }

    #[test]
    fn warning_when_one_node_busy_and_other_idle() {
        let data = NumaRawData {
            nodes: vec![
                node(0, vec![0, 1], 8_000_000, 400_000),   // 95%
                node(1, vec![2, 3], 8_000_000, 6_000_000), // 25%
            ],
        };
        let findings = analyze(&data, &ctx());
        let imbalance = findings.iter().find(|f| f.id == "NUMA002").unwrap();
        assert_eq!(imbalance.severity, Severity::Error); // >= 95%
        assert!(imbalance.recommendation.is_some());
    }

    #[test]
    fn warning_tier_below_95_percent() {
        let data = NumaRawData {
            nodes: vec![
                node(0, vec![0, 1], 8_000_000, 720_000),   // 91%
                node(1, vec![2, 3], 8_000_000, 6_000_000), // 25%
            ],
        };
        let findings = analyze(&data, &ctx());
        let imbalance = findings.iter().find(|f| f.id == "NUMA002").unwrap();
        assert_eq!(imbalance.severity, Severity::Warning);
    }

    #[test]
    fn numa003_reports_symmetric_when_nodes_are_comparable() {
        let data = NumaRawData {
            nodes: vec![
                node(0, vec![0, 1, 2, 3], 32_000_000, 16_000_000),
                node(1, vec![4, 5, 6, 7], 32_000_000, 16_000_000),
            ],
        };
        let findings = analyze(&data, &ctx());
        let numa003 = findings.iter().find(|f| f.id == "NUMA003").unwrap();
        assert!(numa003.explanation.contains("symmetric"));
        assert!(numa003.recommendation.is_none());
        assert_eq!(numa003.severity, Severity::Info);
    }

    #[test]
    fn numa003_flags_cpu_count_asymmetry() {
        let data = NumaRawData {
            nodes: vec![
                node(0, (0..16).collect(), 32_000_000, 16_000_000),
                node(1, vec![16, 17], 32_000_000, 16_000_000), // 8x fewer CPUs
            ],
        };
        let findings = analyze(&data, &ctx());
        let numa003 = findings.iter().find(|f| f.id == "NUMA003").unwrap();
        assert!(numa003.explanation.contains("CPU counts range"));
        assert!(numa003.recommendation.is_some());
    }

    #[test]
    fn numa003_flags_memory_capacity_asymmetry() {
        let data = NumaRawData {
            nodes: vec![
                node(0, vec![0, 1, 2, 3], 64_000_000, 32_000_000),
                node(1, vec![4, 5, 6, 7], 8_000_000, 4_000_000), // 8x less memory
            ],
        };
        let findings = analyze(&data, &ctx());
        let numa003 = findings.iter().find(|f| f.id == "NUMA003").unwrap();
        assert!(numa003.explanation.contains("memory capacity ranges"));
    }

    #[test]
    fn numa003_flags_memoryless_node_distinctly() {
        // A compute-only node (e.g. associated with an accelerator).
        let data = NumaRawData {
            nodes: vec![
                node(0, vec![0, 1, 2, 3], 32_000_000, 16_000_000),
                node(1, vec![4, 5, 6, 7], 0, 0),
            ],
        };
        let findings = analyze(&data, &ctx());
        let numa003 = findings.iter().find(|f| f.id == "NUMA003").unwrap();
        assert!(numa003.explanation.contains("no local memory"));
        assert!(numa003.explanation.contains("node 1"));
    }

    #[test]
    fn numa003_flags_cpuless_node_distinctly() {
        // A memory-only node (memory expansion module with no cores).
        let data = NumaRawData {
            nodes: vec![
                node(0, vec![0, 1, 2, 3], 32_000_000, 16_000_000),
                node(1, vec![], 32_000_000, 16_000_000),
            ],
        };
        let findings = analyze(&data, &ctx());
        let numa003 = findings.iter().find(|f| f.id == "NUMA003").unwrap();
        assert!(numa003.explanation.contains("no CPUs"));
    }

    #[test]
    fn confidence_never_reported_below_60() {
        let data = NumaRawData {
            nodes: vec![
                node(0, vec![0, 1], 8_000_000, 100_000),
                node(1, vec![2, 3], 8_000_000, 7_000_000),
            ],
        };
        for f in analyze(&data, &ctx()) {
            assert!(f.confidence.percent >= 60);
        }
    }
}
