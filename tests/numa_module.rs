// SPDX-License-Identifier: GPL-3.0-only

use linuxdoctor::core::context::Context;
use linuxdoctor::models::Severity;
use linuxdoctor::modules::numa::analyze::analyze;
use linuxdoctor::modules::numa::collect::{parse_node_meminfo, NumaNode, NumaRawData};

fn test_context() -> Context {
    Context {
        hostname: "test-host".into(),
        kernel_version: "6.8.0-test".into(),
        distro: Some("Test Linux".into()),
        architecture: "x86_64".into(),
        cpu_count: 4,
        mem_total_kb: 16_384_000,
        boot_time_unix: 0,
    }
}

#[test]
fn single_node_fixture_matches_this_sandbox_shape() {
    // Same shape as this sandbox's real node0/meminfo.
    let meminfo = "\
Node 0 MemTotal:        4093748 kB
Node 0 MemFree:         3992528 kB
Node 0 MemUsed:          101220 kB
";
    let (total, free) = parse_node_meminfo(meminfo).unwrap();
    let data = NumaRawData {
        nodes: vec![NumaNode {
            id: 0,
            cpus: vec![0],
            mem_total_kb: total,
            mem_free_kb: free,
        }],
    };

    let findings = analyze(&data, &test_context());
    assert_eq!(findings.len(), 1);
    assert_eq!(findings[0].id, "NUMA001");
    assert_eq!(findings[0].severity, Severity::Info);
}

#[test]
fn imbalanced_dual_node_fixture_produces_warning_or_error() {
    let data = NumaRawData {
        nodes: vec![
            NumaNode {
                id: 0,
                cpus: vec![0, 1, 2, 3],
                mem_total_kb: 32_000_000,
                mem_free_kb: 500_000, // ~98% used
            },
            NumaNode {
                id: 1,
                cpus: vec![4, 5, 6, 7],
                mem_total_kb: 32_000_000,
                mem_free_kb: 28_000_000, // ~12.5% used
            },
        ],
    };

    let findings = analyze(&data, &test_context());
    assert_eq!(findings.iter().filter(|f| f.id == "NUMA001").count(), 2);

    let imbalance = findings.iter().find(|f| f.id == "NUMA002").unwrap();
    assert!(imbalance.severity == Severity::Error || imbalance.severity == Severity::Warning);

    // Same fixture is topologically symmetric (identical CPU counts and
    // memory capacity per node) -- NUMA003 should say so, distinctly from
    // NUMA002's usage-based imbalance verdict.
    let topology = findings.iter().find(|f| f.id == "NUMA003").unwrap();
    assert!(topology.explanation.contains("symmetric"));
}

#[test]
fn asymmetric_topology_fixture_flags_structural_imbalance_with_resolution() {
    // A real-world shape: node 0 is a normal compute node, node 1 is a
    // small accelerator-associated node with far fewer CPUs and no local
    // memory at all.
    let data = NumaRawData {
        nodes: vec![
            NumaNode {
                id: 0,
                cpus: (0..16).collect(),
                mem_total_kb: 64_000_000,
                mem_free_kb: 32_000_000,
            },
            NumaNode {
                id: 1,
                cpus: vec![16, 17],
                mem_total_kb: 0,
                mem_free_kb: 0,
            },
        ],
    };

    let findings = analyze(&data, &test_context());
    let topology = findings.iter().find(|f| f.id == "NUMA003").unwrap();

    assert_eq!(topology.severity, Severity::Info);
    assert!(topology.explanation.contains("no local memory"));
    assert!(topology.explanation.contains("CPU counts range"));
    // "Potential resolution" -- a concrete recommendation must accompany
    // any detected asymmetry, not just a description of the problem.
    assert!(topology.recommendation.is_some());
    assert!(topology
        .recommendation
        .as_ref()
        .unwrap()
        .contains("numactl"));
}
