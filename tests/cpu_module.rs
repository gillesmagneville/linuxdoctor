// SPDX-License-Identifier: GPL-3.0-only

use linuxdoctor::core::context::Context;
use linuxdoctor::models::Severity;
use linuxdoctor::modules::cpu::analyze::analyze;
use linuxdoctor::modules::cpu::collect::{parse_loadavg, CpuRawData, CpuSocket};

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
fn idle_single_socket_fixture_produces_only_info_findings() {
    let loadavg = "0.12 0.04 0.01 1/75 476\n";
    let (load_1m, load_5m, load_15m) = parse_loadavg(loadavg).unwrap();

    let data = CpuRawData {
        load_1m,
        load_5m,
        load_15m,
        sockets: vec![CpuSocket {
            physical_id: 0,
            model_name: Some("Test CPU @ 2.10GHz".to_string()),
            cores: 4,
            threads: 4,
            logical_cpus: vec![0, 1, 2, 3],
        }],
        isolcpus: vec![],
        nohz_full: vec![],
        cgroup_isolated: vec![],
        system_slice_excluded: vec![],
        offline_cpus: vec![],
    };

    let findings = analyze(&data, &test_context());
    assert!(findings.iter().all(|f| f.severity == Severity::Info));
    assert!(findings.iter().any(|f| f.id == "CPU001"));
    assert!(findings.iter().any(|f| f.id == "CPU002"));
    assert!(findings.iter().any(|f| f.id == "CPU004"));
    assert!(!findings.iter().any(|f| f.id == "CPU003"));
    // CPU005 is always present now, even with nothing isolated.
    let cpu005 = findings.iter().find(|f| f.id == "CPU005").unwrap();
    assert!(cpu005.explanation.contains("hypervisor/host level"));
    assert!(!findings.iter().any(|f| f.id == "CPU006")); // nothing offline
}

#[test]
fn multi_socket_fixture_reports_one_detail_finding_per_socket() {
    let data = CpuRawData {
        load_1m: 0.5,
        load_5m: 0.5,
        load_15m: 0.5,
        sockets: vec![
            CpuSocket {
                physical_id: 0,
                model_name: Some("Test CPU".to_string()),
                cores: 8,
                threads: 16,
                logical_cpus: (0..16).collect(),
            },
            CpuSocket {
                physical_id: 1,
                model_name: Some("Test CPU".to_string()),
                cores: 8,
                threads: 16,
                logical_cpus: (16..32).collect(),
            },
        ],
        isolcpus: vec![0, 1, 16, 17],
        nohz_full: vec![],
        cgroup_isolated: vec![],
        system_slice_excluded: vec![],
        offline_cpus: vec![],
    };

    let findings = analyze(&data, &test_context());

    let socket_findings: Vec<_> = findings.iter().filter(|f| f.id == "CPU004").collect();
    assert_eq!(socket_findings.len(), 2);

    let overview = findings.iter().find(|f| f.id == "CPU001").unwrap();
    assert!(overview
        .evidence
        .iter()
        .any(|(k, v)| k == "total_logical_cpus" && v == "32"));

    // isolated CPUs 0,1 belong to socket 0 -> that socket's detail should
    // show 14 available (16 - 2), not the machine-wide total.
    let socket0 = socket_findings
        .iter()
        .find(|f| f.title.contains("socket 0"))
        .unwrap();
    assert!(socket0
        .evidence
        .iter()
        .any(|(k, v)| k == "available_threads" && v == "14"));

    let isolated = findings.iter().find(|f| f.id == "CPU005").unwrap();
    assert_eq!(isolated.severity, Severity::Info);
}

#[test]
fn isolation_reported_regardless_of_which_of_the_three_mechanisms_is_used() {
    // A realistic mixed scenario: isolcpus= isolates CPU 0, nohz_full=
    // covers CPU 1 too, and a Kubernetes-style cgroup isolated partition
    // covers CPU 8. All three must show up, correctly attributed.
    let data = CpuRawData {
        load_1m: 0.2,
        load_5m: 0.2,
        load_15m: 0.2,
        sockets: vec![CpuSocket {
            physical_id: 0,
            model_name: Some("Test CPU".to_string()),
            cores: 9,
            threads: 9,
            logical_cpus: (0..9).collect(),
        }],
        isolcpus: vec![0],
        nohz_full: vec![0, 1],
        cgroup_isolated: vec![8],
        system_slice_excluded: vec![],
        offline_cpus: vec![],
    };

    let findings = analyze(&data, &test_context());
    let cpu005 = findings.iter().find(|f| f.id == "CPU005").unwrap();

    assert!(cpu005
        .evidence
        .iter()
        .any(|(k, v)| k == "total_isolated" && v == "3")); // union of {0,1,8}
    assert!(cpu005.explanation.contains("isolcpus="));
    assert!(cpu005.explanation.contains("nohz_full="));
    assert!(cpu005.explanation.contains("cgroup isolated partition"));

    let cpu004 = findings.iter().find(|f| f.id == "CPU004").unwrap();
    assert!(cpu004
        .evidence
        .iter()
        .any(|(k, v)| k == "isolated_threads" && v == "3"));
    assert!(cpu004
        .evidence
        .iter()
        .any(|(k, v)| k == "available_threads" && v == "6"));
}

#[test]
fn libvirt_hook_system_slice_restriction_reserves_cpus_for_vm() {
    // Mirrors the exact setup reported: a libvirt hook runs
    // `systemctl set-property --runtime system.slice AllowedCPUs=<cpus>`
    // when a VM starts, restricting system.slice to a subset and leaving
    // the complement reserved for the VM (machine.slice); the hook
    // reverses this when the VM stops.
    let data = CpuRawData {
        load_1m: 0.3,
        load_5m: 0.3,
        load_15m: 0.3,
        sockets: vec![CpuSocket {
            physical_id: 0,
            model_name: Some("Test CPU".to_string()),
            cores: 8,
            threads: 8,
            logical_cpus: (0..8).collect(),
        }],
        isolcpus: vec![],
        nohz_full: vec![],
        cgroup_isolated: vec![],
        system_slice_excluded: vec![4, 5, 6, 7], // reserved for the VM
        offline_cpus: vec![],
    };

    let findings = analyze(&data, &test_context());

    let cpu005 = findings.iter().find(|f| f.id == "CPU005").unwrap();
    assert!(cpu005
        .evidence
        .iter()
        .any(|(k, v)| k == "system_slice_excluded" && v == "4-7"));
    assert!(cpu005.explanation.contains("AllowedCPUs="));

    // The socket-level breakdown must reflect this too, not just CPU005.
    let cpu004 = findings.iter().find(|f| f.id == "CPU004").unwrap();
    assert!(cpu004
        .evidence
        .iter()
        .any(|(k, v)| k == "available_threads" && v == "4"));
    assert!(cpu004
        .evidence
        .iter()
        .any(|(k, v)| k == "isolated_threads" && v == "4"));
}

#[test]
fn offline_cpus_fixture_reflects_vm_underprovisioning_scenario() {
    // A hypervisor exposing 8 "possible" vCPUs but only activating 4 is
    // exactly what this looks like from inside the guest.
    let data = CpuRawData {
        load_1m: 0.2,
        load_5m: 0.2,
        load_15m: 0.2,
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
        offline_cpus: vec![4, 5, 6, 7],
    };

    let findings = analyze(&data, &test_context());
    let cpu006 = findings.iter().find(|f| f.id == "CPU006").unwrap();
    assert_eq!(cpu006.severity, Severity::Info);
    assert!(cpu006
        .evidence
        .iter()
        .any(|(k, v)| k == "offline_cpus" && v == "4-7"));
}

#[test]
fn sustained_overload_fixture_produces_critical_finding() {
    let loadavg = "9.10 8.50 7.90 12/300 9999\n";
    let (load_1m, load_5m, load_15m) = parse_loadavg(loadavg).unwrap();

    let data = CpuRawData {
        load_1m,
        load_5m,
        load_15m,
        sockets: vec![CpuSocket {
            physical_id: 0,
            model_name: None,
            cores: 4,
            threads: 4,
            logical_cpus: vec![0, 1, 2, 3],
        }],
        isolcpus: vec![],
        nohz_full: vec![],
        cgroup_isolated: vec![],
        system_slice_excluded: vec![],
        offline_cpus: vec![],
    };

    let findings = analyze(&data, &test_context());
    let cpu003 = findings.iter().find(|f| f.id == "CPU003").unwrap();
    assert_eq!(cpu003.severity, Severity::Critical);
}
