// SPDX-License-Identifier: GPL-3.0-only

use linuxdoctor::core::context::Context;
use linuxdoctor::models::Severity;
use linuxdoctor::modules::network::analyze::analyze;
use linuxdoctor::modules::network::collect::{NetworkInterface, NetworkRawData, RouteInfo};

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

fn healthy_iface(name: &str) -> NetworkInterface {
    NetworkInterface {
        name: name.to_string(),
        operstate: "up".to_string(),
        mac_address: Some("aa:bb:cc:dd:ee:ff".to_string()),
        mtu: Some(1500),
        speed_mbps: Some(1000),
        carrier: Some(true),
        sriov_vfs: None,
        rx_bytes: 5_000_000,
        rx_packets: 5000,
        rx_errors: 0,
        rx_dropped: 0,
        tx_bytes: 5_000_000,
        tx_packets: 5000,
        tx_errors: 0,
        tx_dropped: 0,
    }
}

#[test]
fn healthy_system_fixture_produces_only_info_findings() {
    let data = NetworkRawData {
        interfaces: vec![healthy_iface("eth0")],
        route: RouteInfo {
            has_default_route: true,
            default_gateway: Some("192.0.2.1".to_string()),
            default_route_interface: Some("eth0".to_string()),
        },
        dns_servers: vec!["8.8.8.8".to_string()],
        ..Default::default()
    };

    let findings = analyze(&data, &test_context());
    assert!(findings.iter().all(|f| f.severity == Severity::Info));
    let ids: Vec<&str> = findings.iter().map(|f| f.id.as_str()).collect();
    assert!(ids.contains(&"NET001"));
    assert!(ids.contains(&"NET002"));
    assert!(ids.contains(&"NET003"));
    assert!(ids.contains(&"NET004"));
}

/// Mirrors this sandbox's real `/proc/net/dev` for eth0: 99 rx_packets,
/// 13 dropped (~13%) — captured from an actual audit run, not invented.
#[test]
fn real_sandbox_drop_rate_fixture_produces_error() {
    let data = NetworkRawData {
        interfaces: vec![NetworkInterface {
            name: "eth0".to_string(),
            operstate: "up".to_string(),
            mac_address: Some("02:fc:00:00:00:01".to_string()),
            mtu: Some(1400),
            speed_mbps: None, // this sandbox's eth0 reports speed = -1 (unknown)
            carrier: Some(true),
            sriov_vfs: None,
            rx_bytes: 29783,
            rx_packets: 99,
            rx_errors: 0,
            rx_dropped: 13,
            tx_bytes: 18978,
            tx_packets: 89,
            tx_errors: 0,
            tx_dropped: 0,
        }],
        route: RouteInfo {
            has_default_route: true,
            default_gateway: Some("192.0.2.1".to_string()),
            default_route_interface: Some("eth0".to_string()),
        },
        dns_servers: vec!["8.8.8.8".to_string()],
        ..Default::default()
    };

    let findings = analyze(&data, &test_context());
    let net002 = findings.iter().find(|f| f.id == "NET002").unwrap();
    assert_eq!(net002.severity, Severity::Error);
    assert!(net002
        .evidence
        .iter()
        .any(|(k, v)| k == "rx_dropped" && v == "13"));
}

#[test]
fn missing_gateway_and_dns_fixture_flags_both() {
    let data = NetworkRawData {
        interfaces: vec![],
        route: RouteInfo::default(),
        dns_servers: vec![],
        ..Default::default()
    };

    let findings = analyze(&data, &test_context());
    let net003 = findings.iter().find(|f| f.id == "NET003").unwrap();
    let net004 = findings.iter().find(|f| f.id == "NET004").unwrap();
    assert_eq!(net003.severity, Severity::Warning);
    assert_eq!(net004.severity, Severity::Error);
}

/// Reproduces exactly the case reported against this tool: a physical
/// NIC (enp6s0) with 2 active SR-IOV VFs (enp6s0v1, enp6s0v2), showing a
/// ~24.8% RX drop rate despite the interface actually working fine at
/// full speed with clean auto-negotiation. NET002 must not report this
/// as a confident Error the way it would on a non-SR-IOV interface.
#[test]
fn sriov_interface_with_high_pf_rx_dropped_is_not_a_confident_error() {
    let data = NetworkRawData {
        interfaces: vec![NetworkInterface {
            name: "enp6s0".to_string(),
            operstate: "up".to_string(),
            mac_address: Some("aa:bb:cc:dd:ee:ff".to_string()),
            mtu: Some(1500),
            speed_mbps: Some(10000),
            carrier: Some(true),
            sriov_vfs: Some(2),
            rx_bytes: 200_000_000,
            rx_packets: 150_102,
            rx_errors: 0,
            rx_dropped: 37_175,
            tx_bytes: 150_000_000,
            tx_packets: 115_544,
            tx_errors: 0,
            tx_dropped: 0,
        }],
        route: RouteInfo {
            has_default_route: true,
            default_gateway: Some("192.168.1.1".to_string()),
            default_route_interface: Some("enp6s0".to_string()),
        },
        dns_servers: vec!["8.8.8.8".to_string()],
        ..Default::default()
    };

    let findings = analyze(&data, &test_context());
    let net002 = findings.iter().find(|f| f.id == "NET002").unwrap();

    // Downgraded from Error to Warning, and confidence explicitly lower
    // than the equivalent non-SR-IOV Warning tier (76%).
    assert_eq!(net002.severity, Severity::Warning);
    assert!(net002.confidence.percent < 76);
    assert!(net002.explanation.contains("SR-IOV"));
    assert!(net002.explanation.contains("2 active SR-IOV VFs"));
    assert!(net002
        .recommendation
        .as_ref()
        .unwrap()
        .contains("VF interfaces"));
}

/// A connection table that is nearly full, from the figures the kernel
/// prints, through the whole analysis; and no table, no finding.
#[test]
fn a_full_connection_table_is_found_and_a_missing_one_is_not() {
    use linuxdoctor::modules::saturation::{parse_number, Fill};

    let data = NetworkRawData {
        interfaces: vec![healthy_iface("eth0")],
        conntrack: Some(Fill {
            used: parse_number("253000\n").unwrap(),
            limit: parse_number("262144\n").unwrap(),
        }),
        ..Default::default()
    };
    let findings = analyze(&data, &test_context());
    let net005 = findings.iter().find(|f| f.id == "NET005").unwrap();
    assert_eq!(net005.severity, Severity::Error);
    assert!(net005
        .evidence
        .iter()
        .any(|(k, v)| k == "usage_percent" && v == "96"));
    assert!(net005.recommendation.is_some());

    let without = NetworkRawData {
        conntrack: None,
        ..data
    };
    assert!(analyze(&without, &test_context())
        .iter()
        .all(|f| f.id != "NET005"));
}

/// The real binary: the table exists only where `nf_conntrack` is loaded,
/// so what is checked is that the finding agrees with `/proc`.
#[test]
fn the_real_binary_reports_the_connection_table_exactly_when_the_host_has_one() {
    let out = std::process::Command::new(env!("CARGO_BIN_EXE_linuxdoctor"))
        .args([
            "--no-config",
            "audit",
            "--modules",
            "network",
            "--fail-on",
            "never",
            "--output",
            "json",
        ])
        .stdin(std::process::Stdio::null())
        .output()
        .expect("linuxdoctor binary should start");
    let report: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    let findings = report["results"][0]["findings"].as_array().unwrap();
    let net005 = findings.iter().find(|f| f["id"] == "NET005");

    let read = |name: &str| {
        std::fs::read_to_string(format!("/proc/sys/net/netfilter/{name}"))
            .ok()
            .and_then(|text| text.trim().parse::<u64>().ok())
    };
    let table = read("nf_conntrack_count").zip(read("nf_conntrack_max"));
    let expected = table.filter(|&(_, max)| max > 0);
    assert_eq!(net005.is_some(), expected.is_some(), "{table:?}");
    if let (Some(finding), Some((_, max))) = (net005, expected) {
        let reported = finding["evidence"]
            .as_array()
            .unwrap()
            .iter()
            .find_map(|pair| (pair[0] == "conntrack_max").then(|| pair[1].as_str().unwrap()))
            .unwrap();
        assert_eq!(reported, max.to_string(), "{finding}");
    }
}
