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
    };

    let findings = analyze(&data, &test_context());
    let net003 = findings.iter().find(|f| f.id == "NET003").unwrap();
    let net004 = findings.iter().find(|f| f.id == "NET004").unwrap();
    assert_eq!(net003.severity, Severity::Warning);
    assert_eq!(net004.severity, Severity::Error);
}
