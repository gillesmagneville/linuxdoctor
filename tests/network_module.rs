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
        vf_of: None,
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
            vf_of: None,
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
            vf_of: None,
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

/// The virtual functions themselves (enp6s0v1, enp6s0v2), found as VFs from
/// the links the kernel puts in `/sys`, with the drops a VF shows: they get
/// the same explanation as their physical function, not the advice about
/// cables and switch ports that a VF has none of.
#[test]
fn the_virtual_functions_of_a_card_are_explained_as_such() {
    use linuxdoctor::modules::network::collect::read_vf_parent;
    use std::os::unix::fs::symlink;

    let root =
        std::env::temp_dir().join(format!("linuxdoctor-network-vf-it-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&root);
    let devices = root.join("devices");
    std::fs::create_dir_all(devices.join("0000:06:00.0/net/enp6s0")).unwrap();
    let mut interfaces = Vec::new();
    for (number, pci) in [(1, "0000:06:10.0"), (2, "0000:06:10.1")] {
        let name = format!("enp6s0v{number}");
        std::fs::create_dir_all(devices.join(pci)).unwrap();
        symlink("../0000:06:00.0", devices.join(pci).join("physfn")).unwrap();
        let dir = root.join("class/net").join(&name);
        std::fs::create_dir_all(&dir).unwrap();
        symlink(devices.join(pci), dir.join("device")).unwrap();
        let mut vf = healthy_iface(&name);
        vf.vf_of = read_vf_parent(&dir);
        vf.rx_packets = 150_102;
        vf.rx_dropped = 37_175; // ~24.8%, as on the card they belong to
        interfaces.push(vf);
    }
    let _ = std::fs::remove_dir_all(&root);

    let data = NetworkRawData {
        interfaces,
        route: RouteInfo {
            has_default_route: true,
            default_gateway: Some("192.168.1.1".to_string()),
            default_route_interface: Some("enp6s0".to_string()),
        },
        dns_servers: vec!["8.8.8.8".to_string()],
        ..Default::default()
    };
    let findings = analyze(&data, &test_context());

    for name in ["enp6s0v1", "enp6s0v2"] {
        let net002 = findings
            .iter()
            .find(|f| f.id == "NET002" && f.instance.as_deref() == Some(name))
            .unwrap();
        assert_eq!(net002.severity, Severity::Warning, "{name}");
        assert!(net002.confidence.percent < 76, "{name}");
        assert!(
            net002
                .explanation
                .contains("SR-IOV virtual function (VF) of enp6s0."),
            "{name}: {}",
            net002.explanation
        );
        assert!(!net002.explanation.contains("cabling"), "{name}");
        assert!(net002
            .recommendation
            .as_ref()
            .unwrap()
            .contains("A VF has no cable or switch port of its own"));
    }
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

/// What the kernel prints for a bond that lost a card, read from a fake tree
/// and put through the whole analysis.
#[test]
fn a_bond_that_lost_a_card_is_found_from_the_files_of_the_kernel() {
    use linuxdoctor::modules::network::bonding;

    let root = std::env::temp_dir().join(format!(
        "linuxdoctor-network-bond-it-{}",
        std::process::id()
    ));
    let _ = std::fs::remove_dir_all(&root);
    std::fs::create_dir_all(root.join("proc/net/bonding")).unwrap();
    std::fs::write(
        root.join("proc/net/bonding/bond0"),
        "Ethernet Channel Bonding Driver: v6.8.0-45-generic\n\n\
         Bonding Mode: fault-tolerance (active-backup)\n\
         Currently Active Slave: eth0\n\
         MII Status: up\n\n\
         Slave Interface: eth0\n\
         MII Status: up\n\
         Link Failure Count: 0\n\n\
         Slave Interface: eth1\n\
         MII Status: down\n\
         Link Failure Count: 3\n",
    )
    .unwrap();

    let data = NetworkRawData {
        interfaces: vec![healthy_iface("bond0")],
        bonds: bonding::read(&root),
        ..Default::default()
    };
    let findings = analyze(&data, &test_context());
    let net006 = findings.iter().find(|f| f.id == "NET006").unwrap();
    assert_eq!(net006.severity, Severity::Warning);
    assert_eq!(net006.instance.as_deref(), Some("bond0"));
    assert!(net006
        .evidence
        .iter()
        .any(|(k, v)| k == "slaves_with_link" && v == "1/2"));
    assert!(net006.recommendation.is_some());

    // The same bond with the second card back is information.
    let healed = std::fs::read_to_string(root.join("proc/net/bonding/bond0"))
        .unwrap()
        .replace("MII Status: down", "MII Status: up");
    std::fs::write(root.join("proc/net/bonding/bond0"), healed).unwrap();
    let data = NetworkRawData {
        bonds: bonding::read(&root),
        ..data
    };
    let findings = analyze(&data, &test_context());
    let net006 = findings.iter().find(|f| f.id == "NET006").unwrap();
    assert_eq!(net006.severity, Severity::Info);
    assert!(net006.recommendation.is_none());
    let _ = std::fs::remove_dir_all(&root);
}

/// A card whose link keeps dropping, from the counters of `/sys`, through the
/// whole analysis; a machine that has just booted does not flap.
#[test]
fn a_card_that_keeps_losing_its_link_is_found_from_the_files_of_the_kernel() {
    use linuxdoctor::modules::network::carrier;

    let root = std::env::temp_dir().join(format!(
        "linuxdoctor-network-carrier-it-{}",
        std::process::id()
    ));
    let _ = std::fs::remove_dir_all(&root);
    std::fs::create_dir_all(root.join("proc")).unwrap();
    for (name, changes) in [("eno1", "2"), ("eno2", "86")] {
        let dir = root.join("sys/class/net").join(name);
        std::fs::create_dir_all(dir.join("device")).unwrap();
        std::fs::write(dir.join("carrier_changes"), format!("{changes}\n")).unwrap();
    }
    // Two days up.
    std::fs::write(root.join("proc/uptime"), "172800.12 340000.00\n").unwrap();

    let data = NetworkRawData {
        interfaces: vec![healthy_iface("eno1"), healthy_iface("eno2")],
        links: carrier::read(&root),
        ..Default::default()
    };
    let findings = analyze(&data, &test_context());
    let flapping: Vec<_> = findings.iter().filter(|f| f.id == "NET007").collect();
    assert_eq!(flapping.len(), 1);
    assert_eq!(flapping[0].instance.as_deref(), Some("eno2"));
    assert_eq!(flapping[0].severity, Severity::Warning);
    assert!(flapping[0]
        .evidence
        .iter()
        .any(|(k, v)| k == "changes_per_day" && v == "43.0"));

    // The same count in ten minutes is a much faster rate, and is said too.
    std::fs::write(root.join("proc/uptime"), "600.00 1000.00\n").unwrap();
    let data = NetworkRawData {
        links: carrier::read(&root),
        ..data
    };
    assert_eq!(
        analyze(&data, &test_context())
            .iter()
            .filter(|f| f.id == "NET007")
            .count(),
        1
    );
    let _ = std::fs::remove_dir_all(&root);
}

/// The real binary: bonds appear exactly when `/proc/net/bonding` has them,
/// and a card is said to flap only if its own counter agrees.
#[test]
fn the_real_binary_reports_bonds_and_flapping_cards_only_where_the_host_has_them() {
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

    let bonds = std::fs::read_dir("/proc/net/bonding")
        .map(|entries| entries.flatten().count())
        .unwrap_or(0)
        .min(16);
    let reported = findings.iter().filter(|f| f["id"] == "NET006").count();
    assert_eq!(reported, bonds);

    for finding in findings.iter().filter(|f| f["id"] == "NET007") {
        let name = finding["instance"].as_str().unwrap();
        let now: u64 = std::fs::read_to_string(format!("/sys/class/net/{name}/carrier_changes"))
            .unwrap()
            .trim()
            .parse()
            .unwrap();
        // The counter only grows, so it cannot be below what was reported.
        assert!(now >= 10, "{name}: {now}");
    }
}
