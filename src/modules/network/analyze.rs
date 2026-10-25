// SPDX-License-Identifier: GPL-3.0-only

use crate::core::context::Context;
use crate::models::{Category, Confidence, Finding, Severity};

use super::collect::{NetworkInterface, NetworkRawData};
use super::conntrack::conntrack_finding;
use super::{bonding, carrier};

/// Minimum total packets (rx+tx) before error/drop *rates* are evaluated.
/// Below this, a handful of startup-time drops can produce a misleading
/// percentage on a freshly-up interface — report the raw counts as Info
/// instead of a rate-based verdict that isn't statistically meaningful yet.
const MIN_PACKETS_FOR_RATE: u64 = 100;

/// Pure function: RawData -> Findings. No I/O — see ARCHITECTURE.md
/// "Testing Strategy".
pub fn analyze(data: &NetworkRawData, _ctx: &Context) -> Vec<Finding> {
    let mut findings = Vec::new();

    for iface in &data.interfaces {
        findings.push(interface_overview_finding(iface));
        findings.push(interface_errors_finding(iface));
    }

    findings.push(default_gateway_finding(data));
    findings.push(dns_configuration_finding(data));
    findings.extend(data.conntrack.as_ref().and_then(conntrack_finding));
    findings.extend(bonding::findings(&data.bonds));
    findings.extend(carrier::findings(&data.links));

    findings
}

/// NET001 — one per real interface, always Info. Purely descriptive.
fn interface_overview_finding(iface: &NetworkInterface) -> Finding {
    let speed_note = match iface.speed_mbps {
        Some(mbps) => format!(", link speed {mbps} Mbps"),
        None => String::new(),
    };
    let carrier_note = match iface.carrier {
        Some(true) => " Physical link detected.",
        Some(false) => " No physical link detected (cable unplugged or peer down).",
        None => "",
    };

    let mut builder = Finding::builder(
        "NET001",
        format!("Interface Overview \u{2014} {}", iface.name),
        Category::Network,
        Severity::Info,
        Confidence::direct_observation(),
    )
    .instance(iface.name.clone())
    .evidence("operstate", iface.operstate.clone());

    if let Some(mac) = &iface.mac_address {
        builder = builder.evidence("mac_address", mac.clone());
    }
    if let Some(mtu) = iface.mtu {
        builder = builder.evidence("mtu", mtu.to_string());
    }
    if let Some(mbps) = iface.speed_mbps {
        builder = builder.evidence("speed_mbps", mbps.to_string());
    }

    builder
        .explanation(format!(
            "{}: state {}{speed_note}.{carrier_note}",
            iface.name, iface.operstate
        ))
        .build()
}

/// NET002 — one per real interface, graduated on the worst of the four
/// rx/tx error/drop rates. Always reported (even when clean) so a
/// problem interface is never confused with "wasn't checked".
fn interface_errors_finding(iface: &NetworkInterface) -> Finding {
    let total_packets = iface.rx_packets + iface.tx_packets;

    if total_packets < MIN_PACKETS_FOR_RATE {
        return Finding::builder(
            "NET002",
            format!("Interface Errors/Drops \u{2014} {}", iface.name),
            Category::Network,
            Severity::Info,
            Confidence::direct_observation(),
        )
        .instance(iface.name.clone())
        .evidence("rx_packets", iface.rx_packets.to_string())
        .evidence("tx_packets", iface.tx_packets.to_string())
        .explanation(format!(
            "Only {total_packets} packets observed on {} so far — not enough \
             traffic yet to evaluate error/drop rates meaningfully.",
            iface.name
        ))
        .build();
    }

    let rate = |errs: u64, packets: u64| {
        if packets == 0 {
            0.0
        } else {
            errs as f64 / packets as f64 * 100.0
        }
    };
    let rx_err_pct = rate(iface.rx_errors, iface.rx_packets);
    let rx_drop_pct = rate(iface.rx_dropped, iface.rx_packets);
    let tx_err_pct = rate(iface.tx_errors, iface.tx_packets);
    let tx_drop_pct = rate(iface.tx_dropped, iface.tx_packets);
    let worst = rx_err_pct.max(rx_drop_pct).max(tx_err_pct).max(tx_drop_pct);

    let (mut severity, mut confidence) = if worst >= 1.0 {
        (Severity::Error, Confidence::strong_indication(85))
    } else if worst >= 0.1 {
        (Severity::Warning, Confidence::strong_indication(76))
    } else {
        (Severity::Info, Confidence::direct_observation())
    };

    // SR-IOV VFs share this physical NIC. On some driver/NIC
    // combinations, traffic the hardware steers to a VF's own queue gets
    // counted in the PF's rx_dropped without indicating an actual link,
    // cabling, or duplex problem -- a well-documented category of false
    // positive for this exact counter. We can't tell from these counters
    // alone whether that's what's happening here, so rather than silently
    // suppress the finding (which could hide a real coincidental problem)
    // or leave it as confidently alarming as the non-SR-IOV case, this
    // downgrades severity by one tier and lowers confidence -- the raw
    // numbers are still directly observed, but what they *mean* is
    // genuinely less certain with VFs active.
    //
    // The same goes for a VF itself: it has no cable or link of its own (it
    // shares its physical function's), and the NIC can steer traffic to it
    // that nothing on the host consumes, which counts as RX drops too.
    let sriov_active = matches!(iface.sriov_vfs, Some(n) if n > 0);
    let is_vf = iface.vf_of.is_some();
    let flagged = severity > Severity::Info;
    if (sriov_active || is_vf) && flagged {
        severity = match severity {
            Severity::Error => Severity::Warning,
            Severity::Warning => Severity::Info,
            other => other,
        };
        confidence = Confidence::weak_indication(65);
    }

    let sriov_note = match (&iface.vf_of, iface.sriov_vfs) {
        // Only said when the numbers call for it: a VF without drops has
        // nothing to explain.
        (Some(pf), _) if flagged => format!(
            " This interface is an SR-IOV virtual function (VF) of {pf}. A VF \
             has no cable or link of its own: it shares {pf}'s. The NIC can \
             steer traffic to a VF that nothing on the host consumes \
             (broadcast and multicast frames, for example), and that is \
             counted as RX drops without being a link problem, so these \
             numbers are less conclusive here than they would be on a \
             physical interface. Compare them with this VF's own traffic and \
             with {pf}'s counters (`ip -s link show <iface>`)."
        ),
        (Some(_), _) => String::new(),
        (None, Some(n)) if n > 0 => format!(
            " This interface has {n} active SR-IOV VF{s} — on some NIC/driver \
             combinations, traffic steered to a VF's own queue is counted in \
             the physical function's rx_dropped without indicating a real \
             link problem, so this number is less conclusive here than it \
             would be without VFs. Check the VF interfaces' own stats (`ip \
             -s link show <vf-iface>`) to see whether their traffic volume \
             lines up with the drops.",
            s = if n == 1 { "" } else { "s" },
        ),
        _ => String::new(),
    };

    let explanation = if severity == Severity::Info {
        format!(
            "{}: error/drop rates are all comfortably low (worst: {worst:.2}%).{sriov_note}",
            iface.name
        )
    } else {
        // A VF has no cable, duplex or switch port: the note says what it is.
        let physical_advice = if is_vf {
            ""
        } else {
            " Sustained rates like this commonly point to a cabling, \
             driver, duplex-mismatch, or switch-port problem rather than \
             normal network conditions."
        };
        format!(
            "{}: RX errors {rx_err_pct:.2}%, RX drops {rx_drop_pct:.2}%, TX \
             errors {tx_err_pct:.2}%, TX drops {tx_drop_pct:.2}% of \
             packets.{physical_advice}{sriov_note}",
            iface.name
        )
    };

    let mut builder = Finding::builder(
        "NET002",
        format!("Interface Errors/Drops \u{2014} {}", iface.name),
        Category::Network,
        severity,
        confidence,
    )
    .instance(iface.name.clone())
    .evidence("rx_packets", iface.rx_packets.to_string())
    .evidence("rx_errors", iface.rx_errors.to_string())
    .evidence("rx_dropped", iface.rx_dropped.to_string())
    .evidence("tx_packets", iface.tx_packets.to_string())
    .evidence("tx_errors", iface.tx_errors.to_string())
    .evidence("tx_dropped", iface.tx_dropped.to_string())
    .evidence("worst_rate_percent", format!("{worst:.2}"));

    if let Some(n) = iface.sriov_vfs {
        builder = builder.evidence("sriov_vfs", n.to_string());
    }
    if let Some(pf) = &iface.vf_of {
        builder = builder.evidence("sriov_vf_of", pf.clone());
    }

    builder = builder.explanation(explanation);

    if severity > Severity::Info {
        let recommendation = if is_vf {
            "A VF has no cable or switch port of its own, so look at how it \
             is used before suspecting the link: compare its drops with its \
             own traffic (`ip -s link show <vf-iface>`) and check its MAC, \
             VLAN and trust settings on the physical function (`ip link show \
             <pf-iface>` lists them). Only if neither explains it, check the \
             physical function's `ethtool <pf-iface>`, cable and switch port."
        } else if sriov_active {
            "Compare against the VF interfaces' own traffic (`ip -s link \
             show <vf-iface>`) before assuming a cabling/driver problem — \
             with SR-IOV active, elevated PF rx_dropped is often explained \
             by VF-steered traffic rather than a real link issue. If the \
             VF traffic doesn't account for it, then check `ethtool \
             <iface>` and the cable/switch port as usual."
        } else {
            "Check `ethtool <iface>` for link/duplex negotiation issues, \
             inspect the cable/switch port, and watch `ip -s link show \
             <iface>` over time to see whether the rate is still climbing \
             or was a one-off."
        };
        builder = builder.recommendation(recommendation);
    }

    builder.build()
}

/// NET003 — always reported, machine-wide (not per-interface).
fn default_gateway_finding(data: &NetworkRawData) -> Finding {
    let (severity, explanation) = if data.route.has_default_route {
        (
            Severity::Info,
            format!(
                "Default route via {} on {}.",
                data.route.default_gateway.as_deref().unwrap_or("unknown"),
                data.route
                    .default_route_interface
                    .as_deref()
                    .unwrap_or("unknown"),
            ),
        )
    } else {
        (
            Severity::Warning,
            "No default route is configured. This system can't reach \
             networks outside its directly connected subnets — expected \
             for an intentionally isolated host, but worth confirming if \
             that wasn't the intent."
                .to_string(),
        )
    };

    let mut builder = Finding::builder(
        "NET003",
        "Default Gateway",
        Category::Network,
        severity,
        Confidence::direct_observation(),
    )
    .evidence(
        "has_default_route",
        data.route.has_default_route.to_string(),
    );

    if let Some(gw) = &data.route.default_gateway {
        builder = builder.evidence("gateway", gw.clone());
    }
    if let Some(iface) = &data.route.default_route_interface {
        builder = builder.evidence("interface", iface.clone());
    }

    builder.explanation(explanation).build()
}

/// NET004 — always reported, machine-wide.
fn dns_configuration_finding(data: &NetworkRawData) -> Finding {
    let count = data.dns_servers.len();

    let (severity, explanation) = if count == 0 {
        (
            Severity::Error,
            "/etc/resolv.conf has no nameserver entries. Most hostname-based \
             network operations (web requests, package managers, most \
             services) will fail without a resolver configured."
                .to_string(),
        )
    } else {
        (
            Severity::Info,
            format!(
                "{count} nameserver{s} configured: {}.",
                data.dns_servers.join(", "),
                s = if count == 1 { "" } else { "s" },
            ),
        )
    };

    let mut builder = Finding::builder(
        "NET004",
        "DNS Configuration",
        Category::Network,
        severity,
        Confidence::direct_observation(),
    )
    .evidence("nameserver_count", count.to_string())
    .evidence("nameservers", data.dns_servers.join(","))
    .explanation(explanation);

    if severity > Severity::Info {
        builder = builder.recommendation(
            "Add at least one nameserver to /etc/resolv.conf, or check \
             whether it's meant to be managed automatically (systemd-resolved, \
             NetworkManager, DHCP) and that service is running.",
        );
    }

    builder.build()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::modules::network::collect::RouteInfo;

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

    fn iface(name: &str, rx_packets: u64, rx_dropped: u64) -> NetworkInterface {
        NetworkInterface {
            name: name.to_string(),
            operstate: "up".to_string(),
            mac_address: Some("aa:bb:cc:dd:ee:ff".to_string()),
            mtu: Some(1500),
            speed_mbps: Some(1000),
            carrier: Some(true),
            sriov_vfs: None,
            vf_of: None,
            rx_bytes: 1_000_000,
            rx_packets,
            rx_errors: 0,
            rx_dropped,
            tx_bytes: 1_000_000,
            tx_packets: 1000,
            tx_errors: 0,
            tx_dropped: 0,
        }
    }
    fn route(has_default: bool) -> RouteInfo {
        RouteInfo {
            has_default_route: has_default,
            default_gateway: if has_default {
                Some("192.0.2.1".to_string())
            } else {
                None
            },
            default_route_interface: if has_default {
                Some("eth0".to_string())
            } else {
                None
            },
        }
    }

    #[test]
    fn always_reports_overview_and_errors_per_interface() {
        let data = NetworkRawData {
            interfaces: vec![iface("eth0", 5000, 0)],
            route: route(true),
            dns_servers: vec!["8.8.8.8".to_string()],
            ..Default::default()
        };
        let findings = analyze(&data, &ctx());
        assert!(findings.iter().any(|f| f.id == "NET001"));
        assert!(findings.iter().any(|f| f.id == "NET002"));
    }

    #[test]
    fn the_connection_table_comes_last_and_only_when_there_is_one() {
        use crate::modules::saturation::Fill;

        let mut data = NetworkRawData {
            interfaces: vec![iface("eth0", 5000, 0)],
            route: route(true),
            dns_servers: vec!["8.8.8.8".to_string()],
            ..Default::default()
        };
        let ids = |data: &NetworkRawData| -> Vec<String> {
            analyze(data, &ctx()).into_iter().map(|f| f.id).collect()
        };
        assert_eq!(ids(&data), ["NET001", "NET002", "NET003", "NET004"]);
        data.conntrack = Some(Fill {
            used: 900,
            limit: 1000,
        });
        assert_eq!(
            ids(&data),
            ["NET001", "NET002", "NET003", "NET004", "NET005"]
        );
        let findings = analyze(&data, &ctx());
        assert_eq!(findings[4].severity, Severity::Warning);
        // A maximum of zero is not a table to judge.
        data.conntrack = Some(Fill { used: 5, limit: 0 });
        assert_eq!(ids(&data), ["NET001", "NET002", "NET003", "NET004"]);
    }

    #[test]
    fn bonds_and_flapping_links_come_after_the_connection_table() {
        use crate::modules::network::bonding::{Aggregator, Bond, Slave};
        use crate::modules::network::carrier::{Link, Links};
        use crate::modules::saturation::Fill;

        let slave = |name: &str, status: &str| Slave {
            name: name.to_string(),
            status: status.to_string(),
            link_failures: 0,
            aggregator: Aggregator::NotUsed,
        };
        let bond = |name: &str, second: &str| Bond {
            name: name.to_string(),
            mode: "fault-tolerance (active-backup)".to_string(),
            up: true,
            active_slave: Some("eth0".to_string()),
            slaves: vec![slave("eth0", "up"), slave("eth1", second)],
            active_aggregator: None,
            partner_mac: None,
        };
        let link = |name: &str, changes: u64| Link {
            name: name.to_string(),
            changes,
            up: None,
            down: None,
        };
        let mut data = NetworkRawData {
            interfaces: vec![iface("eth0", 5000, 0)],
            route: route(true),
            dns_servers: vec!["8.8.8.8".to_string()],
            conntrack: Some(Fill {
                used: 10,
                limit: 1000,
            }),
            // One bond that is whole, one that lost a card.
            bonds: vec![bond("bond0", "up"), bond("bond1", "down")],
            links: Links {
                uptime_secs: Some(86_400),
                links: vec![link("eth0", 2), link("eth1", 40), link("eth2", 50)],
            },
        };
        let ids = |data: &NetworkRawData| -> Vec<(String, Option<String>)> {
            analyze(data, &ctx())
                .into_iter()
                .map(|f| (f.id, f.instance))
                .collect()
        };
        let named = |id: &str, instance: &str| (id.to_string(), Some(instance.to_string()));
        let found = ids(&data);
        let tail: Vec<_> = found.iter().skip(5).cloned().collect();
        assert_eq!(
            tail,
            [
                named("NET006", "bond0"),
                named("NET006", "bond1"),
                named("NET007", "eth1"),
                named("NET007", "eth2"),
            ]
        );
        assert_eq!(found[4].0, "NET005");
        // Nothing to say without them.
        data.bonds.clear();
        data.links = Links::default();
        assert_eq!(ids(&data).len(), 5);
    }

    #[test]
    fn low_traffic_interface_skips_rate_evaluation() {
        // Genuinely low on both rx and tx -- iface()'s fixed tx_packets=1000
        // would push the total over MIN_PACKETS_FOR_RATE, so build this one
        // directly instead.
        let mut low_traffic = iface("eth0", 10, 5); // 50% drop rate, but tiny sample
        low_traffic.tx_packets = 5;
        let data = NetworkRawData {
            interfaces: vec![low_traffic],
            route: route(true),
            dns_servers: vec!["8.8.8.8".to_string()],
            ..Default::default()
        };
        let findings = analyze(&data, &ctx());
        let net002 = findings.iter().find(|f| f.id == "NET002").unwrap();
        assert_eq!(net002.severity, Severity::Info);
        assert!(net002.explanation.contains("not enough traffic"));
    }

    #[test]
    fn clean_interface_with_enough_traffic_is_info() {
        let data = NetworkRawData {
            interfaces: vec![iface("eth0", 5000, 0)],
            route: route(true),
            dns_servers: vec!["8.8.8.8".to_string()],
            ..Default::default()
        };
        let findings = analyze(&data, &ctx());
        let net002 = findings.iter().find(|f| f.id == "NET002").unwrap();
        assert_eq!(net002.severity, Severity::Info);
    }

    #[test]
    fn moderate_drop_rate_is_warning() {
        // 5000 rx_packets, 10 dropped = 0.2% -- above 0.1%, below 1%.
        let data = NetworkRawData {
            interfaces: vec![iface("eth0", 5000, 10)],
            route: route(true),
            dns_servers: vec!["8.8.8.8".to_string()],
            ..Default::default()
        };
        let findings = analyze(&data, &ctx());
        let net002 = findings.iter().find(|f| f.id == "NET002").unwrap();
        assert_eq!(net002.severity, Severity::Warning);
    }

    #[test]
    fn high_drop_rate_is_error() {
        // Mirrors this sandbox's real eth0: 99 rx_packets, 13 dropped (~13%).
        let data = NetworkRawData {
            interfaces: vec![iface("eth0", 99, 13)],
            route: route(true),
            dns_servers: vec!["8.8.8.8".to_string()],
            ..Default::default()
        };
        let findings = analyze(&data, &ctx());
        let net002 = findings.iter().find(|f| f.id == "NET002").unwrap();
        assert_eq!(net002.severity, Severity::Error);
        assert!(net002.recommendation.is_some());
    }

    #[test]
    fn default_gateway_present_is_info() {
        let data = NetworkRawData {
            interfaces: vec![],
            route: route(true),
            dns_servers: vec!["8.8.8.8".to_string()],
            ..Default::default()
        };
        let findings = analyze(&data, &ctx());
        let net003 = findings.iter().find(|f| f.id == "NET003").unwrap();
        assert_eq!(net003.severity, Severity::Info);
    }

    #[test]
    fn missing_default_gateway_is_warning() {
        let data = NetworkRawData {
            interfaces: vec![],
            route: route(false),
            dns_servers: vec!["8.8.8.8".to_string()],
            ..Default::default()
        };
        let findings = analyze(&data, &ctx());
        let net003 = findings.iter().find(|f| f.id == "NET003").unwrap();
        assert_eq!(net003.severity, Severity::Warning);
    }

    #[test]
    fn dns_configured_is_info() {
        let data = NetworkRawData {
            interfaces: vec![],
            route: route(true),
            dns_servers: vec!["8.8.8.8".to_string(), "1.1.1.1".to_string()],
            ..Default::default()
        };
        let findings = analyze(&data, &ctx());
        let net004 = findings.iter().find(|f| f.id == "NET004").unwrap();
        assert_eq!(net004.severity, Severity::Info);
    }

    #[test]
    fn no_dns_servers_is_error() {
        let data = NetworkRawData {
            interfaces: vec![],
            route: route(true),
            dns_servers: vec![],
            ..Default::default()
        };
        let findings = analyze(&data, &ctx());
        let net004 = findings.iter().find(|f| f.id == "NET004").unwrap();
        assert_eq!(net004.severity, Severity::Error);
        assert!(net004.recommendation.is_some());
    }

    #[test]
    fn confidence_never_reported_below_60() {
        let data = NetworkRawData {
            interfaces: vec![iface("eth0", 99, 13)],
            route: route(false),
            dns_servers: vec![],
            ..Default::default()
        };
        for f in analyze(&data, &ctx()) {
            assert!(f.confidence.percent >= 60);
        }
    }

    #[test]
    fn sriov_active_downgrades_error_to_warning() {
        let mut sriov_iface = iface("enp6s0", 150_102, 37_175); // ~24.8% drop rate
        sriov_iface.sriov_vfs = Some(2);
        let data = NetworkRawData {
            interfaces: vec![sriov_iface],
            route: route(true),
            dns_servers: vec!["8.8.8.8".to_string()],
            ..Default::default()
        };
        let findings = analyze(&data, &ctx());
        let net002 = findings.iter().find(|f| f.id == "NET002").unwrap();
        assert_eq!(net002.severity, Severity::Warning); // downgraded from Error
        assert!(net002.explanation.contains("SR-IOV"));
        assert!(net002.confidence.percent < 76); // lower than the non-SR-IOV Warning tier
        assert!(net002
            .recommendation
            .as_ref()
            .unwrap()
            .contains("VF interfaces"));
    }

    #[test]
    fn sriov_inactive_keeps_full_severity_and_confidence() {
        // Same drop rate as above, but no VFs -- must NOT be downgraded.
        let mut plain_iface = iface("enp6s0", 150_102, 37_175);
        plain_iface.sriov_vfs = Some(0); // SR-IOV-capable, but no VFs provisioned
        let data = NetworkRawData {
            interfaces: vec![plain_iface],
            route: route(true),
            dns_servers: vec!["8.8.8.8".to_string()],
            ..Default::default()
        };
        let findings = analyze(&data, &ctx());
        let net002 = findings.iter().find(|f| f.id == "NET002").unwrap();
        assert_eq!(net002.severity, Severity::Error);
        assert!(!net002.explanation.contains("SR-IOV"));
    }

    /// `iface` through the whole analysis, and its NET002 finding.
    fn net002_of(iface: NetworkInterface) -> Finding {
        let data = NetworkRawData {
            interfaces: vec![iface],
            route: route(true),
            dns_servers: vec!["8.8.8.8".to_string()],
            ..Default::default()
        };
        analyze(&data, &ctx())
            .into_iter()
            .find(|f| f.id == "NET002")
            .unwrap()
    }

    /// A virtual function of `enp6s0`, with the given traffic and drops.
    fn vf(rx_packets: u64, rx_dropped: u64) -> NetworkInterface {
        let mut vf = iface("enp6s0v1", rx_packets, rx_dropped);
        vf.vf_of = Some("enp6s0".to_string());
        vf
    }

    fn evidence<'a>(f: &'a Finding, key: &str) -> Option<&'a str> {
        f.evidence
            .iter()
            .find(|(k, _)| k == key)
            .map(|(_, v)| v.as_str())
    }

    #[test]
    fn a_virtual_function_with_heavy_drops_is_downgraded_and_explained() {
        let net002 = net002_of(vf(150_102, 37_175)); // ~24.8% drop rate
        assert_eq!(net002.severity, Severity::Warning); // downgraded from Error
        assert_eq!(net002.confidence.percent, 65);
        assert!(
            net002.explanation.contains(
                "This interface is an SR-IOV virtual function (VF) of enp6s0. \
                 A VF has no cable or link of its own: it shares enp6s0's."
            ),
            "{}",
            net002.explanation
        );
        assert!(net002.explanation.contains("less conclusive here"));
        // The advice for a physical interface does not apply to a VF.
        assert!(!net002.explanation.contains("cabling"));
        assert_eq!(evidence(&net002, "sriov_vf_of"), Some("enp6s0"));
        let advice = net002.recommendation.as_deref().unwrap();
        assert!(advice.contains("A VF has no cable or switch port of its own"));
        assert!(advice.contains("`ip link show <pf-iface>`"));
        assert!(!advice.contains("duplex negotiation"));
    }

    #[test]
    fn a_virtual_function_with_moderate_drops_is_info_but_keeps_the_explanation() {
        // 0.5% of the packets: a Warning on a physical interface.
        let net002 = net002_of(vf(10_000, 50));
        assert_eq!(net002.severity, Severity::Info);
        assert!(net002
            .explanation
            .contains("virtual function (VF) of enp6s0"));
        assert!(net002.recommendation.is_none());
    }

    #[test]
    fn a_virtual_function_without_drops_gets_no_note() {
        let net002 = net002_of(vf(10_000, 0));
        assert_eq!(net002.severity, Severity::Info);
        assert_eq!(
            net002.explanation,
            "enp6s0v1: error/drop rates are all comfortably low (worst: 0.00%)."
        );
        // It is still said what it is.
        assert_eq!(evidence(&net002, "sriov_vf_of"), Some("enp6s0"));
    }

    #[test]
    fn a_physical_interface_keeps_the_cabling_advice_and_no_vf_note() {
        let net002 = net002_of(iface("enp6s0", 150_102, 37_175));
        assert_eq!(net002.severity, Severity::Error);
        assert!(net002
            .explanation
            .contains("commonly point to a cabling, driver, duplex-mismatch"));
        assert!(!net002.explanation.contains("virtual function"));
        assert_eq!(evidence(&net002, "sriov_vf_of"), None);
        assert!(net002
            .recommendation
            .as_deref()
            .unwrap()
            .contains("duplex negotiation"));
    }

    #[test]
    fn a_card_with_a_single_virtual_function_is_treated_like_one_with_several() {
        let mut pf = iface("enp6s0", 150_102, 37_175);
        pf.sriov_vfs = Some(1);
        let net002 = net002_of(pf);
        assert_eq!(net002.severity, Severity::Warning); // downgraded from Error
        assert!(
            net002
                .explanation
                .contains("has 1 active SR-IOV VF \u{2014}"),
            "{}",
            net002.explanation
        );
    }

    #[test]
    fn the_physical_function_of_vfs_keeps_its_own_note() {
        let mut pf = iface("enp6s0", 150_102, 37_175);
        pf.sriov_vfs = Some(2);
        let net002 = net002_of(pf);
        assert!(net002.explanation.contains("has 2 active SR-IOV VFs"));
        assert!(!net002.explanation.contains("virtual function (VF) of"));
        assert_eq!(evidence(&net002, "sriov_vfs"), Some("2"));
        assert_eq!(evidence(&net002, "sriov_vf_of"), None);
    }

    #[test]
    fn sriov_not_capable_is_same_as_absent() {
        let mut plain_iface = iface("enp6s0", 150_102, 37_175);
        plain_iface.sriov_vfs = None; // not an SR-IOV-capable device at all
        let data = NetworkRawData {
            interfaces: vec![plain_iface],
            route: route(true),
            dns_servers: vec!["8.8.8.8".to_string()],
            ..Default::default()
        };
        let findings = analyze(&data, &ctx());
        let net002 = findings.iter().find(|f| f.id == "NET002").unwrap();
        assert_eq!(net002.severity, Severity::Error);
    }
}
