// SPDX-License-Identifier: GPL-3.0-only

use std::collections::HashMap;
use std::fs;
use std::path::Path;

use crate::core::error::ModuleError;
use crate::core::text::clean;
use crate::modules::saturation::Fill;

#[derive(Debug, Clone, PartialEq)]
pub struct NetworkInterface {
    pub name: String,
    pub operstate: String,
    pub mac_address: Option<String>,
    pub mtu: Option<u32>,
    /// Link speed in Mbps, when the kernel can report it (absent for down
    /// or virtual interfaces — not a collection failure).
    pub speed_mbps: Option<i64>,
    pub carrier: Option<bool>,
    /// Number of active SR-IOV Virtual Functions on this interface, from
    /// `/sys/class/net/<iface>/device/sriov_numvfs` — `None` means the
    /// device isn't SR-IOV-capable at all (this file only exists on PCI
    /// devices that support it). `Some(0)` means SR-IOV-capable but no
    /// VFs currently provisioned. See analyze.rs for why this matters:
    /// on some NIC/driver combinations, traffic steered to a VF's own
    /// queue gets counted in the physical function's `rx_dropped`
    /// without indicating an actual link/cabling problem.
    pub sriov_vfs: Option<u32>,
    /// When this interface is itself an SR-IOV virtual function (VF): the
    /// physical function (PF) it belongs to, by the name of the PF's network
    /// interface, or by its PCI address when it has none. `None` for
    /// anything that is not a VF. A VF has no cable and no link of its own
    /// (it shares its PF's), and the NIC steers traffic to it that nothing on
    /// the host may consume, so its RX drops say less about a problem than
    /// a physical interface's do. See analyze.rs.
    pub vf_of: Option<String>,
    pub rx_bytes: u64,
    pub rx_packets: u64,
    pub rx_errors: u64,
    pub rx_dropped: u64,
    pub tx_bytes: u64,
    pub tx_packets: u64,
    pub tx_errors: u64,
    pub tx_dropped: u64,
}

#[derive(Debug, Clone, PartialEq, Default)]
pub struct RouteInfo {
    pub has_default_route: bool,
    pub default_gateway: Option<String>,
    pub default_route_interface: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Default)]
pub struct NetworkRawData {
    pub interfaces: Vec<NetworkInterface>,
    pub route: RouteInfo,
    pub dns_servers: Vec<String>,
    /// The firewall's table of tracked connections; `None` when the kernel
    /// has none (`nf_conntrack` is not loaded).
    pub conntrack: Option<Fill>,
    /// The bonded interfaces (`/proc/net/bonding`), none when the bonding
    /// driver is not loaded.
    pub bonds: Vec<super::bonding::Bond>,
    /// The physical cards and the number of times their link changed.
    pub links: super::carrier::Links,
}

/// Interface name prefixes that are never a real network path worth
/// diagnosing: loopback, and Intermediate Functional Block pseudo-devices
/// (used for traffic-shaping redirects, always present, never physically
/// meaningful). Deliberately narrower than Storage's exclusion list —
/// bridges, veth pairs, tunnels etc. can be genuinely relevant on a
/// server running containers or a VPN, so they're left in rather than
/// guessed away.
const EXCLUDED_INTERFACE_PREFIXES: &[&str] = &["lo", "ifb"];

fn is_real_interface(name: &str) -> bool {
    !EXCLUDED_INTERFACE_PREFIXES
        .iter()
        .any(|prefix| name == *prefix || name.starts_with(prefix))
}

/// Thin I/O wrapper: reads /sys/class/net per interface, /proc/net/dev,
/// /proc/net/route, and /etc/resolv.conf, delegating interpretation to
/// the pure parse functions below.
pub fn collect() -> Result<NetworkRawData, ModuleError> {
    let dev_text = fs::read_to_string("/proc/net/dev").map_err(|source| ModuleError::Io {
        path: "/proc/net/dev".to_string(),
        source,
    })?;
    let stats = parse_net_dev(&dev_text);

    let route_text = fs::read_to_string("/proc/net/route").map_err(|source| ModuleError::Io {
        path: "/proc/net/route".to_string(),
        source,
    })?;
    let route = parse_net_route(&route_text);

    let dns_servers = fs::read_to_string("/etc/resolv.conf")
        .map(|text| parse_resolv_conf(&text))
        .unwrap_or_default();

    let mut interfaces = Vec::new();
    let names = list_interface_names();
    for name in names {
        let sys_path = format!("/sys/class/net/{name}");
        let operstate = fs::read_to_string(format!("{sys_path}/operstate"))
            .map(|s| s.trim().to_string())
            .unwrap_or_else(|_| "unknown".to_string());
        let mac_address = fs::read_to_string(format!("{sys_path}/address"))
            .ok()
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty());
        let mtu = fs::read_to_string(format!("{sys_path}/mtu"))
            .ok()
            .and_then(|s| s.trim().parse().ok());
        let speed_mbps = fs::read_to_string(format!("{sys_path}/speed"))
            .ok()
            .and_then(|s| s.trim().parse::<i64>().ok())
            .filter(|v| *v >= 0); // -1 means "unknown", not a real speed
        let carrier = fs::read_to_string(format!("{sys_path}/carrier"))
            .ok()
            .and_then(|s| match s.trim() {
                "1" => Some(true),
                "0" => Some(false),
                _ => None,
            });
        let sriov_vfs = fs::read_to_string(format!("{sys_path}/device/sriov_numvfs"))
            .ok()
            .and_then(|s| s.trim().parse().ok());
        let vf_of = read_vf_parent(Path::new(&sys_path));

        let s = stats.get(&name).cloned().unwrap_or_default();

        interfaces.push(NetworkInterface {
            name,
            operstate,
            mac_address,
            mtu,
            speed_mbps,
            carrier,
            sriov_vfs,
            vf_of,
            rx_bytes: s.rx_bytes,
            rx_packets: s.rx_packets,
            rx_errors: s.rx_errors,
            rx_dropped: s.rx_dropped,
            tx_bytes: s.tx_bytes,
            tx_packets: s.tx_packets,
            tx_errors: s.tx_errors,
            tx_dropped: s.tx_dropped,
        });
    }

    Ok(NetworkRawData {
        interfaces,
        route,
        dns_servers,
        conntrack: super::conntrack::read(std::path::Path::new("/")),
        bonds: super::bonding::read(std::path::Path::new("/")),
        links: super::carrier::read(std::path::Path::new("/")),
    })
}

/// Longest physical-function name kept.
const MAX_PF_NAME: usize = 64;

/// The physical function an SR-IOV virtual function belongs to, from the
/// interface's directory under `/sys/class/net`. The PCI device of a VF has a
/// `physfn` link to its PF's device, which no other device has; the PF's own
/// interface is listed under that device's `net/`. The name of that interface
/// when there is one (the first, if there are several), else the PCI address
/// the link points to. `None` when the interface is not a VF.
pub fn read_vf_parent(iface_dir: &Path) -> Option<String> {
    let physfn = iface_dir.join("device/physfn");
    let target = fs::read_link(&physfn).ok()?;
    let address = target.file_name()?.to_str()?;
    let name = fs::read_dir(physfn.join("net"))
        .ok()
        .into_iter()
        .flatten()
        .flatten()
        .filter_map(|entry| entry.file_name().into_string().ok())
        .min()
        .unwrap_or_else(|| address.to_string());
    Some(clean(&name, MAX_PF_NAME))
}

fn list_interface_names() -> Vec<String> {
    let Ok(entries) = fs::read_dir("/sys/class/net") else {
        return Vec::new();
    };
    let mut names: Vec<String> = entries
        .flatten()
        .filter_map(|e| e.file_name().into_string().ok())
        .filter(|name| is_real_interface(name))
        .collect();
    names.sort();
    names
}

#[derive(Debug, Clone, Default)]
struct DevStats {
    rx_bytes: u64,
    rx_packets: u64,
    rx_errors: u64,
    rx_dropped: u64,
    tx_bytes: u64,
    tx_packets: u64,
    tx_errors: u64,
    tx_dropped: u64,
}

/// Parse `/proc/net/dev` (two header lines, then one row per interface:
/// "name: rx_bytes rx_packets rx_errs rx_drop ... tx_bytes tx_packets
/// tx_errs tx_drop ..."). Pure function, tested against fixture text.
fn parse_net_dev(text: &str) -> HashMap<String, DevStats> {
    let mut map = HashMap::new();
    for line in text.lines().skip(2) {
        let Some((name, rest)) = line.split_once(':') else {
            continue;
        };
        let name = name.trim().to_string();
        let fields: Vec<u64> = rest
            .split_whitespace()
            .map(|f| f.parse::<u64>().unwrap_or(0))
            .collect();
        if fields.len() < 16 {
            continue; // malformed/short line -- skip defensively
        }
        map.insert(
            name,
            DevStats {
                rx_bytes: fields[0],
                rx_packets: fields[1],
                rx_errors: fields[2],
                rx_dropped: fields[3],
                tx_bytes: fields[8],
                tx_packets: fields[9],
                tx_errors: fields[10],
                tx_dropped: fields[11],
            },
        );
    }
    map
}

/// Parse `/proc/net/route`: one header line, then one row per route.
/// Destination "00000000" is the default route (0.0.0.0/0). Pure
/// function, tested against fixture text.
fn parse_net_route(text: &str) -> RouteInfo {
    for line in text.lines().skip(1) {
        let fields: Vec<&str> = line.split_whitespace().collect();
        if fields.len() < 3 {
            continue;
        }
        let (iface, dest, gateway) = (fields[0], fields[1], fields[2]);
        if dest == "00000000" {
            return RouteInfo {
                has_default_route: true,
                default_gateway: decode_hex_ipv4(gateway),
                default_route_interface: Some(iface.to_string()),
            };
        }
    }
    RouteInfo::default()
}

/// Decode the 8-hex-digit, byte-reversed IPv4 addresses `/proc/net/route`
/// uses (e.g. "010200C0" -> 192.0.2.1). Kernel writes the 32-bit address
/// value as hex text in host (little-endian) byte order; conventional
/// dotted-decimal reads bytes in network (big-endian) order, hence the
/// reversal.
fn decode_hex_ipv4(hex: &str) -> Option<String> {
    if hex.len() != 8 {
        return None;
    }
    let mut bytes = [0u8; 4];
    for i in 0..4 {
        bytes[i] = u8::from_str_radix(&hex[i * 2..i * 2 + 2], 16).ok()?;
    }
    Some(format!(
        "{}.{}.{}.{}",
        bytes[3], bytes[2], bytes[1], bytes[0]
    ))
}

/// Parse `nameserver` lines out of `/etc/resolv.conf` text.
fn parse_resolv_conf(text: &str) -> Vec<String> {
    text.lines()
        .filter_map(|l| l.trim().strip_prefix("nameserver"))
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn filters_loopback_and_ifb() {
        assert!(!is_real_interface("lo"));
        assert!(!is_real_interface("ifb0"));
        assert!(!is_real_interface("ifb1"));
        assert!(is_real_interface("eth0"));
        assert!(is_real_interface("wlan0"));
        assert!(is_real_interface("docker0"));
        assert!(is_real_interface("veth1234"));
    }

    const FIXTURE_NET_DEV: &str = "\
Inter-|   Receive                                                |  Transmit
 face |bytes    packets errs drop fifo frame compressed multicast|bytes    packets errs drop fifo colls carrier compressed
    lo:       0       0    0    0    0     0          0         0        0       0    0    0    0     0       0          0
  eth0:   29783      99    0   13    0     0          0         0    18978      89    0    0    0     0       0          0
";

    #[test]
    fn parses_net_dev_stats() {
        let stats = parse_net_dev(FIXTURE_NET_DEV);
        let eth0 = stats.get("eth0").unwrap();
        assert_eq!(eth0.rx_bytes, 29783);
        assert_eq!(eth0.rx_packets, 99);
        assert_eq!(eth0.rx_dropped, 13);
        assert_eq!(eth0.tx_packets, 89);
        assert_eq!(eth0.tx_errors, 0);
    }

    const FIXTURE_NET_ROUTE: &str = "\
Iface\tDestination\tGateway \tFlags\tRefCnt\tUse\tMetric\tMask\t\tMTU\tWindow\tIRTT
eth0\t00000000\t010200C0\t0003\t0\t0\t0\t00000000\t0\t0\t0
eth0\t000200C0\t00000000\t0001\t0\t0\t0\t00FFFFFF\t0\t0\t0
";

    #[test]
    fn parses_default_route_and_decodes_gateway() {
        let route = parse_net_route(FIXTURE_NET_ROUTE);
        assert!(route.has_default_route);
        assert_eq!(route.default_gateway.as_deref(), Some("192.0.2.1"));
        assert_eq!(route.default_route_interface.as_deref(), Some("eth0"));
    }

    #[test]
    fn no_default_route_when_absent() {
        let text = "Iface\tDestination\tGateway\nEth0\t000200C0\t00000000\n";
        let route = parse_net_route(text);
        assert!(!route.has_default_route);
        assert!(route.default_gateway.is_none());
    }

    #[test]
    fn decodes_hex_ipv4_correctly() {
        assert_eq!(decode_hex_ipv4("010200C0"), Some("192.0.2.1".to_string()));
        assert_eq!(decode_hex_ipv4("00000000"), Some("0.0.0.0".to_string()));
    }

    #[test]
    fn parses_resolv_conf_nameservers() {
        let text = "nameserver 8.8.8.8\nnameserver 1.1.1.1\nsearch example.com\n";
        assert_eq!(
            parse_resolv_conf(text),
            vec!["8.8.8.8".to_string(), "1.1.1.1".to_string()]
        );
    }

    #[test]
    fn empty_resolv_conf_is_empty_list() {
        assert!(parse_resolv_conf("search example.com\n").is_empty());
    }

    // --- SR-IOV virtual functions -----------------------------------------

    use std::os::unix::fs::symlink;
    use std::path::PathBuf;

    /// What `/sys` looks like for a VF: `class/net/<vf>/device` is a link to
    /// the VF's PCI device, which has a relative `physfn` link to the PF's
    /// PCI device, and the PF's interfaces are under that device's `net/`.
    fn vf_tree(case: &str, pf_interfaces: &[&str]) -> (PathBuf, PathBuf) {
        let root = std::env::temp_dir().join(format!(
            "linuxdoctor-network-vf-{case}-{}",
            std::process::id()
        ));
        let _ = fs::remove_dir_all(&root);
        let devices = root.join("devices");
        fs::create_dir_all(devices.join("0000:06:00.1")).unwrap();
        fs::create_dir_all(devices.join("0000:06:00.0/net")).unwrap();
        for name in pf_interfaces {
            fs::create_dir_all(devices.join("0000:06:00.0/net").join(name)).unwrap();
        }
        symlink("../0000:06:00.0", devices.join("0000:06:00.1/physfn")).unwrap();
        let vf = root.join("class/net/enp6s0v1");
        fs::create_dir_all(&vf).unwrap();
        symlink(devices.join("0000:06:00.1"), vf.join("device")).unwrap();
        (root, vf)
    }

    #[test]
    fn a_virtual_function_names_its_physical_function() {
        let (root, vf) = vf_tree("named", &["enp6s0"]);
        assert_eq!(read_vf_parent(&vf).as_deref(), Some("enp6s0"));
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn a_physical_function_without_an_interface_is_named_by_its_pci_address() {
        // For example one that is bound to vfio-pci, or whose driver is not loaded.
        let (root, vf) = vf_tree("address", &[]);
        assert_eq!(read_vf_parent(&vf).as_deref(), Some("0000:06:00.0"));
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn with_several_interfaces_the_first_by_name_is_used() {
        let (root, vf) = vf_tree("several", &["enp6s0f1", "enp6s0f0", "enp6s0f2"]);
        assert_eq!(read_vf_parent(&vf).as_deref(), Some("enp6s0f0"));
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn a_name_from_the_machine_is_cleaned() {
        let (root, vf) = vf_tree("hostile", &["pf\u{1b}[31m"]);
        assert_eq!(read_vf_parent(&vf).as_deref(), Some("pf?[31m"));
        fs::remove_dir_all(root).unwrap();

        // 64 characters are kept whole; more are cut, with a mark.
        let exact = "p".repeat(64);
        let (root, vf) = vf_tree("exact", &[exact.as_str()]);
        assert_eq!(read_vf_parent(&vf), Some(exact));
        fs::remove_dir_all(root).unwrap();

        let long = "p".repeat(65);
        let (root, vf) = vf_tree("long", &[long.as_str()]);
        assert_eq!(read_vf_parent(&vf), Some(format!("{}…", "p".repeat(64))));
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn a_physical_card_and_a_virtual_interface_are_not_virtual_functions() {
        let (root, _) = vf_tree("plain", &["enp6s0"]);
        // The PF itself: a PCI device, but with no `physfn`.
        let pf = root.join("class/net/enp6s0");
        fs::create_dir_all(&pf).unwrap();
        symlink(root.join("devices/0000:06:00.0"), pf.join("device")).unwrap();
        assert_eq!(read_vf_parent(&pf), None);
        // A bridge or a tunnel: no `device` at all.
        let bridge = root.join("class/net/br0");
        fs::create_dir_all(&bridge).unwrap();
        assert_eq!(read_vf_parent(&bridge), None);
        // An interface that does not exist.
        assert_eq!(read_vf_parent(&root.join("class/net/missing")), None);
        fs::remove_dir_all(root).unwrap();
    }
}
