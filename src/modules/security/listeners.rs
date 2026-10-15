// SPDX-License-Identifier: GPL-3.0-only

//! Listening network services: what accepts connections, on which
//! addresses, and which of them deserve a second look.
//!
//! Pure logic only: parsing the text of `/proc/net/{tcp,tcp6,udp,udp6}`,
//! grouping sockets into services, a small catalogue of services that
//! should rarely be reachable from a network, and the findings built from
//! both. The reading of the files lives in `collect.rs`.

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use crate::models::{Category, Confidence, Finding, Severity};
use crate::modules::recommend::Steps;

use super::firewall::{FirewallKind, FirewallStatus};

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Proto {
    Tcp,
    Udp,
}

impl Proto {
    pub fn label(self) -> &'static str {
        match self {
            Proto::Tcp => "tcp",
            Proto::Udp => "udp",
        }
    }
}

/// How far a bound address reaches. The order matters: a service bound to
/// several addresses is as exposed as its most exposed one.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Exposure {
    /// 127.0.0.0/8 or ::1 — only programs on this machine can connect.
    Loopback,
    /// One specific (non-loopback) address, typically one network interface.
    Specific,
    /// 0.0.0.0 or :: — every interface of the machine.
    Wildcard,
}

impl Exposure {
    pub fn reachable_from_network(self) -> bool {
        self != Exposure::Loopback
    }
}

/// One socket as the kernel lists it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Socket {
    pub proto: Proto,
    pub addr: IpAddr,
    pub port: u16,
    pub uid: u32,
    pub inode: u64,
}

impl Socket {
    pub fn exposure(&self) -> Exposure {
        exposure_of(&self.addr)
    }
}

pub fn exposure_of(addr: &IpAddr) -> Exposure {
    if addr.is_unspecified() {
        return Exposure::Wildcard;
    }
    let loopback = match addr {
        IpAddr::V4(v4) => v4.is_loopback(),
        IpAddr::V6(v6) => {
            v6.is_loopback() || v6.to_ipv4_mapped().is_some_and(|v4| v4.is_loopback())
        }
    };
    if loopback {
        Exposure::Loopback
    } else {
        Exposure::Specific
    }
}

/// The program that owns a socket, when it could be found.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Owner {
    pub pid: u32,
    pub name: String,
}

// ---------------------------------------------------------------------------
// Parsing /proc/net/*
// ---------------------------------------------------------------------------

/// Parses the text of `/proc/net/tcp`, `tcp6`, `udp` or `udp6`.
///
/// TCP: only sockets in the LISTEN state (`0A`). UDP has no listening
/// state: an unconnected socket (state `07`, no remote address) that is
/// bound to a port is what a server looks like, so those are kept — the
/// caller drops the ephemeral ports that ordinary clients use.
pub fn parse_proc_net(text: &str, proto: Proto) -> Vec<Socket> {
    let mut sockets = Vec::new();
    for line in text.lines().skip(1) {
        let fields: Vec<&str> = line.split_whitespace().collect();
        if fields.len() < 10 {
            continue;
        }
        let state = fields[3];
        let wanted = match proto {
            Proto::Tcp => state == "0A",
            Proto::Udp => state == "07",
        };
        if !wanted {
            continue;
        }
        let Some((addr, port)) = parse_endpoint(fields[1]) else {
            continue;
        };
        if proto == Proto::Udp {
            // A connected UDP socket is a client talking to someone.
            match parse_endpoint(fields[2]) {
                Some((remote, remote_port)) if remote.is_unspecified() && remote_port == 0 => {}
                _ => continue,
            }
        }
        let uid = fields[7].parse().unwrap_or(0);
        let inode = fields[9].parse().unwrap_or(0);
        sockets.push(Socket {
            proto,
            addr,
            port,
            uid,
            inode,
        });
    }
    sockets
}

/// "0100007F:0035" (IPv4) or "000080FE00000000...:0035" (IPv6).
///
/// The kernel prints each 32-bit word of the address as a host-order
/// integer, so on a little-endian machine the bytes come out reversed.
/// Reading the integer back and taking its in-memory bytes undoes that on
/// any byte order.
fn parse_endpoint(text: &str) -> Option<(IpAddr, u16)> {
    let (addr_hex, port_hex) = text.split_once(':')?;
    let port = u16::from_str_radix(port_hex, 16).ok()?;
    let addr = match addr_hex.len() {
        8 => {
            let word = u32::from_str_radix(addr_hex, 16).ok()?;
            IpAddr::V4(Ipv4Addr::from(word.to_ne_bytes()))
        }
        32 => {
            let mut bytes = [0u8; 16];
            for (i, chunk) in bytes.chunks_mut(4).enumerate() {
                let word = u32::from_str_radix(&addr_hex[i * 8..i * 8 + 8], 16).ok()?;
                chunk.copy_from_slice(&word.to_ne_bytes());
            }
            IpAddr::V6(Ipv6Addr::from(bytes))
        }
        _ => return None,
    };
    Some((addr, port))
}

/// Parses `/proc/sys/net/ipv4/ip_local_port_range` ("32768\t60999").
pub fn parse_port_range(text: &str) -> Option<(u16, u16)> {
    let mut parts = text.split_whitespace();
    let low = parts.next()?.parse().ok()?;
    let high = parts.next()?.parse().ok()?;
    Some((low, high))
}

// ---------------------------------------------------------------------------
// Services
// ---------------------------------------------------------------------------

/// All the sockets of one program on one port, seen as a single service
/// (a daemon that listens on both 0.0.0.0 and :: is one service).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Endpoint {
    pub proto: Proto,
    pub port: u16,
    pub binds: Vec<IpAddr>,
    pub exposure: Exposure,
    pub owner: Option<Owner>,
    pub uid: u32,
}

impl Endpoint {
    /// "all interfaces", "192.168.1.5", "127.0.0.53, ::1"...
    pub fn bind_label(&self) -> String {
        if self.exposure == Exposure::Wildcard {
            return "all interfaces".to_string();
        }
        let shown: Vec<String> = self.binds.iter().take(2).map(|a| a.to_string()).collect();
        let extra = self.binds.len().saturating_sub(2);
        if extra > 0 {
            format!("{} (+{extra})", shown.join(", "))
        } else {
            shown.join(", ")
        }
    }

    pub fn process_label(&self) -> String {
        match &self.owner {
            Some(o) => format!("{} (pid {})", o.name, o.pid),
            None => "-".to_string(),
        }
    }

    pub fn key(&self) -> String {
        format!("{}/{}", self.port, self.proto.label())
    }
}

/// Groups sockets into services. UDP sockets on the ephemeral port range
/// are dropped: those are the source ports of outgoing queries, not
/// servers.
pub fn endpoints(
    sockets: &[Socket],
    owners: &HashMap<u64, Owner>,
    ephemeral: (u16, u16),
) -> Vec<Endpoint> {
    type Key = (Proto, u16, Option<String>);
    let mut grouped: BTreeMap<Key, Endpoint> = BTreeMap::new();
    for s in sockets {
        if s.proto == Proto::Udp && (ephemeral.0..=ephemeral.1).contains(&s.port) {
            continue;
        }
        let owner = owners.get(&s.inode).cloned();
        let key = (s.proto, s.port, owner.as_ref().map(|o| o.name.clone()));
        let entry = grouped.entry(key).or_insert_with(|| Endpoint {
            proto: s.proto,
            port: s.port,
            binds: Vec::new(),
            exposure: Exposure::Loopback,
            owner,
            uid: s.uid,
        });
        if !entry.binds.contains(&s.addr) {
            entry.binds.push(s.addr);
        }
        entry.exposure = entry.exposure.max(s.exposure());
    }
    let mut list: Vec<Endpoint> = grouped.into_values().collect();
    for e in &mut list {
        e.binds.sort();
    }
    list.sort_by(|a, b| {
        b.exposure
            .cmp(&a.exposure)
            .then(a.port.cmp(&b.port))
            .then(a.proto.cmp(&b.proto))
    });
    list
}

// ---------------------------------------------------------------------------
// Catalogue of services that rarely belong on a network
// ---------------------------------------------------------------------------

/// A kind of service worth flagging when it accepts connections from the
/// network. Deliberately short: every entry is something a careful
/// administrator would want to have chosen on purpose.
#[derive(Debug, PartialEq, Eq)]
pub struct ServiceRisk {
    pub name: &'static str,
    pub proto: Proto,
    /// Inclusive port range.
    pub ports: (u16, u16),
    pub severity: Severity,
    pub why: &'static str,
    /// How to make this particular program listen on the loopback address
    /// only, where that is a setting of its own.
    pub bind_hint: &'static str,
}

const CLEARTEXT_LOGIN: &str = "Logins, passwords and everything typed travel unencrypted, and \
     can be read or altered by anyone on the path.";
const DATA_STORE: &str = "Data stores are normally reached by one application server, not by \
     the whole network; many ship without authentication or with a weak default, and exposed \
     ones are found and emptied by automated scans within hours.";

pub const RISKS: &[ServiceRisk] = &[
    ServiceRisk {
        name: "Telnet",
        proto: Proto::Tcp,
        ports: (23, 23),
        severity: Severity::Error,
        why: CLEARTEXT_LOGIN,
        bind_hint: "Replace it with SSH: stop and disable the telnet service.",
    },
    ServiceRisk {
        name: "rexec",
        proto: Proto::Tcp,
        ports: (512, 512),
        severity: Severity::Error,
        why: "The r-services authenticate by trusting the client's address and send everything \
              unencrypted.",
        bind_hint: "Replace it with SSH: stop and disable the r-services.",
    },
    ServiceRisk {
        name: "rlogin",
        proto: Proto::Tcp,
        ports: (513, 513),
        severity: Severity::Error,
        why: "The r-services authenticate by trusting the client's address and send everything \
              unencrypted.",
        bind_hint: "Replace it with SSH: stop and disable the r-services.",
    },
    ServiceRisk {
        name: "Docker API (unencrypted)",
        proto: Proto::Tcp,
        ports: (2375, 2375),
        severity: Severity::Error,
        why: "The Docker API on port 2375 has no authentication and no encryption: anyone who \
              can connect can start a container that mounts the whole disk, which is root on \
              the host.",
        bind_hint: "Remove the tcp://0.0.0.0:2375 entry from the daemon's `hosts` setting \
                    (/etc/docker/daemon.json or its systemd unit); use the local socket, or \
                    TLS on port 2376 if remote access is needed.",
    },
    ServiceRisk {
        name: "FTP",
        proto: Proto::Tcp,
        ports: (21, 21),
        severity: Severity::Warning,
        why: "Plain FTP sends passwords and files unencrypted.",
        bind_hint: "Use SFTP (part of SSH) or FTPS instead.",
    },
    ServiceRisk {
        name: "TFTP",
        proto: Proto::Udp,
        ports: (69, 69),
        severity: Severity::Warning,
        why: "TFTP has no authentication at all: any file the server can read is readable by \
              any client.",
        bind_hint: "Restrict the TFTP server to the provisioning network, or stop it when no \
                    machine is being installed.",
    },
    ServiceRisk {
        name: "SNMP",
        proto: Proto::Udp,
        ports: (161, 161),
        severity: Severity::Warning,
        why: "SNMP v1/v2c is protected only by a community string sent in clear text, often \
              left at its default; it also reveals a lot about the machine.",
        bind_hint: "In snmpd.conf, set `agentaddress 127.0.0.1` or restrict it to the \
                    monitoring network.",
    },
    ServiceRisk {
        name: "VNC",
        proto: Proto::Tcp,
        ports: (5900, 5909),
        severity: Severity::Warning,
        why: "VNC gives full control of a desktop and is weakly protected (a short password, \
              often no encryption).",
        bind_hint: "Bind it to localhost and reach it through an SSH tunnel \
                    (`ssh -L 5900:localhost:5900 host`).",
    },
    ServiceRisk {
        name: "X11 over TCP",
        proto: Proto::Tcp,
        ports: (6000, 6009),
        severity: Severity::Warning,
        why: "A graphical display reachable from the network lets others read the keyboard \
              and screen of whoever uses it, as soon as access control is lax.",
        bind_hint: "Start the X server with `-nolisten tcp` (this is the default on modern \
                    systems); use `ssh -X` for remote windows.",
    },
    ServiceRisk {
        name: "Redis",
        proto: Proto::Tcp,
        ports: (6379, 6379),
        severity: Severity::Warning,
        why: DATA_STORE,
        bind_hint: "In redis.conf: `bind 127.0.0.1 -::1`, and keep `protected-mode yes`.",
    },
    ServiceRisk {
        name: "Memcached",
        proto: Proto::Tcp,
        ports: (11211, 11211),
        severity: Severity::Warning,
        why: "Memcached has no authentication, and exposed servers are abused for traffic \
              amplification attacks as well as data theft.",
        bind_hint: "In memcached.conf: `-l 127.0.0.1` (and `-U 0` to turn UDP off).",
    },
    ServiceRisk {
        name: "Memcached (UDP)",
        proto: Proto::Udp,
        ports: (11211, 11211),
        severity: Severity::Warning,
        why: "Memcached over UDP is the classic source of very large traffic amplification \
              attacks.",
        bind_hint: "In memcached.conf: `-U 0` to turn UDP off, and `-l 127.0.0.1`.",
    },
    ServiceRisk {
        name: "MongoDB",
        proto: Proto::Tcp,
        ports: (27017, 27017),
        severity: Severity::Warning,
        why: DATA_STORE,
        bind_hint: "In mongod.conf: `net.bindIp: 127.0.0.1`, and enable authentication.",
    },
    ServiceRisk {
        name: "Elasticsearch",
        proto: Proto::Tcp,
        ports: (9200, 9200),
        severity: Severity::Warning,
        why: DATA_STORE,
        bind_hint: "In elasticsearch.yml: `network.host: 127.0.0.1`.",
    },
    ServiceRisk {
        name: "CouchDB",
        proto: Proto::Tcp,
        ports: (5984, 5984),
        severity: Severity::Warning,
        why: DATA_STORE,
        bind_hint: "In local.ini: `[chttpd] bind_address = 127.0.0.1`.",
    },
    ServiceRisk {
        name: "MySQL / MariaDB",
        proto: Proto::Tcp,
        ports: (3306, 3306),
        severity: Severity::Warning,
        why: DATA_STORE,
        bind_hint: "In the server configuration: `bind-address = 127.0.0.1`.",
    },
    ServiceRisk {
        name: "PostgreSQL",
        proto: Proto::Tcp,
        ports: (5432, 5432),
        severity: Severity::Warning,
        why: DATA_STORE,
        bind_hint: "In postgresql.conf: `listen_addresses = 'localhost'`, and limit who may \
                    connect in pg_hba.conf.",
    },
    ServiceRisk {
        name: "Microsoft SQL Server",
        proto: Proto::Tcp,
        ports: (1433, 1433),
        severity: Severity::Warning,
        why: DATA_STORE,
        bind_hint: "Use `mssql-conf set network.ipaddress 127.0.0.1` if only local programs \
                    need it.",
    },
    ServiceRisk {
        name: "ZooKeeper",
        proto: Proto::Tcp,
        ports: (2181, 2181),
        severity: Severity::Warning,
        why: DATA_STORE,
        bind_hint: "In zoo.cfg: `clientPortAddress=127.0.0.1`.",
    },
];

pub fn risk_for(proto: Proto, port: u16) -> Option<&'static ServiceRisk> {
    RISKS
        .iter()
        .find(|r| r.proto == proto && (r.ports.0..=r.ports.1).contains(&port))
}

// ---------------------------------------------------------------------------
// Findings
// ---------------------------------------------------------------------------

/// What the listener analysis found, for the other topics and the
/// overview.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ListenerSummary {
    pub tcp_services: usize,
    pub udp_services: usize,
    pub reachable: usize,
    pub loopback_only: usize,
    /// TCP services reachable from the network other than SSH — what a
    /// firewall would have to hold back. SSH is left out: a machine whose
    /// only open door is SSH is the normal case, not a reason to warn.
    pub reachable_tcp: Vec<u16>,
    /// Ports where the SSH server is reachable from the network.
    pub ssh_ports: Vec<u16>,
    pub unknown_owners: usize,
    pub exposed_risks: usize,
}

/// The TCP ports on which a program with this exact name (the kernel's
/// `comm`) accepts connections from the network, or `None` if there is no
/// such service.
pub fn is_reachable_by(endpoints: &[Endpoint], program: &str) -> Option<Vec<u16>> {
    let ports: BTreeSet<u16> = endpoints
        .iter()
        .filter(|e| e.proto == Proto::Tcp && e.exposure.reachable_from_network())
        .filter(|e| e.owner.as_ref().is_some_and(|o| o.name == program))
        .map(|e| e.port)
        .collect();
    if ports.is_empty() {
        None
    } else {
        Some(ports.into_iter().collect())
    }
}

pub fn summarize(endpoints: &[Endpoint]) -> ListenerSummary {
    let mut s = ListenerSummary::default();
    for e in endpoints {
        match e.proto {
            Proto::Tcp => s.tcp_services += 1,
            Proto::Udp => s.udp_services += 1,
        }
        if e.exposure.reachable_from_network() {
            s.reachable += 1;
            if e.proto == Proto::Tcp {
                let is_sshd = e.owner.as_ref().is_some_and(|o| o.name == "sshd");
                if is_sshd || (e.owner.is_none() && e.port == 22) {
                    s.ssh_ports.push(e.port);
                } else {
                    s.reachable_tcp.push(e.port);
                }
            }
            if e.owner.is_none() {
                s.unknown_owners += 1;
            }
            if risk_for(e.proto, e.port).is_some() {
                s.exposed_risks += 1;
            }
        } else {
            s.loopback_only += 1;
        }
    }
    s.reachable_tcp.sort_unstable();
    s.reachable_tcp.dedup();
    s.ssh_ports.sort_unstable();
    s.ssh_ports.dedup();
    s
}

const MAX_TABLE_ROWS: usize = 40;

/// SEC002 — the full list of listening services. Always Info: it states
/// what is there, the verdicts are SEC003 (risky services) and SEC004
/// (firewall).
pub fn overview_finding(
    endpoints: &[Endpoint],
    summary: &ListenerSummary,
    is_root: bool,
) -> Finding {
    let mut builder = Finding::builder(
        "SEC002",
        "Listening Network Services",
        Category::Security,
        Severity::Info,
        Confidence::direct_observation(),
    )
    .evidence("tcp_services", summary.tcp_services.to_string())
    .evidence("udp_services", summary.udp_services.to_string())
    .evidence("reachable_from_network", summary.reachable.to_string())
    .evidence("loopback_only", summary.loopback_only.to_string());

    let owner_note = if summary.unknown_owners == 0 {
        "all identified".to_string()
    } else if is_root {
        format!("{} not identified", summary.unknown_owners)
    } else {
        format!(
            "{} not identified (run as root to see other users' programs)",
            summary.unknown_owners
        )
    };
    builder = builder.evidence("programs", owner_note);

    let mut paragraphs = Vec::new();
    if endpoints.is_empty() {
        paragraphs
            .push("No program is listening for network connections on this machine.".to_string());
    } else {
        paragraphs.push(format!(
            "{} of {} listening services accept connections from outside this machine (any \
             address other than loopback); the rest can only be reached by programs running \
             here. Whether an outside machine can really connect also depends on the firewall, \
             see the firewall check.",
            summary.reachable,
            endpoints.len()
        ));
        let mut table = String::new();
        table.push_str(&format!(
            "  {:<5} {:<6} {:<9} {:<28} {}\n",
            "PROTO", "PORT", "REACHABLE", "BOUND TO", "PROGRAM"
        ));
        for e in endpoints.iter().take(MAX_TABLE_ROWS) {
            table.push_str(&format!(
                "  {:<5} {:<6} {:<9} {:<28} {}\n",
                e.proto.label(),
                e.port,
                if e.exposure.reachable_from_network() {
                    "yes"
                } else {
                    "local"
                },
                e.bind_label(),
                e.process_label()
            ));
        }
        if endpoints.len() > MAX_TABLE_ROWS {
            table.push_str(&format!(
                "  ... and {} more\n",
                endpoints.len() - MAX_TABLE_ROWS
            ));
        }
        paragraphs.push(table.trim_end().to_string());
    }
    if summary.unknown_owners > 0 {
        paragraphs.push(if is_root {
            "Some rows show no program even for root: the socket belongs to a process in \
             another PID namespace (a container sharing this network), or the process ended \
             after the list was read."
                .to_string()
        } else {
            "Linux only lets root see which program owns another user's socket, so some rows \
             show no program. Run LinuxDoctor with sudo to fill them in."
                .to_string()
        });
    }
    builder.explanation(paragraphs.join("\n\n")).build()
}

/// SEC003 — one finding per risky service that is reachable from the
/// network. The severity is the service's own; the confidence says how
/// sure we are that it is really reachable, which depends on the
/// firewall.
pub fn risk_findings(endpoints: &[Endpoint], firewall: &FirewallStatus) -> Vec<Finding> {
    let mut findings = Vec::new();
    for e in endpoints {
        if !e.exposure.reachable_from_network() {
            continue;
        }
        let Some(risk) = risk_for(e.proto, e.port) else {
            continue;
        };

        let (confidence, firewall_note) = match firewall {
            FirewallStatus::NotDetected { verified: true } => (
                Confidence::strong_indication(89),
                "No firewall was found on this machine, so the service is probably open to \
                 every machine that can route to it.",
            ),
            FirewallStatus::NotDetected { verified: false } | FirewallStatus::Unknown => (
                Confidence::strong_indication(80),
                "No firewall was detected (run as root for a certain answer), so the service \
                 is probably open to every machine that can route to it.",
            ),
            FirewallStatus::Active { .. } => (
                Confidence::weak_indication(70),
                "A firewall is active, so this port may already be filtered; LinuxDoctor does \
                 not evaluate individual firewall rules. Check that this port is blocked from \
                 the networks you do not trust.",
            ),
        };

        let proto_flag = match e.proto {
            Proto::Tcp => "-ltnp",
            Proto::Udp => "-lunp",
        };
        let ss = format!("sudo ss {proto_flag} 'sport = :{}'", e.port);

        let mut steps = Steps::new()
            .step("Confirm which program is listening:", &[&ss])
            .step(
                format!(
                    "If nothing needs to reach it from the network, stop it listening there. {}",
                    risk.bind_hint
                ),
                &[],
            );
        steps = steps.step_owned(
            "If it must stay reachable, allow only the machines that need it:",
            firewall_rule_commands(firewall, e),
        );

        let mut builder = Finding::builder(
            "SEC003",
            format!("Exposed Service \u{2014} {} ({})", risk.name, e.key()),
            Category::Security,
            risk.severity,
            confidence,
        )
        .evidence("port", e.port.to_string())
        .evidence("protocol", e.proto.label())
        .evidence("bound_to", e.bind_label())
        .evidence("program", e.process_label());
        if e.owner.is_none() {
            builder = builder.evidence("program_note", "not visible without root");
        }
        findings.push(
            builder
                .explanation(format!(
                    "{} is accepting connections on {} ({}). {} {}",
                    risk.name,
                    e.key(),
                    e.bind_label(),
                    risk.why,
                    firewall_note
                ))
                .recommendation(steps.build())
                .build(),
        );
    }
    findings
}

/// Commands that let one trusted network reach a port, for the firewall
/// that is in use. With no known firewall the step is prose only.
fn firewall_rule_commands(firewall: &FirewallStatus, e: &Endpoint) -> Vec<String> {
    let proto = e.proto.label();
    match firewall.kind() {
        Some(FirewallKind::Ufw) => vec![format!(
            "sudo ufw allow from 192.168.1.0/24 to any port {} proto {proto}   # use your own network",
            e.port
        )],
        Some(FirewallKind::Firewalld) => vec![
            format!(
                "sudo firewall-cmd --permanent --add-rich-rule='rule family=\"ipv4\" source address=\"192.168.1.0/24\" port port=\"{}\" protocol=\"{proto}\" accept'   # use your own network",
                e.port
            ),
            "sudo firewall-cmd --reload".to_string(),
        ],
        _ => Vec::new(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const TCP: &str = "\
  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
   0: 0100007F:B255 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 779 2 00000000e8ca4bed 100 0 0 10 0
   1: 00000000:0016 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 1176 1 00000000e189d873 100 0 0 10 0
   2: 0501A8C0:18EB 00000000:0000 0A 00000000:00000000 00:00000000 00000000   999        0 727 1 0000000030cb7182 100 0 0 10 0
   3: 0501A8C0:D3A2 0801A8C0:01BB 01 00000000:00000000 00:00000000 00000000  1000        0 5555 1 0000000000000000 100 0 0 10 0
";

    const TCP6: &str = "\
  sl  local_address                         remote_address                        st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
   0: 00000000000000000000000000000000:0016 00000000000000000000000000000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 1180 1 0000000000000000 100 0 0 10 0
   1: 00000000000000000000000001000000:1F90 00000000000000000000000000000000:0000 0A 00000000:00000000 00:00000000 00000000  1000        0 2001 1 0000000000000000 100 0 0 10 0
   2: 0000000000000000FFFF00000100007F:0CEA 00000000000000000000000000000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 2002 1 0000000000000000 100 0 0 10 0
   3: 000080FE00000000FF0A7F26E50A0F20:0050 00000000000000000000000000000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 2003 1 0000000000000000 100 0 0 10 0
";

    const UDP: &str = "\
   sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode ref pointer drops
  100: 00000000:0044 00000000:0000 07 00000000:00000000 00:00000000 00000000     0        0 3001 2 0000000000000000 0
  101: 0100007F:0035 00000000:0000 07 00000000:00000000 00:00000000 00000000   101        0 3002 2 0000000000000000 0
  102: 00000000:A1B2 00000000:0000 07 00000000:00000000 00:00000000 00000000  1000        0 3003 2 0000000000000000 0
  103: 0501A8C0:9999 0801A8C0:0035 01 00000000:00000000 00:00000000 00000000  1000        0 3004 2 0000000000000000 0
";

    fn owner(pid: u32, name: &str) -> Owner {
        Owner {
            pid,
            name: name.into(),
        }
    }

    #[test]
    fn tcp_keeps_only_listening_sockets_and_decodes_addresses() {
        let s = parse_proc_net(TCP, Proto::Tcp);
        assert_eq!(s.len(), 3, "the ESTABLISHED line (01) is not a listener");
        assert_eq!(s[0].addr, IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)));
        assert_eq!(s[0].port, 0xB255);
        assert_eq!(s[1].addr, IpAddr::V4(Ipv4Addr::UNSPECIFIED));
        assert_eq!(s[1].port, 22);
        assert_eq!(s[2].addr, IpAddr::V4(Ipv4Addr::new(192, 168, 1, 5)));
        assert_eq!(s[2].port, 0x18EB);
        assert_eq!(s[2].uid, 999);
        assert_eq!(s[2].inode, 727);
    }

    #[test]
    fn tcp6_decodes_wildcard_loopback_mapped_and_global_addresses() {
        let s = parse_proc_net(TCP6, Proto::Tcp);
        assert_eq!(s.len(), 4);
        assert_eq!(s[0].exposure(), Exposure::Wildcard);
        assert_eq!(s[1].addr, IpAddr::V6(Ipv6Addr::LOCALHOST));
        assert_eq!(s[1].exposure(), Exposure::Loopback);
        assert_eq!(s[2].exposure(), Exposure::Loopback, "::ffff:127.0.0.1");
        assert_eq!(s[3].port, 80);
        assert_eq!(s[3].exposure(), Exposure::Specific);
        assert_eq!(s[3].addr.to_string(), "fe80::267f:aff:200f:ae5");
    }

    #[test]
    fn udp_keeps_unconnected_sockets_only() {
        let s = parse_proc_net(UDP, Proto::Udp);
        let ports: Vec<u16> = s.iter().map(|x| x.port).collect();
        assert_eq!(ports, vec![68, 53, 0xA1B2]);
    }

    #[test]
    fn malformed_lines_are_skipped_not_fatal() {
        let text = "header\n   0: garbage\n   1: 0100007F:0035 00000000:0000 0A 0 0 1\n   2: ZZZZ:0035 00000000:0000 0A 0 0 0 0 0 1\n\n";
        assert!(parse_proc_net(text, Proto::Tcp).is_empty());
        assert!(parse_proc_net("", Proto::Tcp).is_empty());
    }

    #[test]
    fn port_range_parses_and_rejects_junk() {
        assert_eq!(parse_port_range("32768\t60999\n"), Some((32768, 60999)));
        assert_eq!(parse_port_range("nonsense"), None);
        assert_eq!(parse_port_range(""), None);
    }

    #[test]
    fn exposure_classes() {
        let v4 = |a, b, c, d| IpAddr::V4(Ipv4Addr::new(a, b, c, d));
        assert_eq!(exposure_of(&v4(0, 0, 0, 0)), Exposure::Wildcard);
        assert_eq!(exposure_of(&v4(127, 0, 0, 53)), Exposure::Loopback);
        assert_eq!(exposure_of(&v4(10, 0, 0, 2)), Exposure::Specific);
        assert!(Exposure::Wildcard > Exposure::Specific);
        assert!(Exposure::Specific > Exposure::Loopback);
        assert!(!Exposure::Loopback.reachable_from_network());
    }

    fn sockets_for_grouping() -> (Vec<Socket>, HashMap<u64, Owner>) {
        let mut sockets = parse_proc_net(TCP, Proto::Tcp);
        sockets.extend(parse_proc_net(TCP6, Proto::Tcp));
        sockets.extend(parse_proc_net(UDP, Proto::Udp));
        let mut owners = HashMap::new();
        owners.insert(1176, owner(812, "sshd"));
        owners.insert(1180, owner(812, "sshd"));
        owners.insert(3001, owner(600, "dhclient"));
        owners.insert(3002, owner(700, "dnsmasq"));
        (sockets, owners)
    }

    #[test]
    fn dual_stack_daemon_is_one_service() {
        let (sockets, owners) = sockets_for_grouping();
        let eps = endpoints(&sockets, &owners, (32768, 60999));
        let ssh: Vec<&Endpoint> = eps.iter().filter(|e| e.port == 22).collect();
        assert_eq!(ssh.len(), 1, "0.0.0.0:22 and [::]:22 are one sshd");
        assert_eq!(ssh[0].binds.len(), 2);
        assert_eq!(ssh[0].exposure, Exposure::Wildcard);
        assert_eq!(ssh[0].owner.as_ref().unwrap().pid, 812);
        assert_eq!(ssh[0].bind_label(), "all interfaces");
    }

    #[test]
    fn ephemeral_udp_ports_are_dropped_but_tcp_listeners_are_kept() {
        let (sockets, owners) = sockets_for_grouping();
        let eps = endpoints(&sockets, &owners, (32768, 60999));
        assert!(
            !eps.iter()
                .any(|e| e.proto == Proto::Udp && e.port == 0xA1B2),
            "0xA1B2 = 41394 is an outgoing-query port"
        );
        assert!(eps.iter().any(|e| e.proto == Proto::Udp && e.port == 53));
        assert!(eps
            .iter()
            .any(|e| e.proto == Proto::Tcp && e.port == 0xB255));
    }

    #[test]
    fn most_exposed_services_are_listed_first() {
        let (sockets, owners) = sockets_for_grouping();
        let eps = endpoints(&sockets, &owners, (32768, 60999));
        assert_eq!(eps[0].exposure, Exposure::Wildcard);
        let last = eps.last().unwrap();
        assert_eq!(last.exposure, Exposure::Loopback);
    }

    #[test]
    fn same_port_for_two_programs_stays_two_services() {
        let sockets = vec![
            Socket {
                proto: Proto::Udp,
                addr: IpAddr::V4(Ipv4Addr::new(127, 0, 0, 53)),
                port: 53,
                uid: 0,
                inode: 1,
            },
            Socket {
                proto: Proto::Udp,
                addr: IpAddr::V4(Ipv4Addr::new(192, 168, 122, 1)),
                port: 53,
                uid: 0,
                inode: 2,
            },
        ];
        let mut owners = HashMap::new();
        owners.insert(1, owner(10, "systemd-resolve"));
        owners.insert(2, owner(20, "dnsmasq"));
        let eps = endpoints(&sockets, &owners, (32768, 60999));
        assert_eq!(eps.len(), 2);
        assert_eq!(eps[0].owner.as_ref().unwrap().name, "dnsmasq");
        assert_eq!(eps[0].exposure, Exposure::Specific);
        assert_eq!(eps[1].exposure, Exposure::Loopback);
    }

    #[test]
    fn long_bind_lists_are_shortened() {
        let e = Endpoint {
            proto: Proto::Tcp,
            port: 80,
            binds: (1..=4)
                .map(|i| IpAddr::V4(Ipv4Addr::new(10, 0, 0, i)))
                .collect(),
            exposure: Exposure::Specific,
            owner: None,
            uid: 0,
        };
        assert_eq!(e.bind_label(), "10.0.0.1, 10.0.0.2 (+2)");
        assert_eq!(e.process_label(), "-");
        assert_eq!(e.key(), "80/tcp");
    }

    #[test]
    fn catalogue_matches_ports_and_protocols_exactly() {
        assert_eq!(risk_for(Proto::Tcp, 23).unwrap().name, "Telnet");
        assert_eq!(risk_for(Proto::Tcp, 5903).unwrap().name, "VNC");
        assert!(risk_for(Proto::Tcp, 5910).is_none());
        assert!(risk_for(Proto::Udp, 23).is_none(), "telnet is TCP");
        assert_eq!(risk_for(Proto::Udp, 11211).unwrap().name, "Memcached (UDP)");
        assert!(
            risk_for(Proto::Tcp, 22).is_none(),
            "SSH is not a risk entry"
        );
        assert!(risk_for(Proto::Tcp, 80).is_none());
    }

    #[test]
    fn catalogue_is_consistent() {
        for r in RISKS {
            assert!(r.ports.0 <= r.ports.1, "{}", r.name);
            assert!(r.severity >= Severity::Warning, "{}", r.name);
            assert!(!r.why.is_empty() && !r.bind_hint.is_empty(), "{}", r.name);
        }
        // No two entries claim the same port and protocol.
        for (i, a) in RISKS.iter().enumerate() {
            for b in &RISKS[i + 1..] {
                let overlap =
                    a.proto == b.proto && a.ports.0 <= b.ports.1 && b.ports.0 <= a.ports.1;
                assert!(!overlap, "{} overlaps {}", a.name, b.name);
            }
        }
    }

    fn ep(proto: Proto, port: u16, exposure: Exposure, name: Option<&str>) -> Endpoint {
        let addr = match exposure {
            Exposure::Wildcard => IpAddr::V4(Ipv4Addr::UNSPECIFIED),
            Exposure::Specific => IpAddr::V4(Ipv4Addr::new(192, 168, 1, 5)),
            Exposure::Loopback => IpAddr::V4(Ipv4Addr::LOCALHOST),
        };
        Endpoint {
            proto,
            port,
            binds: vec![addr],
            exposure,
            owner: name.map(|n| owner(100, n)),
            uid: 0,
        }
    }

    #[test]
    fn summary_counts_reachable_loopback_and_risks() {
        let eps = vec![
            ep(Proto::Tcp, 22, Exposure::Wildcard, Some("sshd")),
            ep(Proto::Tcp, 6379, Exposure::Wildcard, None),
            ep(Proto::Tcp, 5432, Exposure::Loopback, Some("postgres")),
            ep(Proto::Udp, 68, Exposure::Wildcard, Some("dhclient")),
        ];
        let s = summarize(&eps);
        assert_eq!(s.tcp_services, 3);
        assert_eq!(s.udp_services, 1);
        assert_eq!(s.reachable, 3);
        assert_eq!(s.loopback_only, 1);
        assert_eq!(s.reachable_tcp, vec![6379], "SSH is counted apart");
        assert_eq!(s.ssh_ports, vec![22]);
        assert_eq!(s.unknown_owners, 1);
        assert_eq!(s.exposed_risks, 1, "Redis only: Postgres is loopback");
    }

    #[test]
    fn reachable_by_program_name() {
        let eps = vec![
            ep(Proto::Tcp, 22, Exposure::Wildcard, Some("sshd")),
            ep(Proto::Tcp, 2222, Exposure::Specific, Some("sshd")),
            ep(Proto::Tcp, 2223, Exposure::Loopback, Some("sshd")),
        ];
        assert_eq!(is_reachable_by(&eps, "sshd"), Some(vec![22, 2222]));
        assert_eq!(is_reachable_by(&eps, "nginx"), None);
    }

    #[test]
    fn overview_lists_every_service_and_is_always_info() {
        let eps = vec![
            ep(Proto::Tcp, 22, Exposure::Wildcard, Some("sshd")),
            ep(Proto::Tcp, 631, Exposure::Loopback, Some("cupsd")),
        ];
        let f = overview_finding(&eps, &summarize(&eps), true);
        assert_eq!(f.id, "SEC002");
        assert_eq!(f.severity, Severity::Info);
        assert!(f.explanation.contains("PROTO"));
        assert!(f.explanation.contains("sshd (pid 100)"));
        assert!(f.explanation.contains("local"));
        assert!(f.explanation.contains("1 of 2"));
        assert!(
            f.explanation
                .lines()
                .filter(|l| l.starts_with("  "))
                .count()
                >= 3,
            "table rows are indented so the renderers keep their columns"
        );
        assert!(!f.explanation.contains("Run LinuxDoctor with sudo"));
    }

    #[test]
    fn overview_explains_missing_owners_to_non_root_only() {
        let eps = vec![ep(Proto::Tcp, 22, Exposure::Wildcard, None)];
        let as_user = overview_finding(&eps, &summarize(&eps), false);
        assert!(as_user.explanation.contains("Run LinuxDoctor with sudo"));
        let as_root = overview_finding(&eps, &summarize(&eps), true);
        assert!(!as_root.explanation.contains("Run LinuxDoctor with sudo"));
        assert!(as_root.explanation.contains("another PID namespace"));
    }

    #[test]
    fn overview_for_a_machine_with_no_listeners() {
        let f = overview_finding(&[], &ListenerSummary::default(), true);
        assert!(f.explanation.contains("No program is listening"));
    }

    #[test]
    fn overview_table_is_capped() {
        let eps: Vec<Endpoint> = (0..60)
            .map(|i| ep(Proto::Tcp, 1000 + i, Exposure::Loopback, Some("x")))
            .collect();
        let f = overview_finding(&eps, &summarize(&eps), true);
        assert!(f.explanation.contains("... and 20 more"));
    }

    #[test]
    fn exposed_risky_services_get_a_finding_with_their_own_severity() {
        let eps = vec![
            ep(Proto::Tcp, 23, Exposure::Wildcard, Some("telnetd")),
            ep(Proto::Tcp, 6379, Exposure::Specific, Some("redis-server")),
            ep(Proto::Tcp, 22, Exposure::Wildcard, Some("sshd")),
        ];
        let fw = FirewallStatus::NotDetected { verified: true };
        let f = risk_findings(&eps, &fw);
        assert_eq!(f.len(), 2);
        assert_eq!(f[0].severity, Severity::Error);
        assert!(f[0].title.contains("Telnet"));
        assert_eq!(f[1].severity, Severity::Warning);
        assert!(f[1]
            .recommendation
            .as_ref()
            .unwrap()
            .contains("bind 127.0.0.1"));
    }

    #[test]
    fn loopback_only_risky_services_are_not_reported() {
        let eps = vec![ep(
            Proto::Tcp,
            6379,
            Exposure::Loopback,
            Some("redis-server"),
        )];
        assert!(risk_findings(&eps, &FirewallStatus::Unknown).is_empty());
    }

    #[test]
    fn confidence_depends_on_what_is_known_about_the_firewall() {
        let eps = vec![ep(
            Proto::Tcp,
            6379,
            Exposure::Wildcard,
            Some("redis-server"),
        )];
        let none = &risk_findings(&eps, &FirewallStatus::NotDetected { verified: true })[0];
        let unverified = &risk_findings(&eps, &FirewallStatus::NotDetected { verified: false })[0];
        let active = &risk_findings(
            &eps,
            &FirewallStatus::Active {
                via: vec!["ufw".into()],
            },
        )[0];
        assert!(none.confidence.percent > unverified.confidence.percent);
        assert!(unverified.confidence.percent > active.confidence.percent);
        assert!(active.explanation.contains("may already be filtered"));
        assert!(none.explanation.contains("No firewall was found"));
    }

    #[test]
    fn firewall_step_uses_the_commands_of_the_firewall_in_use() {
        let eps = vec![ep(
            Proto::Tcp,
            6379,
            Exposure::Wildcard,
            Some("redis-server"),
        )];
        let ufw = FirewallStatus::Active {
            via: vec!["ufw".into()],
        };
        let rec = risk_findings(&eps, &ufw)[0].recommendation.clone().unwrap();
        assert!(rec.contains("sudo ufw allow from"));
        assert!(rec.contains("port 6379 proto tcp"));
        let fwd = FirewallStatus::Active {
            via: vec!["firewalld".into()],
        };
        let rec = risk_findings(&eps, &fwd)[0].recommendation.clone().unwrap();
        assert!(rec.contains("firewall-cmd"));
        let rec = risk_findings(&eps, &FirewallStatus::Unknown)[0]
            .recommendation
            .clone()
            .unwrap();
        assert!(!rec.contains("ufw") && !rec.contains("firewall-cmd"));
    }

    #[test]
    fn udp_services_get_the_udp_form_of_the_socket_command() {
        let eps = vec![ep(Proto::Udp, 161, Exposure::Wildcard, Some("snmpd"))];
        let rec = risk_findings(&eps, &FirewallStatus::Unknown)[0]
            .recommendation
            .clone()
            .unwrap();
        assert!(rec.contains("ss -lunp 'sport = :161'"));
    }

    #[test]
    fn missing_owner_is_stated_in_the_evidence() {
        let eps = vec![ep(Proto::Tcp, 23, Exposure::Wildcard, None)];
        let f = &risk_findings(&eps, &FirewallStatus::Unknown)[0];
        assert!(f
            .evidence
            .iter()
            .any(|(k, v)| k == "program_note" && v.contains("root")));
    }
}
