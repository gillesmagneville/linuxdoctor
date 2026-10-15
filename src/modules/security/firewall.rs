// SPDX-License-Identifier: GPL-3.0-only

//! Is a firewall filtering incoming connections?
//!
//! Pure logic only: judging what `collect.rs` could read — service states,
//! the text of `nft list ruleset` and `iptables -S` — and building the
//! finding.
//!
//! What can be known depends on who runs LinuxDoctor. Anyone can ask
//! systemd whether `ufw` or `firewalld` is running; only root can read the
//! rules themselves. The result says which of the two it is
//! ([`FirewallStatus::NotDetected`]'s `verified`), and the confidence of
//! every finding that depends on it follows.

use crate::models::{Category, Confidence, Finding, Severity};
use crate::modules::recommend::{family_of, Family, Steps};

use super::listeners::ListenerSummary;

/// Firewall front-ends worth naming in a recommendation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FirewallKind {
    Ufw,
    Firewalld,
    Nftables,
    Iptables,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FirewallStatus {
    /// Something is filtering incoming traffic; `via` says what was seen.
    Active { via: Vec<String> },
    /// Nothing was found. `verified` is true when the rules themselves
    /// were read (as root) and are empty or accept everything, false when
    /// only service states could be checked.
    NotDetected { verified: bool },
    /// Could not tell: no way to ask systemd, or a rules-based firewall
    /// service is running and its rules cannot be read without root.
    Unknown,
}

impl FirewallStatus {
    pub fn kind(&self) -> Option<FirewallKind> {
        let FirewallStatus::Active { via } = self else {
            return None;
        };
        let has = |needle: &str| via.iter().any(|v| v.starts_with(needle));
        if has("ufw") {
            Some(FirewallKind::Ufw)
        } else if has("firewalld") {
            Some(FirewallKind::Firewalld)
        } else if has("nftables") {
            Some(FirewallKind::Nftables)
        } else if has("iptables") {
            Some(FirewallKind::Iptables)
        } else {
            None
        }
    }
}

// ---------------------------------------------------------------------------
// What was read
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct FirewallData {
    pub is_root: bool,
    /// Firewall-related services and whether each is active; `None` when
    /// systemd could not be asked at all.
    pub units: Option<Vec<(String, bool)>>,
    /// `ENABLED=` in /etc/ufw/ufw.conf, when that file exists.
    pub ufw_enabled_in_config: Option<bool>,
    /// Some netfilter module is loaded (/proc/modules).
    pub netfilter_loaded: bool,
    /// `nft list ruleset`, only when run as root and it worked.
    pub nft: Option<NftSummary>,
    /// `iptables -S`, only when run as root and it worked.
    pub iptables: Option<IptablesSummary>,
}

impl FirewallData {
    fn unit_active(&self, name: &str) -> bool {
        self.units
            .as_ref()
            .is_some_and(|u| u.iter().any(|(n, active)| n == name && *active))
    }
}

/// Services that are a firewall as soon as they run.
pub const FIREWALL_SERVICES: [&str; 3] = ["firewalld", "ufw", "shorewall"];
/// Services that only load a rule file: running says nothing about what
/// the file contains.
pub const RULE_LOADER_SERVICES: [&str; 2] = ["nftables", "netfilter-persistent"];

/// What `nft list ruleset` shows about incoming traffic.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct NftSummary {
    pub tables: usize,
    /// Base chains attached to the input hook.
    pub input_chains: usize,
    /// Rules in all chains, whatever they do (Docker and libvirt add some
    /// without being a firewall).
    pub rules: usize,
    /// An input chain has a drop policy or a rule that drops or rejects.
    pub blocks_input: bool,
}

/// What `iptables -S` shows about the INPUT chain.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct IptablesSummary {
    pub input_policy: Option<String>,
    pub input_rules: usize,
    pub input_blocking_rules: usize,
}

impl IptablesSummary {
    pub fn blocks_input(&self) -> bool {
        self.input_policy
            .as_deref()
            .is_some_and(|p| p == "DROP" || p == "REJECT")
            || self.input_blocking_rules > 0
    }
}

#[derive(Clone, Copy, PartialEq)]
enum Block {
    Table,
    Chain,
    Other,
}

#[derive(Default)]
struct ChainState {
    hook_input: bool,
    policy_blocks: bool,
    blocking_rules: bool,
    rules: usize,
}

/// Parses the output of `nft list ruleset`.
///
/// Only chains attached to the input hook count: Docker and libvirt put
/// plenty of `drop` rules in forwarding chains without protecting the
/// machine itself. Rules of a chain are the lines that are not blocks of
/// their own (sets, maps, counters...) nor the chain's `type ... hook`
/// line.
pub fn parse_nft_ruleset(text: &str) -> NftSummary {
    let mut summary = NftSummary::default();
    let mut stack: Vec<Block> = Vec::new();
    let mut chain = ChainState::default();

    for raw in text.lines() {
        let line = raw.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if line == "}" {
            if let Some(Block::Chain) = stack.pop() {
                summary.rules += chain.rules;
                if chain.hook_input {
                    summary.input_chains += 1;
                    if chain.policy_blocks || chain.blocking_rules {
                        summary.blocks_input = true;
                    }
                }
                chain = ChainState::default();
            }
            continue;
        }
        if line.ends_with('{') {
            let kind = if line.starts_with("table ") {
                summary.tables += 1;
                Block::Table
            } else if line.starts_with("chain ") {
                chain = ChainState::default();
                Block::Chain
            } else {
                Block::Other
            };
            stack.push(kind);
            continue;
        }
        // Anything else (`elements = { ... }` inside a set, and the like)
        // is not a rule.
        if stack.last() == Some(&Block::Chain) {
            let words: Vec<&str> = line
                .split(|c: char| c.is_whitespace() || c == ';')
                .filter(|w| !w.is_empty())
                .collect();
            if words.first() == Some(&"type") && words.contains(&"hook") {
                let hook = words
                    .iter()
                    .position(|w| *w == "hook")
                    .and_then(|i| words.get(i + 1));
                chain.hook_input = hook == Some(&"input");
                let policy = words
                    .iter()
                    .position(|w| *w == "policy")
                    .and_then(|i| words.get(i + 1));
                chain.policy_blocks = matches!(policy, Some(&"drop") | Some(&"reject"));
            } else {
                chain.rules += 1;
                if words.iter().any(|w| *w == "drop" || *w == "reject") {
                    chain.blocking_rules = true;
                }
            }
        }
    }
    summary
}

/// Parses the output of `iptables -S`.
pub fn parse_iptables(text: &str) -> IptablesSummary {
    let mut summary = IptablesSummary::default();
    for line in text.lines() {
        let words: Vec<&str> = line.split_whitespace().collect();
        match words.as_slice() {
            ["-P", "INPUT", policy] => summary.input_policy = Some((*policy).to_string()),
            ["-A", "INPUT", rest @ ..] => {
                summary.input_rules += 1;
                let target = rest
                    .iter()
                    .position(|w| *w == "-j")
                    .and_then(|i| rest.get(i + 1));
                if matches!(target, Some(&"DROP") | Some(&"REJECT")) {
                    summary.input_blocking_rules += 1;
                }
            }
            _ => {}
        }
    }
    summary
}

/// Parses the output of `systemctl is-active a b c`: one state per line,
/// in the order the units were asked for.
pub fn parse_is_active(names: &[&str], output: &str) -> Vec<(String, bool)> {
    names
        .iter()
        .zip(output.lines())
        .map(|(name, state)| ((*name).to_string(), state.trim() == "active"))
        .collect()
}

/// Parses /etc/ufw/ufw.conf for `ENABLED=yes|no`.
pub fn parse_ufw_conf(text: &str) -> Option<bool> {
    for line in text.lines() {
        let line = line.trim();
        if let Some(value) = line.strip_prefix("ENABLED=") {
            return Some(value.trim().eq_ignore_ascii_case("yes"));
        }
    }
    None
}

/// True when /proc/modules lists a netfilter module.
pub fn netfilter_in_modules(text: &str) -> bool {
    text.lines().any(|l| {
        let name = l.split_whitespace().next().unwrap_or("");
        name == "nf_tables" || name == "ip_tables" || name == "ip6_tables" || name == "x_tables"
    })
}

// ---------------------------------------------------------------------------
// Judgement
// ---------------------------------------------------------------------------

pub fn status(data: &FirewallData) -> FirewallStatus {
    let mut via: Vec<String> = Vec::new();
    for name in FIREWALL_SERVICES {
        if data.unit_active(name) {
            via.push(name.to_string());
        }
    }
    if data.ufw_enabled_in_config == Some(true) && !via.iter().any(|v| v == "ufw") {
        via.push("ufw (enabled in /etc/ufw/ufw.conf)".to_string());
    }
    if let Some(nft) = &data.nft {
        if nft.blocks_input {
            via.push(format!(
                "nftables rules ({} input chain(s), {} rule(s) in all chains)",
                nft.input_chains, nft.rules
            ));
        }
    }
    if let Some(ipt) = &data.iptables {
        if ipt.blocks_input() {
            via.push(format!(
                "iptables rules (INPUT policy {}, {} rule(s))",
                ipt.input_policy.as_deref().unwrap_or("unknown"),
                ipt.input_rules
            ));
        }
    }
    if !via.is_empty() {
        return FirewallStatus::Active { via };
    }

    let loader_running = RULE_LOADER_SERVICES.iter().any(|n| data.unit_active(n));
    if data.is_root {
        return FirewallStatus::NotDetected {
            verified: data.nft.is_some() || data.iptables.is_some(),
        };
    }
    if loader_running || data.units.is_none() {
        return FirewallStatus::Unknown;
    }
    FirewallStatus::NotDetected { verified: false }
}

/// SEC004. When the machine accepts SSH, the advice puts "let SSH through"
/// before "turn the firewall on": the classic way to lock oneself out of a
/// remote machine.
pub fn finding(
    data: &FirewallData,
    status: &FirewallStatus,
    summary: &ListenerSummary,
    distro: Option<&str>,
) -> Finding {
    match status {
        FirewallStatus::Active { via } => active_finding(data, via),
        FirewallStatus::NotDetected { verified } => {
            not_detected_finding(*verified, summary, distro)
        }
        FirewallStatus::Unknown => unknown_finding(data),
    }
}

fn active_finding(data: &FirewallData, via: &[String]) -> Finding {
    let mut builder = Finding::builder(
        "SEC004",
        "Firewall",
        Category::Security,
        Severity::Info,
        Confidence::direct_observation(),
    )
    .evidence("status", "active")
    .evidence("detected_by", via.join("; "));
    if let Some(nft) = &data.nft {
        builder = builder.evidence("nft_input_chains", nft.input_chains.to_string());
    }
    if let Some(ipt) = &data.iptables {
        builder = builder.evidence(
            "iptables_input_policy",
            ipt.input_policy.clone().unwrap_or_else(|| "unknown".into()),
        );
    }
    let mut text = format!(
        "A firewall is filtering incoming connections ({}).",
        via.join("; ")
    );
    if !data.is_root {
        text.push_str(
            " Its rules cannot be read without root, so LinuxDoctor cannot tell which ports it \
             lets through; run it with sudo for the rule counts.",
        );
    }
    text.push_str(
        " LinuxDoctor checks that a firewall is in place, not whether each rule is the right one.",
    );
    builder.explanation(text).build()
}

fn not_detected_finding(
    verified: bool,
    summary: &ListenerSummary,
    distro: Option<&str>,
) -> Finding {
    let exposed = !summary.reachable_tcp.is_empty();
    let ports = summary
        .reachable_tcp
        .iter()
        .map(|p| p.to_string())
        .collect::<Vec<_>>()
        .join(", ");

    let (severity, confidence) = match (exposed, verified) {
        (true, true) => (Severity::Warning, Confidence::strong_indication(85)),
        (true, false) => (Severity::Warning, Confidence::weak_indication(70)),
        (false, true) => (Severity::Info, Confidence::strong_indication(85)),
        (false, false) => (Severity::Info, Confidence::weak_indication(70)),
    };

    let basis = if verified {
        "The rules were read and none of them blocks incoming traffic, and no firewall service \
         is running."
    } else {
        "No firewall service (firewalld, ufw) is running. The rules themselves cannot be read \
         without root, so a rule set loaded by hand would not be seen; run LinuxDoctor with \
         sudo to be certain."
    };
    let consequence = if exposed {
        format!(
            "{} TCP service(s) other than SSH accept connections from the network (port(s) \
             {ports}) with nothing in front of them on this machine. If the machine sits \
             behind a router or a cloud provider's security group that already filters \
             traffic, the risk is lower; a firewall on the machine itself is still the \
             protection that follows it from one network to another, and that stops a program \
             installed tomorrow from being exposed by surprise.",
            summary.reachable_tcp.len()
        )
    } else {
        "Nothing other than SSH is reachable from the network at the moment, so there is \
         nothing for a firewall to hold back today; it would protect against services started \
         in the future."
            .to_string()
    };

    let mut builder = Finding::builder(
        "SEC004",
        "No Firewall Detected",
        Category::Security,
        severity,
        confidence,
    )
    .evidence("status", "not detected")
    .evidence(
        "rules_inspected",
        if verified { "yes" } else { "no (not root)" },
    )
    .evidence(
        "services_reachable",
        summary.reachable_tcp.len().to_string(),
    );
    if exposed {
        builder = builder.evidence("reachable_tcp_ports", ports);
    }
    builder = builder.explanation(format!("{basis}\n\n{consequence}"));

    if severity >= Severity::Warning {
        builder = builder.recommendation(enable_steps(family_of(distro), summary));
    }
    builder.build()
}

fn unknown_finding(data: &FirewallData) -> Finding {
    let reason = if data.units.is_none() {
        "systemd could not be asked which services are running, and the rules cannot be read \
         without root."
    } else {
        "A service that loads firewall rules (nftables or netfilter-persistent) is running, \
         but what it loaded cannot be read without root."
    };
    Finding::builder(
        "SEC004",
        "Firewall Status Unknown",
        Category::Security,
        Severity::Info,
        Confidence::weak_indication(60),
    )
    .evidence("status", "unknown")
    .evidence("rules_inspected", "no (not root)")
    .explanation(format!(
        "{reason} Run LinuxDoctor with sudo to find out whether incoming traffic is filtered."
    ))
    .build()
}

/// How many open ports are listed as `allow` examples; the rest are
/// mentioned by the finding's evidence.
const MAX_PORT_EXAMPLES: usize = 4;

fn enable_steps(family: Family, summary: &ListenerSummary) -> String {
    let ssh = !summary.ssh_ports.is_empty();
    let ssh_warning = if ssh {
        " This machine accepts SSH: let it through first or you will lock yourself out."
    } else {
        ""
    };
    let ports: Vec<u16> = summary
        .reachable_tcp
        .iter()
        .copied()
        .take(MAX_PORT_EXAMPLES)
        .collect();
    let port_list = ports
        .iter()
        .map(u16::to_string)
        .collect::<Vec<_>>()
        .join(", ");
    let open_now = if ports.is_empty() {
        String::new()
    } else {
        format!(" These other TCP ports are open now: {port_list}; allow one only if it must stay reachable.")
    };

    match family {
        Family::DebianLike => {
            let mut allow: Vec<String> = Vec::new();
            if ssh {
                allow.push("sudo ufw allow ssh".to_string());
            }
            for p in &ports {
                allow.push(format!(
                    "sudo ufw allow {p}/tcp   # only if this must stay reachable"
                ));
            }
            Steps::new()
                .step(
                    "Install ufw if it is not installed:",
                    &["sudo apt install ufw"],
                )
                .step_owned(
                    format!("Allow what must stay reachable before turning it on.{ssh_warning}{open_now}"),
                    allow,
                )
                .step(
                    "Refuse everything else coming in, and allow everything going out:",
                    &[
                        "sudo ufw default deny incoming",
                        "sudo ufw default allow outgoing",
                    ],
                )
                .step(
                    "Turn it on and check the result:",
                    &["sudo ufw enable", "sudo ufw status verbose"],
                )
                .build()
        }
        Family::RedHatLike => {
            let mut allow: Vec<String> = Vec::new();
            for p in &ports {
                allow.push(format!(
                    "sudo firewall-cmd --permanent --add-port={p}/tcp   # only if this must stay reachable"
                ));
            }
            allow.push("sudo firewall-cmd --reload".to_string());
            allow.push("sudo firewall-cmd --list-all".to_string());
            Steps::new()
                .step(
                    "Install firewalld if it is not installed:",
                    &["sudo dnf install firewalld"],
                )
                .step(
                    format!(
                        "Start it now and at every boot. SSH is allowed by default.{ssh_warning}"
                    ),
                    &["sudo systemctl enable --now firewalld"],
                )
                .step_owned(
                    format!("Allow what must stay reachable, then check the result.{open_now}"),
                    allow,
                )
                .build()
        }
        Family::Unknown => Steps::new()
            .step(
                format!(
                    "Install and enable the firewall your distribution recommends (ufw on \
                     Debian and Ubuntu, firewalld on Fedora and RHEL).{ssh_warning}"
                ),
                &[],
            )
            .step(
                format!(
                    "Refuse incoming connections by default, then allow only the services you \
                     need.{open_now}"
                ),
                &[],
            )
            .step("List the result to check it:", &["sudo nft list ruleset"])
            .build(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const NFT_EMPTY_DEBIAN: &str = "\
table inet filter {
\tchain input {
\t\ttype filter hook input priority filter; policy accept;
\t}
\tchain forward {
\t\ttype filter hook forward priority filter; policy accept;
\t}
\tchain output {
\t\ttype filter hook output priority filter; policy accept;
\t}
}
";

    const NFT_POLICY_DROP: &str = "\
table inet filter {
\tchain input {
\t\ttype filter hook input priority filter; policy drop;
\t\tct state established,related accept
\t\ttcp dport 22 accept
\t}
}
";

    const NFT_FIREWALLD: &str = "\
table inet firewalld {
\tchain filter_INPUT {
\t\ttype filter hook input priority filter + 10; policy accept;
\t\tct state { established, related } accept
\t\tct status dnat accept
\t\tiifname \"lo\" accept
\t\tjump filter_INPUT_ZONES
\t\tct state invalid drop
\t\treject with icmpx type admin-prohibited
\t}
\tset blocked {
\t\ttype ipv4_addr
\t\telements = { 192.0.2.1 }
\t}
}
";

    const NFT_DOCKER_ONLY: &str = "\
table ip nat {
\tchain DOCKER {
\t\ticifname \"docker0\" counter return
\t}
}
table ip filter {
\tchain INPUT {
\t\ttype filter hook input priority filter; policy accept;
\t}
\tchain FORWARD {
\t\ttype filter hook forward priority filter; policy drop;
\t\tcounter jump DOCKER-USER
\t}
\tchain DOCKER-ISOLATION-STAGE-1 {
\t\tiifname \"docker0\" oifname != \"docker0\" counter jump DOCKER-ISOLATION-STAGE-2
\t\tcounter drop
\t}
}
";

    #[test]
    fn debian_default_nftables_ruleset_is_not_a_firewall() {
        let s = parse_nft_ruleset(NFT_EMPTY_DEBIAN);
        assert_eq!(s.tables, 1);
        assert_eq!(s.input_chains, 1);
        assert_eq!(s.rules, 0);
        assert!(!s.blocks_input);
    }

    #[test]
    fn drop_policy_on_the_input_hook_is_a_firewall() {
        let s = parse_nft_ruleset(NFT_POLICY_DROP);
        assert!(s.blocks_input);
        assert_eq!(s.rules, 2);
    }

    #[test]
    fn firewalld_style_reject_rule_is_a_firewall_even_with_accept_policy() {
        let s = parse_nft_ruleset(NFT_FIREWALLD);
        assert!(s.blocks_input);
        assert_eq!(s.input_chains, 1);
        assert_eq!(s.rules, 6, "set contents are not rules");
    }

    #[test]
    fn docker_rules_in_forward_chains_do_not_count() {
        let s = parse_nft_ruleset(NFT_DOCKER_ONLY);
        assert!(
            !s.blocks_input,
            "DROP in FORWARD/isolation is not protection"
        );
        assert_eq!(s.tables, 2);
        assert!(s.rules >= 3);
    }

    #[test]
    fn empty_or_garbage_nft_output_is_an_empty_summary() {
        assert_eq!(parse_nft_ruleset(""), NftSummary::default());
        assert!(!parse_nft_ruleset("Operation not permitted\n").blocks_input);
    }

    #[test]
    fn iptables_policy_drop_or_blocking_rule_is_a_firewall() {
        let ufw = "\
-P INPUT DROP
-P FORWARD DROP
-P OUTPUT ACCEPT
-N ufw-before-input
-A INPUT -j ufw-before-input
";
        let s = parse_iptables(ufw);
        assert_eq!(s.input_policy.as_deref(), Some("DROP"));
        assert!(s.blocks_input());

        let manual = "-P INPUT ACCEPT\n-A INPUT -p tcp --dport 23 -j REJECT --reject-with icmp-port-unreachable\n";
        let s = parse_iptables(manual);
        assert_eq!(s.input_blocking_rules, 1);
        assert!(s.blocks_input());
    }

    #[test]
    fn libvirt_and_docker_rules_that_accept_are_not_a_firewall() {
        let text = "\
-P INPUT ACCEPT
-P FORWARD DROP
-A INPUT -i virbr0 -p udp -m udp --dport 53 -j ACCEPT
-A INPUT -i virbr0 -p udp -m udp --dport 67 -j ACCEPT
-A FORWARD -j DOCKER-USER
-A FORWARD -o docker0 -j DROP
";
        let s = parse_iptables(text);
        assert_eq!(s.input_rules, 2);
        assert!(!s.blocks_input());
    }

    #[test]
    fn is_active_output_is_matched_to_the_units_in_order() {
        let names = ["firewalld", "ufw", "nftables"];
        let parsed = parse_is_active(&names, "inactive\nactive\nfailed\n");
        assert_eq!(
            parsed,
            vec![
                ("firewalld".to_string(), false),
                ("ufw".to_string(), true),
                ("nftables".to_string(), false)
            ]
        );
    }

    #[test]
    fn ufw_conf_and_modules_are_parsed() {
        assert_eq!(
            parse_ufw_conf("# comment\nENABLED=yes\nLOGLEVEL=low\n"),
            Some(true)
        );
        assert_eq!(parse_ufw_conf("ENABLED=no\n"), Some(false));
        assert_eq!(parse_ufw_conf("LOGLEVEL=low\n"), None);
        assert!(netfilter_in_modules(
            "nf_tables 331776 0 - Live 0x0\nvfat 1 0 - Live 0x0\n"
        ));
        assert!(!netfilter_in_modules("vfat 1 0 - Live 0x0\n"));
    }

    fn data() -> FirewallData {
        FirewallData {
            units: Some(vec![
                ("firewalld".into(), false),
                ("ufw".into(), false),
                ("shorewall".into(), false),
                ("nftables".into(), false),
                ("netfilter-persistent".into(), false),
            ]),
            ..Default::default()
        }
    }

    fn with_active(mut d: FirewallData, name: &str) -> FirewallData {
        for (n, active) in d.units.as_mut().unwrap() {
            if n == name {
                *active = true;
            }
        }
        d
    }

    #[test]
    fn running_ufw_or_firewalld_is_enough_without_root() {
        let st = status(&with_active(data(), "ufw"));
        assert_eq!(
            st,
            FirewallStatus::Active {
                via: vec!["ufw".into()]
            }
        );
        assert_eq!(st.kind(), Some(FirewallKind::Ufw));
        let st = status(&with_active(data(), "firewalld"));
        assert_eq!(st.kind(), Some(FirewallKind::Firewalld));
    }

    #[test]
    fn ufw_enabled_in_its_config_counts() {
        let mut d = data();
        d.ufw_enabled_in_config = Some(true);
        assert_eq!(status(&d).kind(), Some(FirewallKind::Ufw));
    }

    #[test]
    fn nothing_running_and_not_root_is_unverified_absence() {
        assert_eq!(
            status(&data()),
            FirewallStatus::NotDetected { verified: false }
        );
    }

    #[test]
    fn nothing_running_as_root_with_rules_read_is_verified_absence() {
        let mut d = data();
        d.is_root = true;
        d.nft = Some(parse_nft_ruleset(NFT_EMPTY_DEBIAN));
        assert_eq!(status(&d), FirewallStatus::NotDetected { verified: true });
        d.nft = None;
        assert_eq!(status(&d), FirewallStatus::NotDetected { verified: false });
    }

    #[test]
    fn nft_rules_found_by_root_make_it_active_even_with_no_service() {
        let mut d = data();
        d.is_root = true;
        d.nft = Some(parse_nft_ruleset(NFT_POLICY_DROP));
        let st = status(&d);
        assert_eq!(st.kind(), Some(FirewallKind::Nftables));
        let mut d = data();
        d.is_root = true;
        d.iptables = Some(parse_iptables("-P INPUT DROP\n"));
        assert_eq!(status(&d).kind(), Some(FirewallKind::Iptables));
    }

    #[test]
    fn a_rule_loader_service_without_root_cannot_be_judged() {
        let d = with_active(data(), "nftables");
        assert_eq!(status(&d), FirewallStatus::Unknown);
        let no_systemd = FirewallData {
            units: None,
            ..Default::default()
        };
        assert_eq!(status(&no_systemd), FirewallStatus::Unknown);
    }

    #[test]
    fn rule_loader_running_as_root_with_empty_rules_is_not_a_firewall() {
        let mut d = with_active(data(), "nftables");
        d.is_root = true;
        d.nft = Some(parse_nft_ruleset(NFT_EMPTY_DEBIAN));
        assert_eq!(status(&d), FirewallStatus::NotDetected { verified: true });
    }

    fn summary(reachable: &[u16], ssh: &[u16]) -> ListenerSummary {
        ListenerSummary {
            reachable_tcp: reachable.to_vec(),
            ssh_ports: ssh.to_vec(),
            ..Default::default()
        }
    }

    #[test]
    fn no_firewall_with_exposed_services_is_a_warning_with_steps() {
        let f = finding(
            &data(),
            &FirewallStatus::NotDetected { verified: true },
            &summary(&[80, 6379], &[22]),
            Some("Ubuntu 24.04.5 LTS"),
        );
        assert_eq!(f.id, "SEC004");
        assert_eq!(f.severity, Severity::Warning);
        assert_eq!(f.confidence.percent, 85);
        assert!(f.explanation.contains("80, 6379"));
        let rec = f.recommendation.unwrap();
        assert!(rec.contains("sudo ufw allow ssh"));
        assert!(rec.contains("lock yourself out"));
        let allow = rec.find("ufw allow ssh").unwrap();
        let enable = rec.find("ufw enable").unwrap();
        assert!(
            allow < enable,
            "SSH must be allowed before the firewall is turned on"
        );
    }

    #[test]
    fn unverified_absence_has_lower_confidence() {
        let f = finding(
            &data(),
            &FirewallStatus::NotDetected { verified: false },
            &summary(&[80], &[]),
            None,
        );
        assert_eq!(f.severity, Severity::Warning);
        assert_eq!(f.confidence.percent, 70);
        assert!(f.explanation.contains("sudo"));
        assert!(!f.recommendation.unwrap().contains("lock yourself out"));
    }

    #[test]
    fn no_firewall_but_only_ssh_exposed_is_info_without_recommendation() {
        let f = finding(
            &data(),
            &FirewallStatus::NotDetected { verified: true },
            &summary(&[], &[22]),
            None,
        );
        assert_eq!(f.severity, Severity::Info);
        assert!(f.recommendation.is_none());
        assert!(f.explanation.contains("Nothing other than SSH"));
    }

    #[test]
    fn red_hat_family_gets_firewalld_commands() {
        let f = finding(
            &data(),
            &FirewallStatus::NotDetected { verified: true },
            &summary(&[80], &[]),
            Some("Fedora Linux 40"),
        );
        let rec = f.recommendation.unwrap();
        assert!(rec.contains("firewall-cmd"));
        assert!(!rec.contains("ufw"));
    }

    #[test]
    fn unknown_distribution_gets_neutral_advice() {
        let f = finding(
            &data(),
            &FirewallStatus::NotDetected { verified: true },
            &summary(&[80], &[]),
            Some("Gentoo"),
        );
        let rec = f.recommendation.unwrap();
        assert!(rec.contains("ufw on Debian"), "{rec}");
    }

    #[test]
    fn active_firewall_is_info_and_says_what_was_seen() {
        let mut d = data();
        d.is_root = true;
        d.nft = Some(parse_nft_ruleset(NFT_POLICY_DROP));
        let st = status(&d);
        let f = finding(&d, &st, &summary(&[80], &[22]), None);
        assert_eq!(f.severity, Severity::Info);
        assert_eq!(f.title, "Firewall");
        assert!(f.explanation.contains("nftables rules"));
        assert!(!f.explanation.contains("cannot be read without root"));

        let not_root = with_active(data(), "ufw");
        let st = status(&not_root);
        let f = finding(&not_root, &st, &summary(&[], &[]), None);
        assert!(f.explanation.contains("cannot be read without root"));
    }

    #[test]
    fn unknown_state_is_info_and_explains_why() {
        let d = with_active(data(), "nftables");
        let f = finding(&d, &FirewallStatus::Unknown, &summary(&[80], &[]), None);
        assert_eq!(f.severity, Severity::Info);
        assert!(f.explanation.contains("nftables"));
        let f = finding(
            &FirewallData::default(),
            &FirewallStatus::Unknown,
            &summary(&[], &[]),
            None,
        );
        assert!(f.explanation.contains("systemd could not be asked"));
    }
}
