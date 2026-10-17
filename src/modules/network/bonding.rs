// SPDX-License-Identifier: GPL-3.0-only

//! NET006 -- bonded network interfaces that have lost a link.
//!
//! A bond (`bond0`) joins several network cards into one interface so that
//! the machine survives the loss of a cable, a card or a switch port. When
//! one of its links goes down the bond keeps working on the others, which is
//! exactly why nobody notices: the redundancy is gone and nothing complains
//! until the second link follows. This reads what the kernel says about each
//! bond in `/proc/net/bonding/<bond>` and reports the state, never silently.
//!
//! The file is the kernel's own (`bond_procfs.c`), one block for the bond
//! and one per slave:
//!
//! ```text
//! Bonding Mode: IEEE 802.3ad Dynamic link aggregation
//! MII Status: up
//!
//! 802.3ad info
//! LACP active: on
//! Active Aggregator Info:
//!         Aggregator ID: 1
//!         Partner Mac Address: 00:11:22:33:44:55
//!
//! Slave Interface: eth0
//! MII Status: up
//! Link Failure Count: 0
//! Aggregator ID: 1
//! ```
//!
//! The aggregator lines of the bond are only printed to root; a slave's own
//! `Aggregator ID` is printed to everyone, so a split is found either way.

use std::fs::{self, File};
use std::io::Read;
use std::path::Path;

use crate::core::text::clean;
use crate::models::{Category, Confidence, Finding, Severity};
use crate::modules::logs::text::is_safe_word;
use crate::modules::recommend::Steps;

const BONDING: &str = "proc/net/bonding";

/// Bonds looked at, slaves kept per bond, and characters kept of a name.
const MAX_BONDS: usize = 16;
const MAX_SLAVES: usize = 64;
const MAX_NAME: usize = 64;

/// Slaves named in a sentence or a command before "and N more".
const SHOWN_SLAVES: usize = 8;
const MAX_COMMANDS: usize = 4;

/// A bond's file is a page or two; a bigger one is not read to the end.
const MAX_BYTES: u64 = 64 * 1024;
const MAX_LINES: usize = 2000;

/// Whether a slave's link is carrying traffic.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Aggregator {
    /// Not an 802.3ad bond: there is no such line.
    NotUsed,
    /// An 802.3ad slave that is in no aggregator (`Aggregator ID: N/A`).
    Detached,
    Id(u64),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Slave {
    pub name: String,
    /// `up`, `going down`, `down` or `going back`, as the kernel says it.
    pub status: String,
    /// Times the link has gone down since the bond was created.
    pub link_failures: u64,
    pub aggregator: Aggregator,
}

impl Slave {
    pub fn has_link(&self) -> bool {
        self.status == "up"
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Bond {
    pub name: String,
    /// `fault-tolerance (active-backup)`, `IEEE 802.3ad Dynamic link
    /// aggregation`...
    pub mode: String,
    /// The bond's own `MII Status`: up while any slave has a link.
    pub up: bool,
    pub active_slave: Option<String>,
    pub slaves: Vec<Slave>,
    /// The aggregator that carries the traffic; only root is told.
    pub active_aggregator: Option<u64>,
    /// The switch's address in the active aggregator, all zeros when no LACP
    /// partner answered; only root is told.
    pub partner_mac: Option<String>,
}

impl Bond {
    fn is_lacp(&self) -> bool {
        self.mode.contains("802.3ad")
    }
}

/// The text of `/proc/net/bonding/<bond>`, one bond.
pub fn parse_bond(name: &str, text: &str) -> Bond {
    let mut bond = Bond {
        name: clean(name, MAX_NAME),
        mode: String::new(),
        up: false,
        active_slave: None,
        slaves: Vec::new(),
        active_aggregator: None,
        partner_mac: None,
    };
    let mut slave: Option<Slave> = None;
    let finish = |bond: &mut Bond, slave: &mut Option<Slave>| {
        if let Some(done) = slave.take() {
            if bond.slaves.len() < MAX_SLAVES {
                bond.slaves.push(done);
            }
        }
    };
    for line in text.lines().take(MAX_LINES) {
        let Some((key, value)) = line.split_once(':') else {
            continue;
        };
        let (key, value) = (key.trim(), value.trim());
        if key == "Slave Interface" {
            finish(&mut bond, &mut slave);
            // What a slave that says nothing more is taken to be: without a
            // link, so that a file cut short is not read as a healthy bond.
            slave = Some(Slave {
                name: clean(value, MAX_NAME),
                status: "down".to_string(),
                link_failures: 0,
                aggregator: Aggregator::NotUsed,
            });
        } else {
            match (&mut slave, key) {
                (None, "Bonding Mode") => bond.mode = clean(value, MAX_NAME),
                (None, "MII Status") => bond.up = value == "up",
                (None, "Currently Active Slave") => {
                    bond.active_slave =
                        (value != "None" && !value.is_empty()).then(|| clean(value, MAX_NAME));
                }
                (None, "Aggregator ID") => bond.active_aggregator = value.parse().ok(),
                (None, "Partner Mac Address") => bond.partner_mac = Some(clean(value, MAX_NAME)),
                (Some(slave), "MII Status") => slave.status = clean(value, MAX_NAME),
                (Some(slave), "Link Failure Count") => {
                    slave.link_failures = value.parse().unwrap_or(0);
                }
                (Some(slave), "Aggregator ID") => {
                    slave.aggregator = match value.parse() {
                        Ok(id) => Aggregator::Id(id),
                        Err(_) => Aggregator::Detached,
                    };
                }
                _ => {}
            }
        }
    }
    finish(&mut bond, &mut slave);
    bond
}

/// A bond's file, read to a bound.
fn read_bounded(path: &Path) -> Option<String> {
    let mut bytes = Vec::new();
    File::open(path)
        .ok()?
        .take(MAX_BYTES)
        .read_to_end(&mut bytes)
        .ok()?;
    Some(String::from_utf8_lossy(&bytes).into_owned())
}

/// Every bond under `root` (`/` on a real machine), sorted by name. None when
/// the machine has no bonding.
pub fn read(root: &Path) -> Vec<Bond> {
    let Ok(entries) = fs::read_dir(root.join(BONDING)) else {
        return Vec::new();
    };
    let mut names: Vec<String> = entries
        .flatten()
        .filter_map(|entry| entry.file_name().into_string().ok())
        .collect();
    names.sort();
    names
        .iter()
        .take(MAX_BONDS)
        .filter_map(|name| {
            let text = read_bounded(&root.join(BONDING).join(name))?;
            Some(parse_bond(name, &text))
        })
        .filter(|bond| !bond.mode.is_empty())
        .collect()
}

/// What is wrong with a bond, worst first.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum State {
    /// No slave has a link: nothing goes through the bond.
    Down,
    /// The bond works, but not all of its slaves have a link.
    Degraded,
    /// 802.3ad: every slave has a link, but not all are in the same
    /// aggregator, so only some of them carry traffic.
    Split,
    Healthy,
}

pub fn state_of(bond: &Bond) -> State {
    if !bond.up {
        return State::Down;
    }
    if bond.slaves.iter().any(|slave| !slave.has_link()) {
        return State::Degraded;
    }
    if bond.is_lacp() && is_split(bond) {
        return State::Split;
    }
    State::Healthy
}

/// An 802.3ad slave that is in no aggregator, or slaves spread over more
/// than one, or an active aggregator the slaves are not in.
fn is_split(bond: &Bond) -> bool {
    let mut ids = Vec::new();
    for slave in &bond.slaves {
        match slave.aggregator {
            Aggregator::Detached => return true,
            Aggregator::Id(id) => {
                if !ids.contains(&id) {
                    ids.push(id);
                }
            }
            Aggregator::NotUsed => {}
        }
    }
    // With one aggregator among the slaves, it must be the active one.
    ids.len() > 1
        || bond
            .active_aggregator
            .is_some_and(|active| ids.first().is_some_and(|&id| id != active))
}

/// `Some` for every bond that was read, healthy or not.
pub fn findings(bonds: &[Bond]) -> Vec<Finding> {
    bonds.iter().map(bond_finding).collect()
}

fn names_of(slaves: &[&Slave]) -> String {
    let joined = slaves
        .iter()
        .take(SHOWN_SLAVES)
        .map(|slave| slave.name.as_str())
        .collect::<Vec<_>>()
        .join(", ");
    let more = slaves.len().saturating_sub(SHOWN_SLAVES);
    if more > 0 {
        format!("{joined} and {more} more")
    } else {
        joined
    }
}

fn plural(count: usize, word: &str) -> String {
    if count == 1 {
        format!("{count} {word}")
    } else {
        format!("{count} {word}s")
    }
}

fn bond_finding(bond: &Bond) -> Finding {
    let state = state_of(bond);
    let total = bond.slaves.len();
    let with_link: Vec<&Slave> = bond.slaves.iter().filter(|s| s.has_link()).collect();
    let without: Vec<&Slave> = bond.slaves.iter().filter(|s| !s.has_link()).collect();
    let (severity, confidence) = match state {
        State::Down => (Severity::Error, Confidence::direct_observation()),
        State::Degraded => (Severity::Warning, Confidence::direct_observation()),
        State::Split => (Severity::Warning, Confidence::strong_indication(80)),
        State::Healthy => (Severity::Info, Confidence::direct_observation()),
    };
    let head = format!("Bond {} ({})", bond.name, bond.mode);
    let failures = |slave: &Slave| match slave.link_failures {
        0 => String::new(),
        1 => ", its link has failed once since the bond was created".to_string(),
        n => format!(", its link has failed {n} times since the bond was created"),
    };
    let text = match state {
        State::Down => format!(
            "{head} has no link at all: {}. Nothing goes through it, so everything that uses \
             this interface is cut off.",
            if total == 0 {
                "it has no slave".to_string()
            } else {
                format!(
                    "none of its {} ({}) has a link",
                    plural(total, "slave"),
                    names_of(&without)
                )
            }
        ),
        State::Degraded => {
            let detail = without
                .iter()
                .take(SHOWN_SLAVES)
                .map(|slave| format!("{} is {}{}", slave.name, slave.status, failures(slave)))
                .collect::<Vec<_>>()
                .join("; ");
            format!(
                "{head} has lost redundancy: {detail}. It still carries traffic through {}, but \
                 only {} between the machine and being cut off, and nothing else says so.",
                names_of(&with_link),
                if with_link.len() == 1 {
                    "1 link stands".to_string()
                } else {
                    format!("{} links stand", with_link.len())
                }
            )
        }
        State::Split => {
            let ids = bond
                .slaves
                .iter()
                .map(|slave| match slave.aggregator {
                    Aggregator::Id(id) => format!("{}: {id}", slave.name),
                    Aggregator::Detached => format!("{}: none", slave.name),
                    Aggregator::NotUsed => format!("{}: -", slave.name),
                })
                .take(SHOWN_SLAVES)
                .collect::<Vec<_>>()
                .join(", ");
            let partner = match bond.partner_mac.as_deref() {
                Some(mac) if mac.chars().all(|c| c == '0' || c == ':') => {
                    " No switch answered the LACP negotiation (the partner address is all zeros)."
                }
                _ => "",
            };
            format!(
                "All {} of {head} have a link, but they are not in the same LACP aggregator \
                 ({ids}): only one aggregator carries traffic, so the links of the others carry \
                 nothing.{partner} This is what a switch not set up for LACP on these ports looks \
                 like; it is intended only if the links go to different switches on purpose.",
                plural(total, "slave")
            )
        }
        State::Healthy => format!(
            "{head} has {}, all with a link ({}){}.",
            plural(total, "slave"),
            names_of(&with_link),
            match bond.active_slave.as_deref() {
                Some(active) => format!("; {active} is the active one"),
                None => String::new(),
            }
        ),
    };

    let slaves_text = bond
        .slaves
        .iter()
        .take(SHOWN_SLAVES)
        .map(|slave| {
            format!(
                "{} {} ({} failures)",
                slave.name, slave.status, slave.link_failures
            )
        })
        .collect::<Vec<_>>()
        .join(", ");
    let mut builder = Finding::builder(
        "NET006",
        format!("Bonded Interface \u{2014} {}", bond.name),
        Category::Network,
        severity,
        confidence,
    )
    .instance(bond.name.clone())
    .evidence("bond_mode", bond.mode.clone())
    .evidence("bond_link", if bond.up { "up" } else { "down" })
    .evidence("slaves", slaves_text)
    .evidence("slaves_with_link", format!("{}/{}", with_link.len(), total));
    if let Some(active) = &bond.active_slave {
        builder = builder.evidence("active_slave", active.clone());
    }
    builder = builder.explanation(text);
    if severity >= Severity::Warning {
        builder = builder.recommendation(steps(bond, state, &without).build());
    }
    builder.build()
}

fn steps(bond: &Bond, state: State, without: &[&Slave]) -> Steps {
    let name = if is_safe_word(&bond.name) {
        bond.name.as_str()
    } else {
        "<bond>"
    };
    let show = format!("cat /proc/net/bonding/{name}");
    let mut steps = Steps::new().step(
        "Look at the state of the bond and of each of its links:",
        &[&show],
    );
    if state == State::Split {
        steps = steps
            .step(
                "On the switch, check that the ports of these links are in the same LACP channel \
                 group (mode active or passive) and that LACP is turned on for them. See what the \
                 switch announces:",
                &[&format!(
                    "grep -E 'Slave Interface|Aggregator ID|Partner Mac Address' \
                     /proc/net/bonding/{name}"
                )],
            )
            .step(
                "If the links go to a pair of switches that do not form one logical switch, \
                 this is the expected result and only one switch carries traffic at a time.",
                &[],
            );
    } else {
        let mut commands = Vec::new();
        for slave in without.iter().take(MAX_COMMANDS) {
            let interface = if is_safe_word(&slave.name) {
                slave.name.as_str()
            } else {
                "<interface>"
            };
            commands.push(format!("ethtool {interface}"));
            commands.push(format!("sudo dmesg | grep -i {interface}"));
        }
        steps = steps
            .step_owned(
                "For each link without carrier, see whether the network card sees a link \
                 (`Link detected`) and what the kernel logged when it went down:",
                commands,
            )
            .step(
                "If the card sees no link, look at the cable, the transceiver and the switch \
                 port; the kernel takes the link back into the bond by itself when it returns.",
                &[],
            );
    }
    steps.step("Check the state again:", &[&show])
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn evidence<'a>(finding: &'a Finding, key: &str) -> Option<&'a str> {
        finding
            .evidence
            .iter()
            .find(|(k, _)| k == key)
            .map(|(_, v)| v.as_str())
    }

    const ACTIVE_BACKUP: &str = "\
Ethernet Channel Bonding Driver: v6.8.0-45-generic

Bonding Mode: fault-tolerance (active-backup)
Primary Slave: None
Currently Active Slave: eth0
MII Status: up
MII Polling Interval (ms): 100
Up Delay (ms): 0
Down Delay (ms): 0
Peer Notification Delay (ms): 0

Slave Interface: eth0
MII Status: up
Speed: 1000 Mbps
Duplex: full
Link Failure Count: 0
Permanent HW addr: 00:11:22:33:44:55
Slave queue ID: 0

Slave Interface: eth1
MII Status: up
Speed: 1000 Mbps
Duplex: full
Link Failure Count: 2
Permanent HW addr: 00:11:22:33:44:56
Slave queue ID: 0
";

    const LACP: &str = "\
Ethernet Channel Bonding Driver: v6.8.0-45-generic

Bonding Mode: IEEE 802.3ad Dynamic link aggregation
Transmit Hash Policy: layer2 (0)
MII Status: up
MII Polling Interval (ms): 100
Up Delay (ms): 0
Down Delay (ms): 0
Peer Notification Delay (ms): 0

802.3ad info
LACP active: on
LACP rate: slow
Min links: 0
Aggregator selection policy (ad_select): stable
System priority: 65535
System MAC address: 00:11:22:33:44:55
Active Aggregator Info:
\tAggregator ID: 1
\tNumber of ports: 2
\tActor Key: 9
\tPartner Key: 32783
\tPartner Mac Address: aa:bb:cc:dd:ee:ff

Slave Interface: eth0
MII Status: up
Speed: 10000 Mbps
Duplex: full
Link Failure Count: 0
Permanent HW addr: 00:11:22:33:44:55
Slave queue ID: 0
Aggregator ID: 1
Actor Churn State: none
Partner Churn State: none
Actor Churned Count: 0
Partner Churned Count: 0
details actor lacp pdu:
    system priority: 65535
    system mac address: 00:11:22:33:44:55
    port key: 9
    port priority: 255
    port number: 1
    port state: 61
details partner lacp pdu:
    system priority: 32768
    system mac address: aa:bb:cc:dd:ee:ff
    oper key: 32783
    port priority: 32768
    port number: 5
    port state: 61

Slave Interface: eth1
MII Status: up
Speed: 10000 Mbps
Duplex: full
Link Failure Count: 0
Permanent HW addr: 00:11:22:33:44:56
Slave queue ID: 0
Aggregator ID: 1
Actor Churn State: none
Partner Churn State: none
Actor Churned Count: 0
Partner Churned Count: 0
";

    /// `LACP` with the second slave in aggregator `id` (`N/A` for none).
    fn lacp_with_second_aggregator(id: &str) -> String {
        let marker = "Aggregator ID: 1\nActor Churn State";
        let at = LACP.rfind(marker).unwrap();
        format!(
            "{}Aggregator ID: {id}\nActor Churn State{}",
            &LACP[..at],
            &LACP[at + marker.len()..]
        )
    }

    fn slave(name: &str, status: &str, failures: u64, aggregator: Aggregator) -> Slave {
        Slave {
            name: name.into(),
            status: status.into(),
            link_failures: failures,
            aggregator,
        }
    }

    fn bond(mode: &str, up: bool, slaves: Vec<Slave>) -> Bond {
        Bond {
            name: "bond0".into(),
            mode: mode.into(),
            up,
            active_slave: Some("eth0".into()),
            slaves,
            active_aggregator: None,
            partner_mac: None,
        }
    }

    // --- parsing -----------------------------------------------------------

    #[test]
    fn an_active_backup_bond_is_read_with_its_slaves() {
        let b = parse_bond("bond0", ACTIVE_BACKUP);
        assert_eq!(b.name, "bond0");
        assert_eq!(b.mode, "fault-tolerance (active-backup)");
        assert!(b.up);
        assert_eq!(b.active_slave.as_deref(), Some("eth0"));
        assert_eq!(
            b.slaves,
            [
                slave("eth0", "up", 0, Aggregator::NotUsed),
                slave("eth1", "up", 2, Aggregator::NotUsed),
            ]
        );
        assert_eq!(b.active_aggregator, None);
        assert_eq!(b.partner_mac, None);
    }

    #[test]
    fn an_lacp_bond_gives_its_aggregators_and_its_partner() {
        let b = parse_bond("bond1", LACP);
        assert_eq!(b.mode, "IEEE 802.3ad Dynamic link aggregation");
        assert_eq!(b.active_aggregator, Some(1));
        assert_eq!(b.partner_mac.as_deref(), Some("aa:bb:cc:dd:ee:ff"));
        assert_eq!(b.active_slave, None);
        assert_eq!(b.slaves.len(), 2);
        assert_eq!(b.slaves[0].aggregator, Aggregator::Id(1));
        assert_eq!(b.slaves[1].aggregator, Aggregator::Id(1));
        // The lines of the slave's own details are not mistaken for its fields.
        assert_eq!(b.slaves[0].status, "up");
        assert_eq!(b.slaves[0].link_failures, 0);
    }

    #[test]
    fn what_root_alone_is_told_may_be_missing() {
        let text = LACP
            .lines()
            .filter(|line| {
                !line.contains("System ")
                    && !line.starts_with("Active Aggregator Info")
                    && !line.starts_with('\t')
            })
            .collect::<Vec<_>>()
            .join("\n");
        let b = parse_bond("bond1", &text);
        assert_eq!(b.active_aggregator, None);
        assert_eq!(b.partner_mac, None);
        assert_eq!(b.slaves[0].aggregator, Aggregator::Id(1));
        assert_eq!(state_of(&b), State::Healthy);
    }

    #[test]
    fn a_slave_that_is_down_and_one_in_no_aggregator_are_read() {
        let text = "\
Bonding Mode: IEEE 802.3ad Dynamic link aggregation
MII Status: up

Slave Interface: eth0
MII Status: going down
Link Failure Count: 7
Aggregator ID: N/A

Slave Interface: eth1
MII Status: down
Link Failure Count: 12
";
        let b = parse_bond("bond0", text);
        assert_eq!(b.slaves[0].status, "going down");
        assert!(!b.slaves[0].has_link());
        assert_eq!(b.slaves[0].link_failures, 7);
        assert_eq!(b.slaves[0].aggregator, Aggregator::Detached);
        assert_eq!(b.slaves[1].status, "down");
        assert_eq!(b.slaves[1].link_failures, 12);
        assert_eq!(b.slaves[1].aggregator, Aggregator::NotUsed);
    }

    #[test]
    fn the_status_words_of_the_kernel_are_kept_and_only_up_has_a_link() {
        for (word, link) in [
            ("up", true),
            ("down", false),
            ("going down", false),
            ("going back", false),
            ("UP", false),
            ("", false),
        ] {
            assert_eq!(
                slave("e", word, 0, Aggregator::NotUsed).has_link(),
                link,
                "{word:?}"
            );
        }
    }

    #[test]
    fn the_bond_with_no_active_slave_has_none() {
        let text = "Bonding Mode: load balancing (round-robin)\nMII Status: up\n";
        let b = parse_bond("bond0", text);
        assert_eq!(b.active_slave, None);
        assert!(b.slaves.is_empty());
        let text = "Bonding Mode: fault-tolerance (active-backup)\nCurrently Active Slave: None\nMII Status: down\n";
        let b = parse_bond("bond0", text);
        assert_eq!(b.active_slave, None);
        assert!(!b.up);
    }

    #[test]
    fn a_name_and_a_mode_from_the_file_are_cleaned_and_bounded() {
        let text = format!(
            "Bonding Mode: {}\u{1b}[2J\nMII Status: up\n\nSlave Interface: ev\u{1b}[31mil\nMII Status: up\n",
            "m".repeat(200)
        );
        let b = parse_bond("bo\u{7}nd", &text);
        assert_eq!(b.name, "bo?nd");
        assert!(!b.mode.contains('\u{1b}'));
        assert!(b.mode.chars().count() <= 65, "{}", b.mode);
        assert_eq!(b.slaves[0].name, "ev?[31mil");
    }

    #[test]
    fn junk_and_blank_text_make_an_empty_bond() {
        for text in ["", "\n\n", "no colon here\n", ":\n", "garbage: value\n"] {
            let b = parse_bond("bond0", text);
            assert_eq!(b.mode, "", "{text:?}");
            assert!(b.slaves.is_empty());
        }
    }

    #[test]
    fn a_hundred_slaves_are_kept_to_sixty_four() {
        let mut text = String::from("Bonding Mode: load balancing (round-robin)\nMII Status: up\n");
        for i in 0..100 {
            text.push_str(&format!(
                "\nSlave Interface: eth{i}\nMII Status: up\nLink Failure Count: 0\n"
            ));
        }
        assert_eq!(parse_bond("bond0", &text).slaves.len(), 64);
    }

    #[test]
    fn a_number_that_is_not_one_is_zero() {
        let text = "Bonding Mode: m\nMII Status: up\n\nSlave Interface: e\nMII Status: up\nLink Failure Count: many\n";
        assert_eq!(parse_bond("b", text).slaves[0].link_failures, 0);
        let text = "Bonding Mode: m\nMII Status: up\n\nSlave Interface: e\nMII Status: up\nLink Failure Count: 18446744073709551615\n";
        assert_eq!(parse_bond("b", text).slaves[0].link_failures, u64::MAX);
    }

    // --- reading -----------------------------------------------------------

    fn tree(name: &str) -> PathBuf {
        let root = std::env::temp_dir().join(format!(
            "linuxdoctor-network-bonding-{name}-{}",
            std::process::id()
        ));
        let _ = fs::remove_dir_all(&root);
        fs::create_dir_all(root.join("proc/net/bonding")).unwrap();
        root
    }

    #[test]
    fn the_bonds_are_read_under_the_root_in_name_order() {
        let root = tree("read");
        fs::write(root.join("proc/net/bonding/bond1"), LACP).unwrap();
        fs::write(root.join("proc/net/bonding/bond0"), ACTIVE_BACKUP).unwrap();
        let bonds = read(&root);
        let names: Vec<&str> = bonds.iter().map(|b| b.name.as_str()).collect();
        assert_eq!(names, ["bond0", "bond1"]);
        assert_eq!(bonds[0].slaves.len(), 2);
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn no_bonding_and_files_that_are_not_bonds_give_no_bond() {
        let root = tree("none");
        assert!(read(&root).is_empty());
        fs::write(root.join("proc/net/bonding/notes"), "just text\n").unwrap();
        assert!(read(&root).is_empty());
        let bare = std::env::temp_dir().join(format!(
            "linuxdoctor-network-bonding-bare-{}",
            std::process::id()
        ));
        let _ = fs::remove_dir_all(&bare);
        assert!(read(&bare).is_empty());
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn so_many_bonds_are_read_and_a_big_file_is_cut() {
        let root = tree("bounds");
        for i in 0..20 {
            fs::write(
                root.join(format!("proc/net/bonding/bond{i:02}")),
                ACTIVE_BACKUP,
            )
            .unwrap();
        }
        assert_eq!(read(&root).len(), 16);
        // A file of a hundred kilobytes: read to 64 KiB, which still has the head.
        let mut big = String::from(ACTIVE_BACKUP);
        big.push_str(&"x: y\n".repeat(30_000));
        fs::write(root.join("proc/net/bonding/bond00"), big).unwrap();
        let bonds = read(&root);
        assert_eq!(bonds[0].slaves.len(), 2);
        let _ = fs::remove_dir_all(&root);
    }

    /// A bond file whose `MII Status: up` starts at byte `offset`, after lines
    /// that say nothing; `Bonding Mode` comes first.
    fn bond_file_with_status_at(offset: usize) -> String {
        let mut text = String::from("Bonding Mode: m\n");
        while text.len() < offset {
            let room = offset - text.len();
            let line = room.min(64);
            text.push_str(&"a".repeat(line - 1));
            text.push('\n');
        }
        assert_eq!(text.len(), offset);
        text.push_str("MII Status: up\n");
        text
    }

    #[test]
    fn a_bond_file_is_read_to_exactly_sixty_four_kibibytes() {
        let root = tree("exact-bytes");
        let read_up = |offset: usize| {
            fs::write(
                root.join("proc/net/bonding/bond0"),
                bond_file_with_status_at(offset),
            )
            .unwrap();
            read(&root)[0].up
        };
        // The last line that starts inside the limit is read; one that starts
        // on its first byte beyond is not.
        assert!(read_up(65_500));
        assert!(read_up(65_535 - "MII Status: up".len()));
        assert!(!read_up(65_536));
        assert!(!read_up(70_000));
        // And a short file is read whole.
        assert!(read_up(2_000));
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn a_bond_file_is_read_to_exactly_two_thousand_lines() {
        let with_status_at_line = |line: usize| {
            let mut text = String::from("Bonding Mode: m\n");
            text.push_str(&"\n".repeat(line - 2));
            text.push_str("MII Status: up\n");
            parse_bond("bond0", &text).up
        };
        assert!(with_status_at_line(1_999));
        assert!(with_status_at_line(2_000));
        assert!(!with_status_at_line(2_001));
        assert!(!with_status_at_line(5_000));
    }

    #[test]
    fn what_the_file_does_not_say_is_taken_as_no_link() {
        // A bond that never says its own state is not up.
        let bond = parse_bond("bond0", "Bonding Mode: balance-rr\n");
        assert!(!bond.up);
        assert_eq!(bond.slaves, []);
        assert_eq!(bond.active_slave, None);
        // A slave that never says its state, its failures or its aggregator.
        let bond = parse_bond(
            "bond0",
            "Bonding Mode: balance-rr\nMII Status: up\nSlave Interface: eth0\n",
        );
        assert!(bond.up);
        assert_eq!(
            bond.slaves,
            [Slave {
                name: "eth0".into(),
                status: "down".into(),
                link_failures: 0,
                aggregator: Aggregator::NotUsed,
            }]
        );
    }

    // --- state -------------------------------------------------------------

    #[test]
    fn the_state_is_the_worst_thing_the_kernel_says() {
        use Aggregator::*;
        let up = |n: &str| slave(n, "up", 0, NotUsed);
        let down = |n: &str| slave(n, "down", 3, NotUsed);
        let ab = "fault-tolerance (active-backup)";
        assert_eq!(
            state_of(&bond(ab, true, vec![up("a"), up("b")])),
            State::Healthy
        );
        assert_eq!(
            state_of(&bond(ab, true, vec![up("a"), down("b")])),
            State::Degraded
        );
        assert_eq!(
            state_of(&bond(ab, true, vec![down("a"), up("b")])),
            State::Degraded
        );
        assert_eq!(
            state_of(&bond(ab, false, vec![down("a"), down("b")])),
            State::Down
        );
        assert_eq!(state_of(&bond(ab, false, vec![])), State::Down);
        // A bond that says it is up while it has a slave that is going down.
        let going = slave("b", "going down", 0, NotUsed);
        assert_eq!(
            state_of(&bond(ab, true, vec![up("a"), going])),
            State::Degraded
        );
    }

    #[test]
    fn lacp_slaves_in_different_aggregators_are_a_split() {
        use Aggregator::*;
        let lacp = "IEEE 802.3ad Dynamic link aggregation";
        let s = |n: &str, a: Aggregator| slave(n, "up", 0, a);
        assert_eq!(
            state_of(&bond(lacp, true, vec![s("a", Id(1)), s("b", Id(1))])),
            State::Healthy
        );
        assert_eq!(
            state_of(&bond(lacp, true, vec![s("a", Id(1)), s("b", Id(2))])),
            State::Split
        );
        assert_eq!(
            state_of(&bond(lacp, true, vec![s("a", Id(1)), s("b", Detached)])),
            State::Split
        );
        // The aggregators are compared with the active one when it is known.
        let mut b = bond(lacp, true, vec![s("a", Id(2)), s("b", Id(2))]);
        b.active_aggregator = Some(1);
        assert_eq!(state_of(&b), State::Split);
        b.active_aggregator = Some(2);
        assert_eq!(state_of(&b), State::Healthy);
        // The same slaves in a bond that is not 802.3ad are nobody's business.
        let ab = "fault-tolerance (active-backup)";
        assert_eq!(
            state_of(&bond(ab, true, vec![s("a", Id(1)), s("b", Id(2))])),
            State::Healthy
        );
        // A down slave is a degraded bond before it is a split one.
        let down = slave("b", "down", 1, Detached);
        assert_eq!(
            state_of(&bond(lacp, true, vec![s("a", Id(1)), down])),
            State::Degraded
        );
    }

    // --- findings ----------------------------------------------------------

    #[test]
    fn a_healthy_bond_is_information_that_names_its_links() {
        let b = parse_bond("bond0", ACTIVE_BACKUP);
        let f = &findings(&[b])[0];
        assert_eq!(f.id, "NET006");
        assert_eq!(f.title, "Bonded Interface \u{2014} bond0");
        assert_eq!(f.instance.as_deref(), Some("bond0"));
        assert_eq!(f.category, Category::Network);
        assert_eq!(f.severity, Severity::Info);
        assert_eq!(f.confidence.percent, 100);
        assert_eq!(f.recommendation, None);
        assert_eq!(
            f.explanation,
            "Bond bond0 (fault-tolerance (active-backup)) has 2 slaves, all with a link \
             (eth0, eth1); eth0 is the active one."
        );
        assert_eq!(
            evidence(f, "bond_mode"),
            Some("fault-tolerance (active-backup)")
        );
        assert_eq!(evidence(f, "bond_link"), Some("up"));
        assert_eq!(
            evidence(f, "slaves"),
            Some("eth0 up (0 failures), eth1 up (2 failures)")
        );
        assert_eq!(evidence(f, "slaves_with_link"), Some("2/2"));
        assert_eq!(evidence(f, "active_slave"), Some("eth0"));
    }

    #[test]
    fn a_healthy_lacp_bond_has_no_active_slave_to_name() {
        let f = &findings(&[parse_bond("bond1", LACP)])[0];
        assert_eq!(f.severity, Severity::Info);
        assert!(
            f.explanation.ends_with("(eth0, eth1)."),
            "{}",
            f.explanation
        );
        assert_eq!(evidence(f, "active_slave"), None);
    }

    fn with_eth1(status: &str) -> String {
        ACTIVE_BACKUP.replacen(
            "Slave Interface: eth1\nMII Status: up",
            &format!("Slave Interface: eth1\nMII Status: {status}"),
            1,
        )
    }

    #[test]
    fn a_slave_without_link_is_a_warning_that_says_what_is_left() {
        let f = &findings(&[parse_bond("bond0", &with_eth1("down"))])[0];
        assert_eq!(f.severity, Severity::Warning);
        assert_eq!(f.confidence.percent, 100);
        assert_eq!(
            f.explanation,
            "Bond bond0 (fault-tolerance (active-backup)) has lost redundancy: eth1 is down, \
             its link has failed 2 times since the bond was created. It still carries traffic \
             through eth0, but only 1 link stands between the machine and being cut off, and \
             nothing else says so."
        );
        assert_eq!(evidence(f, "slaves_with_link"), Some("1/2"));
        assert_eq!(
            evidence(f, "slaves"),
            Some("eth0 up (0 failures), eth1 down (2 failures)")
        );
    }

    #[test]
    fn a_link_that_failed_once_and_several_that_are_left_are_said_right() {
        let text = "Bonding Mode: load balancing (round-robin)\nMII Status: up\n\
                    \nSlave Interface: a\nMII Status: down\nLink Failure Count: 1\n\
                    \nSlave Interface: b\nMII Status: up\n\
                    \nSlave Interface: c\nMII Status: up\n\
                    \nSlave Interface: d\nMII Status: going back\nLink Failure Count: 0\n";
        let f = &findings(&[parse_bond("bond0", text)])[0];
        assert!(
            f.explanation.contains(
                "a is down, its link has failed once since the bond was created; d is going \
                 back. It still carries traffic through b, c, but only 2 links stand between"
            ),
            "{}",
            f.explanation
        );
        assert_eq!(evidence(f, "slaves_with_link"), Some("2/4"));
    }

    #[test]
    fn a_bond_with_no_link_at_all_is_an_error() {
        let text = "Bonding Mode: fault-tolerance (active-backup)\nCurrently Active Slave: None\n\
                    MII Status: down\n\nSlave Interface: eth0\nMII Status: down\n\
                    Link Failure Count: 5\n\nSlave Interface: eth1\nMII Status: down\n";
        let f = &findings(&[parse_bond("bond0", text)])[0];
        assert_eq!(f.severity, Severity::Error);
        assert_eq!(f.confidence.percent, 100);
        assert_eq!(
            f.explanation,
            "Bond bond0 (fault-tolerance (active-backup)) has no link at all: none of its 2 \
             slaves (eth0, eth1) has a link. Nothing goes through it, so everything that uses \
             this interface is cut off."
        );
        assert_eq!(evidence(f, "bond_link"), Some("down"));
        assert_eq!(evidence(f, "slaves_with_link"), Some("0/2"));
        let one = "Bonding Mode: m\nMII Status: down\n\nSlave Interface: eth0\nMII Status: down\n";
        let f = &findings(&[parse_bond("bond0", one)])[0];
        assert!(
            f.explanation.contains("none of its 1 slave (eth0)"),
            "{}",
            f.explanation
        );
        let none = "Bonding Mode: m\nMII Status: down\n";
        let f = &findings(&[parse_bond("bond0", none)])[0];
        assert!(
            f.explanation.contains("it has no slave"),
            "{}",
            f.explanation
        );
        assert_eq!(f.severity, Severity::Error);
    }

    #[test]
    fn slaves_split_over_two_aggregators_are_a_warning_that_is_not_certain() {
        let text = lacp_with_second_aggregator("2");
        let b = parse_bond("bond1", &text);
        assert_eq!(state_of(&b), State::Split, "{:?}", b.slaves);
        let f = &findings(&[b])[0];
        assert_eq!(f.severity, Severity::Warning);
        assert_eq!(f.confidence.percent, 80);
        assert!(
            f.explanation.starts_with(
                "All 2 slaves of Bond bond1 (IEEE 802.3ad Dynamic link aggregation) have a link, \
                 but they are not in the same LACP aggregator (eth0: 1, eth1: 2): only one \
                 aggregator carries traffic, so the links of the others carry nothing."
            ),
            "{}",
            f.explanation
        );
        assert!(
            f.explanation.contains("different switches on purpose"),
            "{}",
            f.explanation
        );
        assert!(!f.explanation.contains("all zeros"), "{}", f.explanation);
    }

    #[test]
    fn a_partner_of_all_zeros_is_said() {
        let text = LACP
            .replace("aa:bb:cc:dd:ee:ff", "00:00:00:00:00:00")
            .replacen(
                "Aggregator ID: 1\nActor Churn",
                "Aggregator ID: N/A\nActor Churn",
                1,
            );
        let b = parse_bond("bond1", &text);
        assert_eq!(b.slaves[0].aggregator, Aggregator::Detached);
        let f = &findings(&[b])[0];
        assert!(f.explanation.contains("eth0: none"), "{}", f.explanation);
        assert!(
            f.explanation.contains(
                "No switch answered the LACP negotiation (the partner address is all zeros)."
            ),
            "{}",
            f.explanation
        );
    }

    // --- steps -------------------------------------------------------------

    #[test]
    fn the_steps_for_a_lost_link_look_at_the_bond_then_at_each_card() {
        let f = &findings(&[parse_bond("bond0", &with_eth1("down"))])[0];
        let rec = f.recommendation.clone().unwrap();
        assert!(
            rec.starts_with("1. Look at the state of the bond and of each of its links:"),
            "{rec}"
        );
        for command in [
            "\n    cat /proc/net/bonding/bond0",
            "\n    ethtool eth1",
            "\n    sudo dmesg | grep -i eth1",
        ] {
            assert!(rec.contains(command), "{command}\n{rec}");
        }
        // eth0 has a link: it is not looked at.
        assert!(!rec.contains("ethtool eth0"), "{rec}");
        assert!(
            rec.ends_with("4. Check the state again:\n    cat /proc/net/bonding/bond0"),
            "{rec}"
        );
    }

    #[test]
    fn the_steps_for_a_split_look_at_the_switch() {
        let text = lacp_with_second_aggregator("N/A");
        let f = &findings(&[parse_bond("bond1", &text)])[0];
        let rec = f.recommendation.clone().unwrap();
        assert!(rec.contains("same LACP channel group"), "{rec}");
        assert!(
            rec.contains("\n    grep -E 'Slave Interface|Aggregator ID|Partner Mac Address' /proc/net/bonding/bond1"),
            "{rec}"
        );
        assert!(!rec.contains("ethtool"), "{rec}");
    }

    #[test]
    fn a_name_that_is_not_a_plain_word_stays_out_of_the_commands() {
        let text =
            "Bonding Mode: m\nMII Status: up\n\nSlave Interface: a b; rm\nMII Status: down\n\
                    \nSlave Interface: eth9\nMII Status: up\n";
        let mut b = parse_bond("bond0", text);
        b.name = "bo nd".into();
        let f = &findings(&[b])[0];
        let rec = f.recommendation.clone().unwrap();
        assert!(rec.contains("\n    cat /proc/net/bonding/<bond>"), "{rec}");
        assert!(rec.contains("\n    ethtool <interface>"), "{rec}");
        assert!(
            rec.contains("\n    sudo dmesg | grep -i <interface>"),
            "{rec}"
        );
        assert!(!rec.contains("rm"), "{rec}");
    }

    #[test]
    fn only_four_cards_get_commands_and_only_eight_are_named() {
        let mut text = String::from("Bonding Mode: load balancing (round-robin)\nMII Status: up\n");
        for i in 0..12 {
            text.push_str(&format!("\nSlave Interface: e{i}\nMII Status: down\n"));
        }
        text.push_str("\nSlave Interface: ok\nMII Status: up\n");
        let f = &findings(&[parse_bond("bond0", &text)])[0];
        let rec = f.recommendation.clone().unwrap();
        assert_eq!(rec.matches("\n    ethtool ").count(), 4, "{rec}");
        assert!(rec.contains("ethtool e3\n"), "{rec}");
        assert!(!rec.contains("ethtool e4"), "{rec}");
        // Eight named in the sentence (the other four, if any, are not).
        assert!(f.explanation.contains("e7 is down"), "{}", f.explanation);
        assert!(!f.explanation.contains("e8 is down"), "{}", f.explanation);
        // Exactly one more than are named is said, and exactly as many is not.
        let down_slaves = |count: usize| {
            "Bonding Mode: m\nMII Status: down\n".to_string()
                + &(0..count)
                    .map(|i| format!("\nSlave Interface: n{i}\nMII Status: down\n"))
                    .collect::<String>()
        };
        let f = &findings(&[parse_bond("bond0", &down_slaves(9))])[0];
        assert!(
            f.explanation
                .contains("(n0, n1, n2, n3, n4, n5, n6, n7 and 1 more)"),
            "{}",
            f.explanation
        );
        let f = &findings(&[parse_bond("bond0", &down_slaves(8))])[0];
        assert!(
            f.explanation.contains("(n0, n1, n2, n3, n4, n5, n6, n7)"),
            "{}",
            f.explanation
        );
        let all_down = "Bonding Mode: m\nMII Status: down\n".to_string()
            + &(0..10)
                .map(|i| format!("\nSlave Interface: n{i}\nMII Status: down\n"))
                .collect::<String>();
        let f = &findings(&[parse_bond("bond0", &all_down)])[0];
        assert!(
            f.explanation
                .contains("(n0, n1, n2, n3, n4, n5, n6, n7 and 2 more)"),
            "{}",
            f.explanation
        );
    }

    #[test]
    fn no_command_is_hidden_in_the_prose_of_the_steps() {
        let split = lacp_with_second_aggregator("2");
        for text in [with_eth1("down"), split] {
            let f = &findings(&[parse_bond("bond0", &text)])[0];
            for line in f
                .recommendation
                .as_deref()
                .unwrap()
                .lines()
                .filter(|l| !l.starts_with("    "))
            {
                for word in ["sudo", "ethtool ", "grep", "cat /"] {
                    assert!(!line.contains(word), "{word}: {line}");
                }
            }
        }
    }

    #[test]
    fn one_finding_per_bond_in_the_order_given() {
        let bonds = vec![
            parse_bond("bond0", ACTIVE_BACKUP),
            parse_bond("bond1", LACP),
        ];
        let ids: Vec<Option<String>> = findings(&bonds).into_iter().map(|f| f.instance).collect();
        assert_eq!(ids, [Some("bond0".to_string()), Some("bond1".to_string())]);
        assert!(findings(&[]).is_empty());
    }
}
