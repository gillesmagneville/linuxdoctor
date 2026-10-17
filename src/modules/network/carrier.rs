// SPDX-License-Identifier: GPL-3.0-only

//! NET007 -- a network card whose link keeps going up and down.
//!
//! A bad cable, a worn transceiver, a switch port that negotiates badly or a
//! power-saving feature of the card (Energy-Efficient Ethernet) make a link
//! drop for a second, come back, and drop again. Each drop breaks every
//! connection that uses it; between drops the card looks fine. The kernel
//! counts the changes of the link of every interface in
//! `/sys/class/net/<interface>/carrier_changes`, since the interface
//! appeared (at boot for a card that is there), up and down together.
//!
//! One count means nothing: the link goes up at boot, and a switch that is
//! restarted takes every card down once. What is looked at is the number
//! **and** the rate since boot: at least [`MIN_CHANGES`] changes, and on
//! average one every [`HALF_DAY_SECS`] or faster. Only physical cards are
//! judged (a virtual interface has no `device`, and a container starting or
//! stopping toggles its `veth`), and not Wi-Fi, which loses and regains its
//! link by design when someone walks around.

use std::fs;
use std::path::Path;

use crate::core::text::clean;
use crate::models::{Category, Confidence, Finding, Severity};
use crate::modules::logs::text::is_safe_word;
use crate::modules::recommend::Steps;
use crate::modules::saturation::{parse_number, read_small};

/// Fewer changes than this are a cable plugged in, a switch restarted.
pub const MIN_CHANGES: u64 = 10;

/// On average a change at least this often is flapping.
pub const HALF_DAY_SECS: u64 = 12 * 3600;

const DAY_SECS: u64 = 24 * 3600;
const HOUR_SECS: u64 = 3600;

/// Interfaces looked at, and characters kept of a name.
const MAX_INTERFACES: usize = 256;
const MAX_NAME: usize = 64;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Link {
    pub name: String,
    /// `carrier_changes`: every change of the link, up and down.
    pub changes: u64,
    /// `carrier_up_count` and `carrier_down_count` (Linux 4.16 and later).
    pub up: Option<u64>,
    pub down: Option<u64>,
}

/// What NET007 judges.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Links {
    /// Seconds since boot; `None` when it could not be read, and then no rate
    /// can be told.
    pub uptime_secs: Option<u64>,
    pub links: Vec<Link>,
}

/// The seconds of `/proc/uptime` (`12345.67 98765.43`), rounded down.
pub fn parse_uptime(text: &str) -> Option<u64> {
    let first = text.split_whitespace().next()?;
    let whole = first.split('.').next()?;
    parse_number(whole)
}

/// The physical, wired cards under `root` (`/` on a real machine), by name.
pub fn read(root: &Path) -> Links {
    let uptime_secs = read_small(&root.join("proc/uptime")).and_then(|text| parse_uptime(&text));
    let base = root.join("sys/class/net");
    let Ok(entries) = fs::read_dir(&base) else {
        return Links {
            uptime_secs,
            links: Vec::new(),
        };
    };
    let mut names: Vec<String> = entries
        .flatten()
        .take(MAX_INTERFACES)
        .filter_map(|entry| entry.file_name().into_string().ok())
        .collect();
    names.sort();
    let mut links = Vec::new();
    for name in names {
        let dir = base.join(&name);
        // A card has a `device`; Wi-Fi also has `wireless` or `phy80211`.
        if !dir.join("device").exists()
            || dir.join("wireless").exists()
            || dir.join("phy80211").exists()
        {
            continue;
        }
        let number = |file: &str| read_small(&dir.join(file)).and_then(|text| parse_number(&text));
        let Some(changes) = number("carrier_changes") else {
            continue;
        };
        links.push(Link {
            name: clean(&name, MAX_NAME),
            changes,
            up: number("carrier_up_count"),
            down: number("carrier_down_count"),
        });
    }
    Links { uptime_secs, links }
}

/// One finding per card that flaps, in the order given. Nothing for the
/// others, and nothing at all without an uptime to take a rate from.
pub fn findings(links: &Links) -> Vec<Finding> {
    let Some(uptime) = links.uptime_secs else {
        return Vec::new();
    };
    links
        .links
        .iter()
        .filter_map(|link| flapping_finding(link, uptime))
        .collect()
}

/// Whether `link` changed often enough, for long enough, to be flapping.
pub fn is_flapping(link: &Link, uptime_secs: u64) -> bool {
    link.changes >= MIN_CHANGES
        && u128::from(link.changes) * u128::from(HALF_DAY_SECS) >= u128::from(uptime_secs)
}

fn duration(secs: u64) -> String {
    if secs >= DAY_SECS {
        let days = secs / DAY_SECS;
        format!("{days} day{}", if days == 1 { "" } else { "s" })
    } else if secs >= HOUR_SECS {
        let hours = secs / HOUR_SECS;
        format!("{hours} hour{}", if hours == 1 { "" } else { "s" })
    } else {
        "less than an hour".to_string()
    }
}

/// The finding for `link`, if it flaps. Pure.
pub fn flapping_finding(link: &Link, uptime_secs: u64) -> Option<Finding> {
    if !is_flapping(link, uptime_secs) {
        return None;
    }
    // Changes a day: over a day when the machine has been up less than one,
    // as if it kept up its pace.
    let per_day = link.changes as f64 * DAY_SECS as f64 / uptime_secs.max(1) as f64;
    let split = match (link.down, link.up) {
        (Some(down), Some(up)) => format!(" ({down} down, {up} up)"),
        _ => String::new(),
    };
    let text = format!(
        "The link of {} has changed {} times since boot{split}, {per_day:.1} a day on average \
         over {}. A link that keeps going down and up points to a bad cable, a worn \
         transceiver or switch port, a port that negotiates badly, or a power-saving feature of \
         the card (Energy-Efficient Ethernet). Each drop breaks every connection that uses it, \
         and between drops the card looks fine. The count is since boot, so a burst of changes \
         long ago (a switch that was restarted, a cable changed) is counted too.",
        link.name,
        link.changes,
        duration(uptime_secs)
    );
    let mut builder = Finding::builder(
        "NET007",
        format!("Link Flapping \u{2014} {}", link.name),
        Category::Network,
        Severity::Warning,
        Confidence::strong_indication(80),
    )
    .instance(link.name.clone())
    .evidence("carrier_changes", link.changes.to_string());
    if let Some(down) = link.down {
        builder = builder.evidence("carrier_down_count", down.to_string());
    }
    if let Some(up) = link.up {
        builder = builder.evidence("carrier_up_count", up.to_string());
    }
    builder = builder
        .evidence("uptime_hours", (uptime_secs / HOUR_SECS).to_string())
        .evidence("changes_per_day", format!("{per_day:.1}"))
        .explanation(text)
        .recommendation(steps(&link.name).build());
    Some(builder.build())
}

fn steps(name: &str) -> Steps {
    let interface = if is_safe_word(name) {
        name
    } else {
        "<interface>"
    };
    Steps::new()
        .step_owned(
            "See when the link dropped and what the driver said:",
            vec![format!("sudo dmesg -T | grep -i {interface}")],
        )
        .step_owned(
            "Look at what the card negotiated, its error counters and whether Energy-Efficient \
             Ethernet is on:",
            vec![
                format!("ethtool {interface}"),
                format!("ethtool -S {interface} | grep -i -E 'err|crc|drop'"),
                format!("ethtool --show-eee {interface}"),
            ],
        )
        .step_owned(
            "Change the cable, or move it to another switch port, and see whether the problem \
             follows the cable or the port. If Energy-Efficient Ethernet is on, turn it off to \
             test (until the next reboot):",
            vec![format!("sudo ethtool --set-eee {interface} eee off")],
        )
        .step_owned(
            "Watch whether the count still grows:",
            vec![format!(
                "watch -n 10 cat /sys/class/net/{interface}/carrier_changes"
            )],
        )
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

    fn link(name: &str, changes: u64) -> Link {
        Link {
            name: name.into(),
            changes,
            up: None,
            down: None,
        }
    }

    const DAY: u64 = 86_400;

    // --- uptime ------------------------------------------------------------

    #[test]
    fn the_uptime_is_the_whole_seconds_of_the_first_number() {
        for (text, secs) in [
            ("12345.67 98765.43\n", Some(12_345)),
            ("0.50 0.00", Some(0)),
            ("86400 1", Some(86_400)),
            ("  7.99  ", Some(7)),
            ("", None),
            ("\n", None),
            ("up 12345.67", None),
            ("-5.0 1", None),
            (".5 1", None),
        ] {
            assert_eq!(parse_uptime(text), secs, "{text:?}");
        }
    }

    // --- the rule ----------------------------------------------------------

    #[test]
    fn ten_changes_and_one_every_twelve_hours_is_flapping() {
        let flaps = |changes: u64, uptime: u64| is_flapping(&link("e", changes), uptime);
        // The count: nine is not ten.
        assert!(!flaps(9, DAY));
        assert!(flaps(10, DAY));
        // The rate: ten in five days is one every twelve hours exactly.
        assert!(flaps(10, 5 * DAY));
        assert!(!flaps(10, 5 * DAY + 1));
        assert!(flaps(20, 10 * DAY));
        assert!(!flaps(20, 10 * DAY + 1));
        // A month of uptime needs sixty changes.
        assert!(flaps(60, 30 * DAY));
        assert!(!flaps(59, 30 * DAY));
        // Many changes in a short time.
        assert!(flaps(10, 60));
        assert!(flaps(10, 0));
        // A machine up for years with a few changes is not flapping.
        assert!(!flaps(30, 1000 * DAY));
        assert!(flaps(u64::MAX, u64::MAX));
    }

    // --- reading -----------------------------------------------------------

    fn tree(name: &str) -> PathBuf {
        let root = std::env::temp_dir().join(format!(
            "linuxdoctor-network-carrier-{name}-{}",
            std::process::id()
        ));
        let _ = fs::remove_dir_all(&root);
        fs::create_dir_all(root.join("proc")).unwrap();
        fs::create_dir_all(root.join("sys/class/net")).unwrap();
        root
    }

    /// An interface directory with its files; `physical` gives it a `device`.
    fn nic(root: &Path, name: &str, physical: bool, files: &[(&str, &str)]) {
        let dir = root.join("sys/class/net").join(name);
        fs::create_dir_all(&dir).unwrap();
        if physical {
            fs::create_dir_all(dir.join("device")).unwrap();
        }
        for (file, text) in files {
            fs::write(dir.join(file), text).unwrap();
        }
    }

    #[test]
    fn physical_cards_are_read_with_their_counts() {
        let root = tree("read");
        fs::write(root.join("proc/uptime"), "3600.50 7000.00\n").unwrap();
        nic(
            &root,
            "eth1",
            true,
            &[
                ("carrier_changes", "24\n"),
                ("carrier_up_count", "12\n"),
                ("carrier_down_count", "12\n"),
            ],
        );
        nic(&root, "eth0", true, &[("carrier_changes", "2\n")]);
        let links = read(&root);
        assert_eq!(links.uptime_secs, Some(3600));
        assert_eq!(
            links.links,
            [
                Link {
                    name: "eth0".into(),
                    changes: 2,
                    up: None,
                    down: None
                },
                Link {
                    name: "eth1".into(),
                    changes: 24,
                    up: Some(12),
                    down: Some(12)
                },
            ]
        );
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn virtual_wireless_and_unreadable_interfaces_are_left_out() {
        let root = tree("skip");
        nic(&root, "veth1234", false, &[("carrier_changes", "400\n")]);
        nic(&root, "docker0", false, &[("carrier_changes", "400\n")]);
        nic(&root, "bond0", false, &[("carrier_changes", "400\n")]);
        nic(&root, "wlan0", true, &[("carrier_changes", "400\n")]);
        fs::create_dir_all(root.join("sys/class/net/wlan0/wireless")).unwrap();
        nic(&root, "wlp3s0", true, &[("carrier_changes", "400\n")]);
        fs::create_dir_all(root.join("sys/class/net/wlp3s0/phy80211")).unwrap();
        nic(&root, "eth7", true, &[("carrier_changes", "many\n")]);
        nic(&root, "eth8", true, &[]);
        nic(&root, "eth9", true, &[("carrier_changes", "30\n")]);
        let links = read(&root);
        let names: Vec<&str> = links.links.iter().map(|l| l.name.as_str()).collect();
        assert_eq!(names, ["eth9"]);
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn a_machine_without_the_files_has_nothing_to_judge() {
        let bare = std::env::temp_dir().join(format!(
            "linuxdoctor-network-carrier-bare-{}",
            std::process::id()
        ));
        let _ = fs::remove_dir_all(&bare);
        assert_eq!(read(&bare), Links::default());
        let root = tree("no-uptime");
        nic(&root, "eth0", true, &[("carrier_changes", "50\n")]);
        let links = read(&root);
        assert_eq!(links.uptime_secs, None);
        assert_eq!(links.links.len(), 1);
        // Without an uptime there is no rate, so nothing is said.
        assert!(findings(&links).is_empty());
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn a_hostile_interface_name_is_cleaned() {
        let root = tree("hostile");
        fs::write(root.join("proc/uptime"), "10.0 1.0\n").unwrap();
        nic(&root, "e\u{1b}[2Jth", true, &[("carrier_changes", "30\n")]);
        let links = read(&root);
        assert_eq!(links.links[0].name, "e?[2Jth");
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn so_many_cards_are_read_and_a_long_name_is_cut() {
        let root = tree("bounds");
        for i in 0..300 {
            nic(
                &root,
                &format!("c{i:03}"),
                true,
                &[("carrier_changes", "1\n")],
            );
        }
        assert_eq!(read(&root).links.len(), 256);
        let _ = fs::remove_dir_all(&root);

        let root = tree("long-name");
        let kept = "n".repeat(64);
        let cut = "m".repeat(65);
        nic(&root, &kept, true, &[("carrier_changes", "1\n")]);
        nic(&root, &cut, true, &[("carrier_changes", "1\n")]);
        let names: Vec<String> = read(&root).links.into_iter().map(|l| l.name).collect();
        assert_eq!(names, [format!("{}\u{2026}", "m".repeat(64)), kept]);
        let _ = fs::remove_dir_all(&root);
    }

    // --- the finding -------------------------------------------------------

    #[test]
    fn a_flapping_card_is_a_warning_with_the_rate() {
        let l = Link {
            name: "eth1".into(),
            changes: 48,
            up: Some(24),
            down: Some(24),
        };
        let f = flapping_finding(&l, 2 * DAY).unwrap();
        assert_eq!(f.id, "NET007");
        assert_eq!(f.title, "Link Flapping \u{2014} eth1");
        assert_eq!(f.instance.as_deref(), Some("eth1"));
        assert_eq!(f.category, Category::Network);
        assert_eq!(f.severity, Severity::Warning);
        assert_eq!(f.confidence.percent, 80);
        assert!(
            f.explanation.starts_with(
                "The link of eth1 has changed 48 times since boot (24 down, 24 up), 24.0 a day \
                 on average over 2 days. A link that keeps going down and up points to a bad \
                 cable"
            ),
            "{}",
            f.explanation
        );
        assert!(
            f.explanation.contains("Energy-Efficient Ethernet"),
            "{}",
            f.explanation
        );
        assert!(f.explanation.contains("since boot"), "{}", f.explanation);
        assert_eq!(evidence(&f, "carrier_changes"), Some("48"));
        assert_eq!(evidence(&f, "carrier_down_count"), Some("24"));
        assert_eq!(evidence(&f, "carrier_up_count"), Some("24"));
        assert_eq!(evidence(&f, "uptime_hours"), Some("48"));
        assert_eq!(evidence(&f, "changes_per_day"), Some("24.0"));
    }

    #[test]
    fn counts_that_the_kernel_does_not_split_are_left_out() {
        let f = flapping_finding(&link("eth1", 30), DAY).unwrap();
        assert!(
            f.explanation.contains("30 times since boot, 30.0 a day"),
            "{}",
            f.explanation
        );
        assert_eq!(evidence(&f, "carrier_down_count"), None);
        assert_eq!(evidence(&f, "carrier_up_count"), None);
        // One of the two alone is not enough to split.
        let mut half = link("eth1", 30);
        half.up = Some(15);
        let f = flapping_finding(&half, DAY).unwrap();
        assert!(!f.explanation.contains("down,"), "{}", f.explanation);
        assert_eq!(evidence(&f, "carrier_up_count"), Some("15"));
    }

    #[test]
    fn a_machine_up_for_no_time_is_not_divided_by_zero() {
        // Ten changes in no time at all is read as in one second.
        for uptime in [0, 1] {
            let f = flapping_finding(&link("eth1", 10), uptime).unwrap();
            assert_eq!(
                evidence(&f, "changes_per_day"),
                Some("864000.0"),
                "{uptime}"
            );
            assert_eq!(evidence(&f, "uptime_hours"), Some("0"));
        }
        let f = flapping_finding(&link("eth1", 10), 2).unwrap();
        assert_eq!(evidence(&f, "changes_per_day"), Some("432000.0"));
    }

    #[test]
    fn the_duration_is_said_in_its_biggest_unit() {
        let said = |uptime: u64| {
            flapping_finding(&link("e", 500), uptime)
                .unwrap()
                .explanation
        };
        assert!(said(DAY).contains("over 1 day."), "{}", said(DAY));
        assert!(
            said(3 * DAY + 5).contains("over 3 days."),
            "{}",
            said(3 * DAY + 5)
        );
        assert!(said(3600).contains("over 1 hour."), "{}", said(3600));
        assert!(
            said(5 * 3600 + 59).contains("over 5 hours."),
            "{}",
            said(5 * 3600 + 59)
        );
        assert!(
            said(3599).contains("over less than an hour."),
            "{}",
            said(3599)
        );
        assert!(said(0).contains("over less than an hour."), "{}", said(0));
    }

    #[test]
    fn a_card_that_does_not_flap_has_no_finding() {
        assert!(flapping_finding(&link("eth0", 2), 400 * DAY).is_none());
        assert!(flapping_finding(&link("eth0", 9), 60).is_none());
        assert!(flapping_finding(&link("eth0", 10), 5 * DAY + 1).is_none());
    }

    #[test]
    fn findings_come_one_per_flapping_card() {
        let links = Links {
            uptime_secs: Some(DAY),
            links: vec![link("eth0", 2), link("eth1", 40), link("eth2", 50)],
        };
        let found = findings(&links);
        let instances: Vec<Option<&str>> = found.iter().map(|f| f.instance.as_deref()).collect();
        assert_eq!(instances, [Some("eth1"), Some("eth2")]);
        assert!(findings(&Links::default()).is_empty());
    }

    // --- steps -------------------------------------------------------------

    #[test]
    fn the_steps_look_before_they_change_anything() {
        let rec = flapping_finding(&link("eth1", 40), DAY)
            .unwrap()
            .recommendation
            .unwrap();
        assert!(rec.starts_with("1. See when the link dropped"), "{rec}");
        let at = |needle: &str| {
            rec.find(needle)
                .unwrap_or_else(|| panic!("{needle}\n{rec}"))
        };
        for command in [
            "\n    sudo dmesg -T | grep -i eth1",
            "\n    ethtool eth1",
            "\n    ethtool -S eth1 | grep -i -E 'err|crc|drop'",
            "\n    ethtool --show-eee eth1",
            "\n    sudo ethtool --set-eee eth1 eee off",
            "\n    watch -n 10 cat /sys/class/net/eth1/carrier_changes",
        ] {
            assert!(rec.contains(command), "{command}\n{rec}");
        }
        assert!(at("ethtool --show-eee") < at("--set-eee"));
        assert!(at("dmesg") < at("ethtool eth1"));
        assert!(rec.ends_with("carrier_changes"), "{rec}");
    }

    #[test]
    fn a_name_that_is_not_a_plain_word_stays_out_of_the_commands() {
        let rec = flapping_finding(&link("e th;rm", 40), DAY)
            .unwrap()
            .recommendation
            .unwrap();
        assert!(rec.contains("\n    ethtool <interface>"), "{rec}");
        assert!(
            rec.contains("/sys/class/net/<interface>/carrier_changes"),
            "{rec}"
        );
        assert!(!rec.contains("th;rm"), "{rec}");
    }

    #[test]
    fn no_command_is_hidden_in_the_prose_of_the_steps() {
        let rec = flapping_finding(&link("eth1", 40), DAY)
            .unwrap()
            .recommendation
            .unwrap();
        for line in rec.lines().filter(|line| !line.starts_with("    ")) {
            for word in ["sudo", "ethtool ", "watch", "dmesg", "cat /"] {
                assert!(!line.contains(word), "{word}: {line}");
            }
        }
    }
}
