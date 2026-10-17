// SPDX-License-Identifier: GPL-3.0-only

//! NET005 -- the firewall's table of tracked connections.
//!
//! With `nf_conntrack` loaded (any stateful firewall, NAT, Docker, Kubernetes
//! and most routers have it), the kernel keeps one entry per connection that
//! goes through or to the machine, in a table of fixed size. When it is full
//! the kernel drops the packets that would open a new connection, and logs
//! `nf_conntrack: table full, dropping packet`: existing connections keep
//! working and new ones time out, which looks like a flaky network and not
//! like a full table. The rule for "getting full" is the one in
//! [`crate::modules::saturation`].
//!
//! Without the module loaded there is no table and no finding. Read from
//! `/proc/sys/net/netfilter`, under a root, without a tool.

use std::path::Path;

use crate::models::{Category, Finding};
use crate::modules::recommend::{sysctl_commands, Steps};
use crate::modules::saturation::{doubled, parse_number, read_small, Fill, Level};

const COUNT: &str = "proc/sys/net/netfilter/nf_conntrack_count";
const MAX: &str = "proc/sys/net/netfilter/nf_conntrack_max";

/// The entries in the table and its size; `None` when the table does not
/// exist (the module is not loaded) or either number cannot be read.
pub fn read(root: &Path) -> Option<Fill> {
    let number = |path: &str| read_small(&root.join(path)).and_then(|text| parse_number(&text));
    Some(Fill {
        used: number(COUNT)?,
        limit: number(MAX)?,
    })
}

/// The finding. `None` when the limit is zero, which is no limit to compare
/// with.
pub fn conntrack_finding(fill: &Fill) -> Option<Finding> {
    let level = fill.level()?;
    let percent = fill.percent()?;
    let mut text = format!(
        "The firewall's connection-tracking table holds {} entries out of the {} it allows \
         (`net.netfilter.nf_conntrack_max`), {}%.",
        fill.used, fill.limit, percent
    );
    match level {
        Level::Ample => {}
        Level::Near => text.push_str(" That is getting full."),
        Level::Full => text.push_str(" That is almost full."),
    }
    if level != Level::Ample {
        text.push_str(
            " When the table is full, the kernel drops the packets that would open a new \
             connection and logs `nf_conntrack: table full, dropping packet`: connections that \
             exist keep working, new ones time out, which looks like an unreliable network.",
        );
    }
    let mut builder = Finding::builder(
        "NET005",
        "Connection Tracking Table",
        Category::Network,
        level.severity(),
        level.confidence(),
    )
    .evidence("conntrack_entries", fill.used.to_string())
    .evidence("conntrack_max", fill.limit.to_string())
    .evidence("usage_percent", percent.to_string())
    .explanation(text);
    if level != Level::Ample {
        builder = builder.recommendation(steps(fill.limit).build());
    }
    Some(builder.build())
}

fn steps(limit: u64) -> Steps {
    Steps::new()
        .step(
            "See whether packets have already been dropped:",
            &["sudo dmesg | grep -i 'nf_conntrack: table full'"],
        )
        .step(
            "See which protocols and which addresses hold the most entries (the table can only \
             be read by root; every connection appears with both of its directions):",
            &[
                "sudo awk '{print $3}' /proc/net/nf_conntrack | sort | uniq -c | sort -rn | head",
                "sudo grep -o 'src=[0-9a-f.:]*' /proc/net/nf_conntrack | sort | uniq -c | sort -rn | head",
            ],
        )
        .step(
            "An established TCP connection stays in the table for 5 days (432000 seconds) after \
             its last packet by default. Look at the value in use; a shorter one empties the \
             table of connections that are gone, but an idle connection older than it is cut:",
            &["sysctl net.netfilter.nf_conntrack_tcp_timeout_established"],
        )
        .step_owned(
            "If the traffic is legitimate, raise the limit to twice what it is now (each entry \
             takes a few hundred bytes of memory):",
            sysctl_commands(
                &format!("net.netfilter.nf_conntrack_max={}", doubled(limit)),
                "90-conntrack-max.conf",
            ),
        )
        .step(
            "Check the count again:",
            &["cat /proc/sys/net/netfilter/nf_conntrack_count"],
        )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::Severity;
    use std::fs;
    use std::path::PathBuf;

    fn evidence<'a>(finding: &'a Finding, key: &str) -> Option<&'a str> {
        finding
            .evidence
            .iter()
            .find(|(k, _)| k == key)
            .map(|(_, v)| v.as_str())
    }

    fn fill(used: u64, limit: u64) -> Fill {
        Fill { used, limit }
    }

    fn tree(name: &str) -> PathBuf {
        let root = std::env::temp_dir().join(format!(
            "linuxdoctor-network-conntrack-{name}-{}",
            std::process::id()
        ));
        let _ = fs::remove_dir_all(&root);
        fs::create_dir_all(root.join("proc/sys/net/netfilter")).unwrap();
        root
    }

    #[test]
    fn the_table_is_read_under_the_root() {
        let root = tree("read");
        fs::write(root.join(COUNT), "1234\n").unwrap();
        fs::write(root.join(MAX), "262144\n").unwrap();
        assert_eq!(read(&root), Some(fill(1234, 262_144)));
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn no_table_or_half_of_one_is_no_reading() {
        let root = tree("missing");
        assert_eq!(read(&root), None);
        fs::write(root.join(COUNT), "5\n").unwrap();
        assert_eq!(read(&root), None, "no maximum");
        fs::remove_file(root.join(COUNT)).unwrap();
        fs::write(root.join(MAX), "100\n").unwrap();
        assert_eq!(read(&root), None, "no count");
        fs::write(root.join(COUNT), "many\n").unwrap();
        assert_eq!(read(&root), None, "not a number");
        fs::write(root.join(COUNT), "5\n").unwrap();
        fs::write(root.join(MAX), "\n").unwrap();
        assert_eq!(read(&root), None, "empty maximum");
        // Without the directory at all (the module is not loaded).
        let bare = std::env::temp_dir().join(format!(
            "linuxdoctor-network-conntrack-bare-{}",
            std::process::id()
        ));
        let _ = fs::remove_dir_all(&bare);
        assert_eq!(read(&bare), None);
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn room_to_spare_is_information_with_the_figures() {
        let f = conntrack_finding(&fill(1234, 262_144)).unwrap();
        assert_eq!(f.id, "NET005");
        assert_eq!(f.title, "Connection Tracking Table");
        assert_eq!(f.category, Category::Network);
        assert_eq!(f.severity, Severity::Info);
        assert_eq!(f.confidence.percent, 100);
        assert_eq!(f.recommendation, None);
        assert_eq!(
            f.explanation,
            "The firewall's connection-tracking table holds 1234 entries out of the 262144 it \
             allows (`net.netfilter.nf_conntrack_max`), 0%."
        );
        assert_eq!(evidence(&f, "conntrack_entries"), Some("1234"));
        assert_eq!(evidence(&f, "conntrack_max"), Some("262144"));
        assert_eq!(evidence(&f, "usage_percent"), Some("0"));
    }

    #[test]
    fn thresholds_are_eighty_and_ninety_five_percent() {
        let at = |used: u64| conntrack_finding(&fill(used, 1000)).unwrap().severity;
        assert_eq!(at(0), Severity::Info);
        assert_eq!(at(799), Severity::Info);
        assert_eq!(at(800), Severity::Warning);
        assert_eq!(at(949), Severity::Warning);
        assert_eq!(at(950), Severity::Error);
        assert_eq!(at(1000), Severity::Error);
        // The counter can overshoot the maximum for a moment.
        let over = conntrack_finding(&fill(1010, 1000)).unwrap();
        assert_eq!(over.severity, Severity::Error);
        assert_eq!(evidence(&over, "usage_percent"), Some("101"));
    }

    #[test]
    fn a_table_getting_full_is_a_warning_that_says_what_it_does() {
        let f = conntrack_finding(&fill(850, 1000)).unwrap();
        assert_eq!(f.severity, Severity::Warning);
        assert_eq!(f.confidence.percent, 85);
        assert_eq!(
            f.explanation,
            "The firewall's connection-tracking table holds 850 entries out of the 1000 it \
             allows (`net.netfilter.nf_conntrack_max`), 85%. That is getting full. When the \
             table is full, the kernel drops the packets that would open a new connection and \
             logs `nf_conntrack: table full, dropping packet`: connections that exist keep \
             working, new ones time out, which looks like an unreliable network."
        );
        let almost = conntrack_finding(&fill(990, 1000)).unwrap();
        assert!(
            almost.explanation.contains("99%. That is almost full."),
            "{}",
            almost.explanation
        );
        assert_eq!(almost.severity, Severity::Error);
    }

    #[test]
    fn the_steps_look_before_they_change_anything_and_double_the_limit() {
        let rec = conntrack_finding(&fill(900, 1000))
            .unwrap()
            .recommendation
            .unwrap();
        assert!(
            rec.starts_with("1. See whether packets have already been dropped:"),
            "{rec}"
        );
        let at = |needle: &str| {
            rec.find(needle)
                .unwrap_or_else(|| panic!("{needle}\n{rec}"))
        };
        for command in [
            "\n    sudo dmesg | grep -i 'nf_conntrack: table full'",
            "\n    sudo awk '{print $3}' /proc/net/nf_conntrack | sort | uniq -c | sort -rn | head",
            "\n    sudo grep -o 'src=[0-9a-f.:]*' /proc/net/nf_conntrack | sort | uniq -c | sort -rn | head",
            "\n    sysctl net.netfilter.nf_conntrack_tcp_timeout_established",
            "\n    sudo sysctl net.netfilter.nf_conntrack_max=2000",
            "\n    echo 'net.netfilter.nf_conntrack_max = 2000' | sudo tee /etc/sysctl.d/90-conntrack-max.conf",
            "\n    cat /proc/sys/net/netfilter/nf_conntrack_count",
        ] {
            assert!(rec.contains(command), "{command}\n{rec}");
        }
        assert!(at("dmesg") < at("nf_conntrack_tcp_timeout_established"));
        assert!(
            at("nf_conntrack_tcp_timeout_established")
                < at("sudo sysctl net.netfilter.nf_conntrack_max")
        );
        assert!(at("sudo sysctl net.netfilter.nf_conntrack_max") < at("nf_conntrack_count"));
    }

    #[test]
    fn the_limit_proposed_never_exceeds_what_sysctl_takes() {
        let max = i64::MAX as u64;
        let rec = conntrack_finding(&fill(max, max))
            .unwrap()
            .recommendation
            .unwrap();
        assert!(
            rec.contains(&format!(
                "sudo sysctl net.netfilter.nf_conntrack_max={max}\n"
            )),
            "{rec}"
        );
        let rec = conntrack_finding(&fill(u64::MAX, u64::MAX))
            .unwrap()
            .recommendation
            .unwrap();
        assert!(
            rec.contains(&format!(
                "sudo sysctl net.netfilter.nf_conntrack_max={max}\n"
            )),
            "{rec}"
        );
    }

    #[test]
    fn a_maximum_of_zero_says_nothing() {
        assert!(conntrack_finding(&fill(0, 0)).is_none());
        assert!(conntrack_finding(&fill(5, 0)).is_none());
    }

    #[test]
    fn no_command_is_hidden_in_the_prose_of_the_steps() {
        let rec = conntrack_finding(&fill(900, 1000))
            .unwrap()
            .recommendation
            .unwrap();
        for line in rec.lines().filter(|line| !line.starts_with("    ")) {
            for word in ["sudo", "sysctl ", " tee ", "awk", "grep", "cat /"] {
                assert!(!line.contains(word), "{word}: {line}");
            }
        }
    }
}
