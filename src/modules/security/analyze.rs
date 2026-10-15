// SPDX-License-Identifier: GPL-3.0-only

//! Puts the topics together: runs each one's analysis, builds the overview
//! and orders the findings the way the module is read.

use std::cmp::Reverse;

use crate::core::context::Context;
use crate::models::{Category, Confidence, Finding, Severity};

use super::collect::SecurityRawData;
use super::firewall::{self, FirewallStatus};
use super::listeners::{self, ListenerSummary};
use super::ssh::{self, SshRuntime};
use super::{access, accounts};

/// The pages of the module's submenu, in the order they are shown.
pub const TOPICS: [&str; 6] = [
    "Listening services",
    "Firewall",
    "SSH",
    "Access control",
    "Hardening",
    "Accounts & files",
];

/// Order of the findings within a page (also the tie-break between equal
/// severities).
const ORDER: [&str; 9] = [
    "SEC001", "SEC003", "SEC004", "SEC005", "SEC006", "SEC007", "SEC008", "SEC009", "SEC002",
];

fn topic_of(id: &str) -> Option<&'static str> {
    match id {
        "SEC002" | "SEC003" => Some(TOPICS[0]),
        "SEC004" => Some(TOPICS[1]),
        "SEC005" => Some(TOPICS[2]),
        "SEC006" => Some(TOPICS[3]),
        "SEC007" => Some(TOPICS[4]),
        "SEC008" | "SEC009" => Some(TOPICS[5]),
        _ => None,
    }
}

fn topic_rank(topic: &str) -> usize {
    TOPICS
        .iter()
        .position(|t| *t == topic)
        .unwrap_or(TOPICS.len())
}

fn order_rank(id: &str) -> usize {
    ORDER.iter().position(|o| *o == id).unwrap_or(ORDER.len())
}

/// Pure function: RawData -> Findings. No I/O — see ARCHITECTURE.md
/// "Testing Strategy".
///
/// Layout of the result: the top page first — the overview and anything of
/// Warning severity or above, worst first, so a problem is never buried in
/// a submenu — then the remaining findings grouped by topic.
pub fn analyze(data: &SecurityRawData, ctx: &Context) -> Vec<Finding> {
    let distro = ctx.distro.as_deref();

    let endpoints = listeners::endpoints(
        &data.listeners.sockets,
        &data.listeners.owners,
        data.listeners.ephemeral,
    );
    let summary = listeners::summarize(&endpoints);
    let fw_status = firewall::status(&data.firewall);
    let ssh_runtime = ssh::runtime_of(&endpoints);
    let hardening = access::evaluate_hardening(&data.hardening);

    let mut findings = vec![listeners::overview_finding(
        &endpoints,
        &summary,
        data.is_root,
    )];
    findings.extend(listeners::risk_findings(&endpoints, &fw_status));
    findings.push(firewall::finding(
        &data.firewall,
        &fw_status,
        &summary,
        distro,
    ));
    let ssh_findings = ssh::findings(&data.ssh, &ssh_runtime);
    let ssh_line = ssh_summary(&data.ssh, &ssh_runtime, &ssh_findings);
    findings.extend(ssh_findings);
    findings.push(access::mac_finding(&data.mac, distro));
    findings.push(access::hardening_finding(&hardening));
    findings.push(accounts::accounts_finding(&data.accounts));
    findings.push(accounts::files_finding(&data.files));

    let lines = OverviewLines {
        network: network_summary(&summary),
        firewall: firewall_summary(&fw_status),
        ssh: ssh_line,
        access: data.mac.summary(),
        hardening: hardening_summary(&hardening),
        accounts: accounts_summary(&findings),
        files: files_summary(&findings),
    };
    findings.insert(0, overview_finding(&findings, &lines, data.is_root));

    for f in &mut findings {
        f.instance = if f.id == "SEC001" || f.severity >= Severity::Warning {
            None
        } else {
            topic_of(&f.id).map(str::to_string)
        };
    }
    findings.sort_by_key(|f| {
        (
            f.instance.is_some(),
            f.instance.as_deref().map(topic_rank).unwrap_or(0),
            f.id != "SEC001", // the overview leads its page
            Reverse(f.severity),
            order_rank(&f.id),
        )
    });
    findings
}

// ---------------------------------------------------------------------------
// Overview
// ---------------------------------------------------------------------------

struct OverviewLines {
    network: String,
    firewall: String,
    ssh: String,
    access: String,
    hardening: String,
    accounts: String,
    files: String,
}

fn network_summary(s: &ListenerSummary) -> String {
    if s.reachable == 0 {
        return format!(
            "nothing reachable from the network ({} local only)",
            s.loopback_only
        );
    }
    let risky = if s.exposed_risks > 0 {
        format!(", {} risky", s.exposed_risks)
    } else {
        String::new()
    };
    format!(
        "{} reachable from the network{risky}, {} local only",
        s.reachable, s.loopback_only
    )
}

fn firewall_summary(status: &FirewallStatus) -> String {
    match status {
        FirewallStatus::Active { via } => format!("active ({})", via.join("; ")),
        FirewallStatus::NotDetected { verified: true } => "none (rules read)".to_string(),
        FirewallStatus::NotDetected { verified: false } => {
            "none detected (rules not readable without root)".to_string()
        }
        FirewallStatus::Unknown => "unknown".to_string(),
    }
}

fn ssh_summary(info: &ssh::SshInfo, rt: &SshRuntime, findings: &[Finding]) -> String {
    if findings.is_empty() {
        return if info.installed {
            "installed, not configured".to_string()
        } else {
            "no SSH server".to_string()
        };
    }
    let state = if !rt.listening {
        "not running"
    } else if rt.reachable {
        "running, reachable"
    } else {
        "running, local only"
    };
    let worst = findings
        .iter()
        .map(|f| f.severity)
        .max()
        .unwrap_or(Severity::Info);
    if worst >= Severity::Warning {
        format!("{state}; worst issue: {worst}")
    } else {
        format!("{state}; no serious issue")
    }
}

fn hardening_summary(r: &access::HardeningReport) -> String {
    if r.readable == 0 {
        return "not readable".to_string();
    }
    let important = r
        .weak
        .iter()
        .filter(|w| w.check.severity >= Severity::Warning)
        .count();
    let optional = r.weak.len() - important;
    format!("{important} weakness(es), {optional} optional hardening")
}

fn finding_summary<'a>(findings: &'a [Finding], id: &str) -> Option<&'a Finding> {
    findings.iter().find(|f| f.id == id)
}

fn accounts_summary(findings: &[Finding]) -> String {
    match finding_summary(findings, "SEC008") {
        Some(f) if f.severity >= Severity::Warning => {
            format!("problem found ({})", f.severity)
        }
        Some(_) => "no problem found".to_string(),
        None => "not checked".to_string(),
    }
}

fn files_summary(findings: &[Finding]) -> String {
    match finding_summary(findings, "SEC009") {
        Some(f) => {
            let problems = f
                .evidence
                .iter()
                .find(|(k, _)| k == "problems")
                .map(|(_, v)| v.as_str())
                .unwrap_or("0");
            if problems == "0" {
                "all as expected".to_string()
            } else {
                format!("{problems} problem(s)")
            }
        }
        None => "not checked".to_string(),
    }
}

/// SEC001 — the top page: one line per area, and which findings need
/// attention.
fn overview_finding(findings: &[Finding], lines: &OverviewLines, is_root: bool) -> Finding {
    let mut attention: Vec<&Finding> = findings
        .iter()
        .filter(|f| f.severity >= Severity::Warning)
        .collect();
    attention.sort_by_key(|f| Reverse(f.severity));

    let mut text = String::new();
    if attention.is_empty() {
        text.push_str(
            "Nothing needs attention: no exposed risky service, no weak SSH setting, no \
             dangerous permission or account, and no serious kernel weakness was found.",
        );
    } else {
        text.push_str(&format!(
            "{} finding(s) need attention, worst first:\n",
            attention.len()
        ));
        for f in attention.iter().take(8) {
            text.push_str(&format!(
                "\n  [{}] {}",
                f.severity.to_string().to_uppercase(),
                f.title
            ));
        }
        if attention.len() > 8 {
            text.push_str(&format!("\n  ... and {} more", attention.len() - 8));
        }
    }
    text.push_str(
        "\n\nEvery check is read-only. A security audit shows what is configured and what is \
         reachable from here; it cannot see the router, the cloud security group or the \
         network policy in front of the machine.",
    );
    if !is_root {
        text.push_str(
            "\n\nLinuxDoctor is running without root, so some things were out of sight: which \
             program owns other users' sockets, the firewall rules themselves, password \
             hashes in /etc/shadow and AppArmor's profile list. Run it with sudo for the \
             complete picture; the checks that could not run say so in their own finding.",
        );
    }

    Finding::builder(
        "SEC001",
        "Security Overview",
        Category::Security,
        Severity::Info,
        Confidence::direct_observation(),
    )
    .evidence(
        "running_as",
        if is_root { "root" } else { "unprivileged user" },
    )
    .evidence("network", lines.network.clone())
    .evidence("firewall", lines.firewall.clone())
    .evidence("ssh_server", lines.ssh.clone())
    .evidence("access_control", lines.access.clone())
    .evidence("hardening", lines.hardening.clone())
    .evidence("accounts", lines.accounts.clone())
    .evidence("sensitive_files", lines.files.clone())
    .explanation(text)
    .build()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::modules::security::access::{AppArmorInfo, HardeningData, MacInfo, CHECKS};
    use crate::modules::security::accounts::{
        parse_group, parse_passwd, AccountsData, FileObservation, ShadowAccess,
    };
    use crate::modules::security::collect::ListenerData;
    use crate::modules::security::firewall::FirewallData;
    use crate::modules::security::listeners::{Owner, Proto, Socket};
    use crate::modules::security::ssh::{SshConfig, SshInfo};
    use std::collections::HashMap;
    use std::net::{IpAddr, Ipv4Addr};

    fn ctx(distro: Option<&str>) -> Context {
        Context {
            hostname: "test".into(),
            kernel_version: "test".into(),
            distro: distro.map(str::to_string),
            architecture: "x86_64".into(),
            cpu_count: 4,
            mem_total_kb: 16_000_000,
            boot_time_unix: 0,
        }
    }

    fn socket(port: u16, addr: [u8; 4], inode: u64) -> Socket {
        Socket {
            proto: Proto::Tcp,
            addr: IpAddr::V4(Ipv4Addr::from(addr)),
            port,
            uid: 0,
            inode,
        }
    }

    fn owner(pid: u32, name: &str) -> Owner {
        Owner {
            pid,
            name: name.into(),
        }
    }

    fn hardening_ok() -> HardeningData {
        let mut readings: Vec<(String, Option<String>)> = CHECKS
            .iter()
            .map(|c| (c.key.to_string(), Some(c.wanted.to_string())))
            .collect();
        readings.push(("net.ipv4.ip_forward".into(), Some("0".into())));
        HardeningData { readings }
    }

    fn good_files() -> Vec<FileObservation> {
        ["/etc/passwd", "/etc/group"]
            .iter()
            .map(|p| FileObservation {
                path: p.to_string(),
                mode: 0o644,
                uid: 0,
                gid: 0,
            })
            .collect()
    }

    /// A well-kept server: SSH with keys only, a firewall, SELinux
    /// enforcing, hardened sysctls, clean accounts and permissions.
    fn healthy() -> SecurityRawData {
        let ssh_cfg = SshConfig {
            files: vec!["/etc/ssh/sshd_config".into()],
            directives: vec![
                ("permitrootlogin".into(), "no".into()),
                ("passwordauthentication".into(), "no".into()),
            ],
            ..Default::default()
        };
        let mut owners = HashMap::new();
        owners.insert(1, owner(800, "sshd"));
        SecurityRawData {
            is_root: true,
            listeners: ListenerData {
                sockets: vec![socket(22, [0, 0, 0, 0], 1), socket(631, [127, 0, 0, 1], 2)],
                owners,
                ..Default::default()
            },
            firewall: FirewallData {
                is_root: true,
                units: Some(vec![("ufw".into(), true)]),
                ..Default::default()
            },
            ssh: SshInfo {
                installed: true,
                config: Some(ssh_cfg),
                read_error: None,
            },
            mac: MacInfo {
                lsm: Some(vec!["apparmor".into()]),
                apparmor: AppArmorInfo {
                    enabled: Some(true),
                    enforce: Some(30),
                    complain: Some(0),
                },
                ..Default::default()
            },
            hardening: hardening_ok(),
            accounts: AccountsData {
                passwd: Some(parse_passwd(
                    "root:x:0:0:root:/root:/bin/bash\nalice:x:1000:1000::/home/alice:/bin/bash\n",
                )),
                shadow: ShadowAccess::Readable(vec![]),
                groups: Some(parse_group("sudo:x:27:alice\n")),
            },
            files: good_files(),
        }
    }

    fn ids(f: &[Finding]) -> Vec<&str> {
        f.iter().map(|x| x.id.as_str()).collect()
    }

    #[test]
    fn healthy_server_is_all_info_with_the_overview_on_top() {
        let f = analyze(&healthy(), &ctx(Some("Ubuntu 24.04")));
        assert!(
            f.iter().all(|x| x.severity == Severity::Info),
            "{:?}",
            f.iter().map(|x| (&x.id, x.severity)).collect::<Vec<_>>()
        );
        assert_eq!(f[0].id, "SEC001");
        assert!(f[0].instance.is_none());
        assert!(f[0].explanation.contains("Nothing needs attention"));
        for id in [
            "SEC002", "SEC004", "SEC005", "SEC006", "SEC007", "SEC008", "SEC009",
        ] {
            assert!(ids(&f).contains(&id), "{id} missing: {:?}", ids(&f));
        }
        assert!(!ids(&f).contains(&"SEC003"), "no risky service");
    }

    #[test]
    fn info_findings_live_on_their_topic_pages_in_topic_order() {
        let f = analyze(&healthy(), &ctx(None));
        let pages: Vec<Option<&str>> = f.iter().map(|x| x.instance.as_deref()).collect();
        assert_eq!(pages[0], None);
        let topics: Vec<&str> = pages.iter().flatten().copied().collect();
        let ranks: Vec<usize> = topics.iter().map(|t| topic_rank(t)).collect();
        let mut sorted = ranks.clone();
        sorted.sort_unstable();
        assert_eq!(ranks, sorted);
        assert!(topics.contains(&"Listening services"));
        assert!(topics.contains(&"Accounts & files"));
    }

    #[test]
    fn problems_move_to_the_top_page_worst_first() {
        let mut d = healthy();
        d.listeners.sockets.push(socket(23, [0, 0, 0, 0], 3)); // telnet
        d.listeners.sockets.push(socket(6379, [0, 0, 0, 0], 4)); // redis
        d.files.push(FileObservation {
            path: "/etc/shadow".into(),
            mode: 0o644,
            uid: 0,
            gid: 0,
        });
        let f = analyze(&d, &ctx(None));
        let top: Vec<(&str, Severity)> = f
            .iter()
            .take_while(|x| x.instance.is_none())
            .map(|x| (x.id.as_str(), x.severity))
            .collect();
        assert_eq!(top[0].0, "SEC001");
        assert_eq!(top[1], ("SEC009", Severity::Critical));
        assert_eq!(top[2], ("SEC003", Severity::Error));
        assert_eq!(top[3], ("SEC003", Severity::Warning));
        assert!(f[0].explanation.contains("3 finding(s) need attention"));
        assert!(f[0]
            .explanation
            .contains("[CRITICAL] Sensitive File Permissions"));
    }

    #[test]
    fn firewall_state_changes_the_confidence_of_the_exposure_findings() {
        let mut d = healthy();
        d.listeners.sockets.push(socket(6379, [0, 0, 0, 0], 4));
        let with_fw = analyze(&d, &ctx(None));
        let redis = |f: &[Finding]| {
            f.iter()
                .find(|x| x.id == "SEC003")
                .unwrap()
                .confidence
                .percent
        };
        d.firewall.units = Some(vec![("ufw".into(), false)]);
        let without = analyze(&d, &ctx(None));
        assert!(redis(&without) > redis(&with_fw));
        let fw = without.iter().find(|x| x.id == "SEC004").unwrap();
        assert_eq!(
            fw.severity,
            Severity::Warning,
            "redis is reachable and nothing blocks it"
        );
    }

    #[test]
    fn a_machine_without_ssh_has_no_ssh_finding_and_says_so_in_the_overview() {
        let mut d = healthy();
        d.ssh = SshInfo::default();
        d.listeners.sockets.retain(|s| s.port != 22);
        let f = analyze(&d, &ctx(None));
        assert!(!ids(&f).contains(&"SEC005"));
        assert!(f[0]
            .evidence
            .iter()
            .any(|(k, v)| k == "ssh_server" && v == "no SSH server"));
    }

    #[test]
    fn non_root_runs_say_what_was_out_of_sight() {
        let mut d = healthy();
        d.is_root = false;
        let f = analyze(&d, &ctx(None));
        assert!(f[0].explanation.contains("running without root"));
        assert!(f[0]
            .evidence
            .iter()
            .any(|(k, v)| k == "running_as" && v == "unprivileged user"));
        let as_root = analyze(&healthy(), &ctx(None));
        assert!(!as_root[0].explanation.contains("running without root"));
    }

    #[test]
    fn overview_has_one_line_per_area() {
        let f = analyze(&healthy(), &ctx(None));
        let keys: Vec<&str> = f[0].evidence.iter().map(|(k, _)| k.as_str()).collect();
        assert_eq!(
            keys,
            vec![
                "running_as",
                "network",
                "firewall",
                "ssh_server",
                "access_control",
                "hardening",
                "accounts",
                "sensitive_files"
            ]
        );
        let get = |k: &str| {
            f[0].evidence
                .iter()
                .find(|(key, _)| key == k)
                .unwrap()
                .1
                .clone()
        };
        assert_eq!(get("network"), "1 reachable from the network, 1 local only");
        assert_eq!(get("firewall"), "active (ufw)");
        assert_eq!(get("access_control"), "AppArmor active");
        assert_eq!(get("hardening"), "0 weakness(es), 0 optional hardening");
        assert_eq!(get("accounts"), "no problem found");
        assert_eq!(get("sensitive_files"), "all as expected");
    }

    #[test]
    fn all_findings_are_in_the_security_category_with_unique_ids_per_topic() {
        let f = analyze(&healthy(), &ctx(None));
        assert!(f.iter().all(|x| x.category == Category::Security));
        let mut seen = ids(&f);
        seen.sort_unstable();
        let n = seen.len();
        seen.dedup();
        assert_eq!(n, seen.len(), "no duplicate ids when nothing is risky");
    }

    #[test]
    fn empty_raw_data_still_produces_a_coherent_report() {
        let f = analyze(&SecurityRawData::default(), &ctx(None));
        assert_eq!(f[0].id, "SEC001");
        assert!(
            f.iter().all(|x| x.severity == Severity::Info),
            "nothing read, nothing to blame"
        );
        assert!(!f.iter().any(|x| x.explanation.is_empty()));
    }
}
