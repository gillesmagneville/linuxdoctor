// SPDX-License-Identifier: GPL-3.0-only

//! Whole-module checks of the security analysis on realistic machines, built
//! from fixtures (no access to the host), plus a run of the real binary.

use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr};
use std::process::Command;

use linuxdoctor::core::context::Context;
use linuxdoctor::core::engine::{ModuleRunResult, Report};
use linuxdoctor::models::{Finding, Severity};
use linuxdoctor::modules::security::access::{
    AppArmorInfo, HardeningData, MacInfo, SelinuxMode, CHECKS,
};
use linuxdoctor::modules::security::accounts::{
    parse_group, parse_passwd, parse_shadow, AccountsData, FileObservation, ShadowAccess,
};
use linuxdoctor::modules::security::analyze::analyze;
use linuxdoctor::modules::security::collect::{ListenerData, SecurityRawData};
use linuxdoctor::modules::security::firewall::{parse_nft_ruleset, FirewallData};
use linuxdoctor::modules::security::listeners::{Owner, Proto, Socket};
use linuxdoctor::modules::security::ssh::{parse_line, Line, SshConfig, SshInfo};
use linuxdoctor::output::common::RenderMeta;
use linuxdoctor::output::{html, json, markdown, terminal};

fn context(distro: &str) -> Context {
    Context {
        hostname: "web-01".into(),
        kernel_version: "6.8.0-test".into(),
        distro: Some(distro.into()),
        architecture: "x86_64".into(),
        cpu_count: 4,
        mem_total_kb: 16_384_000,
        boot_time_unix: 0,
    }
}

fn socket(proto: Proto, port: u16, addr: [u8; 4], inode: u64) -> Socket {
    Socket {
        proto,
        addr: IpAddr::V4(Ipv4Addr::from(addr)),
        port,
        uid: 0,
        inode,
    }
}

fn sshd_config(lines: &[&str]) -> SshConfig {
    let mut cfg = SshConfig {
        files: vec!["/etc/ssh/sshd_config".into()],
        ..Default::default()
    };
    for l in lines {
        if let Some(Line::Directive { key, value }) = parse_line(l) {
            cfg.directives.push((key, value));
        }
    }
    cfg
}

fn file(path: &str, mode: u32, uid: u32) -> FileObservation {
    FileObservation {
        path: path.into(),
        mode,
        uid,
        gid: 0,
    }
}

fn hardened_sysctls() -> HardeningData {
    let mut readings: Vec<(String, Option<String>)> = CHECKS
        .iter()
        .map(|c| (c.key.to_string(), Some(c.wanted.to_string())))
        .collect();
    readings.push(("net.ipv4.ip_forward".into(), Some("0".into())));
    HardeningData { readings }
}

/// A web server somebody looked after.
fn well_kept_server() -> SecurityRawData {
    let mut owners = HashMap::new();
    owners.insert(
        1,
        Owner {
            pid: 700,
            name: "sshd".into(),
        },
    );
    owners.insert(
        2,
        Owner {
            pid: 900,
            name: "nginx".into(),
        },
    );
    owners.insert(
        3,
        Owner {
            pid: 950,
            name: "postgres".into(),
        },
    );
    SecurityRawData {
        is_root: true,
        listeners: ListenerData {
            sockets: vec![
                socket(Proto::Tcp, 22, [0, 0, 0, 0], 1),
                socket(Proto::Tcp, 443, [0, 0, 0, 0], 2),
                socket(Proto::Tcp, 5432, [127, 0, 0, 1], 3),
            ],
            owners,
            ..Default::default()
        },
        firewall: FirewallData {
            is_root: true,
            units: Some(vec![("firewalld".into(), true)]),
            nft: Some(parse_nft_ruleset(
                "table inet firewalld {\n chain filter_INPUT {\n  type filter hook input priority 10; policy accept;\n  reject with icmpx type admin-prohibited\n }\n}\n",
            )),
            ..Default::default()
        },
        ssh: SshInfo {
            installed: true,
            config: Some(sshd_config(&[
                "PermitRootLogin no",
                "PasswordAuthentication no",
                "MaxAuthTries 3",
            ])),
            read_error: None,
        },
        mac: MacInfo {
            lsm: Some(vec!["selinux".into()]),
            selinux_runtime: Some(SelinuxMode::Enforcing),
            selinux_config: Some("enforcing".into()),
            ..Default::default()
        },
        hardening: hardened_sysctls(),
        accounts: AccountsData {
            passwd: Some(parse_passwd(
                "root:x:0:0:root:/root:/bin/bash\nnginx:x:990:990::/var/lib/nginx:/sbin/nologin\ndeploy:x:1000:1000::/home/deploy:/bin/bash\n",
            )),
            shadow: ShadowAccess::Readable(parse_shadow(
                "root:$6$a$b:19000::::::\nnginx:!!:19000::::::\ndeploy:$y$j9T$c$d:19000::::::\n",
            )),
            groups: Some(parse_group("wheel:x:10:deploy\n")),
        },
        files: vec![
            file("/etc/passwd", 0o644, 0),
            file("/etc/shadow", 0o000, 0),
            file("/etc/sudoers", 0o440, 0),
            file("/etc/ssh/sshd_config", 0o600, 0),
            file("/root", 0o550, 0),
            file("/tmp", 0o1777, 0),
        ],
    }
}

/// The opposite: everything that can be wrong, is.
fn neglected_server() -> SecurityRawData {
    let mut owners = HashMap::new();
    owners.insert(
        1,
        Owner {
            pid: 700,
            name: "sshd".into(),
        },
    );
    owners.insert(
        2,
        Owner {
            pid: 800,
            name: "telnetd".into(),
        },
    );
    owners.insert(
        3,
        Owner {
            pid: 810,
            name: "redis-server".into(),
        },
    );
    owners.insert(
        4,
        Owner {
            pid: 820,
            name: "dockerd".into(),
        },
    );
    let mut hardening = hardened_sysctls();
    for (k, v) in &mut hardening.readings {
        if k == "net.ipv4.tcp_syncookies" {
            *v = Some("0".into());
        }
    }
    SecurityRawData {
        is_root: true,
        listeners: ListenerData {
            sockets: vec![
                socket(Proto::Tcp, 22, [0, 0, 0, 0], 1),
                socket(Proto::Tcp, 23, [0, 0, 0, 0], 2),
                socket(Proto::Tcp, 6379, [0, 0, 0, 0], 3),
                socket(Proto::Tcp, 2375, [10, 0, 0, 5], 4),
            ],
            owners,
            ..Default::default()
        },
        firewall: FirewallData {
            is_root: true,
            units: Some(vec![("ufw".into(), false), ("firewalld".into(), false)]),
            nft: Some(Default::default()),
            ..Default::default()
        },
        ssh: SshInfo {
            installed: true,
            config: Some(sshd_config(&["PermitRootLogin yes", "PermitEmptyPasswords yes"])),
            read_error: None,
        },
        mac: MacInfo {
            lsm: Some(vec!["selinux".into()]),
            selinux_runtime: Some(SelinuxMode::Permissive),
            selinux_config: Some("enforcing".into()),
            apparmor: AppArmorInfo::default(),
        },
        hardening,
        accounts: AccountsData {
            passwd: Some(parse_passwd(
                "root:x:0:0:root:/root:/bin/bash\ntoor:x:0:0:backdoor:/root:/bin/bash\nguest::1001:1001::/home/guest:/bin/bash\n",
            )),
            shadow: ShadowAccess::Readable(parse_shadow("root:$1$old$hash:1::::::\n")),
            groups: None,
        },
        files: vec![
            file("/etc/passwd", 0o666, 0),
            file("/etc/shadow", 0o644, 0),
            file("/etc/sudoers", 0o440, 0),
            file("/tmp", 0o777, 0),
        ],
    }
}

fn worst(findings: &[Finding]) -> Severity {
    findings.iter().map(|f| f.severity).max().unwrap()
}

#[test]
fn a_well_kept_server_has_nothing_above_info() {
    let findings = analyze(&well_kept_server(), &context("Rocky Linux 9.3"));
    let bad: Vec<(&str, Severity)> = findings
        .iter()
        .filter(|f| f.severity > Severity::Info)
        .map(|f| (f.id.as_str(), f.severity))
        .collect();
    assert!(bad.is_empty(), "{bad:?}");
    assert_eq!(findings[0].id, "SEC001");
    assert!(findings[0].explanation.contains("Nothing needs attention"));
}

#[test]
fn a_neglected_server_is_flagged_everywhere() {
    let findings = analyze(&neglected_server(), &context("Rocky Linux 9.3"));
    assert_eq!(worst(&findings), Severity::Critical);

    let by_id = |id: &str| -> Vec<&Finding> { findings.iter().filter(|f| f.id == id).collect() };

    // Exposed services: telnet and the Docker API are errors, Redis a warning.
    let risks = by_id("SEC003");
    assert_eq!(risks.len(), 3);
    assert_eq!(
        risks
            .iter()
            .filter(|f| f.severity == Severity::Error)
            .count(),
        2
    );
    assert!(risks
        .iter()
        .any(|f| f.title.contains("Redis") && f.severity == Severity::Warning));

    // The firewall check agrees: nothing in front of them, rules were read.
    assert_eq!(by_id("SEC004")[0].severity, Severity::Warning);

    // SSH: empty passwords are critical.
    assert_eq!(by_id("SEC005")[0].severity, Severity::Critical);

    // SELinux switched off by hand.
    assert_eq!(by_id("SEC006")[0].severity, Severity::Warning);
    assert!(by_id("SEC006")[0].explanation.contains("setenforce 0"));

    // SYN cookies off.
    assert_eq!(by_id("SEC007")[0].severity, Severity::Warning);

    // Accounts: a second root and a passwordless login.
    let accounts = by_id("SEC008")[0];
    assert_eq!(accounts.severity, Severity::Critical);
    assert!(accounts.explanation.contains("toor"));
    assert!(accounts.explanation.contains("guest"));

    // Files: /etc/passwd world-writable, /etc/shadow world-readable, /tmp without sticky bit.
    let files = by_id("SEC009")[0];
    assert_eq!(files.severity, Severity::Critical);
    for needle in ["/etc/passwd", "/etc/shadow", "/tmp"] {
        assert!(files.explanation.contains(needle), "{needle}");
    }
}

#[test]
fn problems_lead_and_every_problem_comes_with_commands_to_fix_it() {
    let findings = analyze(&neglected_server(), &context("Ubuntu 24.04 LTS"));
    assert_eq!(findings[0].id, "SEC001", "the overview opens the module");
    let mut last = Severity::Critical;
    for f in findings[1..].iter().take_while(|f| f.instance.is_none()) {
        assert!(f.severity <= last, "worst first: {} after {:?}", f.id, last);
        last = f.severity;
        assert!(f.severity >= Severity::Warning);
        let rec = f
            .recommendation
            .as_ref()
            .unwrap_or_else(|| panic!("{} has no recommendation", f.id));
        assert!(rec.starts_with("1. "), "{} : {rec}", f.id);
    }
    // The overview lists what needs attention.
    assert!(findings[0].explanation.contains("need attention"));
}

#[test]
fn recommendations_never_contain_a_command_that_the_tool_could_have_run_itself() {
    // Suggestions only: no finding text claims that LinuxDoctor changed anything.
    for data in [well_kept_server(), neglected_server()] {
        for f in analyze(&data, &context("Debian GNU/Linux 12")) {
            let text = format!("{} {}", f.explanation, f.recommendation.unwrap_or_default());
            assert!(!text.contains("has been fixed"), "{}", f.id);
            assert!(!text.contains("LinuxDoctor changed"), "{}", f.id);
        }
    }
}

#[test]
fn identifiers_are_stable_and_documented() {
    let findings = analyze(&neglected_server(), &context("Debian GNU/Linux 12"));
    let mut ids: Vec<&str> = findings.iter().map(|f| f.id.as_str()).collect();
    ids.sort_unstable();
    ids.dedup();
    assert_eq!(
        ids,
        vec![
            "SEC001", "SEC002", "SEC003", "SEC004", "SEC005", "SEC006", "SEC007", "SEC008",
            "SEC009"
        ]
    );
}

// ----- the three document renderers must survive hostile machine data -------

const HOSTILE: &str = "<img src=x onerror=alert(1)>`|*_[x](javascript:alert(2))";

fn hostile_data() -> SecurityRawData {
    let mut d = neglected_server();
    // A program name, a user name and a configuration value an attacker controls.
    d.listeners.owners.insert(
        3,
        Owner {
            pid: 810,
            name: HOSTILE.into(),
        },
    );
    d.accounts.passwd = Some(parse_passwd(&format!(
        "root:x:0:0:root:/root:/bin/bash\n{HOSTILE}:x:0:0::/root:/bin/bash\n"
    )));
    d.ssh.config = Some(sshd_config(&[&format!("Ciphers 3des-cbc,{HOSTILE}")]));
    d
}

fn report_of(findings: Vec<Finding>) -> Report {
    Report {
        context: context("Debian GNU/Linux 12"),
        results: vec![ModuleRunResult {
            module_id: "security",
            findings,
            error: None,
            skipped: false,
            notes: Vec::new(),
        }],
    }
}

#[test]
fn hostile_names_cannot_inject_markup_in_html_or_markdown() {
    let report = report_of(analyze(&hostile_data(), &context("Debian GNU/Linux 12")));
    let meta = RenderMeta::default();

    let page = html::render(&report, &meta);
    assert!(!page.contains("<img"), "raw tag in HTML");
    assert!(!page.contains("onerror=alert(1)>"));
    assert!(page.contains("&lt;img"));

    let md = markdown::render(&report, &meta);
    // Outside code (fenced blocks and inline spans), every `<` must be escaped.
    let prose = outside_code(&md);
    assert!(
        md.contains("<img src=x"),
        "the hostile name should still be shown, inside code"
    );
    for (i, _) in prose.match_indices('<') {
        assert!(
            prose[..i].ends_with('\\'),
            "unescaped `<` in Markdown prose: ...{}",
            &prose[i.saturating_sub(20)..(i + 20).min(prose.len())]
        );
    }
}

/// The Markdown with fenced code blocks and inline code spans removed, i.e.
/// the part a Markdown reader would interpret.
fn outside_code(md: &str) -> String {
    let mut out = String::new();
    let mut fence: Option<String> = None;
    for line in md.lines() {
        let trimmed = line.trim_start();
        let ticks = trimmed.chars().take_while(|&c| c == '`').count();
        match &fence {
            Some(f) => {
                if ticks >= f.len() && trimmed[ticks..].trim().is_empty() {
                    fence = None;
                }
            }
            None if ticks >= 3 => fence = Some("`".repeat(ticks)),
            None => {
                let mut rest = line;
                while let Some(start) = rest.find('`') {
                    let run = rest[start..].chars().take_while(|&c| c == '`').count();
                    out.push_str(&rest[..start]);
                    let after = &rest[start + run..];
                    match after.find(&"`".repeat(run)) {
                        Some(end) => rest = &after[end + run..],
                        None => {
                            rest = "";
                        }
                    }
                }
                out.push_str(rest);
                out.push('\n');
            }
        }
    }
    out
}

#[test]
fn every_format_renders_the_module() {
    let report = report_of(analyze(
        &neglected_server(),
        &context("Debian GNU/Linux 12"),
    ));
    let meta = RenderMeta::default();
    assert!(terminal::render(&report).contains("Exposed Service"));
    assert!(markdown::render(&report, &meta).contains("SEC003"));
    assert!(html::render(&report, &meta).contains("SEC003"));
    let doc: serde_json::Value = serde_json::from_str(&json::render(&report).unwrap()).unwrap();
    assert_eq!(doc["results"][0]["module_id"], "security");
    assert!(doc["results"][0]["findings"].as_array().unwrap().len() >= 9);
}

// ----- the real binary on the real machine ----------------------------------

#[test]
fn the_real_module_runs_and_reports_the_same_nine_topics_on_any_host() {
    let out = Command::new(env!("CARGO_BIN_EXE_linuxdoctor"))
        .args([
            "audit",
            "--modules",
            "security",
            "--output",
            "json",
            "--fail-on",
            "never",
        ])
        .output()
        .expect("linuxdoctor starts");
    assert_eq!(
        out.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let doc: serde_json::Value = serde_json::from_slice(&out.stdout).expect("JSON");
    let result = &doc["results"][0];
    assert_eq!(result["module_id"], "security");
    assert!(result["error"].is_null(), "{}", result["error"]);
    let ids: Vec<&str> = result["findings"]
        .as_array()
        .unwrap()
        .iter()
        .map(|f| f["id"].as_str().unwrap())
        .collect();
    for always in [
        "SEC001", "SEC002", "SEC004", "SEC006", "SEC007", "SEC008", "SEC009",
    ] {
        assert!(ids.contains(&always), "{always} missing from {ids:?}");
    }
    assert_eq!(ids[0], "SEC001");
}
