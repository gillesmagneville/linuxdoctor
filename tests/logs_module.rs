// SPDX-License-Identifier: GPL-3.0-only

//! Whole-module checks of the logs analysis on realistic machines built
//! from fixtures (no access to the host's logs), and runs of the real
//! binary against a fake `journalctl`.

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;
use std::process::Command;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use linuxdoctor::core::context::Context;
use linuxdoctor::core::engine::{ModuleRunResult, Report};
use linuxdoctor::models::{Finding, Severity};
use linuxdoctor::modules::logs::analyze::analyze;
use linuxdoctor::modules::logs::collect::{Gap, LogsRawData, Source};
use linuxdoctor::modules::logs::health::{JournalInfo, LogFile, LogFiles, Storage};
use linuxdoctor::modules::logs::journal::Entry;
use linuxdoctor::output::common::RenderMeta;
use linuxdoctor::output::{html, json, markdown, terminal};

const GIB: u64 = 1024 * 1024 * 1024;

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

fn source(name: &str, entries: Vec<Entry>) -> Option<Source> {
    Some(Source {
        name: name.into(),
        entries,
        truncated: false,
    })
}

fn failed_password(user: &str, ip: &str, port: u16) -> Entry {
    Entry::new(
        "sshd",
        &format!("Failed password for {user} from {ip} port {port} ssh2"),
    )
}

fn quiet_files() -> LogFiles {
    LogFiles {
        scanned: true,
        total_bytes: 80 * 1024 * 1024,
        largest: vec![LogFile {
            path: "/var/log/syslog".into(),
            size: 30 * 1024 * 1024,
        }],
        unreadable_dirs: 0,
        logrotate_installed: true,
    }
}

fn quiet_journal() -> JournalInfo {
    JournalInfo {
        storage: Storage::Persistent,
        size_bytes: Some(300 * 1024 * 1024),
        ..Default::default()
    }
}

/// A server nothing is wrong with.
fn quiet_server() -> LogsRawData {
    LogsRawData {
        is_root: true,
        auth: source(
            "systemd journal",
            vec![
                failed_password("root", "203.0.113.7", 40001),
                failed_password("admin", "203.0.113.7", 40002),
                Entry::new(
                    "sshd",
                    "Accepted publickey for deploy from 192.0.2.10 port 51000 ssh2: ED25519 SHA256:abc",
                ),
                Entry::new(
                    "sudo",
                    "pam_unix(sudo:auth): authentication failure; logname=deploy uid=1000 euid=0 tty=/dev/pts/0 ruser=deploy rhost=  user=deploy",
                ),
            ],
        ),
        errors: source(
            "systemd journal",
            vec![Entry::new("avahi-daemon", "Failed to read /proc/net/if_inet6")
                .with_priority(3)
                .with_unit("avahi-daemon.service")],
        ),
        kernel: source(
            "systemd journal",
            vec![
                Entry::new("kernel", "Linux version 6.8.0"),
                Entry::new("kernel", "ata1: SATA link up 6.0 Gbps"),
            ],
        ),
        journal: quiet_journal(),
        files: quiet_files(),
        gaps: Vec::new(),
    }
}

/// The opposite: a guessed password, a dying disk, a flooding service, a
/// log nobody rotates.
fn troubled_server() -> LogsRawData {
    let mut auth: Vec<Entry> = (0..25)
        .map(|i| failed_password("root", "203.0.113.7", 40000 + i))
        .collect();
    auth.push(Entry::new(
        "sshd",
        "Accepted password for deploy from 203.0.113.7 port 51234 ssh2",
    ));
    auth.push(Entry::new(
        "sudo",
        "mallory : user NOT in sudoers ; TTY=pts/2 ; PWD=/home/mallory ; USER=root ; COMMAND=/bin/bash",
    ));

    let errors: Vec<Entry> = (0..80)
        .map(|i| {
            Entry::new("app", &format!("request {i} failed: backend unreachable"))
                .with_priority(3)
                .with_unit("app.service")
        })
        .collect();

    LogsRawData {
        is_root: true,
        auth: source("systemd journal", auth),
        errors: source("systemd journal", errors),
        kernel: source(
            "systemd journal",
            vec![
                Entry::new(
                    "kernel",
                    "blk_update_request: I/O error, dev sda, sector 4096 op 0x0:(READ)",
                ),
                Entry::new("kernel", "EXT4-fs (sda1): Remounting filesystem read-only"),
                Entry::new(
                    "kernel",
                    "firefox[4321]: segfault at 0 ip 0000 sp 0000 error 4 in libxul.so[7f+1000]",
                ),
            ],
        ),
        journal: JournalInfo {
            storage: Storage::Persistent,
            size_bytes: Some(6 * GIB),
            suppressed: vec![("app.service".into(), 12_000)],
            ..Default::default()
        },
        files: LogFiles {
            scanned: true,
            total_bytes: 7 * GIB,
            largest: vec![LogFile {
                path: "/var/log/app/debug.log".into(),
                size: 6 * GIB,
            }],
            unreadable_dirs: 0,
            logrotate_installed: true,
        },
        gaps: Vec::new(),
    }
}

fn worst(findings: &[Finding]) -> Severity {
    findings.iter().map(|f| f.severity).max().unwrap()
}

fn by_id<'a>(findings: &'a [Finding], id: &str) -> Vec<&'a Finding> {
    findings.iter().filter(|f| f.id == id).collect()
}

#[test]
fn a_quiet_server_has_nothing_above_info() {
    let findings = analyze(&quiet_server(), &context("Debian GNU/Linux 12"));
    let bad: Vec<(&str, Severity)> = findings
        .iter()
        .filter(|f| f.severity > Severity::Info)
        .map(|f| (f.id.as_str(), f.severity))
        .collect();
    assert!(bad.is_empty(), "{bad:?}");
    assert_eq!(findings[0].id, "LOG001");
    assert!(findings[0].explanation.contains("Nothing needs attention"));
}

#[test]
fn a_troubled_server_is_flagged_everywhere() {
    let findings = analyze(&troubled_server(), &context("Debian GNU/Linux 12"));
    assert_eq!(worst(&findings), Severity::Critical);

    // A password login right after 25 failures from the same address.
    let break_in = by_id(&findings, "LOG003");
    assert_eq!(break_in.len(), 1);
    assert_eq!(break_in[0].severity, Severity::Critical);
    assert!(break_in[0].title.contains("deploy") && break_in[0].title.contains("203.0.113.7"));

    assert_eq!(by_id(&findings, "LOG002")[0].severity, Severity::Warning);
    assert_eq!(
        by_id(&findings, "LOG004")[0].severity,
        Severity::Info,
        "one refusal is not an attack"
    );
    assert_eq!(by_id(&findings, "LOG005")[0].severity, Severity::Warning);
    assert_eq!(by_id(&findings, "LOG006")[0].severity, Severity::Critical);
    assert_eq!(
        by_id(&findings, "LOG007")[0].severity,
        Severity::Info,
        "one segfault alone"
    );
    assert_eq!(by_id(&findings, "LOG008")[0].severity, Severity::Warning);
    assert_eq!(by_id(&findings, "LOG009")[0].severity, Severity::Warning);
}

#[test]
fn problems_lead_and_every_problem_comes_with_commands_to_fix_it() {
    for distro in ["Debian GNU/Linux 12", "Rocky Linux 9.3", "Arch Linux"] {
        let findings = analyze(&troubled_server(), &context(distro));
        assert_eq!(findings[0].id, "LOG001", "the overview opens the module");
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
        assert!(findings[0].explanation.contains("need attention"));
    }
}

#[test]
fn the_advice_follows_the_distribution_family() {
    let debian = analyze(&troubled_server(), &context("Ubuntu 24.04 LTS"));
    let rpm = analyze(&troubled_server(), &context("Rocky Linux 9.3"));
    let rec = |fs: &[Finding]| by_id(fs, "LOG002")[0].recommendation.clone().unwrap();
    assert!(
        rec(&debian).contains("apt install fail2ban")
            && rec(&debian).contains("ufw deny from 203.0.113.7")
    );
    assert!(rec(&rpm).contains("dnf install fail2ban") && rec(&rpm).contains("firewall-cmd"));
}

#[test]
fn suggestions_never_claim_that_the_tool_changed_anything() {
    for data in [quiet_server(), troubled_server()] {
        for f in analyze(&data, &context("Debian GNU/Linux 12")) {
            let text = format!("{} {}", f.explanation, f.recommendation.unwrap_or_default());
            assert!(!text.contains("has been fixed"), "{}", f.id);
            assert!(!text.contains("LinuxDoctor changed"), "{}", f.id);
            assert!(!text.contains("LinuxDoctor has blocked"), "{}", f.id);
        }
    }
}

#[test]
fn identifiers_are_stable_and_documented() {
    let mut ids: Vec<String> = analyze(&troubled_server(), &context("Debian GNU/Linux 12"))
        .into_iter()
        .map(|f| f.id)
        .collect();
    ids.sort();
    ids.dedup();
    assert_eq!(
        ids,
        [
            "LOG001", "LOG002", "LOG003", "LOG004", "LOG005", "LOG006", "LOG007", "LOG008",
            "LOG009"
        ]
    );
}

#[test]
fn what_cannot_be_read_is_never_reported_as_clean() {
    let data = LogsRawData {
        is_root: false,
        gaps: vec![Gap {
            what: "systemd journal".into(),
            why: "the journal exists but this user may not read it".into(),
            group_fixes_it: true,
        }],
        journal: quiet_journal(),
        files: quiet_files(),
        ..Default::default()
    };
    let findings = analyze(&data, &context("Debian GNU/Linux 12"));
    let ids: Vec<&str> = findings.iter().map(|f| f.id.as_str()).collect();
    assert_eq!(ids, ["LOG001", "LOG008", "LOG009"]);
    let overview = &findings[0];
    assert!(overview.explanation.contains("could not be read"));
    assert!(overview.explanation.contains("not a clean one"));
    assert!(overview
        .recommendation
        .as_ref()
        .unwrap()
        .contains("usermod -aG adm,systemd-journal"));
}

// ----- hostile data through every renderer ----------------------------------

const MARKUP: &str = "<img src=x onerror=alert(1)>`|*_[x](javascript:alert(2))";
const ESCAPE: &str = "\u{1b}[2J\u{1b}]0;pwned\u{7}";

fn hostile_server() -> LogsRawData {
    let user_markup = MARKUP.to_string();
    let user_escape = format!("ro{ESCAPE}ot");
    let mut auth: Vec<Entry> = (0..25)
        .map(|i| failed_password(&user_markup, "203.0.113.7", 40000 + i))
        .collect();
    auth.extend((0..25).map(|i| failed_password(&user_escape, "198.51.100.9", 41000 + i)));
    auth.push(Entry::new(
        "sshd",
        &format!("Accepted password for {user_markup} from 203.0.113.7 port 51234 ssh2"),
    ));
    let mut data = troubled_server();
    data.auth = source("systemd journal", auth);
    data.errors = source(
        "systemd journal",
        (0..60)
            .map(|_| {
                Entry::new(&format!("x;reboot{ESCAPE}"), &format!("boom {MARKUP}"))
                    .with_priority(3)
                    .with_unit(&format!("evil{MARKUP}.service"))
            })
            .collect(),
    );
    data
}

fn report_of(findings: Vec<Finding>) -> Report {
    Report {
        context: context("Debian GNU/Linux 12"),
        results: vec![ModuleRunResult {
            module_id: "logs",
            findings,
            error: None,
            skipped: false,
            notes: Vec::new(),
        }],
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
                        None => rest = "",
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
fn hostile_log_content_cannot_inject_markup_or_terminal_commands() {
    let findings = analyze(&hostile_server(), &context("Debian GNU/Linux 12"));
    let report = report_of(findings.clone());
    let meta = RenderMeta::default();

    // HTML
    let page = html::render(&report, &meta);
    assert!(!page.contains("<img"), "raw tag in HTML");
    assert!(!page.contains("onerror=alert(1)>"));
    assert!(page.contains("&lt;img"));

    // Markdown: outside code, every `<` is escaped.
    let md = markdown::render(&report, &meta);
    let prose = outside_code(&md);
    for (i, _) in prose.match_indices('<') {
        assert!(
            prose[..i].ends_with('\\'),
            "unescaped `<` in Markdown prose: ...{}",
            &prose[i.saturating_sub(20)..(i + 20).min(prose.len())]
        );
    }

    // No terminal control character from the logs survives anywhere. (The
    // terminal renderer adds its own colors, so look for the attacker's
    // sequences, not for ESC itself.)
    let term = terminal::render(&report);
    for output in [&term, &md, &page, &json::render(&report).unwrap()] {
        assert!(
            !output.contains("\u{1b}[2J"),
            "clear-screen sequence reached the output"
        );
        assert!(
            !output.contains("\u{1b}]0;"),
            "title-change sequence reached the output"
        );
        assert!(!output.contains('\u{7}'), "bell reached the output");
    }
    // The text itself is still there, defanged.
    assert!(md.contains("ro?[2J?]0;pwned?ot"));
    for f in &findings {
        for text in [&f.title, &f.explanation] {
            assert!(!text.contains('\u{1b}'), "{}", f.id);
        }
    }

    // And nothing a stranger chose becomes part of a suggested command.
    for f in &findings {
        if let Some(rec) = &f.recommendation {
            assert!(!rec.contains("reboot"), "{}: {rec}", f.id);
            assert!(!rec.contains("<img"), "{}: {rec}", f.id);
            assert!(!rec.contains("onerror"), "{}: {rec}", f.id);
        }
    }
}

#[test]
fn every_format_renders_the_module() {
    let report = report_of(analyze(&troubled_server(), &context("Debian GNU/Linux 12")));
    let meta = RenderMeta::default();
    assert!(terminal::render(&report).contains("Possible Break-in"));
    assert!(markdown::render(&report, &meta).contains("LOG003"));
    assert!(html::render(&report, &meta).contains("LOG003"));
    let doc: serde_json::Value = serde_json::from_str(&json::render(&report).unwrap()).unwrap();
    assert_eq!(doc["results"][0]["module_id"], "logs");
    assert!(doc["results"][0]["findings"].as_array().unwrap().len() >= 9);
}

// ----- the real binary against a fake journalctl ----------------------------

/// Fake executables are written, then run by the binary under test. Writing
/// a file while another test forks can make an exec fail with "text file
/// busy"; taking turns removes that race.
static ONE_AT_A_TIME: Mutex<()> = Mutex::new(());

struct FakeBin {
    dir: PathBuf,
}

impl FakeBin {
    fn new(name: &str) -> Self {
        let dir = std::env::temp_dir().join(format!("linuxdoctor-{name}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        FakeBin { dir }
    }

    fn script(&self, program: &str, body: &str) {
        let path = self.dir.join(program);
        fs::write(&path, format!("#!/bin/sh\n{body}\n")).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o755)).unwrap();
    }

    fn path_env(&self) -> String {
        format!("{}:/usr/local/bin:/usr/bin:/bin", self.dir.display())
    }
}

impl Drop for FakeBin {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.dir);
    }
}

fn audit(bin: &FakeBin, extra: &[&str]) -> (Option<i32>, Duration, serde_json::Value) {
    let started = Instant::now();
    let output = Command::new(env!("CARGO_BIN_EXE_linuxdoctor"))
        .args(["audit", "--modules", "logs", "--output", "json"])
        .args(extra)
        .env("PATH", bin.path_env())
        .output()
        .expect("linuxdoctor starts");
    let json: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap_or_else(|e| {
        panic!(
            "stdout was not JSON ({e}): {}\nstderr: {}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        )
    });
    (output.status.code(), started.elapsed(), json)
}

fn json_lines(entries: &[(&str, &str, &str, &str)]) -> String {
    entries
        .iter()
        .map(|(identifier, priority, unit, message)| {
            let unit = if unit.is_empty() {
                String::new()
            } else {
                format!(r#","_SYSTEMD_UNIT":"{unit}""#)
            };
            format!(
                r#"{{"MESSAGE":"{message}","PRIORITY":"{priority}","SYSLOG_IDENTIFIER":"{identifier}"{unit}}}"#
            )
        })
        .collect::<Vec<_>>()
        .join("\n")
}

/// A journalctl that answers each of the module's four queries with
/// canned JSON.
fn fake_journalctl(bin: &FakeBin) {
    let mut auth: Vec<(&str, &str, &str, String)> = Vec::new();
    let messages: Vec<String> = (0..25)
        .map(|i| {
            format!(
                "Failed password for root from 203.0.113.7 port {} ssh2",
                40000 + i
            )
        })
        .collect();
    for m in &messages {
        auth.push(("sshd", "6", "", m.clone()));
    }
    let auth_rows: Vec<(&str, &str, &str, &str)> = auth
        .iter()
        .map(|(a, b, c, d)| (*a, *b, *c, d.as_str()))
        .collect();
    let mut auth_text = json_lines(&auth_rows);
    auth_text.push('\n');
    auth_text.push_str(&json_lines(&[
        (
            "sshd",
            "6",
            "",
            "Accepted password for deploy from 203.0.113.7 port 51234 ssh2",
        ),
        (
            "sudo",
            "5",
            "",
            "mallory : user NOT in sudoers ; TTY=pts/2 ; USER=root ; COMMAND=/bin/bash",
        ),
    ]));

    let err_rows: Vec<(&str, &str, &str, &str)> = (0..60)
        .map(|_| ("app", "3", "app.service", "backend unreachable"))
        .collect();
    let errors_text = json_lines(&err_rows);

    let kernel_text = json_lines(&[
        ("kernel", "6", "", "Linux version 6.8.0"),
        (
            "kernel",
            "3",
            "",
            "blk_update_request: I/O error, dev sda, sector 4096 op 0x0:(READ)",
        ),
        (
            "kernel",
            "3",
            "",
            "EXT4-fs (sda1): Remounting filesystem read-only",
        ),
    ]);
    let journald_text = json_lines(&[(
        "systemd-journald",
        "6",
        "systemd-journald.service",
        "Suppressed 5000 messages from app.service",
    )]);

    // Each query is recognised by the option only it uses.
    let body = format!(
        "case \" $* \" in\n\
         *\" -t \"*) cat <<'EOF'\n{auth_text}\nEOF\n;;\n\
         *\" -p \"*) cat <<'EOF'\n{errors_text}\nEOF\n;;\n\
         *\" -k \"*) cat <<'EOF'\n{kernel_text}\nEOF\n;;\n\
         *\" -u \"*) cat <<'EOF'\n{journald_text}\nEOF\n;;\n\
         esac"
    );
    bin.script("journalctl", &body);
}

fn module(report: &serde_json::Value) -> &serde_json::Value {
    &report["results"][0]
}

fn finding<'a>(report: &'a serde_json::Value, id: &str) -> &'a serde_json::Value {
    module(report)["findings"]
        .as_array()
        .unwrap()
        .iter()
        .find(|f| f["id"] == id)
        .unwrap_or_else(|| panic!("{id} missing"))
}

fn evidence<'a>(f: &'a serde_json::Value, key: &str) -> &'a str {
    f["evidence"]
        .as_array()
        .unwrap()
        .iter()
        .find(|e| e[0] == key)
        .map(|e| e[1].as_str().unwrap())
        .unwrap_or_else(|| panic!("evidence {key} missing"))
}

#[test]
fn the_real_binary_reads_journal_output_and_reports_what_it_means() {
    let _turn = ONE_AT_A_TIME.lock().unwrap_or_else(|e| e.into_inner());
    let bin = FakeBin::new("logs-journal");
    fake_journalctl(&bin);

    let (code, _, report) = audit(&bin, &["--fail-on", "never"]);
    assert_eq!(code, Some(0));
    assert!(module(&report)["error"].is_null());

    let break_in = finding(&report, "LOG003");
    assert_eq!(break_in["severity"], "critical");
    assert_eq!(evidence(break_in, "failed_attempts_before"), "25");

    let activity = finding(&report, "LOG002");
    assert_eq!(activity["severity"], "warning");
    assert_eq!(evidence(activity, "failed_attempts"), "25");
    assert_eq!(evidence(activity, "source"), "systemd journal");

    assert_eq!(evidence(finding(&report, "LOG004"), "sudo_refused"), "1");

    let errors = finding(&report, "LOG005");
    assert_eq!(errors["severity"], "warning");
    assert_eq!(evidence(errors, "errors"), "60");

    assert_eq!(finding(&report, "LOG006")["severity"], "critical");
    let journal = finding(&report, "LOG008");
    assert_eq!(journal["severity"], "warning");
    assert_eq!(evidence(journal, "dropped_messages"), "5000");
    assert!(
        !finding(&report, "LOG009").is_null(),
        "the log files are always examined"
    );
}

#[test]
fn the_exit_status_follows_the_logs_findings() {
    let _turn = ONE_AT_A_TIME.lock().unwrap_or_else(|e| e.into_inner());
    let bin = FakeBin::new("logs-gate");
    fake_journalctl(&bin);
    let (default_code, _, _) = audit(&bin, &[]);
    assert_eq!(
        default_code,
        Some(1),
        "a critical finding fails the default gate"
    );
    let (never, _, _) = audit(&bin, &["--fail-on", "never"]);
    assert_eq!(never, Some(0));
}

#[test]
fn a_journal_nobody_may_read_is_reported_not_hidden() {
    let _turn = ONE_AT_A_TIME.lock().unwrap_or_else(|e| e.into_inner());
    let bin = FakeBin::new("logs-denied");
    bin.script(
        "journalctl",
        "echo 'Hint: You are currently not seeing messages from other users and the system.' >&2\nexit 0",
    );
    let (_, _, report) = audit(&bin, &["--fail-on", "never"]);
    let overview = finding(&report, "LOG001");
    assert!(evidence(overview, "not_readable").contains("systemd journal"));
    assert_eq!(evidence(overview, "system_errors"), "not readable");
    assert!(overview["explanation"]
        .as_str()
        .unwrap()
        .contains("a quiet result for these is not a clean one"));
}

#[test]
fn a_hung_journalctl_costs_one_time_limit_and_is_reported_as_incomplete() {
    let _turn = ONE_AT_A_TIME.lock().unwrap_or_else(|e| e.into_inner());
    let bin = FakeBin::new("logs-hung");
    bin.script("journalctl", "sleep 30");
    let (_, elapsed, report) = audit(&bin, &["--timeout", "1", "--fail-on", "never"]);
    assert!(
        elapsed < Duration::from_secs(12),
        "the four queries run together and each is stopped after 1 s; took {elapsed:?}"
    );
    let notes = module(&report)["notes"].as_array().unwrap();
    assert!(
        !notes.is_empty(),
        "the report must say the data is incomplete"
    );
    assert!(notes
        .iter()
        .any(|n| n.as_str().unwrap().contains("journalctl")));
}

#[test]
fn the_real_module_runs_and_always_reports_its_overview_and_log_files() {
    let _turn = ONE_AT_A_TIME.lock().unwrap_or_else(|e| e.into_inner());
    let output = Command::new(env!("CARGO_BIN_EXE_linuxdoctor"))
        .args([
            "audit",
            "--modules",
            "logs",
            "--output",
            "json",
            "--fail-on",
            "never",
        ])
        .output()
        .expect("linuxdoctor starts");
    assert_eq!(
        output.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let report: serde_json::Value = serde_json::from_slice(&output.stdout).expect("JSON");
    assert!(module(&report)["error"].is_null());
    let ids: Vec<&str> = module(&report)["findings"]
        .as_array()
        .unwrap()
        .iter()
        .map(|f| f["id"].as_str().unwrap())
        .collect();
    // Whatever this host has, the overview and the two parts that need no
    // log access always exist; which others do depends on the machine.
    for always in ["LOG001", "LOG008", "LOG009"] {
        assert!(ids.contains(&always), "{always} missing from {ids:?}");
    }
    assert_eq!(ids[0], "LOG001");
}
