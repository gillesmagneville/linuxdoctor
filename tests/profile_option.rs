// SPDX-License-Identifier: GPL-3.0-only

//! Profiles, end to end.
//!
//! The first test uses the real CPU module on a heavily loaded machine and
//! checks what a profile is for: the same readings, an audit that no longer
//! fails for what is normal on that kind of machine. The rest start the real
//! binary, with a throwaway configuration directory, and check what the
//! person sees: the profile named in every format, the configuration file
//! and the command line choosing it, a mistake refused with status 2, a real
//! problem still reported and still failing, and `diff` saying so when two
//! reports were not written with the same profile.

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;
use std::process::{Command, Output};

use linuxdoctor::core::context::Context;
use linuxdoctor::core::engine::{ModuleRunResult, Report};
use linuxdoctor::core::gate::{self, DEFAULT_FAIL_ON};
use linuxdoctor::models::Severity;
use linuxdoctor::modules::cpu::analyze::analyze;
use linuxdoctor::modules::cpu::collect::{CpuRawData, CpuSocket};
use linuxdoctor::profile::{self, Profile};

// ----- the library, on a busy node ------------------------------------------------------------

fn busy_node_report() -> Report {
    let context = Context {
        hostname: "node042".into(),
        kernel_version: "6.8.0-test".into(),
        distro: Some("Test Linux".into()),
        architecture: "x86_64".into(),
        cpu_count: 4,
        mem_total_kb: 16_384_000,
        boot_time_unix: 0,
    };
    // Four CPUs and a load of nine, for a quarter of an hour: a node running
    // jobs, or a machine in trouble -- the load average cannot tell.
    let data = CpuRawData {
        load_1m: 9.10,
        load_5m: 8.50,
        load_15m: 7.90,
        sockets: vec![CpuSocket {
            physical_id: 0,
            model_name: None,
            cores: 4,
            threads: 4,
            logical_cpus: vec![0, 1, 2, 3],
        }],
        isolcpus: vec![],
        nohz_full: vec![],
        cgroup_isolated: vec![],
        system_slice_excluded: vec![],
        offline_cpus: vec![],
    };
    Report {
        profile: None,
        results: vec![ModuleRunResult {
            module_id: "cpu",
            findings: analyze(&data, &context),
            error: None,
            skipped: false,
            notes: vec![],
        }],
        context,
    }
}

fn severity_of(report: &Report, id: &str) -> Severity {
    report.results[0]
        .findings
        .iter()
        .find(|f| f.id == id)
        .unwrap_or_else(|| panic!("{id} not found"))
        .severity
}

#[test]
fn the_rules_name_findings_the_cpu_module_really_produces() {
    // A rule for an id nobody produces would be a profile that silently does
    // nothing. The busy node produces both of the hpc profile's findings.
    let report = busy_node_report();
    for rule in profile::rules(Profile::Hpc) {
        assert!(
            report.results[0].findings.iter().any(|f| f.id == rule.id),
            "{} is not produced by the cpu module",
            rule.id
        );
    }
}

#[test]
fn a_busy_node_fails_the_audit_without_a_profile_and_passes_with_hpc() {
    let mut report = busy_node_report();
    assert_eq!(severity_of(&report, "CPU002"), Severity::Error);
    assert_eq!(severity_of(&report, "CPU003"), Severity::Critical);
    assert!(gate::evaluate(&report, Some(DEFAULT_FAIL_ON)).failed());

    let lowered = profile::apply(&mut report, Profile::Hpc);
    assert_eq!(lowered, 2);
    assert_eq!(severity_of(&report, "CPU002"), Severity::Info);
    assert_eq!(severity_of(&report, "CPU003"), Severity::Info);
    assert!(
        !gate::evaluate(&report, Some(DEFAULT_FAIL_ON)).failed(),
        "the exit status follows the severities the report shows"
    );
}

#[test]
fn the_load_figures_and_the_way_back_stay_in_the_adjusted_finding() {
    let mut report = busy_node_report();
    profile::apply(&mut report, Profile::Hpc);
    let finding = report.results[0]
        .findings
        .iter()
        .find(|f| f.id == "CPU003")
        .unwrap();
    let evidence = |key: &str| {
        finding
            .evidence
            .iter()
            .find(|(k, _)| k == key)
            .map(|(_, v)| v.as_str())
    };
    // What the module saw is untouched...
    assert_eq!(evidence("load_1m"), Some("9.10"));
    assert_eq!(evidence("load_15m"), Some("7.90"));
    // ...and what the profile did is written down.
    assert_eq!(evidence("severity_before_profile"), Some("critical"));
    assert_eq!(evidence("profile"), Some("hpc"));
    assert!(finding.explanation.contains("Profile hpc"));
    assert!(finding.explanation.contains("instead of critical"));
}

#[test]
fn the_other_findings_of_the_module_are_left_alone() {
    let mut report = busy_node_report();
    let before: Vec<(String, Severity)> = report.results[0]
        .findings
        .iter()
        .map(|f| (f.id.clone(), f.severity))
        .collect();
    profile::apply(&mut report, Profile::Hpc);
    for (finding, (id, severity)) in report.results[0].findings.iter().zip(before) {
        if id != "CPU002" && id != "CPU003" {
            assert_eq!(finding.severity, severity, "{id}");
        }
    }
}

// ----- the binary ------------------------------------------------------------------------------

/// A throwaway home for the configuration file, with a directory of fake
/// tools that go first on PATH.
struct Sandbox {
    root: PathBuf,
}

impl Sandbox {
    fn new(name: &str) -> Sandbox {
        let root =
            std::env::temp_dir().join(format!("linuxdoctor-profile-{name}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&root);
        fs::create_dir_all(root.join("xdg/linuxdoctor")).unwrap();
        fs::create_dir_all(root.join("bin")).unwrap();
        let sandbox = Sandbox { root };
        for tool in ["smartctl", "docker", "podman"] {
            sandbox.tool(tool, "exit 127");
        }
        sandbox
    }

    fn tool(&self, program: &str, body: &str) {
        let path = self.root.join("bin").join(program);
        fs::write(&path, format!("#!/bin/sh\n{body}\n")).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o755)).unwrap();
    }

    /// One file system that is nearly full: the storage audit finds an
    /// Error or worse, so the default exit status is 1.
    fn full_disk(&self) {
        self.tool(
            "df",
            r#"case "$1" in
  -kPT)
    printf 'Filesystem Type 1024-blocks Used Available Capacity Mounted on\n'
    printf '/dev/sdb1 ext4 1000000 970000 30000 97%% /mnt/data\n' ;;
  -iPT)
    printf 'Filesystem Type Inodes IUsed IFree IUse%% Mounted on\n'
    printf '/dev/sdb1 ext4 1000 10 990 1%% /mnt/data\n' ;;
  *) exit 1 ;;
esac"#,
        );
    }

    fn config(&self, content: &str) {
        fs::write(self.root.join("xdg/linuxdoctor/config.toml"), content).unwrap();
    }

    fn file(&self, name: &str, content: &str) -> String {
        let path = self.root.join(name);
        fs::write(&path, content).unwrap();
        path.to_string_lossy().into_owned()
    }

    fn run(&self, args: &[&str]) -> Output {
        Command::new(env!("CARGO_BIN_EXE_linuxdoctor"))
            .env("XDG_CONFIG_HOME", self.root.join("xdg"))
            .env("HOME", "/nonexistent")
            .env(
                "PATH",
                format!(
                    "{}:/usr/local/bin:/usr/bin:/bin",
                    self.root.join("bin").display()
                ),
            )
            .args(args)
            .output()
            .expect("linuxdoctor binary should start")
    }
}

impl Drop for Sandbox {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.root);
    }
}

fn stdout(o: &Output) -> String {
    String::from_utf8_lossy(&o.stdout).to_string()
}

fn stderr(o: &Output) -> String {
    String::from_utf8_lossy(&o.stderr).to_string()
}

fn json(o: &Output) -> serde_json::Value {
    serde_json::from_slice(&o.stdout)
        .unwrap_or_else(|e| panic!("not JSON ({e}):\n{}\n{}", stdout(o), stderr(o)))
}

/// Only the memory module runs: always there, quick, and the same on any
/// host. `--fail-on never` so that the health of the host running the tests
/// cannot change the exit status.
fn audit(sandbox: &Sandbox, extra: &[&str]) -> Output {
    let mut args = vec!["audit", "--modules", "memory", "--fail-on", "never"];
    args.extend_from_slice(extra);
    sandbox.run(&args)
}

// ----- the profile is recorded where the report is read -----------------------------------------

#[test]
fn without_a_profile_no_report_mentions_one() {
    let sandbox = Sandbox::new("none");
    let o = audit(&sandbox, &["--output", "json"]);
    assert!(json(&o).get("profile").is_none(), "{}", stdout(&o));

    // The word can appear in a finding's own text; what must not appear is
    // the report saying which profile it was written with.
    let o = audit(&sandbox, &[]);
    let first = stdout(&o).lines().next().unwrap().to_string();
    assert!(!first.contains("profile"), "{first}");
    let o = audit(&sandbox, &["--output", "markdown"]);
    assert!(!stdout(&o).contains("**Profile:**"), "{}", stdout(&o));
    let o = audit(&sandbox, &["--output", "html"]);
    assert!(!stdout(&o).contains("<dt>Profile</dt>"), "{}", stdout(&o));
}

#[test]
fn the_json_report_records_the_profile_right_after_the_version() {
    let sandbox = Sandbox::new("json");
    let o = audit(&sandbox, &["--output", "json", "--profile", "hpc"]);
    assert_eq!(o.status.code(), Some(0), "{}", stderr(&o));
    let text = stdout(&o);
    let lines: Vec<&str> = text.lines().map(str::trim).collect();
    assert!(lines[1].starts_with("\"schema_version\":"), "{}", lines[1]);
    assert!(
        lines[2].starts_with("\"linuxdoctor_version\":"),
        "{}",
        lines[2]
    );
    assert_eq!(lines[3], "\"profile\": \"hpc\",");
    assert_eq!(
        json(&o)["schema_version"],
        1,
        "adding a key is not a new layout"
    );
}

#[test]
fn the_terminal_markdown_and_html_reports_name_the_profile() {
    let sandbox = Sandbox::new("formats");

    let o = audit(&sandbox, &["--profile", "hpc"]);
    let first = stdout(&o).lines().next().unwrap().to_string();
    assert!(first.contains("LinuxDoctor"), "{first}");
    assert!(first.contains("profile hpc"), "{first}");

    let o = audit(&sandbox, &["--profile", "hpc", "--output", "markdown"]);
    let md = stdout(&o);
    assert!(
        md.lines()
            .nth(3)
            .is_some_and(|l| l.starts_with("- **Profile:** hpc")),
        "{md}"
    );

    let o = audit(&sandbox, &["--profile", "hpc", "--output", "html"]);
    assert!(
        stdout(&o).contains("<dt>Profile</dt><dd>hpc"),
        "{}",
        stdout(&o)
    );
}

// ----- the profile is chosen, never guessed ------------------------------------------------------

#[test]
fn the_configuration_file_can_choose_the_profile_and_no_config_ignores_it() {
    let sandbox = Sandbox::new("config");
    sandbox.config("profile = \"hpc\"\n");

    let o = audit(&sandbox, &["--output", "json"]);
    assert_eq!(json(&o)["profile"], "hpc", "{}", stderr(&o));

    // For once, without the file: no profile.
    let o = sandbox.run(&[
        "--no-config",
        "audit",
        "--modules",
        "memory",
        "--output",
        "json",
        "--fail-on",
        "never",
    ]);
    assert!(json(&o).get("profile").is_none(), "{}", stdout(&o));
}

#[test]
fn a_profile_the_machine_seems_to_suit_is_never_chosen_for_it() {
    // No setting, no option: nothing is detected, however the host looks.
    let sandbox = Sandbox::new("never-guessed");
    let o = audit(&sandbox, &["--output", "json"]);
    assert!(json(&o).get("profile").is_none(), "{}", stdout(&o));
}

#[test]
fn an_unknown_profile_is_a_usage_error_that_lists_the_ones_that_exist() {
    let sandbox = Sandbox::new("unknown");
    for word in ["desktop", "HPC", ""] {
        let o = audit(&sandbox, &["--profile", word]);
        assert_eq!(o.status.code(), Some(2), "{word:?}: {}", stderr(&o));
        assert!(stdout(&o).is_empty(), "nothing is run: {}", stdout(&o));
        assert!(stderr(&o).contains("hpc"), "{word:?}: {}", stderr(&o));
    }
}

#[test]
fn an_unknown_profile_in_the_file_stops_the_program_with_status_2() {
    let sandbox = Sandbox::new("bad-file");
    sandbox.config("timeout = 5\nprofile = \"desktop\"\n");
    let o = audit(&sandbox, &[]);
    assert_eq!(o.status.code(), Some(2), "{}", stderr(&o));
    assert!(stdout(&o).is_empty(), "{}", stdout(&o));
    let message = stderr(&o);
    assert!(message.contains("config.toml"), "{message}");
    assert!(message.contains("line 2"), "{message}");
    assert!(message.contains("`desktop` is not one of"), "{message}");
    assert!(message.contains("hpc"), "{message}");
}

#[test]
fn diff_does_not_take_a_profile() {
    let sandbox = Sandbox::new("diff-option");
    let o = sandbox.run(&["diff", "a.json", "b.json", "--profile", "hpc"]);
    assert_eq!(o.status.code(), Some(2), "{}", stderr(&o));
}

#[test]
fn under_hpc_the_load_findings_are_never_above_info_whatever_the_host() {
    // The only end-to-end check that the binary applies the profile: the
    // host's own load cannot be set by a test, so on an idle host this holds
    // trivially, and it earns its keep on a busy one (a developer's machine
    // in the middle of a build, a loaded CI runner). It can never fail on a
    // correct build.
    let sandbox = Sandbox::new("load");
    let o = sandbox.run(&[
        "audit",
        "--modules",
        "cpu",
        "--fail-on",
        "never",
        "--output",
        "json",
        "--profile",
        "hpc",
    ]);
    let report = json(&o);
    for finding in report["results"][0]["findings"].as_array().unwrap() {
        let id = finding["id"].as_str().unwrap();
        if id == "CPU002" || id == "CPU003" {
            assert_eq!(finding["severity"], "info", "{id}: {finding}");
        }
    }
}

// ----- a profile is not a way to look away ----------------------------------------------------------

#[test]
fn a_real_problem_is_still_reported_and_still_fails_under_a_profile() {
    let sandbox = Sandbox::new("full-disk");
    sandbox.full_disk();
    let args = ["audit", "--modules", "storage", "--output", "json"];

    let plain = sandbox.run(&args);
    assert_eq!(plain.status.code(), Some(1), "{}", stderr(&plain));

    let mut with_profile = args.to_vec();
    with_profile.extend_from_slice(&["--profile", "hpc"]);
    let profiled = sandbox.run(&with_profile);
    assert_eq!(profiled.status.code(), Some(1), "{}", stderr(&profiled));

    // The same findings at the same severities: this profile has nothing to
    // say about a full disk.
    let severities = |o: &Output| -> Vec<(String, String)> {
        json(o)["results"][0]["findings"]
            .as_array()
            .unwrap()
            .iter()
            .map(|f| {
                (
                    f["id"].as_str().unwrap().to_string(),
                    f["severity"].as_str().unwrap().to_string(),
                )
            })
            .collect()
    };
    assert_eq!(severities(&plain), severities(&profiled));
    assert!(
        severities(&profiled)
            .iter()
            .any(|(_, severity)| severity == "error" || severity == "critical"),
        "the full disk is at least an Error: {:?}",
        severities(&profiled)
    );
}

// ----- diff -----------------------------------------------------------------------------------------

#[test]
fn diff_says_when_two_reports_were_written_with_different_profiles() {
    let sandbox = Sandbox::new("diff");
    let write = |name: &str, extra: &[&str]| {
        let o = audit(&sandbox, &[&["--output", "json"], extra].concat());
        assert_eq!(o.status.code(), Some(0), "{}", stderr(&o));
        sandbox.file(name, &stdout(&o))
    };
    let plain = write("plain.json", &[]);
    let hpc = write("hpc.json", &["--profile", "hpc"]);
    let hpc_again = write("hpc2.json", &["--profile", "hpc"]);

    // The caveat never moves the exit status: it is about how far to trust
    // the comparison, not about the machine.
    let o = sandbox.run(&["diff", &plain, &hpc]);
    assert_eq!(o.status.code(), Some(0), "{}", stderr(&o));
    assert!(
        stdout(&o).contains("different profiles (none and hpc)"),
        "{}",
        stdout(&o)
    );

    let o = sandbox.run(&["diff", &plain, &hpc, "--output", "json"]);
    let caveats = json(&o)["caveats"].clone();
    let kinds: Vec<&str> = caveats
        .as_array()
        .unwrap()
        .iter()
        .map(|c| c["kind"].as_str().unwrap())
        .collect();
    assert!(kinds.contains(&"different_profiles"), "{caveats}");

    let o = sandbox.run(&["diff", &hpc, &hpc_again]);
    assert!(
        !stdout(&o).contains("different profiles"),
        "the same profile on both sides: {}",
        stdout(&o)
    );
    let o = sandbox.run(&["diff", &plain, &plain]);
    assert!(!stdout(&o).contains("different profiles"), "{}", stdout(&o));
}
