// SPDX-License-Identifier: GPL-3.0-only

//! The module the `hpc` profile adds, end to end, with the real binary.
//!
//! What the module reads (`/sys/devices/system/cpu`) belongs to the host the
//! tests run on, so these tests check what does not depend on it: that the
//! module is there only with the profile, where it comes in the report, that
//! asking for it without the profile is refused in words that say what to do,
//! and that the explicit selection of modules stays exact. What the module
//! says about each possible policy is tested on fake trees in its own unit
//! tests.

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;
use std::process::{Command, Output};

/// A throwaway configuration directory, and fake tools that go first on PATH
/// so that a full audit cannot hang on a missing disk or container tool.
struct Sandbox {
    root: PathBuf,
}

impl Sandbox {
    fn new(name: &str) -> Sandbox {
        let root =
            std::env::temp_dir().join(format!("linuxdoctor-hpc-{name}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&root);
        fs::create_dir_all(root.join("xdg/linuxdoctor")).unwrap();
        fs::create_dir_all(root.join("bin")).unwrap();
        for tool in ["smartctl", "docker", "podman"] {
            let path = root.join("bin").join(tool);
            fs::write(&path, "#!/bin/sh\nexit 127\n").unwrap();
            fs::set_permissions(&path, fs::Permissions::from_mode(0o755)).unwrap();
        }
        Sandbox { root }
    }

    fn config(&self, content: &str) {
        fs::write(self.root.join("xdg/linuxdoctor/config.toml"), content).unwrap();
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
            .stdin(std::process::Stdio::null())
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

fn module_ids(report: &serde_json::Value) -> Vec<String> {
    report["results"]
        .as_array()
        .expect("results")
        .iter()
        .map(|r| r["module_id"].as_str().expect("module_id").to_string())
        .collect()
}

const NEEDS_PROFILE: &str = "the module 'hpc' is added by the hpc profile: \
                             run with --profile hpc (or set profile = \"hpc\" in the configuration file)";

#[test]
fn a_full_audit_has_no_hpc_module_without_the_profile() {
    let sandbox = Sandbox::new("plain");
    let o = sandbox.run(&["audit", "--fail-on", "never", "--output", "json"]);
    let ids = module_ids(&json(&o));
    assert!(ids.len() >= 10, "{ids:?}");
    assert!(!ids.iter().any(|id| id == "hpc"), "{ids:?}");
}

#[test]
fn a_full_audit_under_the_profile_ends_with_the_hpc_module() {
    let sandbox = Sandbox::new("full");
    let o = sandbox.run(&[
        "audit",
        "--fail-on",
        "never",
        "--profile",
        "hpc",
        "--output",
        "json",
    ]);
    let report = json(&o);
    let ids = module_ids(&report);
    assert_eq!(ids.last().map(String::as_str), Some("hpc"), "{ids:?}");
    // The others are all still there, before it.
    for expected in ["memory", "cpu", "gpu", "virtualization"] {
        assert!(ids.iter().any(|id| id == expected), "{expected}: {ids:?}");
    }
    assert_eq!(report["profile"], "hpc");
}

/// The evidence value of a finding; evidence is a list of [key, value] pairs.
fn evidence(finding: &serde_json::Value, key: &str) -> Option<String> {
    finding["evidence"]
        .as_array()
        .unwrap()
        .iter()
        .find_map(|pair| (pair[0] == key).then(|| pair[1].as_str().expect("text").to_string()))
}

fn hpc_findings(sandbox: &Sandbox) -> Vec<serde_json::Value> {
    let o = sandbox.run(&[
        "audit",
        "--modules",
        "hpc",
        "--profile",
        "hpc",
        "--fail-on",
        "never",
        "--output",
        "json",
    ]);
    let report = json(&o);
    assert_eq!(module_ids(&report), ["hpc"]);
    report["results"][0]["findings"].as_array().unwrap().clone()
}

#[test]
fn the_module_reports_its_four_findings_in_order() {
    let sandbox = Sandbox::new("findings");
    let findings = hpc_findings(&sandbox);
    let ids: Vec<&str> = findings.iter().map(|f| f["id"].as_str().unwrap()).collect();
    assert_eq!(
        ids,
        ["HPC001", "HPC002", "HPC003", "HPC004"],
        "{findings:?}"
    );
}

#[test]
fn the_governor_finding_says_how_many_cpus_it_looked_at() {
    let sandbox = Sandbox::new("governor");
    let findings = hpc_findings(&sandbox);
    let finding = &findings[0];
    assert_eq!(finding["id"], "HPC001");
    assert_eq!(finding["title"], "CPU Frequency Governor");
    let cpus: usize = evidence(finding, "cpus_with_cpufreq")
        .expect("always reported")
        .parse()
        .expect("a number");
    // The host decides the number; the finding must agree with what it says.
    if cpus == 0 {
        assert!(finding["explanation"]
            .as_str()
            .unwrap()
            .contains("No CPU frequency scaling interface"));
        assert_eq!(evidence(finding, "governor"), None);
    } else {
        assert!(evidence(finding, "governor").is_some(), "{finding}");
    }
}

#[test]
fn the_locked_memory_finding_says_what_it_found_whatever_the_host() {
    let sandbox = Sandbox::new("memlock");
    let findings = hpc_findings(&sandbox);
    let finding = &findings[1];
    assert_eq!(finding["id"], "HPC002");
    assert_eq!(finding["title"], "Locked Memory Limit");
    let explanation = finding["explanation"].as_str().unwrap();
    // The host decides whether it has RDMA devices; the finding must say
    // which, and judge only when there are some.
    let devices = evidence(finding, "rdma_devices").expect("always reported");
    if devices == "none" {
        assert_eq!(finding["severity"], "info", "{finding}");
        assert!(explanation.contains("No RDMA device"), "{explanation}");
        assert!(finding["recommendation"].is_null(), "{finding}");
    } else {
        assert!(explanation.contains("RDMA device"), "{explanation}");
        assert!(explanation.contains(&devices), "{explanation}");
    }
    // This test process has a limit; it is read in bytes or as unlimited.
    let soft = evidence(finding, "memlock_soft");
    assert!(soft.is_some(), "{finding}");
    assert!(evidence(finding, "memlock_hard").is_some(), "{finding}");
}

#[test]
fn numa_balancing_is_reported_with_the_number_of_nodes_whatever_the_host() {
    let sandbox = Sandbox::new("numa");
    let findings = hpc_findings(&sandbox);
    let finding = &findings[2];
    assert_eq!(finding["id"], "HPC003");
    assert_eq!(finding["title"], "Automatic NUMA Balancing");
    assert_eq!(finding["severity"], "info", "{finding}");
    let nodes: usize = evidence(finding, "numa_nodes")
        .expect("always reported")
        .parse()
        .expect("a number");
    let explanation = finding["explanation"].as_str().unwrap();
    // What the host's own files say, when it has them.
    if let Ok(text) = fs::read_to_string("/proc/sys/kernel/numa_balancing") {
        assert_eq!(
            evidence(finding, "numa_balancing").as_deref(),
            Some(text.trim())
        );
    }
    if std::path::Path::new("/sys/devices/system/node/node0").exists() {
        assert!(nodes >= 1, "{finding}");
    }
    match evidence(finding, "numa_balancing") {
        // The kernel has no switch.
        None => assert!(explanation.contains("no switch"), "{explanation}"),
        Some(_) if nodes < 2 => {
            assert!(
                explanation.contains("no remote memory to balance"),
                "{explanation}"
            )
        }
        Some(_) => assert!(explanation.contains("NUMA nodes"), "{explanation}"),
    }
}

#[test]
fn smt_is_reported_as_information_whatever_the_host() {
    let sandbox = Sandbox::new("smt");
    let findings = hpc_findings(&sandbox);
    let finding = &findings[3];
    assert_eq!(finding["id"], "HPC004");
    assert_eq!(finding["title"], "SMT (Hyper-Threading)");
    assert_eq!(finding["severity"], "info", "{finding}");
    // The explanation always says which of the states the host is in.
    let explanation = finding["explanation"].as_str().unwrap();
    assert!(
        [
            "no SMT",
            "forced off",
            "SMT is off",
            "SMT is on",
            "is not known"
        ]
        .iter()
        .any(|state| explanation.contains(state)),
        "{explanation}"
    );
    // What the host's own files say, when it has them.
    if let Ok(text) = fs::read_to_string("/sys/devices/system/cpu/smt/control") {
        assert_eq!(
            evidence(finding, "smt_control").as_deref(),
            Some(text.trim())
        );
    }
    if let Ok(text) = fs::read_to_string("/sys/devices/system/cpu/smt/active") {
        assert_eq!(
            evidence(finding, "smt_active").as_deref(),
            Some(text.trim())
        );
    }
    // The topology of a host with CPUs is always readable.
    let logical: usize = evidence(finding, "logical_cpus")
        .expect("a host has CPUs")
        .parse()
        .expect("a number");
    let cores: usize = evidence(finding, "cores").unwrap().parse().unwrap();
    assert!(logical >= cores && cores >= 1, "{finding}");
}

#[test]
fn asking_for_the_module_without_the_profile_is_refused_in_words_that_say_what_to_do() {
    let sandbox = Sandbox::new("refused");
    for command in ["audit", "tui"] {
        let o = sandbox.run(&[command, "--modules", "hpc"]);
        assert_eq!(o.status.code(), Some(2), "{command}");
        assert!(
            stdout(&o).is_empty(),
            "{command}: no report: {}",
            stdout(&o)
        );
        assert!(
            stderr(&o).contains(NEEDS_PROFILE),
            "{command}: {}",
            stderr(&o)
        );
    }
    // Among others, too: the whole request is refused, not trimmed.
    let o = sandbox.run(&["audit", "--modules", "memory,hpc"]);
    assert_eq!(o.status.code(), Some(2));
    assert!(stderr(&o).contains(NEEDS_PROFILE), "{}", stderr(&o));
}

#[test]
fn the_configuration_file_can_supply_the_profile_the_module_needs() {
    let sandbox = Sandbox::new("config");
    sandbox.config("profile = \"hpc\"\n");
    let o = sandbox.run(&[
        "audit",
        "--modules",
        "hpc",
        "--fail-on",
        "never",
        "--output",
        "json",
    ]);
    assert_eq!(module_ids(&json(&o)), ["hpc"]);
    // And ignoring the file takes the profile with it.
    let o = sandbox.run(&["--no-config", "audit", "--modules", "hpc"]);
    assert_eq!(o.status.code(), Some(2));
    assert!(stderr(&o).contains(NEEDS_PROFILE), "{}", stderr(&o));
}

#[test]
fn choosing_modules_stays_exact_under_the_profile() {
    let sandbox = Sandbox::new("exact");
    let o = sandbox.run(&[
        "audit",
        "--modules",
        "memory",
        "--profile",
        "hpc",
        "--fail-on",
        "never",
        "--output",
        "json",
    ]);
    // Asking for memory gets memory, not memory and the profile's module.
    assert_eq!(module_ids(&json(&o)), ["memory"]);
}

#[test]
fn an_id_that_does_not_exist_is_still_refused_by_the_command_line_parser() {
    let sandbox = Sandbox::new("unknown");
    let o = sandbox.run(&["audit", "--modules", "hpcc"]);
    assert_eq!(o.status.code(), Some(2));
    let message = stderr(&o);
    assert!(message.contains("invalid value 'hpcc'"), "{message}");
    // The list of valid ones includes the module the profile adds.
    assert!(message.contains("hpc"), "{message}");
    assert!(!message.contains(NEEDS_PROFILE), "{message}");
}

#[test]
fn the_manual_page_and_the_completions_know_the_module() {
    let sandbox = Sandbox::new("docs");
    let man = stdout(&sandbox.run(&["man"]));
    assert!(man.contains("Adds the module hpc: "), "{man}");
    let bash = stdout(&sandbox.run(&["completions", "bash"]));
    assert!(bash.contains("hpc"));
}

#[test]
fn diff_calls_the_module_not_compared_when_only_one_report_has_it() {
    let sandbox = Sandbox::new("diff");
    let with = sandbox.root.join("with.json");
    let without = sandbox.root.join("without.json");
    let o = sandbox.run(&[
        "audit",
        "--modules",
        "memory,cpu",
        "--fail-on",
        "never",
        "--output",
        "json",
    ]);
    fs::write(&without, &o.stdout).unwrap();
    let o = sandbox.run(&[
        "audit",
        "--modules",
        "memory,cpu,hpc",
        "--profile",
        "hpc",
        "--fail-on",
        "never",
        "--output",
        "json",
    ]);
    fs::write(&with, &o.stdout).unwrap();
    let o = sandbox.run(&[
        "diff",
        without.to_str().unwrap(),
        with.to_str().unwrap(),
        "--output",
        "json",
    ]);
    let text = stdout(&o);
    assert!(text.contains("different_profiles"), "{text}");
    let value: serde_json::Value = serde_json::from_str(&text).expect("JSON");
    let not_compared = value["not_compared"].to_string();
    assert!(not_compared.contains("hpc"), "{value}");
}
