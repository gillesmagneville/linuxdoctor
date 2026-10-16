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

#[test]
fn the_module_reports_one_finding_that_says_how_many_cpus_it_looked_at() {
    let sandbox = Sandbox::new("finding");
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
    let findings = report["results"][0]["findings"].as_array().unwrap();
    assert_eq!(findings.len(), 1, "{findings:?}");
    let finding = &findings[0];
    assert_eq!(finding["id"], "HPC001");
    assert_eq!(finding["title"], "CPU Frequency Governor");
    // Evidence is a list of [key, value] pairs.
    let evidence = |key: &str| -> Option<String> {
        finding["evidence"]
            .as_array()
            .unwrap()
            .iter()
            .find_map(|pair| (pair[0] == key).then(|| pair[1].as_str().expect("text").to_string()))
    };
    let cpus: usize = evidence("cpus_with_cpufreq")
        .expect("always reported")
        .parse()
        .expect("a number");
    // The host decides the number; the finding must agree with what it says.
    if cpus == 0 {
        assert!(finding["explanation"]
            .as_str()
            .unwrap()
            .contains("No CPU frequency scaling interface"));
        assert_eq!(evidence("governor"), None);
    } else {
        assert!(evidence("governor").is_some(), "{finding}");
    }
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
