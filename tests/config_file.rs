// SPDX-License-Identifier: GPL-3.0-only

//! The configuration file, end to end: the real binary, a real file in a
//! throwaway `$XDG_CONFIG_HOME`, fake external tools where an audit has to
//! find something specific.
//!
//! The rule under test is the one the file's documentation gives: what is
//! typed on the command line always wins, the file fills in the rest, and a
//! file that cannot be understood stops the program with status 2 instead of
//! being guessed at.

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

/// A throwaway home for the configuration file, with a directory of fake
/// tools that go first on PATH.
struct Sandbox {
    root: PathBuf,
}

impl Sandbox {
    fn new(name: &str) -> Sandbox {
        let root =
            std::env::temp_dir().join(format!("linuxdoctor-config-{name}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&root);
        fs::create_dir_all(root.join("xdg/linuxdoctor")).unwrap();
        fs::create_dir_all(root.join("bin")).unwrap();
        let sandbox = Sandbox { root };
        // No SMART data and no container runtime from the machine running
        // the tests.
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

    /// A single file system that is nearly full: the storage audit finds an
    /// Error, so the default exit status is 1.
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

    /// Writes the default configuration file.
    fn config(&self, content: &str) -> PathBuf {
        let path = self.default_file();
        fs::write(&path, content).unwrap();
        path
    }

    fn default_file(&self) -> PathBuf {
        self.root.join("xdg/linuxdoctor/config.toml")
    }

    fn path(&self, name: &str) -> PathBuf {
        self.root.join(name)
    }

    fn command(&self) -> Command {
        let mut command = Command::new(env!("CARGO_BIN_EXE_linuxdoctor"));
        command
            .env("XDG_CONFIG_HOME", self.root.join("xdg"))
            .env("HOME", "/nonexistent")
            .env(
                "PATH",
                format!(
                    "{}:/usr/local/bin:/usr/bin:/bin",
                    self.root.join("bin").display()
                ),
            );
        command
    }

    fn run(&self, args: &[&str]) -> Output {
        self.command()
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

// ----- the guard for the other tests ----------------------------------------------------------

#[test]
fn every_test_that_runs_the_binary_keeps_it_away_from_the_real_configuration_file() {
    // Someone who has a configuration file of their own (`fail_on = "never"`,
    // say) must not see the test suite change its mind. Every place that
    // starts the program says where its configuration is, or that there is
    // none. A new test file that forgets fails here, not on somebody's
    // machine.
    let tests = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests");
    let mut checked = 0;
    for entry in fs::read_dir(&tests).unwrap() {
        let path = entry.unwrap().path();
        if path.extension().and_then(|e| e.to_str()) != Some("rs") {
            continue;
        }
        let source = fs::read_to_string(&path).unwrap();
        let starts = source
            .matches("Command::new(env!(\"CARGO_BIN_EXE_linuxdoctor\"))")
            .count();
        let isolations = source.matches("\"XDG_CONFIG_HOME\"").count()
            + source.matches("\"--no-config\"").count();
        assert!(
            isolations >= starts,
            "{}: {starts} place(s) start the program but only {isolations} keep it away from \
             the real configuration file (.env(\"XDG_CONFIG_HOME\", ...) or --no-config)",
            path.display()
        );
        checked += starts;
    }
    assert!(
        checked >= 10,
        "only {checked} places found: is the check still looking?"
    );
}

// ----- the file fills in what was not typed ------------------------------------------------------

#[test]
fn the_output_format_comes_from_the_file_unless_one_is_typed() {
    let sandbox = Sandbox::new("output");
    sandbox.config("[audit]\noutput = \"json\"\n");

    let o = sandbox.run(&["audit", "--modules", "memory", "--fail-on", "never"]);
    assert_eq!(json(&o)["schema_version"], 1, "{}", stderr(&o));

    // Typing the default format is still typing something.
    let o = sandbox.run(&[
        "audit",
        "--modules",
        "memory",
        "--fail-on",
        "never",
        "--output",
        "terminal",
    ]);
    assert!(stdout(&o).contains("LinuxDoctor"), "{}", stdout(&o));
    assert!(serde_json::from_slice::<serde_json::Value>(&o.stdout).is_err());

    let o = sandbox.run(&[
        "audit",
        "--modules",
        "memory",
        "--fail-on",
        "never",
        "--output",
        "markdown",
    ]);
    assert!(
        stdout(&o).starts_with("# LinuxDoctor report"),
        "{}",
        stdout(&o)
    );
}

#[test]
fn a_bare_invocation_uses_the_audit_settings_too() {
    // `linuxdoctor > report.json` has no subcommand: it is an audit.
    let sandbox = Sandbox::new("bare");
    sandbox.config("[audit]\noutput = \"json\"\nfail_on = \"never\"\n");
    let o = sandbox.run(&[]);
    assert_eq!(o.status.code(), Some(0), "{}", stderr(&o));
    assert_eq!(json(&o)["schema_version"], 1);
}

#[test]
fn the_home_directory_is_used_when_xdg_config_home_is_not_set() {
    let sandbox = Sandbox::new("home");
    let dir = sandbox.path("home/.config/linuxdoctor");
    fs::create_dir_all(&dir).unwrap();
    fs::write(dir.join("config.toml"), "[audit]\noutput = \"json\"\n").unwrap();
    let o = sandbox
        .command()
        .env_remove("XDG_CONFIG_HOME")
        .env("HOME", sandbox.path("home"))
        .args(["audit", "--modules", "memory", "--fail-on", "never"])
        .output()
        .unwrap();
    assert_eq!(json(&o)["schema_version"], 1, "{}", stderr(&o));
}

#[test]
fn the_display_filter_comes_from_the_file_and_can_be_overridden() {
    let sandbox = Sandbox::new("filter");
    sandbox.full_disk();
    sandbox.config("min_severity = \"critical\"\n[audit]\noutput = \"json\"\n");

    let o = sandbox.run(&["audit", "--modules", "storage", "--fail-on", "never"]);
    let report = json(&o);
    assert_eq!(report["filter"]["min_severity"], "critical", "{report}");

    let o = sandbox.run(&[
        "audit",
        "--modules",
        "storage",
        "--fail-on",
        "never",
        "--min-severity",
        "warning",
    ]);
    assert_eq!(json(&o)["filter"]["min_severity"], "warning");
}

#[test]
fn the_time_limit_comes_from_the_file_and_can_be_overridden() {
    let sandbox = Sandbox::new("timeout");
    // A virsh that never answers: the note says which limit stopped it.
    sandbox.tool(
        "virsh",
        "case \"$1\" in --version) echo 9.0.0 ;; *) exec sleep 60 ;; esac",
    );
    sandbox.config("timeout = 1\n[audit]\noutput = \"json\"\n");
    let note_of = |o: &Output| -> String {
        let report = json(o);
        let result = report["results"]
            .as_array()
            .unwrap()
            .iter()
            .find(|r| r["module_id"] == "virtualization")
            .unwrap_or_else(|| panic!("virtualization missing: {report}"))
            .clone();
        result["notes"][0].as_str().unwrap_or("").to_string()
    };

    let o = sandbox.run(&["audit", "--modules", "virtualization", "--fail-on", "never"]);
    assert!(
        note_of(&o).contains("did not finish within 1s"),
        "{}",
        note_of(&o)
    );

    let o = sandbox.run(&[
        "audit",
        "--modules",
        "virtualization",
        "--fail-on",
        "never",
        "--timeout",
        "2",
    ]);
    assert!(
        note_of(&o).contains("did not finish within 2s"),
        "{}",
        note_of(&o)
    );
}

// ----- the exit status ------------------------------------------------------------------------------

#[test]
fn fail_on_in_the_file_changes_the_exit_status_and_says_so() {
    let sandbox = Sandbox::new("fail-on");
    sandbox.full_disk();

    // Without a file: the default gate fails on the nearly full disk, silently.
    let o = sandbox.run(&["audit", "--modules", "storage"]);
    assert_eq!(o.status.code(), Some(1));
    assert!(stderr(&o).is_empty(), "{}", stderr(&o));

    // The file says never: the same audit passes.
    sandbox.config("fail_on = \"never\"\n");
    let o = sandbox.run(&["audit", "--modules", "storage"]);
    assert_eq!(o.status.code(), Some(0), "{}", stderr(&o));

    // The file says a level that fails: it explains itself, naming the file.
    let file = sandbox.config("[audit]\nfail_on = \"warning\"\n");
    let o = sandbox.run(&["audit", "--modules", "storage"]);
    assert_eq!(o.status.code(), Some(1));
    let message = stderr(&o);
    assert!(
        message.contains(&format!("fail_on = \"warning\" in {}", file.display())),
        "{message}"
    );
    assert!(!message.contains("--fail-on"), "{message}");
}

#[test]
fn fail_on_typed_beats_the_file_in_both_directions() {
    let sandbox = Sandbox::new("fail-on-typed");
    sandbox.full_disk();

    sandbox.config("fail_on = \"never\"\n");
    let o = sandbox.run(&["audit", "--modules", "storage", "--fail-on", "error"]);
    assert_eq!(o.status.code(), Some(1));
    assert!(stderr(&o).contains("(--fail-on error)"), "{}", stderr(&o));

    sandbox.config("fail_on = \"info\"\n");
    let o = sandbox.run(&["audit", "--modules", "storage", "--fail-on", "never"]);
    assert_eq!(o.status.code(), Some(0), "{}", stderr(&o));
}

#[test]
fn the_display_filter_never_changes_the_exit_status_from_the_file_either() {
    let sandbox = Sandbox::new("filter-gate");
    sandbox.full_disk();
    // The Error finding is hidden from the output; the audit still fails.
    sandbox.config("min_severity = \"critical\"\n");
    let o = sandbox.run(&["audit", "--modules", "storage"]);
    assert_eq!(o.status.code(), Some(1), "{}", stderr(&o));
}

// ----- diff ------------------------------------------------------------------------------------------

fn report(severity: &str) -> String {
    serde_json::json!({
        "schema_version": 1,
        "context": {
            "hostname": "web01", "kernel_version": "6.8.0", "distro": null,
            "architecture": "x86_64", "cpu_count": 4, "mem_total_kb": 8_388_608,
            "boot_time_unix": 1_000_000,
        },
        "results": [{
            "module_id": "m",
            "findings": [{"id": "X1", "title": "A finding", "severity": severity,
                          "evidence": [], "instance": null}],
            "error": null, "skipped": false, "notes": [],
        }],
    })
    .to_string()
}

#[test]
fn diff_has_its_own_section_and_its_own_formats() {
    let sandbox = Sandbox::new("diff");
    let (before, after) = (sandbox.path("before.json"), sandbox.path("after.json"));
    fs::write(&before, report("info")).unwrap();
    fs::write(&after, report("critical")).unwrap();
    let (before, after) = (before.to_string_lossy(), after.to_string_lossy());

    // No file: a regression, shown on the terminal, exit 1.
    let o = sandbox.run(&["diff", &before, &after]);
    assert_eq!(o.status.code(), Some(1));
    assert!(serde_json::from_slice::<serde_json::Value>(&o.stdout).is_err());

    // audit and diff do not share `output`: the audit's html is not diff's.
    sandbox.config("[audit]\noutput = \"html\"\n[diff]\noutput = \"json\"\nfail_on = \"never\"\n");
    let o = sandbox.run(&["diff", &before, &after]);
    assert_eq!(o.status.code(), Some(0), "{}", stderr(&o));
    assert_eq!(json(&o)["kind"], "comparison");

    // Typed options still win.
    let o = sandbox.run(&[
        "diff",
        &before,
        &after,
        "--output",
        "markdown",
        "--fail-on",
        "error",
    ]);
    assert_eq!(o.status.code(), Some(1));
    assert!(stdout(&o).starts_with("# "), "{}", stdout(&o));
    assert!(stderr(&o).contains("(--fail-on error)"), "{}", stderr(&o));
}

#[test]
fn diff_explains_a_failure_decided_by_the_file() {
    let sandbox = Sandbox::new("diff-explains");
    let (before, after) = (sandbox.path("before.json"), sandbox.path("after.json"));
    fs::write(&before, report("info")).unwrap();
    fs::write(&after, report("warning")).unwrap();
    let file = sandbox.config("fail_on = \"warning\"\n");
    let o = sandbox.run(&["diff", &before.to_string_lossy(), &after.to_string_lossy()]);
    assert_eq!(o.status.code(), Some(1));
    assert!(
        stderr(&o).contains(&format!("fail_on = \"warning\" in {}", file.display())),
        "{}",
        stderr(&o)
    );
}

// ----- a file that cannot be used --------------------------------------------------------------------

#[test]
fn a_broken_file_stops_the_command_with_status_2_and_says_where() {
    let sandbox = Sandbox::new("broken");
    let file = sandbox.config("timeout = 5\n\nfail_on = \"fatal\"\n");
    for args in [
        &["audit", "--modules", "memory"][..],
        &["tui", "--modules", "memory"][..],
        &["diff", "a.json", "b.json"][..],
    ] {
        let o = sandbox.run(args);
        let message = stderr(&o);
        assert_eq!(o.status.code(), Some(2), "{args:?}: {message}");
        assert!(o.stdout.is_empty(), "{args:?}: nothing is run");
        assert!(message.contains(&file.display().to_string()), "{message}");
        assert!(message.contains("line 3"), "{message}");
        assert!(message.contains("`fatal` is not one of"), "{message}");
        assert!(message.contains("--no-config"), "the way out: {message}");
    }
}

#[test]
fn no_config_ignores_even_a_broken_file() {
    let sandbox = Sandbox::new("no-config");
    sandbox.config("this is not toml");
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
    assert_eq!(o.status.code(), Some(0), "{}", stderr(&o));
    assert_eq!(json(&o)["schema_version"], 1);
}

#[test]
fn the_manual_and_the_completions_do_not_depend_on_the_file() {
    let sandbox = Sandbox::new("man");
    sandbox.config("this is not toml");
    for args in [&["man"][..], &["completions", "bash"][..]] {
        let o = sandbox.run(args);
        assert_eq!(o.status.code(), Some(0), "{args:?}: {}", stderr(&o));
        assert!(!o.stdout.is_empty());
    }
}

#[test]
fn a_named_file_must_exist_and_replaces_the_default_one() {
    let sandbox = Sandbox::new("named");
    sandbox.config("fail_on = \"fatal\"\n"); // broken, but not the one asked for
    let missing = sandbox.path("nope.toml");
    let o = sandbox.run(&["--config", &missing.to_string_lossy(), "audit"]);
    assert_eq!(o.status.code(), Some(2));
    assert!(stderr(&o).contains("nope.toml"), "{}", stderr(&o));
    assert!(
        !stderr(&o).contains("--no-config"),
        "no advice to ignore a file that was asked for: {}",
        stderr(&o)
    );

    let named = sandbox.path("mine.toml");
    fs::write(&named, "[audit]\noutput = \"json\"\nfail_on = \"never\"\n").unwrap();
    let o = sandbox.run(&[
        "audit",
        "--modules",
        "memory",
        "--config",
        &named.to_string_lossy(),
    ]);
    assert_eq!(json(&o)["schema_version"], 1, "{}", stderr(&o));
}

#[test]
fn config_and_no_config_together_are_a_usage_error() {
    let sandbox = Sandbox::new("exclusive");
    let o = sandbox.run(&["--config", "x.toml", "--no-config", "audit"]);
    assert_eq!(o.status.code(), Some(2));
    assert!(stderr(&o).contains("cannot be used with"), "{}", stderr(&o));
}

#[test]
fn modules_cannot_be_configured() {
    // A file that quietly narrowed every audit would hand out clean reports
    // of checks that were never made.
    let sandbox = Sandbox::new("modules");
    sandbox.config("[audit]\nmodules = [\"memory\"]\n");
    let o = sandbox.run(&["audit"]);
    assert_eq!(o.status.code(), Some(2));
    assert!(
        stderr(&o).contains("unknown field `modules`"),
        "{}",
        stderr(&o)
    );
}

#[test]
fn a_file_cannot_make_the_error_message_act_on_the_terminal() {
    let sandbox = Sandbox::new("hostile");
    sandbox.config("# \u{1b}[2J\u{1b}]0;pwned\u{7}\nfail_on = \"\\u001b[2J\"\n");
    let o = sandbox.run(&["audit", "--modules", "memory"]);
    assert_eq!(o.status.code(), Some(2));
    let message = stderr(&o);
    assert!(!message.contains('\u{1b}'), "{message:?}");
    assert!(!message.contains('\u{7}'), "{message:?}");
}

#[test]
fn an_empty_file_changes_nothing() {
    let sandbox = Sandbox::new("empty");
    sandbox.full_disk();
    sandbox.config("");
    let o = sandbox.run(&["audit", "--modules", "storage"]);
    assert_eq!(
        o.status.code(),
        Some(1),
        "the default gate, as without a file"
    );
    assert!(stderr(&o).is_empty(), "{}", stderr(&o));
}
