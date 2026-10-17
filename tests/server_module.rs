// SPDX-License-Identifier: GPL-3.0-only

//! The module the `server` profile adds, end to end, with the real binary.
//!
//! Part of what the module reads (the packages installed, `/etc/dnf`) belongs
//! to the host the tests run on, so the tests that depend on it check what does
//! not: that the module is there only with the profile, where it comes in the
//! report, that asking for it without the profile is refused in words that say
//! what to do, and that the profile lowers nothing. The two tools the module
//! asks, `apt-config` and `systemctl`, are replaced by fake ones first on
//! `PATH`, which is what lets the tests say what they answer; those tests need
//! a Debian-like host (they say so and stop on another). What the module says
//! about every possible setup is tested on fake data in its own unit tests.

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::time::{Instant, SystemTime};

/// A throwaway configuration directory, and fake tools that go first on PATH
/// so that a full audit cannot hang on a missing disk or container tool.
struct Sandbox {
    root: PathBuf,
}

impl Sandbox {
    fn new(name: &str) -> Sandbox {
        let root =
            std::env::temp_dir().join(format!("linuxdoctor-server-{name}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&root);
        fs::create_dir_all(root.join("xdg/linuxdoctor")).unwrap();
        fs::create_dir_all(root.join("bin")).unwrap();
        fs::create_dir_all(root.join("states")).unwrap();
        for tool in ["smartctl", "docker", "podman"] {
            sandbox_script(&root.join("bin").join(tool), "#!/bin/sh\nexit 127\n");
        }
        Sandbox { root }
    }

    fn config(&self, content: &str) {
        fs::write(self.root.join("xdg/linuxdoctor/config.toml"), content).unwrap();
    }

    /// `apt-config dump` prints `dump`.
    fn apt_config(&self, dump: &str) {
        fs::write(self.root.join("dump"), dump).unwrap();
        // Only `apt-config dump`, with nothing else on the line, is answered.
        let script = format!(
            "#!/bin/sh\n[ \"$#\" -eq 1 ] && [ \"$1\" = dump ] || exit 2\ncat '{}'\n",
            self.root.join("dump").display()
        );
        sandbox_script(&self.root.join("bin/apt-config"), &script);
    }

    /// `systemctl is-enabled UNIT` answers what the file `states/UNIT` says,
    /// with the exit status the real one has (0 for `enabled`, 1 for the
    /// other states it names), and `not-found` with status 4 for a unit with
    /// no file.
    fn systemctl(&self) {
        let script = format!(
            "#!/bin/sh\n\
             [ \"$#\" -eq 2 ] && [ \"$1\" = is-enabled ] || exit 1\n\
             f='{}'/\"$2\"\n\
             if [ -f \"$f\" ]; then\n\
               cat \"$f\"\n\
               grep -qx 'enabled' \"$f\" && exit 0\n\
               exit 1\n\
             fi\n\
             echo not-found\n\
             exit 4\n",
            self.root.join("states").display()
        );
        sandbox_script(&self.root.join("bin/systemctl"), &script);
    }

    fn unit(&self, unit: &str, state: &str) {
        fs::write(self.root.join("states").join(unit), format!("{state}\n")).unwrap();
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

    /// The report of the module alone, with the profile.
    fn module(&self, extra: &[&str]) -> serde_json::Value {
        let mut args = vec![
            "audit",
            "--modules",
            "server",
            "--profile",
            "server",
            "--fail-on",
            "never",
            "--output",
            "json",
        ];
        args.extend_from_slice(extra);
        json(&self.run(&args))
    }
}

fn sandbox_script(path: &Path, content: &str) {
    fs::write(path, content).unwrap();
    fs::set_permissions(path, fs::Permissions::from_mode(0o755)).unwrap();
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

/// The evidence value of a finding; evidence is a list of [key, value] pairs.
fn evidence(finding: &serde_json::Value, key: &str) -> Option<String> {
    finding["evidence"]
        .as_array()
        .unwrap()
        .iter()
        .find_map(|pair| (pair[0] == key).then(|| pair[1].as_str().expect("text").to_string()))
}

/// The findings of the module, in the order of the report.
fn findings(report: &serde_json::Value) -> Vec<serde_json::Value> {
    report["results"][0]["findings"].as_array().unwrap().clone()
}

/// The finding of the module with this id, which there is exactly one of.
fn finding_of(report: &serde_json::Value, id: &str) -> serde_json::Value {
    let all = findings(report);
    let mut with_id = all.iter().filter(|f| f["id"] == id);
    let found = with_id.next().unwrap_or_else(|| panic!("no {id}: {all:?}"));
    assert!(with_id.next().is_none(), "{id} twice: {all:?}");
    found.clone()
}

/// The finding about the automatic updates.
fn srv001(report: &serde_json::Value) -> serde_json::Value {
    finding_of(report, "SRV001")
}

const NEEDS_PROFILE: &str = "the module 'server' is added by the server profile: \
                             run with --profile server (or set profile = \"server\" in the configuration file)";

/// What `apt-config dump` prints on a machine set up by the package.
fn dump(enable: Option<&str>, lists: &str, upgrade: &str, origins: usize) -> String {
    let mut text = String::from("APT \"\";\nAPT::Periodic \"\";\n");
    if let Some(enable) = enable {
        text.push_str(&format!("APT::Periodic::Enable \"{enable}\";\n"));
    }
    text.push_str(&format!(
        "APT::Periodic::Update-Package-Lists \"{lists}\";\n\
         APT::Periodic::Unattended-Upgrade \"{upgrade}\";\n\
         Unattended-Upgrade::Allowed-Origins \"\";\n"
    ));
    for i in 0..origins {
        text.push_str(&format!(
            "Unattended-Upgrade::Allowed-Origins:: \"${{distro_id}}:origin{i}-security\";\n"
        ));
    }
    text
}

/// The package manager the module should find on this host, judged from its
/// `os-release` apart from the code under test; `None` when the host is not
/// one of the obvious families (then nothing is asserted).
fn manager_of_this_host() -> Option<&'static str> {
    let text = fs::read_to_string("/etc/os-release").ok()?;
    let name = text
        .lines()
        .find_map(|line| line.strip_prefix("PRETTY_NAME="))?
        .trim_matches('"')
        .to_lowercase();
    let any = |words: &[&str]| words.iter().any(|word| name.contains(word));
    if any(&["ubuntu", "debian"]) {
        Some("apt")
    } else if any(&["fedora", "red hat", "centos", "rocky", "alma"]) {
        Some("dnf")
    } else {
        None
    }
}

/// Whether this host reads the module's apt side. The tests that fake
/// `apt-config` mean nothing on a host that is not Debian-like.
fn host_uses_apt(sandbox: &Sandbox) -> bool {
    sandbox.systemctl();
    sandbox.apt_config(&dump(None, "1", "1", 1));
    let finding = srv001(&sandbox.module(&[]));
    let apt = evidence(&finding, "package_manager").as_deref() == Some("apt");
    if !apt {
        eprintln!(
            "skipped: this host is not Debian-like ({:?})",
            evidence(&finding, "package_manager")
        );
    }
    apt
}

fn both_timers(sandbox: &Sandbox, state: &str) {
    sandbox.unit("apt-daily.timer", state);
    sandbox.unit("apt-daily-upgrade.timer", state);
}

// ----- the profile and its module -----------------------------------------------

#[test]
fn a_full_audit_has_no_server_module_without_the_profile() {
    let sandbox = Sandbox::new("plain");
    let o = sandbox.run(&["audit", "--fail-on", "never", "--output", "json"]);
    let ids = module_ids(&json(&o));
    assert!(ids.len() >= 10, "{ids:?}");
    assert!(!ids.iter().any(|id| id == "server"), "{ids:?}");
}

#[test]
fn a_full_audit_under_the_profile_ends_with_the_server_module_and_not_the_hpc_one() {
    let sandbox = Sandbox::new("full");
    let o = sandbox.run(&[
        "audit",
        "--fail-on",
        "never",
        "--profile",
        "server",
        "--output",
        "json",
    ]);
    let report = json(&o);
    let ids = module_ids(&report);
    assert_eq!(ids.last().map(String::as_str), Some("server"), "{ids:?}");
    assert!(!ids.iter().any(|id| id == "hpc"), "{ids:?}");
    for expected in ["memory", "cpu", "security", "logs", "kernel"] {
        assert!(ids.iter().any(|id| id == expected), "{expected}: {ids:?}");
    }
    assert_eq!(report["profile"], "server");
}

#[test]
fn the_module_reports_the_update_finding_whatever_the_host() {
    let sandbox = Sandbox::new("finding");
    let report = sandbox.module(&[]);
    assert_eq!(module_ids(&report), ["server"]);
    let finding = srv001(&report);
    assert_eq!(finding["title"], "Automatic Security Updates");
    assert_eq!(finding["category"], "security");
    let manager = evidence(&finding, "package_manager").expect("always reported");
    assert!(
        ["apt", "dnf", "unsupported"].contains(&manager.as_str()),
        "{finding}"
    );
    // The family the module found is the one the host's own name gives.
    if let Some(expected) = manager_of_this_host() {
        assert_eq!(manager, expected, "{finding}");
    }
    // Never worse than a warning, and a warning is never certain: another way
    // of patching the machine is possible.
    let severity = finding["severity"].as_str().unwrap();
    assert!(["info", "warning"].contains(&severity), "{finding}");
    if severity == "warning" {
        assert_eq!(finding["confidence"]["percent"], 80, "{finding}");
    }
    // What the host's own files say, when it is a system this reads.
    if manager == "apt" {
        assert_eq!(
            evidence(&finding, "unattended_upgrade_installed").as_deref(),
            Some(if Path::new("/usr/bin/unattended-upgrade").exists() {
                "yes"
            } else {
                "no"
            }),
            "{finding}"
        );
    }
    if manager == "dnf" {
        let dnf5 = Path::new("/usr/bin/dnf5").exists();
        assert_eq!(
            evidence(&finding, "dnf_version").as_deref(),
            Some(if dnf5 { "5" } else { "4" }),
            "{finding}"
        );
        let package = if dnf5 {
            Path::new("/usr/share/dnf5/dnf5-plugins/automatic.conf").exists()
        } else {
            Path::new("/usr/bin/dnf-automatic").exists()
        };
        assert_eq!(
            evidence(&finding, "dnf_automatic_installed").as_deref(),
            Some(if package { "yes" } else { "no" }),
            "{finding}"
        );
    }
}

#[test]
fn asking_for_the_module_without_the_profile_is_refused_in_words_that_say_what_to_do() {
    let sandbox = Sandbox::new("refused");
    for command in ["audit", "tui"] {
        let o = sandbox.run(&[command, "--modules", "server"]);
        assert_eq!(o.status.code(), Some(2), "{command}");
        assert!(stdout(&o).is_empty(), "{command}: {}", stdout(&o));
        assert!(
            stderr(&o).contains(NEEDS_PROFILE),
            "{command}: {}",
            stderr(&o)
        );
    }
    // Another profile's choice does not open it.
    let o = sandbox.run(&["audit", "--modules", "server", "--profile", "hpc"]);
    assert_eq!(o.status.code(), Some(2));
    assert!(stderr(&o).contains(NEEDS_PROFILE), "{}", stderr(&o));
    // And the other way round.
    let o = sandbox.run(&["audit", "--modules", "hpc", "--profile", "server"]);
    assert_eq!(o.status.code(), Some(2));
    assert!(
        stderr(&o).contains("the module 'hpc' is added by the hpc profile"),
        "{}",
        stderr(&o)
    );
}

#[test]
fn the_configuration_file_can_supply_the_profile_the_module_needs() {
    let sandbox = Sandbox::new("config");
    sandbox.config("profile = \"server\"\n");
    let o = sandbox.run(&[
        "audit",
        "--modules",
        "server",
        "--fail-on",
        "never",
        "--output",
        "json",
    ]);
    let report = json(&o);
    assert_eq!(module_ids(&report), ["server"]);
    assert_eq!(report["profile"], "server");
}

#[test]
fn the_manual_page_and_the_completions_know_the_profile_and_its_module() {
    let sandbox = Sandbox::new("docs");
    let man = stdout(&sandbox.run(&["man"]));
    assert!(man.contains("Adds the module server: "), "{man}");
    assert!(man.contains("no severity is lowered"), "{man}");
    let bash = stdout(&sandbox.run(&["completions", "bash"]));
    assert!(bash.contains("server"));
}

#[test]
fn the_profile_lowers_no_finding_of_the_other_modules() {
    // `server` has no rules: the same modules give the same findings with
    // and without it. (Modules whose figures move from one run to the next
    // are left out.)
    let sandbox = Sandbox::new("lowers-nothing");
    let run = |extra: &[&str]| {
        let mut args = vec![
            "audit",
            "--modules",
            "firmware,kernel",
            "--fail-on",
            "never",
            "--output",
            "json",
        ];
        args.extend_from_slice(extra);
        let report = json(&sandbox.run(&args));
        report["results"]
            .as_array()
            .unwrap()
            .iter()
            .flat_map(|r| r["findings"].as_array().unwrap().clone())
            .map(|f| {
                (
                    f["id"].as_str().unwrap().to_string(),
                    f["severity"].as_str().unwrap().to_string(),
                    f["explanation"].as_str().unwrap().to_string(),
                    f["evidence"].clone(),
                )
            })
            .collect::<Vec<_>>()
    };
    let without = run(&[]);
    let with = run(&["--profile", "server"]);
    assert!(!without.is_empty());
    assert_eq!(with, without);
}

// ----- the module with fake tools ----------------------------------------------------

#[test]
fn set_up_by_the_package_is_information_when_the_package_is_there() {
    let sandbox = Sandbox::new("good");
    if !host_uses_apt(&sandbox) {
        return;
    }
    both_timers(&sandbox, "enabled");
    let report = sandbox.module(&[]);
    let finding = srv001(&report);
    assert_eq!(
        evidence(&finding, "update_package_lists").as_deref(),
        Some("1")
    );
    assert_eq!(
        evidence(&finding, "unattended_upgrade_interval").as_deref(),
        Some("1")
    );
    assert_eq!(evidence(&finding, "allowed_origins").as_deref(), Some("1"));
    assert_eq!(
        evidence(&finding, "apt-daily.timer").as_deref(),
        Some("enabled")
    );
    assert_eq!(
        evidence(&finding, "apt-daily-upgrade.timer").as_deref(),
        Some("enabled")
    );
    let explanation = finding["explanation"].as_str().unwrap();
    if evidence(&finding, "unattended_upgrade_installed").as_deref() == Some("yes") {
        assert_eq!(finding["severity"], "info", "{finding}");
        assert_eq!(finding["confidence"]["percent"], 90);
        assert!(finding["recommendation"].is_null());
        assert!(
            explanation.contains("installed without anyone asking"),
            "{explanation}"
        );
    } else {
        // The settings are right and the package is not there: it is the one fault.
        assert_eq!(finding["severity"], "warning", "{finding}");
        assert!(explanation.contains("is not installed"), "{explanation}");
        assert!(!explanation.contains("APT::Periodic"), "{explanation}");
        assert!(
            finding["recommendation"]
                .as_str()
                .unwrap()
                .contains("sudo apt install unattended-upgrades"),
            "{finding}"
        );
    }
}

#[test]
fn a_daily_job_that_is_off_is_a_warning_with_the_commands_to_turn_it_on() {
    let sandbox = Sandbox::new("off");
    if !host_uses_apt(&sandbox) {
        return;
    }
    both_timers(&sandbox, "enabled");
    sandbox.apt_config(&dump(None, "1", "0", 1));
    let finding = srv001(&sandbox.module(&[]));
    assert_eq!(finding["severity"], "warning", "{finding}");
    assert_eq!(finding["confidence"]["percent"], 80);
    assert_eq!(
        evidence(&finding, "unattended_upgrade_interval").as_deref(),
        Some("0")
    );
    let explanation = finding["explanation"].as_str().unwrap();
    assert!(
        explanation.contains("`APT::Periodic::Unattended-Upgrade` is not set (or is 0)"),
        "{explanation}"
    );
    assert!(explanation.contains("patched another way"), "{explanation}");
    let steps = finding["recommendation"].as_str().unwrap();
    assert!(
        steps.contains("/etc/apt/apt.conf.d/20auto-upgrades"),
        "{steps}"
    );
    assert!(steps.contains("unattended-upgrade --dry-run"), "{steps}");
}

#[test]
fn the_switch_that_turns_every_daily_job_off_is_found() {
    let sandbox = Sandbox::new("switch");
    if !host_uses_apt(&sandbox) {
        return;
    }
    both_timers(&sandbox, "enabled");
    sandbox.apt_config(&dump(Some("0"), "1", "1", 1));
    let finding = srv001(&sandbox.module(&[]));
    assert_eq!(finding["severity"], "warning", "{finding}");
    assert_eq!(evidence(&finding, "periodic_enable").as_deref(), Some("0"));
    let explanation = finding["explanation"].as_str().unwrap();
    assert!(
        explanation.contains("`APT::Periodic::Enable` is 0"),
        "{explanation}"
    );
    assert!(
        finding["recommendation"]
            .as_str()
            .unwrap()
            .contains("grep -rn -i 'periodic::enable' /etc/apt/apt.conf.d/"),
        "{finding}"
    );
}

#[test]
fn no_allowed_origin_is_found_when_the_package_is_there() {
    let sandbox = Sandbox::new("origins");
    if !host_uses_apt(&sandbox) {
        return;
    }
    both_timers(&sandbox, "enabled");
    sandbox.apt_config(&dump(None, "1", "1", 0));
    let finding = srv001(&sandbox.module(&[]));
    assert_eq!(evidence(&finding, "allowed_origins").as_deref(), Some("0"));
    let explanation = finding["explanation"].as_str().unwrap();
    if evidence(&finding, "unattended_upgrade_installed").as_deref() == Some("yes") {
        assert_eq!(finding["severity"], "warning", "{finding}");
        assert!(
            explanation.contains("not allowed to take packages from any origin"),
            "{explanation}"
        );
    } else {
        assert!(!explanation.contains("any origin"), "{explanation}");
    }
}

#[test]
fn a_timer_that_is_off_is_read_from_the_answer_not_from_the_exit_status() {
    // `systemctl is-enabled` says `disabled` and exits with 1.
    let sandbox = Sandbox::new("timers");
    if !host_uses_apt(&sandbox) {
        return;
    }
    sandbox.unit("apt-daily.timer", "enabled");
    sandbox.unit("apt-daily-upgrade.timer", "disabled");
    let finding = srv001(&sandbox.module(&[]));
    assert_eq!(finding["severity"], "warning", "{finding}");
    assert_eq!(
        evidence(&finding, "apt-daily.timer").as_deref(),
        Some("enabled")
    );
    assert_eq!(
        evidence(&finding, "apt-daily-upgrade.timer").as_deref(),
        Some("disabled")
    );
    let explanation = finding["explanation"].as_str().unwrap();
    assert!(
        explanation
            .contains("`apt-daily-upgrade.timer`, which runs `unattended-upgrade`, is disabled."),
        "{explanation}"
    );
    assert!(
        !explanation.contains("`apt-daily.timer`, which"),
        "{explanation}"
    );
    let steps = finding["recommendation"].as_str().unwrap();
    assert!(
        steps.contains("    sudo systemctl enable --now apt-daily-upgrade.timer\n"),
        "{steps}"
    );
    assert!(!steps.contains("unmask"), "{steps}");

    // Masked, and missing: the words systemd uses.
    sandbox.unit("apt-daily-upgrade.timer", "masked");
    std::fs::remove_file(sandbox.root.join("states/apt-daily.timer")).unwrap();
    let finding = srv001(&sandbox.module(&[]));
    assert_eq!(
        evidence(&finding, "apt-daily.timer").as_deref(),
        Some("not-found")
    );
    assert_eq!(
        evidence(&finding, "apt-daily-upgrade.timer").as_deref(),
        Some("masked")
    );
    let steps = finding["recommendation"].as_str().unwrap();
    assert!(
        steps.contains("    sudo systemctl unmask apt-daily-upgrade.timer\n"),
        "{steps}"
    );
    assert!(
        steps.contains("    sudo systemctl enable --now apt-daily.timer apt-daily-upgrade.timer\n"),
        "{steps}"
    );
}

#[test]
fn a_systemd_that_does_not_answer_is_information_not_a_warning() {
    // No `systemctl` the module can use: the timers are "unknown".
    let sandbox = Sandbox::new("no-systemd");
    if !host_uses_apt(&sandbox) {
        return;
    }
    sandbox_script(&sandbox.root.join("bin/systemctl"), "#!/bin/sh\nexit 1\n");
    let finding = srv001(&sandbox.module(&[]));
    assert_eq!(
        evidence(&finding, "apt-daily.timer").as_deref(),
        Some("unknown")
    );
    assert_eq!(
        evidence(&finding, "apt-daily-upgrade.timer").as_deref(),
        Some("unknown")
    );
    let explanation = finding["explanation"].as_str().unwrap();
    if evidence(&finding, "unattended_upgrade_installed").as_deref() == Some("yes") {
        assert_eq!(finding["severity"], "info", "{finding}");
        assert_eq!(finding["confidence"]["percent"], 100);
        assert!(explanation.contains("could not be told"), "{explanation}");
        assert!(finding["recommendation"].is_null());
    } else {
        // A fault that was seen is still reported.
        assert_eq!(finding["severity"], "warning", "{finding}");
    }
}

#[test]
fn an_apt_config_that_does_not_run_leaves_the_settings_unread() {
    let sandbox = Sandbox::new("no-apt-config");
    if !host_uses_apt(&sandbox) {
        return;
    }
    both_timers(&sandbox, "enabled");
    sandbox_script(
        &sandbox.root.join("bin/apt-config"),
        "#!/bin/sh\nexit 127\n",
    );
    let finding = srv001(&sandbox.module(&[]));
    assert_eq!(
        evidence(&finding, "update_package_lists"),
        None,
        "{finding}"
    );
    assert_eq!(evidence(&finding, "unattended_upgrade_interval"), None);
    assert_eq!(evidence(&finding, "allowed_origins"), None);
    let explanation = finding["explanation"].as_str().unwrap();
    if evidence(&finding, "unattended_upgrade_installed").as_deref() == Some("yes") {
        assert_eq!(finding["severity"], "info", "{finding}");
        assert!(
            explanation.contains("`apt-config dump` could not be run"),
            "{explanation}"
        );
    } else {
        assert_eq!(finding["severity"], "warning", "{finding}");
    }
}

#[test]
fn a_hung_systemctl_costs_one_time_limit_and_is_noted_once() {
    let sandbox = Sandbox::new("hung");
    if !host_uses_apt(&sandbox) {
        return;
    }
    sandbox_script(
        &sandbox.root.join("bin/systemctl"),
        "#!/bin/sh\nexec sleep 30\n",
    );
    let started = Instant::now();
    let report = sandbox.module(&["--timeout", "2"]);
    let took = started.elapsed();
    // Two units asked, one limit waited: the second call is skipped.
    assert!(took.as_secs_f64() < 3.9, "took {took:?}");
    let finding = srv001(&report);
    assert_eq!(
        evidence(&finding, "apt-daily.timer").as_deref(),
        Some("unknown")
    );
    assert_eq!(
        evidence(&finding, "apt-daily-upgrade.timer").as_deref(),
        Some("unknown")
    );
    let notes = report["results"][0]["notes"].as_array().unwrap();
    assert_eq!(notes.len(), 1, "{notes:?}");
    assert!(
        notes[0].as_str().unwrap().contains("systemctl"),
        "{notes:?}"
    );
}

#[test]
fn a_hostile_setting_is_cleaned_in_every_format() {
    let sandbox = Sandbox::new("hostile");
    if !host_uses_apt(&sandbox) {
        return;
    }
    both_timers(&sandbox, "enabled");
    sandbox.apt_config(&dump(None, "1", "\u{1b}[31mred\u{7}", 1));
    for format in ["json", "terminal", "markdown", "html"] {
        let o = sandbox.run(&[
            "audit",
            "--modules",
            "server",
            "--profile",
            "server",
            "--fail-on",
            "never",
            "--output",
            format,
        ]);
        let text = stdout(&o);
        // The report's own colours are escape sequences; the setting's is not.
        assert!(!text.contains("\u{1b}[31mred"), "{format}: {text}");
        assert!(!text.contains("\\u001b[31mred"), "{format}: {text}");
        assert!(!text.contains('\u{7}'), "{format}: {text}");
        assert!(text.contains("?[31mred?"), "{format}: {text}");
    }
}

#[test]
fn a_warning_does_not_fail_the_default_gate_but_fails_it_when_asked() {
    let sandbox = Sandbox::new("gate");
    if !host_uses_apt(&sandbox) {
        return;
    }
    both_timers(&sandbox, "disabled");
    let args = |gate: &'static [&'static str]| {
        let mut args = vec!["audit", "--modules", "server", "--profile", "server"];
        args.extend_from_slice(gate);
        args
    };
    let o = sandbox.run(&args(&[]));
    assert_eq!(
        o.status.code(),
        Some(0),
        "choosing the profile must not make the default exit status fail: {}",
        stdout(&o)
    );
    let o = sandbox.run(&args(&["--fail-on", "warning"]));
    assert_eq!(o.status.code(), Some(1), "{}", stdout(&o));
}

// ----- SRV002 and SRV003: the logs and the reboot marker ---------------------------
//
// What they read -- `/var/log`, `/run` -- belongs to the host, and a test can
// neither plant files there nor point the binary somewhere else. So these
// check the findings against what the host itself says; what each file would
// make the module say is tested on fake trees in the unit tests.

#[test]
fn the_checks_come_in_order_and_the_logs_follow_the_host() {
    let sandbox = Sandbox::new("logs");
    let report = sandbox.module(&[]);
    let ids: Vec<String> = findings(&report)
        .iter()
        .map(|f| f["id"].as_str().unwrap().to_string())
        .collect();
    assert_eq!(&ids[..2], ["SRV001", "SRV002"], "{ids:?}");
    assert!(ids.len() <= 3, "{ids:?}");

    let logs = finding_of(&report, "SRV002");
    assert_eq!(logs["title"], "Logs Kept Across Reboots");
    assert_eq!(logs["category"], "logs");
    let journald = ["var/log/journal", "run/log/journal", "run/systemd/journal"]
        .iter()
        .any(|dir| Path::new("/").join(dir).is_dir());
    if !journald {
        assert_eq!(evidence(&logs, "journald").as_deref(), Some("not found"));
        assert_eq!(logs["severity"], "info");
        assert_eq!(logs["confidence"]["percent"], 100);
        return;
    }
    assert_eq!(
        evidence(&logs, "var_log_journal").as_deref(),
        Some(if Path::new("/var/log/journal").is_dir() {
            "present"
        } else {
            "absent"
        }),
        "{logs}"
    );
    let setting = evidence(&logs, "journal_storage").expect("always reported");
    assert!(
        ["auto", "persistent", "volatile", "none", "not set"].contains(&setting.as_str()),
        "{logs}"
    );
    // Never worse than a warning, and a warning is never certain: the logs
    // may be sent somewhere else, which this cannot see.
    match logs["severity"].as_str().unwrap() {
        "info" => assert!(logs["recommendation"].is_null(), "{logs}"),
        "warning" => {
            assert_eq!(logs["confidence"]["percent"], 80, "{logs}");
            let steps = logs["recommendation"].as_str().expect("steps");
            assert!(steps.contains("sudo mkdir -p /var/log/journal"), "{steps}");
            assert_eq!(
                evidence(&logs, "syslog_files").as_deref(),
                Some("none written lately"),
                "a warning means no classic log either: {logs}"
            );
        }
        other => panic!("{other}: {logs}"),
    }
}

#[test]
fn a_waiting_reboot_is_reported_when_it_has_waited_a_week_and_not_before() {
    let sandbox = Sandbox::new("reboot");
    let report = sandbox.module(&[]);
    let reboot: Vec<_> = findings(&report)
        .into_iter()
        .filter(|f| f["id"] == "SRV003")
        .collect();
    let age_secs = fs::metadata("/var/run/reboot-required")
        .ok()
        .and_then(|m| m.modified().ok())
        .map(|t| {
            SystemTime::now()
                .duration_since(t)
                .unwrap_or_default()
                .as_secs()
        });
    const WEEK: u64 = 7 * 24 * 3600;
    match age_secs {
        // Far enough from the limit that the time the audit took does not matter.
        Some(age) if age > WEEK + 600 => {
            assert_eq!(reboot.len(), 1, "{reboot:?}");
            let f = &reboot[0];
            assert_eq!(f["title"], "Reboot Left Pending");
            assert_eq!(f["severity"], "warning");
            assert_eq!(f["confidence"]["percent"], 90);
            let days: u64 = evidence(f, "reboot_required_age_days")
                .expect("age")
                .parse()
                .unwrap();
            assert!(days >= 7 && days <= age / 86400 + 1, "{days} {age}");
            assert!(f["recommendation"]
                .as_str()
                .unwrap()
                .contains("sudo reboot"));
        }
        Some(age) if age + 600 < WEEK => assert!(reboot.is_empty(), "{reboot:?}"),
        Some(_) => {}
        None => assert!(reboot.is_empty(), "no marker, no finding: {reboot:?}"),
    }
}
