// SPDX-License-Identifier: GPL-3.0-only

//! The SSH server's configuration.
//!
//! Pure logic only: parsing `sshd_config` lines, the first-value-wins
//! lookup OpenSSH itself uses, and the judgement. Reading the file and
//! following its `Include` lines is `collect.rs`.
//!
//! Only the global part of the configuration is judged. Settings inside
//! `Match` blocks apply to some users or addresses only and depend on who
//! connects; they are counted and mentioned, not evaluated.

use crate::models::{Category, Confidence, Finding, Severity};
use crate::modules::recommend::Steps;

use super::listeners::{Endpoint, Exposure, Proto};

/// One meaningful line of an sshd_config file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Line {
    /// `Keyword value`, with the keyword lower-cased (they are
    /// case-insensitive).
    Directive {
        key: String,
        value: String,
    },
    Include(String),
    Match,
}

/// Parses one line; `None` for blank lines and comments.
///
/// sshd accepts `Keyword value` and `Keyword=value`.
pub fn parse_line(raw: &str) -> Option<Line> {
    let line = raw.trim();
    if line.is_empty() || line.starts_with('#') {
        return None;
    }
    let split = line
        .find(|c: char| c.is_whitespace() || c == '=')
        .unwrap_or(line.len());
    let key = line[..split].to_lowercase();
    let value = line[split..]
        .trim_start_matches(|c: char| c.is_whitespace() || c == '=')
        .trim()
        .trim_matches('"')
        .to_string();
    match key.as_str() {
        "match" => Some(Line::Match),
        "include" => Some(Line::Include(value)),
        _ if value.is_empty() => None,
        _ => Some(Line::Directive { key, value }),
    }
}

/// The global settings of the server, in the order sshd reads them
/// (included files at the place of their `Include` line).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SshConfig {
    /// The files that were read, in order.
    pub files: Vec<String>,
    pub directives: Vec<(String, String)>,
    /// Number of `Match` blocks (their content is not evaluated).
    pub match_blocks: usize,
    /// Included files that exist but could not be read.
    pub unreadable: Vec<String>,
    /// An `Include` of a `sshd_config.d` directory is present, so a
    /// drop-in file there is read.
    pub has_dropin_include: bool,
}

impl SshConfig {
    /// First value wins, as in sshd.
    pub fn get(&self, key: &str) -> Option<&str> {
        self.directives
            .iter()
            .find(|(k, _)| k == key)
            .map(|(_, v)| v.as_str())
    }

    /// Every value, for keywords that accumulate (Port, ListenAddress).
    pub fn all(&self, key: &str) -> Vec<&str> {
        self.directives
            .iter()
            .filter(|(k, _)| k == key)
            .map(|(_, v)| v.as_str())
            .collect()
    }

    /// A yes/no keyword with its default.
    pub fn flag(&self, key: &str, default: bool) -> bool {
        match self.get(key).map(str::to_lowercase).as_deref() {
            Some("yes") | Some("true") | Some("on") | Some("1") => true,
            Some("no") | Some("false") | Some("off") | Some("0") => false,
            _ => default,
        }
    }
}

/// Shell-style match of a file name against a pattern with `*` and `?`,
/// as used by `Include /etc/ssh/sshd_config.d/*.conf`.
pub fn glob_match(pattern: &str, name: &str) -> bool {
    let p: Vec<char> = pattern.chars().collect();
    let n: Vec<char> = name.chars().collect();
    let (mut pi, mut ni) = (0, 0);
    let mut star: Option<(usize, usize)> = None;
    while ni < n.len() {
        if pi < p.len() && (p[pi] == '?' || p[pi] == n[ni]) {
            pi += 1;
            ni += 1;
        } else if pi < p.len() && p[pi] == '*' {
            star = Some((pi, ni));
            pi += 1;
        } else if let Some((sp, sn)) = star {
            pi = sp + 1;
            ni = sn + 1;
            star = Some((sp, sn + 1));
        } else {
            return false;
        }
    }
    while pi < p.len() && p[pi] == '*' {
        pi += 1;
    }
    pi == p.len()
}

/// What was found on disk.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SshInfo {
    /// An sshd binary or its configuration file exists.
    pub installed: bool,
    pub config: Option<SshConfig>,
    /// Why the main file could not be read, when it exists.
    pub read_error: Option<String>,
}

/// What the listener scan says about the SSH server.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SshRuntime {
    pub listening: bool,
    /// Accepts connections from other machines.
    pub reachable: bool,
    pub ports: Vec<u16>,
}

pub fn runtime_of(endpoints: &[Endpoint]) -> SshRuntime {
    let mut rt = SshRuntime::default();
    for e in endpoints.iter().filter(|e| e.proto == Proto::Tcp) {
        let is_ssh = match &e.owner {
            Some(o) => o.name == "sshd",
            None => e.port == 22,
        };
        if !is_ssh {
            continue;
        }
        rt.listening = true;
        rt.ports.push(e.port);
        if e.exposure != Exposure::Loopback {
            rt.reachable = true;
        }
    }
    rt.ports.sort_unstable();
    rt.ports.dedup();
    rt
}

// ---------------------------------------------------------------------------
// Judgement
// ---------------------------------------------------------------------------

const WEAK_CIPHERS: &[&str] = &[
    "3des-cbc",
    "aes128-cbc",
    "aes192-cbc",
    "aes256-cbc",
    "blowfish-cbc",
    "cast128-cbc",
    "arcfour",
    "arcfour128",
    "arcfour256",
    "rijndael-cbc@lysator.liu.se",
];

const WEAK_MACS: &[&str] = &[
    "hmac-md5",
    "hmac-md5-96",
    "hmac-md5-etm@openssh.com",
    "hmac-md5-96-etm@openssh.com",
    "hmac-sha1-96",
    "hmac-sha1-96-etm@openssh.com",
    "hmac-ripemd160",
    "hmac-ripemd160@openssh.com",
    "umac-64@openssh.com",
    "umac-64-etm@openssh.com",
];

const WEAK_KEX: &[&str] = &[
    "diffie-hellman-group1-sha1",
    "diffie-hellman-group-exchange-sha1",
];

/// The explicitly listed algorithms of `value` that are in `weak`.
///
/// A leading `+` (add to the defaults) or `^` (put first) still enables
/// the algorithm, so it is judged; a leading `-` removes it, which is
/// good. Wildcard patterns are not judged: they may enable weak and
/// strong algorithms alike.
pub fn weak_algorithms(value: &str, weak: &[&str]) -> Vec<String> {
    value
        .split(',')
        .map(str::trim)
        .filter(|t| !t.starts_with('-') && !t.contains('*'))
        .map(|t| t.trim_start_matches(['+', '^']))
        .filter(|t| weak.contains(t))
        .map(str::to_string)
        .collect()
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Issue {
    pub severity: Severity,
    pub text: String,
    /// The `Keyword value` line that fixes it.
    pub fix: Option<(&'static str, &'static str)>,
}

fn issue(
    severity: Severity,
    text: impl Into<String>,
    fix: Option<(&'static str, &'static str)>,
) -> Issue {
    Issue {
        severity,
        text: text.into(),
        fix,
    }
}

/// Everything wrong with the global configuration, before the severities
/// are limited by whether the server is running.
pub fn issues(cfg: &SshConfig, rt: &SshRuntime) -> Vec<Issue> {
    let mut out = Vec::new();

    let password_auth = cfg.flag("passwordauthentication", true);
    let root_login = cfg
        .get("permitrootlogin")
        .map(str::to_lowercase)
        .unwrap_or_else(|| "prohibit-password".to_string());

    if cfg.flag("permitemptypasswords", false) {
        out.push(issue(
            Severity::Critical,
            "PermitEmptyPasswords is on: an account with no password can log in over SSH \
             by just pressing Enter.",
            Some(("PermitEmptyPasswords", "no")),
        ));
    }

    if root_login == "yes" {
        if password_auth {
            out.push(issue(
                Severity::Error,
                "PermitRootLogin is yes while password login is enabled: the root account can \
                 be attacked by guessing its password, from any machine that reaches the \
                 port. Automated scans try exactly this around the clock.",
                Some(("PermitRootLogin", "no")),
            ));
        } else {
            out.push(issue(
                Severity::Warning,
                "PermitRootLogin is yes: root can log in directly, with a key. Logging in as \
                 a normal user and using sudo leaves a trace of who did what and removes root \
                 as a known target.",
                Some(("PermitRootLogin", "no")),
            ));
        }
    }

    if let Some(protocol) = cfg.get("protocol") {
        if protocol.split(',').any(|p| p.trim() == "1") {
            out.push(issue(
                Severity::Error,
                "Protocol 1 is enabled: SSH version 1 has been broken for decades and was \
                 removed from OpenSSH in 2017.",
                Some(("Protocol", "2")),
            ));
        }
    }

    if password_auth {
        let explicit = cfg.get("passwordauthentication").is_some();
        let origin = if explicit {
            "PasswordAuthentication is yes"
        } else {
            "Password login is enabled (it is the default)"
        };
        let sev = if !rt.listening {
            Some(Severity::Info)
        } else if rt.reachable {
            Some(Severity::Warning)
        } else {
            None // only reachable from this machine
        };
        if let Some(sev) = sev {
            out.push(issue(
                sev,
                format!(
                    "{origin}: anyone who can reach the port can try passwords, and \
                     machines on the internet are tried thousands of times a day. Keys cannot \
                     be guessed this way."
                ),
                Some(("PasswordAuthentication", "no")),
            ));
        }
    }

    if cfg.flag("hostbasedauthentication", false) {
        out.push(issue(
            Severity::Warning,
            "HostbasedAuthentication is on: a machine is trusted as a whole, so a break-in on \
             it opens this one too.",
            Some(("HostbasedAuthentication", "no")),
        ));
    }
    if !cfg.flag("ignorerhosts", true) {
        out.push(issue(
            Severity::Warning,
            "IgnoreRhosts is off: the obsolete .rhosts trust files are honoured.",
            Some(("IgnoreRhosts", "yes")),
        ));
    }
    if cfg.flag("permituserenvironment", false) {
        out.push(issue(
            Severity::Warning,
            "PermitUserEnvironment is on: users can set environment variables for their own \
             login (such as LD_PRELOAD) and bypass restrictions placed on their account.",
            Some(("PermitUserEnvironment", "no")),
        ));
    }

    for (key, label, weak) in [
        ("ciphers", "Ciphers", WEAK_CIPHERS),
        ("macs", "MACs", WEAK_MACS),
        ("kexalgorithms", "KexAlgorithms", WEAK_KEX),
    ] {
        if let Some(value) = cfg.get(key) {
            let found = weak_algorithms(value, weak);
            if !found.is_empty() {
                out.push(issue(
                    Severity::Warning,
                    format!(
                        "{label} explicitly enables weak algorithms ({}). They exist only for \
                         very old clients; remove the line to get the safe modern defaults.",
                        found.join(", ")
                    ),
                    None,
                ));
            }
        }
    }

    if cfg.flag("x11forwarding", false) {
        out.push(issue(
            Severity::Info,
            "X11Forwarding is on. It is handy for graphical programs, but it lets a \
             compromised server reach the client's display. Turn it off on servers that do \
             not need it.",
            Some(("X11Forwarding", "no")),
        ));
    }
    if let Some(tries) = cfg.get("maxauthtries").and_then(|v| v.parse::<u32>().ok()) {
        if tries > 6 {
            out.push(issue(
                Severity::Info,
                format!(
                    "MaxAuthTries is {tries} (default 6): every connection may guess that \
                     many passwords before being dropped."
                ),
                Some(("MaxAuthTries", "4")),
            ));
        }
    }
    out
}

fn value_or_default(cfg: &SshConfig, key: &str, default: &str) -> String {
    match cfg.get(key) {
        Some(v) => v.to_string(),
        None => format!("{default} (default)"),
    }
}

/// SEC005. Returns nothing when there is no SSH server on the machine.
pub fn findings(info: &SshInfo, rt: &SshRuntime) -> Vec<Finding> {
    let Some(cfg) = &info.config else {
        return unconfigured(info, rt);
    };

    let mut found = issues(cfg, rt);
    // A server that is not running cannot be attacked right now.
    if !rt.listening {
        for i in &mut found {
            i.severity = i.severity.min(Severity::Warning);
        }
    }
    found.sort_by_key(|i| std::cmp::Reverse(i.severity));
    let severity = found.first().map(|i| i.severity).unwrap_or(Severity::Info);

    let confidence = if cfg.match_blocks > 0 || !cfg.unreadable.is_empty() {
        Confidence::strong_indication(85)
    } else {
        Confidence::direct_observation()
    };

    let ports = if cfg.all("port").is_empty() {
        "22 (default)".to_string()
    } else {
        cfg.all("port").join(", ")
    };
    let state = if !rt.listening {
        "not running".to_string()
    } else if rt.reachable {
        format!(
            "running, reachable from the network (port {})",
            join_ports(&rt.ports)
        )
    } else {
        format!(
            "running, local connections only (port {})",
            join_ports(&rt.ports)
        )
    };

    let mut builder = Finding::builder(
        "SEC005",
        "SSH Server Configuration",
        Category::Security,
        severity,
        confidence,
    )
    .evidence("server", state)
    .evidence("port", ports)
    .evidence(
        "PermitRootLogin",
        value_or_default(cfg, "permitrootlogin", "prohibit-password"),
    )
    .evidence(
        "PasswordAuthentication",
        value_or_default(cfg, "passwordauthentication", "yes"),
    )
    .evidence(
        "PermitEmptyPasswords",
        value_or_default(cfg, "permitemptypasswords", "no"),
    )
    .evidence(
        "PubkeyAuthentication",
        value_or_default(cfg, "pubkeyauthentication", "yes"),
    )
    .evidence(
        "X11Forwarding",
        value_or_default(cfg, "x11forwarding", "no"),
    )
    .evidence("MaxAuthTries", value_or_default(cfg, "maxauthtries", "6"))
    .evidence("config_files", cfg.files.join(", "));
    if cfg.match_blocks > 0 {
        builder = builder.evidence("match_blocks", cfg.match_blocks.to_string());
    }

    let mut paragraphs: Vec<String> = Vec::new();
    if found.is_empty() {
        paragraphs.push(
            "No risky setting found in the global section of the configuration: no root \
             login with a password, no empty passwords, no weak algorithms forced."
                .to_string(),
        );
    } else {
        for i in &found {
            paragraphs.push(format!(
                "[{}] {}",
                i.severity.to_string().to_uppercase(),
                i.text
            ));
        }
    }
    if !rt.listening {
        paragraphs.push(
            "The SSH server is installed but not running, so these settings apply from the day \
             it is started; severities are limited to Warning until then."
                .to_string(),
        );
    }
    if cfg.match_blocks > 0 {
        paragraphs.push(format!(
            "{} Match block(s) were not evaluated: they can override the settings above for \
             specific users, groups or addresses.",
            cfg.match_blocks
        ));
    }
    if !cfg.unreadable.is_empty() {
        paragraphs.push(format!(
            "Not readable (run as root): {}.",
            cfg.unreadable.join(", ")
        ));
    }
    builder = builder.explanation(paragraphs.join("\n\n"));

    let fixes: Vec<(&str, &str)> = found.iter().filter_map(|i| i.fix).collect();
    let actionable = found.iter().any(|i| i.severity >= Severity::Warning);
    if actionable {
        builder = builder.recommendation(fix_steps(cfg, &fixes, rt.reachable));
    }
    vec![builder.build()]
}

fn join_ports(ports: &[u16]) -> String {
    ports
        .iter()
        .map(u16::to_string)
        .collect::<Vec<_>>()
        .join(", ")
}

/// No usable configuration: either no SSH server at all (nothing to say),
/// or one that is there but cannot be judged.
fn unconfigured(info: &SshInfo, rt: &SshRuntime) -> Vec<Finding> {
    if let Some(error) = &info.read_error {
        return vec![Finding::builder(
            "SEC005",
            "SSH Server Configuration Unreadable",
            Category::Security,
            Severity::Info,
            Confidence::direct_observation(),
        )
        .evidence("config_file", "/etc/ssh/sshd_config")
        .evidence("error", error.clone())
        .explanation(
            "An SSH server is installed but its configuration file cannot be read by this \
             user, so its settings were not checked. Run LinuxDoctor with sudo.",
        )
        .build()];
    }
    if rt.listening {
        return vec![Finding::builder(
            "SEC005",
            "SSH Service Without sshd_config",
            Category::Security,
            Severity::Info,
            Confidence::strong_indication(80),
        )
        .evidence("port", join_ports(&rt.ports))
        .explanation(
            "Something listens on the SSH port but /etc/ssh/sshd_config does not exist, so it \
             is probably another SSH server (Dropbear, for instance) whose settings LinuxDoctor \
             does not read.",
        )
        .build()];
    }
    Vec::new()
}

fn fix_steps(cfg: &SshConfig, fixes: &[(&str, &str)], reachable: bool) -> String {
    let mut unique: Vec<(&str, &str)> = Vec::new();
    for f in fixes {
        if !unique.iter().any(|u| u.0 == f.0) {
            unique.push(*f);
        }
    }
    let lines: Vec<String> = unique.iter().map(|(k, v)| format!("{k} {v}")).collect();
    let disabling_passwords = unique.iter().any(|(k, _)| *k == "PasswordAuthentication");

    let mut steps = Steps::new();
    if disabling_passwords {
        steps = steps.step(
            "On your own computer, make sure a key works before turning passwords off, or you \
             will lock yourself out. Keep your current session open until step 4:",
            &[
                "ssh-copy-id user@this-machine",
                "ssh user@this-machine   # must log in without a password",
            ],
        );
    } else if reachable {
        steps = steps.step(
            "Keep your current SSH session open until step 4, in case a mistake locks new \
             connections out.",
            &[],
        );
    }

    if !lines.is_empty() {
        if cfg.has_dropin_include {
            let printf = format!(
                "printf '%s\\n' {} | sudo tee /etc/ssh/sshd_config.d/00-linuxdoctor.conf",
                lines
                    .iter()
                    .map(|l| format!("'{l}'"))
                    .collect::<Vec<_>>()
                    .join(" ")
            );
            steps = steps.step(
                "Write the safer settings in a file of their own. The name starts with 00 so \
                 that it is read first, and sshd keeps the first value it reads:",
                &[&printf],
            );
        } else {
            steps = steps.step(
                format!(
                    "Edit the configuration and set (replace any existing line for the same \
                     keyword): {}",
                    lines.join("; ")
                ),
                &["sudo nano /etc/ssh/sshd_config"],
            );
        }
    }
    steps = steps.step(
        "Remove any Ciphers, MACs or KexAlgorithms line that lists a weak algorithm, unless a \
         very old client needs it.",
        &[],
    );
    steps
        .step(
            "Check the syntax, then reload the server (the unit is named sshd on Fedora and \
             RHEL):",
            &["sudo sshd -t", "sudo systemctl reload ssh"],
        )
        .step(
            "From a second terminal, open a new connection to confirm it still works before \
             closing the first one.",
            &[],
        )
        .build()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::modules::security::listeners::Owner;
    use std::net::{IpAddr, Ipv4Addr};

    fn cfg(lines: &[&str]) -> SshConfig {
        let mut c = SshConfig {
            files: vec!["/etc/ssh/sshd_config".into()],
            ..Default::default()
        };
        for l in lines {
            if let Some(Line::Directive { key, value }) = parse_line(l) {
                c.directives.push((key, value));
            }
        }
        c
    }

    fn reachable() -> SshRuntime {
        SshRuntime {
            listening: true,
            reachable: true,
            ports: vec![22],
        }
    }

    fn info(c: SshConfig) -> SshInfo {
        SshInfo {
            installed: true,
            config: Some(c),
            read_error: None,
        }
    }

    #[test]
    fn lines_are_parsed_in_both_syntaxes() {
        assert_eq!(
            parse_line("PermitRootLogin no"),
            Some(Line::Directive {
                key: "permitrootlogin".into(),
                value: "no".into()
            })
        );
        assert_eq!(
            parse_line("  Port=2222  "),
            Some(Line::Directive {
                key: "port".into(),
                value: "2222".into()
            })
        );
        assert_eq!(
            parse_line("Banner \"/etc/issue.net\""),
            Some(Line::Directive {
                key: "banner".into(),
                value: "/etc/issue.net".into()
            })
        );
        assert_eq!(parse_line("# PermitRootLogin yes"), None);
        assert_eq!(parse_line(""), None);
        assert_eq!(
            parse_line("PermitRootLogin"),
            None,
            "a keyword with no value"
        );
        assert_eq!(parse_line("Match User bob"), Some(Line::Match));
        assert_eq!(
            parse_line("Include /etc/ssh/sshd_config.d/*.conf"),
            Some(Line::Include("/etc/ssh/sshd_config.d/*.conf".into()))
        );
    }

    #[test]
    fn glob_matching() {
        assert!(glob_match("*.conf", "50-cloud-init.conf"));
        assert!(!glob_match("*.conf", "50-cloud-init.conf.bak"));
        assert!(glob_match("sshd_config.?", "sshd_config.d"));
        assert!(glob_match("*", "anything"));
        assert!(glob_match("a*b*c", "aXXbYYc"));
        assert!(!glob_match("a*b*c", "aXXbYY"));
        assert!(glob_match("exact", "exact"));
        assert!(!glob_match("exact", "exacts"));
        assert!(glob_match("", ""));
        assert!(!glob_match("", "x"));
    }

    #[test]
    fn first_value_wins_and_port_accumulates() {
        let c = cfg(&[
            "PermitRootLogin no",
            "PermitRootLogin yes",
            "Port 22",
            "Port 2222",
        ]);
        assert_eq!(c.get("permitrootlogin"), Some("no"));
        assert_eq!(c.all("port"), vec!["22", "2222"]);
        assert_eq!(c.get("missing"), None);
    }

    #[test]
    fn flags_understand_every_spelling_and_fall_back_to_the_default() {
        let c = cfg(&["A yes", "B No", "C on", "D off", "E maybe"]);
        assert!(c.flag("a", false));
        assert!(!c.flag("b", true));
        assert!(c.flag("c", false));
        assert!(!c.flag("d", true));
        assert!(c.flag("e", true));
        assert!(!c.flag("absent", false));
    }

    #[test]
    fn weak_algorithms_are_found_even_when_added_to_the_defaults() {
        assert_eq!(
            weak_algorithms("aes256-ctr,aes128-cbc,3des-cbc", WEAK_CIPHERS),
            vec!["aes128-cbc", "3des-cbc"]
        );
        assert_eq!(
            weak_algorithms("+3des-cbc", WEAK_CIPHERS),
            vec!["3des-cbc"],
            "+ adds to the defaults"
        );
        assert!(weak_algorithms("-3des-cbc,-aes128-cbc", WEAK_CIPHERS).is_empty());
        assert!(
            weak_algorithms("aes*-cbc", WEAK_CIPHERS).is_empty(),
            "patterns are not judged"
        );
        assert!(weak_algorithms("chacha20-poly1305@openssh.com", WEAK_CIPHERS).is_empty());
    }

    #[test]
    fn a_default_debian_style_config_on_the_internet_warns_about_passwords_only() {
        let c = cfg(&[
            "Include /etc/ssh/sshd_config.d/*.conf",
            "UsePAM yes",
            "X11Forwarding yes",
        ]);
        let found = issues(&c, &reachable());
        let sev: Vec<Severity> = found.iter().map(|i| i.severity).collect();
        assert_eq!(sev, vec![Severity::Warning, Severity::Info]);
        assert!(found[0].text.contains("it is the default"));
        assert!(found[1].text.contains("X11Forwarding"));
    }

    #[test]
    fn hardened_config_has_no_issues() {
        let c = cfg(&[
            "PermitRootLogin no",
            "PasswordAuthentication no",
            "PubkeyAuthentication yes",
            "MaxAuthTries 3",
        ]);
        assert!(issues(&c, &reachable()).is_empty());
    }

    #[test]
    fn root_login_with_password_is_an_error_and_keys_only_is_a_warning() {
        let c = cfg(&["PermitRootLogin yes"]);
        let found = issues(&c, &reachable());
        assert!(found
            .iter()
            .any(|i| i.severity == Severity::Error && i.text.contains("PermitRootLogin")));

        let c = cfg(&["PermitRootLogin yes", "PasswordAuthentication no"]);
        let found = issues(&c, &reachable());
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].severity, Severity::Warning);
    }

    #[test]
    fn prohibit_password_and_without_password_are_fine() {
        for v in [
            "prohibit-password",
            "without-password",
            "forced-commands-only",
            "no",
        ] {
            let c = cfg(&[&format!("PermitRootLogin {v}"), "PasswordAuthentication no"]);
            assert!(issues(&c, &reachable()).is_empty(), "{v}");
        }
    }

    #[test]
    fn empty_passwords_are_critical() {
        let c = cfg(&["PermitEmptyPasswords yes", "PasswordAuthentication no"]);
        let found = issues(&c, &reachable());
        assert_eq!(found[0].severity, Severity::Critical);
    }

    #[test]
    fn protocol_one_is_an_error_but_protocol_two_is_fine() {
        let bad = issues(
            &cfg(&["Protocol 2,1", "PasswordAuthentication no"]),
            &reachable(),
        );
        assert_eq!(bad[0].severity, Severity::Error);
        let ok = issues(
            &cfg(&["Protocol 2", "PasswordAuthentication no"]),
            &reachable(),
        );
        assert!(ok.is_empty());
    }

    #[test]
    fn password_login_matters_according_to_who_can_reach_the_server() {
        let c = cfg(&[]);
        let local = SshRuntime {
            listening: true,
            reachable: false,
            ports: vec![22],
        };
        assert!(issues(&c, &local).is_empty(), "loopback only");
        let stopped = SshRuntime::default();
        let found = issues(&c, &stopped);
        assert_eq!(found[0].severity, Severity::Info);
    }

    #[test]
    fn other_risky_switches_are_warnings() {
        let c = cfg(&[
            "PasswordAuthentication no",
            "HostbasedAuthentication yes",
            "IgnoreRhosts no",
            "PermitUserEnvironment yes",
            "Ciphers aes128-cbc",
            "MACs hmac-md5",
            "KexAlgorithms diffie-hellman-group1-sha1",
        ]);
        let found = issues(&c, &reachable());
        assert_eq!(found.len(), 6);
        assert!(found.iter().all(|i| i.severity == Severity::Warning));
    }

    #[test]
    fn max_auth_tries_above_the_default_is_info() {
        let c = cfg(&["PasswordAuthentication no", "MaxAuthTries 10"]);
        let found = issues(&c, &reachable());
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].severity, Severity::Info);
        assert!(issues(
            &cfg(&["PasswordAuthentication no", "MaxAuthTries 6"]),
            &reachable()
        )
        .is_empty());
    }

    #[test]
    fn finding_takes_the_worst_severity_and_lists_effective_values() {
        let f = &findings(&info(cfg(&["PermitRootLogin yes"])), &reachable())[0];
        assert_eq!(f.id, "SEC005");
        assert_eq!(f.severity, Severity::Error);
        let ev = |k: &str| {
            f.evidence
                .iter()
                .find(|(key, _)| key == k)
                .map(|(_, v)| v.clone())
        };
        assert_eq!(ev("PermitRootLogin").as_deref(), Some("yes"));
        assert_eq!(
            ev("PasswordAuthentication").as_deref(),
            Some("yes (default)")
        );
        assert_eq!(ev("port").as_deref(), Some("22 (default)"));
        assert!(ev("server").unwrap().contains("reachable from the network"));
        assert!(
            f.explanation.starts_with("[ERROR]"),
            "worst first: {}",
            f.explanation
        );
    }

    #[test]
    fn clean_configuration_is_info_without_recommendation() {
        let c = cfg(&["PermitRootLogin no", "PasswordAuthentication no"]);
        let f = &findings(&info(c), &reachable())[0];
        assert_eq!(f.severity, Severity::Info);
        assert!(f.recommendation.is_none());
        assert!(f.explanation.contains("No risky setting"));
        assert_eq!(f.confidence.percent, 100);
    }

    #[test]
    fn a_stopped_server_is_capped_at_warning() {
        let c = cfg(&["PermitEmptyPasswords yes"]);
        let f = &findings(&info(c), &SshRuntime::default())[0];
        assert_eq!(f.severity, Severity::Warning);
        assert!(f.explanation.contains("not running"));
    }

    #[test]
    fn match_blocks_and_unreadable_files_lower_confidence_and_are_mentioned() {
        let mut c = cfg(&["PasswordAuthentication no"]);
        c.match_blocks = 2;
        c.unreadable = vec!["/etc/ssh/sshd_config.d/50-x.conf".into()];
        let f = &findings(&info(c), &reachable())[0];
        assert_eq!(f.confidence.percent, 85);
        assert!(f
            .explanation
            .contains("2 Match block(s) were not evaluated"));
        assert!(f.explanation.contains("50-x.conf"));
    }

    #[test]
    fn recommendation_uses_a_drop_in_when_the_config_includes_the_directory() {
        let mut c = cfg(&["PermitRootLogin yes"]);
        c.has_dropin_include = true;
        let rec = findings(&info(c), &reachable())[0]
            .recommendation
            .clone()
            .unwrap();
        assert!(rec.contains("/etc/ssh/sshd_config.d/00-linuxdoctor.conf"));
        assert!(rec.contains("'PermitRootLogin no'"));
        assert!(rec.contains("'PasswordAuthentication no'"));
        assert!(
            rec.contains("ssh-copy-id"),
            "passwords are being turned off"
        );
        let key = rec.find("ssh-copy-id").unwrap();
        let write = rec.find("00-linuxdoctor.conf").unwrap();
        let check = rec.find("sudo sshd -t").unwrap();
        assert!(
            key < write && write < check,
            "key first, then the change, then the check"
        );
    }

    #[test]
    fn recommendation_asks_for_a_manual_edit_without_a_drop_in_directory() {
        let rec = findings(&info(cfg(&["PermitRootLogin yes"])), &reachable())[0]
            .recommendation
            .clone()
            .unwrap();
        assert!(rec.contains("sudo nano /etc/ssh/sshd_config"));
        assert!(!rec.contains("00-linuxdoctor.conf"));
    }

    #[test]
    fn info_only_issues_come_without_a_recommendation() {
        let c = cfg(&[
            "PermitRootLogin no",
            "PasswordAuthentication no",
            "X11Forwarding yes",
        ]);
        let f = &findings(&info(c), &reachable())[0];
        assert_eq!(f.severity, Severity::Info);
        assert!(f.recommendation.is_none());
        assert!(f.explanation.contains("X11Forwarding"));
    }

    #[test]
    fn unreadable_main_config_is_reported_not_guessed() {
        let i = SshInfo {
            installed: true,
            config: None,
            read_error: Some("permission denied".into()),
        };
        let f = &findings(&i, &SshRuntime::default())[0];
        assert!(f.title.contains("Unreadable"));
        assert_eq!(f.severity, Severity::Info);
    }

    #[test]
    fn no_ssh_server_means_no_finding() {
        assert!(findings(&SshInfo::default(), &SshRuntime::default()).is_empty());
    }

    #[test]
    fn listener_without_config_is_probably_another_ssh_server() {
        let rt = reachable();
        let f = &findings(&SshInfo::default(), &rt)[0];
        assert!(f.title.contains("Without sshd_config"));
    }

    fn endpoint(port: u16, exposure: Exposure, name: Option<&str>) -> Endpoint {
        Endpoint {
            proto: Proto::Tcp,
            port,
            binds: vec![IpAddr::V4(Ipv4Addr::UNSPECIFIED)],
            exposure,
            owner: name.map(|n| Owner {
                pid: 1,
                name: n.into(),
            }),
            uid: 0,
        }
    }

    #[test]
    fn runtime_is_found_by_program_name_or_by_port_22_when_the_owner_is_hidden() {
        let rt = runtime_of(&[
            endpoint(2222, Exposure::Wildcard, Some("sshd")),
            endpoint(80, Exposure::Wildcard, Some("nginx")),
        ]);
        assert!(rt.listening && rt.reachable);
        assert_eq!(rt.ports, vec![2222]);

        let rt = runtime_of(&[endpoint(22, Exposure::Wildcard, None)]);
        assert!(rt.listening);

        let rt = runtime_of(&[endpoint(22, Exposure::Loopback, Some("sshd"))]);
        assert!(rt.listening && !rt.reachable);

        let rt = runtime_of(&[endpoint(22, Exposure::Wildcard, Some("nginx"))]);
        assert!(!rt.listening, "port 22 belongs to another program");
    }
}
