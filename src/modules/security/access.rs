// SPDX-License-Identifier: GPL-3.0-only

//! Mandatory access control (SELinux, AppArmor) and the kernel and network
//! settings that harden — or weaken — a machine.
//!
//! Pure logic only: the values were read by `collect.rs`.

use crate::models::{Category, Confidence, Finding, Severity};
use crate::modules::recommend::Steps;

use crate::modules::recommend::{family_of, Family};

// ---------------------------------------------------------------------------
// Mandatory access control
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SelinuxMode {
    Enforcing,
    Permissive,
}

impl SelinuxMode {
    fn label(self) -> &'static str {
        match self {
            SelinuxMode::Enforcing => "enforcing",
            SelinuxMode::Permissive => "permissive",
        }
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct AppArmorInfo {
    /// `/sys/module/apparmor/parameters/enabled`; `None` when the module
    /// is not there.
    pub enabled: Option<bool>,
    /// Profile counts, readable by root only.
    pub enforce: Option<usize>,
    pub complain: Option<usize>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct MacInfo {
    /// The active Linux security modules (`/sys/kernel/security/lsm`);
    /// `None` when that file cannot be read (containers, old kernels).
    pub lsm: Option<Vec<String>>,
    /// `None` when SELinux is not running (its filesystem is not mounted).
    pub selinux_runtime: Option<SelinuxMode>,
    /// `SELINUX=` in /etc/selinux/config.
    pub selinux_config: Option<String>,
    pub apparmor: AppArmorInfo,
}

/// Parses `/sys/kernel/security/lsm` ("lockdown,capability,yama,apparmor").
pub fn parse_lsm(text: &str) -> Vec<String> {
    text.trim()
        .split(',')
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_string)
        .collect()
}

/// Parses `/etc/selinux/config` for the `SELINUX=` line.
pub fn parse_selinux_config(text: &str) -> Option<String> {
    text.lines()
        .map(str::trim)
        .filter(|l| !l.starts_with('#'))
        .find_map(|l| l.strip_prefix("SELINUX="))
        .map(|v| v.trim().to_lowercase())
}

/// Parses `/sys/kernel/security/apparmor/profiles`: one profile per line,
/// ending with its mode in parentheses. Returns (enforce, complain).
pub fn parse_apparmor_profiles(text: &str) -> (usize, usize) {
    let mut enforce = 0;
    let mut complain = 0;
    for line in text.lines() {
        let line = line.trim_end();
        if line.ends_with("(enforce)") {
            enforce += 1;
        } else if line.ends_with("(complain)") {
            complain += 1;
        }
    }
    (enforce, complain)
}

impl MacInfo {
    fn lsm_has(&self, name: &str) -> bool {
        self.lsm
            .as_ref()
            .is_some_and(|l| l.iter().any(|m| m == name))
    }

    pub fn selinux_active(&self) -> bool {
        self.selinux_runtime.is_some() || self.lsm_has("selinux")
    }

    pub fn apparmor_active(&self) -> bool {
        match self.apparmor.enabled {
            Some(enabled) => enabled,
            None => self.lsm_has("apparmor"),
        }
    }

    /// One short phrase for the overview.
    pub fn summary(&self) -> String {
        if let Some(mode) = self.selinux_runtime {
            format!("SELinux {}", mode.label())
        } else if self.apparmor_active() {
            "AppArmor active".to_string()
        } else if self.lsm.is_none() {
            "not determined".to_string()
        } else {
            "none active".to_string()
        }
    }
}

/// SEC006.
pub fn mac_finding(mac: &MacInfo, distro: Option<&str>) -> Finding {
    let family = family_of(distro);
    let selinux_configured = matches!(
        mac.selinux_config.as_deref(),
        Some("enforcing") | Some("permissive")
    );

    let mut evidence: Vec<(&str, String)> = Vec::new();
    evidence.push((
        "active_modules",
        mac.lsm
            .as_ref()
            .map(|l| l.join(","))
            .unwrap_or_else(|| "unknown (not readable)".to_string()),
    ));
    if let Some(mode) = mac.selinux_runtime {
        evidence.push(("selinux_mode", mode.label().to_string()));
    }
    if let Some(cfg) = &mac.selinux_config {
        evidence.push(("selinux_config", cfg.clone()));
    }
    if mac.apparmor_active() {
        match (mac.apparmor.enforce, mac.apparmor.complain) {
            (Some(e), Some(c)) => {
                evidence.push(("apparmor_profiles", format!("{e} enforcing, {c} complain")))
            }
            _ => evidence.push(("apparmor_profiles", "not readable without root".to_string())),
        }
    }

    let (title, severity, text, steps): (&str, Severity, String, Option<Steps>) =
        if let Some(mode) = mac.selinux_runtime {
            match mode {
                SelinuxMode::Enforcing => (
                    "Mandatory Access Control \u{2014} SELinux Enforcing",
                    Severity::Info,
                    "SELinux is enforcing: programs are confined by policy, so a compromised \
                     service cannot freely read or change files outside its role."
                        .to_string(),
                    None,
                ),
                SelinuxMode::Permissive => {
                    let how = match mac.selinux_config.as_deref() {
                        Some("enforcing") => {
                            "The configuration asks for enforcing mode, so it was switched off \
                             by hand (setenforce 0) and will return to enforcing at the next \
                             reboot."
                        }
                        Some("permissive") => "The configuration file sets permissive mode.",
                        _ => "",
                    };
                    let parts = [
                        "SELinux is in permissive mode: it logs what the policy would forbid \
                         but blocks nothing, so it gives no protection.",
                        how,
                        "Permissive mode is meant for finding out what a new policy would \
                         break, not for production.",
                    ];
                    (
                        "Mandatory Access Control \u{2014} SELinux Permissive",
                        Severity::Warning,
                        parts
                            .iter()
                            .filter(|p| !p.is_empty())
                            .copied()
                            .collect::<Vec<_>>()
                            .join(" "),
                        Some(enforce_selinux_steps()),
                    )
                }
            }
        } else if selinux_configured {
            (
                "Mandatory Access Control \u{2014} SELinux Not Running",
                Severity::Warning,
                format!(
                    "/etc/selinux/config asks for SELinux ({}), but the kernel is not running \
                     it: it was probably turned off on the kernel command line (selinux=0). \
                     Nothing is confining the programs.",
                    mac.selinux_config.as_deref().unwrap_or("?")
                ),
                Some(reenable_selinux_steps()),
            )
        } else if mac.apparmor_active() {
            let detail = match (mac.apparmor.enforce, mac.apparmor.complain) {
                (Some(e), Some(c)) if e + c == 0 => {
                    "AppArmor is on but no profile is loaded, so it confines nothing yet."
                        .to_string()
                }
                (Some(e), Some(c)) => format!(
                    "AppArmor is on with {e} profile(s) enforcing and {c} in complain mode \
                     (complain mode only logs)."
                ),
                _ => "AppArmor is on. Profile counts are readable by root only.".to_string(),
            };
            (
                "Mandatory Access Control \u{2014} AppArmor Active",
                Severity::Info,
                detail,
                None,
            )
        } else if mac.lsm.is_none() {
            (
                "Mandatory Access Control \u{2014} Not Determined",
                Severity::Info,
                "The kernel does not say which security modules are active (typical of a \
                 container or a very old kernel), so SELinux and AppArmor could not be checked."
                    .to_string(),
                None,
            )
        } else if family == Family::RedHatLike {
            (
                "Mandatory Access Control \u{2014} SELinux Off",
                Severity::Warning,
                "No mandatory access control is active. This distribution family ships with \
                 SELinux enforcing, and its services are written to run under it; running \
                 without it removes the main barrier between a compromised service and the \
                 rest of the system."
                    .to_string(),
                Some(reenable_selinux_steps()),
            )
        } else {
            (
                "Mandatory Access Control \u{2014} None Active",
                Severity::Info,
                "Neither SELinux nor AppArmor is active. Ordinary file permissions still \
                 apply, but a compromised service is not confined beyond them. On Debian, \
                 Ubuntu and SUSE, AppArmor is available (apt install apparmor apparmor-profiles \
                 and boot with apparmor=1 security=apparmor)."
                    .to_string(),
                None,
            )
        };

    let mut builder = Finding::builder(
        "SEC006",
        title,
        Category::Security,
        severity,
        if mac.lsm.is_none() {
            Confidence::strong_indication(80)
        } else {
            Confidence::direct_observation()
        },
    );
    for (k, v) in evidence {
        builder = builder.evidence(k, v);
    }
    builder = builder.explanation(text);
    if let Some(steps) = steps {
        builder = builder.recommendation(steps.build());
    }
    builder.build()
}

fn enforce_selinux_steps() -> Steps {
    Steps::new()
        .step(
            "Look at what the policy has been refusing (needs auditd) before enforcing, so a \
             service you rely on does not stop working:",
            &["sudo ausearch -m avc -ts boot"],
        )
        .step(
            "Enforce now, without a reboot:",
            &["sudo setenforce 1", "getenforce"],
        )
        .step(
            "Make it permanent:",
            &["sudo sed -i 's/^SELINUX=.*/SELINUX=enforcing/' /etc/selinux/config"],
        )
}

fn reenable_selinux_steps() -> Steps {
    Steps::new()
        .step(
            "Check whether the kernel command line turns it off (look for selinux=0 or \
             enforcing=0):",
            &["cat /proc/cmdline"],
        )
        .step(
            "Set SELinux to enforcing in its configuration:",
            &["sudo sed -i 's/^SELINUX=.*/SELINUX=enforcing/' /etc/selinux/config"],
        )
        .step(
            "Files created while SELinux was off carry no label: ask for a full relabel at the \
             next boot (it can take several minutes), then reboot:",
            &["sudo touch /.autorelabel", "sudo reboot"],
        )
}

// ---------------------------------------------------------------------------
// Kernel and network hardening
// ---------------------------------------------------------------------------

/// The sysctl values that were read: key (as `net.ipv4.tcp_syncookies`)
/// and its content, `None` when the file does not exist or cannot be read.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct HardeningData {
    pub readings: Vec<(String, Option<String>)>,
}

impl HardeningData {
    pub fn get(&self, key: &str) -> Option<&str> {
        self.readings
            .iter()
            .find(|(k, _)| k == key)
            .and_then(|(_, v)| v.as_deref())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Weak {
    Equals(&'static str),
    Below(i64),
}

#[derive(Debug, PartialEq, Eq)]
pub struct Check {
    pub key: &'static str,
    pub weak: Weak,
    pub wanted: &'static str,
    pub severity: Severity,
    /// Only meaningful on a machine that does not route packets between
    /// networks (ip_forward = 0).
    pub host_only: bool,
    pub why: &'static str,
}

pub const CHECKS: &[Check] = &[
    Check {
        key: "net.ipv4.tcp_syncookies",
        weak: Weak::Equals("0"),
        wanted: "1",
        severity: Severity::Warning,
        host_only: false,
        why: "SYN cookies are the defence against SYN floods, which fill the connection table \
              with half-open connections until real clients are refused. The kernel enables \
              them by default; someone turned them off.",
    },
    Check {
        key: "net.ipv4.icmp_echo_ignore_broadcasts",
        weak: Weak::Equals("0"),
        wanted: "1",
        severity: Severity::Warning,
        host_only: false,
        why: "The machine answers pings sent to a whole network at once, which lets an attacker \
              use it to flood a victim (a Smurf attack). The kernel ignores them by default.",
    },
    Check {
        key: "net.ipv4.conf.all.accept_source_route",
        weak: Weak::Equals("1"),
        wanted: "0",
        severity: Severity::Warning,
        host_only: false,
        why: "Source-routed packets let the sender choose the path, which can bypass firewalls \
              and spoof trusted addresses. Nothing legitimate needs them today.",
    },
    Check {
        key: "net.ipv6.conf.all.accept_source_route",
        weak: Weak::Equals("1"),
        wanted: "0",
        severity: Severity::Warning,
        host_only: false,
        why: "IPv6 source routing has the same problem as in IPv4 and nothing legitimate uses it.",
    },
    Check {
        key: "fs.protected_symlinks",
        weak: Weak::Equals("0"),
        wanted: "1",
        severity: Severity::Warning,
        host_only: false,
        why: "Without this, a user can plant a symbolic link in a shared directory such as /tmp \
              and trick a privileged program into following it to a file it should not touch.",
    },
    Check {
        key: "fs.protected_hardlinks",
        weak: Weak::Equals("0"),
        wanted: "1",
        severity: Severity::Warning,
        host_only: false,
        why: "Without this, any user can create a hard link to a file they do not own (a setuid \
              program, for instance) and keep it after it is updated or replaced.",
    },
    Check {
        key: "fs.suid_dumpable",
        weak: Weak::Equals("1"),
        wanted: "0",
        severity: Severity::Warning,
        host_only: false,
        why: "Value 1 makes core dumps of privileged programs readable by ordinary users, which \
              can expose passwords and keys held in their memory.",
    },
    Check {
        key: "vm.mmap_min_addr",
        weak: Weak::Below(4096),
        wanted: "65536",
        severity: Severity::Warning,
        host_only: false,
        why: "Programs may map the first memory pages, which turns many kernel null-pointer bugs \
              into privilege escalations.",
    },
    Check {
        key: "net.ipv4.conf.all.accept_redirects",
        weak: Weak::Equals("1"),
        wanted: "0",
        severity: Severity::Info,
        host_only: true,
        why: "ICMP redirects let any machine on the network change this one's routes.",
    },
    Check {
        key: "net.ipv6.conf.all.accept_redirects",
        weak: Weak::Equals("1"),
        wanted: "0",
        severity: Severity::Info,
        host_only: true,
        why: "IPv6 redirects let any machine on the network change this one's routes.",
    },
    Check {
        key: "net.ipv4.conf.all.send_redirects",
        weak: Weak::Equals("1"),
        wanted: "0",
        severity: Severity::Info,
        host_only: true,
        why: "A machine that does not route packets has no reason to tell others about better \
              routes.",
    },
    Check {
        key: "net.ipv4.conf.all.rp_filter",
        weak: Weak::Equals("0"),
        wanted: "1",
        severity: Severity::Info,
        host_only: false,
        why: "Reverse-path filtering drops packets whose source address could not come from the \
              interface they arrived on (spoofing). Use 2 instead of 1 if traffic legitimately \
              returns by another path.",
    },
    Check {
        key: "kernel.kptr_restrict",
        weak: Weak::Equals("0"),
        wanted: "1",
        severity: Severity::Info,
        host_only: false,
        why: "Kernel addresses are visible to every user, which helps exploits defeat address \
              randomisation.",
    },
    Check {
        key: "kernel.dmesg_restrict",
        weak: Weak::Equals("0"),
        wanted: "1",
        severity: Severity::Info,
        host_only: false,
        why: "Every user can read the kernel log, which contains addresses and hardware details \
              useful to an attacker.",
    },
    Check {
        key: "kernel.yama.ptrace_scope",
        weak: Weak::Equals("0"),
        wanted: "1",
        severity: Severity::Info,
        host_only: false,
        why: "Any process can read the memory of any other process of the same user, including a \
              browser's or an ssh-agent's secrets. Debuggers such as gdb need a sudo or a lower \
              value when this is 1.",
    },
    Check {
        key: "kernel.unprivileged_bpf_disabled",
        weak: Weak::Equals("0"),
        wanted: "2",
        severity: Severity::Info,
        host_only: false,
        why: "Unprivileged users can load eBPF programs, a frequent source of kernel exploits.",
    },
    Check {
        key: "kernel.perf_event_paranoid",
        weak: Weak::Below(2),
        wanted: "2",
        severity: Severity::Info,
        host_only: false,
        why: "Unprivileged users can profile the kernel, which exposes timing and address \
              information. Profilers such as perf need it lowered for non-root use.",
    },
    Check {
        key: "fs.protected_regular",
        weak: Weak::Equals("0"),
        wanted: "2",
        severity: Severity::Info,
        host_only: false,
        why: "Programs can be tricked into writing to a file an attacker pre-created in a shared \
              sticky directory such as /tmp.",
    },
    Check {
        key: "fs.protected_fifos",
        weak: Weak::Equals("0"),
        wanted: "2",
        severity: Severity::Info,
        host_only: false,
        why: "Programs can be tricked into writing to a named pipe an attacker pre-created in a \
              shared sticky directory such as /tmp.",
    },
];

/// The keys to read: every check, plus the forwarding switch that decides
/// whether the host-only checks apply.
pub fn keys_to_read() -> Vec<&'static str> {
    let mut keys: Vec<&'static str> = CHECKS.iter().map(|c| c.key).collect();
    keys.push("net.ipv4.ip_forward");
    keys
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WeakSetting {
    pub check: &'static Check,
    pub value: String,
}

fn is_weak(weak: Weak, value: &str) -> bool {
    match weak {
        Weak::Equals(w) => value == w,
        Weak::Below(limit) => value.parse::<i64>().is_ok_and(|v| v < limit),
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct HardeningReport {
    /// Checks whose value could be read.
    pub readable: usize,
    pub weak: Vec<WeakSetting>,
    pub forwarding: bool,
}

pub fn evaluate_hardening(data: &HardeningData) -> HardeningReport {
    let forwarding = data.get("net.ipv4.ip_forward").map(str::trim) == Some("1");
    let mut report = HardeningReport {
        forwarding,
        ..Default::default()
    };
    for check in CHECKS {
        if check.host_only && forwarding {
            continue;
        }
        let Some(value) = data.get(check.key).map(str::trim) else {
            continue;
        };
        report.readable += 1;
        if is_weak(check.weak, value) {
            report.weak.push(WeakSetting {
                check,
                value: value.to_string(),
            });
        }
    }
    report
}

fn sysctl_file_command(file: &str, settings: &[&WeakSetting]) -> String {
    let lines: Vec<String> = settings
        .iter()
        .map(|w| format!("'{} = {}'", w.check.key, w.check.wanted))
        .collect();
    format!(
        "printf '%s\\n' {} | sudo tee /etc/sysctl.d/{file}",
        lines.join(" ")
    )
}

/// SEC007.
pub fn hardening_finding(report: &HardeningReport) -> Finding {
    if report.readable == 0 {
        return Finding::builder(
            "SEC007",
            "Kernel & Network Hardening",
            Category::Security,
            Severity::Info,
            Confidence::weak_indication(60),
        )
        .evidence("settings_read", "0")
        .explanation(
            "None of the hardening settings under /proc/sys could be read (a restricted \
             container, probably), so they were not checked.",
        )
        .build();
    }

    let important: Vec<&WeakSetting> = report
        .weak
        .iter()
        .filter(|w| w.check.severity >= Severity::Warning)
        .collect();
    let optional: Vec<&WeakSetting> = report
        .weak
        .iter()
        .filter(|w| w.check.severity < Severity::Warning)
        .collect();
    let severity = if important.is_empty() {
        Severity::Info
    } else {
        Severity::Warning
    };

    let mut paragraphs = Vec::new();
    if report.weak.is_empty() {
        paragraphs.push(format!(
            "All {} hardening settings that could be read have safe values.",
            report.readable
        ));
    }
    for w in &important {
        paragraphs.push(format!(
            "{} is {} (should be {}). {}",
            w.check.key, w.value, w.check.wanted, w.check.why
        ));
    }
    if !optional.is_empty() {
        paragraphs.push(
            "Optional hardening. These are the values most distributions ship, not faults; \
             tighten them on a machine that holds anything sensitive, after checking nothing \
             you run depends on them:"
                .to_string(),
        );
        let mut table = String::new();
        for w in &optional {
            table.push_str(&format!(
                "  {} = {}   (suggested {})\n",
                w.check.key, w.value, w.check.wanted
            ));
        }
        paragraphs.push(table.trim_end().to_string());
        for w in &optional {
            paragraphs.push(format!("{}: {}", w.check.key, w.check.why));
        }
    }
    if report.forwarding {
        paragraphs.push(
            "This machine forwards packets between networks (net.ipv4.ip_forward = 1), a router, \
             container host or VPN gateway. The redirect settings do not apply to it and were \
             not checked."
                .to_string(),
        );
    }

    let mut builder = Finding::builder(
        "SEC007",
        "Kernel & Network Hardening",
        Category::Security,
        severity,
        Confidence::direct_observation(),
    )
    .evidence("settings_read", report.readable.to_string())
    .evidence("important_weaknesses", important.len().to_string())
    .evidence("optional_hardening", optional.len().to_string())
    .evidence("ip_forward", if report.forwarding { "1" } else { "0" })
    .explanation(paragraphs.join("\n\n"));
    for w in &important {
        builder = builder.evidence(w.check.key, w.value.clone());
    }

    if !important.is_empty() {
        let mut steps = Steps::new().step(
            "Fix the important settings now and keep them after a reboot:",
            &[
                &sysctl_file_command("99-linuxdoctor-hardening.conf", &important),
                "sudo sysctl --system",
            ],
        );
        if !optional.is_empty() {
            steps = steps.step(
                "Optionally, also apply the suggested hardening. A debugger or profiler may need \
                 ptrace_scope or perf_event_paranoid lower, and rp_filter = 1 breaks traffic \
                 that returns by another path:",
                &[
                    &sysctl_file_command("99-linuxdoctor-optional.conf", &optional),
                    "sudo sysctl --system",
                ],
            );
        }
        let name = important[0]
            .check
            .key
            .rsplit('.')
            .next()
            .unwrap_or(important[0].check.key);
        steps = steps.step_owned(
            "If a setting keeps reverting, something else sets it at boot: look for it with:",
            vec![format!(
                "sudo grep -r {name} /etc/sysctl.conf /etc/sysctl.d /usr/lib/sysctl.d /run/sysctl.d"
            )],
        );
        builder = builder.recommendation(steps.build());
    }
    builder.build()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn data(pairs: &[(&str, &str)]) -> HardeningData {
        HardeningData {
            readings: pairs
                .iter()
                .map(|(k, v)| (k.to_string(), Some(v.to_string())))
                .collect(),
        }
    }

    /// Every check at its recommended value, as on a hardened machine.
    fn all_good() -> HardeningData {
        let mut readings: Vec<(String, Option<String>)> = CHECKS
            .iter()
            .map(|c| (c.key.to_string(), Some(c.wanted.to_string())))
            .collect();
        readings.push(("net.ipv4.ip_forward".into(), Some("0".into())));
        HardeningData { readings }
    }

    fn set(d: &mut HardeningData, key: &str, value: &str) {
        for (k, v) in &mut d.readings {
            if k == key {
                *v = Some(value.to_string());
            }
        }
    }

    // --- MAC parsing

    #[test]
    fn lsm_list_is_split() {
        assert_eq!(
            parse_lsm("lockdown,capability,landlock,yama,apparmor\n"),
            vec!["lockdown", "capability", "landlock", "yama", "apparmor"]
        );
        assert!(parse_lsm("\n").is_empty());
    }

    #[test]
    fn selinux_config_ignores_comments_and_case() {
        assert_eq!(
            parse_selinux_config("# SELINUX=disabled\nSELINUX=Enforcing\nSELINUXTYPE=targeted\n"),
            Some("enforcing".into())
        );
        assert_eq!(parse_selinux_config("SELINUXTYPE=targeted\n"), None);
    }

    #[test]
    fn apparmor_profiles_are_counted_by_mode() {
        let text = "/usr/bin/man (enforce)\n/usr/sbin/cupsd (enforce)\nfirefox (complain)\nunconfined//x (kill)\n";
        assert_eq!(parse_apparmor_profiles(text), (2, 1));
        assert_eq!(parse_apparmor_profiles(""), (0, 0));
    }

    // --- MAC judgement

    fn selinux(mode: SelinuxMode, config: Option<&str>) -> MacInfo {
        MacInfo {
            lsm: Some(vec!["selinux".into()]),
            selinux_runtime: Some(mode),
            selinux_config: config.map(str::to_string),
            ..Default::default()
        }
    }

    #[test]
    fn selinux_enforcing_is_fine() {
        let f = mac_finding(&selinux(SelinuxMode::Enforcing, Some("enforcing")), None);
        assert_eq!(f.severity, Severity::Info);
        assert!(f.title.contains("SELinux Enforcing"));
        assert!(f.recommendation.is_none());
    }

    #[test]
    fn selinux_permissive_is_a_warning_and_says_how_it_got_there() {
        let by_hand = mac_finding(&selinux(SelinuxMode::Permissive, Some("enforcing")), None);
        assert_eq!(by_hand.severity, Severity::Warning);
        assert!(by_hand.explanation.contains("setenforce 0"));
        let rec = by_hand.recommendation.unwrap();
        assert!(rec.contains("setenforce 1"));
        let audit = rec.find("ausearch").unwrap();
        let enforce = rec.find("setenforce 1").unwrap();
        assert!(audit < enforce, "look at the denials before enforcing");

        let configured = mac_finding(&selinux(SelinuxMode::Permissive, Some("permissive")), None);
        assert!(configured
            .explanation
            .contains("configuration file sets permissive"));
    }

    #[test]
    fn selinux_configured_but_not_running_is_a_warning() {
        let mac = MacInfo {
            lsm: Some(vec!["capability".into()]),
            selinux_config: Some("enforcing".into()),
            ..Default::default()
        };
        let f = mac_finding(&mac, None);
        assert_eq!(f.severity, Severity::Warning);
        assert!(f.title.contains("Not Running"));
        assert!(f.recommendation.unwrap().contains("/.autorelabel"));
    }

    #[test]
    fn selinux_disabled_in_its_config_is_not_a_mismatch() {
        let mac = MacInfo {
            lsm: Some(vec!["apparmor".into()]),
            selinux_config: Some("disabled".into()),
            apparmor: AppArmorInfo {
                enabled: Some(true),
                enforce: Some(10),
                complain: Some(0),
            },
            ..Default::default()
        };
        let f = mac_finding(&mac, Some("Ubuntu 24.04"));
        assert_eq!(f.severity, Severity::Info);
        assert!(f.title.contains("AppArmor"));
    }

    #[test]
    fn apparmor_profile_counts_are_reported_or_marked_unreadable() {
        let known = MacInfo {
            lsm: Some(vec!["apparmor".into()]),
            apparmor: AppArmorInfo {
                enabled: Some(true),
                enforce: Some(42),
                complain: Some(3),
            },
            ..Default::default()
        };
        let f = mac_finding(&known, None);
        assert!(f.explanation.contains("42 profile(s) enforcing"));
        assert!(f
            .evidence
            .iter()
            .any(|(k, v)| k == "apparmor_profiles" && v == "42 enforcing, 3 complain"));

        let hidden = MacInfo {
            lsm: Some(vec!["apparmor".into()]),
            apparmor: AppArmorInfo {
                enabled: Some(true),
                ..Default::default()
            },
            ..Default::default()
        };
        let f = mac_finding(&hidden, None);
        assert!(f.explanation.contains("readable by root only"));

        let empty = MacInfo {
            apparmor: AppArmorInfo {
                enabled: Some(true),
                enforce: Some(0),
                complain: Some(0),
            },
            lsm: Some(vec!["apparmor".into()]),
            ..Default::default()
        };
        assert!(mac_finding(&empty, None)
            .explanation
            .contains("no profile is loaded"));
    }

    #[test]
    fn no_mac_is_a_warning_only_where_selinux_is_the_default() {
        let none = MacInfo {
            lsm: Some(vec!["capability".into(), "yama".into()]),
            ..Default::default()
        };
        let rh = mac_finding(&none, Some("Rocky Linux 9.3"));
        assert_eq!(rh.severity, Severity::Warning);
        assert!(rh.recommendation.is_some());

        let ubuntu = mac_finding(&none, Some("Ubuntu 24.04"));
        assert_eq!(ubuntu.severity, Severity::Info);
        assert!(ubuntu.recommendation.is_none());
    }

    #[test]
    fn unreadable_lsm_list_is_not_determined() {
        let f = mac_finding(&MacInfo::default(), Some("Fedora Linux 40"));
        assert_eq!(f.severity, Severity::Info, "a container is not a finding");
        assert!(f.title.contains("Not Determined"));
        assert_eq!(f.confidence.percent, 80);
    }

    #[test]
    fn mac_summary_phrases() {
        assert_eq!(
            selinux(SelinuxMode::Enforcing, None).summary(),
            "SELinux enforcing"
        );
        assert_eq!(
            MacInfo {
                apparmor: AppArmorInfo {
                    enabled: Some(true),
                    ..Default::default()
                },
                ..Default::default()
            }
            .summary(),
            "AppArmor active"
        );
        assert_eq!(MacInfo::default().summary(), "not determined");
        assert_eq!(
            MacInfo {
                lsm: Some(vec![]),
                ..Default::default()
            }
            .summary(),
            "none active"
        );
    }

    // --- hardening

    #[test]
    fn every_check_has_a_distinct_key_and_a_reason() {
        let mut keys: Vec<&str> = CHECKS.iter().map(|c| c.key).collect();
        keys.sort_unstable();
        let before = keys.len();
        keys.dedup();
        assert_eq!(before, keys.len());
        for c in CHECKS {
            assert!(!c.why.is_empty() && !c.wanted.is_empty(), "{}", c.key);
            assert!(
                !is_weak(c.weak, c.wanted),
                "{}: the recommended value must not count as weak",
                c.key
            );
        }
        assert!(keys_to_read().contains(&"net.ipv4.ip_forward"));
    }

    #[test]
    fn hardened_machine_has_no_weak_setting() {
        let r = evaluate_hardening(&all_good());
        assert_eq!(r.readable, CHECKS.len());
        assert!(r.weak.is_empty());
        let f = hardening_finding(&r);
        assert_eq!(f.severity, Severity::Info);
        assert!(f.explanation.contains("have safe values"));
        assert!(f.recommendation.is_none());
    }

    #[test]
    fn serious_weakness_is_a_warning_with_a_fix() {
        let mut d = all_good();
        set(&mut d, "net.ipv4.tcp_syncookies", "0");
        set(&mut d, "fs.suid_dumpable", "1");
        let r = evaluate_hardening(&d);
        assert_eq!(r.weak.len(), 2);
        let f = hardening_finding(&r);
        assert_eq!(f.severity, Severity::Warning);
        assert!(f
            .explanation
            .contains("net.ipv4.tcp_syncookies is 0 (should be 1)"));
        let rec = f.recommendation.unwrap();
        assert!(rec.contains("'net.ipv4.tcp_syncookies = 1'"));
        assert!(rec.contains("'fs.suid_dumpable = 0'"));
        assert!(rec.contains("/etc/sysctl.d/99-linuxdoctor-hardening.conf"));
        assert!(rec.contains("sudo sysctl --system"));
        assert!(!rec.contains("optional.conf"));
        assert!(f
            .evidence
            .iter()
            .any(|(k, v)| k == "net.ipv4.tcp_syncookies" && v == "0"));
    }

    #[test]
    fn optional_hardening_alone_stays_info_and_has_no_recommendation() {
        let mut d = all_good();
        set(&mut d, "kernel.kptr_restrict", "0");
        set(&mut d, "kernel.yama.ptrace_scope", "0");
        let f = hardening_finding(&evaluate_hardening(&d));
        assert_eq!(f.severity, Severity::Info);
        assert!(f.recommendation.is_none());
        assert!(f
            .explanation
            .contains("kernel.kptr_restrict = 0   (suggested 1)"));
        assert!(f
            .explanation
            .lines()
            .any(|l| l.starts_with("  kernel.yama.ptrace_scope")));
    }

    #[test]
    fn warning_plus_optional_adds_the_optional_step() {
        let mut d = all_good();
        set(&mut d, "vm.mmap_min_addr", "0");
        set(&mut d, "kernel.dmesg_restrict", "0");
        let rec = hardening_finding(&evaluate_hardening(&d))
            .recommendation
            .unwrap();
        assert!(rec.contains("'vm.mmap_min_addr = 65536'"));
        assert!(rec.contains("99-linuxdoctor-optional.conf"));
        assert!(rec.contains("'kernel.dmesg_restrict = 1'"));
    }

    #[test]
    fn numeric_thresholds_use_below() {
        let mut d = all_good();
        set(&mut d, "kernel.perf_event_paranoid", "-1");
        assert_eq!(evaluate_hardening(&d).weak.len(), 1);
        set(&mut d, "kernel.perf_event_paranoid", "3");
        assert!(evaluate_hardening(&d).weak.is_empty());
        set(&mut d, "vm.mmap_min_addr", "4096");
        assert!(
            evaluate_hardening(&d).weak.is_empty(),
            "4096 is the accepted minimum"
        );
        set(&mut d, "vm.mmap_min_addr", "not-a-number");
        assert!(
            evaluate_hardening(&d).weak.is_empty(),
            "unparsable is not weak"
        );
    }

    #[test]
    fn routers_are_not_judged_on_redirect_settings() {
        let mut d = all_good();
        set(&mut d, "net.ipv4.ip_forward", "1");
        set(&mut d, "net.ipv4.conf.all.accept_redirects", "1");
        set(&mut d, "net.ipv4.conf.all.send_redirects", "1");
        let r = evaluate_hardening(&d);
        assert!(r.forwarding);
        assert!(r.weak.is_empty());
        assert!(r.readable < CHECKS.len());
        assert!(hardening_finding(&r)
            .explanation
            .contains("forwards packets"));

        set(&mut d, "net.ipv4.ip_forward", "0");
        assert_eq!(evaluate_hardening(&d).weak.len(), 2);
    }

    #[test]
    fn missing_settings_are_skipped_and_nothing_readable_is_said_plainly() {
        let r = evaluate_hardening(&HardeningData {
            readings: vec![("fs.protected_symlinks".into(), None)],
        });
        assert_eq!(r.readable, 0);
        let f = hardening_finding(&r);
        assert_eq!(f.severity, Severity::Info);
        assert!(
            f.explanation.contains("could be read") || f.explanation.contains("could not be read")
        );

        let partial = evaluate_hardening(&data(&[("fs.protected_symlinks", "0")]));
        assert_eq!(partial.readable, 1);
        assert_eq!(partial.weak.len(), 1);
    }

    #[test]
    fn values_are_trimmed_before_comparing() {
        let r = evaluate_hardening(&data(&[("net.ipv4.tcp_syncookies", "0\n")]));
        assert_eq!(r.weak.len(), 1);
        assert_eq!(r.weak[0].value, "0");
    }
}
