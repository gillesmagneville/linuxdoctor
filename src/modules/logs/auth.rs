// SPDX-License-Identifier: GPL-3.0-only

//! Who tried to log in, who succeeded, and what looks wrong: failed SSH
//! logins by source address, a successful login that follows many failures
//! from the same address (how a guessed password looks), and failed `sudo`,
//! `su` and console logins.
//!
//! Pure functions over [`Entry`] values. Everything in a message after the
//! program has written it is untrusted — an attacker chooses the account
//! name they try — so names are cleaned on the way in (see `text::clean`)
//! and only reach a suggested command when they are plain words.

use std::collections::{BTreeMap, HashMap, HashSet};
use std::net::IpAddr;
use std::str::FromStr;

use crate::models::{Category, Confidence, Finding, Severity};
use crate::modules::recommend::{Family, Steps};

use super::journal::Entry;
use super::text::{clean, table, word_or};

/// How far back the authentication log is read.
pub const WINDOW_HOURS: u32 = 24;
/// Failed attempts from one address that make the volume worth a warning.
pub const SOURCE_FLOOD: u32 = 20;
/// Failed attempts in total that make the volume worth a warning.
pub const TOTAL_FLOOD: u32 = 100;
/// A login after this many failed attempts from the same address is odd
/// enough to look at (people do mistype a password a few times).
pub const SUSPICIOUS_AFTER: u32 = 5;
/// A password login after this many failures from the same address is how
/// a successful guessing run looks.
pub const BREAK_IN_AFTER: u32 = 20;
/// Distinct account names remembered per source; the rest are only counted.
const MAX_USERS_TRACKED: usize = 200;

// ---------------------------------------------------------------------------
// Recognising events
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AuthEvent {
    /// `Failed password for [invalid user] NAME from IP port N ssh2`
    PasswordFailed {
        user: String,
        ip: String,
        port: Option<u16>,
    },
    /// `Invalid user NAME from IP port N` — an account that does not exist.
    InvalidUser {
        user: String,
        ip: String,
        port: Option<u16>,
    },
    /// `Accepted METHOD for NAME from IP port N ssh2`
    Accepted {
        user: String,
        method: String,
        ip: String,
    },
    /// `pam_unix(SERVICE:auth): authentication failure` for anything but SSH
    /// (sudo, su, console, desktop login...).
    LocalFailure {
        service: String,
        user: Option<String>,
    },
    /// sudo: `NAME : user NOT in sudoers ; ... COMMAND=...`
    NotInSudoers { user: String, command: String },
}

/// Splits `"... from IP port N ..."` at its last ` from `, so account names
/// that contain spaces or the word "from" still parse.
fn split_from(text: &str) -> Option<(&str, &str, Option<u16>)> {
    let at = text.rfind(" from ")?;
    let (before, tail) = (&text[..at], &text[at + " from ".len()..]);
    let mut words = tail.split_whitespace();
    let ip = words.next()?;
    let port = match (words.next(), words.next()) {
        (Some("port"), Some(p)) => p.parse().ok(),
        _ => None,
    };
    Some((before, ip, port))
}

fn parse_ssh(message: &str) -> Option<AuthEvent> {
    if let Some(rest) = message.strip_prefix("Failed password for ") {
        let rest = rest.strip_prefix("invalid user ").unwrap_or(rest);
        let (user, ip, port) = split_from(rest)?;
        return Some(AuthEvent::PasswordFailed {
            user: clean(user, 64),
            ip: clean(ip, 64),
            port,
        });
    }
    if let Some(rest) = message.strip_prefix("Invalid user ") {
        let (user, ip, port) = split_from(rest)?;
        return Some(AuthEvent::InvalidUser {
            user: clean(user, 64),
            ip: clean(ip, 64),
            port,
        });
    }
    if let Some(rest) = message.strip_prefix("Accepted ") {
        let (method, rest) = rest.split_once(" for ")?;
        let (user, ip, _) = split_from(rest)?;
        return Some(AuthEvent::Accepted {
            user: clean(user, 64),
            method: clean(method, 40),
            ip: clean(ip, 64),
        });
    }
    None
}

fn parse_pam(message: &str) -> Option<AuthEvent> {
    let rest = message.strip_prefix("pam_unix(")?;
    let (head, tail) = rest.split_once("):")?;
    let (service, kind) = head.split_once(':')?;
    // SSH failures are counted from sshd's own line; counting PAM's too
    // would count every failed attempt twice.
    if kind != "auth" || service.starts_with("sshd") || !tail.contains("authentication failure") {
        return None;
    }
    let user = tail
        .split_whitespace()
        .find_map(|t| t.strip_prefix("user="))
        .filter(|u| !u.is_empty())
        .map(|u| clean(u, 64));
    Some(AuthEvent::LocalFailure {
        service: clean(service, 32),
        user,
    })
}

fn parse_sudo_denied(message: &str) -> Option<AuthEvent> {
    let (user, rest) = message.split_once(" : ")?;
    if !rest.contains("user NOT in sudoers") {
        return None;
    }
    let command = rest
        .split("COMMAND=")
        .nth(1)
        .map(|c| clean(c.trim(), 100))
        .unwrap_or_default();
    Some(AuthEvent::NotInSudoers {
        user: clean(user.trim(), 64),
        command,
    })
}

/// Recognises the authentication events this module counts; everything
/// else in the log is ignored.
pub fn parse_event(entry: &Entry) -> Option<AuthEvent> {
    let message = entry.message.trim_start();
    if entry.identifier.starts_with("sshd") {
        if let Some(event) = parse_ssh(message) {
            return Some(event);
        }
    }
    if entry.identifier == "sudo" {
        if let Some(event) = parse_sudo_denied(message) {
            return Some(event);
        }
    }
    parse_pam(message)
}

// ---------------------------------------------------------------------------
// Summarising
// ---------------------------------------------------------------------------

/// Failed attempts from one address.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SourceStats {
    pub ip: String,
    pub attempts: u32,
    /// Distinct account names tried, in order of first appearance.
    pub users: Vec<String>,
}

/// A successful SSH login.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Login {
    pub user: String,
    pub method: String,
    pub ip: String,
    /// Failed attempts from the same address since its previous success.
    pub failures_before: u32,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct AuthSummary {
    /// Authentication lines recognised.
    pub events: usize,
    /// Failed SSH password attempts (a probe of a non-existent account that
    /// never reached the password stage counts as one).
    pub attempts: u32,
    /// Sources of failed attempts, most active first.
    pub sources: Vec<SourceStats>,
    /// Distinct account names tried.
    pub users_tried: u32,
    pub root_attempts: u32,
    pub logins: Vec<Login>,
    /// Failed non-SSH authentications, by service (`sudo`, `su`, `login`...).
    pub local_failures: BTreeMap<String, u32>,
    pub not_in_sudoers: Vec<(String, String)>,
}

#[derive(Default)]
struct Tally {
    stats: HashMap<String, SourceStats>,
    since_success: HashMap<String, u32>,
    users: HashSet<String>,
    attempts: u32,
    root_attempts: u32,
}

impl Tally {
    fn failure(&mut self, ip: &str, user: &str) {
        self.attempts += 1;
        if user == "root" {
            self.root_attempts += 1;
        }
        *self.since_success.entry(ip.to_string()).or_insert(0) += 1;
        let source = self
            .stats
            .entry(ip.to_string())
            .or_insert_with(|| SourceStats {
                ip: ip.to_string(),
                ..Default::default()
            });
        source.attempts += 1;
        if self.users.len() < MAX_USERS_TRACKED || self.users.contains(user) {
            self.users.insert(user.to_string());
        }
        if !source.users.iter().any(|u| u == user) && source.users.len() < MAX_USERS_TRACKED {
            source.users.push(user.to_string());
        }
    }
}

pub fn summarize(entries: &[Entry]) -> AuthSummary {
    let events: Vec<AuthEvent> = entries.iter().filter_map(parse_event).collect();

    // A rejected account and the password attempt that follows it describe
    // the same connection (same address and port): count the attempt once.
    let password_connections: HashSet<(String, u16)> = events
        .iter()
        .filter_map(|e| match e {
            AuthEvent::PasswordFailed {
                ip, port: Some(p), ..
            } => Some((ip.clone(), *p)),
            _ => None,
        })
        .collect();

    let mut tally = Tally::default();
    let mut summary = AuthSummary {
        events: events.len(),
        ..Default::default()
    };
    for event in &events {
        match event {
            AuthEvent::PasswordFailed { user, ip, .. } => tally.failure(ip, user),
            AuthEvent::InvalidUser { user, ip, port } => {
                let counted_as_password =
                    matches!(port, Some(p) if password_connections.contains(&(ip.clone(), *p)));
                if counted_as_password {
                    tally.users.insert(user.clone());
                } else {
                    tally.failure(ip, user);
                }
            }
            AuthEvent::Accepted { user, method, ip } => {
                let failures_before = tally.since_success.remove(ip).unwrap_or(0);
                if summary.logins.len() < 500 {
                    summary.logins.push(Login {
                        user: user.clone(),
                        method: method.clone(),
                        ip: ip.clone(),
                        failures_before,
                    });
                }
            }
            AuthEvent::LocalFailure { service, .. } => {
                *summary.local_failures.entry(service.clone()).or_insert(0) += 1;
            }
            AuthEvent::NotInSudoers { user, command } => {
                if summary.not_in_sudoers.len() < 50 {
                    summary.not_in_sudoers.push((user.clone(), command.clone()));
                }
            }
        }
    }

    summary.attempts = tally.attempts;
    summary.root_attempts = tally.root_attempts;
    summary.users_tried = tally.users.len() as u32;
    summary.sources = tally.stats.into_values().collect();
    summary
        .sources
        .sort_by(|a, b| b.attempts.cmp(&a.attempts).then_with(|| a.ip.cmp(&b.ip)));
    summary
}

impl AuthSummary {
    pub fn busiest_source(&self) -> Option<&SourceStats> {
        self.sources.first()
    }

    /// Logins that follow enough failures from their own address to look
    /// at, first occurrence per account and address.
    pub fn suspicious_logins(&self) -> Vec<&Login> {
        let mut seen = HashSet::new();
        self.logins
            .iter()
            .filter(|l| l.failures_before >= SUSPICIOUS_AFTER)
            .filter(|l| seen.insert((l.user.clone(), l.ip.clone())))
            .collect()
    }

    pub fn local_failure_total(&self) -> u32 {
        self.local_failures.values().sum()
    }
}

// ---------------------------------------------------------------------------
// Findings
// ---------------------------------------------------------------------------

/// Commands that stop one address from reaching the machine. The address
/// is only used when it parses as an IP address, so nothing else can end
/// up in a command.
fn block_commands(ip: &str, family: Family) -> Vec<String> {
    let Ok(addr) = IpAddr::from_str(ip) else {
        return Vec::new();
    };
    match family {
        Family::DebianLike => vec![format!("sudo ufw deny from {addr}")],
        Family::RedHatLike => {
            let version = if addr.is_ipv4() { "ipv4" } else { "ipv6" };
            vec![
                format!(
                    "sudo firewall-cmd --permanent --add-rich-rule='rule family=\"{version}\" source address=\"{addr}\" drop'"
                ),
                "sudo firewall-cmd --reload".to_string(),
            ]
        }
        Family::Unknown => {
            let tool = if addr.is_ipv4() {
                "iptables"
            } else {
                "ip6tables"
            };
            vec![format!("sudo {tool} -I INPUT -s {addr} -j DROP")]
        }
    }
}

fn install_fail2ban(family: Family) -> Vec<String> {
    match family {
        Family::DebianLike => vec![
            "sudo apt install fail2ban".to_string(),
            "sudo systemctl enable --now fail2ban".to_string(),
        ],
        Family::RedHatLike => vec![
            "sudo dnf install epel-release".to_string(),
            "sudo dnf install fail2ban".to_string(),
            "sudo systemctl enable --now fail2ban".to_string(),
        ],
        Family::Unknown => Vec::new(),
    }
}

fn plural(n: u32, one: &str, many: &str) -> String {
    if n == 1 {
        format!("{n} {one}")
    } else {
        format!("{n} {many}")
    }
}

/// LOG002 — failed and successful SSH logins over the last 24 hours.
pub fn activity_finding(
    summary: &AuthSummary,
    source: &str,
    truncated: bool,
    family: Family,
) -> Finding {
    let flood = summary.attempts >= TOTAL_FLOOD
        || summary
            .busiest_source()
            .is_some_and(|s| s.attempts >= SOURCE_FLOOD);
    let severity = if flood {
        Severity::Warning
    } else {
        Severity::Info
    };

    let mut text = String::new();
    if summary.attempts == 0 {
        text.push_str(&format!(
            "No failed SSH login was logged in the last {WINDOW_HOURS} hours."
        ));
    } else {
        text.push_str(&format!(
            "{} from {}, trying {} (root: {}), in the last {WINDOW_HOURS} hours. Automated \
             scans like this reach every machine that has SSH open to the internet; they only \
             matter if one of them can succeed.",
            plural(
                summary.attempts,
                "failed login attempt",
                "failed login attempts"
            ),
            plural(summary.sources.len() as u32, "address", "addresses"),
            plural(summary.users_tried, "account name", "account names"),
            summary.root_attempts
        ));
        if flood {
            text.push_str(
                " This volume deserves a defence that works without anyone watching: keys \
                 instead of passwords, and automatic bans for addresses that keep failing.",
            );
        }
    }
    if truncated {
        text.push_str(
            "\n\nThe log holds more lines for this period than were read, so the counts are a \
             minimum.",
        );
    }

    if !summary.sources.is_empty() {
        let rows: Vec<Vec<String>> = summary
            .sources
            .iter()
            .take(10)
            .map(|s| {
                let shown: Vec<&str> = s.users.iter().take(4).map(String::as_str).collect();
                let more = s.users.len().saturating_sub(shown.len());
                let mut names = shown.join(", ");
                if more > 0 {
                    names.push_str(&format!(" (+{more})"));
                }
                vec![s.attempts.to_string(), s.ip.clone(), names]
            })
            .collect();
        text.push_str("\n\nMost active sources:\n");
        text.push_str(&table(&["Attempts", "Source", "Accounts tried"], &rows));
        if summary.sources.len() > 10 {
            text.push_str(&format!("\n\n... and {} more", summary.sources.len() - 10));
        }
    }

    if !summary.logins.is_empty() {
        let mut grouped: BTreeMap<(String, String, String), u32> = BTreeMap::new();
        for l in &summary.logins {
            *grouped
                .entry((l.user.clone(), l.ip.clone(), l.method.clone()))
                .or_insert(0) += 1;
        }
        let mut rows: Vec<((String, String, String), u32)> = grouped.into_iter().collect();
        rows.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));
        let shown: Vec<Vec<String>> = rows
            .iter()
            .take(8)
            .map(|((user, ip, method), n)| {
                vec![n.to_string(), user.clone(), ip.clone(), method.clone()]
            })
            .collect();
        text.push_str("\n\nSuccessful logins:\n");
        text.push_str(&table(&["Count", "Account", "From", "Method"], &shown));
        if rows.len() > 8 {
            text.push_str(&format!("\n\n... and {} more combinations", rows.len() - 8));
        }
    }

    let mut builder = Finding::builder(
        "LOG002",
        "SSH Login Activity",
        Category::Logs,
        severity,
        Confidence::direct_observation(),
    )
    .evidence("source", source)
    .evidence("window_hours", WINDOW_HOURS.to_string())
    .evidence("failed_attempts", summary.attempts.to_string())
    .evidence("sources", summary.sources.len().to_string())
    .evidence("account_names_tried", summary.users_tried.to_string())
    .evidence("root_attempts", summary.root_attempts.to_string())
    .evidence("successful_logins", summary.logins.len().to_string());
    if let Some(top) = summary.busiest_source() {
        builder = builder.evidence("busiest_source", format!("{} ({})", top.ip, top.attempts));
    }
    builder = builder.explanation(text);

    if flood {
        let mut steps = Steps::new()
            .step(
                "Check whether SSH needs to be open to the whole internet. If it does not, \
                 limit it to the addresses that need it (a VPN, your office):",
                &["sudo ss -ltnp 'sport = :22'"],
            )
            .step(
                "Use keys instead of passwords, so guessing can never succeed. Install your \
                 public key first, then turn passwords off. `linuxdoctor audit --modules \
                 security` shows the exact lines to change in the SSH configuration.",
                &[],
            );
        let ban = install_fail2ban(family);
        if ban.is_empty() {
            steps = steps.step(
                "Ban addresses that keep failing automatically, with fail2ban or sshguard \
                 (install it with your package manager).",
                &[],
            );
        } else {
            steps = steps.step_owned("Ban addresses that keep failing automatically:", ban);
        }
        if let Some(top) = summary.busiest_source() {
            let commands = block_commands(&top.ip, family);
            if !commands.is_empty() {
                steps = steps.step_owned(
                    format!("Block the most active address right away ({}):", top.ip),
                    commands,
                );
            }
        }
        builder = builder.recommendation(steps.build());
    }
    builder.build()
}

/// LOG003 — one finding per successful login that follows many failures
/// from the same address.
pub fn break_in_findings(summary: &AuthSummary, family: Family) -> Vec<Finding> {
    summary
        .suspicious_logins()
        .into_iter()
        .take(5)
        .map(|login| {
            let guessable = matches!(
                login.method.as_str(),
                "password" | "keyboard-interactive/pam" | "keyboard-interactive"
            );
            let (severity, confidence) = if guessable && login.failures_before >= BREAK_IN_AFTER {
                (
                    Severity::Critical,
                    Confidence::strong_indication(80),
                )
            } else if guessable {
                (Severity::Warning, Confidence::weak_indication(70))
            } else {
                (Severity::Warning, Confidence::weak_indication(60))
            };

            let why = if guessable {
                "A login by password that comes right after many failed passwords from the \
                 same address is what a successful guessing run looks like. It can also be a \
                 person who mistyped their password many times, which is why this is an \
                 indication, not a proof."
            } else {
                "This login used a key, which cannot be guessed the way a password can, so the \
                 earlier failures were probably password attempts from the same network (a \
                 shared office or home address). It still deserves a look: a stolen key looks \
                 exactly like this."
            };
            let user_word = word_or(&login.user, "<account>");

            let mut steps = Steps::new()
                .step(
                    "Check whether this login was you, and what that session did:",
                    &[
                        "last -i -n 20",
                        &format!(
                            "sudo journalctl -t sshd -t sshd-session --since '{WINDOW_HOURS} hours ago' | grep -F -- '{}'",
                            if IpAddr::from_str(&login.ip).is_ok() {
                                login.ip.as_str()
                            } else {
                                "<address>"
                            }
                        ),
                    ],
                )
                .step(
                    "If it was not you, cut the access first — lock the account and end its \
                     sessions:",
                    &[
                        &format!("sudo passwd -l {user_word}"),
                        &format!("sudo pkill -KILL -u {user_word}"),
                    ],
                )
                .step(
                    "Look for what an intruder leaves to come back — extra keys, scheduled \
                     jobs, recently changed files:",
                    &[
                        &format!("sudo cat ~{user_word}/.ssh/authorized_keys"),
                        &format!("sudo crontab -l -u {user_word}"),
                        "sudo find /etc /root /home /usr/local -xdev -type f -mtime -1 2>/dev/null | head -50",
                    ],
                );
            let block = block_commands(&login.ip, family);
            if !block.is_empty() {
                steps = steps.step_owned("Block the address:", block);
            }
            steps = steps.step(
                "Change the account's password, remove every key you do not recognise, and \
                 if root was reached consider reinstalling: nothing on the machine can be \
                 trusted after that.",
                &[],
            );

            Finding::builder(
                "LOG003",
                format!(
                    "Possible Break-in \u{2014} {} from {}",
                    login.user, login.ip
                ),
                Category::Logs,
                severity,
                confidence,
            )
            .evidence("account", login.user.clone())
            .evidence("source", login.ip.clone())
            .evidence("method", login.method.clone())
            .evidence("failed_attempts_before", login.failures_before.to_string())
            .explanation(format!(
                "{} logged in from {} using {} after {} failed attempts from that same \
                 address. {why}",
                login.user,
                login.ip,
                login.method,
                login.failures_before
            ))
            .recommendation(steps.build())
            .build()
        })
        .collect()
}

/// LOG004 — failed `sudo`, `su` and console logins, and users who tried to
/// use `sudo` without being allowed to.
pub fn local_finding(summary: &AuthSummary, family: Family) -> Finding {
    let total = summary.local_failure_total();
    let denied = summary.not_in_sudoers.len() as u32;
    let noisy = summary.local_failures.values().any(|n| *n >= 10);
    let severity = if denied >= 3 || noisy {
        Severity::Warning
    } else {
        Severity::Info
    };

    let mut text = String::new();
    if total == 0 && denied == 0 {
        text.push_str(&format!(
            "No failed sudo, su or console login was logged in the last {WINDOW_HOURS} hours."
        ));
    } else {
        text.push_str(&format!(
            "In the last {WINDOW_HOURS} hours: {} and {}.",
            plural(
                total,
                "failed local authentication",
                "failed local authentications"
            ),
            plural(
                denied,
                "sudo attempt by an account that is not allowed to use it",
                "sudo attempts by accounts that are not allowed to use it"
            ),
        ));
        text.push_str(
            " A few mistyped passwords are normal. Repeated failures, or an account trying \
             to run commands as root without permission, mean someone is testing what they \
             can do on this machine.",
        );
    }
    if !summary.local_failures.is_empty() {
        let rows: Vec<Vec<String>> = summary
            .local_failures
            .iter()
            .map(|(service, n)| vec![n.to_string(), service.clone()])
            .collect();
        text.push_str("\n\nFailed authentications by service:\n");
        text.push_str(&table(&["Count", "Service"], &rows));
    }
    if !summary.not_in_sudoers.is_empty() {
        let rows: Vec<Vec<String>> = summary
            .not_in_sudoers
            .iter()
            .take(8)
            .map(|(user, command)| vec![user.clone(), command.clone()])
            .collect();
        text.push_str("\n\nSudo refused (account, command):\n");
        text.push_str(&table(&["Account", "Command"], &rows));
    }

    let mut builder = Finding::builder(
        "LOG004",
        "Local Authentication Failures",
        Category::Logs,
        severity,
        Confidence::direct_observation(),
    )
    .evidence("window_hours", WINDOW_HOURS.to_string())
    .evidence("failed_authentications", total.to_string())
    .evidence("sudo_refused", denied.to_string());
    for (service, n) in &summary.local_failures {
        builder = builder.evidence(format!("failed_{service}"), n.to_string());
    }
    builder = builder.explanation(text);

    if severity >= Severity::Warning {
        let group = match family {
            Family::RedHatLike => "wheel",
            _ => "sudo",
        };
        let steps = Steps::new()
            .step(
                "See who it was and when:",
                &[
                    "sudo journalctl -t sudo --since '24 hours ago' | grep -E 'NOT in sudoers|authentication failure'",
                    "last -n 20",
                ],
            )
            .step(
                "If the account should be an administrator, add it to the right group. Do \
                 this only if you are sure the person is entitled to it:",
                &[&format!("sudo usermod -aG {group} <account>")],
            )
            .step(
                "If you do not recognise the account or the commands, treat it as an \
                 intrusion: lock the account and look at what else it did.",
                &["sudo passwd -l <account>", "sudo lastlog -u <account>"],
            );
        builder = builder.recommendation(steps.build());
    }
    builder.build()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sshd(msg: &str) -> Entry {
        Entry::new("sshd", msg)
    }

    fn failed(user: &str, ip: &str, port: u16) -> Entry {
        sshd(&format!(
            "Failed password for {user} from {ip} port {port} ssh2"
        ))
    }

    fn accepted(method: &str, user: &str, ip: &str) -> Entry {
        sshd(&format!(
            "Accepted {method} for {user} from {ip} port 40000 ssh2: RSA SHA256:abc"
        ))
    }

    #[test]
    fn recognises_the_openssh_messages() {
        let ev = |m: &str| parse_event(&sshd(m));
        assert_eq!(
            ev("Failed password for root from 203.0.113.7 port 51322 ssh2"),
            Some(AuthEvent::PasswordFailed {
                user: "root".into(),
                ip: "203.0.113.7".into(),
                port: Some(51322)
            })
        );
        assert_eq!(
            ev("Failed password for invalid user admin from 2001:db8::5 port 4 ssh2"),
            Some(AuthEvent::PasswordFailed {
                user: "admin".into(),
                ip: "2001:db8::5".into(),
                port: Some(4)
            })
        );
        assert_eq!(
            ev("Invalid user test from 198.51.100.2 port 9999"),
            Some(AuthEvent::InvalidUser {
                user: "test".into(),
                ip: "198.51.100.2".into(),
                port: Some(9999)
            })
        );
        assert_eq!(
            ev("Accepted publickey for bob from 192.0.2.9 port 22 ssh2: ED25519 SHA256:x"),
            Some(AuthEvent::Accepted {
                user: "bob".into(),
                method: "publickey".into(),
                ip: "192.0.2.9".into()
            })
        );
        assert_eq!(ev("Connection closed by 1.2.3.4 port 5 [preauth]"), None);
        assert_eq!(ev("Server listening on 0.0.0.0 port 22."), None);
    }

    #[test]
    fn newer_openssh_logs_under_another_name() {
        let e = Entry::new(
            "sshd-session",
            "Failed password for root from 203.0.113.7 port 1 ssh2",
        );
        assert!(parse_event(&e).is_some());
    }

    #[test]
    fn account_names_with_spaces_or_the_word_from_still_parse() {
        let ev = parse_event(&sshd(
            "Failed password for invalid user a from b c from 203.0.113.7 port 1 ssh2",
        ));
        assert_eq!(
            ev,
            Some(AuthEvent::PasswordFailed {
                user: "a from b c".into(),
                ip: "203.0.113.7".into(),
                port: Some(1)
            })
        );
    }

    #[test]
    fn other_programs_cannot_pose_as_sshd() {
        let e = Entry::new("cron", "Failed password for root from 1.2.3.4 port 22 ssh2");
        assert_eq!(parse_event(&e), None);
    }

    #[test]
    fn pam_failures_count_for_local_services_only() {
        let sudo = Entry::new(
            "sudo",
            "pam_unix(sudo:auth): authentication failure; logname=bob uid=1000 euid=0 tty=/dev/pts/0 ruser=bob rhost=  user=bob",
        );
        assert_eq!(
            parse_event(&sudo),
            Some(AuthEvent::LocalFailure {
                service: "sudo".into(),
                user: Some("bob".into())
            })
        );
        let ssh = Entry::new(
            "sshd",
            "pam_unix(sshd:auth): authentication failure; logname= uid=0 euid=0 tty=ssh ruser= rhost=1.2.3.4  user=root",
        );
        assert_eq!(
            parse_event(&ssh),
            None,
            "already counted from sshd's own line"
        );
        let ok = Entry::new(
            "sudo",
            "pam_unix(sudo:session): session opened for user root",
        );
        assert_eq!(parse_event(&ok), None);
    }

    #[test]
    fn sudo_refusals_are_recognised() {
        let e = Entry::new(
            "sudo",
            "    mallory : user NOT in sudoers ; TTY=pts/1 ; PWD=/home/mallory ; USER=root ; COMMAND=/bin/bash",
        );
        assert_eq!(
            parse_event(&e),
            Some(AuthEvent::NotInSudoers {
                user: "mallory".into(),
                command: "/bin/bash".into()
            })
        );
        let allowed = Entry::new(
            "sudo",
            "bob : TTY=pts/0 ; PWD=/ ; USER=root ; COMMAND=/bin/ls",
        );
        assert_eq!(parse_event(&allowed), None);
    }

    #[test]
    fn counts_attempts_sources_and_accounts() {
        let entries = vec![
            failed("root", "203.0.113.7", 1),
            failed("root", "203.0.113.7", 2),
            failed("admin", "203.0.113.7", 3),
            failed("root", "198.51.100.2", 4),
            accepted("publickey", "bob", "192.0.2.9"),
        ];
        let s = summarize(&entries);
        assert_eq!(s.attempts, 4);
        assert_eq!(s.root_attempts, 3);
        assert_eq!(s.users_tried, 2);
        assert_eq!(s.sources.len(), 2);
        assert_eq!(s.sources[0].ip, "203.0.113.7");
        assert_eq!(s.sources[0].attempts, 3);
        assert_eq!(s.sources[0].users, vec!["root", "admin"]);
        assert_eq!(s.logins.len(), 1);
    }

    #[test]
    fn an_invalid_account_and_its_password_attempt_count_once() {
        let entries = vec![
            sshd("Invalid user admin from 203.0.113.7 port 5000"),
            failed("admin", "203.0.113.7", 5000),
            failed("admin", "203.0.113.7", 5000),
            // A probe that never reached the password stage still counts.
            sshd("Invalid user guest from 203.0.113.7 port 6000"),
        ];
        let s = summarize(&entries);
        assert_eq!(s.attempts, 3, "two passwords on one connection + one probe");
        assert_eq!(s.users_tried, 2);
    }

    #[test]
    fn a_login_after_many_failures_from_the_same_address_is_suspicious() {
        let mut entries: Vec<Entry> = (0..25)
            .map(|i| failed("root", "203.0.113.7", 1000 + i))
            .collect();
        entries.push(accepted("password", "root", "203.0.113.7"));
        entries.push(accepted("password", "root", "203.0.113.7"));
        let s = summarize(&entries);
        assert_eq!(s.logins[0].failures_before, 25);
        assert_eq!(
            s.logins[1].failures_before, 0,
            "failures are used up by the first success"
        );
        let sus = s.suspicious_logins();
        assert_eq!(sus.len(), 1);
        assert_eq!(sus[0].user, "root");
    }

    #[test]
    fn failures_from_other_addresses_do_not_count_for_a_login() {
        let mut entries: Vec<Entry> = (0..30)
            .map(|i| failed("root", "203.0.113.7", 1000 + i))
            .collect();
        entries.push(accepted("password", "bob", "192.0.2.9"));
        assert!(summarize(&entries).suspicious_logins().is_empty());
    }

    #[test]
    fn a_failure_after_the_login_is_not_before_it() {
        let entries = vec![
            accepted("password", "bob", "192.0.2.9"),
            failed("bob", "192.0.2.9", 1),
        ];
        assert_eq!(summarize(&entries).logins[0].failures_before, 0);
    }

    #[test]
    fn empty_input_is_a_quiet_day() {
        let s = summarize(&[]);
        assert_eq!(s, AuthSummary::default());
        let f = activity_finding(&s, "journal", false, Family::DebianLike);
        assert_eq!(f.severity, Severity::Info);
        assert!(f.explanation.contains("No failed SSH login"));
        assert!(f.recommendation.is_none());
    }

    fn flood(n: u16, ip: &str) -> Vec<Entry> {
        (0..n).map(|i| failed("root", ip, 1000 + i)).collect()
    }

    #[test]
    fn a_flood_from_one_address_is_a_warning_with_ordered_steps() {
        let s = summarize(&flood(30, "203.0.113.7"));
        let f = activity_finding(&s, "journal", false, Family::DebianLike);
        assert_eq!(f.severity, Severity::Warning);
        let rec = f.recommendation.unwrap();
        assert!(rec.starts_with("1. "));
        assert!(rec.contains("sudo apt install fail2ban"));
        assert!(rec.contains("sudo ufw deny from 203.0.113.7"));
        let order = |needle: &str| rec.find(needle).unwrap();
        assert!(order("sport = :22") < order("fail2ban") && order("fail2ban") < order("ufw deny"));
        assert!(f.explanation.contains("Most active sources:"));
        assert!(f.explanation.contains("203.0.113.7"));
    }

    #[test]
    fn many_small_sources_also_make_a_flood() {
        let mut entries = Vec::new();
        for i in 0..110u16 {
            entries.push(failed("root", &format!("198.51.100.{}", i % 50), i + 1));
        }
        let s = summarize(&entries);
        assert_eq!(s.attempts, 110);
        assert!(s.busiest_source().unwrap().attempts < SOURCE_FLOOD);
        assert_eq!(
            activity_finding(&s, "journal", false, Family::Unknown).severity,
            Severity::Warning
        );
    }

    #[test]
    fn some_background_noise_is_only_information() {
        let s = summarize(&flood(8, "203.0.113.7"));
        let f = activity_finding(&s, "journal", false, Family::DebianLike);
        assert_eq!(f.severity, Severity::Info);
    }

    #[test]
    fn red_hat_family_gets_dnf_and_firewalld() {
        let s = summarize(&flood(30, "2001:db8::5"));
        let rec = activity_finding(&s, "journal", false, Family::RedHatLike)
            .recommendation
            .unwrap();
        assert!(rec.contains("sudo dnf install fail2ban"));
        assert!(rec.contains("rule family=\"ipv6\" source address=\"2001:db8::5\" drop"));
        assert!(rec.contains("sudo firewall-cmd --reload"));
    }

    #[test]
    fn unknown_distribution_stays_neutral() {
        let s = summarize(&flood(30, "203.0.113.7"));
        let rec = activity_finding(&s, "journal", false, Family::Unknown)
            .recommendation
            .unwrap();
        assert!(!rec.contains("apt install") && !rec.contains("dnf install"));
        assert!(rec.contains("sudo iptables -I INPUT -s 203.0.113.7 -j DROP"));
    }

    #[test]
    fn only_real_addresses_reach_a_command() {
        assert!(block_commands("1.2.3.4; reboot", Family::DebianLike).is_empty());
        assert!(block_commands("$(id)", Family::Unknown).is_empty());
        assert!(block_commands("fe80::1%eth0", Family::DebianLike).is_empty());
        let s = summarize(&flood(30, "evil;rm"));
        let rec = activity_finding(&s, "journal", false, Family::DebianLike)
            .recommendation
            .unwrap();
        assert!(!rec.contains("evil;rm"));
        assert!(!rec.contains("Block the most active address"));
    }

    #[test]
    fn truncated_logs_say_the_counts_are_a_minimum() {
        let s = summarize(&flood(3, "203.0.113.7"));
        let f = activity_finding(&s, "journal", true, Family::DebianLike);
        assert!(f.explanation.contains("a minimum"));
    }

    #[test]
    fn password_break_in_after_twenty_failures_is_critical() {
        let mut entries = flood(25, "203.0.113.7");
        entries.push(accepted("password", "deploy", "203.0.113.7"));
        let found = break_in_findings(&summarize(&entries), Family::DebianLike);
        assert_eq!(found.len(), 1);
        let f = &found[0];
        assert_eq!(f.id, "LOG003");
        assert_eq!(f.severity, Severity::Critical);
        assert!(f.title.contains("deploy") && f.title.contains("203.0.113.7"));
        let rec = f.recommendation.as_ref().unwrap();
        assert!(rec.contains("sudo passwd -l deploy"));
        assert!(rec.contains("sudo cat ~deploy/.ssh/authorized_keys"));
        assert!(rec.contains("sudo ufw deny from 203.0.113.7"));
        // Cut the access before looking around.
        assert!(rec.find("passwd -l").unwrap() < rec.find("authorized_keys").unwrap());
    }

    #[test]
    fn fewer_failures_or_a_key_login_are_only_a_warning() {
        let mut few = flood(7, "203.0.113.7");
        few.push(accepted("password", "bob", "203.0.113.7"));
        let f = &break_in_findings(&summarize(&few), Family::DebianLike)[0];
        assert_eq!(f.severity, Severity::Warning);

        let mut key = flood(40, "203.0.113.7");
        key.push(accepted("publickey", "bob", "203.0.113.7"));
        let f = &break_in_findings(&summarize(&key), Family::DebianLike)[0];
        assert_eq!(f.severity, Severity::Warning, "keys cannot be guessed");
        assert!(f.explanation.contains("used a key"));
    }

    #[test]
    fn a_stranger_chosen_name_never_enters_a_command() {
        let mut entries = flood(25, "203.0.113.7");
        entries.push(accepted("password", "x;rm -rf /", "203.0.113.7"));
        let f = &break_in_findings(&summarize(&entries), Family::DebianLike)[0];
        let rec = f.recommendation.as_ref().unwrap();
        assert!(!rec.contains("rm -rf"));
        assert!(rec.contains("sudo passwd -l <account>"));
    }

    #[test]
    fn at_most_five_break_in_findings() {
        let mut entries = Vec::new();
        for i in 0..8u8 {
            let ip = format!("203.0.113.{i}");
            entries.extend(flood(6, &ip));
            entries.push(accepted("password", "bob", &ip));
        }
        assert_eq!(
            break_in_findings(&summarize(&entries), Family::DebianLike).len(),
            5
        );
    }

    #[test]
    fn no_findings_without_a_suspicious_login() {
        assert!(
            break_in_findings(&summarize(&flood(30, "203.0.113.7")), Family::Unknown).is_empty()
        );
    }

    fn sudo_denied(user: &str) -> Entry {
        Entry::new(
            "sudo",
            &format!(
                "{user} : user NOT in sudoers ; TTY=pts/1 ; PWD=/ ; USER=root ; COMMAND=/bin/bash"
            ),
        )
    }

    fn pam(service: &str) -> Entry {
        Entry::new(
            "x",
            &format!("pam_unix({service}:auth): authentication failure; logname= uid=1000 euid=0 tty= ruser= rhost=  user=bob"),
        )
    }

    #[test]
    fn local_failures_are_quiet_when_there_are_none() {
        let f = local_finding(&summarize(&[]), Family::DebianLike);
        assert_eq!(f.severity, Severity::Info);
        assert!(f
            .explanation
            .contains("No failed sudo, su or console login"));
    }

    #[test]
    fn a_few_mistyped_passwords_are_information() {
        let s = summarize(&[pam("sudo"), pam("sudo"), pam("su"), sudo_denied("bob")]);
        let f = local_finding(&s, Family::DebianLike);
        assert_eq!(f.severity, Severity::Info);
        assert!(f.explanation.contains("Failed authentications by service:"));
        assert!(f.explanation.contains("Sudo refused"));
    }

    #[test]
    fn repeated_refusals_or_failures_are_a_warning() {
        let denied = summarize(&[sudo_denied("a"), sudo_denied("b"), sudo_denied("c")]);
        let f = local_finding(&denied, Family::RedHatLike);
        assert_eq!(f.severity, Severity::Warning);
        assert!(f
            .recommendation
            .as_ref()
            .unwrap()
            .contains("usermod -aG wheel <account>"));

        let noisy: Vec<Entry> = (0..10).map(|_| pam("login")).collect();
        let f = local_finding(&summarize(&noisy), Family::DebianLike);
        assert_eq!(f.severity, Severity::Warning);
        assert!(f
            .recommendation
            .as_ref()
            .unwrap()
            .contains("usermod -aG sudo <account>"));
    }

    #[test]
    fn many_distinct_names_do_not_grow_without_bound() {
        let entries: Vec<Entry> = (0..2000)
            .map(|i| failed(&format!("user{i}"), "203.0.113.7", (i % 60000) as u16 + 1))
            .collect();
        let s = summarize(&entries);
        assert_eq!(s.attempts, 2000);
        assert!(s.users_tried as usize <= MAX_USERS_TRACKED);
        assert!(s.sources[0].users.len() <= MAX_USERS_TRACKED);
    }

    #[test]
    fn hostile_names_are_cleaned_before_they_reach_the_report() {
        let s = summarize(&[failed("ro\u{1b}[31mot", "203.0.113.7", 1)]);
        assert_eq!(s.sources[0].users[0], "ro?[31mot");
        let f = activity_finding(&s, "journal", false, Family::DebianLike);
        assert!(!f.explanation.contains('\u{1b}'));
    }
}
