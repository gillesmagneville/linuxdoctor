// SPDX-License-Identifier: GPL-3.0-only

//! User accounts and the permissions of the files that protect them.
//!
//! Pure logic only: parsing `/etc/passwd`, `/etc/shadow` and `/etc/group`,
//! the table of files whose permissions matter, and the judgement.
//! Reading the files and `stat`-ing the paths is `collect.rs`.
//!
//! `/etc/shadow` is readable by root only. Without root the password
//! checks (empty or weak hashes) are skipped and the finding says so; every
//! other check works for any user.

use std::collections::BTreeMap;

use crate::models::{Category, Confidence, Finding, Severity};
use crate::modules::recommend::Steps;

// ---------------------------------------------------------------------------
// Parsing
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PasswdEntry {
    pub name: String,
    /// The password field: `x` (look in shadow), `*` or `!` (locked), empty
    /// (no password!) or, on very old systems, the hash itself.
    pub password: String,
    pub uid: u32,
    pub gid: u32,
    pub shell: String,
}

/// Parses `/etc/passwd`. Lines that are not seven colon-separated fields
/// (comments, NIS `+` entries) are skipped.
pub fn parse_passwd(text: &str) -> Vec<PasswdEntry> {
    text.lines()
        .filter_map(|line| {
            let f: Vec<&str> = line.split(':').collect();
            if f.len() < 7 || f[0].is_empty() || f[0].starts_with('#') || f[0].starts_with('+') {
                return None;
            }
            Some(PasswdEntry {
                name: f[0].to_string(),
                password: f[1].to_string(),
                uid: f[2].parse().ok()?,
                gid: f[3].parse().ok()?,
                shell: f[6].trim().to_string(),
            })
        })
        .collect()
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ShadowEntry {
    pub name: String,
    pub hash: String,
}

pub fn parse_shadow(text: &str) -> Vec<ShadowEntry> {
    text.lines()
        .filter_map(|line| {
            let mut f = line.split(':');
            let name = f.next()?;
            let hash = f.next()?;
            if name.is_empty() || name.starts_with('#') {
                return None;
            }
            Some(ShadowEntry {
                name: name.to_string(),
                hash: hash.to_string(),
            })
        })
        .collect()
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GroupEntry {
    pub name: String,
    pub members: Vec<String>,
}

pub fn parse_group(text: &str) -> Vec<GroupEntry> {
    text.lines()
        .filter_map(|line| {
            let f: Vec<&str> = line.split(':').collect();
            if f.len() < 4 || f[0].is_empty() || f[0].starts_with('#') || f[0].starts_with('+') {
                return None;
            }
            Some(GroupEntry {
                name: f[0].to_string(),
                members: f[3]
                    .split(',')
                    .map(str::trim)
                    .filter(|m| !m.is_empty())
                    .map(str::to_string)
                    .collect(),
            })
        })
        .collect()
}

/// Can someone log in with this shell? `nologin`, `false` and the like are
/// how system accounts are closed.
pub fn is_login_shell(shell: &str) -> bool {
    let shell = shell.trim();
    if shell.is_empty() {
        return true; // an empty field means /bin/sh
    }
    let base = shell.rsplit('/').next().unwrap_or(shell);
    !matches!(
        base,
        "nologin" | "false" | "true" | "sync" | "halt" | "shutdown"
    )
}

/// A hash from an algorithm that is no longer safe to keep: MD5-crypt
/// (`$1$`) and the original DES `crypt` (13 characters, no `$`). Locked
/// accounts (`!` or `*` in front) and modern prefixes are fine.
pub fn is_weak_hash(hash: &str) -> bool {
    if hash.is_empty() || hash.starts_with('!') || hash.starts_with('*') {
        return false;
    }
    if hash.starts_with("$1$") {
        return true;
    }
    !hash.starts_with('$') && hash.len() == 13
}

// ---------------------------------------------------------------------------
// What was read
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub enum ShadowAccess {
    Readable(Vec<ShadowEntry>),
    /// The file exists but this user may not read it.
    Denied,
    #[default]
    Missing,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct AccountsData {
    pub passwd: Option<Vec<PasswdEntry>>,
    pub shadow: ShadowAccess,
    pub groups: Option<Vec<GroupEntry>>,
}

/// A file or directory as `stat` reports it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FileObservation {
    pub path: String,
    /// Permission bits including setuid, setgid and sticky (`& 0o7777`).
    pub mode: u32,
    pub uid: u32,
    pub gid: u32,
}

// ---------------------------------------------------------------------------
// Accounts
// ---------------------------------------------------------------------------

/// Groups whose members can become root.
const PRIVILEGED_GROUPS: [&str; 3] = ["sudo", "wheel", "admin"];

/// First UID of ordinary users on practically every distribution.
const FIRST_USER_UID: u32 = 1000;
/// `nobody` and the like live at the top of the range.
const LAST_USER_UID: u32 = 60000;

#[derive(Debug, Clone, PartialEq, Eq)]
struct AccountIssue {
    severity: Severity,
    text: String,
    /// Not certain to be a problem (an extra root account could, rarely,
    /// be deliberate).
    uncertain: bool,
    steps: Option<StepList>,
}

/// The steps of an issue (text, commands), kept as data so the finding can
/// merge several issues' steps into one numbered list.
type StepList = Vec<(String, Vec<String>)>;

fn names(list: &[&str]) -> String {
    const SHOWN: usize = 5;
    let shown: Vec<&str> = list.iter().copied().take(SHOWN).collect();
    if list.len() > SHOWN {
        format!("{} and {} more", shown.join(", "), list.len() - SHOWN)
    } else {
        shown.join(", ")
    }
}

/// SEC008.
pub fn accounts_finding(data: &AccountsData) -> Finding {
    let Some(passwd) = &data.passwd else {
        return Finding::builder(
            "SEC008",
            "User Accounts",
            Category::Security,
            Severity::Info,
            Confidence::weak_indication(60),
        )
        .evidence("passwd", "not readable")
        .explanation("/etc/passwd could not be read, so accounts were not checked.")
        .build();
    };

    let mut issues: Vec<AccountIssue> = Vec::new();

    // Extra root accounts.
    let extra_root: Vec<&str> = passwd
        .iter()
        .filter(|e| e.uid == 0 && e.name != "root")
        .map(|e| e.name.as_str())
        .collect();
    if !extra_root.is_empty() {
        let list = names(&extra_root);
        let mut steps = vec![(
            "List every account that has root's UID:".to_string(),
            vec!["getent passwd | awk -F: '$3 == 0'".to_string()],
        )];
        let lock: Vec<String> = extra_root
            .iter()
            .take(5)
            .map(|n| format!("sudo passwd -l {n}"))
            .collect();
        let mut investigate = lock;
        investigate.push("last -n 20".to_string());
        steps.push((
            "If you did not create it, treat it as a possible break-in: lock it, then look at \
             who logged in recently, before changing anything else:"
                .to_string(),
            investigate,
        ));
        issues.push(AccountIssue {
            severity: Severity::Error,
            text: format!(
                "Besides root, {list} also ha{} UID 0, which is root's identity: {} full \
                 control of the machine. Creating one is a classic way for an intruder to keep \
                 access, and almost nothing legitimate does it.",
                if extra_root.len() == 1 { "s" } else { "ve" },
                if extra_root.len() == 1 {
                    "it has"
                } else {
                    "they have"
                },
            ),
            uncertain: true,
            steps: Some(steps),
        });
    }

    // Empty password field in /etc/passwd.
    let empty_pw: Vec<&PasswdEntry> = passwd.iter().filter(|e| e.password.is_empty()).collect();
    if !empty_pw.is_empty() {
        let login: Vec<&str> = empty_pw
            .iter()
            .filter(|e| is_login_shell(&e.shell))
            .map(|e| e.name.as_str())
            .collect();
        let all: Vec<&str> = empty_pw.iter().map(|e| e.name.as_str()).collect();
        let severity = if login.is_empty() {
            Severity::Warning
        } else {
            Severity::Critical
        };
        let cmds: Vec<String> = all
            .iter()
            .take(5)
            .map(|n| format!("sudo passwd -l {n}   # or: sudo passwd {n} to set a password"))
            .collect();
        issues.push(AccountIssue {
            severity,
            text: format!(
                "/etc/passwd has an empty password field for {}: with no password set, the \
                 account needs none to log in{}.",
                names(&all),
                if login.is_empty() {
                    " (none of them has a login shell, which limits the damage)"
                } else {
                    ""
                }
            ),
            uncertain: false,
            steps: Some(vec![(
                "Lock the account, or give it a password:".to_string(),
                cmds,
            )]),
        });
    }

    // Hash stored in /etc/passwd itself.
    let hash_in_passwd: Vec<&str> = passwd
        .iter()
        .filter(|e| {
            !e.password.is_empty() && !matches!(e.password.as_str(), "x" | "*" | "!" | "!!")
        })
        .filter(|e| !e.password.starts_with('!'))
        .map(|e| e.name.as_str())
        .collect();
    if !hash_in_passwd.is_empty() {
        issues.push(AccountIssue {
            severity: Severity::Warning,
            text: format!(
                "Password hashes are stored in /etc/passwd for {}. That file is readable by \
                 every user, so anyone can copy the hashes and try to crack them offline; \
                 they belong in /etc/shadow.",
                names(&hash_in_passwd)
            ),
            uncertain: false,
            steps: Some(vec![(
                "Move the hashes to /etc/shadow:".to_string(),
                vec!["sudo pwconv".to_string()],
            )]),
        });
    }

    // Two names for one UID.
    let mut by_uid: BTreeMap<u32, Vec<&str>> = BTreeMap::new();
    for e in passwd {
        by_uid.entry(e.uid).or_default().push(e.name.as_str());
    }
    let duplicates: Vec<(u32, &Vec<&str>)> = by_uid
        .iter()
        .filter(|(uid, n)| **uid != 0 && n.len() > 1)
        .map(|(u, n)| (*u, n))
        .collect();
    if !duplicates.is_empty() {
        let desc: Vec<String> = duplicates
            .iter()
            .take(5)
            .map(|(uid, n)| format!("{} share UID {uid}", n.join(" and ")))
            .collect();
        issues.push(AccountIssue {
            severity: Severity::Warning,
            text: format!(
                "{}. Accounts with the same UID own each other's files and cannot be told apart \
                 in logs or by the kernel.",
                desc.join("; ")
            ),
            uncertain: false,
            steps: Some(vec![
                (
                    "List the accounts sorted by UID to see the clashes:".to_string(),
                    vec!["getent passwd | sort -t: -k3 -n".to_string()],
                ),
                (
                    "Give each its own UID, then hand over its files (replace the numbers):"
                        .to_string(),
                    vec![
                        "sudo usermod -u NEWUID NAME".to_string(),
                        "sudo find / -xdev -uid OLDUID -exec chown -h NEWUID {} +".to_string(),
                    ],
                ),
            ]),
        });
    }

    // Shadow: empty and weak hashes.
    let shadow_note = match &data.shadow {
        ShadowAccess::Readable(entries) => {
            let login_names: Vec<&str> = passwd
                .iter()
                .filter(|e| is_login_shell(&e.shell))
                .map(|e| e.name.as_str())
                .collect();
            let empty: Vec<&str> = entries
                .iter()
                .filter(|e| e.hash.is_empty() && login_names.contains(&e.name.as_str()))
                .map(|e| e.name.as_str())
                .collect();
            if !empty.is_empty() {
                let cmds: Vec<String> = empty
                    .iter()
                    .take(5)
                    .map(|n| {
                        format!("sudo passwd -l {n}   # or: sudo passwd {n} to set a password")
                    })
                    .collect();
                issues.push(AccountIssue {
                    severity: Severity::Critical,
                    text: format!(
                        "{} ha{} an empty password in /etc/shadow and a login shell: anyone can \
                         log in as {} without a password (on a console, over a network login \
                         that allows empty passwords, or with su).",
                        names(&empty),
                        if empty.len() == 1 { "s" } else { "ve" },
                        if empty.len() == 1 { "it" } else { "them" },
                    ),
                    uncertain: false,
                    steps: Some(vec![(
                        "Lock the account, or give it a password:".to_string(),
                        cmds,
                    )]),
                });
            }
            let weak: Vec<&str> = entries
                .iter()
                .filter(|e| is_weak_hash(&e.hash))
                .map(|e| e.name.as_str())
                .collect();
            if !weak.is_empty() {
                let cmds: Vec<String> = weak
                    .iter()
                    .take(5)
                    .map(|n| format!("sudo passwd {n}"))
                    .collect();
                issues.push(AccountIssue {
                    severity: Severity::Warning,
                    text: format!(
                        "{} use an outdated password hash (MD5 or DES crypt), which can be \
                         cracked in minutes on a graphics card if the hash ever leaks.",
                        names(&weak)
                    ),
                    uncertain: false,
                    steps: Some(vec![(
                        "Set the password again; it is stored with the system's current \
                         algorithm:"
                            .to_string(),
                        cmds,
                    )]),
                });
            }
            "checked"
        }
        ShadowAccess::Denied => "not readable without root",
        ShadowAccess::Missing => "no /etc/shadow",
    };

    // Overview facts.
    let interactive: Vec<&PasswdEntry> = passwd
        .iter()
        .filter(|e| (FIRST_USER_UID..LAST_USER_UID).contains(&e.uid) && is_login_shell(&e.shell))
        .collect();
    let mut admins: Vec<&str> = Vec::new();
    if let Some(groups) = &data.groups {
        for g in groups
            .iter()
            .filter(|g| PRIVILEGED_GROUPS.contains(&g.name.as_str()))
        {
            for m in &g.members {
                if !admins.contains(&m.as_str()) {
                    admins.push(m.as_str());
                }
            }
        }
    }

    issues.sort_by_key(|i| std::cmp::Reverse(i.severity));
    let severity = issues.first().map(|i| i.severity).unwrap_or(Severity::Info);
    let confidence = match issues.first() {
        Some(top) if top.uncertain => Confidence::strong_indication(85),
        _ => Confidence::direct_observation(),
    };

    let mut paragraphs: Vec<String> = Vec::new();
    if issues.is_empty() {
        paragraphs.push(
            "No account problem found: root is the only UID 0 account, no account has an empty \
             password field, and no UID is shared."
                .to_string(),
        );
    } else {
        for i in &issues {
            paragraphs.push(format!(
                "[{}] {}",
                i.severity.to_string().to_uppercase(),
                i.text
            ));
        }
    }
    if matches!(data.shadow, ShadowAccess::Denied) {
        paragraphs.push(
            "/etc/shadow can only be read by root, so empty and outdated password hashes were \
             not checked. Run LinuxDoctor with sudo for that part."
                .to_string(),
        );
    }
    if !interactive.is_empty() {
        let n: Vec<&str> = interactive.iter().map(|e| e.name.as_str()).collect();
        paragraphs.push(format!(
            "Accounts that can log in interactively: {}.",
            names(&n)
        ));
    }
    if !admins.is_empty() {
        paragraphs.push(format!(
            "Members of the administrator groups (sudo, wheel, admin): {}.",
            names(&admins)
        ));
    }

    let mut builder = Finding::builder(
        "SEC008",
        "User Accounts",
        Category::Security,
        severity,
        confidence,
    )
    .evidence("accounts", passwd.len().to_string())
    .evidence("interactive_accounts", interactive.len().to_string())
    .evidence(
        "uid_0_accounts",
        passwd
            .iter()
            .filter(|e| e.uid == 0)
            .map(|e| e.name.as_str())
            .collect::<Vec<_>>()
            .join(", "),
    )
    .evidence("administrators", admins.len().to_string())
    .evidence("password_hashes", shadow_note)
    .explanation(paragraphs.join("\n\n"));

    let mut steps = Steps::new();
    let mut any = false;
    for issue in issues.iter().filter(|i| i.severity >= Severity::Warning) {
        if let Some(list) = &issue.steps {
            for (text, cmds) in list {
                steps = steps.step_owned(text.clone(), cmds.clone());
                any = true;
            }
        }
    }
    if any {
        builder = builder.recommendation(steps.build());
    }
    builder.build()
}

// ---------------------------------------------------------------------------
// Sensitive files
// ---------------------------------------------------------------------------

/// A file or directory whose permissions are part of the system's
/// security, with what must not be true of them.
#[derive(Debug, PartialEq, Eq)]
pub struct FileRule {
    pub path: &'static str,
    /// Permission bits that must not be set.
    pub forbidden: u32,
    /// Must belong to root.
    pub root_owned: bool,
    /// World-writable directory that must carry the sticky bit.
    pub require_sticky: bool,
    pub severity: Severity,
    pub why: &'static str,
}

const NO_GROUP_OTHER_WRITE: u32 = 0o022;
const NO_OTHER_ACCESS: u32 = 0o007;
const NO_GROUP_WRITE_OR_OTHER: u32 = 0o027;

pub const FILE_RULES: &[FileRule] = &[
    FileRule {
        path: "/etc/passwd",
        forbidden: NO_GROUP_OTHER_WRITE,
        root_owned: true,
        require_sticky: false,
        severity: Severity::Critical,
        why: "Whoever can write /etc/passwd can add an account with UID 0, or change root's \
              shell: it is a way to become root.",
    },
    FileRule {
        path: "/etc/group",
        forbidden: NO_GROUP_OTHER_WRITE,
        root_owned: true,
        require_sticky: false,
        severity: Severity::Critical,
        why: "Whoever can write /etc/group can put themselves in the sudo or wheel group.",
    },
    FileRule {
        path: "/etc/shadow",
        forbidden: NO_GROUP_WRITE_OR_OTHER,
        root_owned: true,
        require_sticky: false,
        severity: Severity::Critical,
        why: "/etc/shadow holds every password hash. Readable by everyone, they can be cracked \
              offline; writable, anyone can set root's password.",
    },
    FileRule {
        path: "/etc/gshadow",
        forbidden: NO_GROUP_WRITE_OR_OTHER,
        root_owned: true,
        require_sticky: false,
        severity: Severity::Critical,
        why: "/etc/gshadow holds group passwords and administrators; it must not be readable \
              or writable by others.",
    },
    FileRule {
        path: "/etc/sudoers",
        forbidden: NO_GROUP_OTHER_WRITE,
        root_owned: true,
        require_sticky: false,
        severity: Severity::Critical,
        why: "Whoever can write sudoers can give themselves root.",
    },
    FileRule {
        path: "/etc/sudoers.d",
        forbidden: NO_GROUP_OTHER_WRITE,
        root_owned: true,
        require_sticky: false,
        severity: Severity::Critical,
        why: "Whoever can add a file here can give themselves root.",
    },
    FileRule {
        path: "/etc/ssh/sshd_config",
        forbidden: NO_GROUP_OTHER_WRITE,
        root_owned: true,
        require_sticky: false,
        severity: Severity::Error,
        why: "Whoever can edit the SSH server's configuration can open a way in at the next \
              restart.",
    },
    FileRule {
        path: "/etc/ssh/ssh_host_rsa_key",
        forbidden: NO_GROUP_WRITE_OR_OTHER,
        root_owned: true,
        require_sticky: false,
        severity: Severity::Error,
        why: "A server's private key readable by others lets them impersonate the machine.",
    },
    FileRule {
        path: "/etc/ssh/ssh_host_ecdsa_key",
        forbidden: NO_GROUP_WRITE_OR_OTHER,
        root_owned: true,
        require_sticky: false,
        severity: Severity::Error,
        why: "A server's private key readable by others lets them impersonate the machine.",
    },
    FileRule {
        path: "/etc/ssh/ssh_host_ed25519_key",
        forbidden: NO_GROUP_WRITE_OR_OTHER,
        root_owned: true,
        require_sticky: false,
        severity: Severity::Error,
        why: "A server's private key readable by others lets them impersonate the machine.",
    },
    FileRule {
        path: "/etc/crontab",
        forbidden: NO_GROUP_OTHER_WRITE,
        root_owned: true,
        require_sticky: false,
        severity: Severity::Error,
        why: "Whoever can edit the system crontab can run commands as root.",
    },
    FileRule {
        path: "/etc/cron.d",
        forbidden: NO_GROUP_OTHER_WRITE,
        root_owned: true,
        require_sticky: false,
        severity: Severity::Error,
        why: "Whoever can add a file here can run commands as root.",
    },
    FileRule {
        path: "/etc/fstab",
        forbidden: NO_GROUP_OTHER_WRITE,
        root_owned: true,
        require_sticky: false,
        severity: Severity::Error,
        why: "Whoever can edit fstab decides what is mounted, with which options, at boot.",
    },
    FileRule {
        path: "/root",
        forbidden: NO_OTHER_ACCESS,
        root_owned: true,
        require_sticky: false,
        severity: Severity::Warning,
        why: "root's home holds shell history, keys and configuration; other users have no \
              business in it.",
    },
    FileRule {
        path: "/tmp",
        forbidden: 0,
        root_owned: false,
        require_sticky: true,
        severity: Severity::Error,
        why: "Without the sticky bit, any user can delete or replace other users' files in a \
              world-writable directory.",
    },
    FileRule {
        path: "/var/tmp",
        forbidden: 0,
        root_owned: false,
        require_sticky: true,
        severity: Severity::Error,
        why: "Without the sticky bit, any user can delete or replace other users' files in a \
              world-writable directory.",
    },
    FileRule {
        path: "/dev/shm",
        forbidden: 0,
        root_owned: false,
        require_sticky: true,
        severity: Severity::Error,
        why: "Without the sticky bit, any user can delete or replace other users' shared \
              memory files.",
    },
];

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Violation {
    pub rule: &'static FileRule,
    pub observation: FileObservation,
    pub problem: String,
    pub fix: Vec<String>,
}

/// `g-w,o-rwx`-style description of the bits to remove.
fn chmod_expression(bits: u32) -> String {
    let mut parts = Vec::new();
    for (who, r, w, x) in [('g', 0o040, 0o020, 0o010), ('o', 0o004, 0o002, 0o001)] {
        let mut perms = String::new();
        if bits & r != 0 {
            perms.push('r');
        }
        if bits & w != 0 {
            perms.push('w');
        }
        if bits & x != 0 {
            perms.push('x');
        }
        if !perms.is_empty() {
            parts.push(format!("{who}-{perms}"));
        }
    }
    parts.join(",")
}

fn who_can(bits: u32) -> String {
    let group = bits & 0o070 != 0;
    let other = bits & 0o007 != 0;
    match (group, other) {
        (true, true) => "group and others".to_string(),
        (true, false) => "the group".to_string(),
        (false, true) => "everyone".to_string(),
        (false, false) => String::new(),
    }
}

pub fn violations(observations: &[FileObservation]) -> Vec<Violation> {
    let mut out = Vec::new();
    for rule in FILE_RULES {
        let Some(obs) = observations.iter().find(|o| o.path == rule.path) else {
            continue;
        };
        let mut problems: Vec<String> = Vec::new();
        let mut fix: Vec<String> = Vec::new();

        let bad = obs.mode & rule.forbidden;
        if bad != 0 {
            let access = match (bad & 0o222 != 0, bad & 0o444 != 0) {
                (true, true) => "read and write access",
                (true, false) => "write access",
                _ => "read access",
            };
            problems.push(format!(
                "mode {:04o} gives {} {}",
                obs.mode,
                who_can(bad),
                access
            ));
            fix.push(format!(
                "sudo chmod {} {}",
                chmod_expression(bad),
                rule.path
            ));
        }
        if rule.root_owned && obs.uid != 0 {
            problems.push(format!("it belongs to UID {}, not root", obs.uid));
            fix.push(format!("sudo chown root {}", rule.path));
        }
        if rule.require_sticky && obs.mode & 0o002 != 0 && obs.mode & 0o1000 == 0 {
            problems.push(format!(
                "mode {:04o} is world-writable without the sticky bit",
                obs.mode
            ));
            fix.push(format!("sudo chmod +t {}", rule.path));
        }
        if !problems.is_empty() {
            out.push(Violation {
                rule,
                observation: obs.clone(),
                problem: problems.join(" and "),
                fix,
            });
        }
    }
    out.sort_by_key(|v| std::cmp::Reverse(v.rule.severity));
    out
}

/// SEC009.
pub fn files_finding(observations: &[FileObservation]) -> Finding {
    let found = violations(observations);
    let severity = found
        .first()
        .map(|v| v.rule.severity)
        .unwrap_or(Severity::Info);

    let mut paragraphs: Vec<String> = Vec::new();
    if found.is_empty() {
        paragraphs.push(format!(
            "All {} sensitive files and directories that exist here have the expected \
             permissions.",
            observations.len()
        ));
    } else {
        for v in &found {
            paragraphs.push(format!(
                "[{}] {}: {}. {}",
                v.rule.severity.to_string().to_uppercase(),
                v.rule.path,
                v.problem,
                v.rule.why
            ));
        }
    }

    let mut table = String::new();
    table.push_str(&format!(
        "  {:<32} {:<5} {:<9} {}\n",
        "PATH", "MODE", "OWNER", "STATUS"
    ));
    for o in observations {
        let bad = found.iter().any(|v| v.observation.path == o.path);
        table.push_str(&format!(
            "  {:<32} {:04o}  {:<9} {}\n",
            o.path,
            o.mode,
            format!("{}:{}", o.uid, o.gid),
            if bad { "CHECK" } else { "ok" }
        ));
    }
    paragraphs.push(table.trim_end().to_string());

    let mut builder = Finding::builder(
        "SEC009",
        "Sensitive File Permissions",
        Category::Security,
        severity,
        Confidence::direct_observation(),
    )
    .evidence("files_checked", observations.len().to_string())
    .evidence("problems", found.len().to_string())
    .explanation(paragraphs.join("\n\n"));

    if !found.is_empty() {
        let mut steps = Steps::new().step(
            "Look at the files, and ask yourself why they changed: wrong permissions on these \
             files are often the trace of a careless script or of an intruder:",
            &[&format!(
                "ls -ld {}",
                found
                    .iter()
                    .map(|v| v.rule.path)
                    .collect::<Vec<_>>()
                    .join(" ")
            )],
        );
        let fixes: Vec<String> = found.iter().flat_map(|v| v.fix.clone()).collect();
        steps = steps.step_owned("Put the permissions back:", fixes);
        builder = builder.recommendation(steps.build());
    }
    builder.build()
}

#[cfg(test)]
mod tests {
    use super::*;

    const PASSWD: &str = "\
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
sync:x:4:65534:sync:/bin:/bin/sync
alice:x:1000:1000:Alice,,,:/home/alice:/bin/bash
bob:x:1001:1001::/home/bob:/bin/zsh
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
";

    const GROUP: &str = "\
root:x:0:
sudo:x:27:alice
wheel:x:10:alice,bob
audio:x:29:bob
";

    fn healthy() -> AccountsData {
        AccountsData {
            passwd: Some(parse_passwd(PASSWD)),
            shadow: ShadowAccess::Readable(parse_shadow(
                "root:$y$j9T$abc:19000:0:99999:7:::\ndaemon:*:19000:0:99999:7:::\nalice:$6$salt$hash:19000::::::\nbob:!$6$salt$hash:19000::::::\n",
            )),
            groups: Some(parse_group(GROUP)),
        }
    }

    fn entry(name: &str, pw: &str, uid: u32, shell: &str) -> PasswdEntry {
        PasswdEntry {
            name: name.into(),
            password: pw.into(),
            uid,
            gid: uid,
            shell: shell.into(),
        }
    }

    #[test]
    fn passwd_is_parsed_and_junk_lines_are_skipped() {
        let e = parse_passwd(&format!("# comment\n+@nis\nbroken:line\n{PASSWD}"));
        assert_eq!(e.len(), 6);
        assert_eq!(e[3].name, "alice");
        assert_eq!(e[3].uid, 1000);
        assert_eq!(e[3].shell, "/bin/bash");
        assert!(parse_passwd("").is_empty());
        assert!(parse_passwd("a:x:notanumber:1:::/bin/sh").is_empty());
    }

    #[test]
    fn shadow_and_group_are_parsed() {
        let s = parse_shadow("root:$6$x:19000:0:::::\n# c\n:bad\nbob:!:1::::::\n");
        assert_eq!(s.len(), 2);
        assert_eq!(s[1].hash, "!");
        let g = parse_group(GROUP);
        assert_eq!(g[2].members, vec!["alice", "bob"]);
        assert!(g[0].members.is_empty());
    }

    #[test]
    fn login_shells() {
        for s in ["/bin/bash", "/usr/bin/zsh", "/bin/sh", ""] {
            assert!(is_login_shell(s), "{s}");
        }
        for s in [
            "/usr/sbin/nologin",
            "/sbin/nologin",
            "/bin/false",
            "/usr/bin/false",
            "/bin/sync",
            "/sbin/halt",
        ] {
            assert!(!is_login_shell(s), "{s}");
        }
    }

    #[test]
    fn weak_hashes() {
        assert!(is_weak_hash("$1$salt$abcdefghijklmnopqrstuv"));
        assert!(is_weak_hash("abJnggxhB/yWI"), "13-character DES crypt");
        for ok in [
            "$6$salt$hash",
            "$y$j9T$x",
            "$2b$12$x",
            "$5$x$y",
            "!",
            "*",
            "",
            "!$1$x$y",
            "!!",
        ] {
            assert!(!is_weak_hash(ok), "{ok}");
        }
    }

    #[test]
    fn a_normal_machine_has_no_account_problem() {
        let f = accounts_finding(&healthy());
        assert_eq!(f.id, "SEC008");
        assert_eq!(f.severity, Severity::Info);
        assert!(f.recommendation.is_none());
        assert!(f.explanation.contains("No account problem"));
        assert!(f.explanation.contains("alice, bob"), "interactive accounts");
        assert!(f.explanation.contains("administrator groups"));
        let ev = |k: &str| {
            f.evidence
                .iter()
                .find(|(key, _)| key == k)
                .unwrap()
                .1
                .clone()
        };
        assert_eq!(ev("uid_0_accounts"), "root");
        assert_eq!(ev("interactive_accounts"), "2");
        assert_eq!(ev("administrators"), "2");
        assert_eq!(ev("password_hashes"), "checked");
    }

    #[test]
    fn a_second_root_account_is_an_error_with_reduced_confidence() {
        let mut d = healthy();
        d.passwd
            .as_mut()
            .unwrap()
            .push(entry("toor", "x", 0, "/bin/bash"));
        let f = accounts_finding(&d);
        assert_eq!(f.severity, Severity::Error);
        assert_eq!(f.confidence.percent, 85);
        assert!(f.explanation.contains("toor"));
        assert!(f.explanation.contains("UID 0"));
        let rec = f.recommendation.unwrap();
        assert!(rec.contains("sudo passwd -l toor"));
        assert!(rec.contains("last -n 20"));
    }

    #[test]
    fn empty_password_field_with_a_shell_is_critical() {
        let mut d = healthy();
        d.passwd
            .as_mut()
            .unwrap()
            .push(entry("guest", "", 1002, "/bin/bash"));
        let f = accounts_finding(&d);
        assert_eq!(f.severity, Severity::Critical);
        assert_eq!(f.confidence.percent, 100);
        assert!(f.explanation.contains("guest"));
        assert!(f.recommendation.unwrap().contains("sudo passwd -l guest"));
    }

    #[test]
    fn empty_password_field_without_a_shell_is_only_a_warning() {
        let mut d = healthy();
        d.passwd
            .as_mut()
            .unwrap()
            .push(entry("svc", "", 998, "/usr/sbin/nologin"));
        let f = accounts_finding(&d);
        assert_eq!(f.severity, Severity::Warning);
        assert!(f.explanation.contains("none of them has a login shell"));
    }

    #[test]
    fn hash_in_passwd_is_a_warning_and_pwconv_is_suggested() {
        let mut d = healthy();
        d.passwd
            .as_mut()
            .unwrap()
            .push(entry("old", "abJnggxhB/yWI", 1005, "/bin/sh"));
        let f = accounts_finding(&d);
        assert_eq!(f.severity, Severity::Warning);
        assert!(f.recommendation.unwrap().contains("sudo pwconv"));
    }

    #[test]
    fn locked_markers_in_passwd_are_not_hashes() {
        let mut d = healthy();
        let p = d.passwd.as_mut().unwrap();
        p.push(entry("a", "*", 1010, "/bin/sh"));
        p.push(entry("b", "!", 1011, "/bin/sh"));
        p.push(entry("c", "!!", 1012, "/bin/sh"));
        p.push(entry("d", "!$6$x$y", 1013, "/bin/sh"));
        assert_eq!(accounts_finding(&d).severity, Severity::Info);
    }

    #[test]
    fn shared_uid_is_a_warning() {
        let mut d = healthy();
        d.passwd
            .as_mut()
            .unwrap()
            .push(entry("alice2", "x", 1000, "/bin/bash"));
        let f = accounts_finding(&d);
        assert_eq!(f.severity, Severity::Warning);
        assert!(f.explanation.contains("alice and alice2 share UID 1000"));
        assert!(f.recommendation.unwrap().contains("usermod -u"));
    }

    #[test]
    fn empty_shadow_hash_with_a_shell_is_critical_but_a_closed_account_is_not() {
        let mut d = healthy();
        d.shadow =
            ShadowAccess::Readable(parse_shadow("alice::19000:0:::::\ndaemon::19000:0:::::\n"));
        let f = accounts_finding(&d);
        assert_eq!(f.severity, Severity::Critical);
        assert!(f.explanation.contains("alice has an empty password"));
        assert!(
            !f.explanation.contains("daemon"),
            "daemon has no login shell"
        );
    }

    #[test]
    fn outdated_hashes_are_a_warning() {
        let mut d = healthy();
        d.shadow = ShadowAccess::Readable(parse_shadow(
            "alice:$1$abc$defghijklmnopqrstuvwxyz:1:::::\n",
        ));
        let f = accounts_finding(&d);
        assert_eq!(f.severity, Severity::Warning);
        assert!(f.explanation.contains("MD5 or DES"));
        assert!(f.recommendation.unwrap().contains("sudo passwd alice"));
    }

    #[test]
    fn without_root_the_password_checks_are_skipped_and_said_so() {
        let mut d = healthy();
        d.shadow = ShadowAccess::Denied;
        let f = accounts_finding(&d);
        assert_eq!(f.severity, Severity::Info);
        assert!(f.explanation.contains("only be read by root"));
        assert!(f
            .evidence
            .iter()
            .any(|(k, v)| k == "password_hashes" && v.contains("root")));
        d.shadow = ShadowAccess::Missing;
        let f = accounts_finding(&d);
        assert!(f
            .evidence
            .iter()
            .any(|(k, v)| k == "password_hashes" && v == "no /etc/shadow"));
    }

    #[test]
    fn unreadable_passwd_is_reported_not_guessed() {
        let f = accounts_finding(&AccountsData::default());
        assert_eq!(f.severity, Severity::Info);
        assert!(f.explanation.contains("could not be read"));
    }

    #[test]
    fn long_name_lists_are_shortened() {
        let list: Vec<String> = (0..8).map(|i| format!("u{i}")).collect();
        let refs: Vec<&str> = list.iter().map(String::as_str).collect();
        assert_eq!(names(&refs), "u0, u1, u2, u3, u4 and 3 more");
    }

    #[test]
    fn worst_issue_leads_the_explanation() {
        let mut d = healthy();
        let p = d.passwd.as_mut().unwrap();
        p.push(entry("toor", "x", 0, "/bin/bash"));
        p.push(entry("guest", "", 1002, "/bin/bash"));
        let f = accounts_finding(&d);
        assert!(f.explanation.starts_with("[CRITICAL]"), "{}", f.explanation);
    }

    // --- files

    fn obs(path: &str, mode: u32, uid: u32) -> FileObservation {
        FileObservation {
            path: path.into(),
            mode,
            uid,
            gid: 0,
        }
    }

    fn good_files() -> Vec<FileObservation> {
        vec![
            obs("/etc/passwd", 0o644, 0),
            obs("/etc/group", 0o644, 0),
            obs("/etc/shadow", 0o640, 0),
            obs("/etc/gshadow", 0o640, 0),
            obs("/etc/sudoers", 0o440, 0),
            obs("/etc/ssh/sshd_config", 0o644, 0),
            obs("/etc/ssh/ssh_host_ed25519_key", 0o600, 0),
            obs("/root", 0o700, 0),
            obs("/tmp", 0o1777, 0),
        ]
    }

    #[test]
    fn expected_permissions_pass_including_fedora_style_group_readable_host_keys() {
        assert!(violations(&good_files()).is_empty());
        let mut files = good_files();
        files.push(obs("/etc/ssh/ssh_host_rsa_key", 0o640, 0));
        files.push(obs("/etc/shadow", 0o000, 0));
        files.push(obs("/root", 0o550, 0));
        assert!(violations(&files).is_empty());
        let f = files_finding(&good_files());
        assert_eq!(f.severity, Severity::Info);
        assert!(f.recommendation.is_none());
        assert!(f.explanation.contains("All 9 sensitive files"));
    }

    #[test]
    fn world_writable_passwd_is_critical_with_the_exact_chmod() {
        let mut files = good_files();
        files[0] = obs("/etc/passwd", 0o666, 0);
        let v = violations(&files);
        assert_eq!(v.len(), 1);
        assert_eq!(v[0].rule.severity, Severity::Critical);
        assert_eq!(v[0].fix, vec!["sudo chmod g-w,o-w /etc/passwd"]);
        assert!(v[0].problem.contains("mode 0666"));
        let f = files_finding(&files);
        assert_eq!(f.severity, Severity::Critical);
        let rec = f.recommendation.unwrap();
        assert!(rec.contains("ls -ld /etc/passwd"));
        assert!(rec.contains("sudo chmod g-w,o-w /etc/passwd"));
        assert!(f.explanation.contains("CHECK"));
    }

    #[test]
    fn world_readable_shadow_is_critical() {
        let mut files = good_files();
        files[2] = obs("/etc/shadow", 0o644, 0);
        let v = violations(&files);
        assert_eq!(v[0].rule.path, "/etc/shadow");
        assert_eq!(v[0].fix, vec!["sudo chmod o-r /etc/shadow"]);
        assert!(v[0].problem.contains("everyone read access"));
    }

    #[test]
    fn a_file_owned_by_someone_else_is_reported_with_a_chown() {
        let mut files = good_files();
        files[4] = obs("/etc/sudoers", 0o440, 1000);
        let v = violations(&files);
        assert_eq!(v.len(), 1);
        assert!(v[0].problem.contains("belongs to UID 1000"));
        assert_eq!(v[0].fix, vec!["sudo chown root /etc/sudoers"]);
    }

    #[test]
    fn both_problems_give_both_fixes_in_one_violation() {
        let mut files = good_files();
        files[1] = obs("/etc/group", 0o664, 1000);
        let v = violations(&files);
        assert_eq!(v.len(), 1);
        assert_eq!(v[0].fix.len(), 2);
        assert!(v[0].problem.contains(" and "));
    }

    #[test]
    fn tmp_without_the_sticky_bit_is_an_error() {
        let mut files = good_files();
        files[8] = obs("/tmp", 0o777, 0);
        let v = violations(&files);
        assert_eq!(v[0].rule.severity, Severity::Error);
        assert_eq!(v[0].fix, vec!["sudo chmod +t /tmp"]);
        files[8] = obs("/tmp", 0o755, 0);
        assert!(
            violations(&files).is_empty(),
            "not world-writable: nothing to protect"
        );
    }

    #[test]
    fn root_home_open_to_others_is_a_warning() {
        let mut files = good_files();
        files[7] = obs("/root", 0o755, 0);
        let v = violations(&files);
        assert_eq!(v[0].rule.severity, Severity::Warning);
        assert_eq!(v[0].fix, vec!["sudo chmod o-rx /root"]);
    }

    #[test]
    fn host_key_open_to_others_is_an_error_and_missing_files_are_skipped() {
        let files = vec![obs("/etc/ssh/ssh_host_ed25519_key", 0o644, 0)];
        let v = violations(&files);
        assert_eq!(v.len(), 1);
        assert_eq!(v[0].rule.severity, Severity::Error);
        assert!(violations(&[]).is_empty());
        assert!(files_finding(&[]).explanation.contains("All 0 sensitive"));
    }

    #[test]
    fn worst_violation_sets_the_severity_and_comes_first() {
        let mut files = good_files();
        files[7] = obs("/root", 0o755, 0);
        files[2] = obs("/etc/shadow", 0o666, 0);
        let v = violations(&files);
        assert_eq!(v[0].rule.path, "/etc/shadow");
        assert_eq!(v.last().unwrap().rule.path, "/root");
        assert_eq!(files_finding(&files).severity, Severity::Critical);
    }

    #[test]
    fn rules_are_consistent() {
        for r in FILE_RULES {
            assert!(
                r.forbidden != 0 || r.require_sticky,
                "{} would never fail",
                r.path
            );
            assert!(!r.why.is_empty());
        }
        let mut paths: Vec<&str> = FILE_RULES.iter().map(|r| r.path).collect();
        paths.sort_unstable();
        let n = paths.len();
        paths.dedup();
        assert_eq!(n, paths.len());
    }

    #[test]
    fn chmod_expressions() {
        assert_eq!(chmod_expression(0o022), "g-w,o-w");
        assert_eq!(chmod_expression(0o007), "o-rwx");
        assert_eq!(chmod_expression(0o070), "g-rwx");
        assert_eq!(chmod_expression(0), "");
    }
}
