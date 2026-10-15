// SPDX-License-Identifier: GPL-3.0-only

//! The I/O side of the security module: everything read from the system,
//! gathered into one value. Interpretation lives in the topic files; the
//! functions here only open files, run read-only commands and hand the text
//! to the pure parsers.
//!
//! Nothing here needs root, and nothing here changes anything. What root
//! adds is visibility — which program owns another user's socket, the
//! firewall rules, `/etc/shadow`, AppArmor's profile list — and each topic
//! says so when it could not see.

use std::collections::{HashMap, HashSet};
use std::fs;
use std::os::unix::fs::MetadataExt;
use std::path::Path;
use std::time::{Duration, Instant};

use crate::core::command::command;
use crate::core::context::effective_uid;
use crate::core::error::ModuleError;

use super::access::{self, AppArmorInfo, HardeningData, MacInfo, SelinuxMode};
use super::accounts::{self, AccountsData, FileObservation, ShadowAccess, FILE_RULES};
use super::firewall::{self, FirewallData, FIREWALL_SERVICES, RULE_LOADER_SERVICES};
use super::listeners::{self, Owner, Proto, Socket};
use super::ssh::{self, Line, SshConfig, SshInfo};

/// The kernel's ephemeral port range when /proc does not say.
pub const DEFAULT_EPHEMERAL_PORTS: (u16, u16) = (32768, 60999);

/// Finding which program owns each socket means looking at the open files
/// of every process. On a very busy machine that could take a while; past
/// this budget the remaining sockets are simply shown without an owner.
const OWNER_SCAN_BUDGET: Duration = Duration::from_secs(3);

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ListenerData {
    pub sockets: Vec<Socket>,
    /// Socket inode -> the program that has it open.
    pub owners: HashMap<u64, Owner>,
    pub ephemeral: (u16, u16),
}

impl Default for ListenerData {
    fn default() -> Self {
        Self {
            sockets: Vec::new(),
            owners: HashMap::new(),
            ephemeral: DEFAULT_EPHEMERAL_PORTS,
        }
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SecurityRawData {
    /// LinuxDoctor runs with root's identity: the extra checks that need it
    /// were attempted.
    pub is_root: bool,
    pub listeners: ListenerData,
    pub firewall: FirewallData,
    pub ssh: SshInfo,
    pub mac: MacInfo,
    pub hardening: HardeningData,
    pub accounts: AccountsData,
    pub files: Vec<FileObservation>,
}

/// Fails only when the one thing every other check builds on — the list of
/// listening sockets — cannot be read at all. Everything else degrades to
/// "not available" and is reported as such.
pub fn collect() -> Result<SecurityRawData, ModuleError> {
    let is_root = effective_uid() == Some(0);
    let listeners = read_listeners()?;
    Ok(SecurityRawData {
        is_root,
        listeners,
        firewall: read_firewall(is_root),
        ssh: read_ssh(),
        mac: read_mac(),
        hardening: read_hardening(),
        accounts: read_accounts(),
        files: read_files(),
    })
}

fn read_text(path: &str) -> Option<String> {
    fs::read_to_string(path).ok()
}

// ---------------------------------------------------------------------------
// Listening sockets
// ---------------------------------------------------------------------------

fn read_listeners() -> Result<ListenerData, ModuleError> {
    let tcp = fs::read_to_string("/proc/net/tcp").map_err(|source| ModuleError::Io {
        path: "/proc/net/tcp".to_string(),
        source,
    })?;
    let mut sockets = listeners::parse_proc_net(&tcp, Proto::Tcp);
    // The IPv6 and UDP tables are missing on kernels built without them,
    // or when IPv6 is disabled: that is not an error.
    for (path, proto) in [
        ("/proc/net/tcp6", Proto::Tcp),
        ("/proc/net/udp", Proto::Udp),
        ("/proc/net/udp6", Proto::Udp),
    ] {
        if let Some(text) = read_text(path) {
            sockets.extend(listeners::parse_proc_net(&text, proto));
        }
    }

    let ephemeral = read_text("/proc/sys/net/ipv4/ip_local_port_range")
        .and_then(|t| listeners::parse_port_range(&t))
        .unwrap_or(DEFAULT_EPHEMERAL_PORTS);

    let wanted: HashSet<u64> = sockets
        .iter()
        .map(|s| s.inode)
        .filter(|i| *i != 0)
        .collect();
    let owners = find_owners(&wanted);

    Ok(ListenerData {
        sockets,
        owners,
        ephemeral,
    })
}

/// Walks `/proc/<pid>/fd` looking for `socket:[inode]` links. A user sees
/// only their own processes; root sees all. Pids are visited in increasing
/// order, so when a socket is shared by a parent and its workers the
/// parent (the lowest pid) is the one named.
fn find_owners(wanted: &HashSet<u64>) -> HashMap<u64, Owner> {
    let mut owners = HashMap::new();
    if wanted.is_empty() {
        return owners;
    }
    let Ok(proc_dir) = fs::read_dir("/proc") else {
        return owners;
    };
    let mut pids: Vec<u32> = proc_dir
        .flatten()
        .filter_map(|e| e.file_name().to_str().and_then(|n| n.parse().ok()))
        .collect();
    pids.sort_unstable();

    let started = Instant::now();
    for pid in pids {
        if started.elapsed() > OWNER_SCAN_BUDGET {
            break;
        }
        let Ok(fds) = fs::read_dir(format!("/proc/{pid}/fd")) else {
            continue; // not ours, or already gone
        };
        for fd in fds.flatten() {
            let Ok(target) = fs::read_link(fd.path()) else {
                continue;
            };
            let target = target.to_string_lossy();
            let Some(inode) = target
                .strip_prefix("socket:[")
                .and_then(|rest| rest.strip_suffix(']'))
                .and_then(|n| n.parse::<u64>().ok())
            else {
                continue;
            };
            if wanted.contains(&inode) && !owners.contains_key(&inode) {
                let name = read_text(&format!("/proc/{pid}/comm"))
                    .map(|s| s.trim().to_string())
                    .filter(|s| !s.is_empty())
                    .unwrap_or_else(|| "?".to_string());
                owners.insert(inode, Owner { pid, name });
            }
        }
        if owners.len() == wanted.len() {
            break;
        }
    }
    owners
}

// ---------------------------------------------------------------------------
// Firewall
// ---------------------------------------------------------------------------

fn read_firewall(is_root: bool) -> FirewallData {
    let names: Vec<&str> = FIREWALL_SERVICES
        .iter()
        .chain(RULE_LOADER_SERVICES.iter())
        .copied()
        .collect();

    // `systemctl is-active a b c` prints one state per line and exits
    // non-zero if any is inactive, so the exit status says nothing here.
    let units = {
        let mut cmd = command("systemctl");
        cmd.arg("is-active");
        for n in &names {
            cmd.arg(format!("{n}.service"));
        }
        match cmd.output() {
            Ok(out) => {
                let text = String::from_utf8_lossy(&out.stdout).to_string();
                if text.lines().count() == names.len() {
                    Some(firewall::parse_is_active(&names, &text))
                } else {
                    None // systemd is not running (a container, for instance)
                }
            }
            Err(_) => None,
        }
    };

    let (nft, iptables) = if is_root {
        (read_nft(), read_iptables())
    } else {
        (None, None)
    };

    FirewallData {
        is_root,
        units,
        ufw_enabled_in_config: read_text("/etc/ufw/ufw.conf")
            .and_then(|t| firewall::parse_ufw_conf(&t)),
        netfilter_loaded: read_text("/proc/modules")
            .map(|t| firewall::netfilter_in_modules(&t))
            .unwrap_or(false),
        nft,
        iptables,
    }
}

fn read_nft() -> Option<firewall::NftSummary> {
    let out = command("nft").args(["list", "ruleset"]).output().ok()?;
    out.status
        .success()
        .then(|| firewall::parse_nft_ruleset(&String::from_utf8_lossy(&out.stdout)))
}

fn read_iptables() -> Option<firewall::IptablesSummary> {
    let out = command("iptables").arg("-S").output().ok()?;
    out.status
        .success()
        .then(|| firewall::parse_iptables(&String::from_utf8_lossy(&out.stdout)))
}

// ---------------------------------------------------------------------------
// SSH
// ---------------------------------------------------------------------------

const SSHD_CONFIG: &str = "/etc/ssh/sshd_config";
const SSH_CONFIG_DIR: &str = "/etc/ssh";
const SSHD_BINARIES: [&str; 4] = [
    "/usr/sbin/sshd",
    "/usr/bin/sshd",
    "/sbin/sshd",
    "/usr/local/sbin/sshd",
];
/// `Include` can nest; real configurations go one level deep.
const MAX_INCLUDE_DEPTH: usize = 5;
const MAX_CONFIG_FILES: usize = 64;

fn read_ssh() -> SshInfo {
    let binary = SSHD_BINARIES.iter().any(|p| Path::new(p).exists());
    let config_exists = Path::new(SSHD_CONFIG).exists();
    if !binary && !config_exists {
        return SshInfo::default();
    }
    let mut info = SshInfo {
        installed: true,
        ..Default::default()
    };
    match fs::read_to_string(SSHD_CONFIG) {
        Ok(text) => {
            let mut cfg = SshConfig::default();
            read_config_text(SSHD_CONFIG, &text, 0, &mut cfg);
            info.config = Some(cfg);
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => info.read_error = Some(e.to_string()),
    }
    info
}

/// Reads one configuration file the way sshd does: directives in order,
/// `Include` expanded in place, and everything from the first `Match` on
/// (in that file) set aside.
fn read_config_text(path: &str, text: &str, depth: usize, cfg: &mut SshConfig) {
    cfg.files.push(path.to_string());
    let mut in_match = false;
    for raw in text.lines() {
        match ssh::parse_line(raw) {
            Some(Line::Match) => {
                cfg.match_blocks += 1;
                in_match = true;
            }
            _ if in_match => {}
            Some(Line::Directive { key, value }) => cfg.directives.push((key, value)),
            Some(Line::Include(patterns)) => {
                for pattern in patterns.split_whitespace() {
                    if pattern.contains("sshd_config.d") {
                        cfg.has_dropin_include = true;
                    }
                    if depth >= MAX_INCLUDE_DEPTH {
                        continue;
                    }
                    for file in expand_include(pattern) {
                        if cfg.files.len() >= MAX_CONFIG_FILES {
                            return;
                        }
                        match fs::read_to_string(&file) {
                            Ok(t) => read_config_text(&file, &t, depth + 1, cfg),
                            Err(_) => cfg.unreadable.push(file),
                        }
                    }
                }
            }
            None => {}
        }
    }
}

/// The files an `Include` pattern designates, in the alphabetical order
/// sshd reads them. Relative patterns are relative to /etc/ssh.
fn expand_include(pattern: &str) -> Vec<String> {
    let full = if pattern.starts_with('/') {
        pattern.to_string()
    } else {
        format!("{SSH_CONFIG_DIR}/{pattern}")
    };
    let (dir, file_pattern) = match full.rsplit_once('/') {
        Some((d, f)) => (if d.is_empty() { "/" } else { d }, f),
        None => return Vec::new(),
    };
    if !file_pattern.contains(['*', '?']) {
        return if Path::new(&full).is_file() {
            vec![full]
        } else {
            Vec::new()
        };
    }
    let Ok(entries) = fs::read_dir(dir) else {
        return Vec::new();
    };
    let mut files: Vec<String> = entries
        .flatten()
        .filter(|e| {
            e.file_name()
                .to_str()
                .is_some_and(|n| ssh::glob_match(file_pattern, n))
        })
        .map(|e| e.path().to_string_lossy().to_string())
        .collect();
    files.sort();
    files
}

// ---------------------------------------------------------------------------
// Access control and hardening
// ---------------------------------------------------------------------------

fn read_mac() -> MacInfo {
    let selinux_runtime = read_text("/sys/fs/selinux/enforce").and_then(|t| match t.trim() {
        "1" => Some(SelinuxMode::Enforcing),
        "0" => Some(SelinuxMode::Permissive),
        _ => None,
    });

    let (enforce, complain) = match read_text("/sys/kernel/security/apparmor/profiles") {
        Some(t) => {
            let (e, c) = access::parse_apparmor_profiles(&t);
            (Some(e), Some(c))
        }
        None => (None, None),
    };

    MacInfo {
        lsm: read_text("/sys/kernel/security/lsm").map(|t| access::parse_lsm(&t)),
        selinux_runtime,
        selinux_config: read_text("/etc/selinux/config")
            .and_then(|t| access::parse_selinux_config(&t)),
        apparmor: AppArmorInfo {
            enabled: read_text("/sys/module/apparmor/parameters/enabled").and_then(|t| {
                match t.trim() {
                    "Y" => Some(true),
                    "N" => Some(false),
                    _ => None,
                }
            }),
            enforce,
            complain,
        },
    }
}

fn read_hardening() -> HardeningData {
    let readings = access::keys_to_read()
        .into_iter()
        .map(|key| {
            let path = format!("/proc/sys/{}", key.replace('.', "/"));
            (
                key.to_string(),
                read_text(&path).map(|v| v.trim().to_string()),
            )
        })
        .collect();
    HardeningData { readings }
}

// ---------------------------------------------------------------------------
// Accounts and sensitive files
// ---------------------------------------------------------------------------

fn read_accounts() -> AccountsData {
    let shadow = match fs::read_to_string("/etc/shadow") {
        Ok(text) => ShadowAccess::Readable(accounts::parse_shadow(&text)),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => ShadowAccess::Missing,
        Err(_) => ShadowAccess::Denied,
    };
    AccountsData {
        passwd: read_text("/etc/passwd").map(|t| accounts::parse_passwd(&t)),
        shadow,
        groups: read_text("/etc/group").map(|t| accounts::parse_group(&t)),
    }
}

/// `stat`s each path of the rule table. `stat` needs no permission on the
/// file itself, so this works for any user; a path that does not exist is
/// simply absent from the result.
fn read_files() -> Vec<FileObservation> {
    FILE_RULES
        .iter()
        .filter_map(|rule| {
            let meta = fs::metadata(rule.path).ok()?;
            Some(FileObservation {
                path: rule.path.to_string(),
                mode: meta.mode() & 0o7777,
                uid: meta.uid(),
                gid: meta.gid(),
            })
        })
        .fold(Vec::new(), |mut acc, o| {
            if !acc.iter().any(|x: &FileObservation| x.path == o.path) {
                acc.push(o);
            }
            acc
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The I/O layer must never fail on a normal system, whoever runs the
    /// test: no root, no sshd, no firewall — each part degrades instead.
    #[test]
    fn collect_runs_on_this_system() {
        let data = collect().expect("/proc/net/tcp is readable on Linux");
        assert!(data.listeners.ephemeral.0 < data.listeners.ephemeral.1);
        assert!(
            !data.hardening.readings.is_empty(),
            "every key is listed, readable or not"
        );
        // /tmp exists everywhere and is part of the rule table.
        assert!(data.files.iter().any(|f| f.path == "/tmp"));
    }

    #[test]
    fn effective_uid_is_read_without_libc() {
        assert!(effective_uid().is_some());
    }

    #[test]
    fn include_patterns_expand_in_alphabetical_order() {
        let dir = std::env::temp_dir().join(format!("linuxdoctor-ssh-{}", std::process::id()));
        fs::create_dir_all(&dir).unwrap();
        for name in ["50-b.conf", "10-a.conf", "notes.txt"] {
            fs::write(dir.join(name), "").unwrap();
        }
        let pattern = format!("{}/*.conf", dir.display());
        let found = expand_include(&pattern);
        let names: Vec<&str> = found
            .iter()
            .map(|p| p.rsplit('/').next().unwrap())
            .collect();
        assert_eq!(names, vec!["10-a.conf", "50-b.conf"]);
        assert!(expand_include(&format!("{}/missing.conf", dir.display())).is_empty());
        assert_eq!(
            expand_include(&format!("{}/10-a.conf", dir.display())).len(),
            1
        );
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn config_text_stops_directives_at_match_and_follows_includes() {
        let dir = std::env::temp_dir().join(format!("linuxdoctor-ssh-inc-{}", std::process::id()));
        fs::create_dir_all(&dir).unwrap();
        fs::write(
            dir.join("00-site.conf"),
            "PasswordAuthentication no\nPort 2222\n",
        )
        .unwrap();
        let main = format!(
            "# comment\nInclude {}/*.conf\nPermitRootLogin no\nPasswordAuthentication yes\n\
             Match User bob\n    PermitRootLogin yes\nMatch Address 10.0.0.0/8\n    X11Forwarding yes\n",
            dir.display()
        );
        let mut cfg = SshConfig::default();
        read_config_text("/test/sshd_config", &main, 0, &mut cfg);
        assert_eq!(cfg.files.len(), 2);
        assert_eq!(cfg.match_blocks, 2);
        assert_eq!(
            cfg.get("passwordauthentication"),
            Some("no"),
            "included file is read first"
        );
        assert_eq!(
            cfg.get("permitrootlogin"),
            Some("no"),
            "the Match override is not applied"
        );
        assert_eq!(cfg.get("x11forwarding"), None);
        assert_eq!(cfg.all("port"), vec!["2222"]);
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn dropin_include_is_recognised_even_when_the_directory_is_missing() {
        let mut cfg = SshConfig::default();
        read_config_text(
            "/test/sshd_config",
            "Include /nonexistent/sshd_config.d/*.conf\n",
            0,
            &mut cfg,
        );
        assert!(cfg.has_dropin_include);
        assert_eq!(cfg.files.len(), 1);
    }

    #[test]
    fn include_depth_is_bounded() {
        let dir = std::env::temp_dir().join(format!("linuxdoctor-ssh-loop-{}", std::process::id()));
        fs::create_dir_all(&dir).unwrap();
        let file = dir.join("loop.conf");
        fs::write(&file, format!("Include {}\n", file.display())).unwrap();
        let mut cfg = SshConfig::default();
        let text = format!("Include {}\n", file.display());
        read_config_text("/test/sshd_config", &text, 0, &mut cfg);
        assert!(
            cfg.files.len() <= MAX_INCLUDE_DEPTH + 2,
            "{}",
            cfg.files.len()
        );
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn owners_of_our_own_sockets_are_found() {
        use std::net::TcpListener;
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let text = fs::read_to_string("/proc/net/tcp").unwrap();
        let socket = listeners::parse_proc_net(&text, Proto::Tcp)
            .into_iter()
            .find(|s| s.port == port)
            .expect("our listener is in /proc/net/tcp");
        let owners = find_owners(&HashSet::from([socket.inode]));
        let owner = owners
            .get(&socket.inode)
            .expect("we own it, so we can see it");
        assert_eq!(owner.pid, std::process::id());
        drop(listener);
    }
}
