// SPDX-License-Identifier: GPL-3.0-only

//! What the checks of the `server` module read.
//!
//! For the logs that survive a reboot (SRV002), the reboot that has been
//! waiting for days (SRV003) and the newer kernel that is installed (SRV005),
//! files only: see [`super::journal`], [`super::reboot`] and [`super::kernel`].
//!
//! For the package updates that are waiting (SRV004), the stamps of apt's
//! daily jobs (files) and the output of `apt list --upgradable`: see
//! [`super::pending`].
//!
//! For the automatic security updates (SRV001), which depend on the package
//! manager of the system:
//!
//! * on a Debian-like system, the settings apt keeps for its daily jobs --
//!   read with `apt-config dump`, which has already merged every file of
//!   `/etc/apt/apt.conf.d/` the way apt itself does --, whether
//!   `unattended-upgrade` is installed, and whether `apt-daily.timer` and
//!   `apt-daily-upgrade.timer` are enabled;
//! * on a Red Hat-like system, `/etc/dnf/automatic.conf` (and, with dnf5, the
//!   defaults the package ships), whether dnf-automatic is installed, and
//!   whether its timers are enabled.
//!
//! The state of a timer is what `systemctl is-enabled` says about its unit
//! file. That is the persistent intent -- it holds after a reboot -- and it
//! can be read without a running systemd, in a container or a chroot.

use std::fs::{File, Metadata};
use std::io::Read;
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

use crate::core::command::ToolSession;
use crate::core::error::ModuleError;
use crate::core::text::clean;
use crate::modules::recommend::Family;

use super::journal::{self, JournalSetup};
use super::kernel::{self, NewerKernel};
use super::pending::{self, PendingUpdates};
use super::reboot::{self, PendingReboot};

/// Longest value kept from a configuration file. The real ones are a word or a
/// number; the limit only keeps a hostile or broken file from filling a report.
const MAX_VALUE: usize = 64;

/// A configuration file is a few dozen lines. A bigger one is not one, and is
/// not read to the end.
const MAX_CONFIG_BYTES: u64 = 1024 * 1024;

/// What `unattended-upgrade` is installed as.
const UNATTENDED_UPGRADE: &str = "/usr/bin/unattended-upgrade";

/// Installed by the `dnf-automatic` package of dnf 4 (RHEL 8 to 10, Fedora up
/// to 40).
const DNF_AUTOMATIC: &str = "/usr/bin/dnf-automatic";

/// Only dnf 5 (Fedora 41 and later) has it: a system with it uses dnf5's
/// version of dnf-automatic.
const DNF5: &str = "/usr/bin/dnf5";

/// The defaults the dnf5 plugin ships, applied first. Its presence says the
/// plugin is installed.
const DNF5_DEFAULTS: &str = "/usr/share/dnf5/dnf5-plugins/automatic.conf";

/// The file the administrator edits, for dnf 4 and dnf 5 alike.
const DNF_CONFIG: &str = "/etc/dnf/automatic.conf";

/// The timers of apt: the first refreshes the package lists, the second runs
/// `unattended-upgrade`.
pub const APT_UPDATE_TIMER: &str = "apt-daily.timer";
pub const APT_UPGRADE_TIMER: &str = "apt-daily-upgrade.timer";

/// dnf 4's timers. The first installs whatever the configuration file says;
/// the second follows `apply_updates` in it; the last two never install.
pub const DNF4_INSTALL_TIMER: &str = "dnf-automatic-install.timer";
pub const DNF4_CONFIG_TIMER: &str = "dnf-automatic.timer";
pub const DNF4_DOWNLOAD_TIMER: &str = "dnf-automatic-download.timer";
pub const DNF4_NOTIFY_TIMER: &str = "dnf-automatic-notifyonly.timer";

/// dnf 5 has one, which follows `apply_updates`.
pub const DNF5_TIMER: &str = "dnf5-automatic.timer";

/// What systemd says about a unit file (`systemctl is-enabled`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UnitState {
    /// Started at boot (`enabled`, or `enabled-runtime` until the next one).
    Enabled,
    Disabled,
    /// Cannot be started at all, by anyone.
    Masked,
    /// There is no such unit.
    NotFound,
    /// Any other word (`static`, `alias`, `linked`...), as written.
    Other(String),
    /// systemd did not answer: no `systemctl`, or it was stopped.
    Unknown,
}

/// The `APT::Periodic` settings the daily jobs of apt read, as `apt-config`
/// has them. `None` is "not set".
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct AptPeriodic {
    /// `APT::Periodic::Enable`: `0` turns every daily job off.
    pub enable: Option<String>,
    /// `APT::Periodic::Update-Package-Lists`: how often `apt-get update` runs.
    pub update_lists: Option<String>,
    /// `APT::Periodic::Unattended-Upgrade`: how often `unattended-upgrade`
    /// runs.
    pub unattended: Option<String>,
    /// How many origins `unattended-upgrade` is allowed to take packages from
    /// (`Allowed-Origins` and `Origins-Pattern`, together).
    pub origins: usize,
}

/// Automatic updates with apt.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AptSetup {
    /// `unattended-upgrade` is installed.
    pub installed: bool,
    /// `None` when `apt-config` did not answer.
    pub periodic: Option<AptPeriodic>,
    pub update_timer: UnitState,
    pub upgrade_timer: UnitState,
}

/// Which dnf the system has.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DnfVersion {
    Dnf4,
    Dnf5,
}

/// The `[commands]` settings of dnf-automatic that decide whether it installs
/// anything. `None` is "not set".
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct DnfConfig {
    pub apply_updates: Option<String>,
    pub upgrade_type: Option<String>,
}

/// One timer of dnf-automatic and what systemd says about it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Timer {
    pub unit: &'static str,
    pub state: UnitState,
}

/// Automatic updates with dnf-automatic.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DnfSetup {
    pub version: DnfVersion,
    /// The package that provides dnf-automatic is installed.
    pub installed: bool,
    pub config: DnfConfig,
    /// Empty when it is not installed.
    pub timers: Vec<Timer>,
}

/// How the system updates itself, if it has a way this tool knows.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Updates {
    Apt(AptSetup),
    Dnf(DnfSetup),
    /// Not a Debian-like or a Red Hat-like system.
    Unsupported,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServerRawData {
    pub updates: Updates,
    pub journal: JournalSetup,
    /// `None` when no reboot is waiting (or the system has no marker for it).
    pub reboot: Option<PendingReboot>,
    /// The updates that are waiting. `None` outside Debian-like systems: only
    /// `apt` can count them without going to the network.
    pub pending: Option<PendingUpdates>,
    /// A kernel installed that is newer than the one running; `None` when
    /// there is not one, or when the installed ones could not be listed.
    pub kernel: Option<NewerKernel>,
    /// When it was read, in seconds since 1970: the ages are taken from it.
    pub now_unix: u64,
}

/// Where each reading comes from, so that the readings together are tested
/// on fake files.
pub struct Sources<'a> {
    /// What the files of the journal, of the reboot marker, of the kernels
    /// and of the package stamps are under: `/` on a real machine.
    pub root: &'a Path,
    /// The time to take the ages of files from.
    pub now_unix: u64,
    pub unattended_upgrade: &'a Path,
    pub dnf_automatic: &'a Path,
    pub dnf5: &'a Path,
    pub dnf5_defaults: &'a Path,
    pub dnf_config: &'a Path,
}

impl Sources<'static> {
    pub fn system() -> Self {
        Sources {
            root: Path::new("/"),
            now_unix: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map_or(0, |d| d.as_secs()),
            unattended_upgrade: Path::new(UNATTENDED_UPGRADE),
            dnf_automatic: Path::new(DNF_AUTOMATIC),
            dnf5: Path::new(DNF5),
            dnf5_defaults: Path::new(DNF5_DEFAULTS),
            dnf_config: Path::new(DNF_CONFIG),
        }
    }
}

/// The external tools, so that the readings are tested without them.
pub trait Tools {
    /// The output of `apt-config dump`; `None` when it did not run.
    fn apt_config_dump(&mut self) -> Option<String>;
    /// The output of `apt list --upgradable`; `None` when it did not run.
    fn apt_upgradable(&mut self) -> Option<String>;
    /// What systemd says about a unit file.
    fn unit_state(&mut self, unit: &str) -> UnitState;
}

/// The tools of this machine. Each is a session: once one has timed out, the
/// next calls to it are skipped rather than each waiting out its own limit.
pub struct SystemTools {
    apt_config: ToolSession,
    apt: ToolSession,
    systemctl: ToolSession,
}

impl SystemTools {
    pub fn system() -> Self {
        SystemTools {
            apt_config: ToolSession::new("apt-config"),
            // Reading the whole package cache can take a few seconds on a
            // machine that has just been updated.
            apt: ToolSession::new("apt").slow(),
            systemctl: ToolSession::new("systemctl"),
        }
    }
}

impl Tools for SystemTools {
    fn apt_config_dump(&mut self) -> Option<String> {
        self.apt_config.run(&["dump"])
    }

    fn apt_upgradable(&mut self) -> Option<String> {
        self.apt.run(&["list", "--upgradable"])
    }

    fn unit_state(&mut self, unit: &str) -> UnitState {
        // `is-enabled` exits with 1 for `disabled` and 4 for an unknown unit:
        // the answer is on the standard output, not in the status.
        match self.systemctl.run_ignoring_status(&["is-enabled", unit]) {
            Some(text) => parse_unit_state(&text),
            None => UnitState::Unknown,
        }
    }
}

pub fn collect(family: Family) -> Result<ServerRawData, ModuleError> {
    Ok(collect_from(
        family,
        &Sources::system(),
        &mut SystemTools::system(),
    ))
}

/// [`collect`] on the given places and with the given tools.
pub fn collect_from(family: Family, sources: &Sources, tools: &mut impl Tools) -> ServerRawData {
    let updates = match family {
        Family::DebianLike => Updates::Apt(read_apt(sources, tools)),
        Family::RedHatLike => Updates::Dnf(read_dnf(sources, tools)),
        Family::Unknown => Updates::Unsupported,
    };
    let pending = (family == Family::DebianLike).then(|| {
        let listing = tools.apt_upgradable();
        pending::read(sources.root, listing.as_deref())
    });
    ServerRawData {
        updates,
        journal: journal::read(sources.root, sources.now_unix),
        reboot: reboot::read(sources.root),
        pending,
        kernel: kernel::read(sources.root),
        now_unix: sources.now_unix,
    }
}

/// When a file was last written, in seconds since 1970; `None` if the file
/// system would not say, or says a time before 1970.
pub(super) fn modified_unix(metadata: &Metadata) -> Option<u64> {
    let modified = metadata.modified().ok()?;
    Some(modified.duration_since(UNIX_EPOCH).ok()?.as_secs())
}

// ---------------------------------------------------------------------------
// apt
// ---------------------------------------------------------------------------

fn read_apt(sources: &Sources, tools: &mut impl Tools) -> AptSetup {
    AptSetup {
        installed: sources.unattended_upgrade.exists(),
        periodic: tools.apt_config_dump().map(|text| parse_apt_config(&text)),
        update_timer: tools.unit_state(APT_UPDATE_TIMER),
        upgrade_timer: tools.unit_state(APT_UPGRADE_TIMER),
    }
}

/// The settings `unattended-upgrades` depends on, from the output of
/// `apt-config dump`: lines of the form `Key "value";`. apt's keys are not
/// case-sensitive, and the dump spells one the way the first file that set it
/// did, so they are compared without regard to case.
pub fn parse_apt_config(text: &str) -> AptPeriodic {
    let mut periodic = AptPeriodic::default();
    for line in text.lines() {
        let Some((key, value)) = apt_line(line) else {
            continue;
        };
        let setting = |name: &str| key.eq_ignore_ascii_case(name);
        if setting("APT::Periodic::Enable") {
            periodic.enable = Some(clean(value, MAX_VALUE));
        } else if setting("APT::Periodic::Update-Package-Lists") {
            periodic.update_lists = Some(clean(value, MAX_VALUE));
        } else if setting("APT::Periodic::Unattended-Upgrade") {
            periodic.unattended = Some(clean(value, MAX_VALUE));
        } else if (setting("Unattended-Upgrade::Allowed-Origins::")
            || setting("Unattended-Upgrade::Origins-Pattern::"))
            && !value.is_empty()
        {
            periodic.origins += 1;
        }
    }
    periodic
}

/// `Key "value";` as its key and its value. Anything else -- a blank line, a
/// line that is not a setting -- is nothing.
fn apt_line(line: &str) -> Option<(&str, &str)> {
    let line = line.trim();
    let (key, rest) = line.split_once(char::is_whitespace)?;
    let value = rest.trim().strip_suffix(';')?.strip_suffix('"')?;
    Some((key, value.strip_prefix('"')?))
}

/// The first word `systemctl is-enabled` printed, as a state.
pub fn parse_unit_state(text: &str) -> UnitState {
    let Some(word) = text.lines().map(str::trim).find(|line| !line.is_empty()) else {
        return UnitState::Unknown;
    };
    match word {
        "enabled" | "enabled-runtime" => UnitState::Enabled,
        "disabled" => UnitState::Disabled,
        "masked" | "masked-runtime" => UnitState::Masked,
        "not-found" => UnitState::NotFound,
        other => UnitState::Other(clean(other, MAX_VALUE)),
    }
}

// ---------------------------------------------------------------------------
// dnf
// ---------------------------------------------------------------------------

fn read_dnf(sources: &Sources, tools: &mut impl Tools) -> DnfSetup {
    let version = if sources.dnf5.exists() {
        DnfVersion::Dnf5
    } else {
        DnfVersion::Dnf4
    };
    let (installed, units): (bool, &[&'static str]) = match version {
        DnfVersion::Dnf4 => (
            sources.dnf_automatic.exists(),
            &[
                DNF4_INSTALL_TIMER,
                DNF4_CONFIG_TIMER,
                DNF4_DOWNLOAD_TIMER,
                DNF4_NOTIFY_TIMER,
            ],
        ),
        DnfVersion::Dnf5 => (sources.dnf5_defaults.exists(), &[DNF5_TIMER]),
    };
    if !installed {
        return DnfSetup {
            version,
            installed,
            config: DnfConfig::default(),
            timers: Vec::new(),
        };
    }
    // The defaults first, the administrator's file over them.
    let mut config = DnfConfig::default();
    for path in [sources.dnf5_defaults, sources.dnf_config] {
        if let Some(text) = read_config(path) {
            config.layer(parse_automatic_conf(&text));
        }
    }
    DnfSetup {
        version,
        installed,
        config,
        timers: units
            .iter()
            .map(|&unit| Timer {
                unit,
                state: tools.unit_state(unit),
            })
            .collect(),
    }
}

impl DnfConfig {
    /// What `over` sets replaces what is here; what it leaves out stays.
    fn layer(&mut self, over: DnfConfig) {
        if over.apply_updates.is_some() {
            self.apply_updates = over.apply_updates;
        }
        if over.upgrade_type.is_some() {
            self.upgrade_type = over.upgrade_type;
        }
    }
}

/// A text file, if it exists, is readable text and is not absurdly big.
pub(super) fn read_config(path: &Path) -> Option<String> {
    let mut text = String::new();
    File::open(path)
        .ok()?
        .take(MAX_CONFIG_BYTES)
        .read_to_string(&mut text)
        .ok()?;
    Some(text)
}

/// `apply_updates` and `upgrade_type` of the `[commands]` section of
/// `automatic.conf`. The same name in another section is not the setting. A
/// line is `name = value`; one that starts with `#` or `;` is a comment. When
/// a name is set twice, the last one counts.
pub fn parse_automatic_conf(text: &str) -> DnfConfig {
    let mut config = DnfConfig::default();
    let mut in_commands = false;
    for line in text.lines() {
        // A comment (`#` or `;`) needs no case of its own: it is no section,
        // and the name before its `=` starts with the comment mark.
        let line = line.trim();
        if let Some(section) = line.strip_prefix('[').and_then(|s| s.strip_suffix(']')) {
            in_commands = section.trim() == "commands";
            continue;
        }
        if !in_commands {
            continue;
        }
        let Some((name, value)) = line.split_once('=') else {
            continue;
        };
        let value = Some(clean(value.trim(), MAX_VALUE));
        match name.trim() {
            "apply_updates" => config.apply_updates = value,
            "upgrade_type" => config.upgrade_type = value,
            _ => {}
        }
    }
    config
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;
    use std::fs;
    use std::path::PathBuf;
    use std::time::Duration;

    // ----- apt-config dump ----------------------------------------------

    /// What `apt-config dump` prints on a machine set up by
    /// `dpkg-reconfigure unattended-upgrades`, cut down to its lines.
    const DUMP: &str = r#"APT "";
APT::Architecture "amd64";
APT::Periodic "";
APT::Periodic::Update-Package-Lists "1";
APT::Periodic::Unattended-Upgrade "1";
Unattended-Upgrade "";
Unattended-Upgrade::Allowed-Origins "";
Unattended-Upgrade::Allowed-Origins:: "${distro_id}:${distro_codename}";
Unattended-Upgrade::Allowed-Origins:: "${distro_id}:${distro_codename}-security";
Unattended-Upgrade::Origins-Pattern "";
Unattended-Upgrade::Origins-Pattern:: "origin=Debian,codename=${distro_codename}-security";
Unattended-Upgrade::Automatic-Reboot "false";
"#;

    #[test]
    fn the_periodic_settings_and_the_origins_are_read_from_the_dump() {
        assert_eq!(
            parse_apt_config(DUMP),
            AptPeriodic {
                enable: None,
                update_lists: Some("1".into()),
                unattended: Some("1".into()),
                origins: 3,
            }
        );
    }

    #[test]
    fn the_enable_switch_is_read_and_the_others_may_be_absent() {
        let periodic = parse_apt_config("APT::Periodic::Enable \"0\";\n");
        assert_eq!(periodic.enable.as_deref(), Some("0"));
        assert_eq!(periodic.update_lists, None);
        assert_eq!(periodic.unattended, None);
        assert_eq!(periodic.origins, 0);
        assert_eq!(parse_apt_config(""), AptPeriodic::default());
    }

    #[test]
    fn apt_keys_are_not_case_sensitive() {
        // `apt-config` prints a key the way the first file that set it wrote
        // it, and apt reads it whatever the case.
        let periodic = parse_apt_config(
            "apt::periodic::unattended-upgrade \"2\";\n\
             Apt::Periodic::UPDATE-PACKAGE-LISTS \"always\";\n\
             APT::PERIODIC::ENABLE \"1\";\n\
             UNATTENDED-UPGRADE::ALLOWED-ORIGINS:: \"a\";\n\
             unattended-upgrade::origins-pattern:: \"b\";\n",
        );
        assert_eq!(periodic.unattended.as_deref(), Some("2"));
        assert_eq!(periodic.update_lists.as_deref(), Some("always"));
        assert_eq!(periodic.enable.as_deref(), Some("1"));
        assert_eq!(periodic.origins, 2);
    }

    #[test]
    fn only_the_list_entries_count_as_origins_and_an_empty_one_is_none() {
        // The `""` lines are the lists themselves, not an origin in them.
        let periodic = parse_apt_config(
            "Unattended-Upgrade::Allowed-Origins \"\";\n\
             Unattended-Upgrade::Origins-Pattern \"\";\n\
             Unattended-Upgrade::Allowed-Origins:: \"\";\n\
             Unattended-Upgrade::Blacklist:: \"linux-image\";\n",
        );
        assert_eq!(periodic.origins, 0);
    }

    #[test]
    fn the_last_value_of_a_setting_counts() {
        let periodic = parse_apt_config(
            "APT::Periodic::Unattended-Upgrade \"1\";\nAPT::Periodic::Unattended-Upgrade \"0\";\n",
        );
        assert_eq!(periodic.unattended.as_deref(), Some("0"));
    }

    #[test]
    fn a_line_that_is_not_a_setting_is_skipped() {
        // Each wrong line is on a key of its own, so that a line taken for a
        // setting would show.
        for line in [
            "",
            "garbage",
            "APT::Periodic::Unattended-Upgrade",
            "APT::Periodic::Unattended-Upgrade 1;",
            "APT::Periodic::Unattended-Upgrade \"1\"",
            "APT::Periodic::Unattended-Upgrade 1\";",
            "APT::Periodic::Unattended-Upgrade \"1;",
            "APT::Periodic::Unattended-Upgrade \"1\";;",
        ] {
            assert_eq!(
                parse_apt_config(&format!("{line}\n")),
                AptPeriodic::default(),
                "{line:?}"
            );
        }
        // And the same line, well formed, indented and followed by blanks, is one.
        let periodic = parse_apt_config("  \tAPT::Periodic::Enable \"0\";  \n");
        assert_eq!(periodic.enable.as_deref(), Some("0"));
    }

    #[test]
    fn a_value_is_shortened_and_cleaned() {
        let hostile = format!(
            "APT::Periodic::Unattended-Upgrade \"{}\";\n",
            "9".repeat(200)
        );
        let value = parse_apt_config(&hostile).unattended.unwrap();
        assert_eq!(value.chars().count(), MAX_VALUE + 1, "{value}");
        assert!(value.ends_with('…'));
        let escape = parse_apt_config(
            "APT::Periodic::Enable \"\u{1b}[31m\";\n\
             APT::Periodic::Update-Package-Lists \"\u{7}1\";\n\
             APT::Periodic::Unattended-Upgrade \"\u{202e}1\";\n",
        );
        assert_eq!(escape.enable.as_deref(), Some("?[31m"));
        assert_eq!(escape.update_lists.as_deref(), Some("?1"));
        assert_eq!(escape.unattended.as_deref(), Some("?1"));
    }

    // ----- systemctl is-enabled -----------------------------------------

    #[test]
    fn the_words_of_is_enabled_are_states() {
        for (text, state) in [
            ("enabled\n", UnitState::Enabled),
            ("enabled-runtime\n", UnitState::Enabled),
            ("disabled\n", UnitState::Disabled),
            ("masked\n", UnitState::Masked),
            ("masked-runtime\n", UnitState::Masked),
            ("not-found\n", UnitState::NotFound),
            ("static\n", UnitState::Other("static".into())),
            ("alias\n", UnitState::Other("alias".into())),
            ("  enabled  \n", UnitState::Enabled),
            ("\n\nenabled\n", UnitState::Enabled),
            ("enabled\ndisabled\n", UnitState::Enabled),
            ("", UnitState::Unknown),
            ("\n  \n", UnitState::Unknown),
        ] {
            assert_eq!(parse_unit_state(text), state, "{text:?}");
        }
    }

    #[test]
    fn a_word_that_is_not_a_state_is_kept_cleaned() {
        // Case matters: systemd writes the words in lower case.
        assert_eq!(
            parse_unit_state("Enabled\n"),
            UnitState::Other("Enabled".into())
        );
        assert_eq!(
            parse_unit_state("\u{1b}[2Jgone\n"),
            UnitState::Other("?[2Jgone".into())
        );
        let long = "x".repeat(200);
        match parse_unit_state(&long) {
            UnitState::Other(word) => assert_eq!(word.chars().count(), MAX_VALUE + 1),
            other => panic!("{other:?}"),
        }
    }

    // ----- automatic.conf -------------------------------------------------

    #[test]
    fn the_commands_section_of_automatic_conf_is_read() {
        let config = parse_automatic_conf(
            "# comment\n\
             [commands]\n\
             upgrade_type = security\n\
             random_sleep = 360\n\
             apply_updates = yes\n\
             \n\
             [emitters]\n\
             emit_via = stdio\n",
        );
        assert_eq!(config.apply_updates.as_deref(), Some("yes"));
        assert_eq!(config.upgrade_type.as_deref(), Some("security"));
    }

    #[test]
    fn a_name_in_another_section_is_not_the_setting() {
        let config = parse_automatic_conf(
            "[base]\napply_updates = yes\nupgrade_type = security\n\
             [commands]\n[email]\napply_updates = yes\n",
        );
        assert_eq!(config, DnfConfig::default());
        // The section is found again after another one.
        let config = parse_automatic_conf("[base]\n[commands]\napply_updates = no\n");
        assert_eq!(config.apply_updates.as_deref(), Some("no"));
    }

    #[test]
    fn comments_blanks_and_spacing_are_not_settings() {
        let config = parse_automatic_conf(
            "[commands]\n\
             \x20  \n\
             apply_updates=no\n\
             upgrade_type   =   default   \n\
             apply_updates_not = yes\n\
             novalue\n\
             # apply_updates = yes\n\
             ; upgrade_type = security\n\
             \x20 # apply_updates = yes\n",
        );
        assert_eq!(config.apply_updates.as_deref(), Some("no"));
        assert_eq!(config.upgrade_type.as_deref(), Some("default"));
        // A section header is recognised even indented and with spaces.
        let config = parse_automatic_conf("  [ commands ]  \napply_updates = yes\n");
        assert_eq!(config.apply_updates.as_deref(), Some("yes"));
    }

    #[test]
    fn a_value_in_automatic_conf_is_shortened_and_cleaned() {
        let config = parse_automatic_conf(&format!(
            "[commands]\napply_updates = \u{1b}[31myes\nupgrade_type = {}\n",
            "s".repeat(200)
        ));
        assert_eq!(config.apply_updates.as_deref(), Some("?[31myes"));
        let value = config.upgrade_type.unwrap();
        assert_eq!(value.chars().count(), MAX_VALUE + 1, "{value}");
        assert!(value.ends_with('…'));
    }

    #[test]
    fn the_last_value_in_automatic_conf_counts_and_an_empty_one_is_a_value() {
        let config = parse_automatic_conf("[commands]\napply_updates = yes\napply_updates = \n");
        assert_eq!(config.apply_updates.as_deref(), Some(""));
        let config = parse_automatic_conf("[commands]\napply_updates = yes\napply_updates = no\n");
        assert_eq!(config.apply_updates.as_deref(), Some("no"));
    }

    #[test]
    fn a_setting_is_layered_over_the_defaults_and_keeps_what_it_leaves_out() {
        let mut config = DnfConfig {
            apply_updates: Some("no".into()),
            upgrade_type: Some("default".into()),
        };
        config.layer(DnfConfig {
            apply_updates: Some("yes".into()),
            upgrade_type: None,
        });
        assert_eq!(config.apply_updates.as_deref(), Some("yes"));
        assert_eq!(config.upgrade_type.as_deref(), Some("default"));
        config.layer(DnfConfig {
            apply_updates: None,
            upgrade_type: Some("security".into()),
        });
        assert_eq!(config.apply_updates.as_deref(), Some("yes"));
        assert_eq!(config.upgrade_type.as_deref(), Some("security"));
    }

    // ----- the readings together -------------------------------------------

    struct FakeTools {
        dump: Option<String>,
        listing: Option<String>,
        states: BTreeMap<&'static str, UnitState>,
        asked: Vec<String>,
    }

    impl FakeTools {
        fn new(dump: Option<&str>, states: &[(&'static str, UnitState)]) -> Self {
            FakeTools {
                dump: dump.map(str::to_string),
                listing: None,
                states: states.iter().cloned().collect(),
                asked: Vec::new(),
            }
        }
    }

    impl Tools for FakeTools {
        fn apt_config_dump(&mut self) -> Option<String> {
            self.asked.push("apt-config".into());
            self.dump.clone()
        }

        fn apt_upgradable(&mut self) -> Option<String> {
            self.asked.push("apt-list".into());
            self.listing.clone()
        }

        fn unit_state(&mut self, unit: &str) -> UnitState {
            self.asked.push(unit.to_string());
            self.states.get(unit).cloned().unwrap_or(UnitState::Unknown)
        }
    }

    /// The time the fake trees are read at.
    const NOW: u64 = 1_000_000_000;

    fn tree(name: &str) -> PathBuf {
        let root = std::env::temp_dir().join(format!(
            "linuxdoctor-server-collect-{name}-{}",
            std::process::id()
        ));
        let _ = fs::remove_dir_all(&root);
        fs::create_dir_all(&root).unwrap();
        root
    }

    fn touch(root: &Path, relative: &str) {
        fs::write(root.join(relative), "").unwrap();
    }

    fn sources(root: &Path) -> Sources<'static> {
        let leak =
            |relative: &str| -> &'static Path { Box::leak(root.join(relative).into_boxed_path()) };
        Sources {
            root: leak("fs"),
            now_unix: NOW,
            unattended_upgrade: leak("unattended-upgrade"),
            dnf_automatic: leak("dnf-automatic"),
            dnf5: leak("dnf5"),
            dnf5_defaults: leak("dnf5-defaults.conf"),
            dnf_config: leak("automatic.conf"),
        }
    }

    #[test]
    fn the_logs_and_the_reboot_marker_are_read_under_the_root() {
        let root = tree("files");
        let files = root.join("fs");
        for dir in ["var/log/journal", "var/run", "etc/systemd/journald.conf.d"] {
            fs::create_dir_all(files.join(dir)).unwrap();
        }
        fs::write(
            files.join("etc/systemd/journald.conf.d/10-v.conf"),
            "[Journal]\nStorage=volatile\n",
        )
        .unwrap();
        fs::write(files.join("var/log/syslog"), "line\n").unwrap();
        fs::File::options()
            .write(true)
            .open(files.join("var/log/syslog"))
            .unwrap()
            .set_modified(UNIX_EPOCH + Duration::from_secs(NOW - 3 * 3600))
            .unwrap();
        fs::write(files.join("var/run/reboot-required"), "").unwrap();
        fs::write(files.join("var/run/reboot-required.pkgs"), "libc6\n").unwrap();

        let mut tools = FakeTools::new(None, &[]);
        let data = collect_from(Family::Unknown, &sources(&root), &mut tools);
        assert_eq!(data.now_unix, NOW);
        assert!(data.journal.journald && data.journal.directory);
        let setting = data.journal.setting.unwrap();
        assert_eq!(
            setting.value,
            crate::modules::server::journal::Storage::Volatile
        );
        assert_eq!(setting.file, "/etc/systemd/journald.conf.d/10-v.conf");
        // Written 3 hours before the time it is read at.
        assert_eq!(data.journal.syslog.len(), 1);
        assert_eq!(data.journal.syslog[0].age_secs, 3 * 3600);
        let reboot = data.reboot.unwrap();
        assert_eq!(reboot.packages, ["libc6"]);
        assert!(reboot.modified_unix.is_some());
        // The logs and the marker are read whatever the family.
        let data = collect_from(Family::DebianLike, &sources(&root), &mut tools);
        assert!(data.reboot.is_some() && data.journal.journald);
    }

    #[test]
    fn a_root_without_logs_or_marker_has_none() {
        let root = tree("no-files");
        let mut tools = FakeTools::new(None, &[]);
        let data = collect_from(Family::Unknown, &sources(&root), &mut tools);
        assert_eq!(data.journal, JournalSetup::default());
        assert_eq!(data.reboot, None);
    }

    #[test]
    fn a_debian_like_system_is_read_with_apt() {
        let root = tree("apt");
        touch(&root, "unattended-upgrade");
        let mut tools = FakeTools::new(
            Some(DUMP),
            &[
                (APT_UPDATE_TIMER, UnitState::Enabled),
                (APT_UPGRADE_TIMER, UnitState::Disabled),
            ],
        );
        let data = collect_from(Family::DebianLike, &sources(&root), &mut tools);
        let Updates::Apt(apt) = data.updates else {
            panic!("{:?}", data.updates);
        };
        assert!(apt.installed);
        assert_eq!(apt.periodic.unwrap().unattended.as_deref(), Some("1"));
        assert_eq!(apt.update_timer, UnitState::Enabled);
        assert_eq!(apt.upgrade_timer, UnitState::Disabled);
        assert_eq!(
            tools.asked,
            [
                "apt-config",
                APT_UPDATE_TIMER,
                APT_UPGRADE_TIMER,
                "apt-list"
            ]
        );
    }

    fn touched(root: &Path, relative: &str, ago: u64) {
        let path = root.join(relative);
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(&path, "").unwrap();
        fs::File::options()
            .write(true)
            .open(path)
            .unwrap()
            .set_modified(UNIX_EPOCH + Duration::from_secs(NOW - ago))
            .unwrap();
    }

    #[test]
    fn the_waiting_updates_are_counted_on_a_debian_like_system_only() {
        let root = tree("pending");
        touched(&root, "fs/var/lib/apt/periodic/update-success-stamp", 7200);
        touched(&root, "fs/var/log/dpkg.log", 3 * 86_400);
        let mut tools = FakeTools::new(None, &[]);
        tools.listing = Some(
            "Listing...\na/noble-security 2 amd64 [upgradable from: 1]\nb/noble-updates 2 all [upgradable from: 1]\n"
                .into(),
        );
        let data = collect_from(Family::DebianLike, &sources(&root), &mut tools);
        let pending = data.pending.unwrap();
        let upgradable = pending.upgradable.unwrap();
        assert_eq!((upgradable.total, upgradable.security), (2, 1));
        assert_eq!(pending.lists_unix, Some(NOW - 7200));
        assert_eq!(pending.last_run_unix, Some(NOW - 3 * 86_400));

        // `apt` that does not answer is a count that is not known, not zero.
        let mut silent = FakeTools::new(None, &[]);
        let data = collect_from(Family::DebianLike, &sources(&root), &mut silent);
        assert_eq!(data.pending.unwrap().upgradable, None);

        // The other families are not asked, and have nothing to say.
        for family in [Family::RedHatLike, Family::Unknown] {
            let mut tools = FakeTools::new(None, &[]);
            tools.listing = Some("Listing...\n".into());
            let data = collect_from(family, &sources(&root), &mut tools);
            assert_eq!(data.pending, None, "{family:?}");
            assert!(!tools.asked.iter().any(|a| a == "apt-list"), "{family:?}");
        }
    }

    #[test]
    fn a_newer_kernel_is_looked_for_on_every_family() {
        let root = tree("kernel");
        let files = root.join("fs");
        fs::create_dir_all(files.join("proc/sys/kernel")).unwrap();
        fs::create_dir_all(files.join("boot")).unwrap();
        fs::write(
            files.join("proc/sys/kernel/osrelease"),
            "6.8.0-45-generic\n",
        )
        .unwrap();
        touch(&files, "boot/vmlinuz-6.8.0-45-generic");
        touch(&files, "boot/vmlinuz-6.8.0-52-generic");
        touched(&root, "fs/boot/initrd.img-6.8.0-52-generic", 2 * 86_400);
        for family in [Family::DebianLike, Family::RedHatLike, Family::Unknown] {
            let mut tools = FakeTools::new(None, &[]);
            let data = collect_from(family, &sources(&root), &mut tools);
            let kernel = data.kernel.unwrap_or_else(|| panic!("{family:?}"));
            assert_eq!(kernel.running, "6.8.0-45-generic", "{family:?}");
            assert_eq!(kernel.installed, "6.8.0-52-generic", "{family:?}");
            assert_eq!(kernel.installed_unix, Some(NOW - 2 * 86_400), "{family:?}");
        }
        // The kernel that runs is the newest: nothing to say.
        fs::remove_file(files.join("boot/vmlinuz-6.8.0-52-generic")).unwrap();
        let data = collect_from(
            Family::Unknown,
            &sources(&root),
            &mut FakeTools::new(None, &[]),
        );
        assert_eq!(data.kernel, None);
    }

    #[test]
    fn an_apt_system_without_the_package_or_the_dump_says_so() {
        let root = tree("apt-missing");
        let mut tools = FakeTools::new(None, &[]);
        let data = collect_from(Family::DebianLike, &sources(&root), &mut tools);
        let Updates::Apt(apt) = data.updates else {
            panic!("{:?}", data.updates);
        };
        assert!(!apt.installed);
        assert_eq!(apt.periodic, None);
        assert_eq!(apt.update_timer, UnitState::Unknown);
        assert_eq!(apt.upgrade_timer, UnitState::Unknown);
    }

    #[test]
    fn dnf4_is_read_from_its_file_and_its_four_timers() {
        let root = tree("dnf4");
        touch(&root, "dnf-automatic");
        fs::write(
            root.join("automatic.conf"),
            "[commands]\nupgrade_type = security\napply_updates = yes\n",
        )
        .unwrap();
        let mut tools = FakeTools::new(
            None,
            &[
                (DNF4_CONFIG_TIMER, UnitState::Enabled),
                (DNF4_NOTIFY_TIMER, UnitState::Disabled),
            ],
        );
        let data = collect_from(Family::RedHatLike, &sources(&root), &mut tools);
        let Updates::Dnf(dnf) = data.updates else {
            panic!("{:?}", data.updates);
        };
        assert_eq!(dnf.version, DnfVersion::Dnf4);
        assert!(dnf.installed);
        assert_eq!(dnf.config.apply_updates.as_deref(), Some("yes"));
        assert_eq!(dnf.config.upgrade_type.as_deref(), Some("security"));
        let timers: Vec<(&str, &UnitState)> =
            dnf.timers.iter().map(|t| (t.unit, &t.state)).collect();
        assert_eq!(
            timers,
            [
                (DNF4_INSTALL_TIMER, &UnitState::Unknown),
                (DNF4_CONFIG_TIMER, &UnitState::Enabled),
                (DNF4_DOWNLOAD_TIMER, &UnitState::Unknown),
                (DNF4_NOTIFY_TIMER, &UnitState::Disabled),
            ]
        );
        assert_eq!(tools.asked.len(), 4, "dnf4 does not ask for dnf5's timer");
    }

    #[test]
    fn dnf5_is_read_from_the_defaults_and_the_file_over_them() {
        let root = tree("dnf5");
        touch(&root, "dnf5");
        fs::write(
            root.join("dnf5-defaults.conf"),
            "[commands]\napply_updates = no\nupgrade_type = default\n",
        )
        .unwrap();
        fs::write(
            root.join("automatic.conf"),
            "[commands]\napply_updates = yes\n",
        )
        .unwrap();
        let mut tools = FakeTools::new(None, &[(DNF5_TIMER, UnitState::Enabled)]);
        let data = collect_from(Family::RedHatLike, &sources(&root), &mut tools);
        let Updates::Dnf(dnf) = data.updates else {
            panic!("{:?}", data.updates);
        };
        assert_eq!(dnf.version, DnfVersion::Dnf5);
        assert!(dnf.installed);
        assert_eq!(dnf.config.apply_updates.as_deref(), Some("yes"));
        assert_eq!(dnf.config.upgrade_type.as_deref(), Some("default"));
        assert_eq!(
            dnf.timers,
            [Timer {
                unit: DNF5_TIMER,
                state: UnitState::Enabled
            }]
        );
        assert_eq!(tools.asked, [DNF5_TIMER]);
    }

    #[test]
    fn dnf5_without_its_plugin_is_not_installed_even_with_dnf4s_binary_around() {
        let root = tree("dnf5-no-plugin");
        touch(&root, "dnf5");
        touch(&root, "dnf-automatic");
        let mut tools = FakeTools::new(None, &[]);
        let data = collect_from(Family::RedHatLike, &sources(&root), &mut tools);
        let Updates::Dnf(dnf) = data.updates else {
            panic!("{:?}", data.updates);
        };
        assert_eq!(dnf.version, DnfVersion::Dnf5);
        assert!(!dnf.installed);
        assert!(tools.asked.is_empty(), "nothing to ask when not installed");
    }

    #[test]
    fn dnf4_without_the_package_asks_systemd_nothing_and_reads_no_file() {
        let root = tree("dnf4-no-package");
        // The files exist, but the package that would use them does not.
        fs::write(
            root.join("automatic.conf"),
            "[commands]\napply_updates = yes\n",
        )
        .unwrap();
        touch(&root, "dnf5-defaults.conf");
        let mut tools = FakeTools::new(None, &[]);
        let data = collect_from(Family::RedHatLike, &sources(&root), &mut tools);
        let Updates::Dnf(dnf) = data.updates else {
            panic!("{:?}", data.updates);
        };
        assert_eq!(dnf.version, DnfVersion::Dnf4);
        assert!(!dnf.installed);
        assert_eq!(dnf.config, DnfConfig::default());
        assert!(dnf.timers.is_empty());
        assert!(tools.asked.is_empty());
    }

    #[test]
    fn an_unreadable_or_missing_configuration_leaves_the_settings_unset() {
        let root = tree("dnf4-no-config");
        touch(&root, "dnf-automatic");
        // Not UTF-8: not a configuration file.
        fs::write(root.join("automatic.conf"), [0xff, 0xfe, 0x00]).unwrap();
        let mut tools = FakeTools::new(None, &[]);
        let data = collect_from(Family::RedHatLike, &sources(&root), &mut tools);
        let Updates::Dnf(dnf) = data.updates else {
            panic!("{:?}", data.updates);
        };
        assert!(dnf.installed);
        assert_eq!(dnf.config, DnfConfig::default());
    }

    #[test]
    fn a_huge_configuration_file_is_not_read_to_the_end() {
        let root = tree("dnf4-huge");
        touch(&root, "dnf-automatic");
        let mut text = String::from("[commands]\n");
        // Past the limit, a line that would change the answer.
        text.push_str(&"# padding\n".repeat(MAX_CONFIG_BYTES as usize / 10 + 10));
        text.push_str("apply_updates = yes\n");
        fs::write(root.join("automatic.conf"), text).unwrap();
        let mut tools = FakeTools::new(None, &[]);
        let data = collect_from(Family::RedHatLike, &sources(&root), &mut tools);
        let Updates::Dnf(dnf) = data.updates else {
            panic!("{:?}", data.updates);
        };
        assert_eq!(dnf.config.apply_updates, None);
    }

    #[test]
    fn another_family_has_nothing_to_read() {
        let root = tree("other");
        touch(&root, "unattended-upgrade");
        touch(&root, "dnf-automatic");
        let mut tools = FakeTools::new(Some(DUMP), &[]);
        let data = collect_from(Family::Unknown, &sources(&root), &mut tools);
        assert_eq!(data.updates, Updates::Unsupported);
        assert!(
            tools.asked.is_empty(),
            "no tool is run for a family we skip"
        );
    }
}
