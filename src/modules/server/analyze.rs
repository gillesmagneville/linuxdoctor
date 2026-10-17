// SPDX-License-Identifier: GPL-3.0-only

use crate::core::context::Context;
use crate::core::text::clean;
use crate::models::{Category, Confidence, Finding, Severity};
use crate::modules::recommend::Steps;

use super::collect::{
    AptPeriodic, AptSetup, DnfConfig, DnfSetup, DnfVersion, ServerRawData, Timer, UnitState,
    Updates, APT_UPDATE_TIMER, APT_UPGRADE_TIMER, DNF4_CONFIG_TIMER, DNF4_DOWNLOAD_TIMER,
    DNF4_INSTALL_TIMER, DNF4_NOTIFY_TIMER, DNF5_TIMER,
};

/// Pure function: RawData -> Findings. No I/O -- see ARCHITECTURE.md
/// "Testing Strategy".
pub fn analyze(data: &ServerRawData, ctx: &Context) -> Vec<Finding> {
    vec![updates_finding(&data.updates, ctx.distro.as_deref())]
}

// ---------------------------------------------------------------------------
// SRV001 -- automatic security updates
// ---------------------------------------------------------------------------

/// Longest distribution name quoted back: a name is a few words.
const MAX_DISTRO: usize = 64;

/// A server nobody logs in to every day is patched by a mechanism, not by a
/// person. This reports whether the system's own mechanism is set up -- not
/// whether the last run worked --, and says plainly what it did not look at:
/// a machine patched another way (a configuration-management tool, Landscape,
/// Satellite, a maintenance window) is fine without it, which is why the
/// finding is a warning at most, and never certain.
fn updates_finding(updates: &Updates, distro: Option<&str>) -> Finding {
    match updates {
        Updates::Apt(apt) => apt_finding(apt),
        Updates::Dnf(dnf) => dnf_finding(dnf),
        Updates::Unsupported => unsupported_finding(distro),
    }
}

fn builder(severity: Severity, confidence: Confidence) -> crate::models::finding::FindingBuilder {
    Finding::builder(
        "SRV001",
        "Automatic Security Updates",
        Category::Security,
        severity,
        confidence,
    )
}

/// What a finding says when it is wrong that the machine is not patched by
/// something this tool cannot see.
const OTHER_WAYS: &str = "This looks only at the system's own mechanism. If the machine is \
     patched another way (a configuration-management tool, Landscape or Satellite, a regular \
     maintenance window), the absence of it is expected and this can be ignored.";

/// A reading of the setup: what is wrong with it, or that nothing is.
enum Verdict<P> {
    /// Updates are installed automatically.
    Active,
    /// They are not, for these reasons.
    Gaps(Vec<P>),
    /// Something that decides it could not be read, and what could be read
    /// shows no fault.
    Unclear(Vec<String>),
}

/// The state of a unit as a word, for the evidence.
fn state_word(state: &UnitState) -> String {
    match state {
        UnitState::Enabled => "enabled".into(),
        UnitState::Disabled => "disabled".into(),
        UnitState::Masked => "masked".into(),
        UnitState::NotFound => "not-found".into(),
        UnitState::Other(word) => word.clone(),
        UnitState::Unknown => "unknown".into(),
    }
}

/// How a unit that is not enabled is described in a sentence.
fn not_enabled(state: &UnitState) -> String {
    match state {
        UnitState::Disabled => "disabled".into(),
        UnitState::Masked => "masked".into(),
        UnitState::NotFound => "missing".into(),
        UnitState::Other(word) => format!("`{word}`, not enabled"),
        // Not a fault: nothing is said about a unit that could not be read.
        UnitState::Enabled | UnitState::Unknown => String::new(),
    }
}

fn sentence(sentences: &[String]) -> String {
    sentences.join(" ")
}

fn unclear_finding(builder: crate::models::finding::FindingBuilder, reasons: &[String]) -> Finding {
    builder
        .explanation(format!(
            "Whether security updates are installed automatically could not be told: {} \
             Nothing wrong was found in what could be read.",
            sentence(reasons)
        ))
        .build()
}

// ----- apt ------------------------------------------------------------------

/// How often an apt daily job runs, from the value of its setting.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Interval {
    Off,
    On,
    /// A value apt's script cannot make a number of seconds of.
    Invalid,
}

/// What `apt.systemd.daily` makes of an interval: `0` (or nothing) is off,
/// `always` runs at every job, and a number of days -- or of seconds,
/// minutes, hours or days with a suffix -- is on. The script compares the text
/// with `0`, not the number, so `00` or `0d` run the job every time: they are
/// "on" here too, because that is what happens.
fn interval(value: Option<&str>) -> Interval {
    match value {
        None | Some("") | Some("0") => Interval::Off,
        Some("always") => Interval::On,
        Some(text) => {
            let digits = text
                .strip_suffix(|c| matches!(c, 's' | 'm' | 'h' | 'd'))
                .unwrap_or(text);
            if !digits.is_empty() && digits.bytes().all(|b| b.is_ascii_digit()) {
                Interval::On
            } else {
                Interval::Invalid
            }
        }
    }
}

/// `APT::Periodic::Enable` is compared as a number: `0` turns every daily job
/// off, and anything that is not a number does not.
fn jobs_off(enable: Option<&str>) -> bool {
    enable.is_some_and(|value| value.trim().parse::<i64>() == Ok(0))
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum AptProblem {
    NotInstalled,
    JobsOff,
    UnattendedUpgradeOff,
    UnattendedUpgradeInvalid(String),
    PackageListsOff,
    PackageListsInvalid(String),
    NoOrigins,
    TimerNotEnabled {
        unit: &'static str,
        what: &'static str,
        state: UnitState,
    },
}

impl AptProblem {
    fn sentence(&self) -> String {
        match self {
            AptProblem::NotInstalled => {
                "`unattended-upgrade` is not installed, so nothing installs updates on its own."
                    .into()
            }
            AptProblem::JobsOff => {
                "`APT::Periodic::Enable` is 0, which turns off every daily job of apt.".into()
            }
            AptProblem::UnattendedUpgradeOff => {
                "`APT::Periodic::Unattended-Upgrade` is not set (or is 0), so \
                 `unattended-upgrade` never runs."
                    .into()
            }
            AptProblem::UnattendedUpgradeInvalid(value) => format!(
                "`APT::Periodic::Unattended-Upgrade` is `{value}`, which apt cannot read as a \
                 number of days."
            ),
            AptProblem::PackageListsOff => {
                "`APT::Periodic::Update-Package-Lists` is not set (or is 0), so the package \
                 lists are never refreshed and new updates are never seen."
                    .into()
            }
            AptProblem::PackageListsInvalid(value) => format!(
                "`APT::Periodic::Update-Package-Lists` is `{value}`, which apt cannot read as \
                 a number of days."
            ),
            AptProblem::NoOrigins => {
                "`unattended-upgrade` is not allowed to take packages from any origin \
                 (`Unattended-Upgrade::Allowed-Origins` and `Origins-Pattern` are empty), so it \
                 has nothing it may install."
                    .into()
            }
            AptProblem::TimerNotEnabled { unit, what, state } => {
                format!("`{unit}`, which {what}, is {}.", not_enabled(state))
            }
        }
    }
}

/// What stops apt from installing security updates by itself, or that
/// nothing does. Everything below has to hold for the daily jobs to run:
/// `apt-daily.timer` refreshes the lists and `apt-daily-upgrade.timer` runs
/// `unattended-upgrade`, each only if its setting says so.
fn apt_verdict(apt: &AptSetup) -> Verdict<AptProblem> {
    let mut problems = Vec::new();
    let mut unclear = Vec::new();
    if !apt.installed {
        problems.push(AptProblem::NotInstalled);
    }
    match &apt.periodic {
        Some(periodic) => apt_setting_problems(periodic, apt.installed, &mut problems),
        None => unclear.push("`apt-config dump` could not be run.".to_string()),
    }
    for (unit, what, state) in [
        (
            APT_UPDATE_TIMER,
            "refreshes the package lists",
            &apt.update_timer,
        ),
        (
            APT_UPGRADE_TIMER,
            "runs `unattended-upgrade`",
            &apt.upgrade_timer,
        ),
    ] {
        match state {
            UnitState::Enabled => {}
            UnitState::Unknown => {
                unclear.push(format!("systemd did not say whether `{unit}` is enabled."));
            }
            _ => problems.push(AptProblem::TimerNotEnabled {
                unit,
                what,
                state: state.clone(),
            }),
        }
    }
    if !problems.is_empty() {
        Verdict::Gaps(problems)
    } else if !unclear.is_empty() {
        Verdict::Unclear(unclear)
    } else {
        Verdict::Active
    }
}

fn apt_setting_problems(periodic: &AptPeriodic, installed: bool, problems: &mut Vec<AptProblem>) {
    if jobs_off(periodic.enable.as_deref()) {
        problems.push(AptProblem::JobsOff);
    }
    match interval(periodic.unattended.as_deref()) {
        Interval::On => {}
        Interval::Off => problems.push(AptProblem::UnattendedUpgradeOff),
        Interval::Invalid => problems.push(AptProblem::UnattendedUpgradeInvalid(
            periodic.unattended.clone().unwrap_or_default(),
        )),
    }
    match interval(periodic.update_lists.as_deref()) {
        Interval::On => {}
        Interval::Off => problems.push(AptProblem::PackageListsOff),
        Interval::Invalid => problems.push(AptProblem::PackageListsInvalid(
            periodic.update_lists.clone().unwrap_or_default(),
        )),
    }
    // The list of origins is in a file the package ships: before it is
    // installed, an empty list is not a second fault.
    if installed && periodic.origins == 0 {
        problems.push(AptProblem::NoOrigins);
    }
}

fn apt_finding(apt: &AptSetup) -> Finding {
    let with_evidence = |builder: crate::models::finding::FindingBuilder| {
        let mut builder = builder.evidence("package_manager", "apt").evidence(
            "unattended_upgrade_installed",
            if apt.installed { "yes" } else { "no" },
        );
        if let Some(periodic) = &apt.periodic {
            if let Some(enable) = &periodic.enable {
                builder = builder.evidence("periodic_enable", enable.clone());
            }
            builder = builder
                .evidence(
                    "update_package_lists",
                    periodic.update_lists.as_deref().unwrap_or("not set"),
                )
                .evidence(
                    "unattended_upgrade_interval",
                    periodic.unattended.as_deref().unwrap_or("not set"),
                )
                .evidence("allowed_origins", periodic.origins.to_string());
        }
        builder
            .evidence(APT_UPDATE_TIMER, state_word(&apt.update_timer))
            .evidence(APT_UPGRADE_TIMER, state_word(&apt.upgrade_timer))
    };

    match apt_verdict(apt) {
        Verdict::Active => with_evidence(builder(Severity::Info, Confidence::correlated(90)))
            .explanation(
                "Security updates are installed without anyone asking: `unattended-upgrade` is \
                 installed, apt's daily jobs are on, and the two timers that run them are \
                 enabled. What it may install is set by `Unattended-Upgrade::Allowed-Origins` \
                 and `Origins-Pattern` in `/etc/apt/apt.conf.d/50unattended-upgrades`, by \
                 default the security archive only. This shows that the mechanism is set up, \
                 not that its last run worked: `/var/log/unattended-upgrades/` says what it \
                 did.",
            )
            .build(),
        Verdict::Unclear(reasons) => unclear_finding(
            with_evidence(builder(Severity::Info, Confidence::direct_observation())),
            &reasons,
        ),
        Verdict::Gaps(problems) => {
            let sentences: Vec<String> = problems.iter().map(AptProblem::sentence).collect();
            with_evidence(builder(
                Severity::Warning,
                Confidence::strong_indication(80),
            ))
            .explanation(format!(
                "Security updates are not installed automatically, so a fixed vulnerability \
                     stays open until someone installs the update by hand. {} {OTHER_WAYS}",
                sentence(&sentences)
            ))
            .recommendation(apt_steps(&problems).build())
            .build()
        }
    }
}

fn apt_steps(problems: &[AptProblem]) -> Steps {
    let any = |test: fn(&AptProblem) -> bool| problems.iter().any(test);
    let settings = any(|p| {
        matches!(
            p,
            AptProblem::UnattendedUpgradeOff
                | AptProblem::UnattendedUpgradeInvalid(_)
                | AptProblem::PackageListsOff
                | AptProblem::PackageListsInvalid(_)
        )
    });
    let mut steps = Steps::new();
    if any(|p| *p == AptProblem::NotInstalled) {
        steps = steps.step(
            "Install the package that does it:",
            &["sudo apt install unattended-upgrades"],
        );
    }
    if any(|p| *p == AptProblem::JobsOff) {
        steps = steps.step(
            "Find the file that turns every daily job of apt off, and delete its \
             `APT::Periodic::Enable` line or set it to 1:",
            &["grep -rn -i 'periodic::enable' /etc/apt/apt.conf.d/"],
        );
    }
    if settings {
        steps = steps.step(
            "Turn on the daily refresh of the package lists and the daily run of \
             `unattended-upgrade`:",
            &["printf 'APT::Periodic::Update-Package-Lists \"1\";\\nAPT::Periodic::Unattended-Upgrade \"1\";\\n' | sudo tee /etc/apt/apt.conf.d/20auto-upgrades"],
        );
    }
    if any(|p| *p == AptProblem::NoOrigins) {
        steps = steps
            .step(
                "Allow the security archive of your release in \
                 `/etc/apt/apt.conf.d/50unattended-upgrades`: uncomment its line in \
                 `Unattended-Upgrade::Allowed-Origins` (Ubuntu) or \
                 `Unattended-Upgrade::Origins-Pattern` (Debian).",
                &[],
            )
            .step(
                "If that file is missing, put back the one the package ships:",
                &["sudo apt install --reinstall -o Dpkg::Options::=--force-confmiss unattended-upgrades"],
            );
    }
    let timers: Vec<&'static str> = problems
        .iter()
        .filter_map(|p| match p {
            AptProblem::TimerNotEnabled { unit, .. } => Some(*unit),
            _ => None,
        })
        .collect();
    if !timers.is_empty() {
        let masked: Vec<&'static str> = problems
            .iter()
            .filter_map(|p| match p {
                AptProblem::TimerNotEnabled {
                    unit,
                    state: UnitState::Masked,
                    ..
                } => Some(*unit),
                _ => None,
            })
            .collect();
        let mut commands = Vec::new();
        if !masked.is_empty() {
            commands.push(format!("sudo systemctl unmask {}", masked.join(" ")));
        }
        commands.push(format!("sudo systemctl enable --now {}", timers.join(" ")));
        steps = steps.step_owned("Enable the timers that run the daily jobs:", commands);
    }
    if settings || any(|p| *p == AptProblem::JobsOff) {
        steps = steps.step(
            "Check that apt sees the settings (a file with a higher number in its name \
             overrides the others):",
            &["apt-config dump | grep -i -E 'periodic::(enable|update-package-lists|unattended-upgrade)'"],
        );
    }
    steps.step(
        "Check what it would install now, without installing anything, and when the timers \
         run next:",
        &[
            "sudo unattended-upgrade --dry-run --debug",
            "systemctl list-timers 'apt-daily*'",
        ],
    )
}

// ----- dnf ------------------------------------------------------------------

/// `true` or `false` as dnf reads a boolean: `1`, `yes`, `true` and `enabled`
/// are true and `0`, `no`, `false` and `disabled` are false, in any case. Any
/// other word is not a boolean, and dnf refuses it.
fn dnf_boolean(value: &str) -> Option<bool> {
    match value.to_ascii_lowercase().as_str() {
        "1" | "yes" | "true" | "enabled" => Some(true),
        "0" | "no" | "false" | "disabled" => Some(false),
        _ => None,
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum DnfProblem {
    NotInstalled,
    /// No timer of dnf-automatic is enabled.
    NoTimer,
    /// The timer that follows the configuration file is enabled, and the file
    /// does not say to install: `apply_updates` is off, or not set.
    ApplyUpdatesOff(Option<String>),
    /// ... and says something that is not a boolean.
    ApplyUpdatesInvalid(String),
    /// A timer that never installs is the one that is enabled.
    TimerDoesNotInstall {
        unit: &'static str,
        does: &'static str,
    },
}

impl DnfProblem {
    fn sentence(&self, timer_name: &str) -> String {
        match self {
            DnfProblem::NotInstalled => {
                "dnf-automatic is not installed, so nothing installs updates on its own.".into()
            }
            DnfProblem::NoTimer => {
                "No timer of dnf-automatic is enabled, so it never runs.".to_string()
            }
            DnfProblem::ApplyUpdatesOff(None) => format!(
                "`{timer_name}` is enabled, but `apply_updates` is not set in \
                 `/etc/dnf/automatic.conf` and its default is off, so it downloads or reports \
                 the updates and installs none."
            ),
            DnfProblem::ApplyUpdatesOff(Some(value)) => format!(
                "`{timer_name}` is enabled, but `apply_updates` is `{value}` in \
                 `/etc/dnf/automatic.conf`, so it downloads or reports the updates and installs \
                 none."
            ),
            DnfProblem::ApplyUpdatesInvalid(value) => format!(
                "`apply_updates` is `{value}` in `/etc/dnf/automatic.conf`, which dnf does not \
                 read as a yes or a no."
            ),
            DnfProblem::TimerDoesNotInstall { unit, does } => {
                format!("`{unit}` is enabled, but it only {does}; it never installs.")
            }
        }
    }
}

/// The timers that never install, with what they do instead (dnf 4).
const DNF4_NOT_INSTALLING: [(&str, &str); 2] = [
    (DNF4_DOWNLOAD_TIMER, "downloads the updates"),
    (DNF4_NOTIFY_TIMER, "tells you that updates exist"),
];

fn timer_state<'a>(timers: &'a [Timer], unit: &str) -> &'a UnitState {
    timers
        .iter()
        .find(|t| t.unit == unit)
        .map_or(&UnitState::NotFound, |t| &t.state)
}

/// The timer that follows the configuration file.
fn config_timer(version: DnfVersion) -> &'static str {
    match version {
        DnfVersion::Dnf4 => DNF4_CONFIG_TIMER,
        DnfVersion::Dnf5 => DNF5_TIMER,
    }
}

/// dnf-automatic installs updates when the timer that installs whatever the
/// configuration says (dnf 4 only) is enabled, or the timer that follows the
/// configuration is enabled and `apply_updates` is on.
fn dnf_verdict(dnf: &DnfSetup) -> Verdict<DnfProblem> {
    if !dnf.installed {
        return Verdict::Gaps(vec![DnfProblem::NotInstalled]);
    }
    let follows_config = timer_state(&dnf.timers, config_timer(dnf.version));
    let installs_always = timer_state(&dnf.timers, DNF4_INSTALL_TIMER);
    let apply_text = dnf.config.apply_updates.as_deref();
    let applies = apply_text.and_then(dnf_boolean);

    if *installs_always == UnitState::Enabled
        || (*follows_config == UnitState::Enabled && applies == Some(true))
    {
        return Verdict::Active;
    }
    // Not installing: unless a timer that could install could not be read.
    let unreadable: Vec<String> = [
        (DNF4_INSTALL_TIMER, installs_always),
        (config_timer(dnf.version), follows_config),
    ]
    .into_iter()
    .filter(|(_, state)| **state == UnitState::Unknown)
    .map(|(unit, _)| format!("systemd did not say whether `{unit}` is enabled."))
    .collect();
    if !unreadable.is_empty() {
        return Verdict::Unclear(unreadable);
    }

    if *follows_config == UnitState::Enabled {
        return Verdict::Gaps(vec![match (apply_text, applies) {
            (Some(text), None) => DnfProblem::ApplyUpdatesInvalid(text.to_string()),
            _ => DnfProblem::ApplyUpdatesOff(apply_text.map(str::to_string)),
        }]);
    }
    // dnf 5 has no such timer: none is read for it, so none is ever enabled.
    let not_installing: Vec<DnfProblem> = DNF4_NOT_INSTALLING
        .iter()
        .filter(|(unit, _)| *timer_state(&dnf.timers, unit) == UnitState::Enabled)
        .map(|&(unit, does)| DnfProblem::TimerDoesNotInstall { unit, does })
        .collect();
    if not_installing.is_empty() {
        Verdict::Gaps(vec![DnfProblem::NoTimer])
    } else {
        Verdict::Gaps(not_installing)
    }
}

fn dnf_finding(dnf: &DnfSetup) -> Finding {
    let with_evidence = |builder: crate::models::finding::FindingBuilder| {
        let mut builder = builder
            .evidence("package_manager", "dnf")
            .evidence(
                "dnf_version",
                match dnf.version {
                    DnfVersion::Dnf4 => "4",
                    DnfVersion::Dnf5 => "5",
                },
            )
            .evidence(
                "dnf_automatic_installed",
                if dnf.installed { "yes" } else { "no" },
            );
        if dnf.installed {
            builder = builder
                .evidence(
                    "apply_updates",
                    dnf.config.apply_updates.as_deref().unwrap_or("not set"),
                )
                .evidence(
                    "upgrade_type",
                    dnf.config.upgrade_type.as_deref().unwrap_or("not set"),
                );
        }
        for timer in &dnf.timers {
            builder = builder.evidence(timer.unit, state_word(&timer.state));
        }
        builder
    };

    match dnf_verdict(dnf) {
        Verdict::Active => with_evidence(builder(Severity::Info, Confidence::correlated(90)))
            .explanation(active_dnf_text(dnf))
            .build(),
        Verdict::Unclear(reasons) => unclear_finding(
            with_evidence(builder(Severity::Info, Confidence::direct_observation())),
            &reasons,
        ),
        Verdict::Gaps(problems) => {
            let timer_name = config_timer(dnf.version);
            let sentences: Vec<String> = problems.iter().map(|p| p.sentence(timer_name)).collect();
            with_evidence(builder(
                Severity::Warning,
                Confidence::strong_indication(80),
            ))
            .explanation(format!(
                "Security updates are not installed automatically, so a fixed vulnerability \
                     stays open until someone installs the update by hand. {} {OTHER_WAYS}",
                sentence(&sentences)
            ))
            .recommendation(dnf_steps(dnf, &problems).build())
            .build()
        }
    }
}

/// Which updates dnf-automatic installs, from `upgrade_type`.
fn dnf_scope(config: &DnfConfig) -> &'static str {
    match config.upgrade_type.as_deref() {
        Some("security") => "`upgrade_type` is `security`: it installs the security updates only.",
        Some("distro-sync") => {
            "`upgrade_type` is `distro-sync`: it brings every package to the latest version \
             the repositories offer, security fixes included."
        }
        _ => {
            "`upgrade_type` is `default`: it installs every update, security fixes included. \
             Set it to `security` in the `[commands]` section of `/etc/dnf/automatic.conf` to \
             limit it to those."
        }
    }
}

fn active_dnf_text(dnf: &DnfSetup) -> String {
    let how = if *timer_state(&dnf.timers, DNF4_INSTALL_TIMER) == UnitState::Enabled {
        format!(
            "`{DNF4_INSTALL_TIMER}` is enabled, and installs the updates whatever \
             `apply_updates` says."
        )
    } else {
        format!(
            "`{}` is enabled and `apply_updates` is on.",
            config_timer(dnf.version)
        )
    };
    format!(
        "Updates are installed without anyone asking: {how} {} This shows that the mechanism \
         is set up, not that its last run worked: `journalctl -u 'dnf*automatic*'` says what \
         it did.",
        dnf_scope(&dnf.config)
    )
}

fn dnf_steps(dnf: &DnfSetup, problems: &[DnfProblem]) -> Steps {
    let timer = config_timer(dnf.version);
    let mut steps = Steps::new();
    let package = match dnf.version {
        DnfVersion::Dnf4 => "dnf-automatic",
        DnfVersion::Dnf5 => "dnf5-plugin-automatic",
    };
    if problems.contains(&DnfProblem::NotInstalled) {
        steps = steps.step_owned(
            "Install the package that does it:",
            vec![format!("sudo dnf install {package}")],
        );
    }
    let apply_problem = problems.iter().any(|p| {
        matches!(
            p,
            DnfProblem::ApplyUpdatesOff(_) | DnfProblem::ApplyUpdatesInvalid(_)
        )
    });
    // dnf 5 has no timer that installs by itself: the file has to say so.
    let needs_apply = apply_problem
        || (dnf.version == DnfVersion::Dnf5
            && problems
                .iter()
                .any(|p| matches!(p, DnfProblem::NoTimer | DnfProblem::NotInstalled)));
    if needs_apply {
        steps = steps.step(
            "In the `[commands]` section of `/etc/dnf/automatic.conf`, set `apply_updates = \
                 yes` (and `upgrade_type = security` to install the security updates only; \
                 without it every update is installed):",
            &["grep -E '^(apply_updates|upgrade_type)' /etc/dnf/automatic.conf"],
        );
    }
    for problem in problems {
        if let DnfProblem::TimerDoesNotInstall { unit, .. } = problem {
            steps = steps.step_owned(
                format!("Turn off `{unit}`, which never installs:"),
                vec![format!("sudo systemctl disable --now {unit}")],
            );
        }
    }
    let timer_needed = problems.iter().any(|p| {
        matches!(
            p,
            DnfProblem::NoTimer | DnfProblem::NotInstalled | DnfProblem::TimerDoesNotInstall { .. }
        )
    });
    if timer_needed {
        // With dnf 4 the timer that installs whatever the file says does not
        // depend on `apply_updates`; dnf 5 has only the one that follows it.
        let unit = match dnf.version {
            DnfVersion::Dnf4 => DNF4_INSTALL_TIMER,
            DnfVersion::Dnf5 => timer,
        };
        steps = steps.step_owned(
            "Enable the timer that installs the updates:",
            vec![format!("sudo systemctl enable --now {unit}")],
        );
    }
    steps.step(
        "Check when it runs next:",
        &["systemctl list-timers 'dnf*automatic*'"],
    )
}

// ----- other systems ---------------------------------------------------------

fn unsupported_finding(distro: Option<&str>) -> Finding {
    let system = distro.map_or("this system".to_string(), |name| {
        format!("`{}`", clean(name, MAX_DISTRO))
    });
    builder(Severity::Info, Confidence::direct_observation())
        .evidence("package_manager", "unsupported")
        .explanation(format!(
            "Whether security updates are installed automatically was not checked: {system} is \
             neither Debian-like (apt, `unattended-upgrades`) nor Red Hat-like (dnf, \
             `dnf-automatic`), the two mechanisms this check knows. That is not the same as \
             the updates being installed."
        ))
        .build()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn periodic(
        enable: Option<&str>,
        lists: Option<&str>,
        upgrade: Option<&str>,
        origins: usize,
    ) -> AptPeriodic {
        AptPeriodic {
            enable: enable.map(str::to_string),
            update_lists: lists.map(str::to_string),
            unattended: upgrade.map(str::to_string),
            origins,
        }
    }

    /// A machine set up the way `dpkg-reconfigure unattended-upgrades` leaves
    /// it.
    fn working_apt() -> AptSetup {
        AptSetup {
            installed: true,
            periodic: Some(periodic(None, Some("1"), Some("1"), 3)),
            update_timer: UnitState::Enabled,
            upgrade_timer: UnitState::Enabled,
        }
    }

    fn problems(apt: &AptSetup) -> Vec<AptProblem> {
        match apt_verdict(apt) {
            Verdict::Gaps(problems) => problems,
            Verdict::Active => panic!("active"),
            Verdict::Unclear(reasons) => panic!("unclear: {reasons:?}"),
        }
    }

    fn evidence<'a>(finding: &'a Finding, key: &str) -> Option<&'a str> {
        finding
            .evidence
            .iter()
            .find(|(k, _)| k == key)
            .map(|(_, v)| v.as_str())
    }

    // ----- intervals ---------------------------------------------------------

    #[test]
    fn an_interval_is_read_the_way_the_apt_script_reads_it() {
        for (value, expected) in [
            (None, Interval::Off),
            (Some(""), Interval::Off),
            (Some("0"), Interval::Off),
            (Some("1"), Interval::On),
            (Some("7"), Interval::On),
            (Some("always"), Interval::On),
            (Some("1d"), Interval::On),
            (Some("12h"), Interval::On),
            (Some("30m"), Interval::On),
            (Some("3600s"), Interval::On),
            // The script compares with the text "0": these run every time.
            (Some("00"), Interval::On),
            (Some("0d"), Interval::On),
            (Some("d"), Interval::Invalid),
            (Some("1w"), Interval::Invalid),
            (Some("-1"), Interval::Invalid),
            (Some("1.5"), Interval::Invalid),
            (Some("1 d"), Interval::Invalid),
            (Some("yes"), Interval::Invalid),
            (Some("Always"), Interval::Invalid),
            (Some("1dd"), Interval::Invalid),
        ] {
            assert_eq!(interval(value), expected, "{value:?}");
        }
    }

    #[test]
    fn the_enable_switch_is_a_number_and_only_zero_turns_the_jobs_off() {
        assert!(jobs_off(Some("0")));
        assert!(jobs_off(Some(" 0 ")));
        assert!(jobs_off(Some("00")));
        assert!(jobs_off(Some("+0")));
        assert!(!jobs_off(Some("1")));
        assert!(!jobs_off(Some("2")));
        assert!(!jobs_off(Some("-1")));
        // The script's own test fails on a word and goes on: so does this.
        assert!(!jobs_off(Some("false")));
        assert!(!jobs_off(Some("")));
        assert!(!jobs_off(None));
    }

    // ----- apt: what is wrong ---------------------------------------------------

    #[test]
    fn a_machine_set_up_by_the_package_has_nothing_wrong() {
        assert!(matches!(apt_verdict(&working_apt()), Verdict::Active));
    }

    #[test]
    fn each_thing_that_stops_apt_is_a_problem_of_its_own() {
        let mut apt = working_apt();
        apt.installed = false;
        assert_eq!(problems(&apt), [AptProblem::NotInstalled]);

        let mut apt = working_apt();
        apt.periodic = Some(periodic(Some("0"), Some("1"), Some("1"), 3));
        assert_eq!(problems(&apt), [AptProblem::JobsOff]);

        let mut apt = working_apt();
        apt.periodic = Some(periodic(None, Some("1"), None, 3));
        assert_eq!(problems(&apt), [AptProblem::UnattendedUpgradeOff]);

        let mut apt = working_apt();
        apt.periodic = Some(periodic(None, Some("1"), Some("0"), 3));
        assert_eq!(problems(&apt), [AptProblem::UnattendedUpgradeOff]);

        let mut apt = working_apt();
        apt.periodic = Some(periodic(None, Some("1"), Some("weekly"), 3));
        assert_eq!(
            problems(&apt),
            [AptProblem::UnattendedUpgradeInvalid("weekly".into())]
        );

        let mut apt = working_apt();
        apt.periodic = Some(periodic(None, None, Some("1"), 3));
        assert_eq!(problems(&apt), [AptProblem::PackageListsOff]);

        let mut apt = working_apt();
        apt.periodic = Some(periodic(None, Some("often"), Some("1"), 3));
        assert_eq!(
            problems(&apt),
            [AptProblem::PackageListsInvalid("often".into())]
        );

        let mut apt = working_apt();
        apt.periodic = Some(periodic(None, Some("1"), Some("1"), 0));
        assert_eq!(problems(&apt), [AptProblem::NoOrigins]);

        let mut apt = working_apt();
        apt.update_timer = UnitState::Disabled;
        assert_eq!(
            problems(&apt),
            [AptProblem::TimerNotEnabled {
                unit: APT_UPDATE_TIMER,
                what: "refreshes the package lists",
                state: UnitState::Disabled
            }]
        );

        let mut apt = working_apt();
        apt.upgrade_timer = UnitState::Masked;
        assert_eq!(
            problems(&apt),
            [AptProblem::TimerNotEnabled {
                unit: APT_UPGRADE_TIMER,
                what: "runs `unattended-upgrade`",
                state: UnitState::Masked
            }]
        );
    }

    #[test]
    fn no_origin_is_not_a_second_fault_before_the_package_is_installed() {
        let mut apt = working_apt();
        apt.installed = false;
        apt.periodic = Some(periodic(None, Some("1"), Some("1"), 0));
        assert_eq!(problems(&apt), [AptProblem::NotInstalled]);
        let steps = apt_steps(&problems(&apt)).build();
        assert!(!steps.contains("50unattended-upgrades"), "{steps}");
    }

    #[test]
    fn one_origin_is_enough_and_a_daily_interval_with_a_suffix_works() {
        let mut apt = working_apt();
        apt.periodic = Some(periodic(Some("1"), Some("1d"), Some("always"), 1));
        assert!(matches!(apt_verdict(&apt), Verdict::Active));
    }

    #[test]
    fn several_problems_are_all_reported_in_the_order_of_the_checks() {
        let mut apt = AptSetup {
            installed: true,
            periodic: Some(periodic(Some("0"), None, None, 0)),
            update_timer: UnitState::Disabled,
            upgrade_timer: UnitState::NotFound,
        };
        let kinds = |apt: &AptSetup| -> Vec<&'static str> {
            problems(apt)
                .iter()
                .map(|p| match p {
                    AptProblem::NotInstalled => "not installed",
                    AptProblem::JobsOff => "jobs off",
                    AptProblem::UnattendedUpgradeOff => "unattended off",
                    AptProblem::PackageListsOff => "lists off",
                    AptProblem::NoOrigins => "no origins",
                    AptProblem::TimerNotEnabled { unit, .. } => unit,
                    other => panic!("{other:?}"),
                })
                .collect()
        };
        assert_eq!(
            kinds(&apt),
            [
                "jobs off",
                "unattended off",
                "lists off",
                "no origins",
                APT_UPDATE_TIMER,
                APT_UPGRADE_TIMER
            ]
        );
        apt.installed = false;
        assert_eq!(
            kinds(&apt),
            [
                "not installed",
                "jobs off",
                "unattended off",
                "lists off",
                APT_UPDATE_TIMER,
                APT_UPGRADE_TIMER
            ],
            "no origins is not reported before the package that has the list"
        );
    }

    #[test]
    fn a_timer_that_is_not_enabled_is_a_problem_whatever_it_says_instead() {
        for state in [
            UnitState::Disabled,
            UnitState::Masked,
            UnitState::NotFound,
            UnitState::Other("static".into()),
        ] {
            let mut apt = working_apt();
            apt.upgrade_timer = state.clone();
            assert_eq!(problems(&apt).len(), 1, "{state:?}");
        }
    }

    #[test]
    fn what_could_not_be_read_is_unclear_unless_something_else_is_wrong() {
        let mut apt = working_apt();
        apt.periodic = None;
        let Verdict::Unclear(reasons) = apt_verdict(&apt) else {
            panic!("expected unclear");
        };
        assert_eq!(reasons.len(), 1);
        assert!(reasons[0].contains("apt-config dump"), "{reasons:?}");

        let mut apt = working_apt();
        apt.update_timer = UnitState::Unknown;
        apt.upgrade_timer = UnitState::Unknown;
        let Verdict::Unclear(reasons) = apt_verdict(&apt) else {
            panic!("expected unclear");
        };
        assert_eq!(reasons.len(), 2);
        assert!(reasons[0].contains(APT_UPDATE_TIMER), "{reasons:?}");
        assert!(reasons[1].contains(APT_UPGRADE_TIMER), "{reasons:?}");

        // A fault that was seen is reported even if another reading failed.
        let mut apt = working_apt();
        apt.periodic = None;
        apt.installed = false;
        assert_eq!(problems(&apt), [AptProblem::NotInstalled]);
        let mut apt = working_apt();
        apt.update_timer = UnitState::Unknown;
        apt.upgrade_timer = UnitState::Disabled;
        assert_eq!(problems(&apt).len(), 1);
    }

    // ----- apt: the finding --------------------------------------------------------

    #[test]
    fn a_working_apt_setup_is_information_with_its_evidence() {
        let f = apt_finding(&working_apt());
        assert_eq!(f.id, "SRV001");
        assert_eq!(f.title, "Automatic Security Updates");
        assert_eq!(f.category, Category::Security);
        assert_eq!(f.severity, Severity::Info);
        assert_eq!(f.confidence.percent, 90);
        assert!(f.recommendation.is_none());
        assert!(f.explanation.contains("installed without anyone asking"));
        assert!(f.explanation.contains("not that its last run worked"));
        assert_eq!(evidence(&f, "package_manager"), Some("apt"));
        assert_eq!(evidence(&f, "unattended_upgrade_installed"), Some("yes"));
        assert_eq!(evidence(&f, "update_package_lists"), Some("1"));
        assert_eq!(evidence(&f, "unattended_upgrade_interval"), Some("1"));
        assert_eq!(evidence(&f, "allowed_origins"), Some("3"));
        assert_eq!(evidence(&f, "periodic_enable"), None, "not set, not shown");
        assert_eq!(evidence(&f, APT_UPDATE_TIMER), Some("enabled"));
        assert_eq!(evidence(&f, APT_UPGRADE_TIMER), Some("enabled"));
    }

    #[test]
    fn the_evidence_shows_what_is_set_and_what_is_not() {
        let mut apt = working_apt();
        apt.installed = false;
        apt.periodic = Some(periodic(Some("0"), None, None, 0));
        apt.update_timer = UnitState::Masked;
        apt.upgrade_timer = UnitState::Other("static".into());
        let f = apt_finding(&apt);
        assert_eq!(evidence(&f, "unattended_upgrade_installed"), Some("no"));
        assert_eq!(evidence(&f, "periodic_enable"), Some("0"));
        assert_eq!(evidence(&f, "update_package_lists"), Some("not set"));
        assert_eq!(evidence(&f, "unattended_upgrade_interval"), Some("not set"));
        assert_eq!(evidence(&f, "allowed_origins"), Some("0"));
        assert_eq!(evidence(&f, APT_UPDATE_TIMER), Some("masked"));
        assert_eq!(evidence(&f, APT_UPGRADE_TIMER), Some("static"));

        apt.update_timer = UnitState::NotFound;
        apt.upgrade_timer = UnitState::Disabled;
        let f = apt_finding(&apt);
        assert_eq!(evidence(&f, APT_UPDATE_TIMER), Some("not-found"));
        assert_eq!(evidence(&f, APT_UPGRADE_TIMER), Some("disabled"));
    }

    #[test]
    fn several_problems_are_several_sentences_in_one_explanation() {
        let mut apt = working_apt();
        apt.periodic = Some(periodic(None, Some("1"), Some("0"), 3));
        apt.update_timer = Disabled;
        let sentences: Vec<String> = problems(&apt).iter().map(AptProblem::sentence).collect();
        assert_eq!(sentences.len(), 2);
        let f = apt_finding(&apt);
        assert!(
            f.explanation
                .contains(&format!("{} {}", sentences[0], sentences[1])),
            "{}",
            f.explanation
        );

        // The reasons a verdict is unclear are joined the same way.
        let mut apt = working_apt();
        apt.update_timer = Unknown;
        apt.upgrade_timer = Unknown;
        let f = apt_finding(&apt);
        assert!(
            f.explanation.contains(&format!(
                "whether `{APT_UPDATE_TIMER}` is enabled. systemd did not say whether `{APT_UPGRADE_TIMER}`"
            )),
            "{}",
            f.explanation
        );

        let d = dnf4(Some("yes"), Unknown, Unknown, Disabled, Disabled);
        let f = dnf_finding(&d);
        assert!(
            f.explanation.contains(&format!(
                "whether `{DNF4_INSTALL_TIMER}` is enabled. systemd did not say whether `{DNF4_CONFIG_TIMER}`"
            )),
            "{}",
            f.explanation
        );
    }

    #[test]
    fn a_broken_apt_setup_is_a_warning_that_says_what_and_how_to_fix_it() {
        let mut apt = working_apt();
        apt.periodic = Some(periodic(None, Some("1"), Some("0"), 3));
        let f = apt_finding(&apt);
        assert_eq!(f.severity, Severity::Warning);
        assert_eq!(f.confidence.percent, 80);
        assert!(f.explanation.contains("not installed automatically"));
        assert!(f
            .explanation
            .contains("`APT::Periodic::Unattended-Upgrade` is not set"));
        assert!(
            f.explanation.contains("patched another way"),
            "{}",
            f.explanation
        );
        let steps = f.recommendation.unwrap();
        assert!(steps.contains("20auto-upgrades"), "{steps}");
        assert!(steps.contains("unattended-upgrade --dry-run"), "{steps}");
        assert!(!steps.contains("apt install"), "{steps}");
        assert!(!steps.contains("systemctl enable"), "{steps}");
    }

    #[test]
    fn the_steps_follow_the_problems_and_only_them() {
        let timers_only = {
            let mut apt = working_apt();
            apt.update_timer = UnitState::Disabled;
            apt.upgrade_timer = UnitState::Masked;
            apt_steps(&problems(&apt)).build()
        };
        assert!(
            timers_only.contains(
                "    sudo systemctl unmask apt-daily-upgrade.timer\n    sudo systemctl enable --now apt-daily.timer apt-daily-upgrade.timer"
            ),
            "{timers_only}"
        );
        assert!(!timers_only.contains("20auto-upgrades"), "{timers_only}");
        assert!(!timers_only.contains("apt-config dump"), "{timers_only}");
        assert!(!timers_only.contains("apt install"), "{timers_only}");

        let both_masked = {
            let mut apt = working_apt();
            apt.update_timer = UnitState::Masked;
            apt.upgrade_timer = UnitState::Masked;
            apt_steps(&problems(&apt)).build()
        };
        assert!(
            both_masked.contains(
                "    sudo systemctl unmask apt-daily.timer apt-daily-upgrade.timer\n    sudo systemctl enable --now apt-daily.timer apt-daily-upgrade.timer"
            ),
            "{both_masked}"
        );

        let not_masked = {
            let mut apt = working_apt();
            apt.update_timer = UnitState::Disabled;
            apt_steps(&problems(&apt)).build()
        };
        assert!(!not_masked.contains("unmask"), "{not_masked}");
        assert!(
            not_masked.contains("    sudo systemctl enable --now apt-daily.timer\n"),
            "{not_masked}"
        );
        assert!(
            !not_masked.contains("apt-daily-upgrade.timer"),
            "{not_masked}"
        );

        let missing = {
            let mut apt = working_apt();
            apt.installed = false;
            apt_steps(&problems(&apt)).build()
        };
        assert!(
            missing.starts_with(
                "1. Install the package that does it:\n    sudo apt install unattended-upgrades"
            ),
            "{missing}"
        );

        let off = {
            let mut apt = working_apt();
            apt.periodic = Some(periodic(Some("0"), Some("1"), Some("1"), 3));
            apt_steps(&problems(&apt)).build()
        };
        assert!(
            off.contains("\n    grep -rn -i 'periodic::enable' /etc/apt/apt.conf.d/\n"),
            "{off}"
        );
        assert!(off.contains("apt-config dump | grep -i -E"), "{off}");
        assert!(!off.contains("20auto-upgrades"), "{off}");

        let origins = {
            let mut apt = working_apt();
            apt.periodic = Some(periodic(None, Some("1"), Some("1"), 0));
            apt_steps(&problems(&apt)).build()
        };
        assert!(origins.contains("50unattended-upgrades"), "{origins}");
        assert!(origins.contains("--force-confmiss"), "{origins}");
        assert!(!origins.contains("apt-config dump"), "{origins}");

        for (i, text) in [&timers_only, &missing, &off, &origins].iter().enumerate() {
            assert!(
                text.trim_end()
                    .ends_with("systemctl list-timers 'apt-daily*'"),
                "{i}: {text}"
            );
        }
    }

    #[test]
    fn the_settings_step_is_given_for_every_kind_of_wrong_interval() {
        for periodic in [
            periodic(None, Some("1"), None, 3),
            periodic(None, Some("1"), Some("x"), 3),
            periodic(None, None, Some("1"), 3),
            periodic(None, Some("x"), Some("1"), 3),
        ] {
            let mut apt = working_apt();
            apt.periodic = Some(periodic);
            let text = apt_steps(&problems(&apt)).build();
            assert!(text.contains("20auto-upgrades"), "{text}");
            assert!(text.contains("apt-config dump | grep"), "{text}");
        }
    }

    #[test]
    fn what_could_not_be_read_is_information_not_a_warning() {
        let mut apt = working_apt();
        apt.periodic = None;
        apt.upgrade_timer = UnitState::Unknown;
        let f = apt_finding(&apt);
        assert_eq!(f.severity, Severity::Info);
        assert_eq!(f.confidence.percent, 100);
        assert!(f.recommendation.is_none());
        assert!(
            f.explanation.contains("could not be told"),
            "{}",
            f.explanation
        );
        assert!(
            f.explanation.contains("apt-config dump"),
            "{}",
            f.explanation
        );
        assert!(
            f.explanation.contains(APT_UPGRADE_TIMER),
            "{}",
            f.explanation
        );
        assert!(
            f.explanation.contains("Nothing wrong was found"),
            "{}",
            f.explanation
        );
        assert_eq!(
            evidence(&f, "update_package_lists"),
            None,
            "nothing was read"
        );
        assert_eq!(evidence(&f, APT_UPGRADE_TIMER), Some("unknown"));
    }

    #[test]
    fn every_problem_has_its_own_sentence() {
        let all = [
            AptProblem::NotInstalled,
            AptProblem::JobsOff,
            AptProblem::UnattendedUpgradeOff,
            AptProblem::UnattendedUpgradeInvalid("w".into()),
            AptProblem::PackageListsOff,
            AptProblem::PackageListsInvalid("w".into()),
            AptProblem::NoOrigins,
            AptProblem::TimerNotEnabled {
                unit: "x.timer",
                what: "does it",
                state: UnitState::Other("static".into()),
            },
        ];
        let sentences: Vec<String> = all.iter().map(AptProblem::sentence).collect();
        for (i, a) in sentences.iter().enumerate() {
            assert!(a.ends_with('.'), "{a}");
            for b in &sentences[i + 1..] {
                assert_ne!(a, b);
            }
        }
        assert!(sentences[3].contains("`w`"));
        assert!(sentences[5].contains("`w`"));
        assert_eq!(
            sentences[7],
            "`x.timer`, which does it, is `static`, not enabled."
        );
        for (state, word) in [
            (UnitState::Disabled, "disabled"),
            (UnitState::Masked, "masked"),
            (UnitState::NotFound, "missing"),
        ] {
            let s = AptProblem::TimerNotEnabled {
                unit: "x.timer",
                what: "does it",
                state,
            }
            .sentence();
            assert_eq!(s, format!("`x.timer`, which does it, is {word}."));
        }
    }

    // ----- dnf -----------------------------------------------------------------------

    fn timer(unit: &'static str, state: UnitState) -> Timer {
        Timer { unit, state }
    }

    fn dnf4(
        apply: Option<&str>,
        install: UnitState,
        config: UnitState,
        download: UnitState,
        notify: UnitState,
    ) -> DnfSetup {
        DnfSetup {
            version: DnfVersion::Dnf4,
            installed: true,
            config: DnfConfig {
                apply_updates: apply.map(str::to_string),
                upgrade_type: None,
            },
            timers: vec![
                timer(DNF4_INSTALL_TIMER, install),
                timer(DNF4_CONFIG_TIMER, config),
                timer(DNF4_DOWNLOAD_TIMER, download),
                timer(DNF4_NOTIFY_TIMER, notify),
            ],
        }
    }

    fn dnf5(apply: Option<&str>, state: UnitState) -> DnfSetup {
        DnfSetup {
            version: DnfVersion::Dnf5,
            installed: true,
            config: DnfConfig {
                apply_updates: apply.map(str::to_string),
                upgrade_type: None,
            },
            timers: vec![timer(DNF5_TIMER, state)],
        }
    }

    fn dnf_problems(dnf: &DnfSetup) -> Vec<DnfProblem> {
        match dnf_verdict(dnf) {
            Verdict::Gaps(problems) => problems,
            Verdict::Active => panic!("active"),
            Verdict::Unclear(reasons) => panic!("unclear: {reasons:?}"),
        }
    }

    use UnitState::{Disabled, Enabled, Masked, Unknown};

    #[test]
    fn dnf_booleans_are_read_the_way_dnf_reads_them() {
        for word in ["1", "yes", "true", "enabled", "YES", "True", "Enabled"] {
            assert_eq!(dnf_boolean(word), Some(true), "{word}");
        }
        for word in ["0", "no", "false", "disabled", "NO", "False", "DISABLED"] {
            assert_eq!(dnf_boolean(word), Some(false), "{word}");
        }
        for word in ["", "2", "y", "on", "off", "yes please", "-1"] {
            assert_eq!(dnf_boolean(word), None, "{word}");
        }
    }

    #[test]
    fn dnf4_installs_with_either_timer_that_does() {
        // The timer that installs whatever the file says.
        let d = dnf4(None, Enabled, Disabled, Disabled, Disabled);
        assert!(matches!(dnf_verdict(&d), Verdict::Active));
        let d = dnf4(Some("no"), Enabled, Disabled, Disabled, Disabled);
        assert!(matches!(dnf_verdict(&d), Verdict::Active));
        // The one that follows the file, when the file says to install.
        for yes in ["yes", "true", "1", "enabled", "Yes"] {
            let d = dnf4(Some(yes), Disabled, Enabled, Disabled, Disabled);
            assert!(matches!(dnf_verdict(&d), Verdict::Active), "{yes}");
        }
    }

    #[test]
    fn dnf4_that_only_notifies_or_downloads_does_not_install() {
        let d = dnf4(Some("yes"), Disabled, Disabled, Disabled, Enabled);
        assert_eq!(
            dnf_problems(&d),
            [DnfProblem::TimerDoesNotInstall {
                unit: DNF4_NOTIFY_TIMER,
                does: "tells you that updates exist"
            }]
        );
        let d = dnf4(Some("yes"), Disabled, Disabled, Enabled, Disabled);
        assert_eq!(
            dnf_problems(&d),
            [DnfProblem::TimerDoesNotInstall {
                unit: DNF4_DOWNLOAD_TIMER,
                does: "downloads the updates"
            }]
        );
        let d = dnf4(Some("yes"), Disabled, Disabled, Enabled, Enabled);
        assert_eq!(dnf_problems(&d).len(), 2);
    }

    #[test]
    fn dnf4_with_no_timer_does_not_run() {
        for other in [Disabled, Masked, UnitState::NotFound] {
            let d = dnf4(
                Some("yes"),
                other.clone(),
                other.clone(),
                other.clone(),
                other,
            );
            assert_eq!(dnf_problems(&d), [DnfProblem::NoTimer]);
        }
    }

    #[test]
    fn the_timer_that_follows_the_file_needs_the_file_to_say_yes() {
        let d = dnf4(None, Disabled, Enabled, Disabled, Disabled);
        assert_eq!(dnf_problems(&d), [DnfProblem::ApplyUpdatesOff(None)]);
        let d = dnf4(Some("no"), Disabled, Enabled, Disabled, Disabled);
        assert_eq!(
            dnf_problems(&d),
            [DnfProblem::ApplyUpdatesOff(Some("no".into()))]
        );
        let d = dnf4(Some("maybe"), Disabled, Enabled, Disabled, Disabled);
        assert_eq!(
            dnf_problems(&d),
            [DnfProblem::ApplyUpdatesInvalid("maybe".into())]
        );
        let d = dnf4(Some(""), Disabled, Enabled, Disabled, Disabled);
        assert_eq!(
            dnf_problems(&d),
            [DnfProblem::ApplyUpdatesInvalid("".into())]
        );
    }

    #[test]
    fn a_file_that_says_yes_does_nothing_without_the_timer_that_follows_it() {
        let d = dnf4(Some("yes"), Disabled, Masked, Disabled, Disabled);
        assert_eq!(dnf_problems(&d), [DnfProblem::NoTimer]);
    }

    #[test]
    fn dnf5_has_one_timer_which_follows_the_file() {
        assert!(matches!(
            dnf_verdict(&dnf5(Some("yes"), Enabled)),
            Verdict::Active
        ));
        assert_eq!(
            dnf_problems(&dnf5(Some("no"), Enabled)),
            [DnfProblem::ApplyUpdatesOff(Some("no".into()))]
        );
        assert_eq!(
            dnf_problems(&dnf5(None, Enabled)),
            [DnfProblem::ApplyUpdatesOff(None)]
        );
        assert_eq!(
            dnf_problems(&dnf5(Some("yes"), Disabled)),
            [DnfProblem::NoTimer]
        );
    }

    #[test]
    fn dnf_that_is_not_installed_is_the_only_problem() {
        let mut d = dnf4(Some("yes"), Enabled, Enabled, Enabled, Enabled);
        d.installed = false;
        assert_eq!(dnf_problems(&d), [DnfProblem::NotInstalled]);
        let mut d = dnf5(Some("yes"), Enabled);
        d.installed = false;
        d.timers.clear();
        assert_eq!(dnf_problems(&d), [DnfProblem::NotInstalled]);
    }

    #[test]
    fn a_timer_that_could_not_be_read_makes_it_unclear_unless_updates_are_installed() {
        let d = dnf4(Some("yes"), Unknown, Unknown, Unknown, Unknown);
        let Verdict::Unclear(reasons) = dnf_verdict(&d) else {
            panic!("expected unclear");
        };
        assert_eq!(reasons.len(), 2, "{reasons:?}");
        assert!(reasons[0].contains(DNF4_INSTALL_TIMER));
        assert!(reasons[1].contains(DNF4_CONFIG_TIMER));
        // Only the timers that could install count.
        let d = dnf4(Some("yes"), Disabled, Disabled, Unknown, Unknown);
        assert_eq!(dnf_problems(&d), [DnfProblem::NoTimer]);
        let d = dnf4(Some("yes"), Unknown, Disabled, Disabled, Disabled);
        assert!(matches!(dnf_verdict(&d), Verdict::Unclear(_)));
        let d = dnf4(Some("yes"), Disabled, Unknown, Disabled, Disabled);
        assert!(matches!(dnf_verdict(&d), Verdict::Unclear(_)));
        // One that installs settles it, whatever the other says.
        let d = dnf4(None, Enabled, Unknown, Unknown, Unknown);
        assert!(matches!(dnf_verdict(&d), Verdict::Active));
        let d = dnf4(Some("yes"), Unknown, Enabled, Disabled, Disabled);
        assert!(matches!(dnf_verdict(&d), Verdict::Active));
        // dnf 5 has just the one.
        let d = dnf5(Some("yes"), Unknown);
        let Verdict::Unclear(reasons) = dnf_verdict(&d) else {
            panic!("expected unclear");
        };
        assert_eq!(reasons.len(), 1);
        assert!(reasons[0].contains(DNF5_TIMER));
    }

    // ----- dnf: the finding -------------------------------------------------------------

    #[test]
    fn working_dnf_is_information_that_says_what_it_installs() {
        let mut d = dnf4(Some("yes"), Disabled, Enabled, Disabled, Disabled);
        d.config.upgrade_type = Some("security".into());
        let f = dnf_finding(&d);
        assert_eq!(f.id, "SRV001");
        assert_eq!(f.severity, Severity::Info);
        assert_eq!(f.confidence.percent, 90);
        assert!(f.recommendation.is_none());
        assert!(
            f.explanation
                .contains("`dnf-automatic.timer` is enabled and `apply_updates` is on"),
            "{}",
            f.explanation
        );
        assert!(
            f.explanation.contains("the security updates only"),
            "{}",
            f.explanation
        );
        assert_eq!(evidence(&f, "package_manager"), Some("dnf"));
        assert_eq!(evidence(&f, "dnf_version"), Some("4"));
        assert_eq!(evidence(&f, "dnf_automatic_installed"), Some("yes"));
        assert_eq!(evidence(&f, "apply_updates"), Some("yes"));
        assert_eq!(evidence(&f, "upgrade_type"), Some("security"));
        assert_eq!(evidence(&f, DNF4_CONFIG_TIMER), Some("enabled"));
        assert_eq!(evidence(&f, DNF4_INSTALL_TIMER), Some("disabled"));

        let f = dnf_finding(&dnf5(Some("yes"), Enabled));
        assert_eq!(evidence(&f, "dnf_version"), Some("5"));
        assert_eq!(evidence(&f, "upgrade_type"), Some("not set"));
        assert!(
            f.explanation.contains("`dnf5-automatic.timer` is enabled"),
            "{}",
            f.explanation
        );
        assert!(
            f.explanation
                .contains("every update, security fixes included"),
            "{}",
            f.explanation
        );
    }

    #[test]
    fn the_install_timer_is_named_when_it_is_the_one_that_installs() {
        let f = dnf_finding(&dnf4(Some("no"), Enabled, Disabled, Disabled, Disabled));
        assert!(
            f.explanation.contains("`dnf-automatic-install.timer` is enabled, and installs the updates whatever `apply_updates` says"),
            "{}",
            f.explanation
        );
        // Both enabled and the file says yes: the install timer is still the one named.
        let f = dnf_finding(&dnf4(Some("yes"), Enabled, Enabled, Disabled, Disabled));
        assert!(
            f.explanation.contains("whatever `apply_updates` says"),
            "{}",
            f.explanation
        );
    }

    #[test]
    fn what_upgrade_type_means_is_said_for_each_value() {
        let scope = |value: Option<&str>| {
            dnf_scope(&DnfConfig {
                apply_updates: None,
                upgrade_type: value.map(str::to_string),
            })
        };
        assert!(scope(Some("security")).contains("security updates only"));
        assert!(scope(Some("distro-sync")).contains("latest version"));
        for other in [None, Some("default"), Some("whatever")] {
            let text = scope(other);
            assert!(text.contains("installs every update"), "{text}");
            assert!(text.contains("`security`"), "{text}");
        }
    }

    #[test]
    fn broken_dnf_is_a_warning_with_the_steps_that_fix_it() {
        let f = dnf_finding(&dnf4(None, Disabled, Disabled, Disabled, Disabled));
        assert_eq!(f.severity, Severity::Warning);
        assert_eq!(f.confidence.percent, 80);
        assert!(
            f.explanation
                .contains("No timer of dnf-automatic is enabled"),
            "{}",
            f.explanation
        );
        assert!(
            f.explanation.contains("patched another way"),
            "{}",
            f.explanation
        );
        let steps = f.recommendation.unwrap();
        assert!(
            steps.contains("sudo systemctl enable --now dnf-automatic-install.timer"),
            "{steps}"
        );
        assert!(!steps.contains("dnf install"), "{steps}");
        assert!(
            !steps.contains("apply_updates"),
            "dnf 4's install timer needs no file: {steps}"
        );
        assert!(
            steps
                .trim_end()
                .ends_with("systemctl list-timers 'dnf*automatic*'"),
            "{steps}"
        );
    }

    #[test]
    fn the_sentences_name_the_timer_of_the_version() {
        let f = dnf_finding(&dnf5(Some("no"), Enabled));
        assert!(
            f.explanation
                .contains("`dnf5-automatic.timer` is enabled, but `apply_updates` is `no`"),
            "{}",
            f.explanation
        );
        let f = dnf_finding(&dnf5(None, Enabled));
        assert!(
            f.explanation
                .contains("`dnf5-automatic.timer` is enabled, but `apply_updates` is not set"),
            "{}",
            f.explanation
        );
        let f = dnf_finding(&dnf4(Some("no"), Disabled, Enabled, Disabled, Disabled));
        assert!(
            f.explanation
                .contains("`dnf-automatic.timer` is enabled, but `apply_updates` is `no`"),
            "{}",
            f.explanation
        );
    }

    #[test]
    fn dnf_steps_depend_on_the_version_and_the_problem() {
        let steps = |dnf: &DnfSetup| dnf_steps(dnf, &dnf_problems(dnf)).build();

        // dnf 5 needs the file as well as the timer.
        let s = steps(&dnf5(Some("yes"), Disabled));
        assert!(s.contains("apply_updates = yes"), "{s}");
        assert!(
            s.contains("sudo systemctl enable --now dnf5-automatic.timer"),
            "{s}"
        );
        assert!(!s.contains("dnf-automatic-install"), "{s}");

        // The timer is on, the file says no: the file is what to change.
        let s = steps(&dnf4(Some("no"), Disabled, Enabled, Disabled, Disabled));
        assert!(s.contains("apply_updates = yes"), "{s}");
        assert!(
            s.contains("grep -E '^(apply_updates|upgrade_type)' /etc/dnf/automatic.conf"),
            "{s}"
        );
        assert!(!s.contains("systemctl enable"), "{s}");
        let s = steps(&dnf5(None, Enabled));
        assert!(s.contains("apply_updates = yes"), "{s}");
        assert!(!s.contains("systemctl enable"), "{s}");
        let s = steps(&dnf5(Some("maybe"), Enabled));
        assert!(s.contains("apply_updates = yes"), "{s}");

        // A timer that never installs is turned off, and the one that does is turned on.
        let s = steps(&dnf4(Some("yes"), Disabled, Disabled, Disabled, Enabled));
        assert!(
            s.contains("sudo systemctl disable --now dnf-automatic-notifyonly.timer"),
            "{s}"
        );
        assert!(
            s.contains("sudo systemctl enable --now dnf-automatic-install.timer"),
            "{s}"
        );
        assert!(!s.contains("download.timer"), "{s}");
        let s = steps(&dnf4(Some("yes"), Disabled, Disabled, Enabled, Enabled));
        assert!(
            s.contains("disable --now dnf-automatic-download.timer"),
            "{s}"
        );
        assert!(
            s.contains("disable --now dnf-automatic-notifyonly.timer"),
            "{s}"
        );
    }

    #[test]
    fn missing_dnf_is_installed_with_the_package_of_its_version() {
        let mut d = dnf4(None, Disabled, Disabled, Disabled, Disabled);
        d.installed = false;
        d.timers.clear();
        let f = dnf_finding(&d);
        assert_eq!(f.severity, Severity::Warning);
        assert!(
            f.explanation.contains("dnf-automatic is not installed"),
            "{}",
            f.explanation
        );
        assert_eq!(evidence(&f, "dnf_automatic_installed"), Some("no"));
        assert_eq!(
            evidence(&f, "apply_updates"),
            None,
            "nothing is installed to configure"
        );
        let steps = f.recommendation.unwrap();
        assert!(
            steps.starts_with(
                "1. Install the package that does it:\n    sudo dnf install dnf-automatic\n"
            ),
            "{steps}"
        );
        assert!(
            steps.contains("enable --now dnf-automatic-install.timer"),
            "{steps}"
        );

        let mut d = dnf5(None, Disabled);
        d.installed = false;
        d.timers.clear();
        let steps = dnf_finding(&d).recommendation.unwrap();
        assert!(
            steps.contains("sudo dnf install dnf5-plugin-automatic"),
            "{steps}"
        );
        assert!(steps.contains("apply_updates = yes"), "{steps}");
        assert!(
            steps.contains("enable --now dnf5-automatic.timer"),
            "{steps}"
        );
    }

    #[test]
    fn unreadable_dnf_timers_are_information() {
        let f = dnf_finding(&dnf5(Some("yes"), Unknown));
        assert_eq!(f.severity, Severity::Info);
        assert_eq!(f.confidence.percent, 100);
        assert!(f.recommendation.is_none());
        assert!(
            f.explanation.contains("could not be told"),
            "{}",
            f.explanation
        );
        assert!(f.explanation.contains(DNF5_TIMER), "{}", f.explanation);
        assert_eq!(evidence(&f, DNF5_TIMER), Some("unknown"));
    }

    #[test]
    fn every_dnf_problem_has_its_own_sentence() {
        let all = [
            DnfProblem::NotInstalled,
            DnfProblem::NoTimer,
            DnfProblem::ApplyUpdatesOff(None),
            DnfProblem::ApplyUpdatesOff(Some("no".into())),
            DnfProblem::ApplyUpdatesInvalid("maybe".into()),
            DnfProblem::TimerDoesNotInstall {
                unit: "x.timer",
                does: "does little",
            },
        ];
        let sentences: Vec<String> = all.iter().map(|p| p.sentence("t.timer")).collect();
        for (i, a) in sentences.iter().enumerate() {
            assert!(a.ends_with('.'), "{a}");
            for b in &sentences[i + 1..] {
                assert_ne!(a, b);
            }
        }
        assert!(sentences[2].contains("`t.timer` is enabled"));
        assert!(sentences[2].contains("not set"));
        assert!(sentences[3].contains("`t.timer` is enabled"));
        assert!(sentences[3].contains("`no`"));
        assert!(sentences[4].contains("`maybe`"));
        assert_eq!(
            sentences[5],
            "`x.timer` is enabled, but it only does little; it never installs."
        );
    }

    // ----- other systems and the module ----------------------------------------------------

    fn context(distro: Option<&str>) -> Context {
        Context {
            hostname: "srv01".into(),
            kernel_version: "6.8.0".into(),
            distro: distro.map(str::to_string),
            architecture: "x86_64".into(),
            cpu_count: 8,
            mem_total_kb: 16 * 1024 * 1024,
            boot_time_unix: 0,
        }
    }

    #[test]
    fn another_system_is_said_not_to_have_been_checked() {
        let f = updates_finding(&Updates::Unsupported, Some("openSUSE Leap 15.6"));
        assert_eq!(f.id, "SRV001");
        assert_eq!(f.severity, Severity::Info);
        assert_eq!(f.confidence.percent, 100);
        assert!(f.recommendation.is_none());
        assert!(
            f.explanation.contains("`openSUSE Leap 15.6`"),
            "{}",
            f.explanation
        );
        assert!(
            f.explanation.contains("was not checked"),
            "{}",
            f.explanation
        );
        assert!(
            f.explanation
                .contains("not the same as the updates being installed"),
            "{}",
            f.explanation
        );
        assert_eq!(evidence(&f, "package_manager"), Some("unsupported"));
        let f = updates_finding(&Updates::Unsupported, None);
        assert!(
            f.explanation.contains("this system is"),
            "{}",
            f.explanation
        );
    }

    #[test]
    fn a_hostile_distribution_name_is_cleaned_and_shortened() {
        let name = format!("Evil\u{1b}[2J{}", "x".repeat(200));
        let f = updates_finding(&Updates::Unsupported, Some(&name));
        assert!(!f.explanation.contains('\u{1b}'), "{}", f.explanation);
        assert!(f.explanation.contains("`Evil?[2J"), "{}", f.explanation);
        assert!(f.explanation.contains('…'), "{}", f.explanation);
        assert!(
            !f.explanation.contains(&"x".repeat(100)),
            "{}",
            f.explanation
        );
    }

    #[test]
    fn analyze_reports_the_one_check_with_the_system_it_found() {
        let data = ServerRawData {
            updates: Updates::Apt(working_apt()),
        };
        let findings = analyze(&data, &context(Some("Ubuntu 24.04 LTS")));
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].id, "SRV001");
        assert_eq!(findings[0].severity, Severity::Info);
        assert_eq!(evidence(&findings[0], "package_manager"), Some("apt"));

        let data = ServerRawData {
            updates: Updates::Dnf(dnf5(Some("yes"), Enabled)),
        };
        let findings = analyze(&data, &context(Some("Fedora Linux 42")));
        assert_eq!(evidence(&findings[0], "package_manager"), Some("dnf"));
        assert_eq!(evidence(&findings[0], "dnf_version"), Some("5"));

        let data = ServerRawData {
            updates: Updates::Unsupported,
        };
        let findings = analyze(&data, &context(Some("Alpine Linux v3.20")));
        assert!(
            findings[0].explanation.contains("`Alpine Linux v3.20`"),
            "{}",
            findings[0].explanation
        );
    }

    #[test]
    fn no_recommendation_hides_a_command_in_its_prose() {
        // The recommendation layout: a command is on its own indented line.
        // Any line that is not indented is prose, and prose has no `sudo`.
        let mut texts = Vec::new();
        let mut apt = working_apt();
        apt.installed = false;
        apt.periodic = Some(periodic(Some("0"), None, None, 0));
        apt.update_timer = Masked;
        apt.upgrade_timer = Disabled;
        texts.push(apt_finding(&apt).recommendation.unwrap());
        let mut d = dnf4(None, Disabled, Disabled, Enabled, Enabled);
        d.installed = true;
        texts.push(dnf_finding(&d).recommendation.unwrap());
        texts.push(
            dnf_finding(&dnf5(Some("no"), Enabled))
                .recommendation
                .unwrap(),
        );
        for text in texts {
            for line in text.lines() {
                if !line.starts_with("    ") {
                    assert!(!line.contains("sudo "), "{line}");
                    assert!(!line.contains("systemctl "), "{line}");
                }
            }
        }
    }
}
