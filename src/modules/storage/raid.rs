// SPDX-License-Identifier: GPL-3.0-only

//! STOR005: software RAID (md) arrays, read from `/proc/mdstat`.
//!
//! SMART says whether one disk is dying; it does not say that an array has
//! already lost one. The kernel's own table does, and it is the first place
//! an administrator looks. One finding per array: information when it is
//! whole, a warning while it rebuilds, an error when it has no redundancy
//! left or is not running at all.

use std::fs;
use std::path::Path;

use crate::core::text::clean;
use crate::models::{Category, Confidence, Finding, Severity};
use crate::modules::logs::text::is_safe_word;
use crate::modules::recommend::Steps;

use super::device::disk_of;

/// Where the kernel lists its md arrays, under the root being read.
const MDSTAT: &str = "proc/mdstat";
/// Bounds on what a file can make the report carry.
const MAX_ARRAYS: usize = 64;
const MAX_MEMBERS: usize = 128;
const MAX_NAME: usize = 64;
/// Members named in the evidence; a longer list is cut.
const SHOWN_MEMBERS: usize = 16;
/// Disks a recommendation gives a command for.
const MAX_COMMANDS: usize = 4;

/// One device of an array. `failed` is the kernel's `(F)`, `spare` its `(S)`.
#[derive(Debug, Clone, PartialEq)]
pub struct Member {
    pub name: String,
    pub failed: bool,
    pub spare: bool,
}

/// What the kernel is doing to an array besides serving it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Work {
    Resync,
    Recovery,
    Check,
    Repair,
    Reshape,
}

impl Work {
    fn word(self) -> &'static str {
        match self {
            Work::Resync => "resync",
            Work::Recovery => "recovery",
            Work::Check => "check",
            Work::Repair => "repair",
            Work::Reshape => "reshape",
        }
    }
}

const WORKS: [(&str, Work); 5] = [
    ("resync", Work::Resync),
    ("recovery", Work::Recovery),
    ("check", Work::Check),
    ("repair", Work::Repair),
    ("reshape", Work::Reshape),
];

/// A running or waiting resync, rebuild or check. `percent` is `None` while
/// it waits (`DELAYED`, `PENDING`), `finish_minutes` what the kernel
/// estimates when it prints one.
#[derive(Debug, Clone, PartialEq)]
pub struct Progress {
    pub work: Work,
    pub percent: Option<f64>,
    pub finish_minutes: Option<u64>,
}

impl Progress {
    /// `check 42.0%`, `resync waiting`.
    fn text(&self) -> String {
        match self.percent {
            Some(percent) => format!("{} {percent:.1}%", self.work.word()),
            None => format!("{} waiting", self.work.word()),
        }
    }

    /// `a check is running, 42.0% done`.
    fn sentence(&self) -> String {
        match self.percent {
            Some(percent) => format!("a {} is running, {percent:.1}% done", self.work.word()),
            None => format!("a {} is waiting to run", self.work.word()),
        }
    }
}

/// One array of `/proc/mdstat`. `configured` and `working` are the kernel's
/// `[n/m]`, `health` its `[UU_]`; RAID 0 and linear arrays print neither.
#[derive(Debug, Clone, PartialEq)]
pub struct MdArray {
    pub name: String,
    pub active: bool,
    pub level: Option<String>,
    pub members: Vec<Member>,
    pub configured: Option<u32>,
    pub working: Option<u32>,
    pub health: Option<String>,
    pub progress: Option<Progress>,
    /// A container of firmware RAID metadata (Intel `imsm`, `ddf`): it is
    /// always `inactive`, and the arrays inside it are listed on their own.
    pub container: bool,
}

/// `sdb1[1]` and `sda1[0](F)`: a device name, its slot, and flags.
fn parse_member(word: &str) -> Option<Member> {
    let (name, rest) = word.split_once('[')?;
    let (slot, flags) = rest.split_once(']')?;
    if name.is_empty() || slot.is_empty() || !slot.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    Some(Member {
        name: clean(name, MAX_NAME),
        failed: flags.contains("(F)"),
        spare: flags.contains("(S)"),
    })
}

/// `md0 : active raid1 sdb1[1] sda1[0]`. Lines that do not start an array
/// (`Personalities`, `unused devices`, the indented ones) are `None`.
fn parse_array_line(line: &str) -> Option<MdArray> {
    if line.starts_with(char::is_whitespace) {
        return None;
    }
    let (name, rest) = line.split_once(" : ")?;
    let name = name.trim();
    if !name.starts_with("md") {
        return None;
    }
    let mut words = rest.split_whitespace();
    let active = words.next()? == "active";
    let mut level = None;
    let mut members = Vec::new();
    for word in words {
        // `(auto-read-only)` and the like say nothing about health.
        if word.starts_with('(') {
            continue;
        }
        if let Some(member) = parse_member(word) {
            if members.len() < MAX_MEMBERS {
                members.push(member);
            }
        } else if level.is_none() {
            level = Some(clean(word, MAX_NAME));
        }
    }
    Some(MdArray {
        name: clean(name, MAX_NAME),
        active,
        level,
        members,
        configured: None,
        working: None,
        health: None,
        progress: None,
        container: false,
    })
}

/// `[4/3]`: devices the array should have, and devices that work.
fn device_counts(word: &str) -> Option<(u32, u32)> {
    let inner = word.strip_prefix('[')?.strip_suffix(']')?;
    let (configured, working) = inner.split_once('/')?;
    Some((configured.parse().ok()?, working.parse().ok()?))
}

/// `[UU_]`: one letter per slot, `_` for a slot with no working device.
fn health_of(word: &str) -> Option<&str> {
    let inner = word.strip_prefix('[')?.strip_suffix(']')?;
    let only_slots = inner.chars().all(|c| c == 'U' || c == '_');
    (!inner.is_empty() && only_slots).then_some(inner)
}

/// `recovery = 12.6% (..) finish=60.0min`, `resync=DELAYED`.
fn read_progress(words: &[&str]) -> Option<Progress> {
    let finish_minutes = words
        .iter()
        .find_map(|word| word.strip_prefix("finish="))
        .and_then(|value| value.trim_end_matches("min").parse::<f64>().ok())
        .filter(|minutes| minutes.is_finite() && *minutes >= 0.0)
        .map(|minutes| minutes.round() as u64);
    for (i, word) in words.iter().enumerate() {
        for (keyword, work) in WORKS {
            let value = match word.strip_prefix(keyword) {
                Some("") if words.get(i + 1) == Some(&"=") => words.get(i + 2).copied(),
                Some(rest) => rest.strip_prefix('='),
                None => None,
            };
            let Some(value) = value else { continue };
            let percent = if matches!(value, "DELAYED" | "PENDING") {
                None
            } else {
                let percent = value.strip_suffix('%').and_then(|p| p.parse::<f64>().ok());
                match percent.filter(|p| (0.0..=100.0).contains(p)) {
                    Some(percent) => Some(percent),
                    None => continue,
                }
            };
            return Some(Progress {
                work,
                percent,
                finish_minutes,
            });
        }
    }
    None
}

/// The lines under an array's first one: sizes, `[n/m] [UU_]`, progress.
fn read_detail(array: &mut MdArray, line: &str) {
    let words: Vec<&str> = line.split_whitespace().collect();
    for (i, word) in words.iter().enumerate() {
        if let Some((configured, working)) = device_counts(word) {
            array.configured = Some(configured);
            array.working = Some(working);
            array.health = words
                .get(i + 1)
                .and_then(|next| health_of(next))
                .map(str::to_string);
        }
    }
    if let Some(progress) = read_progress(&words) {
        array.progress = Some(progress);
    }
    // `super external:imsm` is a container; an array inside one says
    // `super external:/md127/0` (or `external:-md127/0` while it is idle).
    let metadata = words
        .windows(2)
        .find(|pair| pair[0] == "super")
        .and_then(|pair| pair[1].strip_prefix("external:"));
    if let Some(metadata) = metadata {
        array.container = !metadata.starts_with(['/', '-']);
    }
}

/// Pure: the arrays listed in the text of `/proc/mdstat`.
pub fn parse_mdstat(text: &str) -> Vec<MdArray> {
    let mut arrays: Vec<MdArray> = Vec::new();
    let mut current: Option<MdArray> = None;
    for line in text.lines() {
        if let Some(array) = parse_array_line(line) {
            arrays.extend(current.replace(array));
        } else if let Some(array) = current.as_mut() {
            read_detail(array, line);
        }
    }
    arrays.extend(current);
    arrays.truncate(MAX_ARRAYS);
    arrays
}

/// The arrays of the machine under `root` (`/` for the real one). A machine
/// without md, or a file that cannot be read, has none.
pub fn read(root: &Path) -> Vec<MdArray> {
    fs::read_to_string(root.join(MDSTAT))
        .map(|text| parse_mdstat(&text))
        .unwrap_or_default()
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum State {
    /// Not started: `inactive`.
    Stopped,
    /// Short of devices, and nothing is rebuilding onto a new one.
    Degraded,
    /// Short of devices, and a spare is being filled.
    Rebuilding,
    /// Whole again, with a failed device still listed.
    Replaced,
    /// Whole, with a resync or a check running.
    Busy,
    Healthy,
}

/// Devices the array should have and does not: the kernel's own count, or
/// the empty slots of its `[UU_]` when it printed no count.
fn missing(array: &MdArray) -> u32 {
    match (array.configured, array.working) {
        (Some(configured), Some(working)) => configured.saturating_sub(working),
        _ => array
            .health
            .as_deref()
            .map_or(0, |health| health.matches('_').count() as u32),
    }
}

fn state_of(array: &MdArray) -> State {
    let rebuilding = array
        .progress
        .as_ref()
        .is_some_and(|progress| progress.work == Work::Recovery);
    if !array.active {
        State::Stopped
    } else if missing(array) > 0 {
        if rebuilding {
            State::Rebuilding
        } else {
            State::Degraded
        }
    } else if array.members.iter().any(|member| member.failed) {
        State::Replaced
    } else if array.progress.is_some() {
        State::Busy
    } else {
        State::Healthy
    }
}

fn names(members: &[&Member]) -> String {
    members
        .iter()
        .take(SHOWN_MEMBERS)
        .map(|member| member.name.as_str())
        .collect::<Vec<_>>()
        .join(", ")
}

/// `3 of 4 devices up`, or what is known when the kernel printed no count.
fn devices_up(array: &MdArray) -> String {
    match (array.configured, array.working, &array.health) {
        (Some(configured), Some(working), _) => format!("{working} of {configured} devices up"),
        (_, _, Some(health)) => format!("status [{health}]"),
        _ => "some devices missing".to_string(),
    }
}

fn explanation(array: &MdArray, state: State) -> String {
    let who = match &array.level {
        Some(level) => format!("{} ({level})", array.name),
        None => array.name.clone(),
    };
    let members: Vec<&Member> = array.members.iter().collect();
    let failed: Vec<&Member> = array.members.iter().filter(|m| m.failed).collect();
    let activity = array.progress.as_ref().map(Progress::text);
    match state {
        State::Stopped => format!(
            "{who} is inactive: the kernel sees its members ({}) but has not started the \
             array, so nothing stored on it can be reached.",
            names(&members)
        ),
        State::Degraded => {
            let failed_note = if failed.is_empty() {
                String::new()
            } else {
                format!(", failed: {}", names(&failed))
            };
            format!(
                "{who} is running without its full set of devices ({}{failed_note}), so it \
                 has no redundancy left: one more failure loses data, and no rebuild is \
                 running.",
                devices_up(array)
            )
        }
        State::Rebuilding => {
            let left = array
                .progress
                .as_ref()
                .and_then(|progress| progress.finish_minutes)
                .map_or(String::new(), |minutes| {
                    format!(", about {minutes} min left")
                });
            format!(
                "{who} is rebuilding onto a new device ({}; {}{left}). It has no redundancy \
                 until the rebuild ends.",
                devices_up(array),
                activity.unwrap_or_default()
            )
        }
        State::Replaced => format!(
            "{who} is complete again, but {} is still attached to it as failed: a spare took \
             its place. The failed disk has to be removed and replaced before the next \
             failure.",
            names(&failed)
        ),
        State::Busy => format!(
            "{who} is healthy ({}); {}.",
            devices_up(array),
            array
                .progress
                .as_ref()
                .map(Progress::sentence)
                .unwrap_or_default()
        ),
        State::Healthy => match array.configured {
            Some(configured) => format!("{who} is healthy: all {configured} devices are up."),
            None => format!("{who} is active with {} members.", array.members.len()),
        },
    }
}

/// `sudo smartctl -a /dev/sda` for the disks behind the failed members.
fn smart_commands(failed: &[&Member]) -> Vec<String> {
    let mut disks: Vec<&str> = Vec::new();
    for member in failed {
        if let Some(disk) = disk_of(&member.name).filter(|disk| is_safe_word(disk)) {
            if !disks.contains(&disk) {
                disks.push(disk);
            }
        }
    }
    if disks.is_empty() {
        return vec!["sudo smartctl --scan".to_string()];
    }
    disks
        .iter()
        .take(MAX_COMMANDS)
        .map(|disk| format!("sudo smartctl -a /dev/{disk}"))
        .collect()
}

fn steps(array: &MdArray, state: State) -> Steps {
    let device = if is_safe_word(&array.name) {
        format!("/dev/{}", array.name)
    } else {
        "/dev/<array>".to_string()
    };
    let failed: Vec<&Member> = array.members.iter().filter(|m| m.failed).collect();
    let mut steps = Steps::new();
    if matches!(state, State::Degraded | State::Rebuilding) {
        steps = steps.step(
            "Make sure what matters on it is also somewhere else before touching the disks: \
             a second failure on an array with no redundancy loses it.",
            &[],
        );
    }
    steps = steps.step_owned(
        "See the state of the array and of each of its members:",
        vec![format!("sudo mdadm --detail {device}")],
    );
    if state == State::Stopped {
        let examine: Vec<String> = array
            .members
            .iter()
            .filter(|member| is_safe_word(&member.name))
            .take(MAX_COMMANDS)
            .map(|member| format!("sudo mdadm --examine /dev/{}", member.name))
            .collect();
        if !examine.is_empty() {
            steps = steps.step_owned(
                "Read what each member still says about the array (the event count shows \
                 which copy is the newest):",
                examine,
            );
        }
        return steps.step(
            "Do not force the array to start before you know why a member is missing: a disk \
             that was out for a while holds older data, and assembling it with the others can \
             overwrite the newer copy. Find the cause first (a cable, the controller, a failed \
             disk).",
            &[],
        );
    }
    if failed.is_empty() {
        if state == State::Degraded {
            steps = steps.step(
                "A device is missing rather than marked failed: find which one is gone, then \
                 check its cable and the controller:",
                &["lsblk -o NAME,SIZE,MODEL,SERIAL"],
            );
        }
    } else {
        steps = steps
            .step_owned(
                "Ask each failed disk about its own health (install smartmontools if the \
                 command is missing). Sector errors confirm it is dying; a clean report \
                 points to a cable or the controller:",
                smart_commands(&failed),
            )
            .step_owned(
                "Take the failed device out of the array:",
                vec![format!("sudo mdadm {device} --remove failed")],
            );
    }
    match state {
        State::Rebuilding => steps.step(
            "Let the rebuild finish before anything else: no reboot, and no disk pulled. \
             Follow it:",
            &["watch -n 5 cat /proc/mdstat"],
        ),
        State::Replaced => steps.step_owned(
            "Replace the failed disk and add the new one: it becomes the spare that covers \
             the next failure (replace the placeholder with its partition):",
            vec![format!("sudo mdadm {device} --add /dev/<partition>")],
        ),
        _ => steps.step_owned(
            "Put the replacement disk in (or the same disk once its cable is fixed) and add \
             its partition; the array rebuilds by itself (replace the placeholder with it):",
            vec![
                format!("sudo mdadm {device} --add /dev/<partition>"),
                "watch -n 5 cat /proc/mdstat".to_string(),
            ],
        ),
    }
}

/// The findings for every array. A container is not one: it has no health
/// of its own, only the arrays inside it do. Pure.
pub fn findings(arrays: &[MdArray]) -> Vec<Finding> {
    arrays
        .iter()
        .filter(|array| !array.container)
        .map(array_finding)
        .collect()
}

/// The finding for one array. Pure.
pub fn array_finding(array: &MdArray) -> Finding {
    let state = state_of(array);
    let severity = match state {
        State::Stopped | State::Degraded => Severity::Error,
        State::Rebuilding | State::Replaced => Severity::Warning,
        State::Busy | State::Healthy => Severity::Info,
    };
    let members: Vec<&Member> = array.members.iter().collect();
    let failed: Vec<&Member> = array.members.iter().filter(|m| m.failed).collect();
    let spares: Vec<&Member> = array.members.iter().filter(|m| m.spare).collect();
    let mut builder = Finding::builder(
        "STOR005",
        format!("RAID Array \u{2014} {}", array.name),
        Category::Storage,
        severity,
        Confidence::direct_observation(),
    )
    .instance(array.name.clone())
    .evidence("array", array.name.clone())
    .evidence("state", if array.active { "active" } else { "inactive" })
    .evidence("members", names(&members));
    if let Some(level) = &array.level {
        builder = builder.evidence("level", level.clone());
    }
    if let (Some(configured), Some(working)) = (array.configured, array.working) {
        builder = builder
            .evidence("devices_configured", configured.to_string())
            .evidence("devices_working", working.to_string());
    }
    if let Some(health) = &array.health {
        builder = builder.evidence("status", health.clone());
    }
    if !failed.is_empty() {
        builder = builder.evidence("failed_members", names(&failed));
    }
    if !spares.is_empty() {
        builder = builder.evidence("spare_members", names(&spares));
    }
    if let Some(progress) = &array.progress {
        builder = builder.evidence("activity", progress.text());
    }
    builder = builder.explanation(explanation(array, state));
    if severity >= Severity::Warning {
        builder = builder.recommendation(steps(array, state).build());
    }
    builder.build()
}

#[cfg(test)]
mod tests {
    use super::*;

    const HEALTHY: &str = "\
Personalities : [raid1] [raid6] [raid5] [raid4]
md0 : active raid1 sdb1[1] sda1[0]
      976630336 blocks super 1.2 [2/2] [UU]
      bitmap: 0/8 pages [0KB], 65536KB chunk

unused devices: <none>
";

    const REBUILDING: &str = "\
Personalities : [raid6] [raid5] [raid4]
md1 : active raid5 sdd1[4] sdc1[2] sdb1[1] sda1[0]
      2930010240 blocks super 1.2 level 5, 512k chunk, algorithm 2 [4/3] [UUU_]
      [==>..................]  recovery = 12.6% (123456/976543) finish=60.4min speed=100000K/sec

unused devices: <none>
";

    const FAILED: &str = "\
md2 : active raid1 sdb1[1](F) sda1[0]
      976630336 blocks super 1.2 [2/1] [U_]

unused devices: <none>
";

    fn one(text: &str) -> MdArray {
        let mut arrays = parse_mdstat(text);
        assert_eq!(arrays.len(), 1, "{text}");
        arrays.remove(0)
    }

    fn member(name: &str) -> Member {
        Member {
            name: name.to_string(),
            failed: false,
            spare: false,
        }
    }

    fn failed(name: &str) -> Member {
        Member {
            failed: true,
            ..member(name)
        }
    }

    /// An active two-disk RAID 1 that is whole; tests change what they test.
    fn array() -> MdArray {
        MdArray {
            name: "md0".to_string(),
            active: true,
            level: Some("raid1".to_string()),
            members: vec![member("sda1"), member("sdb1")],
            configured: Some(2),
            working: Some(2),
            health: Some("UU".to_string()),
            progress: None,
            container: false,
        }
    }

    fn evidence<'a>(finding: &'a Finding, key: &str) -> Option<&'a str> {
        finding
            .evidence
            .iter()
            .find(|(k, _)| k == key)
            .map(|(_, v)| v.as_str())
    }

    #[test]
    fn a_healthy_raid1_is_read_with_its_counts_and_members() {
        let md = one(HEALTHY);
        assert_eq!(md.name, "md0");
        assert!(md.active);
        assert_eq!(md.level.as_deref(), Some("raid1"));
        assert_eq!(md.members, vec![member("sdb1"), member("sda1")]);
        assert_eq!((md.configured, md.working), (Some(2), Some(2)));
        assert_eq!(md.health.as_deref(), Some("UU"));
        assert_eq!(md.progress, None);
    }

    #[test]
    fn a_rebuild_is_read_with_its_percent_and_its_time() {
        let md = one(REBUILDING);
        assert_eq!(md.level.as_deref(), Some("raid5"));
        assert_eq!((md.configured, md.working), (Some(4), Some(3)));
        assert_eq!(md.health.as_deref(), Some("UUU_"));
        assert_eq!(
            md.progress,
            Some(Progress {
                work: Work::Recovery,
                percent: Some(12.6),
                finish_minutes: Some(60),
            })
        );
    }

    #[test]
    fn a_failed_member_and_a_spare_are_flagged() {
        let md = one(FAILED);
        assert_eq!(md.members, vec![failed("sdb1"), member("sda1")]);
        let md = one("md5 : active raid1 sdc1[2](S) sdb1[1] sda1[0](W)\n  1 blocks [2/2] [UU]\n");
        assert_eq!(
            md.members,
            vec![
                Member {
                    spare: true,
                    ..member("sdc1")
                },
                member("sdb1"),
                member("sda1"),
            ]
        );
        let md = one("md6 : active raid1 sdb1[1](W)(F) sda1[0]\n  1 blocks [2/1] [U_]\n");
        assert!(md.members[0].failed);
    }

    #[test]
    fn an_inactive_array_has_no_level_and_is_not_active() {
        let md = one("md3 : inactive sdc1[0](S) sdd1[1](S)\n      1953260032 blocks super 1.2\n");
        assert!(!md.active);
        assert_eq!(md.level, None);
        assert_eq!(md.members.len(), 2);
        assert_eq!((md.configured, md.working, md.health), (None, None, None));
    }

    const IMSM: &str = "\
Personalities : [raid1]
md126 : active raid1 sdb[1] sda[0]
      488383488 blocks super external:/md127/0 [2/2] [UU]

md127 : inactive sdb[1](S) sda[0](S)
      6320 blocks super external:imsm

unused devices: <none>
";

    #[test]
    fn words_that_are_not_a_member_are_not_taken_for_one() {
        // No name, no slot, a slot that is not a number, a number with more.
        let md = one("md0 : active raid1 [0] sda[] sdb[x] sdd[1x] sde[x1] sdc[1]\n  1 blocks\n");
        assert_eq!(md.members, vec![member("sdc")]);
        let md = one("md0 : active raid1 sda[0 sdb]0] sdc[12]\n  1 blocks\n");
        assert_eq!(md.members, vec![member("sdc")]);
    }

    #[test]
    fn each_kind_of_work_is_named_in_the_evidence_and_the_explanation() {
        for (work, word) in [
            (Work::Resync, "resync"),
            (Work::Recovery, "recovery"),
            (Work::Check, "check"),
            (Work::Repair, "repair"),
            (Work::Reshape, "reshape"),
        ] {
            let running = Progress {
                work,
                percent: Some(50.0),
                finish_minutes: None,
            };
            assert_eq!(running.text(), format!("{word} 50.0%"));
            assert_eq!(
                running.sentence(),
                format!("a {word} is running, 50.0% done")
            );
            let waiting = Progress {
                percent: None,
                ..running
            };
            assert_eq!(waiting.text(), format!("{word} waiting"));
            assert_eq!(waiting.sentence(), format!("a {word} is waiting to run"));
        }
        // A fraction is shown to one decimal.
        let p = Progress {
            work: Work::Check,
            percent: Some(12.56),
            finish_minutes: None,
        };
        assert_eq!(p.text(), "check 12.6%");
    }

    #[test]
    fn a_firmware_raid_container_is_told_from_the_array_inside_it() {
        let arrays = parse_mdstat(IMSM);
        assert_eq!(arrays.len(), 2);
        assert_eq!(
            (arrays[0].name.as_str(), arrays[0].container),
            ("md126", false)
        );
        assert_eq!(
            (arrays[1].name.as_str(), arrays[1].container),
            ("md127", true)
        );
        assert!(!arrays[1].active);
        for (metadata, container) in [
            ("external:imsm", true),
            ("external:ddf", true),
            ("external:/md127/0", false),
            ("external:-md127/1", false),
            ("1.2", false),
            ("0.90", false),
        ] {
            let md = one(&format!(
                "md0 : inactive sda[0](S)\n  1 blocks super {metadata}\n"
            ));
            assert_eq!(md.container, container, "{metadata}");
        }
        // Not a container until something says so.
        assert!(!one(HEALTHY).container);
        assert!(!one("md0 : inactive sda[0](S)\n  1 blocks super\n").container);
    }

    #[test]
    fn a_container_is_not_reported_but_the_array_inside_it_is() {
        let ids: Vec<Option<String>> = findings(&parse_mdstat(IMSM))
            .into_iter()
            .map(|f| f.instance)
            .collect();
        assert_eq!(ids, vec![Some("md126".to_string())]);
        assert_eq!(findings(&parse_mdstat(IMSM))[0].severity, Severity::Info);
        assert_eq!(findings(&[]).len(), 0);
        // An inactive array that is not a container is.
        assert_eq!(
            findings(&parse_mdstat(
                "md3 : inactive sdc1[0](S)\n  1 blocks super 1.2\n"
            ))
            .len(),
            1
        );
    }

    #[test]
    fn a_raid0_has_no_device_count() {
        let md = one(
            "md4 : active raid0 sdb[1] sda[0]\n      1953260032 blocks super 1.2 512k chunks\n",
        );
        assert_eq!(md.level.as_deref(), Some("raid0"));
        assert_eq!((md.configured, md.working, md.health), (None, None, None));
    }

    #[test]
    fn a_read_only_note_is_not_taken_for_the_level() {
        let md =
            one("md0 : active (auto-read-only) raid1 sdb1[1] sda1[0]\n  1 blocks [2/2] [UU]\n");
        assert_eq!(md.level.as_deref(), Some("raid1"));
        assert_eq!(md.members.len(), 2);
    }

    #[test]
    fn work_in_progress_is_read_in_each_of_its_forms() {
        for (line, work, percent) in [
            (
                "      [>....]  resync =  6.2% (1/2) finish=12.1min speed=1K/sec",
                Work::Resync,
                Some(6.2),
            ),
            (
                "      [>....]  check = 42.0% (1/2) finish=1.0min speed=1K/sec",
                Work::Check,
                Some(42.0),
            ),
            (
                "      [>....]  repair = 0.0% (1/2) finish=1.0min speed=1K/sec",
                Work::Repair,
                Some(0.0),
            ),
            (
                "      [>....]  reshape = 100.0% (1/2) finish=0.0min speed=1K/sec",
                Work::Reshape,
                Some(100.0),
            ),
            ("        resync=DELAYED", Work::Resync, None),
            ("        resync=PENDING", Work::Resync, None),
            (
                "      [>....]  recovery=7.5% (1/2) finish=1.0min",
                Work::Recovery,
                Some(7.5),
            ),
        ] {
            let md = one(&format!(
                "md0 : active raid1 sdb1[1] sda1[0]\n  1 blocks [2/2] [UU]\n{line}\n"
            ));
            let progress = md.progress.unwrap_or_else(|| panic!("{line}"));
            assert_eq!((progress.work, progress.percent), (work, percent), "{line}");
        }
    }

    #[test]
    fn a_waiting_resync_has_no_percent_and_no_time() {
        let md = one(
            "md0 : active raid1 sdb1[1] sda1[0]\n  1 blocks [2/2] [UU]\n        resync=DELAYED\n",
        );
        assert_eq!(
            md.progress,
            Some(Progress {
                work: Work::Resync,
                percent: None,
                finish_minutes: None,
            })
        );
    }

    #[test]
    fn words_that_only_start_like_a_task_are_not_one() {
        for line in [
            "      checking = 5.0%",
            "      resync = soon",
            "      resync = 140%",
            "      resync = 100.1%",
            "      resync = -3%",
            "      resync = nan%",
            "      resync",
            "      resync =",
            "      recovery=",
        ] {
            let md = one(&format!(
                "md0 : active raid1 sdb1[1] sda1[0]\n  1 blocks [2/2] [UU]\n{line}\n"
            ));
            assert_eq!(md.progress, None, "{line}");
        }
    }

    #[test]
    fn a_time_that_is_not_a_time_is_dropped() {
        for (finish, minutes) in [
            ("finish=60.4min", Some(60)),
            ("finish=60.5min", Some(61)),
            ("finish=0.0min", Some(0)),
            ("finish=-1.0min", None),
            ("finish=inf", None),
            ("finish=soon", None),
        ] {
            let md = one(&format!(
                "md0 : active raid1 sdb1[1] sda1[0]\n  1 blocks [2/1] [U_]\n  recovery = 1.0% (1/2) {finish}\n"
            ));
            assert_eq!(md.progress.unwrap().finish_minutes, minutes, "{finish}");
        }
    }

    #[test]
    fn a_count_without_a_status_leaves_the_status_empty() {
        let md = one("md0 : active raid1 sdb1[1] sda1[0]\n  1 blocks [2/1]\n");
        assert_eq!((md.configured, md.working), (Some(2), Some(1)));
        assert_eq!(md.health, None);
        for slots in ["[xyz]", "[UxU]", "[U1]", "[_u]", "[ U]"] {
            let md = one(&format!(
                "md0 : active raid1 sdb1[1] sda1[0]\n  1 blocks [2/1] {slots}\n"
            ));
            assert_eq!(md.health, None, "{slots}");
        }
        let md = one("md0 : active raid1 sdb1[1] sda1[0]\n  1 blocks [2/1] []\n");
        assert_eq!(md.health, None);
    }

    #[test]
    fn several_arrays_are_each_read_with_their_own_lines() {
        let text = format!("{HEALTHY}{FAILED}").replace("unused devices: <none>\n", "");
        let arrays = parse_mdstat(&text);
        assert_eq!(arrays.len(), 2);
        assert_eq!(arrays[0].name, "md0");
        assert_eq!(arrays[0].working, Some(2));
        assert_eq!(arrays[1].name, "md2");
        assert_eq!(arrays[1].working, Some(1));
    }

    #[test]
    fn text_without_arrays_gives_none() {
        for text in [
            "",
            "Personalities :\nunused devices: <none>\n",
            "   md0 : active raid1 sda[0]\n",
            "md0 active raid1 sda[0]\n",
            "sda : active raid1 sda[0]\n",
            "md0 : \n",
            "garbage\n\x00\u{1b}[31m\n",
        ] {
            assert_eq!(parse_mdstat(text), vec![], "{text:?}");
        }
    }

    #[test]
    fn a_file_cannot_make_the_report_carry_more_than_the_bounds() {
        let members: String = (0..300).map(|i| format!(" sd{i}[{i}]")).collect();
        let md = one(&format!("md0 : active raid1{members}\n"));
        assert_eq!(md.members.len(), 128);
        let many: String = (0..100)
            .map(|i| format!("md{i} : active raid1 sda[0]\n"))
            .collect();
        assert_eq!(parse_mdstat(&many).len(), 64);
        let md = one(&format!("md0 : active raid1 {}[0]\n", "a".repeat(200)));
        assert_eq!(md.members[0].name.chars().count(), 65);
        let md = one(&format!("md0 : active {}\n", "r".repeat(200)));
        assert_eq!(md.level.unwrap().chars().count(), 65);
        let md = one(&format!("md{} : active raid1 sda[0]\n", "7".repeat(200)));
        assert_eq!(md.name.chars().count(), 65);
    }

    #[test]
    fn terminal_escapes_in_names_are_replaced() {
        let md = one("md0 : active raid1 sd\u{1b}1[0]\n");
        assert_eq!(md.members[0].name, "sd?1");
        let md = one("md0 : active ra\u{1b}id1 sda[0]\n");
        assert!(!md.level.unwrap().contains('\u{1b}'));
    }

    #[test]
    fn the_arrays_are_read_under_the_root_and_a_missing_file_gives_none() {
        let root = std::env::temp_dir().join(format!("ld-raid-{}", std::process::id()));
        let _ = fs::remove_dir_all(&root);
        assert_eq!(read(&root), vec![]);
        fs::create_dir_all(root.join("proc")).unwrap();
        assert_eq!(read(&root), vec![]);
        fs::write(root.join("proc/mdstat"), HEALTHY).unwrap();
        let arrays = read(&root);
        assert_eq!(arrays.len(), 1);
        assert_eq!(arrays[0].name, "md0");
        fs::write(root.join("proc/mdstat"), [0xff, 0xfe]).unwrap();
        assert_eq!(read(&root), vec![]);
        let _ = fs::remove_dir_all(&root);
    }

    // --- the verdict -----------------------------------------------------

    #[test]
    fn what_each_array_is_in() {
        let mut inactive = array();
        inactive.active = false;
        let mut degraded = array();
        degraded.working = Some(1);
        let mut rebuilding = degraded.clone();
        rebuilding.progress = Some(Progress {
            work: Work::Recovery,
            percent: Some(5.0),
            finish_minutes: None,
        });
        let mut resyncing_while_short = degraded.clone();
        resyncing_while_short.progress = Some(Progress {
            work: Work::Resync,
            percent: Some(5.0),
            finish_minutes: None,
        });
        let mut replaced = array();
        replaced.members[1].failed = true;
        let mut checking = array();
        checking.progress = Some(Progress {
            work: Work::Check,
            percent: Some(5.0),
            finish_minutes: None,
        });
        let mut recovering_while_whole = array();
        recovering_while_whole.progress = Some(Progress {
            work: Work::Recovery,
            percent: Some(99.0),
            finish_minutes: None,
        });
        for (md, state, severity) in [
            (inactive, State::Stopped, Severity::Error),
            (degraded, State::Degraded, Severity::Error),
            (rebuilding, State::Rebuilding, Severity::Warning),
            (resyncing_while_short, State::Degraded, Severity::Error),
            (replaced, State::Replaced, Severity::Warning),
            (checking, State::Busy, Severity::Info),
            (recovering_while_whole, State::Busy, Severity::Info),
            (array(), State::Healthy, Severity::Info),
        ] {
            assert_eq!(state_of(&md), state, "{md:?}");
            assert_eq!(array_finding(&md).severity, severity, "{md:?}");
        }
    }

    #[test]
    fn a_stopped_array_is_stopped_whatever_else_it_says() {
        let mut md = array();
        md.active = false;
        md.working = Some(0);
        md.members[0].failed = true;
        assert_eq!(state_of(&md), State::Stopped);
    }

    #[test]
    fn the_empty_slots_count_when_the_kernel_printed_no_count() {
        let mut md = array();
        md.configured = None;
        md.working = None;
        md.health = Some("U_".to_string());
        assert_eq!(missing(&md), 1);
        md.health = Some("__U".to_string());
        assert_eq!(missing(&md), 2);
        md.health = Some("UU".to_string());
        assert_eq!(missing(&md), 0);
        md.health = None;
        assert_eq!(missing(&md), 0);
        // With a count, the count decides.
        md.configured = Some(3);
        md.working = Some(1);
        md.health = Some("UU".to_string());
        assert_eq!(missing(&md), 2);
        md.working = Some(5);
        assert_eq!(missing(&md), 0);
        // One number alone is not a count.
        md.working = None;
        assert_eq!(missing(&md), 0);
    }

    // --- the finding -----------------------------------------------------

    #[test]
    fn a_healthy_array_is_information_with_its_facts() {
        let f = array_finding(&one(HEALTHY));
        assert_eq!(f.id, "STOR005");
        assert_eq!(f.title, "RAID Array \u{2014} md0");
        assert_eq!(f.instance.as_deref(), Some("md0"));
        assert_eq!(f.severity, Severity::Info);
        assert_eq!(f.confidence.percent, 100);
        assert_eq!(
            f.explanation,
            "md0 (raid1) is healthy: all 2 devices are up."
        );
        assert_eq!(f.recommendation, None);
        assert_eq!(evidence(&f, "array"), Some("md0"));
        assert_eq!(evidence(&f, "state"), Some("active"));
        assert_eq!(evidence(&f, "level"), Some("raid1"));
        assert_eq!(evidence(&f, "members"), Some("sdb1, sda1"));
        assert_eq!(evidence(&f, "devices_configured"), Some("2"));
        assert_eq!(evidence(&f, "devices_working"), Some("2"));
        assert_eq!(evidence(&f, "status"), Some("UU"));
        assert_eq!(evidence(&f, "failed_members"), None);
        assert_eq!(evidence(&f, "spare_members"), None);
        assert_eq!(evidence(&f, "activity"), None);
    }

    #[test]
    fn an_array_without_a_count_says_how_many_members_it_has() {
        let md = one(
            "md4 : active raid0 sdb[1] sda[0]\n      1953260032 blocks super 1.2 512k chunks\n",
        );
        let f = array_finding(&md);
        assert_eq!(f.severity, Severity::Info);
        assert_eq!(f.explanation, "md4 (raid0) is active with 2 members.");
        assert_eq!(evidence(&f, "devices_configured"), None);
        assert_eq!(evidence(&f, "status"), None);
    }

    #[test]
    fn a_rebuild_says_how_far_it_is_and_how_long_it_has_to_go() {
        let f = array_finding(&one(REBUILDING));
        assert_eq!(f.severity, Severity::Warning);
        assert_eq!(
            f.explanation,
            "md1 (raid5) is rebuilding onto a new device (3 of 4 devices up; recovery \
             12.6%, about 60 min left). It has no redundancy until the rebuild ends."
        );
        assert_eq!(evidence(&f, "activity"), Some("recovery 12.6%"));
        assert_eq!(evidence(&f, "status"), Some("UUU_"));
        let rec = f.recommendation.unwrap();
        assert!(rec.contains("Let the rebuild finish"), "{rec}");
        assert!(rec.contains("\n    watch -n 5 cat /proc/mdstat"), "{rec}");
        assert!(rec.contains("\n    sudo mdadm --detail /dev/md1"), "{rec}");
        assert!(rec.starts_with("1. Make sure what matters"), "{rec}");
        // Nothing failed, so nothing to remove or add.
        assert!(!rec.contains("--remove"), "{rec}");
        assert!(!rec.contains("--add"), "{rec}");
    }

    #[test]
    fn a_rebuild_without_a_time_does_not_invent_one() {
        let mut md = one(REBUILDING);
        md.progress.as_mut().unwrap().finish_minutes = None;
        let f = array_finding(&md);
        assert!(
            f.explanation.contains("recovery 12.6%)."),
            "{}",
            f.explanation
        );
        assert!(!f.explanation.contains("left"), "{}", f.explanation);
    }

    #[test]
    fn a_degraded_array_names_the_failed_disk_and_what_to_do() {
        let f = array_finding(&one(FAILED));
        assert_eq!(f.severity, Severity::Error);
        assert_eq!(
            f.explanation,
            "md2 (raid1) is running without its full set of devices (1 of 2 devices up, \
             failed: sdb1), so it has no redundancy left: one more failure loses data, \
             and no rebuild is running."
        );
        assert_eq!(evidence(&f, "failed_members"), Some("sdb1"));
        let rec = f.recommendation.unwrap();
        assert!(rec.starts_with("1. Make sure what matters"), "{rec}");
        for command in [
            "\n    sudo mdadm --detail /dev/md2",
            "\n    sudo smartctl -a /dev/sdb",
            "\n    sudo mdadm /dev/md2 --remove failed",
            "\n    sudo mdadm /dev/md2 --add /dev/<partition>",
            "\n    watch -n 5 cat /proc/mdstat",
        ] {
            assert!(rec.contains(command), "{command}\n{rec}");
        }
        let at = |needle: &str| rec.find(needle).unwrap();
        assert!(at("--detail") < at("smartctl"));
        assert!(at("smartctl") < at("--remove"));
        assert!(at("--remove") < at("--add"));
        assert!(!rec.contains("lsblk"), "{rec}");
    }

    #[test]
    fn a_missing_device_that_is_not_marked_failed_is_looked_for_not_removed() {
        let mut md = array();
        md.working = Some(1);
        md.health = Some("U_".to_string());
        let f = array_finding(&md);
        assert_eq!(f.severity, Severity::Error);
        assert!(
            f.explanation.contains("(1 of 2 devices up)"),
            "{}",
            f.explanation
        );
        let rec = f.recommendation.unwrap();
        assert!(
            rec.contains("\n    lsblk -o NAME,SIZE,MODEL,SERIAL"),
            "{rec}"
        );
        assert!(
            rec.contains("\n    sudo mdadm /dev/md0 --add /dev/<partition>"),
            "{rec}"
        );
        assert!(!rec.contains("--remove"), "{rec}");
        assert!(!rec.contains("smartctl"), "{rec}");
    }

    #[test]
    fn without_a_count_the_status_tells_how_short_the_array_is() {
        let mut md = array();
        md.configured = None;
        md.working = None;
        md.health = Some("U_".to_string());
        let f = array_finding(&md);
        assert!(f.explanation.contains("(status [U_])"), "{}", f.explanation);
        md.health = None;
        md.members[1].failed = true;
        md.progress = None;
        // Nothing says it is short: whole, with a failed device still listed.
        assert_eq!(state_of(&md), State::Replaced);
        assert_eq!(devices_up(&md), "some devices missing");
    }

    #[test]
    fn an_array_that_took_a_spare_asks_for_the_failed_disk_to_be_replaced() {
        let md = one("md2 : active raid1 sdc1[2] sdb1[1](F) sda1[0]\n  1 blocks [2/2] [UU]\n");
        let f = array_finding(&md);
        assert_eq!(f.severity, Severity::Warning);
        assert_eq!(
            f.explanation,
            "md2 (raid1) is complete again, but sdb1 is still attached to it as failed: a \
             spare took its place. The failed disk has to be removed and replaced before the \
             next failure."
        );
        let rec = f.recommendation.unwrap();
        assert!(!rec.contains("Make sure what matters"), "{rec}");
        assert!(rec.starts_with("1. See the state"), "{rec}");
        assert!(rec.contains("\n    sudo smartctl -a /dev/sdb"), "{rec}");
        assert!(
            rec.contains("\n    sudo mdadm /dev/md2 --remove failed"),
            "{rec}"
        );
        assert!(
            rec.contains("\n    sudo mdadm /dev/md2 --add /dev/<partition>"),
            "{rec}"
        );
        assert!(!rec.contains("watch"), "{rec}");
    }

    #[test]
    fn a_check_in_progress_on_a_whole_array_is_only_information() {
        let md = one("md0 : active raid1 sdb1[1] sda1[0]\n  1 blocks [2/2] [UU]\n  [>....]  check = 42.0% (1/2) finish=70.5min speed=1K/sec\n");
        let f = array_finding(&md);
        assert_eq!(f.severity, Severity::Info);
        assert_eq!(
            f.explanation,
            "md0 (raid1) is healthy (2 of 2 devices up); a check is running, 42.0% done."
        );
        assert_eq!(evidence(&f, "activity"), Some("check 42.0%"));
        assert_eq!(f.recommendation, None);
    }

    #[test]
    fn a_waiting_resync_is_said_to_wait() {
        let mut md = array();
        md.progress = Some(Progress {
            work: Work::Resync,
            percent: None,
            finish_minutes: None,
        });
        let f = array_finding(&md);
        assert_eq!(evidence(&f, "activity"), Some("resync waiting"));
    }

    #[test]
    fn an_inactive_array_is_not_to_be_forced_to_start() {
        let md = one("md3 : inactive sdc1[0](S) sdd1[1](S)\n      1953260032 blocks super 1.2\n");
        let f = array_finding(&md);
        assert_eq!(f.severity, Severity::Error);
        assert_eq!(evidence(&f, "state"), Some("inactive"));
        assert_eq!(evidence(&f, "spare_members"), Some("sdc1, sdd1"));
        assert_eq!(
            f.explanation,
            "md3 is inactive: the kernel sees its members (sdc1, sdd1) but has not started \
             the array, so nothing stored on it can be reached."
        );
        let rec = f.recommendation.unwrap();
        assert!(rec.starts_with("1. See the state"), "{rec}");
        assert!(rec.contains("\n    sudo mdadm --detail /dev/md3"), "{rec}");
        assert!(
            rec.contains("\n    sudo mdadm --examine /dev/sdc1"),
            "{rec}"
        );
        assert!(
            rec.contains("\n    sudo mdadm --examine /dev/sdd1"),
            "{rec}"
        );
        assert!(rec.contains("Do not force the array to start"), "{rec}");
        for absent in [
            "--add",
            "--remove",
            "smartctl",
            "lsblk",
            "Make sure what matters",
        ] {
            assert!(!rec.contains(absent), "{absent}\n{rec}");
        }
    }

    #[test]
    fn an_inactive_array_with_no_member_to_examine_has_no_examine_step() {
        let mut md = array();
        md.active = false;
        md.members.clear();
        let rec = array_finding(&md).recommendation.unwrap();
        assert!(!rec.contains("--examine"), "{rec}");
        assert!(!rec.contains("event count"), "{rec}");
        assert!(rec.contains("Do not force"), "{rec}");
    }

    #[test]
    fn at_most_four_members_are_examined() {
        let mut md = array();
        md.active = false;
        md.members = (0..9)
            .map(|i| member(&format!("sd{}1", (b'a' + i) as char)))
            .collect();
        let rec = array_finding(&md).recommendation.unwrap();
        assert_eq!(rec.matches("--examine").count(), 4);
        assert!(rec.contains("/dev/sdd1"), "{rec}");
        assert!(!rec.contains("/dev/sde1"), "{rec}");
    }

    #[test]
    fn names_that_are_not_safe_in_a_command_are_not_put_in_one() {
        let mut md = array();
        md.name = "md0;reboot".to_string();
        md.members = vec![member("sda1;halt"), failed("sdb1 x")];
        md.working = Some(1);
        let rec = array_finding(&md).recommendation.unwrap();
        assert!(!rec.contains("reboot") && !rec.contains("halt"), "{rec}");
        assert!(
            rec.contains("\n    sudo mdadm --detail /dev/<array>"),
            "{rec}"
        );
        assert!(rec.contains("\n    sudo smartctl --scan"), "{rec}");
        md.active = false;
        let rec = array_finding(&md).recommendation.unwrap();
        assert!(!rec.contains("reboot") && !rec.contains("halt"), "{rec}");
        assert!(!rec.contains("--examine"), "{rec}");
    }

    #[test]
    fn each_failed_disk_is_asked_once_and_only_whole_disks_are() {
        let mut md = array();
        md.members = vec![
            failed("sda1"),
            failed("sda2"),
            failed("nvme0n1p3"),
            failed("dm-3"),
            failed("sdb1"),
            failed("sdc1"),
            failed("sdd1"),
            failed("sde1"),
        ];
        md.working = Some(0);
        let rec = array_finding(&md).recommendation.unwrap();
        assert_eq!(rec.matches("smartctl -a").count(), 4, "{rec}");
        assert!(rec.contains("\n    sudo smartctl -a /dev/sda\n"), "{rec}");
        assert!(
            rec.contains("\n    sudo smartctl -a /dev/nvme0n1\n"),
            "{rec}"
        );
        assert!(!rec.contains("/dev/sda1"), "{rec}");
        assert!(!rec.contains("dm-3"), "{rec}");
        let mut md = array();
        md.members = vec![failed("dm-3")];
        md.working = Some(1);
        let rec = array_finding(&md).recommendation.unwrap();
        assert!(rec.contains("\n    sudo smartctl --scan"), "{rec}");
    }

    #[test]
    fn the_members_shown_are_cut_after_sixteen() {
        let mut md = array();
        md.members = (0..20).map(|i| member(&format!("sdz{i}"))).collect();
        let f = array_finding(&md);
        let shown = evidence(&f, "members").unwrap();
        assert_eq!(shown.split(", ").count(), 16);
        assert!(shown.ends_with("sdz15"), "{shown}");
        md.working = Some(1);
        md.members.iter_mut().for_each(|m| m.failed = true);
        let f = array_finding(&md);
        assert_eq!(
            evidence(&f, "failed_members").unwrap().split(", ").count(),
            16
        );
    }
}
