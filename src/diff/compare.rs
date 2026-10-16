// SPDX-License-Identifier: GPL-3.0-only

//! Comparing two reports. Pure: no I/O, no clock, so every rule below is
//! tested against small literal reports.
//!
//! # How a finding is identified
//!
//! By module, finding id and instance (the specific disk, socket, service
//! or account the finding is about). The title and the evidence are *not*
//! part of the identity: they carry measurements that change from one run
//! to the next, and a finding whose numbers moved is the same finding.
//!
//! # What "resolved" is allowed to mean
//!
//! A finding missing from the second report is only *resolved* when the
//! module that would have reported it ran to completion in that report. If
//! the module failed, was skipped, was not run at all, or had a command cut
//! short, nothing can be concluded: the module is listed as *not compared*
//! (or the change is marked as doubtful) instead. The same holds for a
//! finding that appears *new* because the first report could not see it.
//! This is the report-level version of the rule the audit itself follows:
//! something nobody checked is never presented as fine.

use std::collections::HashMap;

use serde::Serialize;

use crate::models::Severity;
use crate::output::common::format_utc;

use super::report::{ContextFile, FindingFile, ModuleFile, ReportFile};

/// Reboots are told apart from clock jitter by this many seconds.
const REBOOT_TOLERANCE_SECS: u64 = 60;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Side {
    Before,
    After,
}

impl Side {
    pub fn word(self) -> &'static str {
        match self {
            Side::Before => "before",
            Side::After => "after",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ChangeKind {
    /// In the second report only.
    New,
    /// In the first report only.
    Resolved,
    /// In both, at a higher severity in the second.
    Worse,
    /// In both, at a lower severity in the second.
    Better,
}

/// The heading a change is shown under.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Section {
    Worse,
    Better,
    /// Informational findings that appeared or disappeared: inventory
    /// changes, not problems.
    Other,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct EvidenceChange {
    pub key: String,
    pub before: Option<String>,
    pub after: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Change {
    pub kind: ChangeKind,
    pub module_id: String,
    pub id: String,
    pub instance: Option<String>,
    pub title: String,
    pub before: Option<Severity>,
    pub after: Option<Severity>,
    /// What moved in the finding's evidence. Only filled in for findings
    /// present in both reports (`Worse` and `Better`), where it explains the
    /// change in severity.
    pub evidence: Vec<EvidenceChange>,
    /// Set when incomplete data in this report makes the change uncertain:
    /// a *resolved* finding the second report may simply not have seen, or a
    /// *new* one the first report may have missed.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub doubt: Option<Side>,
}

impl Change {
    /// The severity this change is about: what the finding is now or, for a
    /// resolved one, what it was.
    pub fn severity(&self) -> Severity {
        self.after.or(self.before).unwrap_or(Severity::Info)
    }

    /// The worse of the two severities, for the display filter.
    fn highest(&self) -> Severity {
        self.before.max(self.after).unwrap_or(Severity::Info)
    }

    pub fn section(&self) -> Section {
        match self.kind {
            ChangeKind::Worse => Section::Worse,
            ChangeKind::Better => Section::Better,
            ChangeKind::New if self.severity() > Severity::Info => Section::Worse,
            ChangeKind::Resolved if self.severity() > Severity::Info => Section::Better,
            ChangeKind::New | ChangeKind::Resolved => Section::Other,
        }
    }
}

/// The facts about a machine that a report records.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct MachineFacts {
    pub hostname: String,
    pub distro: Option<String>,
    pub kernel_version: String,
    pub architecture: String,
    pub cpu_count: u64,
    pub mem_total_kb: u64,
    pub boot_time_unix: u64,
}

impl From<&ContextFile> for MachineFacts {
    fn from(c: &ContextFile) -> Self {
        MachineFacts {
            hostname: c.hostname.clone(),
            distro: c.distro.clone(),
            kernel_version: c.kernel_version.clone(),
            architecture: c.architecture.clone(),
            cpu_count: c.cpu_count,
            mem_total_kb: c.mem_total_kb,
            boot_time_unix: c.boot_time_unix,
        }
    }
}

/// One fact that differs between the two machines' records.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct FactChange {
    pub fact: &'static str,
    pub before: String,
    pub after: String,
}

/// Something the reader must know to judge how far the comparison can be
/// trusted.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Caveat {
    /// The two reports do not describe the same machine.
    DifferentMachines { before: String, after: String },
    /// The second report was taken during an earlier boot than the first on
    /// the same machine, which cannot happen if they are in order.
    ReportsLookReversed,
    /// At least one report was written with `--min-severity`, so findings
    /// below `floor` exist in neither side of the comparison.
    Filtered {
        floor: Severity,
        before: Option<Severity>,
        after: Option<Severity>,
    },
    /// The two reports were not written by the same version of LinuxDoctor.
    /// Checks are added and thresholds move between versions, so a finding
    /// that appeared or disappeared may come from the program, not from the
    /// machine. `None` is a report that does not record its version (an
    /// older one): next to a recorded version that is a different version
    /// for certain, since every version after the change records it. Two
    /// reports that both lack it say nothing, and raise no caveat.
    DifferentVersions {
        before: Option<String>,
        after: Option<String>,
    },
    /// The two reports were not written with the same profile. A profile
    /// lowers the severity of readings that are normal for a kind of
    /// machine, so a finding that "got better" or "got worse" may come from
    /// the profile, not from the machine. `None` is no profile -- also what
    /// a report from a version without profiles is -- so, unlike a missing
    /// version, it is a real value and is compared like the others.
    DifferentProfiles {
        before: Option<String>,
        after: Option<String>,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Incomplete {
    pub side: Side,
    pub notes: Vec<String>,
}

/// A module that ran to the end in both reports.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ComparedModule {
    pub module_id: String,
    pub changes: Vec<Change>,
    pub unchanged: usize,
    /// Sides where a command was cut short (the module's data may be
    /// incomplete), with the notes saying which.
    pub incomplete: Vec<Incomplete>,
}

/// How a module stood in one report.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "state", rename_all = "snake_case")]
pub enum Availability {
    Ran,
    Skipped,
    Failed {
        error: String,
    },
    /// The report has no entry for the module (it was not run, for instance
    /// with `--modules`).
    Missing,
}

/// A module whose findings cannot be compared because one report has
/// nothing trustworthy to compare against.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct NotCompared {
    pub module_id: String,
    pub before: Availability,
    pub after: Availability,
    pub findings_before: usize,
    pub findings_after: usize,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize)]
pub struct Totals {
    pub new: usize,
    pub resolved: usize,
    pub worse: usize,
    pub better: usize,
    pub unchanged: usize,
    pub not_compared: usize,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Comparison {
    pub before: MachineFacts,
    pub after: MachineFacts,
    pub machine_changes: Vec<FactChange>,
    pub rebooted: bool,
    pub caveats: Vec<Caveat>,
    /// The lowest severity that was compared (`info` unless a report was
    /// filtered).
    pub floor: Severity,
    pub compared: Vec<ComparedModule>,
    pub not_compared: Vec<NotCompared>,
    /// Modules that were skipped (not applicable here) in both reports.
    pub skipped_in_both: Vec<String>,
    /// Changes removed from `compared` by [`Comparison::retain_at_or_above`].
    pub hidden: usize,
    /// The severity that display filter used, when one was applied.
    pub hidden_below: Option<Severity>,
}

impl Comparison {
    pub fn changes(&self) -> impl Iterator<Item = &Change> {
        self.compared.iter().flat_map(|m| m.changes.iter())
    }

    /// The changes shown under `section`, worst first; within one severity,
    /// in the order of the modules.
    pub fn changes_in(&self, section: Section) -> Vec<&Change> {
        let mut changes: Vec<&Change> = self.changes().filter(|c| c.section() == section).collect();
        changes.sort_by_key(|c| std::cmp::Reverse(c.severity()));
        changes
    }

    pub fn totals(&self) -> Totals {
        let mut totals = Totals {
            not_compared: self.not_compared.len(),
            unchanged: self.compared.iter().map(|m| m.unchanged).sum(),
            ..Totals::default()
        };
        for change in self.changes() {
            match change.kind {
                ChangeKind::New => totals.new += 1,
                ChangeKind::Resolved => totals.resolved += 1,
                ChangeKind::Worse => totals.worse += 1,
                ChangeKind::Better => totals.better += 1,
            }
        }
        totals
    }

    /// The findings that got worse, or appeared, at `threshold` or above:
    /// what makes `diff` fail its exit status. A finding that is merely
    /// still there, however severe, is the business of `audit --fail-on`,
    /// not of a comparison. Judged on the whole comparison, before any
    /// display filter.
    pub fn regressions(&self, threshold: Severity) -> Vec<&Change> {
        self.changes()
            .filter(|c| matches!(c.kind, ChangeKind::New | ChangeKind::Worse))
            .filter(|c| c.after.is_some_and(|s| s >= threshold))
            .collect()
    }

    /// Display filter: drops the changes whose finding never reached `min`
    /// in either report, and returns how many it dropped (also kept in
    /// `hidden`). Modules that were not compared stay listed: nothing about
    /// whether the comparison worked is ever hidden.
    pub fn retain_at_or_above(&mut self, min: Severity) -> usize {
        let mut dropped = 0;
        for module in &mut self.compared {
            let before = module.changes.len();
            module.changes.retain(|c| c.highest() >= min);
            dropped += before - module.changes.len();
        }
        self.hidden += dropped;
        self.hidden_below = Some(min);
        dropped
    }
}

/// Compares two reports, `before` being the earlier one.
pub fn compare(before: &ReportFile, after: &ReportFile) -> Comparison {
    let floor = before
        .filter
        .map(|f| f.min_severity)
        .max(after.filter.map(|f| f.min_severity))
        .unwrap_or(Severity::Info);

    let mut caveats = Vec::new();
    let before_facts = MachineFacts::from(&before.context);
    let after_facts = MachineFacts::from(&after.context);
    let (machine_changes, rebooted) = machine_changes(&before_facts, &after_facts);

    let same_name = before_facts
        .hostname
        .eq_ignore_ascii_case(&after_facts.hostname);
    if !same_name || before_facts.architecture != after_facts.architecture {
        caveats.push(Caveat::DifferentMachines {
            before: before_facts.hostname.clone(),
            after: after_facts.hostname.clone(),
        });
    } else if before_facts.boot_time_unix != 0
        && after_facts.boot_time_unix + REBOOT_TOLERANCE_SECS < before_facts.boot_time_unix
    {
        caveats.push(Caveat::ReportsLookReversed);
    }
    if floor > Severity::Info {
        caveats.push(Caveat::Filtered {
            floor,
            before: before.filter.map(|f| f.min_severity),
            after: after.filter.map(|f| f.min_severity),
        });
    }
    if written_by_different_versions(
        before.linuxdoctor_version.as_deref(),
        after.linuxdoctor_version.as_deref(),
    ) {
        caveats.push(Caveat::DifferentVersions {
            before: before.linuxdoctor_version.clone(),
            after: after.linuxdoctor_version.clone(),
        });
    }
    if before.profile != after.profile {
        caveats.push(Caveat::DifferentProfiles {
            before: before.profile.clone(),
            after: after.profile.clone(),
        });
    }

    let mut comparison = Comparison {
        before: before_facts,
        after: after_facts,
        machine_changes,
        rebooted,
        caveats,
        floor,
        compared: Vec::new(),
        not_compared: Vec::new(),
        skipped_in_both: Vec::new(),
        hidden: 0,
        hidden_below: None,
    };

    // Modules in the order of the second report, then those only the first
    // one has. The first entry wins if a report repeats a module.
    let before_modules = by_id(&before.results);
    let after_modules = by_id(&after.results);
    let ids = after
        .results
        .iter()
        .map(|m| m.module_id.as_str())
        .chain(before.results.iter().map(|m| m.module_id.as_str()));
    let mut seen = std::collections::HashSet::new();
    for id in ids {
        if !seen.insert(id) {
            continue;
        }
        let b = before_modules.get(id).copied();
        let a = after_modules.get(id).copied();
        compare_module(&mut comparison, id, b, a);
    }
    comparison
}

/// Whether two reports certainly come from different versions of the
/// program. A report without a version predates the field, so next to one
/// that has it the versions differ; two without cannot be told apart.
fn written_by_different_versions(before: Option<&str>, after: Option<&str>) -> bool {
    match (before, after) {
        (Some(b), Some(a)) => b != a,
        (None, None) => false,
        _ => true,
    }
}

fn by_id(modules: &[ModuleFile]) -> HashMap<&str, &ModuleFile> {
    let mut map = HashMap::new();
    for module in modules {
        map.entry(module.module_id.as_str()).or_insert(module);
    }
    map
}

fn availability(module: Option<&ModuleFile>) -> Availability {
    match module {
        None => Availability::Missing,
        Some(m) if m.skipped => Availability::Skipped,
        Some(m) => match &m.error {
            Some(error) => Availability::Failed {
                error: error.clone(),
            },
            None => Availability::Ran,
        },
    }
}

fn compare_module(
    comparison: &mut Comparison,
    id: &str,
    before: Option<&ModuleFile>,
    after: Option<&ModuleFile>,
) {
    let (state_before, state_after) = (availability(before), availability(after));
    let floor = comparison.floor;
    let count = |m: Option<&ModuleFile>| {
        m.map_or(0, |m| {
            m.findings.iter().filter(|f| f.severity >= floor).count()
        })
    };

    match (&state_before, &state_after, before, after) {
        (Availability::Ran, Availability::Ran, Some(b), Some(a)) => {
            let compared = compare_findings(id, b, a, floor);
            comparison.compared.push(compared);
        }
        (Availability::Skipped, Availability::Skipped, _, _) => {
            comparison.skipped_in_both.push(id.to_string());
        }
        _ => comparison.not_compared.push(NotCompared {
            module_id: id.to_string(),
            before: state_before,
            after: state_after,
            findings_before: count(before),
            findings_after: count(after),
        }),
    }
}

fn compare_findings(
    module_id: &str,
    before: &ModuleFile,
    after: &ModuleFile,
    floor: Severity,
) -> ComparedModule {
    let mut incomplete = Vec::new();
    if !before.notes.is_empty() {
        incomplete.push(Incomplete {
            side: Side::Before,
            notes: before.notes.clone(),
        });
    }
    if !after.notes.is_empty() {
        incomplete.push(Incomplete {
            side: Side::After,
            notes: after.notes.clone(),
        });
    }
    let before_incomplete = !before.notes.is_empty();
    let after_incomplete = !after.notes.is_empty();

    let before_groups = group(&before.findings, floor);
    let after_groups = group(&after.findings, floor);
    let before_index: HashMap<Key, usize> = before_groups
        .iter()
        .enumerate()
        .map(|(i, (key, _))| (*key, i))
        .collect();
    let after_index: HashMap<Key, usize> = after_groups
        .iter()
        .enumerate()
        .map(|(i, (key, _))| (*key, i))
        .collect();

    let mut changes = Vec::new();
    let mut unchanged = 0;

    let mut visit = |key: Key, b: &[&FindingFile], a: &[&FindingFile]| {
        let (pairs, only_before, only_after) = pair(b, a);
        for (b, a) in pairs {
            if a.severity == b.severity {
                unchanged += 1;
                continue;
            }
            let kind = if a.severity > b.severity {
                ChangeKind::Worse
            } else {
                ChangeKind::Better
            };
            changes.push(Change {
                kind,
                module_id: module_id.to_string(),
                id: key.0.to_string(),
                instance: key.1.map(str::to_string),
                title: a.title.clone(),
                before: Some(b.severity),
                after: Some(a.severity),
                evidence: evidence_changes(&b.evidence, &a.evidence),
                doubt: None,
            });
        }
        for f in only_after {
            changes.push(Change {
                kind: ChangeKind::New,
                module_id: module_id.to_string(),
                id: key.0.to_string(),
                instance: key.1.map(str::to_string),
                title: f.title.clone(),
                before: None,
                after: Some(f.severity),
                evidence: Vec::new(),
                doubt: before_incomplete.then_some(Side::Before),
            });
        }
        for f in only_before {
            changes.push(Change {
                kind: ChangeKind::Resolved,
                module_id: module_id.to_string(),
                id: key.0.to_string(),
                instance: key.1.map(str::to_string),
                title: f.title.clone(),
                before: Some(f.severity),
                after: None,
                evidence: Vec::new(),
                doubt: after_incomplete.then_some(Side::After),
            });
        }
    };

    for (key, a) in &after_groups {
        let b: &[&FindingFile] = before_index
            .get(key)
            .map_or(&[], |&i| before_groups[i].1.as_slice());
        visit(*key, b, a);
    }
    for (key, b) in &before_groups {
        if !after_index.contains_key(key) {
            visit(*key, b, &[]);
        }
    }

    ComparedModule {
        module_id: module_id.to_string(),
        changes,
        unchanged,
        incomplete,
    }
}

type Key<'a> = (&'a str, Option<&'a str>);

/// Findings at or above `floor`, grouped by (id, instance), in the order the
/// keys first appear.
fn group(findings: &[FindingFile], floor: Severity) -> Vec<(Key<'_>, Vec<&FindingFile>)> {
    let mut index: HashMap<Key, usize> = HashMap::new();
    let mut groups: Vec<(Key, Vec<&FindingFile>)> = Vec::new();
    for finding in findings.iter().filter(|f| f.severity >= floor) {
        let key = (finding.id.as_str(), finding.instance.as_deref());
        match index.get(&key) {
            Some(&i) => groups[i].1.push(finding),
            None => {
                index.insert(key, groups.len());
                groups.push((key, vec![finding]));
            }
        }
    }
    groups
}

type Pairs<'a> = Vec<(&'a FindingFile, &'a FindingFile)>;

/// Pairs the findings that share one key. Almost always there is exactly one
/// on each side; when a module reports several findings under one key, those
/// with the same title are paired first, then the rest in order, and
/// whatever is left over is new or resolved.
fn pair<'a>(
    before: &[&'a FindingFile],
    after: &[&'a FindingFile],
) -> (Pairs<'a>, Vec<&'a FindingFile>, Vec<&'a FindingFile>) {
    if before.len() == 1 && after.len() == 1 {
        return (vec![(before[0], after[0])], Vec::new(), Vec::new());
    }
    let mut unused_before: Vec<&FindingFile> = before.to_vec();
    let mut pairs = Vec::new();
    let mut unmatched_after = Vec::new();
    for &a in after {
        match unused_before.iter().position(|b| b.title == a.title) {
            Some(i) => pairs.push((unused_before.remove(i), a)),
            None => unmatched_after.push(a),
        }
    }
    let mut only_after = Vec::new();
    for a in unmatched_after {
        if unused_before.is_empty() {
            only_after.push(a);
        } else {
            pairs.push((unused_before.remove(0), a));
        }
    }
    (pairs, unused_before, only_after)
}

fn evidence_changes(
    before: &[(String, String)],
    after: &[(String, String)],
) -> Vec<EvidenceChange> {
    let find = |list: &[(String, String)], key: &str| {
        list.iter().find(|(k, _)| k == key).map(|(_, v)| v.clone())
    };
    let mut keys: Vec<&str> = after.iter().map(|(k, _)| k.as_str()).collect();
    for (k, _) in before {
        if !keys.contains(&k.as_str()) {
            keys.push(k);
        }
    }
    keys.into_iter()
        .filter_map(|key| {
            let (b, a) = (find(before, key), find(after, key));
            (b != a).then(|| EvidenceChange {
                key: key.to_string(),
                before: b,
                after: a,
            })
        })
        .collect()
}

fn machine_changes(before: &MachineFacts, after: &MachineFacts) -> (Vec<FactChange>, bool) {
    let mut changes = Vec::new();
    let mut push = |fact: &'static str, b: String, a: String| {
        if b != a {
            changes.push(FactChange {
                fact,
                before: b,
                after: a,
            });
        }
    };
    push("hostname", before.hostname.clone(), after.hostname.clone());
    push(
        "distribution",
        before.distro.clone().unwrap_or_else(|| "unknown".into()),
        after.distro.clone().unwrap_or_else(|| "unknown".into()),
    );
    push(
        "kernel",
        before.kernel_version.clone(),
        after.kernel_version.clone(),
    );
    push(
        "architecture",
        before.architecture.clone(),
        after.architecture.clone(),
    );
    push(
        "CPUs",
        before.cpu_count.to_string(),
        after.cpu_count.to_string(),
    );
    push(
        "memory",
        format!("{} MB", before.mem_total_kb / 1024),
        format!("{} MB", after.mem_total_kb / 1024),
    );

    let rebooted = before.boot_time_unix != 0
        && after.boot_time_unix != 0
        && before.boot_time_unix.abs_diff(after.boot_time_unix) > REBOOT_TOLERANCE_SECS;
    if rebooted {
        changes.push(FactChange {
            fact: "booted",
            before: format_utc(before.boot_time_unix),
            after: format_utc(after.boot_time_unix),
        });
    }
    (changes, rebooted)
}

#[cfg(test)]
pub(crate) mod testkit {
    //! Small literal reports for the tests of this module and of `render`.

    use super::super::report::{parse, ReportFile};
    use serde_json::{json, Value};

    /// `(finding id, instance, severity word)`.
    pub type Spec<'a> = (&'a str, Option<&'a str>, &'a str);

    pub fn finding(spec: Spec) -> Value {
        json!({
            "id": spec.0,
            "title": format!("Title of {}", spec.0),
            "severity": spec.2,
            "evidence": [],
            "instance": spec.1,
        })
    }

    pub fn module(id: &str, findings: &[Spec]) -> Value {
        json!({
            "module_id": id,
            "findings": findings.iter().map(|s| finding(*s)).collect::<Vec<_>>(),
            "error": null,
            "skipped": false,
            "notes": [],
        })
    }

    pub fn failed(id: &str, error: &str) -> Value {
        json!({"module_id": id, "findings": [], "error": error, "skipped": false, "notes": []})
    }

    pub fn skipped(id: &str) -> Value {
        json!({"module_id": id, "findings": [], "error": null, "skipped": true, "notes": []})
    }

    pub fn with_notes(mut module: Value, notes: &[&str]) -> Value {
        module["notes"] = json!(notes);
        module
    }

    pub fn with_evidence(mut module: Value, finding_index: usize, pairs: &[(&str, &str)]) -> Value {
        module["findings"][finding_index]["evidence"] =
            json!(pairs.iter().map(|(k, v)| json!([k, v])).collect::<Vec<_>>());
        module
    }

    pub fn report_on(host: &str, boot: u64, modules: Vec<Value>) -> ReportFile {
        let value = json!({
            "schema_version": 1,
            "context": {
                "hostname": host, "kernel_version": "6.8.0-31", "distro": "Ubuntu 24.04",
                "architecture": "x86_64", "cpu_count": 4, "mem_total_kb": 8_388_608,
                "boot_time_unix": boot,
            },
            "results": modules,
        });
        parse(&value.to_string(), "test").expect("the test report is valid")
    }

    pub fn report(modules: Vec<Value>) -> ReportFile {
        report_on("web01", 1_000_000, modules)
    }

    /// The report as a given version of LinuxDoctor wrote it.
    pub fn by_version(mut report: ReportFile, version: &str) -> ReportFile {
        report.linuxdoctor_version = Some(version.to_string());
        report
    }

    /// The report as written with a given profile.
    pub fn with_profile(mut report: ReportFile, profile: &str) -> ReportFile {
        report.profile = Some(profile.to_string());
        report
    }

    pub fn filtered(mut report: ReportFile, min: crate::models::Severity) -> ReportFile {
        report.filter = Some(super::super::report::FilterFile { min_severity: min });
        report
    }
}

#[cfg(test)]
mod tests {
    use super::testkit::*;
    use super::*;

    fn changes_of(c: &Comparison) -> Vec<(ChangeKind, &str, &str)> {
        c.changes()
            .map(|c| (c.kind, c.module_id.as_str(), c.id.as_str()))
            .collect()
    }

    #[test]
    fn identical_reports_have_nothing_to_report() {
        let r = || {
            report(vec![module(
                "memory",
                &[("MEM001", None, "info"), ("MEM002", None, "warning")],
            )])
        };
        let c = compare(&r(), &r());
        assert_eq!(c.changes().count(), 0);
        assert_eq!(c.totals().unchanged, 2);
        assert!(c.not_compared.is_empty());
        assert!(c.caveats.is_empty());
        assert!(c.machine_changes.is_empty());
    }

    #[test]
    fn new_resolved_worse_and_better_are_told_apart() {
        let before = report(vec![module(
            "m",
            &[
                ("GONE", None, "error"),
                ("UP", None, "warning"),
                ("DOWN", None, "critical"),
                ("SAME", None, "warning"),
            ],
        )]);
        let after = report(vec![module(
            "m",
            &[
                ("UP", None, "error"),
                ("DOWN", None, "info"),
                ("SAME", None, "warning"),
                ("FRESH", None, "critical"),
            ],
        )]);
        let c = compare(&before, &after);
        assert_eq!(
            changes_of(&c),
            [
                (ChangeKind::Worse, "m", "UP"),
                (ChangeKind::Better, "m", "DOWN"),
                (ChangeKind::New, "m", "FRESH"),
                (ChangeKind::Resolved, "m", "GONE"),
            ]
        );
        let t = c.totals();
        assert_eq!(
            (t.new, t.resolved, t.worse, t.better, t.unchanged),
            (1, 1, 1, 1, 1)
        );
    }

    #[test]
    fn the_instance_is_part_of_the_identity() {
        // Two disks: one got worse, the other is untouched, a third is new.
        let before = report(vec![module(
            "storage",
            &[
                ("STOR001", Some("/"), "info"),
                ("STOR001", Some("/data"), "info"),
            ],
        )]);
        let after = report(vec![module(
            "storage",
            &[
                ("STOR001", Some("/"), "info"),
                ("STOR001", Some("/data"), "error"),
                ("STOR001", Some("/backup"), "info"),
            ],
        )]);
        let c = compare(&before, &after);
        let changes: Vec<_> = c
            .changes()
            .map(|c| (c.kind, c.instance.as_deref().unwrap()))
            .collect();
        assert_eq!(
            changes,
            [(ChangeKind::Worse, "/data"), (ChangeKind::New, "/backup")]
        );
        assert_eq!(c.totals().unchanged, 1);
    }

    #[test]
    fn sections_follow_what_the_reader_cares_about() {
        let before = report(vec![module(
            "m",
            &[
                ("OLDINFO", None, "info"),
                ("OLDBAD", None, "error"),
                ("TOINFO", None, "warning"),
            ],
        )]);
        let after = report(vec![module(
            "m",
            &[
                ("NEWINFO", None, "info"),
                ("NEWBAD", None, "warning"),
                ("TOINFO", None, "info"),
            ],
        )]);
        let c = compare(&before, &after);
        let ids = |s| -> Vec<&str> { c.changes_in(s).iter().map(|c| c.id.as_str()).collect() };
        assert_eq!(ids(Section::Worse), ["NEWBAD"]);
        assert_eq!(ids(Section::Better), ["OLDBAD", "TOINFO"]);
        assert_eq!(ids(Section::Other), ["NEWINFO", "OLDINFO"]);
    }

    #[test]
    fn a_section_lists_the_most_severe_first() {
        let before = report(vec![module("m", &[])]);
        let after = report(vec![module(
            "m",
            &[
                ("W", None, "warning"),
                ("C", None, "critical"),
                ("E", None, "error"),
            ],
        )]);
        let c = compare(&before, &after);
        let ids: Vec<_> = c
            .changes_in(Section::Worse)
            .iter()
            .map(|c| c.id.clone())
            .collect();
        assert_eq!(ids, ["C", "E", "W"]);
    }

    #[test]
    fn evidence_that_moved_explains_a_change_in_severity() {
        let b = with_evidence(
            module("m", &[("X", None, "warning")]),
            0,
            &[
                ("swap_used_kb", "100"),
                ("swappiness", "60"),
                ("only_before", "1"),
            ],
        );
        let a = with_evidence(
            module("m", &[("X", None, "error")]),
            0,
            &[
                ("swap_used_kb", "4200000"),
                ("swappiness", "60"),
                ("only_after", "2"),
            ],
        );
        let c = compare(&report(vec![b]), &report(vec![a]));
        let change = c.changes().next().unwrap();
        assert_eq!(
            change.evidence,
            [
                EvidenceChange {
                    key: "swap_used_kb".into(),
                    before: Some("100".into()),
                    after: Some("4200000".into())
                },
                EvidenceChange {
                    key: "only_after".into(),
                    before: None,
                    after: Some("2".into())
                },
                EvidenceChange {
                    key: "only_before".into(),
                    before: Some("1".into()),
                    after: None
                },
            ]
        );
    }

    #[test]
    fn a_finding_whose_numbers_moved_but_not_its_severity_is_unchanged() {
        let b = with_evidence(module("m", &[("X", None, "info")]), 0, &[("used", "10")]);
        let a = with_evidence(module("m", &[("X", None, "info")]), 0, &[("used", "99")]);
        let c = compare(&report(vec![b]), &report(vec![a]));
        assert_eq!(c.changes().count(), 0);
        assert_eq!(c.totals().unchanged, 1);
    }

    // ----- the rule: nothing unchecked is good news -------------------------------

    #[test]
    fn a_module_that_failed_later_does_not_resolve_its_findings() {
        let before = report(vec![module("network", &[("NET001", None, "error")])]);
        let after = report(vec![failed("network", "could not read /proc/net/dev")]);
        let c = compare(&before, &after);
        assert_eq!(c.changes().count(), 0, "nothing may be called resolved");
        assert_eq!(c.not_compared.len(), 1);
        let n = &c.not_compared[0];
        assert_eq!(n.module_id, "network");
        assert_eq!(n.before, Availability::Ran);
        assert!(
            matches!(&n.after, Availability::Failed { error } if error.contains("/proc/net/dev"))
        );
        assert_eq!((n.findings_before, n.findings_after), (1, 0));
    }

    #[test]
    fn a_module_that_failed_earlier_does_not_make_its_findings_new() {
        let before = report(vec![failed("network", "boom")]);
        let after = report(vec![module("network", &[("NET001", None, "critical")])]);
        let c = compare(&before, &after);
        assert_eq!(c.changes().count(), 0);
        assert_eq!(c.not_compared[0].findings_after, 1);
        // ... which also means it cannot be a "regression" for the exit status.
        assert!(c.regressions(Severity::Info).is_empty());
    }

    #[test]
    fn a_module_skipped_on_one_side_only_is_not_compared() {
        let before = report(vec![skipped("systemd")]);
        let after = report(vec![module("systemd", &[("SYS001", None, "error")])]);
        let c = compare(&before, &after);
        assert_eq!(c.changes().count(), 0);
        assert_eq!(c.not_compared[0].before, Availability::Skipped);
        assert_eq!(c.not_compared[0].after, Availability::Ran);
    }

    #[test]
    fn a_module_skipped_in_both_is_only_mentioned() {
        let r = || report(vec![skipped("numa"), module("cpu", &[])]);
        let c = compare(&r(), &r());
        assert_eq!(c.skipped_in_both, ["numa"]);
        assert!(c.not_compared.is_empty());
    }

    #[test]
    fn a_module_missing_from_one_report_is_not_compared() {
        // The first report was made with --modules memory.
        let before = report(vec![module("memory", &[("MEM001", None, "info")])]);
        let after = report(vec![
            module("memory", &[("MEM001", None, "info")]),
            module("security", &[("SEC002", None, "critical")]),
        ]);
        let c = compare(&before, &after);
        assert_eq!(c.changes().count(), 0);
        assert_eq!(c.not_compared.len(), 1);
        assert_eq!(c.not_compared[0].module_id, "security");
        assert_eq!(c.not_compared[0].before, Availability::Missing);
        // And the other way round, the module is listed once, from the first report.
        let c = compare(&after, &before);
        assert_eq!(c.not_compared[0].module_id, "security");
        assert_eq!(c.not_compared[0].after, Availability::Missing);
    }

    #[test]
    fn incomplete_data_makes_resolved_and_new_findings_doubtful_but_not_severity_changes() {
        let notes = ["`smartctl` stopped after 10 s"];
        let before = report(vec![module(
            "storage",
            &[("GONE", None, "error"), ("UP", None, "warning")],
        )]);
        let after = report(vec![with_notes(
            module(
                "storage",
                &[("UP", None, "error"), ("FRESH", None, "warning")],
            ),
            &notes,
        )]);
        let c = compare(&before, &after);
        let by_id = |id: &str| c.changes().find(|c| c.id == id).unwrap();
        assert_eq!(
            by_id("GONE").doubt,
            Some(Side::After),
            "may just not have been seen"
        );
        assert_eq!(by_id("UP").doubt, None, "seen on both sides");
        assert_eq!(by_id("FRESH").doubt, None, "the first report was complete");
        assert_eq!(c.compared[0].incomplete.len(), 1);
        assert_eq!(c.compared[0].incomplete[0].side, Side::After);

        // Incomplete *before*: a "new" finding may have been there all along.
        let c = compare(&after, &before);
        let fresh = c.changes().find(|c| c.id == "GONE").unwrap();
        assert_eq!(fresh.kind, ChangeKind::New);
        assert_eq!(fresh.doubt, Some(Side::Before));
    }

    #[test]
    fn a_filtered_report_is_compared_only_above_the_common_floor() {
        use crate::models::Severity::Warning;
        // The first report kept only warnings and worse; the second is complete.
        let before = filtered(
            report(vec![module("m", &[("W", None, "warning")])]),
            Warning,
        );
        let after = report(vec![module(
            "m",
            &[
                ("W", None, "warning"),
                ("I1", None, "info"),
                ("I2", None, "info"),
            ],
        )]);
        let c = compare(&before, &after);
        assert_eq!(c.floor, Warning);
        assert_eq!(
            c.changes().count(),
            0,
            "the Info findings were never visible before"
        );
        assert!(c.caveats.iter().any(|c| matches!(
            c,
            Caveat::Filtered {
                floor: Warning,
                before: Some(Warning),
                after: None
            }
        )));
    }

    // ----- the machines --------------------------------------------------------------

    #[test]
    fn a_kernel_update_and_a_reboot_are_reported_as_facts() {
        let before = report_on("web01", 1_000_000, vec![]);
        let mut after = report_on("web01", 1_900_000, vec![]);
        after.context.kernel_version = "6.8.0-40".into();
        let c = compare(&before, &after);
        let facts: Vec<_> = c.machine_changes.iter().map(|f| f.fact).collect();
        assert_eq!(facts, ["kernel", "booted"]);
        assert!(c.rebooted);
        assert!(c.caveats.is_empty());
    }

    #[test]
    fn boot_time_jitter_is_not_a_reboot() {
        let c = compare(
            &report_on("h", 1_000_000, vec![]),
            &report_on("h", 1_000_030, vec![]),
        );
        assert!(!c.rebooted);
        assert!(c.machine_changes.is_empty());
    }

    #[test]
    fn reports_from_two_machines_are_flagged() {
        let c = compare(
            &report_on("web01", 1_000_000, vec![]),
            &report_on("db02", 1_000_000, vec![]),
        );
        assert!(c.caveats.contains(&Caveat::DifferentMachines {
            before: "web01".into(),
            after: "db02".into()
        }));
    }

    #[test]
    fn reports_given_in_the_wrong_order_are_flagged() {
        // The "after" report was taken during an earlier boot.
        let c = compare(
            &report_on("web01", 2_000_000, vec![]),
            &report_on("web01", 1_000_000, vec![]),
        );
        assert!(c.caveats.contains(&Caveat::ReportsLookReversed));
    }

    // ----- the versions --------------------------------------------------------------

    fn version_caveat(c: &Comparison) -> Option<&Caveat> {
        c.caveats
            .iter()
            .find(|c| matches!(c, Caveat::DifferentVersions { .. }))
    }

    #[test]
    fn reports_from_two_versions_are_flagged() {
        let c = compare(
            &by_version(report(vec![]), "1.8.1"),
            &by_version(report(vec![]), "1.9.0"),
        );
        assert_eq!(
            version_caveat(&c),
            Some(&Caveat::DifferentVersions {
                before: Some("1.8.1".into()),
                after: Some("1.9.0".into())
            })
        );
    }

    #[test]
    fn two_reports_from_the_same_version_raise_nothing() {
        let c = compare(
            &by_version(report(vec![]), "1.9.0"),
            &by_version(report(vec![]), "1.9.0"),
        );
        assert!(c.caveats.is_empty(), "{:?}", c.caveats);
    }

    #[test]
    fn a_report_with_a_version_next_to_one_without_is_a_different_version() {
        // Every version that records the field is newer than every one that
        // does not, so one side having it is enough to know they differ.
        let old = report(vec![]);
        let new = by_version(report(vec![]), "1.9.0");
        let c = compare(&old, &new);
        assert_eq!(
            version_caveat(&c),
            Some(&Caveat::DifferentVersions {
                before: None,
                after: Some("1.9.0".into())
            })
        );
        let c = compare(&new, &old);
        assert_eq!(
            version_caveat(&c),
            Some(&Caveat::DifferentVersions {
                before: Some("1.9.0".into()),
                after: None
            })
        );
    }

    #[test]
    fn two_reports_that_both_lack_a_version_say_nothing_about_it() {
        // They may or may not come from the same version: no information,
        // so no warning (it would appear on every comparison of old reports).
        let c = compare(&report(vec![]), &report(vec![]));
        assert!(version_caveat(&c).is_none());
        assert!(c.caveats.is_empty());
    }

    #[test]
    fn the_version_caveat_does_not_change_what_was_compared() {
        // A caveat tells the reader how far to trust the comparison; it never
        // adds or hides a change, and so never moves the exit status.
        let b = || {
            report(vec![module(
                "m",
                &[("A", None, "warning"), ("B", None, "info")],
            )])
        };
        let a = || {
            report(vec![module(
                "m",
                &[("A", None, "error"), ("C", None, "warning")],
            )])
        };
        let plain = compare(&b(), &a());
        let versioned = compare(&by_version(b(), "1.8.1"), &by_version(a(), "1.9.0"));
        assert!(version_caveat(&versioned).is_some());
        assert_eq!(changes_of(&plain), changes_of(&versioned));
        assert_eq!(plain.totals(), versioned.totals());
        assert_eq!(
            plain.regressions(crate::models::Severity::Warning).len(),
            versioned
                .regressions(crate::models::Severity::Warning)
                .len()
        );
    }

    #[test]
    fn the_version_caveat_comes_after_the_others_and_is_one_of_several() {
        let c = compare(
            &filtered(
                by_version(report_on("web01", 1_000_000, vec![]), "1.8.1"),
                crate::models::Severity::Warning,
            ),
            &by_version(report_on("db02", 1_000_000, vec![]), "1.9.0"),
        );
        let kinds: Vec<&str> = c
            .caveats
            .iter()
            .map(|c| match c {
                Caveat::DifferentMachines { .. } => "machines",
                Caveat::ReportsLookReversed => "reversed",
                Caveat::Filtered { .. } => "filtered",
                Caveat::DifferentVersions { .. } => "versions",
                Caveat::DifferentProfiles { .. } => "profiles",
            })
            .collect();
        assert_eq!(kinds, ["machines", "filtered", "versions"]);
    }

    // ----- the profiles --------------------------------------------------------------

    fn profile_caveat(c: &Comparison) -> Option<&Caveat> {
        c.caveats
            .iter()
            .find(|c| matches!(c, Caveat::DifferentProfiles { .. }))
    }

    #[test]
    fn a_report_with_a_profile_next_to_one_without_is_flagged() {
        // "No profile" is a value: it is what the audit did when none was
        // chosen, and what every report of an older version looks like.
        let plain = report(vec![]);
        let hpc = with_profile(report(vec![]), "hpc");
        assert_eq!(
            profile_caveat(&compare(&plain, &hpc)),
            Some(&Caveat::DifferentProfiles {
                before: None,
                after: Some("hpc".into())
            })
        );
        assert_eq!(
            profile_caveat(&compare(&hpc, &plain)),
            Some(&Caveat::DifferentProfiles {
                before: Some("hpc".into()),
                after: None
            })
        );
    }

    #[test]
    fn two_different_profiles_are_flagged_and_two_equal_ones_are_not() {
        let c = compare(
            &with_profile(report(vec![]), "hpc"),
            &with_profile(report(vec![]), "server"),
        );
        assert_eq!(
            profile_caveat(&c),
            Some(&Caveat::DifferentProfiles {
                before: Some("hpc".into()),
                after: Some("server".into())
            })
        );
        let same = compare(
            &with_profile(report(vec![]), "hpc"),
            &with_profile(report(vec![]), "hpc"),
        );
        assert!(same.caveats.is_empty(), "{:?}", same.caveats);
    }

    #[test]
    fn two_reports_without_a_profile_say_nothing_about_it() {
        let c = compare(&report(vec![]), &report(vec![]));
        assert!(profile_caveat(&c).is_none());
        assert!(c.caveats.is_empty());
    }

    #[test]
    fn the_profile_caveat_does_not_change_what_was_compared() {
        let b = || {
            report(vec![module(
                "m",
                &[("A", None, "warning"), ("B", None, "info")],
            )])
        };
        let a = || {
            report(vec![module(
                "m",
                &[("A", None, "error"), ("C", None, "warning")],
            )])
        };
        let plain = compare(&b(), &a());
        let profiled = compare(&b(), &with_profile(a(), "hpc"));
        assert!(profile_caveat(&profiled).is_some());
        assert_eq!(changes_of(&plain), changes_of(&profiled));
        assert_eq!(plain.totals(), profiled.totals());
        assert_eq!(
            plain.regressions(crate::models::Severity::Warning).len(),
            profiled.regressions(crate::models::Severity::Warning).len()
        );
    }

    #[test]
    fn the_profile_caveat_comes_after_the_version_one() {
        let c = compare(
            &by_version(report(vec![]), "1.9.0"),
            &with_profile(by_version(report(vec![]), "1.10.0"), "hpc"),
        );
        assert!(matches!(c.caveats[0], Caveat::DifferentVersions { .. }));
        assert!(matches!(c.caveats[1], Caveat::DifferentProfiles { .. }));
    }

    // ----- several findings under one key ---------------------------------------------

    #[test]
    fn findings_sharing_a_key_are_paired_by_title_then_by_position() {
        use serde_json::json;
        let mut b = module("m", &[("DUP", None, "warning"), ("DUP", None, "info")]);
        let mut a = module("m", &[("DUP", None, "info"), ("DUP", None, "warning")]);
        b["findings"][0]["title"] = json!("first");
        b["findings"][1]["title"] = json!("second");
        a["findings"][0]["title"] = json!("second");
        a["findings"][1]["title"] = json!("first");
        let c = compare(&report(vec![b]), &report(vec![a]));
        assert_eq!(
            c.changes().count(),
            0,
            "titles pair them up: nothing changed"
        );
        assert_eq!(c.totals().unchanged, 2);
    }

    #[test]
    fn an_extra_finding_under_a_shared_key_is_new() {
        let b = module("m", &[("DUP", None, "info")]);
        let a = module("m", &[("DUP", None, "info"), ("DUP", None, "error")]);
        let c = compare(&report(vec![b]), &report(vec![a]));
        assert_eq!(changes_of(&c), [(ChangeKind::New, "m", "DUP")]);
    }

    // ----- exit status and display filter ----------------------------------------------

    fn mixed() -> Comparison {
        compare(
            &report(vec![module(
                "m",
                &[
                    ("GONE", None, "critical"),
                    ("UP", None, "info"),
                    ("STILL", None, "critical"),
                ],
            )]),
            &report(vec![module(
                "m",
                &[
                    ("UP", None, "warning"),
                    ("STILL", None, "critical"),
                    ("NEWINFO", None, "info"),
                    ("NEWERR", None, "error"),
                ],
            )]),
        )
    }

    #[test]
    fn regressions_are_new_or_worse_findings_at_the_threshold_or_above() {
        let c = mixed();
        let ids = |t| -> Vec<&str> { c.regressions(t).iter().map(|c| c.id.as_str()).collect() };
        assert_eq!(ids(Severity::Info), ["UP", "NEWINFO", "NEWERR"]);
        assert_eq!(ids(Severity::Warning), ["UP", "NEWERR"]);
        assert_eq!(ids(Severity::Error), ["NEWERR"]);
        assert!(
            ids(Severity::Critical).is_empty(),
            "STILL is old news, GONE is good news"
        );
    }

    #[test]
    fn the_display_filter_hides_changes_but_not_what_the_exit_status_sees() {
        let mut c = mixed();
        let failing_before = c.regressions(Severity::Warning).len();
        let hidden = c.retain_at_or_above(Severity::Error);
        // UP (info -> warning), NEWINFO are below error in both reports.
        assert_eq!(hidden, 2);
        assert_eq!(c.hidden, 2);
        let ids: Vec<_> = c.changes().map(|c| c.id.as_str()).collect();
        assert_eq!(ids, ["NEWERR", "GONE"]);
        assert_eq!(failing_before, 2, "judged before the filter");
    }

    #[test]
    fn the_display_filter_never_hides_a_module_that_was_not_compared() {
        let mut c = compare(
            &report(vec![module("n", &[("A", None, "critical")])]),
            &report(vec![failed("n", "x")]),
        );
        c.retain_at_or_above(Severity::Critical);
        assert_eq!(c.not_compared.len(), 1);
    }
}
