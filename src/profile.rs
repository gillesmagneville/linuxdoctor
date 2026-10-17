// SPDX-License-Identifier: GPL-3.0-only

//! Machine profiles: what kind of machine is being audited.
//!
//! The checks are written for a machine in general. Some readings mean
//! something else on a particular kind of machine -- a load average at the
//! number of CPUs is contention on a desktop and a node doing its job in a
//! compute cluster -- and a profile says so, once, in one place, instead of
//! each module guessing.
//!
//! A profile is **chosen** (`--profile`, or `profile` in the configuration
//! file), never detected: two similar machines must not be judged differently
//! for a reason nobody can see. With no profile nothing here runs and every
//! severity is the one the module gave.
//!
//! What a profile may do to a finding is deliberately narrow:
//!
//! * It only ever **lowers** a severity (a [`Rule`] is a cap), for a reading
//!   that is the normal state of that kind of machine. It never raises one,
//!   because the exit status follows the severities: a profile that quietly
//!   made findings worse would make audits that pass today fail.
//! * It never removes a finding, never touches the evidence it was given and
//!   never changes its confidence.
//! * It says what it did, in the finding itself: the explanation gets a
//!   closing paragraph with the reason, and the evidence gets
//!   `severity_before_profile` and `profile`. Anybody reading a report can
//!   tell an adjusted finding from an untouched one, and see what it would
//!   have been.
//!
//! A profile may also **add modules**: checks that are right on one kind of
//! machine and noise on another (a desktop is not wrong for leaving its CPUs
//! on `powersave`), which lowering a severity cannot express. They are part of
//! the audit only when the profile is chosen, and are named in the profile's
//! description, in the manual page and in the report like any other module.
//!
//! The adjustment is applied to the finished report, before the exit status
//! is decided and before any display filter, so it is the severity after the
//! profile that every output, the exit status and `diff` work from.

use crate::core::engine::Report;
use crate::models::Severity;
use crate::modules::Module;

/// A kind of machine. See the module documentation for what a profile does.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Profile {
    /// A compute node: the CPUs are meant to be busy.
    Hpc,
}

impl Profile {
    /// Every profile, in the order they are listed to the person.
    pub const ALL: [Profile; 1] = [Profile::Hpc];

    /// The word that chooses this profile, on the command line and in the
    /// configuration file, and that reports record.
    pub fn name(self) -> &'static str {
        match self {
            Profile::Hpc => "hpc",
        }
    }

    /// The profile a recorded name stands for. Exact, like the command line.
    pub fn from_name(name: &str) -> Option<Profile> {
        Profile::ALL.into_iter().find(|p| p.name() == name)
    }

    /// One line on what the profile is for.
    pub fn description(self) -> &'static str {
        match self {
            Profile::Hpc => {
                "a compute node, where fully used CPUs are the normal state: \
                 load-average findings are reported as informational, and the \
                 `hpc` module checks that the CPUs are free to run at full speed and \
                 that RDMA can lock the memory it needs, and reports how NUMA balancing \
                 and SMT are set"
            }
        }
    }

    /// The modules this profile adds to an audit, after the ones every audit
    /// has. Empty for a profile that only adjusts severities. See the module
    /// documentation.
    pub fn modules(self) -> Vec<Box<dyn Module>> {
        match self {
            Profile::Hpc => vec![Box::new(crate::modules::hpc::HpcModule)],
        }
    }
}

/// The first module among `ids` that belongs to a profile other than the one
/// chosen (or to a profile when none is), with that profile. `--modules hpc`
/// without `--profile hpc` cannot run what was asked for; saying so beats
/// returning a report that quietly lacks it.
pub fn module_needing_profile(ids: &[String], chosen: Option<Profile>) -> Option<(&str, Profile)> {
    ids.iter().find_map(|id| {
        Profile::ALL
            .into_iter()
            .filter(|profile| Some(*profile) != chosen)
            .find(|profile| profile.modules().iter().any(|m| m.id() == id))
            .map(|profile| (id.as_str(), profile))
    })
}

/// Every id a profile adds, in profile order: what `--modules` accepts on top
/// of the ids every audit has.
pub fn module_ids() -> Vec<&'static str> {
    Profile::ALL
        .into_iter()
        .flat_map(|profile| profile.modules().into_iter().map(|m| m.id()))
        .collect()
}

/// One adjustment: a finding the profile reports at most at `cap`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Rule {
    /// The finding it applies to.
    pub id: &'static str,
    /// The highest severity the finding keeps under this profile.
    pub cap: Severity,
    /// Why this reading is normal for the profile. Quoted in the finding.
    pub reason: &'static str,
}

const HPC_RULES: &[Rule] = &[
    Rule {
        id: "CPU002",
        cap: Severity::Info,
        reason: "On a compute node the CPUs are meant to be busy: a load average \
                 at or above the number of CPUs is what a node running jobs looks \
                 like, not necessarily contention. The load figures stay in the \
                 evidence.",
    },
    Rule {
        id: "CPU003",
        cap: Severity::Info,
        reason: "On a compute node the CPUs are meant to be busy: a load average \
                 at or above the number of CPUs over every window is what a node \
                 running jobs looks like, not necessarily a bottleneck. The load \
                 figures stay in the evidence.",
    },
];

/// The adjustments a profile makes.
pub fn rules(profile: Profile) -> &'static [Rule] {
    match profile {
        Profile::Hpc => HPC_RULES,
    }
}

/// Applies a profile to a finished report and returns how many findings it
/// lowered. See the module documentation for what that does and does not
/// change.
pub fn apply(report: &mut Report, profile: Profile) -> usize {
    apply_rules(report, profile, rules(profile))
}

/// [`apply`] with the rules given, so that the properties every rule set
/// must have (a cap never raises) are tested with rules that exercise them.
///
/// Also records the profile on the report: this is the only thing that does,
/// so a report never names a profile that was not applied to it.
fn apply_rules(report: &mut Report, profile: Profile, rules: &[Rule]) -> usize {
    report.profile = Some(profile);
    let mut adjusted = 0;
    for finding in report
        .results
        .iter_mut()
        .flat_map(|result| result.findings.iter_mut())
    {
        let Some(rule) = rules
            .iter()
            .find(|rule| rule.id == finding.id && finding.severity > rule.cap)
        else {
            continue;
        };
        let before = finding.severity;
        finding.severity = rule.cap;
        finding
            .evidence
            .push(("severity_before_profile".into(), word(before)));
        finding
            .evidence
            .push(("profile".into(), profile.name().into()));
        if !finding.explanation.is_empty() {
            finding.explanation.push_str("\n\n");
        }
        finding.explanation.push_str(&format!(
            "Profile {}: reported as {} instead of {}. {}",
            profile.name(),
            word(rule.cap),
            word(before),
            rule.reason
        ));
        adjusted += 1;
    }
    adjusted
}

fn word(severity: Severity) -> String {
    severity.to_string().to_lowercase()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::context::Context;
    use crate::core::engine::ModuleRunResult;
    use crate::models::{Category, Confidence, Finding};

    fn finding(id: &str, severity: Severity) -> Finding {
        Finding::builder(
            id,
            "Some check",
            Category::Cpu,
            severity,
            Confidence::strong_indication(88),
        )
        .evidence("load_1m", "130.00")
        .explanation("The load is high.")
        .recommendation("Look at top.")
        .instance("socket 0")
        .build()
    }

    fn report(findings: Vec<Finding>) -> Report {
        Report {
            profile: None,
            context: Context {
                hostname: "node01".into(),
                kernel_version: "6.8.0".into(),
                distro: None,
                architecture: "x86_64".into(),
                cpu_count: 128,
                mem_total_kb: 1,
                boot_time_unix: 0,
            },
            results: vec![ModuleRunResult {
                module_id: "cpu",
                findings,
                error: None,
                skipped: false,
                notes: vec![],
            }],
        }
    }

    fn only(report: &Report) -> &Finding {
        &report.results[0].findings[0]
    }

    #[test]
    fn a_profile_is_found_by_the_exact_word_that_names_it() {
        for profile in Profile::ALL {
            assert_eq!(Profile::from_name(profile.name()), Some(profile));
        }
        for wrong in [
            "", "HPC", "Hpc", " hpc", "hpc ", "hpc\n", "hpcx", "hp", "server", "desktop",
        ] {
            assert_eq!(Profile::from_name(wrong), None, "{wrong:?}");
        }
    }

    #[test]
    fn applying_a_profile_records_it_on_the_report_even_when_nothing_was_lowered() {
        // The report says which profile it was judged with because the one
        // thing that judges it also says so: the two cannot differ.
        let mut r = report(vec![finding("CPU002", Severity::Info)]);
        assert_eq!(r.profile, None);
        assert_eq!(apply(&mut r, Profile::Hpc), 0);
        assert_eq!(r.profile, Some(Profile::Hpc));
    }

    #[test]
    fn a_cap_only_ever_lowers_a_severity() {
        // `hpc` caps at Info, the lowest level, so nothing there can show
        // what a cap does to a finding already below it. These rules can.
        const RULES: &[Rule] = &[Rule {
            id: "X1",
            cap: Severity::Warning,
            reason: "a reason",
        }];
        let before = [
            Severity::Info,
            Severity::Warning,
            Severity::Error,
            Severity::Critical,
        ];
        let mut r = report(before.iter().map(|&s| finding("X1", s)).collect());
        let lowered = apply_rules(&mut r, Profile::Hpc, RULES);
        let after: Vec<Severity> = r.results[0].findings.iter().map(|f| f.severity).collect();
        assert_eq!(
            after,
            [
                Severity::Info,
                Severity::Warning,
                Severity::Warning,
                Severity::Warning
            ]
        );
        assert_eq!(lowered, 2, "only the two above the cap were adjusted");
        // A finding that was not adjusted carries no mark of the profile.
        for untouched in &r.results[0].findings[..2] {
            assert!(untouched.evidence.iter().all(|(k, _)| k != "profile"));
            assert_eq!(untouched.explanation, "The load is high.");
        }
    }

    #[test]
    fn every_profile_describes_itself() {
        for profile in Profile::ALL {
            assert!(!profile.description().is_empty());
            assert!(!rules(profile).is_empty(), "a profile that changes nothing");
        }
    }

    #[test]
    fn a_rule_lowers_the_severity_to_its_cap() {
        for (id, before) in [
            ("CPU002", Severity::Warning),
            ("CPU002", Severity::Error),
            ("CPU003", Severity::Critical),
        ] {
            let mut r = report(vec![finding(id, before)]);
            assert_eq!(apply(&mut r, Profile::Hpc), 1);
            assert_eq!(only(&r).severity, Severity::Info, "{id} from {before}");
        }
    }

    #[test]
    fn what_the_profile_did_is_written_in_the_finding() {
        let mut r = report(vec![finding("CPU003", Severity::Critical)]);
        apply(&mut r, Profile::Hpc);
        let f = only(&r);
        assert!(f.explanation.starts_with("The load is high.\n\n"));
        assert!(f
            .explanation
            .contains("Profile hpc: reported as info instead of critical."));
        assert!(f.explanation.contains("meant to be busy"));
        let evidence: Vec<(&str, &str)> = f
            .evidence
            .iter()
            .map(|(k, v)| (k.as_str(), v.as_str()))
            .collect();
        assert_eq!(
            evidence,
            [
                ("load_1m", "130.00"),
                ("severity_before_profile", "critical"),
                ("profile", "hpc"),
            ],
            "the evidence it was given is kept, in front"
        );
    }

    #[test]
    fn nothing_but_the_severity_and_those_notes_changes() {
        let mut r = report(vec![finding("CPU002", Severity::Error)]);
        let before = only(&r).clone();
        apply(&mut r, Profile::Hpc);
        let after = only(&r);
        assert_eq!(after.id, before.id);
        assert_eq!(after.title, before.title);
        assert_eq!(after.category, before.category);
        assert_eq!(after.confidence.percent, before.confidence.percent);
        assert_eq!(after.confidence.reason, before.confidence.reason);
        assert_eq!(after.recommendation, before.recommendation);
        assert_eq!(after.instance, before.instance);
    }

    #[test]
    fn a_finding_already_at_or_below_the_cap_is_left_alone() {
        let mut r = report(vec![finding("CPU002", Severity::Info)]);
        let before = only(&r).clone();
        assert_eq!(apply(&mut r, Profile::Hpc), 0);
        let after = only(&r);
        assert_eq!(after.severity, Severity::Info);
        assert_eq!(after.explanation, before.explanation);
        assert_eq!(after.evidence, before.evidence);
    }

    #[test]
    fn other_findings_are_never_touched_whatever_their_severity() {
        let mut r = report(vec![
            finding("CPU001", Severity::Critical),
            finding("MEM003", Severity::Error),
            finding("NUMA002", Severity::Warning),
            finding("GPU002", Severity::Info),
        ]);
        let before = r.results[0].findings.clone();
        assert_eq!(apply(&mut r, Profile::Hpc), 0);
        for (a, b) in r.results[0].findings.iter().zip(&before) {
            assert_eq!(a.severity, b.severity);
            assert_eq!(a.explanation, b.explanation);
            assert_eq!(a.evidence, b.evidence);
        }
    }

    #[test]
    fn no_rule_ever_raises_a_severity() {
        // The one rule of this module: a profile only quiets what is normal.
        // A finding below the cap must come out exactly as it went in.
        for profile in Profile::ALL {
            for rule in rules(profile) {
                for below in [Severity::Info, Severity::Warning, Severity::Error] {
                    if below > rule.cap {
                        continue;
                    }
                    let mut r = report(vec![finding(rule.id, below)]);
                    apply(&mut r, profile);
                    assert_eq!(only(&r).severity, below, "{} at {below}", rule.id);
                }
            }
        }
    }

    #[test]
    fn rules_are_unique_per_finding_and_always_give_a_reason() {
        for profile in Profile::ALL {
            let rules = rules(profile);
            for (i, rule) in rules.iter().enumerate() {
                assert!(!rule.reason.is_empty(), "{}", rule.id);
                assert!(
                    rules[i + 1..].iter().all(|other| other.id != rule.id),
                    "{} appears twice",
                    rule.id
                );
            }
        }
    }

    #[test]
    fn several_findings_across_modules_are_each_adjusted_once() {
        let mut r = report(vec![
            finding("CPU002", Severity::Warning),
            finding("CPU003", Severity::Critical),
            finding("CPU001", Severity::Warning),
        ]);
        r.results.push(ModuleRunResult {
            module_id: "other",
            findings: vec![finding("CPU002", Severity::Error)],
            error: None,
            skipped: false,
            notes: vec![],
        });
        assert_eq!(apply(&mut r, Profile::Hpc), 3);
        assert_eq!(r.results[0].findings[2].severity, Severity::Warning);
        assert_eq!(r.results[1].findings[0].severity, Severity::Info);
        let again = apply(&mut r, Profile::Hpc);
        assert_eq!(again, 0, "applying it twice changes nothing more");
        let notes = r.results[0].findings[1]
            .explanation
            .matches("Profile hpc:")
            .count();
        assert_eq!(notes, 1);
    }

    // ----- the modules a profile adds -----------------------------------

    #[test]
    fn the_hpc_profile_adds_the_hpc_module_and_only_it() {
        let ids: Vec<&str> = Profile::Hpc.modules().iter().map(|m| m.id()).collect();
        assert_eq!(ids, ["hpc"]);
        assert_eq!(module_ids(), ["hpc"]);
    }

    #[test]
    fn a_module_a_profile_adds_never_takes_the_id_of_one_every_audit_has() {
        let general: Vec<&str> = crate::modules::all_modules()
            .iter()
            .map(|m| m.id())
            .collect();
        let added = module_ids();
        for id in &added {
            assert!(!general.contains(id), "{id} is in both lists");
        }
        for (i, id) in added.iter().enumerate() {
            assert!(!added[i + 1..].contains(id), "{id} is added twice");
        }
    }

    #[test]
    fn asking_for_a_profile_module_without_its_profile_names_the_module_and_the_profile() {
        let ids = |list: &[&str]| -> Vec<String> { list.iter().map(|s| s.to_string()).collect() };
        // Not chosen at all.
        let asked = ids(&["memory", "hpc"]);
        assert_eq!(
            module_needing_profile(&asked, None),
            Some(("hpc", Profile::Hpc))
        );
        // Chosen: nothing to say.
        assert_eq!(module_needing_profile(&asked, Some(Profile::Hpc)), None);
        // Only modules every audit has: nothing to say, with or without one.
        let plain = ids(&["memory", "cpu"]);
        assert_eq!(module_needing_profile(&plain, None), None);
        assert_eq!(module_needing_profile(&plain, Some(Profile::Hpc)), None);
        // An id nobody knows is not this function's business (clap refuses it).
        assert_eq!(module_needing_profile(&ids(&["nope"]), None), None);
        assert_eq!(module_needing_profile(&[], None), None);
    }
}
