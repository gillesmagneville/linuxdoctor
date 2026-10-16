// SPDX-License-Identifier: GPL-3.0-only

use std::cmp::Reverse;
use std::collections::BTreeMap;

use crate::core::context::Context;
use crate::models::{Category, Confidence, Finding, Severity};
use crate::modules::recommend::Steps;

use super::collect::{CpuFreq, HpcRawData};

/// Pure function: RawData -> Findings. No I/O -- see ARCHITECTURE.md
/// "Testing Strategy".
pub fn analyze(data: &HpcRawData, _ctx: &Context) -> Vec<Finding> {
    vec![governor_finding(&data.cpufreq)]
}

/// What the CPUs of one kind have in common: the same driver, governor and
/// preference. A machine usually has one kind; a few have two.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
struct Setup<'a> {
    driver: Option<&'a str>,
    governor: &'a str,
    epp: Option<&'a str>,
}

/// The drivers that let the processor choose its own frequency and take the
/// governor as a hint, not as the rule: `intel_pstate` (active mode) and
/// `amd-pstate-epp`. Under them `powersave` is not "lowest frequency".
/// Every other driver (`acpi-cpufreq`, `intel_cpufreq` -- the passive mode of
/// `intel_pstate` --, `amd-pstate`, `cppc_cpufreq`...) uses the generic
/// governors, where `powersave` pins the lowest frequency.
fn hardware_managed(driver: Option<&str>) -> bool {
    matches!(driver, Some("intel_pstate" | "amd-pstate-epp"))
}

/// Which way an energy/performance preference leans.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Lean {
    Performance,
    Efficiency,
    /// `default` (whatever the firmware set), a number, or a name this tool
    /// does not know.
    Unknown,
}

fn lean(epp: &str) -> Lean {
    match epp {
        "performance" | "balance_performance" => Lean::Performance,
        "balance_power" | "power" => Lean::Efficiency,
        _ => Lean::Unknown,
    }
}

/// How one kind of CPU is judged on a compute node.
struct Judgement {
    severity: Severity,
    /// How sure the judgement is; `None` for a plain reading with nothing to
    /// judge.
    confidence: Option<Confidence>,
    text: String,
}

impl Judgement {
    fn info(text: String) -> Self {
        Judgement {
            severity: Severity::Info,
            confidence: None,
            text,
        }
    }

    fn warning(confidence: Confidence, text: String) -> Self {
        Judgement {
            severity: Severity::Warning,
            confidence: Some(confidence),
            text,
        }
    }
}

/// Which CPUs a sentence is about.
fn who(count: usize, total: usize) -> String {
    match (count == total, total) {
        (true, 1) => "The CPU".to_string(),
        (true, _) => format!("All {total} CPUs"),
        (false, _) => format!("{count} of {total} CPUs"),
    }
}

const COMMONLY_PERFORMANCE: &str = "Compute nodes are commonly set to `performance`.";

fn judge(setup: &Setup, subject: &str) -> Judgement {
    let governor = setup.governor;
    let via = setup
        .driver
        .map(|d| format!(" (driver {d})"))
        .unwrap_or_default();
    let head = format!("{subject}: `{governor}` governor{via}.");
    match governor {
        "performance" => Judgement::info(format!("{head} Nothing holds the frequency back.")),
        "userspace" => Judgement::info(format!(
            "{head} The frequency is set by hand or by a program; this tool cannot tell to \
             what value."
        )),
        "powersave" if hardware_managed(setup.driver) => match setup.epp {
            Some(epp) => match lean(epp) {
                Lean::Performance => Judgement::info(format!(
                    "{head} With this driver the processor picks its own frequency and \
                     `powersave` only sets how much it favours saving power; the preference \
                     here is `{epp}`, which leans toward performance, so little is lost. \
                     `performance` removes the remaining bias."
                )),
                Lean::Efficiency => Judgement::warning(
                    Confidence::strong_indication(80),
                    format!(
                        "{head} The processor picks its own frequency, and the \
                         energy/performance preference `{epp}` makes it favour saving power \
                         over speed, so it may hold back, or be slow to reach, the frequency \
                         a job could use. {COMMONLY_PERFORMANCE}"
                    ),
                ),
                Lean::Unknown => Judgement::info(format!(
                    "{head} With this driver the processor picks its own frequency; the \
                     preference here is `{epp}`, which this tool cannot place between \
                     performance and saving power."
                )),
            },
            None => Judgement::warning(
                Confidence::strong_indication(78),
                format!(
                    "{head} With this driver and no preference to steer it, `powersave` picks \
                     the frequency from the load, so a CPU has to ramp up when work arrives. \
                     {COMMONLY_PERFORMANCE}"
                ),
            ),
        },
        "powersave" if setup.driver.is_some() => Judgement::warning(
            Confidence::correlated(90),
            format!(
                "{head} With this driver `powersave` holds each CPU at its lowest allowed \
                 frequency, so jobs run at a fraction of the speed the hardware can give."
            ),
        ),
        "powersave" => Judgement::warning(
            Confidence::weak_indication(70),
            format!(
                "{head} Unless the driver (unknown here) steers the frequency itself, \
                 `powersave` holds each CPU at its lowest allowed frequency, so jobs run at a \
                 fraction of the speed the hardware can give."
            ),
        ),
        "ondemand" | "conservative" | "schedutil" => Judgement::warning(
            Confidence::strong_indication(80),
            format!(
                "{head} The frequency follows the load: a CPU that has been idle has to ramp \
                 up when work arrives, which costs time on parallel jobs that wait for each \
                 other. {COMMONLY_PERFORMANCE}"
            ),
        ),
        _ => Judgement::info(format!(
            "{head} This tool does not know this governor and does not judge it."
        )),
    }
}

/// `a` when every CPU has the same value, `a=30,b=2` when they differ.
fn counts_text<'a>(values: impl Iterator<Item = &'a str>) -> String {
    let mut counts: BTreeMap<&str, usize> = BTreeMap::new();
    for value in values {
        *counts.entry(value).or_default() += 1;
    }
    if counts.len() == 1 {
        return counts
            .keys()
            .next()
            .map(|k| k.to_string())
            .unwrap_or_default();
    }
    counts
        .iter()
        .map(|(value, n)| format!("{value}={n}"))
        .collect::<Vec<_>>()
        .join(",")
}

/// HPC001 -- the CPU frequency governor, judged for a compute node. Always
/// reported, like the other overview findings: no policy at all is said
/// outright, so a missing finding is never ambiguous between "nothing to
/// check" and "not checked".
fn governor_finding(cpus: &[CpuFreq]) -> Finding {
    let total = cpus.len();
    let builder = |severity: Severity, confidence: Confidence| {
        Finding::builder(
            "HPC001",
            "CPU Frequency Governor",
            Category::Cpu,
            severity,
            confidence,
        )
        .evidence("cpus_with_cpufreq", total.to_string())
    };

    if cpus.is_empty() {
        return builder(Severity::Info, Confidence::direct_observation())
            .explanation(
                "No CPU frequency scaling interface (cpufreq) is exposed. That is normal in a \
                 virtual machine, or on a platform that fixes the frequency, and it also \
                 happens when the driver is not loaded. There is nothing to check here, which \
                 is not the same as the frequency being right.",
            )
            .build();
    }

    let mut kinds: BTreeMap<Setup, usize> = BTreeMap::new();
    for cpu in cpus {
        *kinds
            .entry(Setup {
                driver: cpu.driver.as_deref(),
                governor: &cpu.governor,
                epp: cpu.epp.as_deref(),
            })
            .or_default() += 1;
    }
    // The most common kind first: it is what the machine is mostly like.
    let mut ordered: Vec<(Setup, usize)> = kinds.into_iter().collect();
    ordered.sort_by_key(|(setup, n)| (Reverse(*n), *setup));

    let judgements: Vec<Judgement> = ordered
        .iter()
        .map(|(setup, n)| judge(setup, &who(*n, total)))
        .collect();

    let governors: Vec<&str> = cpus.iter().map(|c| c.governor.as_str()).collect();
    let mixed = governors.iter().any(|g| *g != governors[0]);

    let mut severity = judgements
        .iter()
        .map(|j| j.severity)
        .max()
        .unwrap_or(Severity::Info);
    // A finding is only as sure as its least sure part.
    let mut confidence = judgements
        .iter()
        .filter_map(|j| j.confidence.clone())
        .min_by_key(|c| c.percent);
    let mut explanation = judgements
        .iter()
        .map(|j| j.text.as_str())
        .collect::<Vec<_>>()
        .join(" ");
    if mixed {
        explanation.push_str(
            " The CPUs do not all use the same governor: a node whose CPUs run at different \
             speeds gives uneven results for parallel jobs.",
        );
        severity = severity.max(Severity::Warning);
        // That the CPUs differ is observed; that it matters for this node is
        // the unconfirmed part.
        if confidence.as_ref().map_or(true, |c| c.percent > 80) {
            confidence = Some(Confidence::strong_indication(80));
        }
    }

    let confidence = match confidence {
        Some(c) if severity >= Severity::Warning => c,
        _ => Confidence::direct_observation(),
    };

    let mut finding = builder(severity, confidence);
    if cpus.iter().any(|c| c.driver.is_some()) {
        finding = finding.evidence(
            "scaling_driver",
            counts_text(cpus.iter().filter_map(|c| c.driver.as_deref())),
        );
    }
    finding = finding.evidence("governor", counts_text(governors.iter().copied()));
    if cpus.iter().any(|c| c.epp.is_some()) {
        finding = finding.evidence(
            "energy_performance_preference",
            counts_text(cpus.iter().filter_map(|c| c.epp.as_deref())),
        );
    }
    finding = finding.explanation(explanation);
    if severity >= Severity::Warning {
        finding = finding.recommendation(performance_steps());
    }
    finding.build()
}

fn performance_steps() -> String {
    Steps::new()
        .step(
            "Set the performance governor on every CPU now (it lasts until the next reboot):",
            &["echo performance | sudo tee /sys/devices/system/cpu/cpu*/cpufreq/scaling_governor"],
        )
        .step(
            "Make it permanent; systemd applies this file at every boot. If a tool such as \
             tuned or the site's configuration management already manages the governor, change \
             it there instead, or it will be set back:",
            &[
                "echo 'w /sys/devices/system/cpu/cpu*/cpufreq/scaling_governor - - - - performance' | sudo tee /etc/tmpfiles.d/cpu-governor.conf",
                "sudo systemd-tmpfiles --create /etc/tmpfiles.d/cpu-governor.conf",
            ],
        )
        .step(
            "Check the result (one line per governor, with the number of CPUs):",
            &["cat /sys/devices/system/cpu/cpu*/cpufreq/scaling_governor | sort | uniq -c"],
        )
        .build()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ctx() -> Context {
        Context {
            hostname: "test".into(),
            kernel_version: "test".into(),
            distro: None,
            architecture: "x86_64".into(),
            cpu_count: 8,
            mem_total_kb: 16_000_000,
            boot_time_unix: 0,
        }
    }

    /// `n` CPUs with the same policy, numbered from `first`.
    fn group(
        first: u32,
        n: u32,
        driver: Option<&str>,
        governor: &str,
        epp: Option<&str>,
    ) -> Vec<CpuFreq> {
        (first..first + n)
            .map(|cpu| CpuFreq {
                cpu,
                driver: driver.map(str::to_string),
                governor: governor.to_string(),
                epp: epp.map(str::to_string),
            })
            .collect()
    }

    fn finding_of(cpufreq: Vec<CpuFreq>) -> Finding {
        let mut findings = analyze(&HpcRawData { cpufreq }, &ctx());
        assert_eq!(findings.len(), 1);
        findings.remove(0)
    }

    fn one(driver: Option<&str>, governor: &str, epp: Option<&str>) -> Finding {
        finding_of(group(0, 8, driver, governor, epp))
    }

    fn evidence<'a>(finding: &'a Finding, key: &str) -> Option<&'a str> {
        finding
            .evidence
            .iter()
            .find(|(k, _)| k == key)
            .map(|(_, v)| v.as_str())
    }

    #[test]
    fn no_policy_at_all_is_said_outright_and_is_not_a_problem() {
        let f = finding_of(vec![]);
        assert_eq!(f.id, "HPC001");
        assert_eq!(f.severity, Severity::Info);
        assert!(f.explanation.contains("No CPU frequency scaling interface"));
        assert!(f
            .explanation
            .contains("not the same as the frequency being right"));
        assert_eq!(evidence(&f, "cpus_with_cpufreq"), Some("0"));
        assert_eq!(evidence(&f, "governor"), None);
        assert!(f.recommendation.is_none());
    }

    #[test]
    fn performance_everywhere_is_fine() {
        let f = one(Some("intel_pstate"), "performance", Some("performance"));
        assert_eq!(f.severity, Severity::Info);
        assert!(f.explanation.starts_with(
            "All 8 CPUs: `performance` governor (driver intel_pstate). Nothing holds the frequency back."
        ));
        assert_eq!(evidence(&f, "cpus_with_cpufreq"), Some("8"));
        assert_eq!(evidence(&f, "scaling_driver"), Some("intel_pstate"));
        assert_eq!(evidence(&f, "governor"), Some("performance"));
        assert_eq!(
            evidence(&f, "energy_performance_preference"),
            Some("performance")
        );
        assert!(f.recommendation.is_none());
        assert_eq!(f.confidence.percent, 100);
    }

    #[test]
    fn a_single_cpu_is_called_the_cpu() {
        let f = finding_of(group(0, 1, None, "performance", None));
        assert!(f
            .explanation
            .starts_with("The CPU: `performance` governor."));
        assert_eq!(evidence(&f, "scaling_driver"), None);
        assert_eq!(evidence(&f, "energy_performance_preference"), None);
    }

    #[test]
    fn generic_powersave_pins_the_lowest_frequency() {
        for driver in [
            "acpi-cpufreq",
            "intel_cpufreq",
            "amd-pstate",
            "cppc_cpufreq",
        ] {
            let f = one(Some(driver), "powersave", None);
            assert_eq!(f.severity, Severity::Warning, "{driver}");
            assert!(
                f.explanation
                    .contains("holds each CPU at its lowest allowed frequency"),
                "{driver}"
            );
            assert!(
                !f.explanation.contains("picks its own frequency"),
                "{driver}"
            );
            assert_eq!(f.confidence.percent, 90, "{driver}");
            assert!(f.recommendation.is_some());
        }
    }

    #[test]
    fn powersave_with_an_unknown_driver_is_judged_with_less_certainty() {
        let f = one(None, "powersave", None);
        assert_eq!(f.severity, Severity::Warning);
        assert!(f.explanation.contains("Unless the driver (unknown here)"));
        assert_eq!(f.confidence.percent, 70);
        assert_eq!(f.confidence.reason, "weak indication");
    }

    #[test]
    fn hardware_managed_powersave_leaning_to_performance_is_fine() {
        for (driver, epp) in [
            ("intel_pstate", "balance_performance"),
            ("intel_pstate", "performance"),
            ("amd-pstate-epp", "balance_performance"),
        ] {
            let f = one(Some(driver), "powersave", Some(epp));
            assert_eq!(f.severity, Severity::Info, "{driver} {epp}");
            assert!(
                f.explanation.contains("leans toward performance"),
                "{driver} {epp}"
            );
            assert!(f.explanation.contains(&format!("`{epp}`")));
            assert!(f.recommendation.is_none());
            // Not the generic reading: nothing is pinned.
            assert!(!f.explanation.contains("lowest allowed frequency"));
        }
    }

    #[test]
    fn hardware_managed_powersave_leaning_to_saving_power_is_a_warning() {
        for epp in ["balance_power", "power"] {
            let f = one(Some("intel_pstate"), "powersave", Some(epp));
            assert_eq!(f.severity, Severity::Warning, "{epp}");
            assert!(f.explanation.contains(&format!("`{epp}`")));
            assert!(f.explanation.contains("favour saving power over speed"));
            assert_eq!(f.confidence.percent, 80, "{epp}");
            assert!(!f.explanation.contains("lowest allowed frequency"));
        }
    }

    #[test]
    fn a_preference_this_tool_cannot_place_is_reported_not_judged() {
        for epp in ["default", "128", "something-new"] {
            let f = one(Some("intel_pstate"), "powersave", Some(epp));
            assert_eq!(f.severity, Severity::Info, "{epp}");
            assert!(f.explanation.contains("cannot place"), "{epp}");
            assert!(f.recommendation.is_none());
        }
    }

    #[test]
    fn hardware_managed_powersave_without_a_preference_follows_the_load() {
        // intel_pstate without HWP: no preference file, and `powersave`
        // picks the frequency from the load.
        let f = one(Some("intel_pstate"), "powersave", None);
        assert_eq!(f.severity, Severity::Warning);
        assert!(f.explanation.contains("picks the frequency from the load"));
        assert_eq!(f.confidence.percent, 78);
    }

    #[test]
    fn governors_that_follow_the_load_are_a_warning() {
        for governor in ["ondemand", "conservative", "schedutil"] {
            let f = one(Some("acpi-cpufreq"), governor, None);
            assert_eq!(f.severity, Severity::Warning, "{governor}");
            assert!(f.explanation.contains(&format!("`{governor}` governor")));
            assert!(f.explanation.contains("The frequency follows the load"));
            assert!(f.explanation.ends_with(COMMONLY_PERFORMANCE));
            assert_eq!(f.confidence.percent, 80);
        }
    }

    #[test]
    fn userspace_and_unknown_governors_are_reported_not_judged() {
        let f = one(Some("acpi-cpufreq"), "userspace", None);
        assert_eq!(f.severity, Severity::Info);
        assert!(f.explanation.contains("set by hand or by a program"));
        let f = one(Some("acpi-cpufreq"), "brand-new", None);
        assert_eq!(f.severity, Severity::Info);
        assert!(f.explanation.contains("`brand-new` governor"));
        assert!(f.explanation.contains("does not know this governor"));
    }

    #[test]
    fn a_warning_comes_with_the_steps_to_fix_it() {
        let f = one(Some("acpi-cpufreq"), "powersave", None);
        let steps = f.recommendation.expect("a warning has a recommendation");
        assert!(steps.starts_with("1. Set the performance governor on every CPU now"));
        assert!(steps.contains(
            "\n    echo performance | sudo tee /sys/devices/system/cpu/cpu*/cpufreq/scaling_governor"
        ));
        assert!(steps.contains("/etc/tmpfiles.d/cpu-governor.conf"));
        assert!(steps.contains("sudo systemd-tmpfiles --create"));
        assert!(steps.contains("tuned"));
        assert!(steps.contains("uniq -c"));
    }

    #[test]
    fn cpus_with_different_governors_are_a_warning_even_when_each_is_fine() {
        let mut cpus = group(0, 6, Some("acpi-cpufreq"), "performance", None);
        cpus.extend(group(6, 2, Some("acpi-cpufreq"), "userspace", None));
        let f = finding_of(cpus);
        assert_eq!(f.severity, Severity::Warning);
        assert!(f.explanation.contains("do not all use the same governor"));
        assert!(f.explanation.contains("6 of 8 CPUs: `performance`"));
        assert!(f.explanation.contains("2 of 8 CPUs: `userspace`"));
        assert_eq!(evidence(&f, "governor"), Some("performance=6,userspace=2"));
        assert_eq!(f.confidence.percent, 80);
        assert!(f.recommendation.is_some());
    }

    #[test]
    fn a_mixed_machine_is_only_as_sure_as_its_least_sure_part() {
        // A pinned minimum (90) next to a governor that follows the load
        // (80): 80.
        let mut cpus = group(0, 4, Some("acpi-cpufreq"), "powersave", None);
        cpus.extend(group(4, 4, Some("acpi-cpufreq"), "ondemand", None));
        let f = finding_of(cpus);
        assert_eq!(f.severity, Severity::Warning);
        assert_eq!(f.confidence.percent, 80);
        // A powersave whose driver is unknown (70) next to a fine
        // governor: the weak part is not raised to the mix's own 80.
        let mut cpus = group(0, 4, None, "powersave", None);
        cpus.extend(group(4, 4, None, "performance", None));
        let f = finding_of(cpus);
        assert_eq!(f.confidence.percent, 70);
        // A judgement just below the mix's own (78) is not raised to it.
        let mut cpus = group(0, 4, Some("intel_pstate"), "powersave", None);
        cpus.extend(group(4, 4, Some("intel_pstate"), "performance", None));
        let f = finding_of(cpus);
        assert_eq!(f.confidence.percent, 78);
        // A certain judgement (90) in a mix is lowered to the mix's 80:
        // that the CPUs differ is seen, that it matters is not.
        let mut cpus = group(0, 4, Some("acpi-cpufreq"), "powersave", None);
        cpus.extend(group(4, 4, Some("acpi-cpufreq"), "performance", None));
        let f = finding_of(cpus);
        assert_eq!(f.confidence.percent, 80);
    }

    #[test]
    fn the_same_governor_with_different_preferences_is_not_a_mix() {
        let mut cpus = group(
            0,
            4,
            Some("intel_pstate"),
            "powersave",
            Some("balance_performance"),
        );
        cpus.extend(group(
            4,
            4,
            Some("intel_pstate"),
            "powersave",
            Some("performance"),
        ));
        let f = finding_of(cpus);
        assert_eq!(f.severity, Severity::Info);
        assert!(!f.explanation.contains("do not all use the same governor"));
        assert_eq!(evidence(&f, "governor"), Some("powersave"));
        assert_eq!(
            evidence(&f, "energy_performance_preference"),
            Some("balance_performance=4,performance=4")
        );
    }

    #[test]
    fn the_finding_is_as_severe_as_its_worst_kind_of_cpu() {
        // One governor, two preferences: a fine kind and a kind that leans
        // toward saving power. The worst decides.
        let mut cpus = group(
            0,
            6,
            Some("intel_pstate"),
            "powersave",
            Some("balance_performance"),
        );
        cpus.extend(group(
            6,
            2,
            Some("intel_pstate"),
            "powersave",
            Some("power"),
        ));
        let f = finding_of(cpus);
        assert_eq!(f.severity, Severity::Warning);
        assert!(f.explanation.contains("2 of 8 CPUs"));
        assert!(!f.explanation.contains("do not all use the same governor"));
        assert_eq!(f.confidence.percent, 80);
        assert!(f.recommendation.is_some());
    }

    #[test]
    fn the_most_common_kind_is_described_first() {
        let mut cpus = group(0, 2, Some("acpi-cpufreq"), "performance", None);
        cpus.extend(group(2, 6, Some("acpi-cpufreq"), "ondemand", None));
        let f = finding_of(cpus);
        let first = f.explanation.find("6 of 8 CPUs").expect("the big group");
        let second = f.explanation.find("2 of 8 CPUs").expect("the small group");
        assert!(first < second);
    }

    #[test]
    fn evidence_lists_the_drivers_when_they_differ() {
        let mut cpus = group(0, 3, Some("acpi-cpufreq"), "performance", None);
        cpus.extend(group(3, 1, Some("intel_cpufreq"), "performance", None));
        let f = finding_of(cpus);
        assert_eq!(
            evidence(&f, "scaling_driver"),
            Some("acpi-cpufreq=3,intel_cpufreq=1")
        );
        assert_eq!(f.severity, Severity::Info);
    }

    #[test]
    fn counts_text_is_the_value_when_alone_and_a_tally_otherwise() {
        assert_eq!(counts_text(["a", "a", "a"].into_iter()), "a");
        assert_eq!(counts_text(["b", "a", "b"].into_iter()), "a=1,b=2");
        assert_eq!(counts_text(std::iter::empty()), "");
    }

    #[test]
    fn the_driver_table_tells_hardware_managed_from_generic() {
        for driver in ["intel_pstate", "amd-pstate-epp"] {
            assert!(hardware_managed(Some(driver)), "{driver}");
        }
        for driver in [
            "acpi-cpufreq",
            "intel_cpufreq",
            "amd-pstate",
            "cppc_cpufreq",
            "",
        ] {
            assert!(!hardware_managed(Some(driver)), "{driver}");
        }
        assert!(!hardware_managed(None));
    }

    #[test]
    fn the_preference_table_leans_the_documented_way() {
        assert_eq!(lean("performance"), Lean::Performance);
        assert_eq!(lean("balance_performance"), Lean::Performance);
        assert_eq!(lean("balance_power"), Lean::Efficiency);
        assert_eq!(lean("power"), Lean::Efficiency);
        for other in ["default", "0", "255", "", "Performance"] {
            assert_eq!(lean(other), Lean::Unknown, "{other:?}");
        }
    }
}
