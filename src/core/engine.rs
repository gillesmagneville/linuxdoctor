// SPDX-License-Identifier: GPL-3.0-only

use std::any::Any;
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::sync::mpsc;
use std::thread;

use serde::Serialize;

use crate::core::command::take_timeouts;
use crate::core::context::Context;
use crate::core::error::CoreError;
use crate::models::Finding;
use crate::modules::{all_modules, Module};
use crate::profile::{self, Profile};

/// One module's outcome: either the findings it produced, or a note that it
/// failed / was skipped. Kept separate from `Finding` so a collector failure
/// is visible in output rather than silently disappearing.
#[derive(Debug, Clone, Serialize)]
pub struct ModuleRunResult {
    pub module_id: &'static str,
    pub findings: Vec<Finding>,
    pub error: Option<String>,
    pub skipped: bool,
    /// Incidents that did not stop the module but mean its data may be
    /// incomplete — today, external commands stopped for exceeding the
    /// time limit. Empty on a healthy run. Shown by every output format so
    /// a missing finding is never mistaken for a clean bill of health.
    pub notes: Vec<String>,
}

impl ModuleRunResult {
    fn new(module_id: &'static str) -> Self {
        ModuleRunResult {
            module_id,
            findings: Vec::new(),
            error: None,
            skipped: false,
            notes: Vec::new(),
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct Report {
    pub context: Context,
    pub results: Vec<ModuleRunResult>,
    /// The profile that was applied to this report, if one was
    /// ([`crate::profile::apply`] is the only thing that sets it). It lives
    /// on the report, not beside it, so that what a report says it was
    /// judged as and what was done to its findings cannot differ.
    ///
    /// Not part of the serialized `Report`: the JSON renderer writes it in
    /// its own place, next to the version, and only when there is one.
    #[serde(skip)]
    pub profile: Option<Profile>,
}

impl Report {
    pub fn all_findings(&self) -> impl Iterator<Item = &Finding> {
        self.results.iter().flat_map(|r| r.findings.iter())
    }

    pub fn highest_severity(&self) -> Option<crate::models::Severity> {
        self.all_findings().map(|f| f.severity).max()
    }

    /// How many findings are at `min` severity or worse.
    pub fn count_at_or_above(&self, min: crate::models::Severity) -> usize {
        self.all_findings().filter(|f| f.severity >= min).count()
    }

    /// Drops every finding below `min` and returns how many were dropped.
    /// A display filter: module errors, skips and notes are left alone, so
    /// nothing about *whether the audit worked* is ever hidden.
    pub fn retain_at_or_above(&mut self, min: crate::models::Severity) -> usize {
        let mut dropped = 0;
        for result in &mut self.results {
            let before = result.findings.len();
            result.findings.retain(|f| f.severity >= min);
            dropped += before - result.findings.len();
        }
        dropped
    }
}

/// Best-effort text of a panic payload (`panic!("literal")` carries a
/// `&str`, `panic!("{x}")` a `String`).
fn panic_message(payload: &(dyn Any + Send)) -> String {
    if let Some(s) = payload.downcast_ref::<&str>() {
        (*s).to_string()
    } else if let Some(s) = payload.downcast_ref::<String>() {
        s.clone()
    } else {
        "unknown cause".to_string()
    }
}

/// Runs one module and converts every way it can end — findings, a
/// returned error, being skipped, even a panic — into a
/// `ModuleRunResult`. Must run on the thread that executes the module:
/// the timeout notes it attaches are collected per thread.
fn run_one(module: &dyn Module, ctx: &Context) -> ModuleRunResult {
    // Anything left over from earlier work on this thread is not this
    // module's business.
    let _ = take_timeouts();

    let mut result = ModuleRunResult::new(module.id());
    let outcome = catch_unwind(AssertUnwindSafe(|| {
        if module.is_available(ctx) {
            Some(module.run(ctx))
        } else {
            None
        }
    }));
    match outcome {
        Ok(None) => result.skipped = true,
        Ok(Some(Ok(findings))) => result.findings = findings,
        Ok(Some(Err(e))) => result.error = Some(e.to_string()),
        Err(payload) => {
            result.error = Some(format!(
                "module crashed unexpectedly ({}) — this is a bug in LinuxDoctor, \
                 other modules are unaffected",
                panic_message(payload.as_ref())
            ));
        }
    }

    result.notes = take_timeouts();
    result
}

/// Runs the given modules **concurrently**, one thread each, and returns
/// their results in the order the modules were given (the left-menu
/// order), regardless of which finished first.
///
/// Modules never depend on each other's output (ARCHITECTURE.md
/// "Context"), so parallel execution changes only the elapsed time: a
/// slow `smartctl` or `virsh` no longer holds up memory, CPU and
/// network. Failures stay isolated exactly as before — an error or a
/// panic in one module becomes that module's `error`, nothing else.
///
/// `on_progress(done, total, pending)` is called on the calling thread
/// (never from a worker, so it needs no `Send`): once at the start with
/// nothing done, then each time a module finishes, with the ids of the
/// modules still running. The TUI uses it to keep its startup gauge
/// moving and to say what it is waiting for.
pub fn run_modules(
    modules: &[&dyn Module],
    ctx: &Context,
    mut on_progress: impl FnMut(usize, usize, &[&'static str]),
) -> Vec<ModuleRunResult> {
    let total = modules.len();
    let mut slots: Vec<Option<ModuleRunResult>> = (0..total).map(|_| None).collect();

    let pending_ids = |slots: &[Option<ModuleRunResult>]| -> Vec<&'static str> {
        modules
            .iter()
            .zip(slots)
            .filter(|(_, slot)| slot.is_none())
            .map(|(m, _)| m.id())
            .collect()
    };

    on_progress(0, total, &pending_ids(&slots));
    if total == 0 {
        return Vec::new();
    }

    thread::scope(|scope| {
        let (tx, rx) = mpsc::channel::<(usize, ModuleRunResult)>();

        for (index, module) in modules.iter().copied().enumerate() {
            let worker_tx = tx.clone();
            let fallback_tx = tx.clone();
            let spawned = thread::Builder::new()
                .name(format!("module-{}", module.id()))
                .spawn_scoped(scope, move || {
                    let _ = worker_tx.send((index, run_one(module, ctx)));
                });
            if spawned.is_err() {
                // The OS refused another thread (resource limits). Run
                // this module here instead of losing it; slower, but the
                // audit still completes.
                let _ = fallback_tx.send((index, run_one(module, ctx)));
            }
        }
        drop(tx);

        let mut done = 0;
        while let Ok((index, result)) = rx.recv() {
            done += 1;
            slots[index] = Some(result);
            on_progress(done, total, &pending_ids(&slots));
        }
    });

    modules
        .iter()
        .zip(slots)
        .map(|(module, slot)| {
            slot.unwrap_or_else(|| {
                let mut lost = ModuleRunResult::new(module.id());
                lost.error = Some("module produced no result".to_string());
                lost
            })
        })
        .collect()
}

/// Run every registered module, isolating failures per ARCHITECTURE.md
/// "Error Handling": one module failing never stops the others.
///
/// See [`run_modules`] for the concurrency and for what `on_progress`
/// receives. The plain `run_audit()` below passes a no-op callback.
///
/// `profile` is the kind of machine the person said this is, if they did
/// (see [`crate::profile`]). It is a parameter of the only functions that
/// build a report, not a step the caller has to remember: a report never
/// leaves the engine half-way between "judged in general" and "judged as a
/// compute node", so what is recorded and what was applied cannot disagree.
pub fn run_audit_with_progress(
    selected_ids: Option<&[String]>,
    profile: Option<Profile>,
    on_progress: impl FnMut(usize, usize, &[&'static str]),
) -> Result<Report, CoreError> {
    let context = Context::detect()?;
    let modules = all_modules();
    let selected: Vec<&dyn Module> = modules
        .iter()
        .map(|m| m.as_ref())
        .filter(|m| {
            selected_ids
                .map(|ids| ids.iter().any(|id| id == m.id()))
                .unwrap_or(true)
        })
        .collect();

    Ok(audit_of(&selected, context, profile, on_progress))
}

/// The report of running `modules`, with the profile (if any) applied to
/// the finished result -- before anything decides an exit status or filters
/// what is shown, which happen in the caller, after this returns.
pub fn audit_of(
    modules: &[&dyn Module],
    context: Context,
    profile: Option<Profile>,
    on_progress: impl FnMut(usize, usize, &[&'static str]),
) -> Report {
    let results = run_modules(modules, &context, on_progress);
    let mut report = Report {
        profile: None,
        context,
        results,
    };
    if let Some(profile) = profile {
        profile::apply(&mut report, profile);
    }
    report
}

/// Plain entry point for the non-interactive `audit` command, which has
/// no progress screen to update.
pub fn run_audit(
    selected_ids: Option<&[String]>,
    profile: Option<Profile>,
) -> Result<Report, CoreError> {
    run_audit_with_progress(selected_ids, profile, |_, _, _| {})
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::command::command;
    use crate::core::error::ModuleError;
    use crate::models::{Category, Confidence, Severity};
    use std::time::{Duration, Instant};

    enum Behavior {
        Findings,
        /// Findings of a heavily loaded machine: the two a compute-node
        /// profile caps, and one it has nothing to say about.
        Loaded,
        Fail,
        Panic,
        Unavailable,
        SlowCommand,
    }

    struct Fake {
        id: &'static str,
        delay: Duration,
        behavior: Behavior,
    }

    impl Fake {
        fn new(id: &'static str, delay_ms: u64, behavior: Behavior) -> Self {
            Fake {
                id,
                delay: Duration::from_millis(delay_ms),
                behavior,
            }
        }
    }

    impl Module for Fake {
        fn id(&self) -> &'static str {
            self.id
        }
        fn category(&self) -> Category {
            Category::Cpu
        }
        fn is_available(&self, _ctx: &Context) -> bool {
            !matches!(self.behavior, Behavior::Unavailable)
        }
        fn run(&self, _ctx: &Context) -> Result<Vec<Finding>, ModuleError> {
            thread::sleep(self.delay);
            match self.behavior {
                Behavior::Findings | Behavior::Unavailable => Ok(Vec::new()),
                Behavior::Loaded => Ok([
                    ("CPU002", Severity::Error),
                    ("CPU003", Severity::Critical),
                    ("STO001", Severity::Error),
                ]
                .into_iter()
                .map(|(id, severity)| {
                    Finding::builder(
                        id,
                        "t",
                        Category::Cpu,
                        severity,
                        Confidence::direct_observation(),
                    )
                    .build()
                })
                .collect()),
                Behavior::Fail => Err(ModuleError::Parse {
                    what: "fixture".into(),
                    reason: "broken on purpose".into(),
                }),
                Behavior::Panic => panic!("deliberate test panic"),
                Behavior::SlowCommand => {
                    let _ = command("sleep")
                        .arg("30")
                        .timeout(Duration::from_millis(200))
                        .output();
                    Ok(Vec::new())
                }
            }
        }
    }

    fn ctx() -> Context {
        Context {
            hostname: "test".into(),
            kernel_version: "0".into(),
            distro: None,
            architecture: "x86_64".into(),
            cpu_count: 1,
            mem_total_kb: 0,
            boot_time_unix: 0,
        }
    }

    fn run(mods: &[Fake]) -> Vec<ModuleRunResult> {
        let refs: Vec<&dyn Module> = mods.iter().map(|m| m as &dyn Module).collect();
        run_modules(&refs, &ctx(), |_, _, _| {})
    }

    fn audit_of_loaded(profile: Option<Profile>) -> Report {
        let fake = Fake::new("cpu", 0, Behavior::Loaded);
        audit_of(&[&fake as &dyn Module], ctx(), profile, |_, _, _| {})
    }

    fn severities(report: &Report) -> Vec<(String, Severity)> {
        report
            .all_findings()
            .map(|f| (f.id.clone(), f.severity))
            .collect()
    }

    #[test]
    fn without_a_profile_the_report_is_what_the_modules_gave() {
        let report = audit_of_loaded(None);
        assert_eq!(
            severities(&report),
            [
                ("CPU002".to_string(), Severity::Error),
                ("CPU003".to_string(), Severity::Critical),
                ("STO001".to_string(), Severity::Error),
            ]
        );
        assert!(report
            .all_findings()
            .all(|f| f.evidence.iter().all(|(k, _)| k != "profile")));
        assert_eq!(report.profile, None);
    }

    #[test]
    fn the_engine_applies_the_profile_to_the_finished_report() {
        let report = audit_of_loaded(Some(Profile::Hpc));
        assert_eq!(report.profile, Some(Profile::Hpc));
        assert_eq!(
            severities(&report),
            [
                ("CPU002".to_string(), Severity::Info),
                ("CPU003".to_string(), Severity::Info),
                // Nothing to say about this one.
                ("STO001".to_string(), Severity::Error),
            ]
        );
        // And the report says so, in the findings themselves.
        let cpu003 = report.all_findings().find(|f| f.id == "CPU003").unwrap();
        assert!(cpu003
            .evidence
            .iter()
            .any(|(k, v)| k == "severity_before_profile" && v == "critical"));
    }

    #[test]
    fn the_profile_is_applied_before_the_gate_can_look_at_the_report() {
        // The caller gets the report only after the profile was applied, so
        // whatever it decides from the report -- the exit status first --
        // follows the severities the report shows.
        use crate::core::gate::{evaluate, DEFAULT_FAIL_ON};
        let without = audit_of_loaded(None);
        let with = audit_of_loaded(Some(Profile::Hpc));
        assert_eq!(
            evaluate(&without, Some(DEFAULT_FAIL_ON)).failing,
            3,
            "all three are Error or worse"
        );
        assert_eq!(
            evaluate(&with, Some(DEFAULT_FAIL_ON)).failing,
            1,
            "only the storage finding is left at Error"
        );
    }

    #[test]
    fn results_keep_menu_order_even_when_completion_order_differs() {
        let results = run(&[
            Fake::new("slowest", 300, Behavior::Findings),
            Fake::new("instant", 0, Behavior::Findings),
            Fake::new("middle", 150, Behavior::Findings),
        ]);
        let ids: Vec<_> = results.iter().map(|r| r.module_id).collect();
        assert_eq!(ids, ["slowest", "instant", "middle"]);
    }

    #[test]
    fn modules_run_concurrently_not_one_after_another() {
        // Four modules of 400 ms: ~1600 ms one after another, ~400 ms in
        // parallel. The bound sits well between the two.
        let started = Instant::now();
        let results = run(&[
            Fake::new("a", 400, Behavior::Findings),
            Fake::new("b", 400, Behavior::Findings),
            Fake::new("c", 400, Behavior::Findings),
            Fake::new("d", 400, Behavior::Findings),
        ]);
        let elapsed = started.elapsed();
        assert_eq!(results.len(), 4);
        assert!(
            elapsed < Duration::from_millis(1100),
            "took {elapsed:?}, looks sequential"
        );
    }

    #[test]
    fn an_error_in_one_module_does_not_affect_the_others() {
        let results = run(&[
            Fake::new("ok", 0, Behavior::Findings),
            Fake::new("bad", 0, Behavior::Fail),
            Fake::new("also_ok", 0, Behavior::Findings),
        ]);
        assert!(results[0].error.is_none());
        assert!(results[1]
            .error
            .as_deref()
            .unwrap()
            .contains("broken on purpose"));
        assert!(results[2].error.is_none());
    }

    #[test]
    fn a_panic_in_one_module_is_isolated_and_reported() {
        let results = run(&[
            Fake::new("ok", 0, Behavior::Findings),
            Fake::new("boom", 0, Behavior::Panic),
            Fake::new("also_ok", 20, Behavior::Findings),
        ]);
        assert!(results[0].error.is_none());
        let message = results[1].error.as_deref().unwrap();
        assert!(message.contains("deliberate test panic"), "{message}");
        assert!(message.contains("bug in LinuxDoctor"), "{message}");
        assert!(results[2].error.is_none());
    }

    #[test]
    fn unavailable_module_is_skipped() {
        let results = run(&[Fake::new("n/a", 0, Behavior::Unavailable)]);
        assert!(results[0].skipped);
        assert!(results[0].error.is_none());
    }

    #[test]
    fn stopped_commands_are_attributed_to_the_right_module_only() {
        // Thread-local bookkeeping: the module that ran the slow command
        // gets the note, its concurrent neighbour gets nothing.
        let results = run(&[
            Fake::new("healthy", 50, Behavior::Findings),
            Fake::new("hung_tool", 0, Behavior::SlowCommand),
        ]);
        assert!(results[0].notes.is_empty(), "{:?}", results[0].notes);
        assert_eq!(results[1].notes.len(), 1);
        assert!(results[1].notes[0].contains("sleep 30"));
        assert!(
            results[1].error.is_none(),
            "a timeout is a note, not a failure"
        );
    }

    #[test]
    fn progress_starts_empty_ends_complete_and_shrinks_the_pending_list() {
        let mods = [
            Fake::new("fast", 0, Behavior::Findings),
            Fake::new("slow", 200, Behavior::Findings),
        ];
        let refs: Vec<&dyn Module> = mods.iter().map(|m| m as &dyn Module).collect();
        let mut calls: Vec<(usize, usize, Vec<&'static str>)> = Vec::new();
        run_modules(&refs, &ctx(), |done, total, pending| {
            calls.push((done, total, pending.to_vec()));
        });

        assert_eq!(calls.first().unwrap(), &(0, 2, vec!["fast", "slow"]));
        assert_eq!(calls.last().unwrap(), &(2, 2, vec![]));
        // One call at the start plus one per module.
        assert_eq!(calls.len(), 3);
        // `done` never goes backwards and the pending list only shrinks.
        for pair in calls.windows(2) {
            assert!(pair[1].0 >= pair[0].0);
            assert!(pair[1].2.len() <= pair[0].2.len());
        }
        // The fast one finishes first, so "slow" is what is left waiting.
        assert_eq!(calls[1].2, vec!["slow"]);
    }

    #[test]
    fn no_modules_reports_once_and_returns_nothing() {
        let mut calls = 0;
        let results = run_modules(&[], &ctx(), |done, total, pending| {
            calls += 1;
            assert_eq!((done, total, pending.len()), (0, 0, 0));
        });
        assert!(results.is_empty());
        assert_eq!(calls, 1);
    }
}

#[cfg(test)]
mod report_filter_tests {
    use super::*;
    use crate::models::{Category, Confidence, Severity};

    fn finding(id: &str, severity: Severity) -> Finding {
        Finding::builder(
            id,
            "title",
            Category::Memory,
            severity,
            Confidence::direct_observation(),
        )
        .build()
    }

    fn result(id: &'static str, findings: Vec<Finding>) -> ModuleRunResult {
        ModuleRunResult {
            module_id: id,
            findings,
            error: None,
            skipped: false,
            notes: vec![],
        }
    }

    fn report() -> Report {
        let mut failed = result("net", vec![]);
        failed.error = Some("boom".into());
        let mut skipped = result("ntp", vec![]);
        skipped.skipped = true;
        let mut noted = result("gpu", vec![finding("G1", Severity::Info)]);
        noted.notes = vec!["nvidia-smi did not finish".into()];
        Report {
            profile: None,
            context: Context {
                hostname: "h".into(),
                kernel_version: "6".into(),
                distro: None,
                architecture: "x86_64".into(),
                cpu_count: 1,
                mem_total_kb: 1024,
                boot_time_unix: 0,
            },
            results: vec![
                result(
                    "memory",
                    vec![
                        finding("M1", Severity::Info),
                        finding("M2", Severity::Warning),
                        finding("M3", Severity::Critical),
                    ],
                ),
                result("cpu", vec![finding("C1", Severity::Error)]),
                failed,
                skipped,
                noted,
            ],
        }
    }

    #[test]
    fn counts_findings_at_or_above_a_level() {
        let r = report();
        assert_eq!(r.count_at_or_above(Severity::Info), 5);
        assert_eq!(r.count_at_or_above(Severity::Warning), 3);
        assert_eq!(r.count_at_or_above(Severity::Error), 2);
        assert_eq!(r.count_at_or_above(Severity::Critical), 1);
    }

    #[test]
    fn retain_drops_lower_findings_and_reports_how_many() {
        let mut r = report();
        assert_eq!(r.retain_at_or_above(Severity::Error), 3);
        let ids: Vec<&str> = r.all_findings().map(|f| f.id.as_str()).collect();
        assert_eq!(ids, ["M3", "C1"]);
    }

    #[test]
    fn retain_info_changes_nothing() {
        let mut r = report();
        assert_eq!(r.retain_at_or_above(Severity::Info), 0);
        assert_eq!(r.all_findings().count(), 5);
    }

    #[test]
    fn retain_never_hides_errors_skips_or_notes() {
        let mut r = report();
        r.retain_at_or_above(Severity::Critical);
        assert_eq!(r.results.len(), 5, "no module disappears");
        assert_eq!(r.results[2].error.as_deref(), Some("boom"));
        assert!(r.results[3].skipped);
        assert_eq!(r.results[4].notes.len(), 1);
        assert!(r.results[4].findings.is_empty());
    }
}
