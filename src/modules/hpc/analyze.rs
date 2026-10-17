// SPDX-License-Identifier: GPL-3.0-only

use std::cmp::Reverse;
use std::collections::{BTreeMap, BTreeSet};

use crate::core::context::Context;
use crate::models::{Category, Confidence, Finding, Severity};
use crate::modules::logs::text::human_size;
use crate::modules::recommend::{family_of, sysctl_commands, Family, Steps};

use super::collect::{CpuFreq, CpuTopology, HpcRawData, Limit, MemLock, RdmaDevice, Smt};

/// Pure function: RawData -> Findings. No I/O -- see ARCHITECTURE.md
/// "Testing Strategy".
pub fn analyze(data: &HpcRawData, ctx: &Context) -> Vec<Finding> {
    let ram = ctx.mem_total_kb.saturating_mul(1024);
    vec![
        governor_finding(&data.cpufreq),
        memlock_finding(data.memlock, &data.rdma, ram),
        numa_balancing_finding(data.numa_balancing, data.numa_nodes),
        smt_finding(
            &data.smt,
            data.topology.as_ref(),
            family_of(ctx.distro.as_deref()),
        ),
    ]
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

/// How many RDMA device names an evidence value lists before it counts the
/// rest.
const MAX_NAMES: usize = 8;

/// What every sentence about the locked-memory limit has to say: it is the
/// limit of the process that was measured, not of the jobs the node will run.
const OWN_SESSION: &str = "This is the limit of the session LinuxDoctor ran in: jobs started by \
                           a scheduler or a systemd service have limits of their own.";

fn limit_text(limit: Limit) -> String {
    match limit {
        Limit::Unlimited => "unlimited".to_string(),
        Limit::Bytes(bytes) => human_size(bytes),
    }
}

/// The device names, `mlx5_0, mlx5_1`; the first few and a count when there
/// are many.
fn names_text(devices: &[RdmaDevice]) -> String {
    let shown = devices
        .iter()
        .take(MAX_NAMES)
        .map(|d| d.name.as_str())
        .collect::<Vec<_>>()
        .join(", ");
    match devices.len().saturating_sub(MAX_NAMES) {
        0 => shown,
        more => format!("{shown}, and {more} more"),
    }
}

/// The link layers of all the ports, without repeats: `Ethernet, InfiniBand`.
fn link_layers_text(devices: &[RdmaDevice]) -> Option<String> {
    let layers: BTreeSet<&str> = devices
        .iter()
        .flat_map(|d| d.link_layers.iter().map(String::as_str))
        .collect();
    if layers.is_empty() {
        None
    } else {
        Some(layers.into_iter().collect::<Vec<_>>().join(", "))
    }
}

/// Whether the locked-memory limit leaves RDMA the memory it can ask for.
enum Fit {
    Enough,
    Short,
    /// Finite, but the amount of RAM is not known to compare it with.
    Unknown,
}

/// HPC002 -- the locked-memory limit, judged for a node with RDMA devices.
/// RDMA locks the memory it transfers in RAM, and the kernel counts that
/// against the process's `RLIMIT_MEMLOCK` (the default, a few MiB, is far
/// below what an MPI job registers). Always reported, like HPC001: a node
/// with no RDMA device says so, instead of staying silent.
fn memlock_finding(memlock: Option<MemLock>, rdma: &[RdmaDevice], ram: u64) -> Finding {
    let builder = |severity: Severity, confidence: Confidence| {
        let devices = if rdma.is_empty() {
            "none".to_string()
        } else {
            names_text(rdma)
        };
        let mut finding = Finding::builder(
            "HPC002",
            "Locked Memory Limit",
            Category::Memory,
            severity,
            confidence,
        )
        .evidence("rdma_devices", devices);
        if let Some(layers) = link_layers_text(rdma) {
            finding = finding.evidence("rdma_link_layers", layers);
        }
        if let Some(limits) = memlock {
            finding = finding
                .evidence("memlock_soft", limit_text(limits.soft))
                .evidence("memlock_hard", limit_text(limits.hard));
            if ram > 0 {
                finding = finding.evidence("ram", human_size(ram));
            }
        }
        finding
    };
    let info = |explanation: String| {
        builder(Severity::Info, Confidence::direct_observation())
            .explanation(explanation)
            .build()
    };

    if rdma.is_empty() {
        let limit = memlock.map_or(String::new(), |m| {
            format!(" (soft limit {})", limit_text(m.soft))
        });
        return info(format!(
            "No RDMA device (InfiniBand, RoCE) is listed, so the limit on locked memory{limit} \
             does not matter for RDMA here. A card whose driver is not loaded does not appear."
        ));
    }

    let n = rdma.len();
    let what = format!(
        "{n} RDMA device{} ({})",
        if n == 1 { "" } else { "s" },
        names_text(rdma)
    );
    let Some(limits) = memlock else {
        return info(format!(
            "{what} found, but the limit on locked memory could not be read from \
             /proc/self/limits. RDMA needs it to be unlimited or close to the RAM; check it with \
             `ulimit -l`."
        ));
    };

    let soft = limit_text(limits.soft);
    let fit = match limits.soft {
        Limit::Unlimited => Fit::Enough,
        Limit::Bytes(_) if ram == 0 => Fit::Unknown,
        Limit::Bytes(bytes) if bytes >= ram => Fit::Enough,
        Limit::Bytes(_) => Fit::Short,
    };
    match fit {
        Fit::Enough => {
            let against = if limits.soft == Limit::Unlimited {
                String::new()
            } else {
                format!(", at least the {} of RAM", human_size(ram))
            };
            info(format!(
                "{what} found. The soft limit on locked memory is {soft}{against}, so RDMA can \
                 lock all the memory it needs. {OWN_SESSION}"
            ))
        }
        Fit::Unknown => info(format!(
            "{what} found. The soft limit on locked memory is {soft}; the amount of RAM is not \
             known, so it cannot be compared with it. RDMA needs the limit to be unlimited or \
             close to the RAM. {OWN_SESSION}"
        )),
        Fit::Short => {
            let raise = match limits.hard {
                Limit::Bytes(bytes) if bytes < ram => format!(
                    "The hard limit is {} as well, so raising the limit takes root.",
                    human_size(bytes)
                ),
                hard => format!(
                    "The hard limit ({}) lets users raise it themselves.",
                    limit_text(hard)
                ),
            };
            builder(Severity::Warning, Confidence::strong_indication(75))
                .explanation(format!(
                    "{what} found, but the soft limit on locked memory is only {soft} for {} of \
                     RAM. RDMA locks the memory it transfers in RAM; an application that \
                     registers more than the limit allows (an MPI job does) fails to register \
                     memory, and the job either stops or falls back to a slower transport. \
                     {raise} {OWN_SESSION}",
                    human_size(ram)
                ))
                .recommendation(memlock_steps())
                .build()
        }
    }
}

fn memlock_steps() -> String {
    Steps::new()
        .step(
            "Raise the limit in the current shell and the jobs it starts (this needs the hard \
             limit to allow it, or root):",
            &["ulimit -l unlimited"],
        )
        .step(
            "Make it permanent for logins; PAM applies this file at every login. The `*` lines \
             do not cover root: add `root` lines if root runs jobs:",
            &["printf '* soft memlock unlimited\\n* hard memlock unlimited\\n' | sudo tee /etc/security/limits.d/90-memlock.conf"],
        )
        .step(
            "Services started by systemd do not read that file; give them the same default (a \
             service started after this, or after a reboot, gets it; a running service keeps \
             its limit until it is restarted):",
            &[
                "sudo mkdir -p /etc/systemd/system.conf.d",
                "printf '[Manager]\\nDefaultLimitMEMLOCK=infinity\\n' | sudo tee /etc/systemd/system.conf.d/memlock.conf",
                "sudo systemctl daemon-reexec",
            ],
        )
        .step(
            "Check the result in a new login session, and the default systemd gives to services:",
            &["ulimit -l", "systemctl show -p DefaultLimitMEMLOCK"],
        )
        .build()
}

/// How automatic NUMA balancing is set. The sysctl is a bit field: bit 0
/// balances pages and tasks between the nodes, bit 1 optimises page
/// placement for memory of different speeds (memory tiering).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Balancing {
    Off,
    Normal,
    Tiering,
    Both,
    /// A value with bits this tool does not know.
    Other(u32),
}

fn balancing(value: u32) -> Balancing {
    match value {
        0 => Balancing::Off,
        1 => Balancing::Normal,
        2 => Balancing::Tiering,
        3 => Balancing::Both,
        other => Balancing::Other(other),
    }
}

/// HPC003 -- automatic NUMA balancing. Reported, never judged: whether it
/// helps depends on whether the jobs are bound to NUMA nodes, which the node
/// cannot tell. What it says is how the kernel is set and what that means
/// for each kind of job. Always reported, like HPC001.
fn numa_balancing_finding(value: Option<u32>, nodes: usize) -> Finding {
    let mut builder = Finding::builder(
        "HPC003",
        "Automatic NUMA Balancing",
        Category::Numa,
        Severity::Info,
        Confidence::direct_observation(),
    );
    if let Some(value) = value {
        builder = builder.evidence("numa_balancing", value.to_string());
    }
    builder = builder.evidence("numa_nodes", nodes.to_string());

    let Some(value) = value else {
        return builder
            .explanation(
                "The kernel has no switch for automatic NUMA balancing \
                 (`/proc/sys/kernel/numa_balancing` is missing): it is built without it. There \
                 is nothing to check here.",
            )
            .build();
    };
    let state = balancing(value);
    if nodes < 2 {
        let setting = match state {
            Balancing::Off => "off".to_string(),
            Balancing::Normal => "on".to_string(),
            Balancing::Tiering => "memory tiering".to_string(),
            Balancing::Both => "on, with memory tiering".to_string(),
            Balancing::Other(v) => format!("value {v}"),
        };
        let layout = if nodes == 1 {
            "This machine has a single NUMA node"
        } else {
            "No NUMA node was found"
        };
        return builder
            .explanation(format!(
                "{layout}, so there is no remote memory to balance toward and the setting \
                 ({setting}) changes nothing here."
            ))
            .build();
    }

    let normal = format!(
        "Automatic NUMA balancing is on across {nodes} NUMA nodes: the kernel periodically \
         unmaps pages, takes the page faults that follow to see which node uses them, and moves \
         memory toward it. That helps jobs that are not bound to nodes. The faults cost time \
         that better locality may not win back, and the kernel documentation says to disable \
         the feature for a workload already bound to NUMA nodes."
    );
    let tiering = "optimises page placement for memory of different speeds (frequently used \
                   pages are moved to the faster tier)";
    match state {
        Balancing::Off => builder.explanation(format!(
            "Automatic NUMA balancing is off across {nodes} NUMA nodes. Memory stays on the node \
             where a job first touched it: that is what jobs bound to NUMA nodes (numactl, MPI \
             or Slurm binding) want, while a job that is not bound gets no help in moving \
             memory next to the CPUs that use it."
        )),
        Balancing::Normal => builder
            .explanation(normal)
            .recommendation(numa_balancing_steps()),
        Balancing::Tiering => builder.explanation(format!(
            "Automatic NUMA balancing is in memory tiering mode (value 2): the kernel {tiering}, \
             not between ordinary nodes of the same speed."
        )),
        Balancing::Both => builder.explanation(format!(
            "{normal} Memory tiering is also enabled (value 3): the kernel {tiering}."
        )),
        Balancing::Other(v) => builder.explanation(format!(
            "The value of the switch ({v}) has bits this tool does not know: 0 is off, 1 \
             balances between nodes, 2 is memory tiering, and 3 is both."
        )),
    }
    .build()
}

fn numa_balancing_steps() -> String {
    Steps::new()
        .step_owned(
            "If your jobs are bound to NUMA nodes (numactl, MPI or Slurm binding), switch it \
             off now and keep it off at every boot:",
            sysctl_commands("kernel.numa_balancing=0", "90-numa-balancing.conf"),
        )
        .step(
            "Check the result:",
            &["cat /proc/sys/kernel/numa_balancing"],
        )
        .build()
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SmtState {
    /// The processors have none.
    Unsupported,
    /// Off, and the kernel will not switch it on again before a reboot.
    ForcedOff,
    Off,
    On,
    Unknown,
}

/// `control` decides when it says something; otherwise `active`, then the
/// topology (more logical CPUs than cores means threads share cores).
fn smt_state(smt: &Smt, topology: Option<&CpuTopology>) -> SmtState {
    match smt.control.as_deref() {
        Some("notsupported") => SmtState::Unsupported,
        Some("forceoff") => SmtState::ForcedOff,
        Some("off") => SmtState::Off,
        Some("on") => SmtState::On,
        // `notimplemented`, a word this tool does not know, or no file.
        _ => match (smt.active, topology) {
            (Some(true), _) => SmtState::On,
            (Some(false), _) => SmtState::Off,
            (None, Some(t)) if t.logical > t.cores => SmtState::On,
            (None, Some(_)) => SmtState::Off,
            (None, None) => SmtState::Unknown,
        },
    }
}

/// `56 logical CPUs on 28 cores, 2 threads per core`.
fn shape_text(topology: &CpuTopology) -> String {
    let base = format!(
        "{} logical CPUs on {} cores",
        topology.logical, topology.cores
    );
    match topology.threads_per_core {
        Some(1) => format!("{base}, 1 thread per core"),
        Some(n) => format!("{base}, {n} threads per core"),
        None => format!("{base} (not the same number of threads on every core)"),
    }
}

/// HPC004 -- SMT (hyper-threading). Reported, never judged: for jobs that
/// fill every CPU and compute, one thread per core is often faster, for jobs
/// that wait on memory the second thread often helps, and only a measurement
/// on the real jobs settles it. Always reported, like HPC001.
fn smt_finding(smt: &Smt, topology: Option<&CpuTopology>, family: Family) -> Finding {
    let state = smt_state(smt, topology);
    let mut builder = Finding::builder(
        "HPC004",
        "SMT (Hyper-Threading)",
        Category::Cpu,
        Severity::Info,
        Confidence::direct_observation(),
    );
    if let Some(control) = &smt.control {
        builder = builder.evidence("smt_control", control.clone());
    }
    if let Some(active) = smt.active {
        builder = builder.evidence("smt_active", if active { "1" } else { "0" });
    }
    if let Some(t) = topology {
        builder = builder
            .evidence("logical_cpus", t.logical.to_string())
            .evidence("cores", t.cores.to_string());
        if let Some(n) = t.threads_per_core {
            builder = builder.evidence("threads_per_core", n.to_string());
        }
    }
    let topology_sentence = topology.map_or(String::new(), |t| {
        format!(" The topology shows {}.", shape_text(t))
    });

    match state {
        SmtState::Unsupported => builder.explanation(format!(
            "The processors have no SMT (hyper-threading): each core runs one \
             thread.{topology_sentence}"
        )),
        SmtState::ForcedOff => builder.explanation(format!(
            "SMT is forced off and cannot be switched back on without a reboot (for example by \
             the `nosmt=force` kernel parameter): each core runs one \
             thread.{topology_sentence}"
        )),
        SmtState::Off => builder.explanation(format!(
            "SMT is off: each core runs one thread, so a job that uses every CPU does not make \
             two threads share a core's execution units. Many compute nodes run this way; jobs \
             that mostly wait on memory can do better with SMT on.{topology_sentence}"
        )),
        SmtState::On => {
            let explanation = format!(
                "SMT is on: several threads share each core's execution units. That helps jobs \
                 that mostly wait on memory and can slow compute-bound jobs that use every \
                 logical CPU, which is why many sites turn it off on compute nodes. Which is \
                 better depends on your jobs: measure them.{topology_sentence}"
            );
            // Switching it off at run time needs the kernel to offer it.
            if smt.control.as_deref() == Some("on") {
                builder
                    .explanation(explanation)
                    .recommendation(smt_steps(family))
            } else {
                builder.explanation(explanation)
            }
        }
        SmtState::Unknown => builder.explanation(
            "The kernel exposes no SMT state here and the CPU topology could not be read \
             either, so whether threads share cores is not known.",
        ),
    }
    .build()
}

fn smt_steps(family: Family) -> String {
    let regenerate: &[&str] = match family {
        Family::DebianLike => &["sudo update-grub"],
        Family::RedHatLike => &["sudo grub2-mkconfig -o /boot/grub2/grub.cfg"],
        Family::Unknown => &[],
    };
    let regenerate_text = match family {
        Family::Unknown => {
            "Regenerate the boot configuration with your distribution's tool, then reboot."
        }
        _ => "Regenerate the boot configuration, then reboot:",
    };
    Steps::new()
        .step(
            "If your jobs do better with one thread per core, switch SMT off now (it lasts until \
             the next reboot):",
            &["echo off | sudo tee /sys/devices/system/cpu/smt/control"],
        )
        .step(
            "Make it permanent with the `nosmt` kernel parameter: add it to GRUB_CMDLINE_LINUX \
             in this file, if the machine boots with GRUB:",
            &["sudoedit /etc/default/grub"],
        )
        .step(regenerate_text, regenerate)
        .step(
            "Check the result after the reboot (it should say `off`):",
            &["cat /sys/devices/system/cpu/smt/control"],
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

    /// HPC001 for these CPUs (the other finding is not looked at).
    fn finding_of(cpufreq: Vec<CpuFreq>) -> Finding {
        let data = HpcRawData {
            cpufreq,
            ..Default::default()
        };
        let mut findings = analyze(&data, &ctx());
        assert_eq!(findings.len(), 4);
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

    const MIB: u64 = 1024 * 1024;
    const GIB: u64 = 1024 * MIB;

    fn soft_hard(soft: Limit, hard: Limit) -> Option<MemLock> {
        Some(MemLock { soft, hard })
    }

    fn device(name: &str, layers: &[&str]) -> RdmaDevice {
        RdmaDevice {
            name: name.to_string(),
            link_layers: layers.iter().map(|l| l.to_string()).collect(),
        }
    }

    fn mlx() -> Vec<RdmaDevice> {
        vec![device("mlx5_0", &["InfiniBand"])]
    }

    /// HPC002 for a node with `ram` bytes of RAM.
    fn memlock_of(memlock: Option<MemLock>, rdma: Vec<RdmaDevice>, ram: u64) -> Finding {
        let data = HpcRawData {
            memlock,
            rdma,
            ..Default::default()
        };
        let ctx = Context {
            mem_total_kb: ram / 1024,
            ..ctx()
        };
        let mut findings = analyze(&data, &ctx);
        assert_eq!(findings.len(), 4);
        findings.remove(1)
    }

    #[test]
    fn the_findings_come_in_the_order_of_their_ids() {
        let ids: Vec<String> = analyze(&HpcRawData::default(), &ctx())
            .into_iter()
            .map(|f| f.id)
            .collect();
        assert_eq!(ids, ["HPC001", "HPC002", "HPC003", "HPC004"]);
    }

    #[test]
    fn without_an_rdma_device_the_limit_is_said_not_to_matter() {
        let limits = soft_hard(Limit::Bytes(8 * MIB), Limit::Bytes(8 * MIB));
        let f = memlock_of(limits, vec![], 64 * GIB);
        assert_eq!(f.id, "HPC002");
        assert_eq!(f.severity, Severity::Info);
        assert_eq!(f.confidence.percent, 100);
        assert!(f.recommendation.is_none());
        assert_eq!(evidence(&f, "rdma_devices"), Some("none"));
        assert_eq!(evidence(&f, "rdma_link_layers"), None);
        let text = f.explanation.as_str();
        assert!(text.contains("No RDMA device"), "{text}");
        assert!(text.contains("soft limit 8.0 MiB"), "{text}");
        assert!(text.contains("driver is not loaded"), "{text}");
    }

    #[test]
    fn without_an_rdma_device_and_without_a_reading_nothing_is_claimed_about_the_limit() {
        let f = memlock_of(None, vec![], 64 * GIB);
        assert_eq!(f.severity, Severity::Info);
        let text = f.explanation.as_str();
        assert!(text.contains("No RDMA device"), "{text}");
        assert!(!text.contains("soft limit"), "{text}");
        assert_eq!(evidence(&f, "memlock_soft"), None);
        assert_eq!(evidence(&f, "memlock_hard"), None);
        assert_eq!(evidence(&f, "ram"), None);
    }

    #[test]
    fn an_unreadable_limit_with_rdma_present_is_reported_not_judged() {
        let f = memlock_of(None, mlx(), 64 * GIB);
        assert_eq!(f.severity, Severity::Info);
        assert_eq!(f.confidence.percent, 100);
        assert!(f.recommendation.is_none());
        let text = f.explanation.as_str();
        assert!(text.contains("1 RDMA device (mlx5_0) found"), "{text}");
        assert!(text.contains("could not be read"), "{text}");
        assert!(text.contains("`ulimit -l`"), "{text}");
        assert_eq!(evidence(&f, "rdma_devices"), Some("mlx5_0"));
        assert_eq!(evidence(&f, "memlock_soft"), None);
    }

    #[test]
    fn an_unlimited_soft_limit_is_fine_whatever_the_hard_one() {
        for hard in [Limit::Unlimited, Limit::Bytes(MIB)] {
            let f = memlock_of(soft_hard(Limit::Unlimited, hard), mlx(), 64 * GIB);
            assert_eq!(f.severity, Severity::Info, "{hard:?}");
            assert_eq!(f.confidence.percent, 100);
            assert!(f.recommendation.is_none());
            let text = f.explanation.as_str();
            assert!(text.contains("is unlimited, so RDMA can lock"), "{text}");
            assert!(!text.contains("at least the"), "{text}");
            assert!(text.contains("limits of their own"), "{text}");
        }
    }

    #[test]
    fn a_finite_limit_is_fine_from_the_amount_of_ram_up() {
        let ram = 64 * GIB;
        for soft in [ram, ram + 1, 2 * ram] {
            let f = memlock_of(soft_hard(Limit::Bytes(soft), Limit::Unlimited), mlx(), ram);
            assert_eq!(f.severity, Severity::Info, "{soft}");
            let text = f.explanation.as_str();
            assert!(text.contains("at least the 64.0 GiB of RAM"), "{text}");
            assert!(text.contains("limits of their own"), "{text}");
        }
    }

    #[test]
    fn a_limit_below_the_ram_with_rdma_present_is_a_warning_with_the_steps() {
        let ram = 64 * GIB;
        for soft in [8 * MIB, ram - 1] {
            let f = memlock_of(soft_hard(Limit::Bytes(soft), Limit::Unlimited), mlx(), ram);
            assert_eq!(f.severity, Severity::Warning, "{soft}");
            assert_eq!(f.confidence.percent, 75);
            assert_eq!(f.category, Category::Memory);
            let text = f.explanation.as_str();
            assert!(text.contains("only"), "{text}");
            assert!(text.contains("for 64.0 GiB of RAM"), "{text}");
            assert!(text.contains("fails to register memory"), "{text}");
            assert!(text.contains("limits of their own"), "{text}");
            let steps = f.recommendation.as_deref().unwrap();
            for expected in [
                "1. ",
                "2. ",
                "3. ",
                "4. ",
                "ulimit -l unlimited",
                "printf '* soft memlock unlimited\\n* hard memlock unlimited\\n' | sudo tee /etc/security/limits.d/90-memlock.conf",
                "printf '[Manager]\\nDefaultLimitMEMLOCK=infinity\\n' | sudo tee /etc/systemd/system.conf.d/memlock.conf",
                "systemctl daemon-reexec",
                "systemctl show -p DefaultLimitMEMLOCK",
            ] {
                assert!(steps.contains(expected), "{expected} in {steps}");
            }
        }
    }

    #[test]
    fn the_warning_says_whether_users_can_raise_the_limit_themselves() {
        let ram = 64 * GIB;
        let said = |hard: Limit| {
            let f = memlock_of(soft_hard(Limit::Bytes(8 * MIB), hard), mlx(), ram);
            assert_eq!(f.severity, Severity::Warning);
            f.explanation
        };
        for hard in [Limit::Unlimited, Limit::Bytes(ram), Limit::Bytes(ram + 1)] {
            let text = said(hard);
            assert!(text.contains("lets users raise it themselves"), "{text}");
            assert!(!text.contains("takes root"), "{text}");
        }
        let text = said(Limit::Bytes(ram - 1));
        assert!(text.contains("takes root"), "{text}");
        assert!(!text.contains("raise it themselves"), "{text}");
        let text = said(Limit::Bytes(8 * MIB));
        assert!(text.contains("The hard limit is 8.0 MiB as well"), "{text}");
    }

    #[test]
    fn a_finite_limit_is_not_judged_when_the_ram_is_not_known() {
        let f = memlock_of(
            soft_hard(Limit::Bytes(8 * MIB), Limit::Bytes(8 * MIB)),
            mlx(),
            0,
        );
        assert_eq!(f.severity, Severity::Info);
        assert!(f.recommendation.is_none());
        let text = f.explanation.as_str();
        assert!(text.contains("not known"), "{text}");
        assert!(text.contains("limits of their own"), "{text}");
        assert_eq!(evidence(&f, "ram"), None);
        // An unlimited one needs no comparison.
        let f = memlock_of(soft_hard(Limit::Unlimited, Limit::Unlimited), mlx(), 0);
        assert!(f.explanation.contains("is unlimited, so"));
    }

    #[test]
    fn the_evidence_gives_the_limits_the_ram_and_the_devices() {
        let devices = vec![
            device("mlx5_0", &["InfiniBand"]),
            device("mlx5_1", &["Ethernet"]),
            device("rxe0", &["Ethernet", "InfiniBand"]),
        ];
        let f = memlock_of(
            soft_hard(Limit::Bytes(64 * 1024), Limit::Unlimited),
            devices,
            32 * GIB,
        );
        assert_eq!(evidence(&f, "rdma_devices"), Some("mlx5_0, mlx5_1, rxe0"));
        assert_eq!(
            evidence(&f, "rdma_link_layers"),
            Some("Ethernet, InfiniBand")
        );
        assert_eq!(evidence(&f, "memlock_soft"), Some("64.0 KiB"));
        assert_eq!(evidence(&f, "memlock_hard"), Some("unlimited"));
        assert_eq!(evidence(&f, "ram"), Some("32.0 GiB"));
        let text = f.explanation.as_str();
        assert!(
            text.contains("3 RDMA devices (mlx5_0, mlx5_1, rxe0) found"),
            "{text}"
        );
    }

    #[test]
    fn link_layers_are_left_out_when_no_port_gave_one() {
        let f = memlock_of(
            soft_hard(Limit::Unlimited, Limit::Unlimited),
            vec![device("mlx5_0", &[])],
            GIB,
        );
        assert_eq!(evidence(&f, "rdma_link_layers"), None);
        assert_eq!(evidence(&f, "rdma_devices"), Some("mlx5_0"));
    }

    #[test]
    fn many_devices_are_listed_up_to_a_limit_and_then_counted() {
        let many = |n: usize| -> Vec<RdmaDevice> {
            (0..n).map(|i| device(&format!("d{i}"), &[])).collect()
        };
        assert_eq!(names_text(&many(1)), "d0");
        assert_eq!(
            names_text(&many(MAX_NAMES)),
            "d0, d1, d2, d3, d4, d5, d6, d7"
        );
        assert_eq!(
            names_text(&many(MAX_NAMES + 1)),
            "d0, d1, d2, d3, d4, d5, d6, d7, and 1 more"
        );
        assert_eq!(
            names_text(&many(MAX_NAMES + 5)),
            "d0, d1, d2, d3, d4, d5, d6, d7, and 5 more"
        );
    }

    #[test]
    fn a_limit_is_written_as_unlimited_or_as_a_size() {
        assert_eq!(limit_text(Limit::Unlimited), "unlimited");
        assert_eq!(limit_text(Limit::Bytes(0)), "0 B");
        assert_eq!(limit_text(Limit::Bytes(65_536)), "64.0 KiB");
        assert_eq!(limit_text(Limit::Bytes(8 * MIB)), "8.0 MiB");
    }

    /// HPC003 for a machine with `nodes` NUMA nodes.
    fn numa_of(value: Option<u32>, nodes: usize) -> Finding {
        let data = HpcRawData {
            numa_balancing: value,
            numa_nodes: nodes,
            ..Default::default()
        };
        let mut findings = analyze(&data, &ctx());
        assert_eq!(findings.len(), 4);
        findings.remove(2)
    }

    #[test]
    fn numa_balancing_is_always_an_information_about_numa() {
        for (value, nodes) in [
            (None, 2),
            (Some(0), 1),
            (Some(1), 2),
            (Some(2), 2),
            (Some(9), 4),
        ] {
            let f = numa_of(value, nodes);
            assert_eq!(f.id, "HPC003");
            assert_eq!(f.title, "Automatic NUMA Balancing");
            assert_eq!(f.category, Category::Numa);
            assert_eq!(f.severity, Severity::Info, "{value:?} {nodes}");
            assert_eq!(f.confidence.percent, 100);
            assert_eq!(evidence(&f, "numa_nodes"), Some(nodes.to_string().as_str()));
        }
    }

    #[test]
    fn a_kernel_without_the_switch_says_there_is_nothing_to_check() {
        let f = numa_of(None, 2);
        assert!(f.explanation.contains("no switch"), "{}", f.explanation);
        assert_eq!(evidence(&f, "numa_balancing"), None);
        assert!(f.recommendation.is_none());
    }

    #[test]
    fn with_fewer_than_two_nodes_the_setting_changes_nothing() {
        for (value, setting) in [
            (0, "off"),
            (1, "on"),
            (2, "memory tiering"),
            (3, "on, with memory tiering"),
            (7, "value 7"),
        ] {
            for nodes in [0, 1] {
                let f = numa_of(Some(value), nodes);
                let text = &f.explanation;
                let layout = if nodes == 1 {
                    "This machine has a single NUMA node,"
                } else {
                    "No NUMA node was found,"
                };
                assert!(text.contains(layout), "{text}");
                assert!(text.contains(&format!("the setting ({setting})")), "{text}");
                assert!(f.recommendation.is_none(), "{value} {nodes}");
            }
        }
        assert_eq!(evidence(&numa_of(Some(1), 1), "numa_balancing"), Some("1"));
    }

    #[test]
    fn off_across_several_nodes_suits_bound_jobs() {
        let f = numa_of(Some(0), 2);
        let text = &f.explanation;
        assert!(text.contains("is off across 2 NUMA nodes"), "{text}");
        assert!(text.contains("first touched"), "{text}");
        assert!(text.contains("numactl"), "{text}");
        assert!(f.recommendation.is_none());
    }

    #[test]
    fn on_across_several_nodes_is_explained_with_the_way_to_switch_it_off() {
        let f = numa_of(Some(1), 4);
        let text = &f.explanation;
        assert!(text.contains("is on across 4 NUMA nodes"), "{text}");
        assert!(text.contains("page faults"), "{text}");
        assert!(text.contains("already bound to NUMA nodes"), "{text}");
        assert!(!text.contains("tiering"), "{text}");
        let steps = f.recommendation.as_deref().unwrap();
        for expected in [
            "1. If your jobs are bound to NUMA nodes",
            "sudo sysctl kernel.numa_balancing=0",
            "echo 'kernel.numa_balancing = 0' | sudo tee /etc/sysctl.d/90-numa-balancing.conf",
            "2. Check the result:",
            "cat /proc/sys/kernel/numa_balancing",
        ] {
            assert!(steps.contains(expected), "{expected} in {steps}");
        }
    }

    #[test]
    fn two_nodes_are_enough_for_balancing_to_matter() {
        assert!(numa_of(Some(1), 2).recommendation.is_some());
        assert!(numa_of(Some(1), 1).recommendation.is_none());
    }

    #[test]
    fn memory_tiering_is_not_balancing_between_nodes() {
        let f = numa_of(Some(2), 2);
        let text = &f.explanation;
        assert!(text.contains("memory tiering mode (value 2)"), "{text}");
        assert!(text.contains("not between ordinary nodes"), "{text}");
        assert!(!text.contains("page faults"), "{text}");
        assert!(f.recommendation.is_none());
    }

    #[test]
    fn both_bits_are_described_and_the_commands_are_left_out() {
        let f = numa_of(Some(3), 2);
        let text = &f.explanation;
        assert!(text.contains("is on across 2 NUMA nodes"), "{text}");
        assert!(
            text.contains("Memory tiering is also enabled (value 3)"),
            "{text}"
        );
        // Writing 0 would also switch tiering off: not suggested blindly.
        assert!(f.recommendation.is_none());
    }

    #[test]
    fn a_value_with_unknown_bits_is_reported_not_interpreted() {
        for value in [4, 5, 7, 255] {
            let f = numa_of(Some(value), 2);
            let text = &f.explanation;
            assert!(
                text.contains(&format!("switch ({value}) has bits")),
                "{text}"
            );
            assert!(f.recommendation.is_none());
            assert_eq!(
                evidence(&f, "numa_balancing"),
                Some(value.to_string().as_str())
            );
        }
    }

    fn topology(logical: usize, cores: usize, per_core: Option<usize>) -> Option<CpuTopology> {
        Some(CpuTopology {
            logical,
            cores,
            threads_per_core: per_core,
        })
    }

    fn smt(control: Option<&str>, active: Option<bool>) -> Smt {
        Smt {
            control: control.map(str::to_string),
            active,
        }
    }

    /// HPC004 on a machine of the given distribution.
    fn smt_of(smt: Smt, topology: Option<CpuTopology>, distro: Option<&str>) -> Finding {
        let data = HpcRawData {
            smt,
            topology,
            ..Default::default()
        };
        let ctx = Context {
            distro: distro.map(str::to_string),
            ..ctx()
        };
        let mut findings = analyze(&data, &ctx);
        assert_eq!(findings.len(), 4);
        findings.remove(3)
    }

    fn smt_text(control: Option<&str>, active: Option<bool>, t: Option<CpuTopology>) -> String {
        smt_of(smt(control, active), t, None).explanation
    }

    #[test]
    fn smt_is_always_an_information_about_the_cpu() {
        for (control, active) in [
            (Some("on"), Some(true)),
            (Some("off"), Some(false)),
            (Some("forceoff"), Some(false)),
            (Some("notsupported"), Some(false)),
            (None, None),
        ] {
            let f = smt_of(smt(control, active), topology(8, 4, Some(2)), None);
            assert_eq!(f.id, "HPC004");
            assert_eq!(f.title, "SMT (Hyper-Threading)");
            assert_eq!(f.category, Category::Cpu);
            assert_eq!(f.severity, Severity::Info, "{control:?}");
            assert_eq!(f.confidence.percent, 100);
        }
    }

    #[test]
    fn a_processor_without_smt_says_so() {
        let text = smt_text(Some("notsupported"), Some(false), topology(4, 4, Some(1)));
        assert!(text.contains("no SMT"), "{text}");
        assert!(
            text.contains("The topology shows 4 logical CPUs on 4 cores, 1 thread per core."),
            "{text}"
        );
        let f = smt_of(smt(Some("notsupported"), None), None, None);
        assert!(f.recommendation.is_none());
        assert!(!f.explanation.contains("topology"), "{}", f.explanation);
    }

    #[test]
    fn forced_off_cannot_be_switched_back_on() {
        let f = smt_of(
            smt(Some("forceoff"), Some(false)),
            topology(28, 28, Some(1)),
            None,
        );
        assert!(f.explanation.contains("forced off"), "{}", f.explanation);
        assert!(f.explanation.contains("nosmt=force"), "{}", f.explanation);
        assert!(f.recommendation.is_none());
    }

    #[test]
    fn off_is_described_with_both_sides_of_the_choice() {
        let f = smt_of(
            smt(Some("off"), Some(false)),
            topology(28, 28, Some(1)),
            None,
        );
        let text = &f.explanation;
        assert!(text.contains("SMT is off"), "{text}");
        assert!(text.contains("mostly wait on memory"), "{text}");
        assert!(
            text.contains("28 logical CPUs on 28 cores, 1 thread per core"),
            "{text}"
        );
        assert!(f.recommendation.is_none());
    }

    #[test]
    fn on_is_described_with_both_sides_and_the_way_to_switch_it_off() {
        let f = smt_of(
            smt(Some("on"), Some(true)),
            topology(56, 28, Some(2)),
            Some("Ubuntu 26.04.1 LTS"),
        );
        let text = &f.explanation;
        assert!(text.contains("SMT is on"), "{text}");
        assert!(text.contains("slow compute-bound jobs"), "{text}");
        assert!(text.contains("measure them"), "{text}");
        assert!(
            text.contains("56 logical CPUs on 28 cores, 2 threads per core"),
            "{text}"
        );
        let steps = f.recommendation.as_deref().unwrap();
        for expected in [
            "1. If your jobs do better with one thread per core",
            "echo off | sudo tee /sys/devices/system/cpu/smt/control",
            "2. Make it permanent with the `nosmt` kernel parameter",
            "sudoedit /etc/default/grub",
            "3. Regenerate the boot configuration, then reboot:",
            "sudo update-grub",
            "4. Check the result after the reboot",
            "cat /sys/devices/system/cpu/smt/control",
        ] {
            assert!(steps.contains(expected), "{expected} in {steps}");
        }
        assert!(!steps.contains("grub2-mkconfig"), "{steps}");
    }

    #[test]
    fn the_command_that_regenerates_the_boot_configuration_follows_the_distribution() {
        let steps = |distro: Option<&str>| {
            smt_of(smt(Some("on"), Some(true)), None, distro)
                .recommendation
                .unwrap()
        };
        let debian = steps(Some("Debian GNU/Linux 12"));
        assert!(debian.contains("sudo update-grub"), "{debian}");
        let redhat = steps(Some("Rocky Linux 9.3"));
        assert!(
            redhat.contains("sudo grub2-mkconfig -o /boot/grub2/grub.cfg"),
            "{redhat}"
        );
        assert!(!redhat.contains("update-grub"), "{redhat}");
        for other in [Some("Arch Linux"), None] {
            let text = steps(other);
            assert!(text.contains("3. Regenerate the boot configuration with your distribution's tool, then reboot."), "{text}");
            assert!(!text.contains("update-grub"), "{text}");
            assert!(!text.contains("grub2-mkconfig"), "{text}");
            assert!(text.contains("4. Check the result"), "{text}");
        }
    }

    #[test]
    fn smt_that_cannot_be_switched_at_run_time_comes_without_steps() {
        // No `control`, `notimplemented`, or a word this tool does not know.
        for control in [None, Some("notimplemented"), Some("2")] {
            let f = smt_of(smt(control, Some(true)), topology(8, 4, Some(2)), None);
            assert!(f.explanation.contains("SMT is on"), "{control:?}");
            assert!(f.recommendation.is_none(), "{control:?}");
        }
    }

    #[test]
    fn the_control_file_decides_before_active_and_the_topology() {
        let t = topology(8, 4, Some(2));
        assert!(smt_text(Some("off"), Some(true), t.clone()).contains("SMT is off"));
        assert!(smt_text(Some("on"), Some(false), topology(4, 4, Some(1))).contains("SMT is on"));
        assert!(smt_text(Some("notsupported"), Some(true), t.clone()).contains("no SMT"));
        assert!(smt_text(Some("forceoff"), Some(true), t).contains("forced off"));
    }

    #[test]
    fn without_a_control_file_active_decides_before_the_topology() {
        assert!(smt_text(None, Some(true), topology(4, 4, Some(1))).contains("SMT is on"));
        assert!(smt_text(None, Some(false), topology(8, 4, Some(2))).contains("SMT is off"));
        assert!(smt_text(Some("notimplemented"), Some(true), None).contains("SMT is on"));
        assert!(smt_text(Some("notimplemented"), Some(false), None).contains("SMT is off"));
    }

    #[test]
    fn with_nothing_but_the_topology_more_cpus_than_cores_means_smt() {
        assert!(smt_text(None, None, topology(8, 4, Some(2))).contains("SMT is on"));
        assert!(smt_text(None, None, topology(4, 4, Some(1))).contains("SMT is off"));
        // Cores of different sizes (performance and efficiency cores).
        assert!(smt_text(None, None, topology(6, 4, None)).contains("SMT is on"));
    }

    #[test]
    fn with_nothing_at_all_the_state_is_said_to_be_unknown() {
        let f = smt_of(Smt::default(), None, None);
        assert!(f.explanation.contains("is not known"), "{}", f.explanation);
        assert!(f.evidence.iter().all(|(k, _)| k != "smt_control"));
        assert!(f.recommendation.is_none());
        // A word this tool does not know and no other reading.
        let f = smt_of(smt(Some("weird"), None), None, None);
        assert!(f.explanation.contains("is not known"), "{}", f.explanation);
        assert_eq!(evidence(&f, "smt_control"), Some("weird"));
    }

    #[test]
    fn the_evidence_gives_the_control_the_activity_and_the_shape() {
        let f = smt_of(smt(Some("on"), Some(true)), topology(56, 28, Some(2)), None);
        assert_eq!(evidence(&f, "smt_control"), Some("on"));
        assert_eq!(evidence(&f, "smt_active"), Some("1"));
        assert_eq!(evidence(&f, "logical_cpus"), Some("56"));
        assert_eq!(evidence(&f, "cores"), Some("28"));
        assert_eq!(evidence(&f, "threads_per_core"), Some("2"));
        let f = smt_of(smt(Some("off"), Some(false)), topology(6, 4, None), None);
        assert_eq!(evidence(&f, "smt_active"), Some("0"));
        assert_eq!(evidence(&f, "threads_per_core"), None);
        assert!(
            f.explanation
                .contains("(not the same number of threads on every core)"),
            "{}",
            f.explanation
        );
        let f = smt_of(Smt::default(), None, None);
        for key in ["smt_active", "logical_cpus", "cores", "threads_per_core"] {
            assert_eq!(evidence(&f, key), None, "{key}");
        }
    }
}
