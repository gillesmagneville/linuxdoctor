// SPDX-License-Identifier: GPL-3.0-only

//! Kernel memory policy: overcommit (MEM011) and huge pages (MEM012).

use crate::models::{Category, Confidence, Finding, Severity};

use super::collect::{percent, MemoryRawData};
use super::format::{kb, pct, sysctl_commands, Steps};

/// In strict mode, committed memory this close to the limit means new
/// allocations are about to fail even though RAM may be free.
const COMMIT_NEAR_LIMIT_PERCENT: f64 = 90.0;

/// Programs that document needing `vm.overcommit_memory=1`.
const OVERCOMMIT_PROGRAMS: [&str; 2] = ["redis-server", "valkey-server"];

/// Programs whose vendors document disabling "always" transparent huge pages.
const THP_SENSITIVE_PROGRAMS: [&str; 5] = [
    "mongod",
    "mongos",
    "redis-server",
    "valkey-server",
    "couchbase",
];

/// Reserved but unused huge pages are worth a warning from 1 GiB and 5% of RAM.
const IDLE_HUGEPAGES_MIN_KB: u64 = 1024 * 1024;
const IDLE_HUGEPAGES_MIN_PERCENT: f64 = 5.0;

fn running<'a>(data: &'a MemoryRawData, names: &[&str]) -> Option<&'a str> {
    data.processes
        .iter()
        .find(|p| names.iter().any(|n| p.name == *n))
        .map(|p| p.name.as_str())
}

// ---------------------------------------------------------------------------
// MEM011 — overcommit
// ---------------------------------------------------------------------------

/// MEM011 — reported when vm.overcommit_memory is readable. Explains the
/// mode in use and, in the strict mode, warns when programs are about to
/// be refused memory that is physically free.
pub fn overcommit(data: &MemoryRawData) -> Option<Finding> {
    let mode = data.vm.overcommit_memory?;
    let d = &data.detail;
    let committed = d.committed_as_kb;
    let limit = d.commit_limit_kb;
    let committed_of_ram = percent(committed, data.mem_total_kb);

    let mut severity = Severity::Info;
    let mut confidence = Confidence::direct_observation();
    let mut paragraphs: Vec<String> = Vec::new();
    let mut steps = Steps::new();

    match mode {
        0 => {
            paragraphs.push(format!(
                "Overcommit is in heuristic mode (the default): the kernel lets programs reserve \
                 more memory than exists and refuses only absurd single requests. Programs have \
                 reserved {} of address space ({} of RAM). A reservation is a promise, not use: \
                 big runtimes (Java, Go, browsers) and fork() reserve far more than they touch.",
                kb(committed),
                pct(committed_of_ram)
            ));
            if let Some(name) = running(data, &OVERCOMMIT_PROGRAMS) {
                paragraphs.push(format!(
                    "{name} is running. Its documentation asks for vm.overcommit_memory=1: it \
                     saves its data by fork()ing, and under the heuristic mode that fork can fail \
                     when memory is tight, so the save fails."
                ));
                steps = steps.step_owned(
                    format!("Follow {name}'s recommendation:"),
                    sysctl_commands("vm.overcommit_memory=1", "99-overcommit.conf"),
                );
            }
        }
        1 => paragraphs.push(format!(
            "Overcommit is set to 'always': the kernel never refuses a memory request. A \
             shortage then shows up as the OOM killer terminating something, not as a program \
             being told 'out of memory' and handling it. Programs have reserved {} ({} of RAM). \
             This is what Redis recommends, but it removes a safety net for everything else.",
            kb(committed),
            pct(committed_of_ram)
        )),
        2 => {
            let limit_text = if data.vm.overcommit_kbytes.unwrap_or(0) > 0 {
                format!(
                    "{} (vm.overcommit_kbytes) plus swap",
                    kb(data.vm.overcommit_kbytes.unwrap_or(0))
                )
            } else {
                format!(
                    "swap plus {}% of RAM (vm.overcommit_ratio)",
                    data.vm.overcommit_ratio.unwrap_or(50)
                )
            };
            paragraphs.push(format!(
                "Overcommit is strict: the kernel refuses any request that would push the total \
                 reserved memory past the commit limit of {} ({limit_text}). Programs have \
                 reserved {}.",
                kb(limit),
                kb(committed),
            ));
            if limit > 0 {
                let used = percent(committed, limit);
                if used >= 100.0 {
                    severity = Severity::Error;
                    confidence = Confidence::correlated(92);
                    paragraphs.push(format!(
                        "That is {} of the limit: new allocations are being refused right now, \
                         even though RAM may be free. Programs fail with 'Cannot allocate \
                         memory' or crash.",
                        pct(used)
                    ));
                } else if used >= COMMIT_NEAR_LIMIT_PERCENT {
                    severity = Severity::Warning;
                    confidence = Confidence::strong_indication(85);
                    paragraphs.push(format!(
                        "That is {} of the limit: the next programs to start may be refused \
                         memory even though RAM is free.",
                        pct(used)
                    ));
                }
                if severity > Severity::Info {
                    steps = strict_steps(data, committed);
                }
            }
        }
        other => paragraphs.push(format!(
            "vm.overcommit_memory has the unusual value {other}."
        )),
    }

    let mut builder = Finding::builder(
        "MEM011",
        "Memory Overcommit Policy",
        Category::Memory,
        severity,
        confidence,
    )
    .evidence("vm.overcommit_memory", mode.to_string())
    .evidence("committed_as_kb", committed.to_string())
    .evidence("commit_limit_kb", limit.to_string())
    .evidence("committed_percent_of_ram", format!("{committed_of_ram:.1}"));
    if let Some(r) = data.vm.overcommit_ratio {
        builder = builder.evidence("vm.overcommit_ratio", r.to_string());
    }
    if limit > 0 {
        builder = builder.evidence(
            "committed_percent_of_limit",
            format!("{:.1}", percent(committed, limit)),
        );
    }
    builder = builder.explanation(paragraphs.join("\n\n"));
    if !steps.is_empty() {
        builder = builder.recommendation(steps.build());
    }
    Some(builder.build())
}

fn strict_steps(data: &MemoryRawData, committed: u64) -> Steps {
    let mut steps = Steps::new().step(
        "See what has reserved the memory (the biggest virtual sizes, VSZ in kB):",
        &["ps -eo pid,vsz,comm --sort=-vsz | head"],
    );
    // Ratio that would give 20% headroom over what is committed now.
    let wanted = committed + committed / 5;
    let from_swap = data.swap_total_kb;
    if data.vm.overcommit_kbytes.unwrap_or(0) == 0 && data.mem_total_kb > 0 && wanted > from_swap {
        let ratio = ((wanted - from_swap) as f64 / data.mem_total_kb as f64 * 100.0).ceil() as u64;
        if ratio <= 100 {
            steps = steps.step_owned(
                format!(
                    "Raise the commit limit: a ratio of {ratio} gives about 20% headroom over \
                     what is reserved now (the default is 50, which allows only half of RAM):"
                ),
                sysctl_commands(
                    &format!("vm.overcommit_ratio={ratio}"),
                    "99-overcommit.conf",
                ),
            );
        } else {
            steps = steps.step(
                "The limit cannot be raised enough with the ratio alone: RAM plus swap is \
                 smaller than what programs reserve. Add swap (see Swap configuration) or move \
                 to heuristic mode:",
                &["sudo sysctl vm.overcommit_memory=0"],
            );
        }
    }
    steps.step(
        "Heuristic mode (0) avoids these refusals altogether, at the price of the OOM killer \
         taking over when memory really runs out. Most general-purpose machines use it:",
        &["sudo sysctl vm.overcommit_memory=0"],
    )
}

// ---------------------------------------------------------------------------
// MEM012 — huge pages
// ---------------------------------------------------------------------------

/// MEM012 — reported when transparent huge pages are visible or explicit
/// huge pages are reserved. Warns about two real traps: "always" THP under
/// latency-sensitive databases, and RAM reserved for huge pages that
/// nothing uses.
pub fn huge_pages(data: &MemoryRawData) -> Option<Finding> {
    let d = &data.detail;
    let thp = data.vm.thp_enabled.as_deref();
    if thp.is_none() && d.hugepages_total == 0 {
        return None;
    }

    let mut severity = Severity::Info;
    let mut confidence = Confidence::direct_observation();
    let mut paragraphs: Vec<String> = Vec::new();
    let mut steps = Steps::new();
    let mut builder = Finding::builder(
        "MEM012",
        "Huge Pages",
        Category::Memory,
        severity,
        confidence.clone(),
    );

    if let Some(mode) = thp {
        let meaning = match mode {
            "always" => {
                "the kernel backs memory with 2 MB pages automatically. That speeds up programs \
                 with large heaps, but compacting memory to find those pages can cause latency \
                 spikes, and sparse memory use gets inflated"
            }
            "madvise" => {
                "only programs that explicitly ask for huge pages get them. This is the safe \
                 middle ground and what most distributions recommend for servers"
            }
            "never" => "huge pages are off; every program uses ordinary 4 KB pages",
            _ => "an unusual setting",
        };
        let in_use = if d.anon_huge_pages_kb > 0 {
            format!(
                " Right now {} of program memory sits on huge pages.",
                kb(d.anon_huge_pages_kb)
            )
        } else {
            String::new()
        };
        paragraphs.push(format!(
            "Transparent huge pages are set to '{mode}': {meaning}.{in_use}"
        ));
        builder = builder
            .evidence("transparent_hugepage", mode)
            .evidence("anon_huge_pages_kb", d.anon_huge_pages_kb.to_string());

        if mode == "always" {
            if let Some(name) = running(data, &THP_SENSITIVE_PROGRAMS) {
                severity = Severity::Warning;
                confidence = Confidence::strong_indication(88);
                paragraphs.push(format!(
                    "{name} is running. Its vendor documents that transparent huge pages in \
                     'always' mode cause latency spikes and memory bloat for it, and asks for \
                     'madvise' or 'never'."
                ));
                steps = steps
                    .step(
                        format!("Switch to madvise now ({name} keeps running; it benefits fully after a restart):"),
                        &["echo madvise | sudo tee /sys/kernel/mm/transparent_hugepage/enabled"],
                    )
                    .step(
                        "Keep it after reboot (this rule is read at boot; the kernel option \
                         transparent_hugepage=madvise does the same):",
                        &["echo 'w /sys/kernel/mm/transparent_hugepage/enabled - - - - madvise' | sudo tee /etc/tmpfiles.d/thp.conf"],
                    );
                builder = builder.evidence("thp_sensitive_program", name);
            }
        }
        if let Some(defrag) = data.vm.thp_defrag.as_deref() {
            builder = builder.evidence("transparent_hugepage_defrag", defrag);
            if mode == "always" && defrag == "always" {
                paragraphs.push(
                    "Defragmentation is also 'always': a program that needs a huge page waits \
                     while the kernel compacts memory for it, which is the usual source of THP \
                     latency stalls. 'defer+madvise' avoids the wait."
                        .to_string(),
                );
                if severity == Severity::Info {
                    steps = steps.step(
                        "Optional: stop programs from waiting on compaction:",
                        &["echo defer+madvise | sudo tee /sys/kernel/mm/transparent_hugepage/defrag"],
                    );
                }
            }
        }
    }

    if d.hugepages_total > 0 {
        let size = d.hugepage_size_kb.max(1);
        let reserved_kb = d.hugepages_total * size;
        let idle_pages = d.hugepages_free.saturating_sub(d.hugepages_rsvd);
        let idle_kb = idle_pages * size;
        let in_use_pages = d.hugepages_total.saturating_sub(d.hugepages_free);
        paragraphs.push(format!(
            "{} huge pages of {} are reserved, {} of RAM in total, and removed from what \
             ordinary programs can use. {} {} in use, {} {} idle ({} of RAM).",
            d.hugepages_total,
            kb(size),
            kb(reserved_kb),
            in_use_pages,
            if in_use_pages == 1 {
                "page is"
            } else {
                "pages are"
            },
            idle_pages,
            if idle_pages == 1 { "is" } else { "are" },
            kb(idle_kb),
        ));
        builder = builder
            .evidence("hugepages_total", d.hugepages_total.to_string())
            .evidence("hugepages_free", d.hugepages_free.to_string())
            .evidence("hugepages_reserved_pending", d.hugepages_rsvd.to_string())
            .evidence("hugepage_size_kb", size.to_string())
            .evidence("hugepages_idle_kb", idle_kb.to_string());

        if idle_kb >= IDLE_HUGEPAGES_MIN_KB
            && percent(idle_kb, data.mem_total_kb) >= IDLE_HUGEPAGES_MIN_PERCENT
        {
            if severity < Severity::Warning {
                severity = Severity::Warning;
                confidence = Confidence::strong_indication(85);
            }
            paragraphs.push(format!(
                "{} of RAM is held for huge pages that no program is using. Unlike cache, that \
                 memory can never be borrowed by anything else, so it is simply lost unless a \
                 database or VM manager is about to claim it.",
                kb(idle_kb)
            ));
            let keep = in_use_pages + d.hugepages_rsvd;
            steps = steps
                .step(
                    "If a database or virtual machine is meant to use them, check its own \
                     setting (for example huge_pages in PostgreSQL, or the hugepages option of \
                     the VM) — it may be misconfigured. Otherwise:",
                    &["grep -i huge /proc/meminfo"],
                )
                .step_owned(
                    format!(
                        "Shrink the reservation to what is actually needed ({keep} pages) and \
                         get the RAM back immediately:"
                    ),
                    sysctl_commands(&format!("vm.nr_hugepages={keep}"), "99-hugepages.conf"),
                )
                .step(
                    "If it was set by a tuning profile, find where, so it is not re-applied at boot:",
                    &["grep -r nr_hugepages /etc/sysctl.conf /etc/sysctl.d /usr/lib/sysctl.d /etc/default/grub"],
                );
        }
    }

    builder = builder.explanation(paragraphs.join("\n\n"));
    let mut finding = builder.build();
    finding.severity = severity;
    finding.confidence = confidence;
    if !steps.is_empty() {
        finding.recommendation = Some(steps.build());
    }
    Some(finding)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::modules::memory::collect::VmTunables;
    use crate::modules::memory::test_support::{evidence, healthy, proc};

    fn with_vm(mut d: MemoryRawData, vm: VmTunables) -> MemoryRawData {
        d.vm = vm;
        d
    }

    // ---- MEM011 --------------------------------------------------------

    #[test]
    fn unreadable_overcommit_mode_means_no_finding() {
        assert!(overcommit(&healthy()).is_none());
    }

    #[test]
    fn heuristic_mode_is_explained_and_quiet() {
        let mut d = with_vm(
            healthy(),
            VmTunables {
                overcommit_memory: Some(0),
                ..Default::default()
            },
        );
        d.detail.committed_as_kb = 20_000_000;
        d.detail.commit_limit_kb = 12_000_000;
        let f = overcommit(&d).unwrap();
        assert_eq!(f.id, "MEM011");
        assert_eq!(
            f.severity,
            Severity::Info,
            "exceeding the limit is normal in mode 0"
        );
        assert!(f.recommendation.is_none());
        assert!(f
            .explanation
            .contains("A reservation is a promise, not use"));
    }

    #[test]
    fn redis_under_heuristic_mode_gets_the_documented_setting() {
        let mut d = with_vm(
            healthy(),
            VmTunables {
                overcommit_memory: Some(0),
                ..Default::default()
            },
        );
        d.processes = vec![proc(5, "redis-server", 1000)];
        let f = overcommit(&d).unwrap();
        assert_eq!(f.severity, Severity::Info);
        assert!(f.explanation.contains("redis-server is running"));
        assert!(f
            .recommendation
            .unwrap()
            .contains("sudo sysctl vm.overcommit_memory=1"));
    }

    #[test]
    fn always_mode_is_explained() {
        let d = with_vm(
            healthy(),
            VmTunables {
                overcommit_memory: Some(1),
                ..Default::default()
            },
        );
        let f = overcommit(&d).unwrap();
        assert!(f.explanation.contains("never refuses"));
        assert!(f.recommendation.is_none());
    }

    #[test]
    fn strict_mode_below_the_limit_is_quiet_but_states_the_limit() {
        let mut d = with_vm(
            healthy(),
            VmTunables {
                overcommit_memory: Some(2),
                overcommit_ratio: Some(50),
                ..Default::default()
            },
        );
        d.detail.commit_limit_kb = 10_000_000;
        d.detail.committed_as_kb = 4_000_000;
        let f = overcommit(&d).unwrap();
        assert_eq!(f.severity, Severity::Info);
        assert!(f.explanation.contains("swap plus 50% of RAM"));
    }

    #[test]
    fn strict_mode_near_the_limit_warns_and_computes_a_ratio() {
        let mut d = with_vm(
            healthy(),
            VmTunables {
                overcommit_memory: Some(2),
                overcommit_ratio: Some(50),
                ..Default::default()
            },
        );
        d.detail.commit_limit_kb = 10_000_000;
        d.detail.committed_as_kb = 9_500_000; // 95%
        let f = overcommit(&d).unwrap();
        assert_eq!(f.severity, Severity::Warning);
        let rec = f.recommendation.unwrap();
        // wanted = 9.5M * 1.2 = 11.4M; minus swap 4.0M = 7.4M; / 16.0M RAM = 46.25% -> 47
        assert!(rec.contains("sudo sysctl vm.overcommit_ratio=47"), "{rec}");
        assert!(rec.contains("ps -eo pid,vsz,comm --sort=-vsz"));
        assert!(rec.contains("vm.overcommit_memory=0"));
    }

    #[test]
    fn strict_mode_at_the_limit_is_an_error() {
        let mut d = with_vm(
            healthy(),
            VmTunables {
                overcommit_memory: Some(2),
                ..Default::default()
            },
        );
        d.detail.commit_limit_kb = 10_000_000;
        d.detail.committed_as_kb = 10_000_000;
        let f = overcommit(&d).unwrap();
        assert_eq!(f.severity, Severity::Error);
        assert!(f.explanation.contains("refused right now"));
    }

    #[test]
    fn strict_mode_that_ratio_cannot_fix_points_to_swap_or_heuristic() {
        let mut d = with_vm(
            healthy(),
            VmTunables {
                overcommit_memory: Some(2),
                ..Default::default()
            },
        );
        d.detail.commit_limit_kb = 10_000_000;
        d.detail.committed_as_kb = 30_000_000;
        let rec = overcommit(&d).unwrap().recommendation.unwrap();
        assert!(rec.contains("cannot be raised enough"));
        assert!(!rec.contains("vm.overcommit_ratio="));
    }

    #[test]
    fn byte_based_limit_is_described_and_not_given_a_ratio_fix() {
        let mut d = with_vm(
            healthy(),
            VmTunables {
                overcommit_memory: Some(2),
                overcommit_kbytes: Some(8_000_000),
                ..Default::default()
            },
        );
        d.detail.commit_limit_kb = 12_000_000;
        d.detail.committed_as_kb = 11_900_000;
        let f = overcommit(&d).unwrap();
        assert!(f.explanation.contains("vm.overcommit_kbytes"));
        assert!(!f.recommendation.unwrap().contains("vm.overcommit_ratio="));
    }

    // ---- MEM012 --------------------------------------------------------

    fn thp(mode: &str) -> VmTunables {
        VmTunables {
            thp_enabled: Some(mode.into()),
            ..Default::default()
        }
    }

    #[test]
    fn nothing_to_say_without_thp_or_reserved_pages() {
        assert!(huge_pages(&healthy()).is_none());
    }

    #[test]
    fn madvise_is_described_as_the_safe_middle_ground() {
        let f = huge_pages(&with_vm(healthy(), thp("madvise"))).unwrap();
        assert_eq!(f.id, "MEM012");
        assert_eq!(f.severity, Severity::Info);
        assert!(f.explanation.contains("safe middle ground"));
        assert!(f.recommendation.is_none());
    }

    #[test]
    fn always_with_no_sensitive_program_is_info() {
        let mut d = with_vm(healthy(), thp("always"));
        d.processes = vec![proc(1, "firefox", 100)];
        let f = huge_pages(&d).unwrap();
        assert_eq!(f.severity, Severity::Info);
        assert!(f.explanation.contains("latency spikes"));
    }

    #[test]
    fn always_under_mongodb_warns_with_runtime_and_persistent_fixes() {
        let mut d = with_vm(healthy(), thp("always"));
        d.processes = vec![proc(1, "mongod", 4_000_000)];
        let f = huge_pages(&d).unwrap();
        assert_eq!(f.severity, Severity::Warning);
        assert_eq!(evidence(&f, "thp_sensitive_program"), Some("mongod"));
        let rec = f.recommendation.unwrap();
        assert!(rec.contains("echo madvise | sudo tee /sys/kernel/mm/transparent_hugepage/enabled"));
        assert!(rec.contains("/etc/tmpfiles.d/thp.conf"));
    }

    #[test]
    fn madvise_under_mongodb_is_already_right() {
        let mut d = with_vm(healthy(), thp("madvise"));
        d.processes = vec![proc(1, "mongod", 4_000_000)];
        assert_eq!(huge_pages(&d).unwrap().severity, Severity::Info);
    }

    #[test]
    fn always_defrag_is_an_optional_tweak() {
        let mut d = with_vm(
            healthy(),
            VmTunables {
                thp_enabled: Some("always".into()),
                thp_defrag: Some("always".into()),
                ..Default::default()
            },
        );
        let f = huge_pages(&d).unwrap();
        assert_eq!(f.severity, Severity::Info);
        assert!(f.recommendation.unwrap().contains("defer+madvise"));
        d.vm.thp_defrag = Some("madvise".into());
        assert!(huge_pages(&d).unwrap().recommendation.is_none());
    }

    #[test]
    fn thp_usage_is_reported() {
        let mut d = with_vm(healthy(), thp("always"));
        d.detail.anon_huge_pages_kb = 2_097_152;
        let f = huge_pages(&d).unwrap();
        assert!(f
            .explanation
            .contains("2.0 GB of program memory sits on huge pages"));
    }

    #[test]
    fn idle_reserved_huge_pages_warn_and_say_how_many_to_keep() {
        let mut d = healthy();
        d.detail.hugepages_total = 4096; // 4096 x 2 MB = 8 GB
        d.detail.hugepages_free = 3996; // 100 in use
        d.detail.hugepages_rsvd = 50;
        d.detail.hugepage_size_kb = 2048;
        let f = huge_pages(&d).unwrap();
        assert_eq!(f.severity, Severity::Warning);
        // idle = 3996 - 50 = 3946 pages = 7.7 GB
        assert!(f.explanation.contains("3946 are idle"), "{}", f.explanation);
        let rec = f.recommendation.unwrap();
        // keep = in use 100 + pending 50
        assert!(rec.contains("sudo sysctl vm.nr_hugepages=150"), "{rec}");
        assert!(rec.contains("huge_pages in PostgreSQL"));
        assert!(rec.contains("grep -r nr_hugepages"));
    }

    #[test]
    fn well_used_reservation_is_info() {
        let mut d = healthy();
        d.detail.hugepages_total = 4096;
        d.detail.hugepages_free = 100;
        d.detail.hugepage_size_kb = 2048;
        let f = huge_pages(&d).unwrap();
        assert_eq!(f.severity, Severity::Info);
        assert!(f.recommendation.is_none());
    }

    #[test]
    fn small_idle_reservation_is_not_worth_a_warning() {
        let mut d = healthy();
        d.detail.hugepages_total = 100; // 200 MB
        d.detail.hugepages_free = 100;
        d.detail.hugepage_size_kb = 2048;
        assert_eq!(huge_pages(&d).unwrap().severity, Severity::Info);
    }

    #[test]
    fn pending_reservations_are_not_idle() {
        let mut d = healthy();
        d.detail.hugepages_total = 4096;
        d.detail.hugepages_free = 4096;
        d.detail.hugepages_rsvd = 4096; // a database has claimed them all
        d.detail.hugepage_size_kb = 2048;
        assert_eq!(huge_pages(&d).unwrap().severity, Severity::Info);
    }

    #[test]
    fn thp_warning_is_not_downgraded_by_a_healthy_reservation() {
        let mut d = with_vm(healthy(), thp("always"));
        d.processes = vec![proc(1, "redis-server", 100)];
        d.detail.hugepages_total = 10;
        d.detail.hugepages_free = 0;
        d.detail.hugepage_size_kb = 2048;
        assert_eq!(huge_pages(&d).unwrap().severity, Severity::Warning);
    }
}
