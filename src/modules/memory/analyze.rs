// SPDX-License-Identifier: GPL-3.0-only

use std::cmp::Reverse;

use crate::core::context::Context;
use crate::models::{Finding, Severity};

use super::collect::MemoryRawData;
use super::{cache, kernel, pressure, shared, swap, tuning, used};

/// The pages of the module's submenu, in the order they are shown. Each
/// finding that is not serious enough to deserve the top page lives on the
/// page of its topic (see [`topic_of`]).
pub const TOPICS: [&str; 6] = [
    "Used memory",
    "Page cache",
    "Shared memory",
    "Swap",
    "Pressure",
    "Kernel tuning",
];

/// Order in which findings appear within the module (also the tie-break
/// when severities are equal).
const ORDER: [&str; 13] = [
    "MEM004", "MEM003", "MEM007", "MEM008", "MEM005", "MEM006", "MEM001", "MEM002", "MEM010",
    "MEM009", "MEM013", "MEM011", "MEM012",
];

/// Which submenu page a finding belongs to.
fn topic_of(id: &str) -> Option<&'static str> {
    match id {
        "MEM003" | "MEM007" => Some(TOPICS[0]),
        "MEM005" | "MEM008" => Some(TOPICS[1]),
        "MEM006" => Some(TOPICS[2]),
        "MEM001" | "MEM002" | "MEM010" => Some(TOPICS[3]),
        "MEM009" => Some(TOPICS[4]),
        "MEM011" | "MEM012" | "MEM013" => Some(TOPICS[5]),
        _ => None,
    }
}

fn topic_rank(topic: &str) -> usize {
    TOPICS
        .iter()
        .position(|t| *t == topic)
        .unwrap_or(TOPICS.len())
}

fn order_rank(id: &str) -> usize {
    ORDER.iter().position(|o| *o == id).unwrap_or(ORDER.len())
}

/// Pure function: RawData -> Findings. No I/O, no filesystem access, fully
/// unit-testable — this is the whole point of separating collect() from
/// analyze(). See ARCHITECTURE.md "Testing Strategy".
///
/// Layout of the result: the top page first — anything of Warning severity
/// or above, worst first (so a problem is never buried in a submenu),
/// followed by the overview (MEM004), which is the whole page on a healthy
/// machine — then the remaining findings grouped by topic: Used memory,
/// Page cache, Shared memory, Swap, Pressure, Kernel tuning.
pub fn analyze(data: &MemoryRawData, _ctx: &Context) -> Vec<Finding> {
    let mut findings = vec![
        used::overview(data),
        used::used_memory(data),
        cache::page_cache(data),
        cache::dirty_pages(data),
        shared::shared_memory(data),
        swap::swappiness(data),
        swap::swap_config(data),
    ];
    findings.extend(used::critical(data));
    findings.extend(swap::swap_activity(data));
    findings.extend(pressure::pressure(data));
    findings.extend(kernel::kernel_memory(data));
    findings.extend(tuning::overcommit(data));
    findings.extend(tuning::huge_pages(data));

    for f in &mut findings {
        f.instance = if f.id == "MEM004" || f.severity >= Severity::Warning {
            None
        } else {
            topic_of(&f.id).map(str::to_string)
        };
    }

    findings.sort_by_key(|f| {
        (
            f.instance.is_some(),
            f.instance.as_deref().map(topic_rank).unwrap_or(0),
            Reverse(f.severity),
            order_rank(&f.id),
        )
    });
    findings
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::modules::memory::collect::{
        MemoryPressure, PsiLine, SwapDevice, SwapKind, SysvSegment, TmpfsMount, VmTunables,
        VmstatCounters, ZramStats,
    };
    use crate::modules::memory::test_support::{ctx, evidence, healthy, proc};

    /// What the module could always read, and nothing else: the shape of
    /// data on a container or an old kernel.
    fn minimal() -> MemoryRawData {
        MemoryRawData {
            mem_total_kb: 16_384_000,
            mem_free_kb: 7_500_000,
            mem_available_kb: 8_000_000, // plenty free
            cached_kb: 4_300_000,
            shmem_kb: 200_000, // ~1.2%, normal
            dirty_kb: 16_000,  // ~0.1%, well below defaults
            swap_total_kb: 4_194_300,
            swap_free_kb: 4_194_300, // swap fully unused
            swappiness: 60,
            dirty_ratio: 20,
            dirty_background_ratio: 10,
            ..Default::default()
        }
    }

    fn ids(findings: &[Finding]) -> Vec<&str> {
        findings.iter().map(|f| f.id.as_str()).collect()
    }

    fn find<'a>(findings: &'a [Finding], id: &str) -> &'a Finding {
        findings
            .iter()
            .find(|f| f.id == id)
            .unwrap_or_else(|| panic!("{id} missing from {:?}", ids(findings)))
    }

    // ---- what is reported -------------------------------------------

    #[test]
    fn healthy_machine_reports_every_always_on_finding() {
        let findings = analyze(&healthy(), &ctx());
        for id in [
            "MEM001", "MEM004", "MEM005", "MEM006", "MEM007", "MEM008", "MEM010", "MEM013",
        ] {
            assert!(
                ids(&findings).contains(&id),
                "{id} missing: {:?}",
                ids(&findings)
            );
        }
        for id in ["MEM002", "MEM003", "MEM009", "MEM011", "MEM012"] {
            assert!(
                !ids(&findings).contains(&id),
                "{id} should be absent: {:?}",
                ids(&findings)
            );
        }
        assert!(findings.iter().all(|f| f.severity == Severity::Info));
    }

    #[test]
    fn minimal_data_still_produces_the_historic_findings() {
        let findings = analyze(&minimal(), &ctx());
        for id in ["MEM001", "MEM004", "MEM005", "MEM006"] {
            assert!(ids(&findings).contains(&id));
        }
        assert!(
            !ids(&findings).contains(&"MEM013"),
            "no slab data, no kernel finding"
        );
        assert!(findings.iter().all(|f| f.severity == Severity::Info));
    }

    #[test]
    fn optional_sources_add_their_findings() {
        let mut d = healthy();
        d.pressure = Some(MemoryPressure {
            some: PsiLine::default(),
            full: Some(PsiLine::default()),
        });
        d.vm = VmTunables {
            overcommit_memory: Some(0),
            thp_enabled: Some("madvise".into()),
            ..Default::default()
        };
        let findings = analyze(&d, &ctx());
        for id in ["MEM009", "MEM011", "MEM012"] {
            assert!(ids(&findings).contains(&id), "{id}");
        }
    }

    #[test]
    fn ids_are_unique() {
        let mut d = healthy();
        d.swap_free_kb = 1_000_000;
        d.vmstat = Some(VmstatCounters::default());
        let findings = analyze(&d, &ctx());
        let mut seen = ids(&findings);
        seen.sort();
        let before = seen.len();
        seen.dedup();
        assert_eq!(before, seen.len());
    }

    // ---- layout ------------------------------------------------------

    #[test]
    fn on_a_healthy_machine_the_overview_is_the_whole_top_page() {
        let findings = analyze(&healthy(), &ctx());
        assert_eq!(findings[0].id, "MEM004");
        assert!(findings[0].instance.is_none());
        assert!(findings[1..].iter().all(|f| f.instance.is_some()));
    }

    #[test]
    fn problems_come_before_the_overview() {
        let mut d = healthy();
        d.mem_available_kb = 1_200_000; // 7.5%
        let findings = analyze(&d, &ctx());
        assert_eq!(findings[0].id, "MEM007", "{:?}", ids(&findings));
        assert_eq!(findings[1].id, "MEM004");
        assert!(findings[2].instance.is_some());
    }

    #[test]
    fn quiet_findings_are_filed_under_their_topic() {
        let mut d = healthy();
        d.swap_free_kb = 3_000_000; // swap in use -> MEM002
        d.vm.overcommit_memory = Some(0);
        d.vmstat = Some(VmstatCounters::default());
        let findings = analyze(&d, &ctx());
        let topic = |id: &str| find(&findings, id).instance.clone();
        assert_eq!(topic("MEM007").as_deref(), Some("Used memory"));
        assert_eq!(topic("MEM008").as_deref(), Some("Page cache"));
        assert_eq!(topic("MEM005").as_deref(), Some("Page cache"));
        assert_eq!(topic("MEM006").as_deref(), Some("Shared memory"));
        assert_eq!(topic("MEM001").as_deref(), Some("Swap"));
        assert_eq!(topic("MEM002").as_deref(), Some("Swap"));
        assert_eq!(topic("MEM010").as_deref(), Some("Swap"));
        assert_eq!(topic("MEM009").as_deref(), Some("Pressure"));
        assert_eq!(topic("MEM013").as_deref(), Some("Kernel tuning"));
        assert_eq!(topic("MEM011").as_deref(), Some("Kernel tuning"));
        assert!(
            findings.iter().all(|f| match f.instance.as_deref() {
                None => true,
                Some(t) => TOPICS.contains(&t),
            }),
            "every instance is a declared topic"
        );
    }

    #[test]
    fn warnings_surface_on_the_top_page() {
        let mut d = healthy();
        d.mem_available_kb = 1_200_000; // 7.5%: MEM007 warns
        d.swap_free_kb = 3_000_000; // MEM002 warns too
        let findings = analyze(&d, &ctx());
        assert!(find(&findings, "MEM007").instance.is_none());
        assert!(find(&findings, "MEM002").instance.is_none());
        assert_eq!(
            find(&findings, "MEM008").instance.as_deref(),
            Some("Page cache")
        );
    }

    #[test]
    fn top_level_findings_come_first_worst_first() {
        let mut d = healthy();
        d.mem_available_kb = 400_000; // 2.5%: MEM007 error, MEM002 error
        d.swap_free_kb = 3_000_000;
        let findings = analyze(&d, &ctx());
        let top: Vec<&Finding> = findings
            .iter()
            .take_while(|f| f.instance.is_none())
            .collect();
        assert!(top.len() >= 3);
        assert_eq!(
            top.last().unwrap().id,
            "MEM004",
            "the Info overview closes the top page"
        );
        for pair in top.windows(2) {
            assert!(pair[0].severity >= pair[1].severity, "{:?}", ids(&findings));
        }
        // everything after the top page is grouped, never top-level again
        assert!(findings[top.len()..].iter().all(|f| f.instance.is_some()));
    }

    #[test]
    fn topic_findings_are_grouped_in_menu_order() {
        let findings = analyze(&healthy(), &ctx());
        let topics: Vec<&str> = findings
            .iter()
            .filter_map(|f| f.instance.as_deref())
            .collect();
        let mut ranks: Vec<usize> = topics.iter().map(|t| topic_rank(t)).collect();
        let sorted = {
            let mut s = ranks.clone();
            s.sort();
            s
        };
        assert_eq!(ranks, sorted, "{topics:?}");
        ranks.dedup();
        assert_eq!(
            ranks.len(),
            5,
            "healthy machine shows five topics: {topics:?}"
        );
    }

    // ---- behaviour carried over from the original module -----------

    #[test]
    fn overview_reports_used_as_total_minus_available() {
        let findings = analyze(&minimal(), &ctx());
        // 16_384_000 - 8_000_000 = 8_384_000
        assert_eq!(
            evidence(find(&findings, "MEM004"), "used_kb"),
            Some("8384000")
        );
    }

    #[test]
    fn no_swap_pressure_finding_when_swap_unused() {
        assert!(!ids(&analyze(&minimal(), &ctx())).contains(&"MEM002"));
    }

    #[test]
    fn swap_activity_tiers() {
        let mut data = minimal();
        data.swap_free_kb = 2_000_000; // about half of swap in use
        assert_eq!(
            find(&analyze(&data, &ctx()), "MEM002").severity,
            Severity::Info
        );
        data.mem_available_kb = 1_000_000; // ~6.1%
        assert_eq!(
            find(&analyze(&data, &ctx()), "MEM002").severity,
            Severity::Warning
        );
        data.mem_available_kb = 300_000; // ~1.8%
        assert_eq!(
            find(&analyze(&data, &ctx()), "MEM002").severity,
            Severity::Error
        );
    }

    #[test]
    fn nearly_full_swap_is_a_warning_even_with_plenty_of_ram() {
        let mut data = minimal();
        data.swap_free_kb = 100_000; // 97.6% of swap used, 8 GB of RAM available
        assert_eq!(
            find(&analyze(&data, &ctx()), "MEM002").severity,
            Severity::Warning
        );
    }

    #[test]
    fn low_swappiness_note_appears_when_swapping_anyway() {
        let mut data = minimal();
        data.swap_free_kb = 100_000;
        data.swappiness = 1;
        assert!(find(&analyze(&data, &ctx()), "MEM002")
            .explanation
            .contains("stronger signal"));
        data.swappiness = 60;
        assert!(!find(&analyze(&data, &ctx()), "MEM002")
            .explanation
            .contains("stronger signal"));
    }

    #[test]
    fn critical_finding_when_memory_low_and_swap_exhausted() {
        let mut data = minimal();
        data.mem_available_kb = 200_000;
        data.swap_free_kb = 0;
        let findings = analyze(&data, &ctx());
        assert_eq!(find(&findings, "MEM003").severity, Severity::Critical);
        data.swap_free_kb = 1000; // swap still has room
        assert!(!ids(&analyze(&data, &ctx())).contains(&"MEM003"));
    }

    #[test]
    fn critical_machine_leads_with_the_critical_finding() {
        let mut data = healthy();
        data.mem_available_kb = 200_000;
        data.swap_total_kb = 0;
        data.swap_free_kb = 0;
        let findings = analyze(&data, &ctx());
        assert_eq!(findings[0].id, "MEM003");
        assert!(ids(&findings).contains(&"MEM004"));
    }

    #[test]
    fn dirty_pages_tiers_on_minimal_data() {
        // 16_384_000 kB: background 1_638_400, throttling from 2_457_600,
        // hard limit 3_276_800.
        let sev = |dirty: u64| {
            let mut data = minimal();
            data.dirty_kb = dirty;
            find(&analyze(&data, &ctx()), "MEM005").severity
        };
        assert_eq!(sev(16_000), Severity::Info);
        assert_eq!(
            sev(1_700_000),
            Severity::Info,
            "background flushing is normal"
        );
        assert_eq!(sev(2_500_000), Severity::Warning);
        assert_eq!(sev(3_400_000), Severity::Error);
    }

    #[test]
    fn dirty_pages_handles_bytes_based_tuning_gracefully() {
        let mut data = minimal();
        data.dirty_ratio = 0;
        data.dirty_kb = 5_000_000;
        let f = analyze(&data, &ctx())
            .into_iter()
            .find(|f| f.id == "MEM005")
            .unwrap();
        assert_eq!(f.severity, Severity::Info);
        assert!(f.explanation.contains("dirty_bytes"));
    }

    #[test]
    fn shared_memory_tiers() {
        let sev = |shmem: u64| {
            let mut data = minimal();
            data.shmem_kb = shmem;
            find(&analyze(&data, &ctx()), "MEM006").severity
        };
        assert_eq!(sev(200_000), Severity::Info);
        assert_eq!(sev(2_000_000), Severity::Warning);
        assert_eq!(sev(5_000_000), Severity::Error);
    }

    // ---- invariants over many machines -----------------------------

    /// A set of machines, each in a different kind of trouble.
    fn scenarios() -> Vec<(&'static str, MemoryRawData)> {
        let mut out = vec![("healthy", healthy()), ("minimal", minimal())];

        let mut tight = healthy();
        tight.mem_available_kb = 1_000_000;
        tight.swap_free_kb = 300_000;
        tight.processes = vec![proc(10, "java", 8_000_000), proc(11, "java", 1_000_000)];
        tight.pressure = Some(MemoryPressure {
            some: PsiLine {
                avg10: 35.0,
                avg60: 28.0,
                avg300: 12.0,
                total_us: 1,
            },
            full: Some(PsiLine {
                avg10: 9.0,
                avg60: 6.0,
                avg300: 2.0,
                total_us: 1,
            }),
        });
        tight.vmstat = Some(VmstatCounters {
            oom_kill: 2,
            pswpout: 4_000_000,
            ..Default::default()
        });
        out.push(("tight", tight));

        let mut no_swap = healthy();
        no_swap.swap_total_kb = 0;
        no_swap.swap_free_kb = 0;
        no_swap.mem_available_kb = 300_000;
        out.push(("critical, no swap", no_swap));

        let mut shm = healthy();
        shm.shmem_kb = 5_000_000;
        shm.tmpfs_mounts = vec![TmpfsMount {
            mount_point: "/dev/shm".into(),
            size_kb: 8_000_000,
            used_kb: 7_800_000,
        }];
        shm.sysv_shm = Some(vec![SysvSegment {
            shmid: 9,
            size_kb: 2_000_000,
            nattch: 0,
            rss_kb: 2_000_000,
            swap_kb: 0,
            uid: 0,
        }]);
        out.push(("shared memory leak", shm));

        let mut zram = healthy();
        zram.swap_devices = vec![
            SwapDevice {
                path: "/dev/zram0".into(),
                kind: SwapKind::Zram,
                size_kb: 8_000_000,
                used_kb: 6_000_000,
                priority: 10,
                zram: Some(ZramStats {
                    original_kb: 6_000_000,
                    compressed_kb: 4_800_000,
                    memory_used_kb: 4_800_000,
                    algorithm: Some("lzo-rle".into()),
                }),
                rotational: None,
            },
            SwapDevice {
                path: "/dev/sda2".into(),
                kind: SwapKind::Partition,
                size_kb: 4_000_000,
                used_kb: 0,
                priority: 20,
                zram: None,
                rotational: Some(true),
            },
        ];
        zram.swappiness = 150;
        zram.vm = VmTunables {
            page_cluster: Some(3),
            zswap_enabled: Some(true),
            ..Default::default()
        };
        out.push(("badly configured swap", zram));

        let mut kernel = healthy();
        kernel.detail.slab_kb = 4_000_000;
        kernel.detail.sunreclaim_kb = 3_800_000;
        kernel.detail.page_tables_kb = 1_500_000;
        kernel.vm = VmTunables {
            min_free_kbytes: Some(2_000_000),
            overcommit_memory: Some(2),
            thp_enabled: Some("always".into()),
            ..Default::default()
        };
        kernel.detail.commit_limit_kb = 10_000_000;
        kernel.detail.committed_as_kb = 10_500_000;
        kernel.detail.hugepages_total = 5000;
        kernel.detail.hugepages_free = 5000;
        kernel.detail.hugepage_size_kb = 2048;
        kernel.processes = vec![proc(1, "mongod", 3_000_000)];
        out.push(("kernel and tuning trouble", kernel));

        let mut writeback = healthy();
        writeback.dirty_kb = 3_400_000;
        writeback.detail.active_file_kb = 500_000;
        writeback.detail.inactive_file_kb = 400_000;
        writeback.mem_available_kb = 1_200_000;
        out.push(("writeback storm", writeback));

        out
    }

    #[test]
    fn confidence_never_reported_below_60() {
        for (name, data) in scenarios() {
            for f in analyze(&data, &ctx()) {
                assert!(
                    f.confidence.percent >= 60,
                    "{name}: {} at {}",
                    f.id,
                    f.confidence.percent
                );
            }
        }
    }

    #[test]
    fn every_problem_comes_with_a_numbered_solution() {
        let mut checked = 0;
        for (name, data) in scenarios() {
            for f in analyze(&data, &ctx()) {
                if f.severity >= Severity::Warning {
                    let rec = f.recommendation.as_deref().unwrap_or_else(|| {
                        panic!("{name}: {} ({}) has no recommendation", f.id, f.severity)
                    });
                    assert!(
                        rec.starts_with("1. "),
                        "{name}: {} recommendation is not a step list:\n{rec}",
                        f.id
                    );
                    checked += 1;
                }
            }
        }
        assert!(
            checked >= 12,
            "scenarios should exercise many problem findings, got {checked}"
        );
    }

    #[test]
    fn recommendations_have_no_formatting_leftovers() {
        // Commands are suggestions, never executed; make sure none of them
        // (or any explanation) still holds a `{}` that was meant to be
        // filled in, and that no command line is empty.
        for (name, data) in scenarios() {
            for f in analyze(&data, &ctx()) {
                if let Some(rec) = &f.recommendation {
                    for line in rec.lines().filter(|l| l.starts_with("    ")) {
                        assert!(
                            !line.trim().is_empty(),
                            "{name}: {} has an empty command line",
                            f.id
                        );
                    }
                    assert!(
                        !rec.contains('{') || rec.contains("-F") || rec.contains("awk"),
                        "{name}: {}:\n{rec}",
                        f.id
                    );
                }
                assert!(!f.explanation.contains("{}"), "{name}: {}", f.id);
            }
        }
    }

    #[test]
    fn explanations_use_the_tools_binary_units_not_mib_or_gib() {
        for (name, data) in scenarios() {
            for f in analyze(&data, &ctx()) {
                assert!(
                    !f.explanation.contains("MiB") && !f.explanation.contains("GiB"),
                    "{name}: {}",
                    f.id
                );
            }
        }
    }

    #[test]
    fn scenarios_trigger_the_findings_they_were_built_for() {
        let by_name = |wanted: &str| {
            scenarios()
                .into_iter()
                .find(|(n, _)| *n == wanted)
                .unwrap()
                .1
        };

        let tight = analyze(&by_name("tight"), &ctx());
        assert_eq!(find(&tight, "MEM009").severity, Severity::Error);
        assert!(find(&tight, "MEM007").severity >= Severity::Warning);

        let shm = analyze(&by_name("shared memory leak"), &ctx());
        assert_eq!(find(&shm, "MEM006").severity, Severity::Error);
        assert!(find(&shm, "MEM006")
            .recommendation
            .as_deref()
            .unwrap()
            .contains("ipcrm"));

        let swap = analyze(&by_name("badly configured swap"), &ctx());
        assert_eq!(
            find(&swap, "MEM010").severity,
            Severity::Warning,
            "disk outranks zram"
        );

        let kernel = analyze(&by_name("kernel and tuning trouble"), &ctx());
        for id in ["MEM011", "MEM012", "MEM013"] {
            assert!(find(&kernel, id).severity >= Severity::Warning, "{id}");
        }
    }

    #[test]
    fn findings_serialise_to_json() {
        for (_, data) in scenarios() {
            let findings = analyze(&data, &ctx());
            let json = serde_json::to_string(&findings).expect("findings serialise");
            assert!(json.contains("MEM004"));
        }
    }
}
