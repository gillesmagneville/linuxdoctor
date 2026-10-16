// SPDX-License-Identifier: GPL-3.0-only

use linuxdoctor::core::context::Context;
use linuxdoctor::core::engine::{ModuleRunResult, Report};
use linuxdoctor::models::{Finding, Severity};
use linuxdoctor::modules::memory::analyze::analyze;
use linuxdoctor::modules::memory::collect::{
    parse_bracketed_choice, parse_df_tmpfs, parse_meminfo, parse_proc_status, parse_proc_swaps,
    parse_psi, parse_swappiness, parse_sysv_shm, parse_vmstat, parse_zfs_arcstats,
    parse_zram_mm_stat, MemoryRawData, ProcessMemory, VmTunables,
};

fn test_context() -> Context {
    Context {
        hostname: "test-host".into(),
        kernel_version: "6.8.0-test".into(),
        distro: Some("Test Linux".into()),
        architecture: "x86_64".into(),
        cpu_count: 4,
        mem_total_kb: 16_384_000,
        boot_time_unix: 0,
    }
}

fn build_from_fixture(
    meminfo: &str,
    swappiness: &str,
    dirty_ratio: u8,
    dirty_bg_ratio: u8,
) -> MemoryRawData {
    let fields = parse_meminfo(meminfo).expect("meminfo should parse");
    MemoryRawData {
        mem_total_kb: fields["MemTotal"],
        mem_free_kb: *fields.get("MemFree").unwrap_or(&0),
        mem_available_kb: fields["MemAvailable"],
        cached_kb: fields.get("Buffers").unwrap_or(&0) + fields.get("Cached").unwrap_or(&0),
        shmem_kb: *fields.get("Shmem").unwrap_or(&0),
        dirty_kb: *fields.get("Dirty").unwrap_or(&0),
        swap_total_kb: fields["SwapTotal"],
        swap_free_kb: fields["SwapFree"],
        swappiness: parse_swappiness(swappiness).expect("swappiness should parse"),
        dirty_ratio,
        dirty_background_ratio: dirty_bg_ratio,
        ..Default::default()
    }
}

#[test]
fn healthy_system_fixture_produces_only_info_findings() {
    let meminfo = "\
MemTotal:       16384000 kB
MemFree:         9000000 kB
MemAvailable:   12000000 kB
Buffers:          300000 kB
Cached:          3500000 kB
Shmem:            180000 kB
Dirty:               800 kB
SwapTotal:       4194300 kB
SwapFree:        4194300 kB
";
    let data = build_from_fixture(meminfo, "60\n", 20, 10);

    let findings = analyze(&data, &test_context());

    assert!(findings.iter().all(|f| f.severity == Severity::Info));
    let ids: Vec<&str> = findings.iter().map(|f| f.id.as_str()).collect();
    assert!(ids.contains(&"MEM001"));
    assert!(ids.contains(&"MEM004"));
    assert!(ids.contains(&"MEM005"));
    assert!(ids.contains(&"MEM006"));
    assert!(!ids.contains(&"MEM002")); // swap unused
    assert!(!ids.contains(&"MEM003"));
}

#[test]
fn under_pressure_fixture_produces_warning_and_no_critical() {
    let meminfo = "\
MemTotal:       16384000 kB
MemFree:          800000 kB
MemAvailable:    1300000 kB
Buffers:          200000 kB
Cached:          1800000 kB
Shmem:            150000 kB
Dirty:               900 kB
SwapTotal:       4194300 kB
SwapFree:         150000 kB
";
    let data = build_from_fixture(meminfo, "10\n", 20, 10);

    let findings = analyze(&data, &test_context());
    let ids: Vec<&str> = findings.iter().map(|f| f.id.as_str()).collect();

    assert!(ids.contains(&"MEM001"));
    assert!(ids.contains(&"MEM002"));
    assert!(
        !ids.contains(&"MEM003"),
        "swap still has headroom, shouldn't hit CRITICAL"
    );

    let mem002 = findings.iter().find(|f| f.id == "MEM002").unwrap();
    assert_eq!(mem002.severity, Severity::Warning);
    // swappiness=10 is <=10, so the cross-reference note should appear.
    assert!(mem002.explanation.contains("stronger signal"));
}

#[test]
fn heavy_writeback_and_shared_memory_fixture_flags_both() {
    let meminfo = "\
MemTotal:       16384000 kB
MemFree:         6000000 kB
MemAvailable:    9000000 kB
Buffers:          200000 kB
Cached:          2000000 kB
Shmem:           4500000 kB
Dirty:           3500000 kB
SwapTotal:              0 kB
SwapFree:               0 kB
";
    let data = build_from_fixture(meminfo, "60\n", 20, 10);

    let findings = analyze(&data, &test_context());

    let mem005 = findings.iter().find(|f| f.id == "MEM005").unwrap();
    assert_eq!(mem005.severity, Severity::Error); // 3_500_000/16_384_000 ~21.4% >= 20%
    assert!(mem005.recommendation.is_some());

    let mem006 = findings.iter().find(|f| f.id == "MEM006").unwrap();
    assert_eq!(mem006.severity, Severity::Error); // 4_500_000/16_384_000 ~27.5% >= 25%
    assert!(mem006.recommendation.is_some());
}

// ---------------------------------------------------------------------------
// Realistic machines, built from the same text the kernel produces
// ---------------------------------------------------------------------------

fn find<'a>(findings: &'a [Finding], id: &str) -> &'a Finding {
    findings.iter().find(|f| f.id == id).unwrap_or_else(|| {
        panic!(
            "{id} missing from {:?}",
            findings.iter().map(|f| &f.id).collect::<Vec<_>>()
        )
    })
}

fn evidence<'a>(f: &'a Finding, key: &str) -> Option<&'a str> {
    f.evidence
        .iter()
        .find(|(k, _)| k == key)
        .map(|(_, v)| v.as_str())
}

fn process(pid: u32, name: &str, anon_kb: u64, swap_kb: u64) -> ProcessMemory {
    let text = format!(
        "Name:\t{name}\nRssAnon:\t{anon_kb} kB\nRssFile:\t150000 kB\nRssShmem:\t50000 kB\nVmSwap:\t{swap_kb} kB\n"
    );
    parse_proc_status(pid, &text).expect("status parses")
}

/// A 64 GB database server doing fine: lots of cache, SysV segments in use,
/// no pressure, zram absent, conservative settings.
fn healthy_server() -> MemoryRawData {
    let meminfo = "\
MemTotal:       65536000 kB
MemFree:         6000000 kB
MemAvailable:   40000000 kB
Buffers:          500000 kB
Cached:         33000000 kB
SwapCached:             0 kB
Active:         22000000 kB
Inactive:       28000000 kB
Active(anon):    4000000 kB
Inactive(anon):   500000 kB
Active(file):   18000000 kB
Inactive(file): 27500000 kB
Unevictable:           0 kB
Mlocked:               0 kB
SwapTotal:       8388604 kB
SwapFree:        8388604 kB
Dirty:             30000 kB
Writeback:             0 kB
AnonPages:      14000000 kB
Mapped:           900000 kB
Shmem:           8200000 kB
KReclaimable:    1500000 kB
Slab:            2000000 kB
SReclaimable:    1500000 kB
SUnreclaim:       500000 kB
KernelStack:       30000 kB
PageTables:       150000 kB
Percpu:            20000 kB
CommitLimit:    41000000 kB
Committed_AS:   30000000 kB
";
    MemoryRawData {
        swappiness: 10,
        dirty_ratio: 10,
        dirty_background_ratio: 5,
        vm: VmTunables {
            overcommit_memory: Some(0),
            thp_enabled: Some("madvise".into()),
            min_free_kbytes: Some(131_072),
            vfs_cache_pressure: Some(100),
            ..Default::default()
        },
        swap_devices: parse_proc_swaps(
            "Filename\t\t\t\tType\t\tSize\t\tUsed\t\tPriority\n/swapfile\tfile\t8388604\t0\t-2\n",
        ),
        pressure: parse_psi(
            "some avg10=0.00 avg60=0.02 avg300=0.01 total=1234\nfull avg10=0.00 avg60=0.00 avg300=0.00 total=12\n",
        ),
        vmstat: parse_vmstat("pswpin 0\npswpout 0\noom_kill 0\npgscan_kswapd 100\npgscan_direct 1\nallocstall_normal 0\n"),
        processes: vec![process(900, "postgres", 3_500_000, 0), process(901, "postgres", 400_000, 0)],
        tmpfs_mounts: parse_df_tmpfs(
            "Filesystem     1024-blocks    Used Available Capacity Mounted on\n\
             tmpfs             13107200    2400   13104800       1% /run\n\
             tmpfs             32768000 8190000   24578000      25% /dev/shm\n",
        ),
        sysv_shm: Some(parse_sysv_shm(
            "       key      shmid perms                  size  cpid  lpid nattch   uid   gid  cuid  cgid      atime      dtime      ctime                   rss                  swap\n\
             0       32768   600            8388608000   900   901      4   999   999   999   999 1700000000          0 1700000000            8388608000                     0\n",
        )),
        page_size_kb: 4,
        ..MemoryRawData::from_meminfo(meminfo).expect("meminfo parses")
    }
}

#[test]
fn healthy_server_with_full_data_is_all_info_and_organised_by_topic() {
    let findings = analyze(&healthy_server(), &test_context());

    assert!(
        findings.iter().all(|f| f.severity == Severity::Info),
        "{:?}",
        findings
            .iter()
            .filter(|f| f.severity > Severity::Info)
            .map(|f| (&f.id, f.severity))
            .collect::<Vec<_>>()
    );
    assert_eq!(
        findings[0].id, "MEM004",
        "a healthy machine's top page is the overview"
    );

    let mut topics: Vec<&str> = findings
        .iter()
        .filter_map(|f| f.instance.as_deref())
        .collect();
    topics.dedup();
    assert_eq!(
        topics,
        [
            "Used memory",
            "Page cache",
            "Shared memory",
            "Swap",
            "Pressure",
            "Kernel tuning"
        ]
    );

    // The breakdown and the top consumers are there.
    let used = find(&findings, "MEM007");
    assert!(used.explanation.contains("Programs (private memory)"));
    assert!(
        used.explanation.contains("postgres (2 processes)"),
        "{}",
        used.explanation
    );
    assert_eq!(evidence(used, "anon_kb"), Some("14000000"));

    // free(1)'s buff/cache is split into what is really cache and what is shared.
    let overview = find(&findings, "MEM004");
    assert_eq!(evidence(overview, "buff_cache_kb"), Some("35000000"));
    assert_eq!(evidence(overview, "shared_kb"), Some("8200000"));
    // Buffers 0.5M + (Cached 33.0M - Shmem 8.2M) + SReclaimable 1.5M
    assert_eq!(evidence(overview, "reclaimable_cache_kb"), Some("26800000"));

    // Shared memory is traced to the SysV segment, which is attached.
    let shared = find(&findings, "MEM006");
    assert_eq!(evidence(shared, "sysv_segments"), Some("1"));
    assert!(evidence(shared, "sysv_orphan_segments").is_none());

    // 10% dirty ratio is measured against dirtyable memory (free + file cache).
    let dirty = find(&findings, "MEM005");
    assert_eq!(evidence(dirty, "dirtyable_kb"), Some("51500000"));
}

#[test]
fn memory_starved_workstation_gets_a_diagnosis_with_numbered_fixes() {
    let meminfo = "\
MemTotal:       16384000 kB
MemFree:          150000 kB
MemAvailable:     600000 kB
Buffers:           20000 kB
Cached:           900000 kB
SwapCached:       150000 kB
Active(anon):    9000000 kB
Inactive(anon):  4500000 kB
Active(file):     250000 kB
Inactive(file):   300000 kB
Unevictable:         100 kB
Mlocked:             100 kB
SwapTotal:       4194300 kB
SwapFree:         400000 kB
Dirty:              5000 kB
Writeback:             0 kB
AnonPages:      13400000 kB
Mapped:           300000 kB
Shmem:            350000 kB
Slab:             400000 kB
SReclaimable:     150000 kB
SUnreclaim:       250000 kB
KernelStack:       40000 kB
PageTables:       120000 kB
Percpu:            10000 kB
";
    let data = MemoryRawData {
        swappiness: 60,
        dirty_ratio: 20,
        dirty_background_ratio: 10,
        swap_devices: parse_proc_swaps(
            "Filename\t\t\t\tType\t\tSize\t\tUsed\t\tPriority\n/dev/sda2\tpartition\t4194300\t3794300\t-2\n",
        ),
        pressure: parse_psi(
            "some avg10=41.20 avg60=31.07 avg300=12.90 total=987654321\nfull avg10=18.00 avg60=11.50 avg300=3.10 total=123456789\n",
        ),
        vmstat: parse_vmstat("pswpin 9000000\npswpout 12000000\noom_kill 2\npgscan_kswapd 3000000\npgscan_direct 5000000\nallocstall_normal 4100\n"),
        processes: vec![
            process(2100, "chrome", 2_600_000, 300_000),
            process(2101, "chrome", 2_200_000, 250_000),
            process(2102, "chrome", 1_900_000, 200_000),
            process(3300, "java", 4_800_000, 900_000),
            process(1, "systemd", 12_000, 0),
        ],
        page_size_kb: 4,
        ..MemoryRawData::from_meminfo(meminfo).expect("meminfo parses")
    };

    let findings = analyze(&data, &test_context());

    // Problems sit on the top page, worst first, after the overview.
    let top: Vec<&Finding> = findings
        .iter()
        .take_while(|f| f.instance.is_none())
        .collect();
    assert_eq!(
        top.last().unwrap().id,
        "MEM004",
        "the overview closes the top page"
    );
    assert!(
        top[0].severity >= Severity::Error,
        "the worst problem leads"
    );
    assert!(
        top.len() >= 4,
        "{:?}",
        top.iter().map(|f| &f.id).collect::<Vec<_>>()
    );

    let used = find(&findings, "MEM007");
    assert_eq!(used.severity, Severity::Error);
    // Programs are counted as a whole: chrome's three processes (6.7 GB)
    // outweigh java's single 4.6 GB one.
    assert!(
        used.explanation.contains("chrome (3 processes)"),
        "{}",
        used.explanation
    );
    assert!(evidence(used, "top_consumer_1")
        .unwrap()
        .starts_with("chrome (3 processes)"));
    assert!(evidence(used, "top_consumer_1")
        .unwrap()
        .contains("PID 2100"));
    assert!(evidence(used, "top_consumer_2")
        .unwrap()
        .starts_with("java"));
    assert!(used
        .recommendation
        .as_deref()
        .unwrap()
        .contains("systemctl status 2100"));

    let swap = find(&findings, "MEM002");
    assert_eq!(
        swap.severity,
        Severity::Warning,
        "3.7% available, swap 90% full"
    );
    assert!(swap.explanation.contains("nearly full"));
    assert_eq!(
        evidence(swap, "swapped_program_1"),
        Some("java (PID 3300): 879 MB")
    );

    let pressure = find(&findings, "MEM009");
    assert_eq!(pressure.severity, Severity::Error);
    assert!(pressure.explanation.contains("killed 2 processes"));

    let cache = find(&findings, "MEM008");
    assert_eq!(
        cache.severity,
        Severity::Warning,
        "cache squeezed out by programs"
    );

    for f in findings.iter().filter(|f| f.severity >= Severity::Warning) {
        let rec = f
            .recommendation
            .as_deref()
            .unwrap_or_else(|| panic!("{} has no fix", f.id));
        assert!(rec.starts_with("1. "), "{}: {rec}", f.id);
    }
}

#[test]
fn zram_desktop_with_mistuned_priority_and_algorithm_is_explained() {
    let swaps = "Filename\t\t\t\tType\t\tSize\t\tUsed\t\tPriority\n\
                 /dev/zram0\tpartition\t8388604\t2000000\t10\n\
                 /dev/nvme0n1p3\tpartition\t8388604\t0\t50\n";
    let mut devices = parse_proc_swaps(swaps);
    // 3.0 GB of data held in 1.0 GB, using lzo-rle.
    let stats =
        parse_zram_mm_stat("3221225472 1073741824 1100000000 0 1100000000 0 0 0 0").unwrap();
    devices[0].zram = Some(linuxdoctor::modules::memory::collect::ZramStats {
        algorithm: parse_bracketed_choice("lzo [lzo-rle] lz4 zstd"),
        ..stats
    });
    devices[1].rotational = Some(false);

    let meminfo = "\
MemTotal:       16384000 kB
MemFree:         3000000 kB
MemAvailable:    8000000 kB
Buffers:          200000 kB
Cached:          4000000 kB
SwapTotal:      16777208 kB
SwapFree:       14777208 kB
Shmem:            400000 kB
";
    let data = MemoryRawData {
        swappiness: 60,
        dirty_ratio: 20,
        dirty_background_ratio: 10,
        swap_devices: devices,
        vm: VmTunables {
            page_cluster: Some(3),
            ..Default::default()
        },
        ..MemoryRawData::from_meminfo(meminfo).unwrap()
    };

    let findings = analyze(&data, &test_context());

    let config = find(&findings, "MEM010");
    assert_eq!(
        config.severity,
        Severity::Warning,
        "disk swap outranks zram"
    );
    assert!(
        config
            .explanation
            .contains("3.0:1 compression with lzo-rle"),
        "{}",
        config.explanation
    );
    let rec = config.recommendation.as_deref().unwrap();
    assert!(rec.contains("sudo swapon --priority 100 /dev/zram0"));
    assert!(rec.contains("compression-algorithm = zstd"));
    assert!(rec.contains("vm.page-cluster=0"));

    let swappiness = find(&findings, "MEM001");
    assert_eq!(evidence(swappiness, "swap_type"), Some("zram + disk"));
    assert!(swappiness
        .recommendation
        .as_deref()
        .unwrap()
        .contains("vm.swappiness=100"));
}

#[test]
fn leaked_sysv_segments_and_a_full_dev_shm_are_found_and_fixable() {
    let meminfo = "\
MemTotal:       16384000 kB
MemFree:         2000000 kB
MemAvailable:    6000000 kB
Buffers:          100000 kB
Cached:          7000000 kB
SwapTotal:             0 kB
SwapFree:              0 kB
Shmem:           5200000 kB
";
    let data = MemoryRawData {
        swappiness: 60,
        dirty_ratio: 20,
        dirty_background_ratio: 10,
        tmpfs_mounts: parse_df_tmpfs(
            "Filesystem     1024-blocks    Used Available Capacity Mounted on\n\
             tmpfs              1638400    1100   1637300       1% /run\n\
             tmpfs              2097152 2060000     37152      99% /dev/shm\n",
        ),
        sysv_shm: Some(parse_sysv_shm(
            "       key      shmid perms                  size  cpid  lpid nattch   uid   gid  cuid  cgid      atime      dtime      ctime                   rss                  swap\n\
             0       65536   600            2147483648   500   500      0  1000  1000  1000  1000 1700000000 1700000100 1700000000            2147483648                     0\n\
             0       65537   600            1073741824   501   501      0  1000  1000  1000  1000 1700000000 1700000100 1700000000            1073741824                     0\n",
        )),
        ..MemoryRawData::from_meminfo(meminfo).unwrap()
    };

    let findings = analyze(&data, &test_context());
    let shared = find(&findings, "MEM006");

    assert_eq!(shared.severity, Severity::Error, "31% of RAM");
    assert_eq!(evidence(shared, "sysv_orphan_segments"), Some("2"));
    assert_eq!(evidence(shared, "tmpfs_nearly_full"), Some("/dev/shm"));
    let rec = shared.recommendation.as_deref().unwrap();
    assert!(rec.contains("sudo ipcrm -m 65536"));
    assert!(rec.contains("sudo ipcrm -m 65537"));
    assert!(rec.contains("sudo du -ah /dev/shm"));
    // No swap at all and 37% available: informational advice, not an alarm.
    assert_eq!(find(&findings, "MEM010").severity, Severity::Info);
}

#[test]
fn zfs_arc_is_reported_outside_the_page_cache() {
    let meminfo = "\
MemTotal:       32768000 kB
MemFree:          400000 kB
MemAvailable:    2500000 kB
Buffers:           10000 kB
Cached:          1500000 kB
SwapTotal:       2097148 kB
SwapFree:        2097148 kB
Shmem:            300000 kB
Slab:           17000000 kB
SReclaimable:     300000 kB
SUnreclaim:     16700000 kB
KernelStack:       30000 kB
PageTables:       100000 kB
";
    let arcstats = "\
13 1 0x01 123 33456 1000 2000
name                            type data
hits                            4    123456
size                            4    17179869184
c_max                           4    17179869184
";
    let data = MemoryRawData {
        swappiness: 60,
        dirty_ratio: 20,
        dirty_background_ratio: 10,
        zfs_arc: parse_zfs_arcstats(arcstats),
        ..MemoryRawData::from_meminfo(meminfo).unwrap()
    };

    let findings = analyze(&data, &test_context());
    let kernel = find(&findings, "MEM013");

    assert_eq!(evidence(kernel, "zfs_arc_kb"), Some("16777216"));
    assert!(kernel.explanation.contains("does not count it"));
    assert!(
        kernel.severity >= Severity::Warning,
        "ARC is half of RAM and only 7.6% is available"
    );
    assert!(kernel
        .recommendation
        .as_deref()
        .unwrap()
        .contains("zfs_arc_max"));
}

#[test]
fn numbered_steps_reach_the_terminal_report_readably() {
    let mut data = healthy_server();
    data.mem_available_kb = 2_000_000; // 3%
    data.swap_total_kb = 0;
    data.swap_free_kb = 0;
    data.swap_devices.clear();
    let findings = analyze(&data, &test_context());
    let report = Report {
        profile: None,
        context: test_context(),
        results: vec![ModuleRunResult {
            module_id: "memory",
            findings,
            error: None,
            skipped: false,
            notes: Vec::new(),
        }],
    };

    let out = linuxdoctor::output::terminal::render(&report);

    assert!(
        out.contains("MEM003 — Critically Low Available Memory"),
        "{out}"
    );
    assert!(out.contains("Recommendation:"), "{out}");
    assert!(out.contains("\n  1. "), "{out}");
    assert!(
        out.contains("      sudo fallocate -l"),
        "commands are indented under their step: {out}"
    );
}

#[test]
fn json_carries_the_new_evidence_and_the_topic() {
    let findings = analyze(&healthy_server(), &test_context());
    let json = serde_json::to_value(&findings).unwrap();
    let swap_cfg = json
        .as_array()
        .unwrap()
        .iter()
        .find(|f| f["id"] == "MEM010")
        .unwrap();
    assert_eq!(swap_cfg["instance"], "Swap");
    assert!(swap_cfg["evidence"].to_string().contains("swap_device_1"));
}
