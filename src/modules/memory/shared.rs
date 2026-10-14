// SPDX-License-Identifier: GPL-3.0-only

//! Shared memory (MEM006): tmpfs files, POSIX and SysV shared memory,
//! memfd and shared mappings. The kernel lists it inside "cached", but
//! unlike cache it cannot be dropped on demand — it stays in RAM until
//! something deletes it (or it is swapped out).

use crate::models::{Category, Confidence, Finding, Severity};

use super::collect::{percent, MemoryRawData, SysvSegment, TmpfsMount};
use super::format::{kb, pct, Steps};

const WARNING_PERCENT: f64 = 10.0;
const ERROR_PERCENT: f64 = 25.0;

/// Resident memory held by SysV segments nobody is attached to, from which
/// the situation is worth a warning on its own: 256 MB.
const ORPHAN_WARNING_KB: u64 = 256 * 1024;

/// A tmpfs this full makes programs fail with "No space left on device".
const TMPFS_FULL_PERCENT: f64 = 90.0;
/// Small tmpfs mounts (/run/lock, ...) fill up for harmless reasons.
const TMPFS_MIN_SIZE_KB: u64 = 32 * 1024;

/// Shared memory that is in neither a tmpfs file nor a SysV segment is
/// explained once it is at least this large and this share of the total.
const UNATTRIBUTED_MIN_KB: u64 = 512 * 1024;
const UNATTRIBUTED_SHARE: f64 = 25.0;

/// How many items each list shows.
const LIST_LEN: usize = 3;
const ORPHAN_COMMANDS: usize = 5;

fn largest_tmpfs(mounts: &[TmpfsMount], n: usize) -> Vec<&TmpfsMount> {
    let mut v: Vec<&TmpfsMount> = mounts.iter().filter(|m| m.used_kb > 0).collect();
    v.sort_by(|a, b| {
        b.used_kb
            .cmp(&a.used_kb)
            .then_with(|| a.mount_point.cmp(&b.mount_point))
    });
    v.truncate(n);
    v
}

fn full_tmpfs(mounts: &[TmpfsMount]) -> Vec<&TmpfsMount> {
    let mut v: Vec<&TmpfsMount> = mounts
        .iter()
        .filter(|m| {
            m.size_kb >= TMPFS_MIN_SIZE_KB && percent(m.used_kb, m.size_kb) >= TMPFS_FULL_PERCENT
        })
        .collect();
    v.sort_by(|a, b| a.mount_point.cmp(&b.mount_point));
    v
}

fn orphans(segments: &[SysvSegment]) -> Vec<&SysvSegment> {
    let mut v: Vec<&SysvSegment> = segments
        .iter()
        .filter(|s| s.nattch == 0 && s.size_kb > 0)
        .collect();
    v.sort_by(|a, b| b.rss_kb.cmp(&a.rss_kb).then_with(|| a.shmid.cmp(&b.shmid)));
    v
}

/// MEM006 — always reported. Shows how much memory is shared, where it
/// lives (tmpfs mounts, SysV segments, programs' shared mappings) and
/// flags what can be reclaimed by the administrator: oversized tmpfs
/// content and segments left behind by programs that have exited.
pub fn shared_memory(data: &MemoryRawData) -> Finding {
    let total = data.mem_total_kb;
    let shmem_pct = percent(data.shmem_kb, total);

    let tmpfs_used: u64 = data.tmpfs_mounts.iter().map(|m| m.used_kb).sum();
    let segments: &[SysvSegment] = data.sysv_shm.as_deref().unwrap_or(&[]);
    let sysv_resident: u64 = segments.iter().map(|s| s.rss_kb).sum();
    let orphan_list = orphans(segments);
    let orphan_resident: u64 = orphan_list.iter().map(|s| s.rss_kb).sum();
    let full = full_tmpfs(&data.tmpfs_mounts);
    // Segments that running programs are attached to are memory in
    // legitimate use (a database's buffer pool, typically). They explain
    // the shared memory but are not what the percentage thresholds are
    // meant to catch, so they are left out of the severity decision.
    let attached_resident: u64 = segments
        .iter()
        .filter(|s| s.nattch > 0)
        .map(|s| s.rss_kb)
        .sum();
    let judged_kb = data.shmem_kb.saturating_sub(attached_resident);
    let judged_pct = percent(judged_kb, total);
    let have_sources = !data.tmpfs_mounts.is_empty() || data.sysv_shm.is_some();
    let unattributed = data.shmem_kb.saturating_sub(tmpfs_used + sysv_resident);
    let explain_unattributed = have_sources
        && unattributed >= UNATTRIBUTED_MIN_KB
        && percent(unattributed, data.shmem_kb) >= UNATTRIBUTED_SHARE;

    // The finding takes the most severe of its independent reasons.
    let mut drivers: Vec<(Severity, Confidence)> = Vec::new();
    drivers.push(if judged_pct >= ERROR_PERCENT {
        (Severity::Error, Confidence::strong_indication(85))
    } else if judged_pct >= WARNING_PERCENT {
        (Severity::Warning, Confidence::strong_indication(76))
    } else {
        (Severity::Info, Confidence::direct_observation())
    });
    if orphan_resident >= ORPHAN_WARNING_KB {
        drivers.push((Severity::Warning, Confidence::strong_indication(82)));
    }
    if !full.is_empty() {
        drivers.push((Severity::Warning, Confidence::correlated(90)));
    }
    let (severity, confidence) = drivers
        .into_iter()
        .max_by_key(|(s, c)| (*s, c.percent))
        .expect("at least the percentage driver is present");

    let mut paragraphs: Vec<String> = Vec::new();
    paragraphs.push(match () {
        _ if judged_pct >= ERROR_PERCENT => format!(
            "Shared memory (tmpfs files, /dev/shm, SysV and POSIX shared memory, memfd, \
             shared mappings) takes {} of RAM ({}). Unlike page cache it is not dropped \
             on demand: it stays allocated until something deletes it (or it is swapped \
             out), so it competes directly with programs for RAM.",
            kb(data.shmem_kb),
            pct(shmem_pct),
        ),
        _ if judged_pct >= WARNING_PERCENT => format!(
            "Shared memory takes {} of RAM ({}). That is worth understanding, because \
             unlike page cache it is not given back when programs need memory.",
            kb(data.shmem_kb),
            pct(shmem_pct),
        ),
        _ => format!(
            "Shared memory takes {} of RAM ({}), a normal level. It is the part of the \
             'buff/cache' figure of free(1) that is not really cache: it stays in RAM \
             until deleted.",
            kb(data.shmem_kb),
            pct(shmem_pct),
        ),
    });

    let mut builder = Finding::builder(
        "MEM006",
        "Shared Memory Usage",
        Category::Memory,
        severity,
        confidence,
    )
    .evidence("shmem_kb", data.shmem_kb.to_string())
    .evidence("shmem_percent", format!("{shmem_pct:.1}"));

    let biggest_tmpfs = largest_tmpfs(&data.tmpfs_mounts, LIST_LEN);
    if !data.tmpfs_mounts.is_empty() {
        builder = builder.evidence("tmpfs_used_kb", tmpfs_used.to_string());
    }
    if !biggest_tmpfs.is_empty() {
        let mut list =
            String::from("Where it lives — tmpfs mounts (files that exist only in RAM):");
        for (i, m) in biggest_tmpfs.iter().enumerate() {
            let size = if m.size_kb > 0 {
                format!(
                    " of {} ({} full)",
                    kb(m.size_kb),
                    pct(percent(m.used_kb, m.size_kb))
                )
            } else {
                String::new()
            };
            list.push_str(&format!(
                "\n  {}. {} — {}{}",
                i + 1,
                m.mount_point,
                kb(m.used_kb),
                size
            ));
            builder = builder.evidence(
                format!("tmpfs_{}", i + 1),
                format!("{}: {} used", m.mount_point, kb(m.used_kb)),
            );
        }
        paragraphs.push(list);
    }

    if let Some(segs) = &data.sysv_shm {
        builder = builder
            .evidence("sysv_segments", segs.len().to_string())
            .evidence("sysv_resident_kb", sysv_resident.to_string());
        if !segs.is_empty() {
            let mut text = format!(
                "SysV shared memory: {} segment{} using {} of RAM.",
                segs.len(),
                if segs.len() == 1 { "" } else { "s" },
                kb(sysv_resident),
            );
            if attached_resident > 0 {
                text.push_str(&format!(
                    " {} of it belongs to segments that running programs are attached to — \
                     memory in legitimate use, such as a database's buffer pool.",
                    kb(attached_resident)
                ));
                builder =
                    builder.evidence("sysv_attached_resident_kb", attached_resident.to_string());
            }
            paragraphs.push(text);
        }
    }

    if !orphan_list.is_empty() {
        builder = builder
            .evidence("sysv_orphan_segments", orphan_list.len().to_string())
            .evidence("sysv_orphan_resident_kb", orphan_resident.to_string());
        let mut text = format!(
            "{} SysV segment{} ({} resident) {} no program attached. The program that \
             created {} has exited or crashed without removing {}, so the memory stays \
             allocated until the segment is deleted:",
            orphan_list.len(),
            if orphan_list.len() == 1 { "" } else { "s" },
            kb(orphan_resident),
            if orphan_list.len() == 1 {
                "has"
            } else {
                "have"
            },
            if orphan_list.len() == 1 { "it" } else { "them" },
            if orphan_list.len() == 1 { "it" } else { "them" },
        );
        for s in orphan_list.iter().take(LIST_LEN) {
            text.push_str(&format!(
                "\n  - id {} — {} ({} resident), owner uid {}",
                s.shmid,
                kb(s.size_kb),
                kb(s.rss_kb),
                s.uid
            ));
        }
        paragraphs.push(text);
    }

    if !full.is_empty() {
        let mut text = String::from(
            "These tmpfs mounts are nearly full, so programs writing to them will fail with \
             'No space left on device':",
        );
        for m in &full {
            text.push_str(&format!(
                "\n  - {} — {} of {} ({})",
                m.mount_point,
                kb(m.used_kb),
                kb(m.size_kb),
                pct(percent(m.used_kb, m.size_kb))
            ));
        }
        paragraphs.push(text);
        builder = builder.evidence(
            "tmpfs_nearly_full",
            full.iter()
                .map(|m| m.mount_point.as_str())
                .collect::<Vec<_>>()
                .join(", "),
        );
    }

    if explain_unattributed {
        paragraphs.push(format!(
            "{} of the shared memory is in neither a tmpfs file nor a SysV segment. That is \
             memory that programs share through anonymous mappings and memfd — typical of \
             browsers, Wayland compositors and graphics drivers, and of databases such as \
             PostgreSQL that keep their buffer cache in shared memory. It disappears when \
             those programs exit.",
            kb(unattributed)
        ));
        builder = builder.evidence("shared_in_mappings_kb", unattributed.to_string());
    }

    // Biggest sharers among running programs. Several programs mapping
    // the same memory each count it, so these are not added together.
    let mut sharers: Vec<_> = data
        .processes
        .iter()
        .filter(|p| p.rss_shmem_kb > 0)
        .collect();
    sharers.sort_by(|a, b| {
        b.rss_shmem_kb
            .cmp(&a.rss_shmem_kb)
            .then_with(|| a.pid.cmp(&b.pid))
    });
    sharers.truncate(LIST_LEN);
    if !sharers.is_empty() && data.shmem_kb > 0 {
        let mut text = String::from(
            "Largest shared mappings per program (programs that share the same memory each \
             count it, so do not add these up):",
        );
        for (i, p) in sharers.iter().enumerate() {
            text.push_str(&format!(
                "\n  {}. {} (PID {}) — {}",
                i + 1,
                p.name,
                p.pid,
                kb(p.rss_shmem_kb)
            ));
            builder = builder.evidence(
                format!("shared_user_{}", i + 1),
                format!("{} (PID {}): {}", p.name, p.pid, kb(p.rss_shmem_kb)),
            );
        }
        paragraphs.push(text);
    }

    builder = builder.explanation(paragraphs.join("\n\n"));

    if severity > Severity::Info {
        builder = builder.recommendation(
            steps(
                data,
                &biggest_tmpfs,
                &orphan_list,
                &full,
                explain_unattributed,
                &sharers,
            )
            .build(),
        );
    }
    builder.build()
}

fn steps(
    data: &MemoryRawData,
    biggest_tmpfs: &[&TmpfsMount],
    orphan_list: &[&SysvSegment],
    full: &[&TmpfsMount],
    unattributed: bool,
    sharers: &[&super::collect::ProcessMemory],
) -> Steps {
    let mut steps = Steps::new().step(
        "See where the shared memory is:",
        &[
            "df -h -t tmpfs",
            "sudo du -xsh /dev/shm/* /tmp/* 2>/dev/null | sort -h | tail",
            "ipcs -m",
        ],
    );

    if let Some(m) = biggest_tmpfs.first() {
        let looks_big = percent(m.used_kb, data.mem_total_kb) >= 2.0;
        if looks_big {
            steps = steps.step_owned(
                format!(
                    "{} holds {} in RAM. List its largest files and delete what is no longer \
                     needed (the memory is returned immediately):",
                    m.mount_point,
                    kb(m.used_kb)
                ),
                vec![format!(
                    "sudo du -ah {} 2>/dev/null | sort -h | tail -15",
                    m.mount_point
                )],
            );
        }
        if m.mount_point == "/tmp" && looks_big {
            steps = steps.step(
                "If /tmp is a tmpfs and large temporary files are normal here, either cap its \
                 size now, or make it disk-based so it stops using RAM (systemd-based \
                 distributions; applies at next boot):",
                &[
                    "sudo mount -o remount,size=2G /tmp",
                    "sudo systemctl mask tmp.mount",
                ],
            );
        }
    }

    if !full.is_empty() {
        let names: Vec<&str> = full.iter().map(|m| m.mount_point.as_str()).collect();
        steps = steps.step_owned(
            format!(
                "{} {} almost full. Delete what is no longer needed, or enlarge the limit \
                 (it only caps usage; the memory is taken as files are written):",
                names.join(", "),
                if names.len() == 1 { "is" } else { "are" }
            ),
            full.iter()
                .map(|m| {
                    format!(
                        "sudo mount -o remount,size={}M {}",
                        (m.size_kb * 2 / 1024).max(64),
                        m.mount_point
                    )
                })
                .collect(),
        );
    }

    if !orphan_list.is_empty() {
        let mut cmds: Vec<String> = orphan_list
            .iter()
            .take(ORPHAN_COMMANDS)
            .map(|s| {
                format!(
                    "sudo ipcrm -m {}     # {}, uid {}",
                    s.shmid,
                    kb(s.size_kb),
                    s.uid
                )
            })
            .collect();
        if orphan_list.len() > ORPHAN_COMMANDS {
            cmds.push(format!(
                "# ... and {} more: see 'ipcs -m'",
                orphan_list.len() - ORPHAN_COMMANDS
            ));
        }
        steps = steps.step_owned(
            "Remove the segments nobody uses. First make sure the application that owns them \
             (a database or an application server, often) is really stopped — some keep a \
             segment across restarts on purpose:",
            cmds,
        );
    }

    if unattributed {
        if let Some(p) = sharers.first() {
            steps = steps.step_owned(
                format!(
                    "Most of the shared memory is held by running programs ({} maps {}). If it \
                     keeps growing, restart that program; if it is a database buffer cache, \
                     size it in the database configuration (for example shared_buffers in \
                     PostgreSQL) so it fits the machine:",
                    p.name,
                    kb(p.rss_shmem_kb)
                ),
                vec![format!("systemctl status {}", p.pid)],
            );
        }
    }

    steps.step(
        "Shared memory cannot be dropped like cache; if it must stay, swap (or zram) is the \
         only way for the kernel to move its idle parts out of RAM. See the Swap page.",
        &[],
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::modules::memory::collect::ProcessMemory;
    use crate::modules::memory::test_support::{evidence, healthy};

    fn tmpfs(mount: &str, size_mb: u64, used_mb: u64) -> TmpfsMount {
        TmpfsMount {
            mount_point: mount.into(),
            size_kb: size_mb * 1024,
            used_kb: used_mb * 1024,
        }
    }

    fn segment(shmid: u64, size_mb: u64, nattch: u64, rss_mb: u64) -> SysvSegment {
        SysvSegment {
            shmid,
            size_kb: size_mb * 1024,
            nattch,
            rss_kb: rss_mb * 1024,
            swap_kb: 0,
            uid: 1000,
        }
    }

    #[test]
    fn normal_level_is_info_and_explains_what_shared_memory_is() {
        let f = shared_memory(&healthy());
        assert_eq!(f.id, "MEM006");
        assert_eq!(f.severity, Severity::Info);
        assert!(f.recommendation.is_none());
        assert!(f.explanation.contains("not really cache"));
    }

    #[test]
    fn percentage_tiers_match_the_historic_thresholds() {
        let mut d = healthy();
        d.shmem_kb = 2_000_000; // 12.5%
        assert_eq!(shared_memory(&d).severity, Severity::Warning);
        d.shmem_kb = 5_000_000; // 31%
        let f = shared_memory(&d);
        assert_eq!(f.severity, Severity::Error);
        assert!(f.recommendation.unwrap().contains("df -h -t tmpfs"));
    }

    #[test]
    fn largest_tmpfs_mounts_are_listed_biggest_first() {
        let mut d = healthy();
        d.shmem_kb = 3_000_000;
        d.tmpfs_mounts = vec![
            tmpfs("/run", 1600, 40),
            tmpfs("/dev/shm", 8000, 2200),
            tmpfs("/tmp", 8000, 600),
            tmpfs("/run/user/1000", 1600, 0),
        ];
        let f = shared_memory(&d);
        let first = evidence(&f, "tmpfs_1").unwrap();
        assert!(first.starts_with("/dev/shm"), "{first}");
        assert!(evidence(&f, "tmpfs_2").unwrap().starts_with("/tmp"));
        assert!(evidence(&f, "tmpfs_4").is_none(), "only three are listed");
        assert_eq!(
            evidence(&f, "tmpfs_used_kb"),
            Some(&*((40 + 2200 + 600) * 1024u64).to_string())
        );
    }

    #[test]
    fn big_tmpfs_gets_a_cleanup_step_with_its_own_mount_point() {
        let mut d = healthy();
        d.shmem_kb = 3_000_000;
        d.tmpfs_mounts = vec![tmpfs("/dev/shm", 8000, 2900)];
        let rec = shared_memory(&d).recommendation.unwrap();
        assert!(rec.contains("sudo du -ah /dev/shm"), "{rec}");
        assert!(!rec.contains("systemctl mask tmp.mount"));
    }

    #[test]
    fn tmp_on_tmpfs_gets_the_cap_or_disk_based_advice() {
        let mut d = healthy();
        d.shmem_kb = 3_000_000;
        d.tmpfs_mounts = vec![tmpfs("/tmp", 8000, 2900)];
        let rec = shared_memory(&d).recommendation.unwrap();
        assert!(rec.contains("mount -o remount,size=2G /tmp"));
        assert!(rec.contains("systemctl mask tmp.mount"));
    }

    #[test]
    fn orphaned_sysv_segments_are_listed_with_ipcrm_commands() {
        let mut d = healthy();
        d.sysv_shm = Some(vec![
            segment(32769, 512, 0, 512),
            segment(65538, 64, 3, 64),
            segment(98307, 1024, 0, 900),
        ]);
        let f = shared_memory(&d);
        assert_eq!(
            f.severity,
            Severity::Warning,
            "1.4 GB orphaned must warn even though total shmem is small"
        );
        assert_eq!(evidence(&f, "sysv_orphan_segments"), Some("2"));
        assert_eq!(
            evidence(&f, "sysv_orphan_resident_kb"),
            Some(&*((512 + 900) * 1024u64).to_string())
        );
        assert!(f.explanation.contains("id 98307"));
        let rec = f.recommendation.unwrap();
        assert!(rec.contains("sudo ipcrm -m 98307"));
        assert!(rec.contains("sudo ipcrm -m 32769"));
        assert!(
            !rec.contains("ipcrm -m 65538"),
            "attached segments must not be suggested"
        );
        assert!(rec.contains("really stopped"));
    }

    #[test]
    fn small_orphans_are_reported_but_do_not_raise_severity() {
        let mut d = healthy();
        d.sysv_shm = Some(vec![segment(1, 4, 0, 4)]);
        let f = shared_memory(&d);
        assert_eq!(f.severity, Severity::Info);
        assert!(f.explanation.contains("no program attached"));
    }

    #[test]
    fn attached_segments_are_not_orphans() {
        let mut d = healthy();
        d.sysv_shm = Some(vec![segment(1, 2048, 2, 2048)]);
        let f = shared_memory(&d);
        assert!(evidence(&f, "sysv_orphan_segments").is_none());
        assert_eq!(evidence(&f, "sysv_segments"), Some("1"));
    }

    #[test]
    fn a_databases_attached_segment_is_not_flagged_by_percentage() {
        let mut d = healthy();
        d.shmem_kb = 8_200_000; // 51% of the 16 GB machine, all in one attached segment
        d.sysv_shm = Some(vec![segment(7, 8000, 4, 8000)]);
        let f = shared_memory(&d);
        assert_eq!(f.severity, Severity::Info, "{}", f.explanation);
        assert!(f.explanation.contains("memory in legitimate use"));
        assert_eq!(evidence(&f, "sysv_attached_resident_kb"), Some("8192000"));
    }

    #[test]
    fn what_attached_segments_do_not_explain_is_still_judged() {
        let mut d = healthy();
        d.shmem_kb = 9_000_000; // 8000 MB attached, but ~0.8 GB of something else... plus
        d.tmpfs_mounts = vec![tmpfs("/dev/shm", 8000, 4000)];
        d.sysv_shm = Some(vec![segment(7, 4000, 4, 4000)]); // 4.1 GB attached; 4.9 GB remains = 30%
        assert_eq!(shared_memory(&d).severity, Severity::Error);
    }

    #[test]
    fn orphans_never_count_as_legitimate() {
        let mut d = healthy();
        d.shmem_kb = 5_000_000;
        d.sysv_shm = Some(vec![segment(7, 5000, 0, 5000)]);
        assert_eq!(shared_memory(&d).severity, Severity::Error);
    }

    #[test]
    fn unreadable_sysv_table_is_distinct_from_an_empty_one() {
        let mut d = healthy();
        d.sysv_shm = None;
        assert!(evidence(&shared_memory(&d), "sysv_segments").is_none());
        d.sysv_shm = Some(Vec::new());
        assert_eq!(evidence(&shared_memory(&d), "sysv_segments"), Some("0"));
    }

    #[test]
    fn nearly_full_tmpfs_warns_even_when_ram_use_is_small() {
        let mut d = healthy();
        d.tmpfs_mounts = vec![tmpfs("/dev/shm", 512, 500), tmpfs("/run/lock", 5, 5)];
        let f = shared_memory(&d);
        assert_eq!(f.severity, Severity::Warning);
        assert_eq!(
            evidence(&f, "tmpfs_nearly_full"),
            Some("/dev/shm"),
            "tiny mounts are ignored"
        );
        assert!(f.explanation.contains("No space left on device"));
        assert!(f
            .recommendation
            .unwrap()
            .contains("remount,size=1024M /dev/shm"));
    }

    #[test]
    fn half_full_tmpfs_is_fine() {
        let mut d = healthy();
        d.tmpfs_mounts = vec![tmpfs("/dev/shm", 512, 250)];
        assert_eq!(shared_memory(&d).severity, Severity::Info);
    }

    #[test]
    fn unattributed_shared_memory_is_explained_as_mappings() {
        let mut d = healthy();
        d.shmem_kb = 3_000_000;
        d.tmpfs_mounts = vec![tmpfs("/dev/shm", 8000, 100)];
        d.sysv_shm = Some(Vec::new());
        d.processes = vec![ProcessMemory {
            pid: 777,
            name: "postgres".into(),
            rss_anon_kb: 1,
            rss_file_kb: 0,
            rss_shmem_kb: 2_500_000,
            swap_kb: 0,
        }];
        let f = shared_memory(&d);
        assert!(f.explanation.contains("anonymous mappings"));
        assert!(f.explanation.contains("postgres (PID 777)"));
        assert!(evidence(&f, "shared_in_mappings_kb").is_some());
        let rec = f.recommendation.unwrap();
        assert!(rec.contains("shared_buffers"));
        assert!(rec.contains("systemctl status 777"));
    }

    #[test]
    fn attributed_memory_is_not_called_unattributed() {
        let mut d = healthy();
        d.shmem_kb = 3_000_000;
        d.tmpfs_mounts = vec![tmpfs("/dev/shm", 8000, 2800)];
        d.sysv_shm = Some(Vec::new());
        assert!(!shared_memory(&d).explanation.contains("anonymous mappings"));
    }

    #[test]
    fn no_attribution_claims_without_any_source() {
        let mut d = healthy();
        d.shmem_kb = 3_000_000;
        // no tmpfs mounts, sysv unreadable: we cannot say where it lives
        let f = shared_memory(&d);
        assert!(!f.explanation.contains("anonymous mappings"));
    }

    #[test]
    fn many_orphans_are_truncated_with_a_pointer_to_ipcs() {
        let mut d = healthy();
        d.sysv_shm = Some((1..=8).map(|i| segment(i, 100, 0, 100)).collect());
        let rec = shared_memory(&d).recommendation.unwrap();
        assert!(rec.contains("and 3 more"));
        assert_eq!(rec.matches("sudo ipcrm -m").count(), 5);
    }

    #[test]
    fn sharers_are_not_summed() {
        let mut d = healthy();
        d.processes = vec![
            ProcessMemory {
                pid: 1,
                name: "a".into(),
                rss_anon_kb: 0,
                rss_file_kb: 0,
                rss_shmem_kb: 100,
                swap_kb: 0,
            },
            ProcessMemory {
                pid: 2,
                name: "b".into(),
                rss_anon_kb: 0,
                rss_file_kb: 0,
                rss_shmem_kb: 300,
                swap_kb: 0,
            },
        ];
        let f = shared_memory(&d);
        assert_eq!(evidence(&f, "shared_user_1"), Some("b (PID 2): 300 kB"));
        assert!(f.explanation.contains("do not add these up"));
    }
}
