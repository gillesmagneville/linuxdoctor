// SPDX-License-Identifier: GPL-3.0-only

//! Memory pressure (MEM009): is the machine actually short of memory
//! right now, and has it been before? Combines the kernel's stall
//! accounting (PSI) with the cumulative counters in /proc/vmstat.

use crate::models::{Category, Confidence, Finding, Severity};

use super::collect::{percent, MemoryPressure, MemoryRawData, VmstatCounters};
use super::format::{group_label, kb, pct, top_by_anon, Steps};

/// Share of the last minute spent stalled (PSI "some"), and the thresholds
/// at which it matters.
const SOME_WARNING: f64 = 10.0;
const SOME_ERROR: f64 = 25.0;
/// PSI "full": every non-idle task stalled at once.
const FULL_WARNING: f64 = 1.0;
const FULL_ERROR: f64 = 5.0;
/// A sharp, short burst (last 10 s) is worth a warning on its own.
const SOME_BURST_WARNING: f64 = 40.0;

/// Direct reclaim is only worth a remark when it has done real work (1 GiB
/// of pages scanned) and makes up a large share of all reclaim.
const DIRECT_RECLAIM_MIN_KB: u64 = 1024 * 1024;
const DIRECT_RECLAIM_SHARE: f64 = 25.0;

fn psi_severity(p: &MemoryPressure) -> (Severity, Confidence) {
    let some60 = p.some.avg60;
    let full60 = p.full.map(|f| f.avg60).unwrap_or(0.0);
    if some60 >= SOME_ERROR || full60 >= FULL_ERROR {
        (Severity::Error, Confidence::correlated(92))
    } else if some60 >= SOME_WARNING || full60 >= FULL_WARNING || p.some.avg10 >= SOME_BURST_WARNING
    {
        (Severity::Warning, Confidence::strong_indication(85))
    } else {
        (Severity::Info, Confidence::direct_observation())
    }
}

fn direct_reclaim_share(c: &VmstatCounters) -> f64 {
    percent(c.pgscan_direct, c.pgscan_direct + c.pgscan_kswapd)
}

/// MEM009 — reported whenever the kernel exposes PSI or /proc/vmstat. The
/// pressure numbers say how much time programs lose *now*; the counters
/// say whether memory has run out *before* (OOM kills, programs forced to
/// reclaim memory themselves).
pub fn pressure(data: &MemoryRawData) -> Option<Finding> {
    if data.pressure.is_none() && data.vmstat.is_none() {
        return None;
    }
    let page_kb = data.page_size_kb_or_default();

    let mut severity = Severity::Info;
    let mut confidence = Confidence::direct_observation();
    let mut paragraphs: Vec<String> = Vec::new();
    let mut builder_evidence: Vec<(String, String)> = Vec::new();

    match &data.pressure {
        Some(p) => {
            let (sev, conf) = psi_severity(p);
            severity = sev;
            confidence = conf;
            let mut line = format!(
                "Over the last 10 / 60 / 300 seconds, at least one program was stalled waiting \
                 for memory {} / {} / {} of the time",
                pct(p.some.avg10),
                pct(p.some.avg60),
                pct(p.some.avg300)
            );
            match p.full {
                Some(f) => line.push_str(&format!(
                    ", and all programs were stalled at once {} / {} / {} of the time.",
                    pct(f.avg10),
                    pct(f.avg60),
                    pct(f.avg300)
                )),
                None => line.push('.'),
            }
            paragraphs.push(line);
            paragraphs.push(match sev {
                Severity::Error => {
                    "That is severe: the machine loses a large part of its time waiting for \
                     memory. Programs freeze or crawl, and the OOM killer is likely to act."
                        .to_string()
                }
                Severity::Warning => {
                    "That is a real cost: programs are regularly held up waiting for memory, \
                     which users feel as stutter or slow responses. The machine does not have \
                     enough RAM for what it is running."
                        .to_string()
                }
                _ => "No meaningful stalls at the moment: programs are getting the memory \
                      they ask for without waiting."
                    .to_string(),
            });
            builder_evidence.push(("psi_some_avg10".into(), format!("{:.2}", p.some.avg10)));
            builder_evidence.push(("psi_some_avg60".into(), format!("{:.2}", p.some.avg60)));
            builder_evidence.push(("psi_some_avg300".into(), format!("{:.2}", p.some.avg300)));
            if let Some(f) = p.full {
                builder_evidence.push(("psi_full_avg10".into(), format!("{:.2}", f.avg10)));
                builder_evidence.push(("psi_full_avg60".into(), format!("{:.2}", f.avg60)));
                builder_evidence.push(("psi_full_avg300".into(), format!("{:.2}", f.avg300)));
            }
        }
        None => paragraphs.push(
            "Memory pressure (PSI) is not available on this kernel — it needs Linux 4.20 or \
             later, built with CONFIG_PSI and not booted with psi=0 — so current stalls cannot \
             be measured. The counters below still show what happened since boot."
                .to_string(),
        ),
    }

    let mut oom_kills = 0;
    if let Some(c) = &data.vmstat {
        oom_kills = c.oom_kill;
        if c.oom_kill > 0 {
            if severity < Severity::Warning {
                severity = Severity::Warning;
                confidence = Confidence::direct_observation();
            }
            paragraphs.push(format!(
                "The kernel has killed {} process{} since boot because memory ran out. This \
                 counts both a whole machine out of RAM and a program or service exceeding its \
                 own memory limit (a container or systemd MemoryMax).",
                c.oom_kill,
                if c.oom_kill == 1 { "" } else { "es" }
            ));
        } else {
            paragraphs.push("No process has been killed by the OOM killer since boot.".to_string());
        }
        builder_evidence.push(("oom_kills".into(), c.oom_kill.to_string()));

        if c.pswpout > 0 || c.pswpin > 0 {
            paragraphs.push(format!(
                "Since boot, {} was written to swap and {} read back from it.",
                kb(c.pswpout * page_kb),
                kb(c.pswpin * page_kb)
            ));
            builder_evidence.push((
                "swapped_out_since_boot_kb".into(),
                (c.pswpout * page_kb).to_string(),
            ));
            builder_evidence.push((
                "swapped_in_since_boot_kb".into(),
                (c.pswpin * page_kb).to_string(),
            ));
        }

        let share = direct_reclaim_share(c);
        let direct_kb = c.pgscan_direct * page_kb;
        builder_evidence.push(("allocation_stalls".into(), c.allocstall.to_string()));
        builder_evidence.push(("direct_reclaim_percent".into(), format!("{share:.1}")));
        if direct_kb >= DIRECT_RECLAIM_MIN_KB && share >= DIRECT_RECLAIM_SHARE {
            paragraphs.push(format!(
                "Programs have often had to free memory themselves instead of the background \
                 reclaim thread doing it ({} of all page scanning, {} allocation stalls since \
                 boot). Each such stall freezes the program that asked for memory until enough \
                 is freed — a sign that memory has repeatedly been tight.",
                pct(share),
                c.allocstall
            ));
        }
        if c.workingset_refault > 0 {
            builder_evidence.push((
                "file_cache_refaults_kb".into(),
                (c.workingset_refault * page_kb).to_string(),
            ));
        }
    }

    let mut builder = Finding::builder(
        "MEM009",
        "Memory Pressure and OOM History",
        Category::Memory,
        severity,
        confidence,
    );
    for (k, v) in builder_evidence {
        builder = builder.evidence(k, v);
    }
    builder = builder.explanation(paragraphs.join("\n\n"));

    if severity > Severity::Info {
        builder = builder.recommendation(steps(data, oom_kills).build());
    }
    Some(builder.build())
}

fn steps(data: &MemoryRawData, oom_kills: u64) -> Steps {
    let mut steps = Steps::new().step(
        "Confirm what is happening now (the pressure file should be near zero on a healthy \
         machine; in vmstat, non-zero si/so columns mean active swapping):",
        &["cat /proc/pressure/memory", "vmstat 1 5"],
    );

    if oom_kills > 0 {
        steps = steps.step(
            "Find out who was killed and why (the log says whether the whole machine or a \
             single memory limit was the cause):",
            &["sudo dmesg -T | grep -i -E 'out of memory|oom-kill|killed process'"],
        );
    }

    let top = top_by_anon(&data.processes, 1);
    steps = steps.step(
        match top.first() {
            Some(g) => format!(
                "Reduce the demand: {} holds the most private memory ({}). The Used memory \
                 page lists the consumers and what to do about each.",
                group_label(g),
                kb(g.anon_kb)
            ),
            None => "Reduce the demand: the Used memory page lists the consumers and what to \
                     do about each."
                .to_string(),
        },
        &[],
    );

    if !data.has_swap() {
        steps = steps.step(
            "There is no swap, so the kernel has nothing to relieve the pressure with. The \
             Swap configuration finding has the zram and swap file commands.",
            &[],
        );
    }

    steps = steps
        .step(
            "Stop one runaway service from taking the whole machine down by giving it a ceiling \
             (MemoryHigh slows it first, MemoryMax is the hard limit), and shield the services \
             that must survive with a negative OOM score:",
            &[
                "sudo systemctl set-property <service> MemoryHigh=<N>G MemoryMax=<M>G",
                "sudo systemctl edit <critical-service>     # add: [Service] OOMScoreAdjust=-900",
            ],
        )
        .step(
            "Let a userspace daemon act early, while the machine is still responsive, instead \
             of waiting for the kernel's OOM killer. systemd-oomd needs systemd 248+ and cgroup \
             v2; earlyoom is the alternative that works anywhere:",
            &[
                "sudo systemctl enable --now systemd-oomd",
                "sudo apt install earlyoom && sudo systemctl enable --now earlyoom",
            ],
        );
    steps
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::modules::memory::collect::PsiLine;
    use crate::modules::memory::test_support::{evidence, healthy, proc};

    fn psi(some10: f64, some60: f64, some300: f64, full60: Option<f64>) -> MemoryPressure {
        let line = |v: f64| PsiLine {
            avg10: v,
            avg60: v,
            avg300: v,
            total_us: 0,
        };
        MemoryPressure {
            some: PsiLine {
                avg10: some10,
                avg60: some60,
                avg300: some300,
                total_us: 0,
            },
            full: full60.map(line),
        }
    }

    fn with(p: MemoryPressure) -> MemoryRawData {
        MemoryRawData {
            pressure: Some(p),
            ..healthy()
        }
    }

    #[test]
    fn nothing_to_report_without_psi_or_vmstat() {
        assert!(pressure(&healthy()).is_none());
    }

    #[test]
    fn calm_machine_is_info_without_advice() {
        let f = pressure(&with(psi(0.0, 0.2, 0.1, Some(0.0)))).unwrap();
        assert_eq!(f.id, "MEM009");
        assert_eq!(f.severity, Severity::Info);
        assert!(f.recommendation.is_none());
        assert!(f.explanation.contains("No meaningful stalls"));
        assert_eq!(evidence(&f, "psi_some_avg60"), Some("0.20"));
    }

    #[test]
    fn psi_tiers() {
        let sev = |p| pressure(&with(p)).unwrap().severity;
        assert_eq!(sev(psi(0.0, 9.9, 0.0, Some(0.0))), Severity::Info);
        assert_eq!(sev(psi(0.0, 10.0, 0.0, Some(0.0))), Severity::Warning);
        assert_eq!(sev(psi(0.0, 24.9, 0.0, Some(0.0))), Severity::Warning);
        assert_eq!(sev(psi(0.0, 25.0, 0.0, Some(0.0))), Severity::Error);
        assert_eq!(
            sev(psi(0.0, 2.0, 0.0, Some(1.0))),
            Severity::Warning,
            "full stalls matter"
        );
        assert_eq!(sev(psi(0.0, 2.0, 0.0, Some(5.0))), Severity::Error);
        assert_eq!(
            sev(psi(45.0, 3.0, 1.0, Some(0.0))),
            Severity::Warning,
            "sharp burst"
        );
        assert_eq!(
            sev(psi(30.0, 3.0, 1.0, Some(0.0))),
            Severity::Info,
            "mild burst"
        );
    }

    #[test]
    fn pressure_without_a_full_line_still_works() {
        let f = pressure(&with(psi(0.0, 12.0, 0.0, None))).unwrap();
        assert_eq!(f.severity, Severity::Warning);
        assert!(evidence(&f, "psi_full_avg60").is_none());
    }

    #[test]
    fn stalls_bring_numbered_steps_naming_the_top_consumer() {
        let mut d = with(psi(0.0, 18.0, 0.0, Some(0.5)));
        d.processes = vec![proc(1, "java", 7_000_000)];
        let f = pressure(&d).unwrap();
        let rec = f.recommendation.unwrap();
        assert!(rec.starts_with("1. "));
        assert!(rec.contains("cat /proc/pressure/memory"));
        assert!(rec.contains("java holds the most private memory"));
        assert!(rec.contains("MemoryHigh"));
        assert!(rec.contains("systemd-oomd"));
        assert!(
            !rec.contains("dmesg"),
            "no OOM kills, so no kill-hunting step"
        );
    }

    #[test]
    fn oom_kills_raise_a_warning_even_when_pressure_is_calm() {
        let mut d = with(psi(0.0, 0.0, 0.0, Some(0.0)));
        d.vmstat = Some(VmstatCounters {
            oom_kill: 3,
            ..Default::default()
        });
        let f = pressure(&d).unwrap();
        assert_eq!(f.severity, Severity::Warning);
        assert_eq!(f.confidence.percent, 100);
        assert!(f.explanation.contains("killed 3 processes since boot"));
        assert!(
            f.explanation.contains("MemoryMax"),
            "memory-limit kills are not machine-wide OOM"
        );
        assert!(f
            .recommendation
            .unwrap()
            .contains("grep -i -E 'out of memory|oom-kill|killed process'"));
    }

    #[test]
    fn oom_kill_never_lowers_a_worse_pressure_verdict() {
        let mut d = with(psi(0.0, 40.0, 0.0, Some(0.0)));
        d.vmstat = Some(VmstatCounters {
            oom_kill: 1,
            ..Default::default()
        });
        let f = pressure(&d).unwrap();
        assert_eq!(f.severity, Severity::Error);
        assert!(f.explanation.contains("killed 1 process since boot"));
    }

    #[test]
    fn zero_oom_kills_is_stated() {
        let mut d = healthy();
        d.vmstat = Some(VmstatCounters::default());
        let f = pressure(&d).unwrap();
        assert!(f.explanation.contains("No process has been killed"));
        assert!(f.explanation.contains("not available on this kernel"));
        assert_eq!(f.severity, Severity::Info);
    }

    #[test]
    fn swap_traffic_uses_the_page_size() {
        let mut d = healthy();
        d.page_size_kb = 64; // arm64 with 64 KiB pages
        d.vmstat = Some(VmstatCounters {
            pswpout: 100,
            pswpin: 10,
            ..Default::default()
        });
        let f = pressure(&d).unwrap();
        assert_eq!(evidence(&f, "swapped_out_since_boot_kb"), Some("6400"));
        assert_eq!(evidence(&f, "swapped_in_since_boot_kb"), Some("640"));
    }

    #[test]
    fn heavy_direct_reclaim_is_noted_but_stays_informational() {
        let mut d = healthy();
        d.vmstat = Some(VmstatCounters {
            pgscan_direct: 600_000, // 2.3 GB at 4 kB
            pgscan_kswapd: 1_000_000,
            allocstall: 777,
            ..Default::default()
        });
        let f = pressure(&d).unwrap();
        assert_eq!(f.severity, Severity::Info);
        assert!(f.explanation.contains("free memory themselves"));
        assert!(f.explanation.contains("777 allocation stalls"));
    }

    #[test]
    fn light_direct_reclaim_is_not_mentioned() {
        let mut d = healthy();
        d.vmstat = Some(VmstatCounters {
            pgscan_direct: 1000,
            pgscan_kswapd: 100,
            allocstall: 5,
            ..Default::default()
        });
        assert!(!pressure(&d)
            .unwrap()
            .explanation
            .contains("free memory themselves"));
        d.vmstat = Some(VmstatCounters {
            pgscan_direct: 1_000_000,
            pgscan_kswapd: 100_000_000,
            ..Default::default()
        });
        assert!(
            !pressure(&d)
                .unwrap()
                .explanation
                .contains("free memory themselves"),
            "small share"
        );
    }

    #[test]
    fn no_swap_adds_the_swap_pointer() {
        let mut d = with(psi(0.0, 30.0, 0.0, Some(0.0)));
        d.swap_total_kb = 0;
        d.swap_free_kb = 0;
        assert!(pressure(&d)
            .unwrap()
            .recommendation
            .unwrap()
            .contains("There is no swap"));
        let d = with(psi(0.0, 30.0, 0.0, Some(0.0)));
        assert!(!pressure(&d)
            .unwrap()
            .recommendation
            .unwrap()
            .contains("There is no swap"));
    }
}
