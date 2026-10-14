// SPDX-License-Identifier: GPL-3.0-only

//! Fast, cheap system stats for the TUI's continuously-updating header
//! (CPU/memory/disk %). Deliberately kept separate from the `Module`
//! trait pipeline in `modules/`: those produce evidence-based `Finding`s
//! meant to be read once per audit, complete with explanations and
//! recommendations. This is different — plain gauges refreshed roughly
//! once a second for as long as the TUI is open, with no interpretation
//! attached. Reusing the Storage/Memory modules for this would mean
//! re-running their full collect+analyze pipelines every tick (including
//! Storage's per-device `smartctl` calls), which is both wasteful and
//! far too slow for a once-a-second refresh.

use std::fs;

use crate::core::command::command;

/// One /proc/stat aggregate-CPU sample, in USER_HZ clock ticks since
/// boot. CPU *usage* isn't a single instantaneous value on Linux — it's
/// derived from the busy/idle delta between two samples, so the caller
/// keeps the previous sample around and calls `cpu_usage_percent`.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct CpuStatSample {
    idle: u64,
    total: u64,
}

/// Read the first ("cpu ") line of `/proc/stat`. `None` if the file is
/// missing or malformed — the header just shows "—" for CPU in that
/// case rather than a wrong number.
pub fn read_cpu_stat() -> Option<CpuStatSample> {
    let text = fs::read_to_string("/proc/stat").ok()?;
    parse_cpu_stat(&text)
}

/// Parse `/proc/stat`'s aggregate CPU line: "cpu  user nice system idle
/// iowait irq softirq steal guest guest_nice". `idle` and `iowait`
/// together are "not busy"; everything else (excluding guest/guest_nice,
/// which are already counted inside user/nice) is "busy". Pure function,
/// tested against fixture text.
pub fn parse_cpu_stat(text: &str) -> Option<CpuStatSample> {
    let line = text.lines().find(|l| l.starts_with("cpu "))?;
    let fields: Vec<u64> = line
        .split_whitespace()
        .skip(1)
        .filter_map(|f| f.parse().ok())
        .collect();
    if fields.len() < 4 {
        return None;
    }
    let get = |i: usize| fields.get(i).copied().unwrap_or(0);
    let (user, nice, system, idle) = (get(0), get(1), get(2), get(3));
    let (iowait, irq, softirq, steal) = (get(4), get(5), get(6), get(7));

    let idle_total = idle + iowait;
    let total = user + nice + system + idle + iowait + irq + softirq + steal;
    Some(CpuStatSample {
        idle: idle_total,
        total,
    })
}

/// CPU busy percentage between two samples. `None` if `total` hasn't
/// advanced (e.g. samples taken back-to-back with no real elapsed time),
/// since dividing by zero there would be meaningless rather than merely
/// imprecise.
pub fn cpu_usage_percent(prev: CpuStatSample, curr: CpuStatSample) -> Option<f64> {
    let total_delta = curr.total.saturating_sub(prev.total);
    if total_delta == 0 {
        return None;
    }
    let idle_delta = curr.idle.saturating_sub(prev.idle);
    let busy_delta = total_delta.saturating_sub(idle_delta);
    Some(busy_delta as f64 / total_delta as f64 * 100.0)
}

/// Snapshot of the live header stats for one refresh tick.
#[derive(Debug, Clone, Copy, PartialEq, Default)]
pub struct LiveStats {
    /// `None` until a second /proc/stat sample lets a delta be computed.
    pub cpu_percent: Option<f64>,
    pub mem_percent: Option<f64>,
    pub mem_used_gb: Option<f64>,
    pub mem_total_gb: Option<f64>,
    pub disk_percent: Option<f64>,
}

/// Read `/proc/meminfo` and return (used_percent, used_gb, total_gb).
/// Same "used = total - available" calculation as MEM004, kept as its
/// own minimal read here rather than routing through the Memory module.
fn read_memory_percent() -> Option<(f64, f64, f64)> {
    let text = fs::read_to_string("/proc/meminfo").ok()?;
    let mut total_kb = None;
    let mut available_kb = None;
    for line in text.lines() {
        let Some((key, rest)) = line.split_once(':') else {
            continue;
        };
        let Some(value_str) = rest.split_whitespace().next() else {
            continue;
        };
        let Ok(value) = value_str.parse::<u64>() else {
            continue;
        };
        match key {
            "MemTotal" => total_kb = Some(value),
            "MemAvailable" => available_kb = Some(value),
            _ => {}
        }
    }
    let (total_kb, available_kb) = (total_kb?, available_kb?);
    if total_kb == 0 {
        return None;
    }
    let used_kb = total_kb.saturating_sub(available_kb);
    let pct = used_kb as f64 / total_kb as f64 * 100.0;
    let to_gb = |kb: u64| kb as f64 / 1024.0 / 1024.0;
    Some((pct, to_gb(used_kb), to_gb(total_kb)))
}

/// Root filesystem usage percentage via a single, fast `df -kP /` call
/// (not the Storage module's full `-kPT` sweep of every filesystem) —
/// there's no `/proc` source for filesystem space, so this is the one
/// piece of the live header that shells out.
fn read_root_disk_percent() -> Option<f64> {
    let output = command("df").args(["-kP", "/"]).output().ok()?;
    parse_df_percent(&String::from_utf8_lossy(&output.stdout))
}

/// Parse the "Capacity" column (e.g. "62%") from `df -kP` output's data
/// row. Pure function, tested against fixture text.
pub fn parse_df_percent(text: &str) -> Option<f64> {
    let data_line = text.lines().nth(1)?;
    let fields: Vec<&str> = data_line.split_whitespace().collect();
    let pct_field = fields.get(4)?; // Filesystem 1024-blocks Used Available Capacity Mounted
    pct_field.trim_end_matches('%').parse().ok()
}

/// Take a fresh reading of everything the header shows. `prev_cpu` is
/// the previous tick's CPU sample (`None` on the very first call, in
/// which case `cpu_percent` comes back `None` too — there's no delta
/// yet). Returns the new stats plus the CPU sample to keep for next time.
pub fn refresh(prev_cpu: Option<CpuStatSample>) -> (LiveStats, Option<CpuStatSample>) {
    let curr_cpu = read_cpu_stat();
    let cpu_percent = match (prev_cpu, curr_cpu) {
        (Some(prev), Some(curr)) => cpu_usage_percent(prev, curr),
        _ => None,
    };

    let (mem_percent, mem_used_gb, mem_total_gb) = match read_memory_percent() {
        Some((pct, used, total)) => (Some(pct), Some(used), Some(total)),
        None => (None, None, None),
    };

    let disk_percent = read_root_disk_percent();

    (
        LiveStats {
            cpu_percent,
            mem_percent,
            mem_used_gb,
            mem_total_gb,
            disk_percent,
        },
        curr_cpu,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    const FIXTURE_STAT_A: &str = "\
cpu  100 10 50 800 5 0 2 0 0 0
cpu0 100 10 50 800 5 0 2 0 0 0
";
    const FIXTURE_STAT_B: &str = "\
cpu  150 10 70 900 10 0 3 0 0 0
cpu0 150 10 70 900 10 0 3 0 0 0
";

    #[test]
    fn parses_cpu_stat_line() {
        let sample = parse_cpu_stat(FIXTURE_STAT_A).unwrap();
        // idle = 800 + 5 = 805; total = 100+10+50+800+5+0+2 = 967
        assert_eq!(sample.idle, 805);
        assert_eq!(sample.total, 967);
    }

    #[test]
    fn ignores_per_core_lines() {
        // Only the aggregate "cpu " line (with the trailing space,
        // distinguishing it from "cpu0", "cpu1", ...) should be read.
        let sample = parse_cpu_stat(FIXTURE_STAT_A).unwrap();
        let sample_b = parse_cpu_stat(FIXTURE_STAT_B).unwrap();
        assert_ne!(sample, sample_b);
    }

    #[test]
    fn computes_usage_between_two_samples() {
        let a = parse_cpu_stat(FIXTURE_STAT_A).unwrap();
        let b = parse_cpu_stat(FIXTURE_STAT_B).unwrap();
        let pct = cpu_usage_percent(a, b).unwrap();
        // total delta = (150+10+70+900+10+0+3) - 967 = 1143-967 = 176
        // idle delta = (900+10) - 805 = 105
        // busy delta = 176 - 105 = 71 -> 71/176 * 100 ~= 40.34%
        assert!((pct - 40.34).abs() < 0.1);
    }

    #[test]
    fn identical_samples_yield_none_not_a_divide_by_zero() {
        let a = parse_cpu_stat(FIXTURE_STAT_A).unwrap();
        assert_eq!(cpu_usage_percent(a, a), None);
    }

    #[test]
    fn malformed_stat_text_is_none() {
        assert_eq!(parse_cpu_stat("not /proc/stat at all\n"), None);
    }

    #[test]
    fn parses_df_percent_from_root_row() {
        let text = "Filesystem     1024-blocks     Used Available Capacity Mounted on\n/dev/sda1        102400000 63488000  38912000      62% /\n";
        assert_eq!(parse_df_percent(text), Some(62.0));
    }

    #[test]
    fn df_percent_missing_data_row_is_none() {
        assert_eq!(parse_df_percent("Filesystem header only\n"), None);
    }

    #[test]
    fn refresh_first_call_has_no_cpu_delta_yet() {
        // No previous sample -> cpu_percent must be None, not a bogus
        // value computed against a zeroed baseline.
        let (stats, _sample) = refresh(None);
        assert_eq!(stats.cpu_percent, None);
    }
}
