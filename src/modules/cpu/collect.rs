// SPDX-License-Identifier: GPL-3.0-only

use std::collections::BTreeMap;
use std::fs;
use std::path::Path;

use crate::core::error::ModuleError;

/// One physical socket, reconstructed by grouping /proc/cpuinfo's
/// per-logical-CPU entries by `physical id`. On a single-socket machine
/// (the common case) this collapses to exactly one entry — the grouping
/// still runs, it just has nothing to group.
#[derive(Debug, Clone, PartialEq)]
pub struct CpuSocket {
    pub physical_id: u32,
    pub model_name: Option<String>,
    /// Distinct `core id` values seen for this socket — physical cores,
    /// not logical CPUs (a core with SMT/Hyper-Threading exposes 2+
    /// logical CPUs per core id).
    pub cores: usize,
    /// Logical CPUs (threads) belonging to this socket.
    pub threads: usize,
    /// The actual online logical CPU indices belonging to this socket
    /// (e.g. [0, 1, 2, 3]) — needed to work out, per socket, which of its
    /// CPUs are isolated vs available.
    pub logical_cpus: Vec<u32>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct CpuRawData {
    pub load_1m: f64,
    pub load_5m: f64,
    pub load_15m: f64,
    pub sockets: Vec<CpuSocket>,

    /// CPUs excluded from the general scheduler via the `isolcpus=` boot
    /// parameter — `/sys/devices/system/cpu/isolated`.
    pub isolcpus: Vec<u32>,
    /// CPUs running in full-tickless mode via the `nohz_full=` boot
    /// parameter — `/sys/devices/system/cpu/nohz_full`. A distinct
    /// mechanism from `isolcpus=`, with its own sysfs file — commonly
    /// used together, but not the same thing, and not interchangeable.
    pub nohz_full: Vec<u32>,
    /// CPUs isolated via a cgroup v2 "isolated" cpuset partition — found
    /// by walking `/sys/fs/cgroup` for any `cpuset.cpus.isolated` file.
    /// This is the mechanism most likely to be behind CPUs a VM/container
    /// orchestrator (e.g. Kubernetes' CPU Manager static policy) reserved
    /// at runtime, since it isn't set via the kernel command line at all.
    pub cgroup_isolated: Vec<u32>,
    /// CPUs excluded from `system.slice`'s effective cpuset
    /// (`/sys/fs/cgroup/system.slice/cpuset.cpus.effective`). A common
    /// libvirt-hook technique for reserving cores for VMs: a hook script
    /// runs `systemctl set-property --runtime system.slice
    /// AllowedCPUs=<cpus>` when a VM starts (restricting ordinary host
    /// services to that set and leaving the complement free for
    /// `machine.slice`, where libvirt/qemu VMs run), then reverses it
    /// when the VM stops. Distinct from `cgroup_isolated` above: this is
    /// a plain cpuset restriction on one specific slice, not an
    /// "isolated partition" — `cpuset.cpus.isolated` is never populated
    /// by this technique.
    pub system_slice_excluded: Vec<u32>,

    /// CPUs the kernel considers "possible" but which aren't currently
    /// online — read by diffing `/sys/devices/system/cpu/possible`
    /// against the CPUs actually seen in `/proc/cpuinfo`. On a VM, this is
    /// commonly a hypervisor provisioning more vCPUs than it currently
    /// activates (for later hot-add), which — unlike host-side pinning —
    /// *is* visible from inside the guest.
    pub offline_cpus: Vec<u32>,
}

impl CpuRawData {
    pub fn total_cores(&self) -> usize {
        self.sockets.iter().map(|s| s.cores).sum()
    }

    pub fn total_logical_cpus(&self) -> usize {
        self.sockets.iter().map(|s| s.threads).sum()
    }

    /// Union of every isolation mechanism checked, deduplicated and
    /// sorted. Used where "is this CPU excluded from the general
    /// scheduler, for any reason" is what matters (e.g. per-socket
    /// available/isolated attribution) — see CPU005 for the mechanism
    /// breakdown instead.
    pub fn all_isolated_cpus(&self) -> Vec<u32> {
        let mut all: Vec<u32> = self
            .isolcpus
            .iter()
            .chain(self.nohz_full.iter())
            .chain(self.cgroup_isolated.iter())
            .chain(self.system_slice_excluded.iter())
            .copied()
            .collect();
        all.sort_unstable();
        all.dedup();
        all
    }
}

/// One /proc/cpuinfo entry, before grouping into sockets.
struct LogicalCpu {
    processor: u32,
    physical_id: u32,
    core_id: u32,
    model_name: Option<String>,
}

const CGROUP_ROOT: &str = "/sys/fs/cgroup";
// Comfortably covers systemd slice/scope nesting and Kubernetes'
// kubepods.slice/pod.../container.scope nesting, without an unbounded
// walk on a system with an unusually deep or wide cgroup tree.
const MAX_CGROUP_WALK_DEPTH: u32 = 8;
const MAX_CGROUP_WALK_NODES: u32 = 4000;

/// Thin I/O wrapper: reads the source files and delegates all
/// interpretation to the pure parse/group functions below.
pub fn collect() -> Result<CpuRawData, ModuleError> {
    let loadavg_text = fs::read_to_string("/proc/loadavg").map_err(|source| ModuleError::Io {
        path: "/proc/loadavg".to_string(),
        source,
    })?;
    let (load_1m, load_5m, load_15m) = parse_loadavg(&loadavg_text)?;

    let cpuinfo_text = fs::read_to_string("/proc/cpuinfo").map_err(|source| ModuleError::Io {
        path: "/proc/cpuinfo".to_string(),
        source,
    })?;
    let logical_cpus = parse_cpuinfo(&cpuinfo_text)?;
    let sockets = group_into_sockets(&logical_cpus);

    // All three isolation sources are lenient on absence: an older kernel,
    // a container, or a system simply not using a given mechanism will be
    // missing the corresponding file/entries entirely, which just means
    // "nothing isolated this way" -- not a collection failure.
    let isolcpus = fs::read_to_string("/sys/devices/system/cpu/isolated")
        .map(|text| parse_cpu_list(&text))
        .unwrap_or_default();
    let nohz_full = fs::read_to_string("/sys/devices/system/cpu/nohz_full")
        .map(|text| parse_cpu_list(&text))
        .unwrap_or_default();
    let cgroup_isolated = find_cgroup_isolated_cpus(Path::new(CGROUP_ROOT));

    let possible_cpus = fs::read_to_string("/sys/devices/system/cpu/possible")
        .map(|text| parse_cpu_list(&text))
        .unwrap_or_default();
    let online: Vec<u32> = logical_cpus.iter().map(|c| c.processor).collect();
    let offline_cpus: Vec<u32> = possible_cpus
        .into_iter()
        .filter(|c| !online.contains(c))
        .collect();

    let system_slice_excluded = read_system_slice_excluded(Path::new(CGROUP_ROOT), &online);

    Ok(CpuRawData {
        load_1m,
        load_5m,
        load_15m,
        sockets,
        isolcpus,
        nohz_full,
        cgroup_isolated,
        system_slice_excluded,
        offline_cpus,
    })
}

/// Parse `/proc/loadavg`, e.g. "0.52 0.58 0.59 1/234 5678". Pure function,
/// tested directly against fixture strings.
pub fn parse_loadavg(text: &str) -> Result<(f64, f64, f64), ModuleError> {
    let mut fields = text.trim().split_whitespace();
    let parse_next = |fields: &mut std::str::SplitWhitespace, which: &str| {
        fields
            .next()
            .ok_or_else(|| ModuleError::Parse {
                what: "/proc/loadavg".to_string(),
                reason: format!("missing {which} field"),
            })
            .and_then(|s| {
                s.parse::<f64>().map_err(|e| ModuleError::Parse {
                    what: "/proc/loadavg".to_string(),
                    reason: format!("{which} field '{s}': {e}"),
                })
            })
    };
    let load_1m = parse_next(&mut fields, "load_1m")?;
    let load_5m = parse_next(&mut fields, "load_5m")?;
    let load_15m = parse_next(&mut fields, "load_15m")?;
    Ok((load_1m, load_5m, load_15m))
}

/// Parse the full `/proc/cpuinfo` into one record per logical CPU. Entries
/// are separated by blank lines; `physical id`/`core id` default to 0 when
/// absent (common on simple single-socket VMs, where the field may be
/// omitted entirely rather than explicitly zero).
fn parse_cpuinfo(text: &str) -> Result<Vec<LogicalCpu>, ModuleError> {
    let mut cpus = Vec::new();
    let mut processor: Option<u32> = None;
    let mut physical_id: u32 = 0;
    let mut core_id: u32 = 0;
    let mut model_name: Option<String> = None;

    let flush = |cpus: &mut Vec<LogicalCpu>,
                 processor: &mut Option<u32>,
                 physical_id: &mut u32,
                 core_id: &mut u32,
                 model_name: &mut Option<String>| {
        if let Some(p) = processor.take() {
            cpus.push(LogicalCpu {
                processor: p,
                physical_id: *physical_id,
                core_id: *core_id,
                model_name: model_name.clone(),
            });
        }
        *physical_id = 0;
        *core_id = 0;
        *model_name = None;
    };

    for line in text.lines() {
        if line.trim().is_empty() {
            flush(
                &mut cpus,
                &mut processor,
                &mut physical_id,
                &mut core_id,
                &mut model_name,
            );
            continue;
        }
        let Some((key, value)) = line.split_once(':') else {
            continue;
        };
        let value = value.trim();
        match key.trim() {
            "processor" => processor = value.parse().ok(),
            "physical id" => physical_id = value.parse().unwrap_or(0),
            "core id" => core_id = value.parse().unwrap_or(0),
            "model name" => model_name = Some(value.to_string()),
            _ => {}
        }
    }
    // Final block may not be followed by a trailing blank line.
    flush(
        &mut cpus,
        &mut processor,
        &mut physical_id,
        &mut core_id,
        &mut model_name,
    );

    if cpus.is_empty() {
        return Err(ModuleError::Parse {
            what: "/proc/cpuinfo".to_string(),
            reason: "no processor entries found".to_string(),
        });
    }
    Ok(cpus)
}

/// Group logical CPUs by `physical_id` into sockets. `cores` is the count
/// of *distinct* `core_id` values actually observed, not a self-reported
/// field -- direct observation over trusting a value that can be stale or
/// absent in virtualized environments.
fn group_into_sockets(cpus: &[LogicalCpu]) -> Vec<CpuSocket> {
    let mut by_socket: BTreeMap<u32, Vec<&LogicalCpu>> = BTreeMap::new();
    for cpu in cpus {
        by_socket.entry(cpu.physical_id).or_default().push(cpu);
    }

    by_socket
        .into_iter()
        .map(|(physical_id, members)| {
            let mut core_ids: Vec<u32> = members.iter().map(|c| c.core_id).collect();
            core_ids.sort_unstable();
            core_ids.dedup();
            let mut logical_cpus: Vec<u32> = members.iter().map(|c| c.processor).collect();
            logical_cpus.sort_unstable();
            CpuSocket {
                physical_id,
                model_name: members.first().and_then(|c| c.model_name.clone()),
                cores: core_ids.len().max(1),
                threads: members.len(),
                logical_cpus,
            }
        })
        .collect()
}

/// Parse a Linux "cpu list" string (`/sys/devices/system/cpu/isolated`,
/// `.../nohz_full`, `.../possible`, `cpuset.cpus.isolated`, and friends),
/// e.g. "0-3,8,10-12". Infallible: unparseable or empty input just yields
/// no CPUs, matching how these files read when the set is empty rather
/// than treating that as an error.
pub fn parse_cpu_list(text: &str) -> Vec<u32> {
    let text = text.trim();
    if text.is_empty() {
        return Vec::new();
    }
    let mut result = Vec::new();
    for part in text.split(',') {
        if let Some((start, end)) = part.split_once('-') {
            if let (Ok(s), Ok(e)) = (start.trim().parse::<u32>(), end.trim().parse::<u32>()) {
                result.extend(s..=e);
            }
        } else if let Ok(n) = part.trim().parse::<u32>() {
            result.push(n);
        }
    }
    result
}

/// Walk the cgroup v2 hierarchy looking for `cpuset.cpus.isolated` files
/// (populated at any cgroup where an isolated cpuset partition has been
/// created — e.g. by Kubernetes' CPU Manager static policy, or manual
/// systemd/cgroup tuning). Bounded by depth and total directories visited
/// so a large or unusual cgroup tree can't turn a diagnostic run into a
/// slow filesystem crawl. Missing/unreadable directories are skipped
/// silently, consistent with every other isolation source here being
/// lenient on absence.
fn find_cgroup_isolated_cpus(root: &Path) -> Vec<u32> {
    let mut found = Vec::new();
    let mut visited = 0u32;
    walk_cgroup_for_isolated(root, 0, &mut visited, &mut found);
    found.sort_unstable();
    found.dedup();
    found
}

fn walk_cgroup_for_isolated(dir: &Path, depth: u32, visited: &mut u32, found: &mut Vec<u32>) {
    if depth > MAX_CGROUP_WALK_DEPTH || *visited > MAX_CGROUP_WALK_NODES {
        return;
    }
    *visited += 1;

    if let Ok(text) = fs::read_to_string(dir.join("cpuset.cpus.isolated")) {
        found.extend(parse_cpu_list(&text));
    }

    let Ok(entries) = fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        if *visited > MAX_CGROUP_WALK_NODES {
            return;
        }
        if entry.file_type().map(|t| t.is_dir()).unwrap_or(false) {
            walk_cgroup_for_isolated(&entry.path(), depth + 1, visited, found);
        }
    }
}

/// CPUs excluded from `system.slice`'s effective cpuset, given the full
/// set of online CPUs. Reads `cpuset.cpus.effective` (the read-only,
/// post-inheritance value systemd exposes as `EffectiveCPUs=`) rather than
/// the raw `cpuset.cpus`, since that's what's actually enforced. Absence
/// of the file (cpuset controller not delegated to system.slice — the
/// default on most systems that don't use this technique) or an empty/
/// unrestricted value both mean "nothing excluded", not an error.
fn read_system_slice_excluded(cgroup_root: &Path, online_cpus: &[u32]) -> Vec<u32> {
    let system_slice = cgroup_root.join("system.slice");
    let text = fs::read_to_string(system_slice.join("cpuset.cpus.effective"))
        .or_else(|_| fs::read_to_string(system_slice.join("cpuset.cpus")));

    let Ok(text) = text else {
        return Vec::new();
    };

    let allowed = parse_cpu_list(&text);
    if allowed.is_empty() {
        // Empty conventionally means "not restricted here, inherits the
        // parent's range" -- not "zero CPUs allowed".
        return Vec::new();
    }

    online_cpus
        .iter()
        .filter(|c| !allowed.contains(c))
        .copied()
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    const FIXTURE_SINGLE_SOCKET: &str = "\
processor\t: 0
physical id\t: 0
core id\t\t: 0
model name\t: Intel(R) Xeon(R) Processor @ 2.10GHz
";

    // 2 sockets x 2 cores x 2 threads (SMT) = 8 logical CPUs.
    const FIXTURE_DUAL_SOCKET_SMT: &str = "\
processor\t: 0
physical id\t: 0
core id\t\t: 0
model name\t: Test CPU

processor\t: 1
physical id\t: 0
core id\t\t: 0
model name\t: Test CPU

processor\t: 2
physical id\t: 0
core id\t\t: 1
model name\t: Test CPU

processor\t: 3
physical id\t: 0
core id\t\t: 1
model name\t: Test CPU

processor\t: 4
physical id\t: 1
core id\t\t: 0
model name\t: Test CPU

processor\t: 5
physical id\t: 1
core id\t\t: 0
model name\t: Test CPU

processor\t: 6
physical id\t: 1
core id\t\t: 1
model name\t: Test CPU

processor\t: 7
physical id\t: 1
core id\t\t: 1
model name\t: Test CPU
";

    fn empty_isolation() -> CpuRawData {
        CpuRawData {
            load_1m: 0.0,
            load_5m: 0.0,
            load_15m: 0.0,
            sockets: vec![],
            isolcpus: vec![],
            nohz_full: vec![],
            cgroup_isolated: vec![],
            system_slice_excluded: vec![],
            offline_cpus: vec![],
        }
    }

    #[test]
    fn parses_loadavg_fields() {
        let (l1, l5, l15) = parse_loadavg("0.52 0.58 0.59 1/234 5678\n").unwrap();
        assert_eq!(l1, 0.52);
        assert_eq!(l5, 0.58);
        assert_eq!(l15, 0.59);
    }

    #[test]
    fn errors_on_missing_fields() {
        assert!(parse_loadavg("0.52 0.58").is_err());
    }

    #[test]
    fn errors_on_non_numeric_field() {
        assert!(parse_loadavg("not-a-number 0.58 0.59 1/1 1").is_err());
    }

    #[test]
    fn single_socket_topology() {
        let cpus = parse_cpuinfo(FIXTURE_SINGLE_SOCKET).unwrap();
        let sockets = group_into_sockets(&cpus);
        assert_eq!(sockets.len(), 1);
        assert_eq!(sockets[0].physical_id, 0);
        assert_eq!(sockets[0].cores, 1);
        assert_eq!(sockets[0].threads, 1);
        assert_eq!(sockets[0].logical_cpus, vec![0]);
        assert_eq!(
            sockets[0].model_name.as_deref(),
            Some("Intel(R) Xeon(R) Processor @ 2.10GHz")
        );
    }

    #[test]
    fn dual_socket_smt_topology() {
        let cpus = parse_cpuinfo(FIXTURE_DUAL_SOCKET_SMT).unwrap();
        let sockets = group_into_sockets(&cpus);
        assert_eq!(sockets.len(), 2);
        for socket in &sockets {
            assert_eq!(socket.cores, 2);
            assert_eq!(socket.threads, 4);
        }
        assert_eq!(sockets[0].logical_cpus, vec![0, 1, 2, 3]);
        assert_eq!(sockets[1].logical_cpus, vec![4, 5, 6, 7]);
    }

    #[test]
    fn total_cores_and_threads_sum_across_sockets() {
        let cpus = parse_cpuinfo(FIXTURE_DUAL_SOCKET_SMT).unwrap();
        let data = CpuRawData {
            sockets: group_into_sockets(&cpus),
            ..empty_isolation()
        };
        assert_eq!(data.total_cores(), 4);
        assert_eq!(data.total_logical_cpus(), 8);
    }

    #[test]
    fn all_isolated_cpus_unions_all_three_sources() {
        let data = CpuRawData {
            isolcpus: vec![0, 1],
            nohz_full: vec![1, 2], // overlaps with isolcpus on CPU 1
            cgroup_isolated: vec![8],
            ..empty_isolation()
        };
        assert_eq!(data.all_isolated_cpus(), vec![0, 1, 2, 8]);
    }

    #[test]
    fn all_isolated_cpus_includes_system_slice_exclusion() {
        let data = CpuRawData {
            system_slice_excluded: vec![4, 5, 6, 7],
            ..empty_isolation()
        };
        assert_eq!(data.all_isolated_cpus(), vec![4, 5, 6, 7]);
    }

    #[test]
    fn errors_on_empty_cpuinfo() {
        assert!(parse_cpuinfo("").is_err());
    }

    #[test]
    fn parses_cpu_list_ranges_and_singles() {
        assert_eq!(parse_cpu_list("0-3,8,10-12"), vec![0, 1, 2, 3, 8, 10, 11, 12]);
    }

    #[test]
    fn empty_cpu_list_is_empty() {
        assert_eq!(parse_cpu_list(""), Vec::<u32>::new());
        assert_eq!(parse_cpu_list("\n"), Vec::<u32>::new());
    }

    // The cgroup walk touches the real filesystem (it has to -- that's the
    // point), so unlike the parse_* functions above it's tested against a
    // real temporary directory tree rather than a fixture string.
    #[test]
    fn finds_cgroup_isolated_cpus_via_directory_walk() {
        let root = std::env::temp_dir().join(format!(
            "linuxdoctor_test_cgroup_{}_{}",
            std::process::id(),
            "found"
        ));
        let nested = root.join("kubepods.slice").join("pod-abc").join("container.scope");
        fs::create_dir_all(&nested).unwrap();
        fs::write(nested.join("cpuset.cpus.isolated"), "4-5\n").unwrap();

        let found = find_cgroup_isolated_cpus(&root);

        fs::remove_dir_all(&root).unwrap();
        assert_eq!(found, vec![4, 5]);
    }

    #[test]
    fn cgroup_walk_returns_empty_when_nothing_present() {
        let root = std::env::temp_dir().join(format!(
            "linuxdoctor_test_cgroup_{}_{}",
            std::process::id(),
            "empty"
        ));
        fs::create_dir_all(&root).unwrap();

        let found = find_cgroup_isolated_cpus(&root);

        fs::remove_dir_all(&root).unwrap();
        assert!(found.is_empty());
    }

    #[test]
    fn cgroup_walk_on_missing_root_returns_empty_without_erroring() {
        let root = std::env::temp_dir().join("linuxdoctor_test_cgroup_does_not_exist_at_all");
        assert!(find_cgroup_isolated_cpus(&root).is_empty());
    }

    // Mirrors the exact libvirt-hook pattern reported against this tool:
    // `systemctl set-property --runtime system.slice AllowedCPUs=<cpus>`
    // writes cpuset.cpus (and systemd exposes the enforced value via
    // cpuset.cpus.effective) on system.slice's cgroup -- the complement
    // is implicitly freed for machine.slice, i.e. the VM.
    #[test]
    fn detects_cpus_excluded_via_system_slice_allowedcpus() {
        let root = std::env::temp_dir().join(format!(
            "linuxdoctor_test_system_slice_{}_{}",
            std::process::id(),
            "restricted"
        ));
        let system_slice = root.join("system.slice");
        fs::create_dir_all(&system_slice).unwrap();
        // system.slice restricted to CPUs 0-3 on an 8-CPU machine ->
        // CPUs 4-7 are reserved for the VM.
        fs::write(system_slice.join("cpuset.cpus.effective"), "0-3\n").unwrap();

        let online: Vec<u32> = (0..8).collect();
        let excluded = read_system_slice_excluded(&root, &online);

        fs::remove_dir_all(&root).unwrap();
        assert_eq!(excluded, vec![4, 5, 6, 7]);
    }

    #[test]
    fn system_slice_unrestricted_reports_nothing_excluded() {
        let root = std::env::temp_dir().join(format!(
            "linuxdoctor_test_system_slice_{}_{}",
            std::process::id(),
            "unrestricted"
        ));
        let system_slice = root.join("system.slice");
        fs::create_dir_all(&system_slice).unwrap();
        // Full range explicitly present -- no VM reservation active.
        fs::write(system_slice.join("cpuset.cpus.effective"), "0-7\n").unwrap();

        let online: Vec<u32> = (0..8).collect();
        let excluded = read_system_slice_excluded(&root, &online);

        fs::remove_dir_all(&root).unwrap();
        assert!(excluded.is_empty());
    }

    #[test]
    fn system_slice_file_absent_reports_nothing_excluded() {
        // The common case: cpuset controller never delegated to
        // system.slice because this technique isn't in use here.
        let root = std::env::temp_dir()
            .join("linuxdoctor_test_system_slice_never_created_at_all");
        let online: Vec<u32> = (0..8).collect();
        assert!(read_system_slice_excluded(&root, &online).is_empty());
    }
}
