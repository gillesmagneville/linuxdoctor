// SPDX-License-Identifier: GPL-3.0-only

use std::fs;

use crate::core::command::command;
use crate::core::error::ModuleError;
use crate::core::parallel::parallel_map;

/// Raw facts read from the system, before any interpretation. See
/// ARCHITECTURE.md "Collectors". Deliberately includes every mounted
/// filesystem `df` reports, including pseudo/virtual ones (tmpfs, proc,
/// ...) — deciding which of these are worth a finding is analyze()'s job,
/// not collect()'s.
#[derive(Debug, Clone, PartialEq)]
pub struct FilesystemUsage {
    pub mount_point: String,
    pub fstype: String,
    pub total_kb: u64,
    pub used_kb: u64,
    pub available_kb: u64,
    pub use_percent: f64,
}

#[derive(Debug, Clone, PartialEq)]
pub struct InodeUsage {
    pub mount_point: String,
    pub fstype: String,
    pub inodes_total: u64,
    pub inodes_used: u64,
    pub inodes_free: u64,
    pub use_percent: f64,
}

#[derive(Debug, Clone, PartialEq)]
pub struct StorageRawData {
    pub filesystems: Vec<FilesystemUsage>,
    pub inodes: Vec<InodeUsage>,
    /// Whether the `smartctl` binary itself was found and runnable.
    pub smartctl_available: bool,
    /// Candidate block devices examined (after filtering out loop/ram/
    /// zram/dm/md/optical devices) — regardless of whether they turned
    /// out to support SMART.
    pub disks_checked: usize,
    /// Only devices that actually returned usable SMART data.
    pub disk_health: Vec<DiskHealth>,
    /// Whether this process is running as root — SMART queries need raw
    /// device access, which is normally root-only, so this is used to
    /// give an accurate hint when no devices report SMART data at all.
    pub running_as_root: bool,
}

/// Health facts for one block device with usable SMART data. Fields are
/// `Option` throughout because ATA and NVMe devices expose different
/// (and sometimes incomplete) subsets — see ARCHITECTURE.md "Collectors":
/// this stays a faithful transcription of what `smartctl` reported, not
/// an interpretation of it.
#[derive(Debug, Clone, PartialEq)]
pub struct DiskHealth {
    pub device: String,
    pub model: Option<String>,
    pub device_type: Option<String>,
    /// Overall SMART self-assessment: `smart_status.passed`.
    pub smart_passed: Option<bool>,
    pub temperature_celsius: Option<i64>,
    pub power_on_hours: Option<u64>,
    // ATA "big four" early-warning attributes (raw values).
    pub reallocated_sectors: Option<u64>,
    pub pending_sectors: Option<u64>,
    pub uncorrectable_sectors: Option<u64>,
    // NVMe-specific health log fields.
    pub nvme_critical_warning: Option<u64>,
    pub nvme_percentage_used: Option<u64>,
    pub nvme_media_errors: Option<u64>,
}

/// Block device name prefixes that never represent physical, directly
/// SMART-queryable storage — loopback, RAM disks, compressed RAM, device
/// mapper (LVM/crypt — query the underlying physical device instead),
/// software RAID, and optical drives.
const SMART_EXCLUDED_PREFIXES: &[&str] = &["loop", "ram", "zram", "dm-", "md", "sr", "fd"];

fn is_candidate_block_device(name: &str) -> bool {
    !SMART_EXCLUDED_PREFIXES
        .iter()
        .any(|prefix| name.starts_with(prefix))
}

/// How many `smartctl` processes may run at once. Enough to overlap the
/// waits on a large machine, few enough not to hammer the disks (or the
/// process table) with dozens of simultaneous queries.
const SMART_PARALLELISM: usize = 8;

/// List candidate block device names (e.g. "sda", "nvme0n1") from
/// `/sys/block`, filtering out pseudo/virtual ones. Missing directory
/// (exotic kernel/container) just yields no candidates, not an error.
fn list_block_devices() -> Vec<String> {
    let Ok(entries) = fs::read_dir("/sys/block") else {
        return Vec::new();
    };
    let mut devices: Vec<String> = entries
        .flatten()
        .filter_map(|e| e.file_name().into_string().ok())
        .filter(|name| is_candidate_block_device(name))
        .collect();
    devices.sort();
    devices
}

/// Whether this process is running as root (effective UID 0), read from
/// `/proc/self/status` rather than a libc call, to avoid a new
/// dependency for one field. Used only to give an accurate hint when no
/// device reports SMART data — smartctl's own error text doesn't reliably
/// distinguish "permission denied" from "device type not detected" (both
/// produce the same generic message for some device types).
fn is_root() -> bool {
    let Ok(status) = fs::read_to_string("/proc/self/status") else {
        return false;
    };
    for line in status.lines() {
        if let Some(rest) = line.strip_prefix("Uid:") {
            if let Some(euid) = rest.split_whitespace().nth(1) {
                return euid == "0";
            }
        }
    }
    false
}

fn run_smartctl(device: &str) -> Option<serde_json::Value> {
    let path = format!("/dev/{device}");
    let output = command("smartctl")
        .args(["-a", "--json=c", &path])
        .slow() // may have to spin up a sleeping disk
        .output()
        .ok()?;
    serde_json::from_slice(&output.stdout).ok()
}

/// Pure function: given smartctl's JSON output for one device, extract
/// the health facts this module cares about. Returns `None` if the
/// device has no usable SMART data (wrong type, not detected, etc.) —
/// not an error; most block devices genuinely don't support SMART.
/// Tested directly against fixture JSON (real smartctl output shapes),
/// no filesystem or subprocess access needed.
pub fn parse_smart_json(device_path: &str, json: &serde_json::Value) -> Option<DiskHealth> {
    let smart_passed = json
        .get("smart_status")
        .and_then(|s| s.get("passed"))
        .and_then(|v| v.as_bool());
    let ata_table = json
        .get("ata_smart_attributes")
        .and_then(|a| a.get("table"))
        .and_then(|t| t.as_array());
    let nvme_log = json.get("nvme_smart_health_information_log");

    if smart_passed.is_none() && ata_table.is_none() && nvme_log.is_none() {
        return None; // nothing usable -- this device doesn't support SMART
    }

    let model = json
        .get("model_name")
        .and_then(|v| v.as_str())
        .map(str::to_string);
    let device_type = json
        .get("device")
        .and_then(|d| d.get("type"))
        .and_then(|v| v.as_str())
        .map(str::to_string);
    let temperature_celsius = json
        .get("temperature")
        .and_then(|t| t.get("current"))
        .and_then(|v| v.as_i64());
    let power_on_hours = json
        .get("power_on_time")
        .and_then(|p| p.get("hours"))
        .and_then(|v| v.as_u64());

    let mut reallocated_sectors = None;
    let mut pending_sectors = None;
    let mut uncorrectable_sectors = None;
    if let Some(table) = ata_table {
        for attr in table {
            let id = attr.get("id").and_then(|v| v.as_u64());
            let raw = attr
                .get("raw")
                .and_then(|r| r.get("value"))
                .and_then(|v| v.as_u64());
            match id {
                Some(5) => reallocated_sectors = raw, // Reallocated_Sector_Ct
                Some(197) => pending_sectors = raw,   // Current_Pending_Sector
                Some(198) => uncorrectable_sectors = raw, // Offline_Uncorrectable
                _ => {}
            }
        }
    }

    let nvme_critical_warning = nvme_log
        .and_then(|n| n.get("critical_warning"))
        .and_then(|v| v.as_u64());
    let nvme_percentage_used = nvme_log
        .and_then(|n| n.get("percentage_used"))
        .and_then(|v| v.as_u64());
    let nvme_media_errors = nvme_log
        .and_then(|n| n.get("media_errors"))
        .and_then(|v| v.as_u64());

    Some(DiskHealth {
        device: device_path.to_string(),
        model,
        device_type,
        smart_passed,
        temperature_celsius,
        power_on_hours,
        reallocated_sectors,
        pending_sectors,
        uncorrectable_sectors,
        nvme_critical_warning,
        nvme_percentage_used,
        nvme_media_errors,
    })
}

/// Thin I/O wrapper: shells out to `df` twice (space, then inodes) and
/// queries SMART health per candidate block device, delegating all
/// interpretation to the pure parse functions.
pub fn collect() -> Result<StorageRawData, ModuleError> {
    let space_output = run_df(&["-kPT"])?;
    let inode_output = run_df(&["-iPT"])?;

    let smartctl_available = command("smartctl")
        .arg("--version")
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false);

    let mut disks_checked = 0;
    let mut disk_health = Vec::new();
    if smartctl_available {
        let devices = list_block_devices();
        disks_checked = devices.len();
        // One smartctl per disk, several at a time: each query is
        // independent, and on a server with a dozen disks (some of them
        // possibly spun down) doing them one after another is what made
        // this module the slowest part of the whole audit.
        let readings = parallel_map(&devices, SMART_PARALLELISM, |device| {
            let json = run_smartctl(device)?; // smartctl couldn't even produce JSON
            parse_smart_json(&format!("/dev/{device}"), &json)
        });
        disk_health.extend(readings.into_iter().flatten());
    }

    Ok(StorageRawData {
        filesystems: parse_space_usage(&space_output)?,
        inodes: parse_inode_usage(&inode_output)?,
        smartctl_available,
        disks_checked,
        disk_health,
        running_as_root: is_root(),
    })
}

/// `df` can exit non-zero while still printing valid lines for every
/// filesystem it *could* read (e.g. one permission-denied mount among
/// several). We deliberately use stdout regardless of exit status —
/// partial results beat none, consistent with "Collector failure must
/// never stop execution" in ARCHITECTURE.md.
fn run_df(args: &[&str]) -> Result<String, ModuleError> {
    let output = command("df")
        .args(args)
        .output()
        .map_err(|source| ModuleError::Command {
            command: format!("df {}", args.join(" ")),
            source,
        })?;
    Ok(String::from_utf8_lossy(&output.stdout).to_string())
}

/// Parse `df -kPT` output. Pure function, tested against fixture text.
pub fn parse_space_usage(text: &str) -> Result<Vec<FilesystemUsage>, ModuleError> {
    Ok(parse_df_rows(text)?
        .into_iter()
        .map(|r| FilesystemUsage {
            mount_point: r.mount_point,
            fstype: r.fstype,
            total_kb: r.col3,
            used_kb: r.col4,
            available_kb: r.col5,
            use_percent: r.percent,
        })
        .collect())
}

/// Parse `df -iPT` output. Pure function, tested against fixture text.
pub fn parse_inode_usage(text: &str) -> Result<Vec<InodeUsage>, ModuleError> {
    Ok(parse_df_rows(text)?
        .into_iter()
        .map(|r| InodeUsage {
            mount_point: r.mount_point,
            fstype: r.fstype,
            inodes_total: r.col3,
            inodes_used: r.col4,
            inodes_free: r.col5,
            use_percent: r.percent,
        })
        .collect())
}

struct DfRow {
    fstype: String,
    col3: u64,
    col4: u64,
    col5: u64,
    percent: f64,
    mount_point: String,
}

/// Shared row parser for `df -P` output (POSIX format: one header line,
/// then one whitespace-separated row per filesystem). Used by both the
/// space and inode parsers, since `-kPT` and `-iPT` share the same column
/// layout — just different units in columns 3-5.
fn parse_df_rows(text: &str) -> Result<Vec<DfRow>, ModuleError> {
    if text.trim().is_empty() {
        return Err(ModuleError::Parse {
            what: "df output".to_string(),
            reason: "empty output".to_string(),
        });
    }

    let mut rows = Vec::new();
    for line in text.lines().skip(1) {
        let fields: Vec<&str> = line.split_whitespace().collect();
        if fields.len() < 7 {
            continue; // malformed/short line — skip defensively
        }
        let fstype = fields[1].to_string();
        let (Ok(col3), Ok(col4), Ok(col5)) = (
            fields[2].parse::<u64>(),
            fields[3].parse::<u64>(),
            fields[4].parse::<u64>(),
        ) else {
            continue;
        };
        let Ok(percent) = fields[5].trim_end_matches('%').parse::<f64>() else {
            continue;
        };
        let mount_point = fields[6..].join(" ");

        rows.push(DfRow {
            fstype,
            col3,
            col4,
            col5,
            percent,
            mount_point,
        });
    }
    Ok(rows)
}

#[cfg(test)]
mod tests {
    use super::*;

    const FIXTURE_SPACE: &str = "\
Filesystem     Type  1024-blocks     Used Available Capacity Mounted on
tmpfs          tmpfs     4093748        0   4093748       0% /dev/shm
/dev/vda       ext4    264212084 14177364   5255172      73% /
";

    const FIXTURE_INODES: &str = "\
Filesystem     Type    Inodes  IUsed    IFree IUse% Mounted on
tmpfs          tmpfs   511718     20   511698    1% /dev/shm
/dev/vda       ext4  16777216 206913 16570303    2% /
";

    #[test]
    fn parses_space_usage() {
        let rows = parse_space_usage(FIXTURE_SPACE).unwrap();
        assert_eq!(rows.len(), 2);
        let root = rows.iter().find(|r| r.mount_point == "/").unwrap();
        assert_eq!(root.fstype, "ext4");
        assert_eq!(root.total_kb, 264212084);
        assert_eq!(root.used_kb, 14177364);
        assert_eq!(root.available_kb, 5255172);
        assert_eq!(root.use_percent, 73.0);
    }

    #[test]
    fn parses_inode_usage() {
        let rows = parse_inode_usage(FIXTURE_INODES).unwrap();
        let root = rows.iter().find(|r| r.mount_point == "/").unwrap();
        assert_eq!(root.inodes_total, 16777216);
        assert_eq!(root.inodes_used, 206913);
        assert_eq!(root.use_percent, 2.0);
    }

    #[test]
    fn errors_on_empty_output() {
        assert!(parse_space_usage("").is_err());
    }

    #[test]
    fn skips_malformed_lines() {
        let text = "Filesystem Type 1024-blocks Used Available Capacity Mounted on\nbroken line\n/dev/vda ext4 100 50 50 50% /\n";
        let rows = parse_space_usage(text).unwrap();
        assert_eq!(rows.len(), 1);
    }

    #[test]
    fn handles_mount_points_with_spaces() {
        let text = "Filesystem Type 1024-blocks Used Available Capacity Mounted on\n/dev/sdb1 ext4 100 50 50 50% /mnt/My Backup\n";
        let rows = parse_space_usage(text).unwrap();
        assert_eq!(rows[0].mount_point, "/mnt/My Backup");
    }

    #[test]
    fn filters_pseudo_block_devices() {
        assert!(!is_candidate_block_device("loop0"));
        assert!(!is_candidate_block_device("ram0"));
        assert!(!is_candidate_block_device("zram0"));
        assert!(!is_candidate_block_device("dm-0"));
        assert!(!is_candidate_block_device("md0"));
        assert!(!is_candidate_block_device("sr0"));
        assert!(is_candidate_block_device("sda"));
        assert!(is_candidate_block_device("nvme0n1"));
        assert!(is_candidate_block_device("vda"));
    }

    // Real output captured from `smartctl -a --json=c /dev/vda` against a
    // virtio block device: valid JSON, but no usable SMART data at all.
    const FIXTURE_UNSUPPORTED: &str = r#"{
        "json_format_version": [1, 0],
        "smartctl": {
            "messages": [{"string": "/dev/vda: Unable to detect device type", "severity": "error"}],
            "exit_status": 1
        }
    }"#;

    const FIXTURE_ATA_HEALTHY: &str = r#"{
        "model_name": "Samsung SSD 870 EVO 1TB",
        "device": {"name": "/dev/sda", "type": "sat"},
        "smart_status": {"passed": true},
        "temperature": {"current": 32},
        "power_on_time": {"hours": 8760},
        "ata_smart_attributes": {
            "table": [
                {"id": 5, "name": "Reallocated_Sector_Ct", "raw": {"value": 0}},
                {"id": 197, "name": "Current_Pending_Sector", "raw": {"value": 0}},
                {"id": 198, "name": "Offline_Uncorrectable", "raw": {"value": 0}}
            ]
        }
    }"#;

    const FIXTURE_ATA_FAILING: &str = r#"{
        "model_name": "WDC WD40EFRX-68N32N0",
        "device": {"name": "/dev/sdb", "type": "sat"},
        "smart_status": {"passed": false},
        "temperature": {"current": 45},
        "power_on_time": {"hours": 45000},
        "ata_smart_attributes": {
            "table": [
                {"id": 5, "name": "Reallocated_Sector_Ct", "raw": {"value": 87}},
                {"id": 197, "name": "Current_Pending_Sector", "raw": {"value": 12}},
                {"id": 198, "name": "Offline_Uncorrectable", "raw": {"value": 3}}
            ]
        }
    }"#;

    const FIXTURE_NVME_WORN: &str = r#"{
        "model_name": "Samsung SSD 980 PRO 2TB",
        "device": {"name": "/dev/nvme0", "type": "nvme"},
        "smart_status": {"passed": true},
        "temperature": {"current": 55},
        "power_on_time": {"hours": 20000},
        "nvme_smart_health_information_log": {
            "critical_warning": 0,
            "percentage_used": 85,
            "media_errors": 0
        }
    }"#;

    #[test]
    fn parse_smart_json_returns_none_for_unsupported_device() {
        let json: serde_json::Value = serde_json::from_str(FIXTURE_UNSUPPORTED).unwrap();
        assert!(parse_smart_json("/dev/vda", &json).is_none());
    }

    #[test]
    fn parse_smart_json_extracts_healthy_ata_device() {
        let json: serde_json::Value = serde_json::from_str(FIXTURE_ATA_HEALTHY).unwrap();
        let health = parse_smart_json("/dev/sda", &json).unwrap();
        assert_eq!(health.model.as_deref(), Some("Samsung SSD 870 EVO 1TB"));
        assert_eq!(health.smart_passed, Some(true));
        assert_eq!(health.temperature_celsius, Some(32));
        assert_eq!(health.power_on_hours, Some(8760));
        assert_eq!(health.reallocated_sectors, Some(0));
        assert_eq!(health.pending_sectors, Some(0));
        assert_eq!(health.uncorrectable_sectors, Some(0));
    }

    #[test]
    fn parse_smart_json_extracts_failing_ata_device() {
        let json: serde_json::Value = serde_json::from_str(FIXTURE_ATA_FAILING).unwrap();
        let health = parse_smart_json("/dev/sdb", &json).unwrap();
        assert_eq!(health.smart_passed, Some(false));
        assert_eq!(health.reallocated_sectors, Some(87));
        assert_eq!(health.pending_sectors, Some(12));
        assert_eq!(health.uncorrectable_sectors, Some(3));
    }

    #[test]
    fn parse_smart_json_extracts_nvme_device() {
        let json: serde_json::Value = serde_json::from_str(FIXTURE_NVME_WORN).unwrap();
        let health = parse_smart_json("/dev/nvme0", &json).unwrap();
        assert_eq!(health.device_type.as_deref(), Some("nvme"));
        assert_eq!(health.nvme_percentage_used, Some(85));
        assert_eq!(health.nvme_critical_warning, Some(0));
        // ATA-only fields must stay None for an NVMe device.
        assert_eq!(health.reallocated_sectors, None);
    }
}
